use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use peerward_service::ServiceProtocol;
use peerward_types::TransportProtocol;

const DNS_HEADER: usize = 12;
const MAX_DNS_MESSAGE: usize = 4096;

struct MobileQuestion {
    flags: u16,
    name: String,
    qtype: u16,
    end: usize,
}

impl NativeSession {
    /// Answers an authoritative Mesh DNS query from signed directory state.
    /// An empty result means the name is outside the Mesh suffix and must be
    /// sent through a protected Android upstream socket.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed, oversized, or non-canonical DNS input.
    pub fn resolve_dns(
        &self,
        query: &[u8],
        source: IpAddr,
        suffix: &str,
    ) -> Result<Vec<u8>, MobileError> {
        if let Some(owner) = &self.wireguard {
            let mut owner = owner.lock().map_err(|_| MobileError::InvalidState)?;
            return owner.resolve_dns(query, source, suffix, UnixTime(wall_clock_seconds()));
        }
        resolve_mesh_dns(&self.policy, &self.services, query, source, suffix)
    }
}

fn resolve_mesh_dns(
    policy: &PolicyEngine,
    services: &RemoteServiceTable,
    query: &[u8],
    source: IpAddr,
    suffix: &str,
) -> Result<Vec<u8>, MobileError> {
    let suffix = canonical_suffix(suffix)?;
    let question = parse_question(query)?;
    if let Some(label) = question
        .name
        .strip_suffix(&format!(".{suffix}"))
        .filter(|label| canonical_mesh_label(label))
    {
        let resolved = resolve_forward(
            policy,
            services,
            label,
            source,
            match question.qtype {
                1 => Some(false),
                28 => Some(true),
                _ => None,
            },
        );
        let answer = match question.qtype {
            1 => resolved.filter(IpAddr::is_ipv4),
            28 => resolved.filter(IpAddr::is_ipv6),
            _ => None,
        };
        return build_address_reply(query, &question, answer, resolved.is_some());
    }
    if question.qtype == 12
        && let Some(address) = parse_reverse(&question.name)
    {
        let peer = policy.resolve_peer_address(address, source);
        let service = services.resolve_ptr_visible(address, source, |source, item| {
            item.protocols.iter().any(|protocol| {
                policy.allows_service(
                    source,
                    item.virtual_address,
                    service_transport(*protocol),
                    item.listen_port,
                )
            })
        });
        let answer = peer.or(service).map(|label| format!("{label}.{suffix}"));
        return build_ptr_reply(query, &question, answer.as_deref());
    }
    Ok(Vec::new())
}

fn resolve_managed_dns(
    dns: &peerward_management::EffectiveDns,
    query: &[u8],
) -> Result<Vec<u8>, MobileError> {
    use peerward_management::DnsRecord;
    let question = parse_question(query)?;
    if !dns.records.contains_key(&question.name) {
        return Ok(Vec::new());
    }
    let records = dns
        .answer_records(&question.name, question.qtype)
        .map_err(|_| MobileError::InvalidInput)?;
    let mut reply = build_reply(query, &question, None, None, true)?;
    reply[6..8].copy_from_slice(
        &u16::try_from(records.len())
            .map_err(|_| MobileError::InvalidInput)?
            .to_be_bytes(),
    );
    for (name, record) in records {
        let (kind, data) = match record {
            DnsRecord::A(address) => (1u16, address.octets().to_vec()),
            DnsRecord::AAAA(address) => (28u16, address.octets().to_vec()),
            DnsRecord::CNAME(target) => (5u16, encode_name(&target)?),
        };
        reply.extend(encode_name(&name)?);
        reply.extend(kind.to_be_bytes());
        reply.extend(1u16.to_be_bytes());
        reply.extend(30u32.to_be_bytes());
        reply.extend(
            u16::try_from(data.len())
                .map_err(|_| MobileError::InvalidInput)?
                .to_be_bytes(),
        );
        reply.extend(data);
    }
    if reply.len() > MAX_DNS_MESSAGE {
        return Err(MobileError::InvalidInput);
    }
    Ok(reply)
}

fn resolve_forward(
    policy: &PolicyEngine,
    services: &RemoteServiceTable,
    label: &str,
    source: IpAddr,
    ipv6: Option<bool>,
) -> Option<IpAddr> {
    let peer = policy
        .resolve_peer_name_family(label, source, ipv6)
        .or_else(|| policy.resolve_peer_name(label, source));
    let service = services.resolve_visible(label, source, |source, item| {
        item.protocols.iter().any(|protocol| {
            policy.allows_service(
                source,
                item.virtual_address,
                service_transport(*protocol),
                item.listen_port,
            )
        })
    });
    peer.or(service)
}
fn service_transport(protocol: ServiceProtocol) -> TransportProtocol {
    match protocol {
        ServiceProtocol::Tcp => TransportProtocol::Tcp,
        ServiceProtocol::Udp => TransportProtocol::Udp,
    }
}

fn canonical_suffix(suffix: &str) -> Result<String, MobileError> {
    let suffix = suffix.trim_end_matches('.').to_ascii_lowercase();
    if suffix.is_empty()
        || suffix.len() > 253
        || suffix.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(MobileError::InvalidInput);
    }
    Ok(suffix)
}

fn canonical_mesh_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn parse_question(query: &[u8]) -> Result<MobileQuestion, MobileError> {
    if query.len() < DNS_HEADER || query.len() > MAX_DNS_MESSAGE {
        return Err(MobileError::InvalidInput);
    }
    let flags = read_u16(query, 2)?;
    if flags & 0xf800 != 0
        || read_u16(query, 4)? != 1
        || read_u16(query, 6)? != 0
        || read_u16(query, 8)? != 0
        || read_u16(query, 10)? > 1
    {
        return Err(MobileError::InvalidInput);
    }
    let (name, name_end) = decode_name(query, DNS_HEADER)?;
    let end = name_end.checked_add(4).ok_or(MobileError::InvalidInput)?;
    if end > query.len() || read_u16(query, name_end + 2)? != 1 {
        return Err(MobileError::InvalidInput);
    }
    Ok(MobileQuestion {
        flags,
        name,
        qtype: read_u16(query, name_end)?,
        end,
    })
}

fn decode_name(message: &[u8], start: usize) -> Result<(String, usize), MobileError> {
    let mut labels = Vec::new();
    let mut cursor = start;
    let mut expanded = 0_usize;
    loop {
        let length = usize::from(*message.get(cursor).ok_or(MobileError::InvalidInput)?);
        cursor += 1;
        if length == 0 {
            return Ok((labels.join("."), cursor));
        }
        if length > 63 {
            return Err(MobileError::InvalidInput);
        }
        let end = cursor
            .checked_add(length)
            .ok_or(MobileError::InvalidInput)?;
        let label = std::str::from_utf8(message.get(cursor..end).ok_or(MobileError::InvalidInput)?)
            .map_err(|_| MobileError::InvalidInput)?;
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return Err(MobileError::InvalidInput);
        }
        expanded += length + 1;
        if expanded > 254 {
            return Err(MobileError::InvalidInput);
        }
        labels.push(label.to_ascii_lowercase());
        cursor = end;
    }
}

fn build_address_reply(
    query: &[u8],
    question: &MobileQuestion,
    answer: Option<IpAddr>,
    name_exists: bool,
) -> Result<Vec<u8>, MobileError> {
    let data = answer.map(|address| match address {
        IpAddr::V4(value) => value.octets().to_vec(),
        IpAddr::V6(value) => value.octets().to_vec(),
    });
    build_reply(query, question, data.as_deref(), None, name_exists)
}

fn build_ptr_reply(
    query: &[u8],
    question: &MobileQuestion,
    answer: Option<&str>,
) -> Result<Vec<u8>, MobileError> {
    let encoded = answer.map(encode_name).transpose()?;
    build_reply(
        query,
        question,
        encoded.as_deref(),
        Some(12),
        encoded.is_some(),
    )
}

fn build_reply(
    query: &[u8],
    question: &MobileQuestion,
    answer: Option<&[u8]>,
    forced_type: Option<u16>,
    name_exists: bool,
) -> Result<Vec<u8>, MobileError> {
    let mut response = query[..question.end].to_vec();
    let rcode = u16::from(!name_exists) * 3;
    response[2..4].copy_from_slice(&(0x8400 | (question.flags & 0x0100) | rcode).to_be_bytes());
    response[6..8].copy_from_slice(&u16::from(answer.is_some()).to_be_bytes());
    response[8..12].fill(0);
    if let Some(data) = answer {
        response.extend_from_slice(&0xc00c_u16.to_be_bytes());
        response.extend_from_slice(&forced_type.unwrap_or(question.qtype).to_be_bytes());
        response.extend_from_slice(&1_u16.to_be_bytes());
        response.extend_from_slice(&60_u32.to_be_bytes());
        response.extend_from_slice(
            &u16::try_from(data.len())
                .map_err(|_| MobileError::InvalidInput)?
                .to_be_bytes(),
        );
        response.extend_from_slice(data);
    }
    Ok(response)
}

fn encode_name(name: &str) -> Result<Vec<u8>, MobileError> {
    let mut encoded = Vec::new();
    for label in name.trim_end_matches('.').split('.') {
        let length = u8::try_from(label.len()).map_err(|_| MobileError::InvalidInput)?;
        if length == 0 || length > 63 {
            return Err(MobileError::InvalidInput);
        }
        encoded.push(length);
        encoded.extend_from_slice(label.as_bytes());
    }
    encoded.push(0);
    Ok(encoded)
}

fn parse_reverse(name: &str) -> Option<IpAddr> {
    if let Some(prefix) = name.strip_suffix(".in-addr.arpa") {
        let octets = prefix
            .split('.')
            .map(str::parse::<u8>)
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        let [d, c, b, a] = octets.as_slice() else {
            return None;
        };
        return Some(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)));
    }
    let prefix = name.strip_suffix(".ip6.arpa")?;
    let nibbles = prefix.split('.').collect::<Vec<_>>();
    if nibbles.len() != 32 || nibbles.iter().any(|nibble| nibble.len() != 1) {
        return None;
    }
    let hex = nibbles.into_iter().rev().collect::<String>();
    let mut bytes = [0_u8; 16];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(IpAddr::V6(Ipv6Addr::from(bytes)))
}

fn read_u16(message: &[u8], offset: usize) -> Result<u16, MobileError> {
    let bytes = message
        .get(offset..offset + 2)
        .ok_or(MobileError::InvalidInput)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

#[cfg(test)]
mod dns_parser_tests {
    use super::*;

    #[test]
    fn external_service_labels_are_parsed_without_weakening_mesh_labels() {
        let mut query = vec![0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["_dns", "resolver", "arpa"] {
            query.push(u8::try_from(label.len()).unwrap());
            query.extend_from_slice(label.as_bytes());
        }
        query.extend_from_slice(&[0, 0, 33, 0, 1]);
        assert_eq!(parse_question(&query).unwrap().qtype, 33);
        assert!(!canonical_mesh_label("_dns"));
        assert!(canonical_mesh_label("peer-1"));
    }
}
