const TCP: u8 = 6;
const UDP: u8 = 17;
const ICMP_V4: u8 = 1;
const ICMP_V6: u8 = 58;
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

/// Packet decoding failure.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub enum ParseError {
    /// Packet is shorter than its mandatory header.
    #[error("packet is truncated")]
    Truncated,
    /// Version, lengths, checksum, or extension headers are invalid.
    #[error("packet header is malformed")]
    Malformed,
    /// Network or transport protocol is outside the supported data plane.
    #[error("packet protocol is unsupported")]
    Unsupported,
}

/// Fragment metadata shared by IPv4 and IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Fragment {
    /// Identification value scoped by source, destination, and protocol.
    pub identification: u32,
    /// Eight-byte fragment offset units.
    pub offset: u16,
    /// More-fragments bit.
    pub more: bool,
}

/// Parsed metadata used by policy and state tracking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedPacket {
    /// Source address.
    pub source: IpAddr,
    /// Destination address.
    pub destination: IpAddr,
    /// Final IP next-header value, or the Fragment header's value for a
    /// non-initial IPv6 fragment whose transport header is unavailable.
    pub protocol: u8,
    /// TCP/UDP source port or echo identifier.
    pub source_port: Option<u16>,
    /// TCP/UDP destination port or echo identifier.
    pub destination_port: Option<u16>,
    /// TCP flags.
    pub tcp_flags: Option<u8>,
    /// ICMP type and code.
    pub icmp: Option<(u8, u8)>,
    /// Fragment metadata.
    pub fragment: Option<Fragment>,
    /// Complete authenticated packet length.
    pub packet_len: usize,
    /// Quoted flow in a supported ICMP error.
    pub related_flow: Option<FlowKey>,
}

/// Parses exactly one IPv4 or IPv6 packet.
pub fn parse_packet(bytes: &[u8]) -> Result<ParsedPacket, ParseError> {
    match bytes.first().ok_or(ParseError::Truncated)? >> 4 {
        4 => parse_ipv4(bytes, true),
        6 => parse_ipv6(bytes, true),
        _ => Err(ParseError::Unsupported),
    }
}

fn parse_ipv4(bytes: &[u8], related: bool) -> Result<ParsedPacket, ParseError> {
    if bytes.len() < 20 {
        return Err(ParseError::Truncated);
    }
    let header_len = usize::from(bytes[0] & 0x0f) * 4;
    if header_len < 20 || header_len > bytes.len() {
        return Err(ParseError::Malformed);
    }
    let total = usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    if total != bytes.len() || total < header_len || ipv4_checksum(&bytes[..header_len]) != 0 {
        return Err(ParseError::Malformed);
    }
    let source = IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]));
    let destination = IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]));
    let bits = u16::from_be_bytes([bytes[6], bytes[7]]);
    let offset = bits & 0x1fff;
    let more = bits & 0x2000 != 0;
    let fragment = (offset != 0 || more).then_some(Fragment {
        identification: u32::from(u16::from_be_bytes([bytes[4], bytes[5]])),
        offset,
        more,
    });
    finish_transport(
        &bytes[header_len..],
        source,
        destination,
        bytes[9],
        fragment,
        total,
        related,
    )
}

fn parse_ipv6(bytes: &[u8], related: bool) -> Result<ParsedPacket, ParseError> {
    if bytes.len() < 40 {
        return Err(ParseError::Truncated);
    }
    let payload_len = usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
    if payload_len.checked_add(40) != Some(bytes.len()) {
        return Err(ParseError::Malformed);
    }
    let source = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&bytes[8..24]).map_err(|_| ParseError::Truncated)?,
    ));
    let destination = IpAddr::V6(Ipv6Addr::from(
        <[u8; 16]>::try_from(&bytes[24..40]).map_err(|_| ParseError::Truncated)?,
    ));
    let mut next = bytes[6];
    let mut cursor = 40_usize;
    let mut fragment = None;
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                if cursor + 2 > bytes.len() {
                    return Err(ParseError::Truncated);
                }
                let extension_len = (usize::from(bytes[cursor + 1]) + 1) * 8;
                if cursor + extension_len > bytes.len() {
                    return Err(ParseError::Truncated);
                }
                next = bytes[cursor];
                cursor += extension_len;
            }
            44 => {
                if cursor + 8 > bytes.len() || fragment.is_some() {
                    return Err(ParseError::Malformed);
                }
                let bits = u16::from_be_bytes([bytes[cursor + 2], bytes[cursor + 3]]);
                fragment = Some(Fragment {
                    identification: u32::from_be_bytes(
                        bytes[cursor + 4..cursor + 8]
                            .try_into()
                            .map_err(|_| ParseError::Truncated)?,
                    ),
                    offset: bits >> 3,
                    more: bits & 1 != 0,
                });
                next = bytes[cursor];
                cursor += 8;
                if bits >> 3 != 0 {
                    // The fragmentable extension chain exists only at offset
                    // zero. Later payload must never be interpreted as headers.
                    return finish_transport(
                        &bytes[cursor..], source, destination, next, fragment, bytes.len(), related,
                    );
                }
            }
            _ => {
                return finish_transport(
                    &bytes[cursor..],
                    source,
                    destination,
                    next,
                    fragment,
                    bytes.len(),
                    related,
                );
            }
        }
    }
    Err(ParseError::Malformed)
}

fn finish_transport(
    payload: &[u8],
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    fragment: Option<Fragment>,
    packet_len: usize,
    related: bool,
) -> Result<ParsedPacket, ParseError> {
    if fragment.is_some_and(|item| item.offset != 0) {
        return Ok(ParsedPacket {
            source,
            destination,
            protocol,
            source_port: None,
            destination_port: None,
            tcp_flags: None,
            icmp: None,
            fragment,
            packet_len,
            related_flow: None,
        });
    }
    let incomplete_fragment = fragment.is_some_and(|item| item.offset != 0 || item.more);
    let (source_port, destination_port, tcp_flags, icmp, related_flow) = match protocol {
        TCP => {
            if payload.len() < 20 {
                return Err(ParseError::Truncated);
            }
            let header_len = usize::from(payload[12] >> 4) * 4;
            if header_len < 20 {
                return Err(ParseError::Malformed);
            }
            if header_len > payload.len() {
                return Err(ParseError::Truncated);
            }
            if !incomplete_fragment
                && !transport_checksum_valid(payload, source, destination, TCP)
            {
                return Err(ParseError::Malformed);
            }
            (
                Some(u16::from_be_bytes([payload[0], payload[1]])),
                Some(u16::from_be_bytes([payload[2], payload[3]])),
                Some(payload[13] & 0x3f),
                None,
                None,
            )
        }
        UDP => {
            if payload.len() < 8 {
                return Err(ParseError::Truncated);
            }
            let length = usize::from(u16::from_be_bytes([payload[4], payload[5]]));
            if length < 8
                || (!incomplete_fragment && length != payload.len())
                || (incomplete_fragment && length < payload.len())
            {
                return Err(ParseError::Malformed);
            }
            let checksum = u16::from_be_bytes([payload[6], payload[7]]);
            if !incomplete_fragment
                && ((source.is_ipv6() && checksum == 0)
                    || (checksum != 0
                        && !transport_checksum_valid(payload, source, destination, UDP)))
            {
                return Err(ParseError::Malformed);
            }
            (
                Some(u16::from_be_bytes([payload[0], payload[1]])),
                Some(u16::from_be_bytes([payload[2], payload[3]])),
                None,
                None,
                None,
            )
        }
        ICMP_V4 | ICMP_V6 => {
            if payload.len() < 8 {
                return Err(ParseError::Truncated);
            }
            if !incomplete_fragment
                && match protocol {
                    ICMP_V4 => internet_checksum(payload) != 0,
                    ICMP_V6 => !transport_checksum_valid(payload, source, destination, ICMP_V6),
                    _ => unreachable!(),
                }
            {
                return Err(ParseError::Malformed);
            }
            let kind = payload[0];
            let code = payload[1];
            let echo = matches!((protocol, kind), (ICMP_V4, 0 | 8) | (ICMP_V6, 128 | 129));
            let identifier = echo.then(|| u16::from_be_bytes([payload[4], payload[5]]));
            let is_error = matches!((protocol, kind), (ICMP_V4, 3 | 11 | 12) | (ICMP_V6, 1..=4));
            let quoted = if related && is_error {
                parse_quoted_flow(&payload[8..])
            } else {
                None
            };
            (identifier, identifier, None, Some((kind, code)), quoted)
        }
        _ => (None, None, None, None, None),
    };
    Ok(ParsedPacket {
        source,
        destination,
        protocol,
        source_port,
        destination_port,
        tcp_flags,
        icmp,
        fragment,
        packet_len,
        related_flow,
    })
}

fn parse_quoted_flow(bytes: &[u8]) -> Option<FlowKey> {
    match bytes.first().map(|value| value >> 4) {
        Some(4) if bytes.len() >= 24 => {
            let header = usize::from(bytes[0] & 0x0f) * 4;
            let transport = bytes.get(header..header + 4)?;
            let protocol = bytes[9];
            Some(FlowKey {
                source: IpAddr::V4(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15])),
                destination: IpAddr::V4(Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19])),
                protocol,
                source_port: Some(u16::from_be_bytes([transport[0], transport[1]])),
                destination_port: Some(u16::from_be_bytes([transport[2], transport[3]])),
            })
        }
        Some(6) if bytes.len() >= 44 => {
            let transport = &bytes[40..44];
            Some(FlowKey {
                source: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).ok()?)),
                destination: IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).ok()?)),
                protocol: bytes[6],
                source_port: Some(u16::from_be_bytes([transport[0], transport[1]])),
                destination_port: Some(u16::from_be_bytes([transport[2], transport[3]])),
            })
        }
        _ => None,
    }
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    internet_checksum(header)
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = checksum_words(0, bytes);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("checksum fold is at most sixteen bits")
}

fn checksum_words(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        sum += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let Some(last) = chunks.remainder().first() {
        sum += u32::from(*last) << 8;
    }
    sum
}

fn transport_checksum_valid(
    payload: &[u8],
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
) -> bool {
    let Ok(length) = u32::try_from(payload.len()) else {
        return false;
    };
    let mut sum = 0_u32;
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            sum = checksum_words(sum, &source.octets());
            sum = checksum_words(sum, &destination.octets());
            sum += u32::from(protocol);
            sum += length;
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            sum = checksum_words(sum, &source.octets());
            sum = checksum_words(sum, &destination.octets());
            sum = checksum_words(sum, &length.to_be_bytes());
            sum += u32::from(protocol);
        }
        _ => return false,
    }
    sum = checksum_words(sum, payload);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
}
