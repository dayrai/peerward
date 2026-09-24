/// Resolve only configured transport names over marked underlay sockets. The caller
/// enforces the allowlist; application queries never call this bootstrap resolver.
pub(crate) async fn resolve_bootstrap(
    underlay: &dyn peerward_platform::UnderlayNetwork,
    upstreams: &[SocketAddr],
    host: &str,
    port: u16,
) -> io::Result<Vec<SocketAddr>> {
    let (ipv4, ipv6) = tokio::join!(
        bootstrap_family(underlay, upstreams, host, 1),
        bootstrap_family(underlay, upstreams, host, 28)
    );
    let mut result = Vec::new();
    for address in ipv6
        .unwrap_or_default()
        .into_iter()
        .chain(ipv4.unwrap_or_default())
    {
        let address = SocketAddr::new(address, port);
        if !result.contains(&address) {
            result.push(address);
        }
    }
    if result.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "configured underlay DNS returned no endpoint addresses",
        ));
    }
    Ok(result)
}
async fn bootstrap_family(
    underlay: &dyn peerward_platform::UnderlayNetwork,
    upstreams: &[SocketAddr],
    host: &str,
    kind: u16,
) -> io::Result<Vec<IpAddr>> {
    use rand::RngCore as _;
    if host.len() > 253
        || host.is_empty()
        || host.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(invalid_dns());
    }
    let random = rand::rngs::OsRng.next_u32().to_be_bytes();
    let id = u16::from_be_bytes([random[0], random[1]]);
    let mut query = Vec::from(id.to_be_bytes());
    query.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    query.extend(encode_name(host));
    query.extend(kind.to_be_bytes());
    query.extend([0, 1]);
    let question = parse_question(&query)?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    for upstream in upstreams.iter().take(8) {
        let attempt = async {
            let bind = SocketAddr::new(
                if upstream.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                } else {
                    IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
                },
                0,
            );
            let socket = underlay.bind_udp(bind).await.map_err(io::Error::other)?;
            socket.connect(*upstream).await?;
            socket.send(&query).await?;
            let mut reply = vec![0; MAX_DNS_MESSAGE];
            let size = socket.recv(&mut reply).await?;
            reply.truncate(size);
            validate_forwarded(&reply, &question)?;
            if read_u16(&reply, 2)? & 0x0200 != 0 {
                let mut stream = underlay
                    .connect_tcp(*upstream)
                    .await
                    .map_err(io::Error::other)?;
                stream
                    .write_u16(u16::try_from(query.len()).map_err(|_| invalid_dns())?)
                    .await?;
                stream.write_all(&query).await?;
                let length = usize::from(stream.read_u16().await?);
                if !(DNS_HEADER..=MAX_DNS_MESSAGE).contains(&length) {
                    return Err(invalid_dns());
                }
                reply.resize(length, 0);
                stream.read_exact(&mut reply).await?;
            }
            bootstrap_answers(&reply, &question)
        };
        let limit = deadline.min(tokio::time::Instant::now() + Duration::from_secs(1));
        if let Ok(Ok(addresses)) = tokio::time::timeout_at(limit, attempt).await {
            return Ok(addresses);
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
    }
    Err(io::ErrorKind::TimedOut.into())
}
fn bootstrap_answers(reply: &[u8], question: &Question) -> io::Result<Vec<IpAddr>> {
    validate_forwarded(reply, question)?;
    let flags = read_u16(reply, 2)?;
    if flags & 0x7a00 != 0 || flags & 15 != 0 {
        return Err(invalid_dns());
    }
    let count = usize::from(read_u16(reply, 6)?);
    if count > 64 {
        return Err(invalid_dns());
    }
    let (_, end) = decode_name(reply, DNS_HEADER)?;
    let mut cursor = end + 4;
    let mut aliases = std::collections::BTreeMap::new();
    let mut addresses = Vec::new();
    for _ in 0..count {
        let (name, position) = decode_name(reply, cursor)?;
        let kind = read_u16(reply, position)?;
        let class = read_u16(reply, position + 2)?;
        let size = usize::from(read_u16(reply, position + 8)?);
        let start = position.checked_add(10).ok_or_else(invalid_dns)?;
        cursor = start
            .checked_add(size)
            .filter(|end| *end <= reply.len())
            .ok_or_else(invalid_dns)?;
        if class != 1 {
            continue;
        }
        let name = name.to_ascii_lowercase();
        match kind {
            5 => {
                let (target, end) = decode_name(reply, start)?;
                if end != cursor || aliases.insert(name, target.to_ascii_lowercase()).is_some() {
                    return Err(invalid_dns());
                }
            }
            1 if size == 4 && question.qtype == 1 => addresses.push((
                name,
                IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(&reply[start..cursor]).map_err(|_| invalid_dns())?,
                )),
            )),
            28 if size == 16 && question.qtype == 28 => addresses.push((
                name,
                IpAddr::V6(std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(&reply[start..cursor]).map_err(|_| invalid_dns())?,
                )),
            )),
            _ => {}
        }
    }
    let mut owner = question.name.to_ascii_lowercase();
    let mut visited = std::collections::BTreeSet::new();
    while let Some(next) = aliases.get(&owner) {
        if visited.len() >= 8 || !visited.insert(owner.clone()) {
            return Err(invalid_dns());
        }
        owner = next.clone();
    }
    Ok(addresses
        .into_iter()
        .filter_map(|(name, address)| {
            (name == owner && !address.is_unspecified() && !address.is_multicast())
                .then_some(address)
        })
        .take(16)
        .collect())
}
