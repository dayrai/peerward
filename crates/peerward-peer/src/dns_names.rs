fn canonical_suffix(suffix: &str) -> io::Result<String> {
    let value = suffix.trim_end_matches('.').to_ascii_lowercase();
    if value.is_empty()
        || value.len() > 253
        || value.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid DNS suffix",
        ));
    }
    Ok(value)
}

fn local_label<'a>(name: &'a str, suffix: &str) -> Option<&'a str> {
    let stem = name.strip_suffix(suffix)?.strip_suffix('.')?;
    (!stem.is_empty() && !stem.contains('.')).then_some(stem)
}

fn reverse_address(name: &str) -> Option<IpAddr> {
    if let Some(stem) = name.strip_suffix(".ip6.arpa") {
        let nibbles: Vec<_> = stem.split('.').collect();
        if nibbles.len() != 32 || nibbles.iter().any(|nibble| nibble.len() != 1) {
            return None;
        }
        let text: String = nibbles.into_iter().rev().collect();
        return u128::from_str_radix(&text, 16)
            .ok()
            .map(std::net::Ipv6Addr::from)
            .map(IpAddr::V6);
    }
    let stem = name.strip_suffix(".in-addr.arpa")?;
    let parts = stem
        .split('.')
        .map(str::parse::<u8>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (parts.len() == 4).then(|| IpAddr::V4(Ipv4Addr::new(parts[3], parts[2], parts[1], parts[0])))
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut output = Vec::new();
    for label in name.split('.') {
        output.push(u8::try_from(label.len()).unwrap_or(0));
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    output
}

fn form_error(query: &[u8]) -> Vec<u8> {
    let id = query
        .get(..2)
        .and_then(|bytes| bytes.try_into().ok())
        .map_or(0, u16::from_be_bytes);
    let rd = query
        .get(2..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map_or(0, u16::from_be_bytes)
        & 0x0100;
    let mut output = Vec::with_capacity(DNS_HEADER);
    output.extend_from_slice(&id.to_be_bytes());
    output.extend_from_slice(&(0x8000 | rd | 1).to_be_bytes());
    output.extend_from_slice(&[0; 8]);
    output
}

fn read_u16(message: &[u8], offset: usize) -> io::Result<u16> {
    message
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(invalid_dns)
}

fn invalid_dns() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid DNS message")
}
