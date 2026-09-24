use super::{
    TCP_ACK, TCP_HEADER, TCP_PROTOCOL, TCP_PSH, TCP_RST, TCP_SYN, TcpFlow, TcpKey, TcpRequest,
    UDP_HEADER, UDP_PROTOCOL, UdpRequest,
};

pub(super) fn parse_udp(packet: &[u8]) -> Option<UdpRequest> {
    match packet.first().map(|byte| byte >> 4)? {
        4 => {
            if packet.len() < 28 || packet[9] != UDP_PROTOCOL {
                return None;
            }
            let header = usize::from(packet[0] & 0x0f) * 4;
            if !(20..=60).contains(&header)
                || packet.len() < header + UDP_HEADER
                || read_u16(packet, 6) & 0x3fff != 0
            {
                return None;
            }
            parse_udp_payload(
                packet,
                4,
                header,
                packet[12..16].to_vec(),
                packet[16..20].to_vec(),
            )
        }
        6 => {
            if packet.len() < 48 || packet[6] != UDP_PROTOCOL {
                return None;
            }
            parse_udp_payload(
                packet,
                6,
                40,
                packet[8..24].to_vec(),
                packet[24..40].to_vec(),
            )
        }
        _ => None,
    }
}

fn parse_udp_payload(
    packet: &[u8],
    version: u8,
    header: usize,
    source: Vec<u8>,
    destination: Vec<u8>,
) -> Option<UdpRequest> {
    let udp_length = usize::from(read_u16(packet, header + 4));
    if udp_length < UDP_HEADER || header + udp_length != packet.len() {
        return None;
    }
    Some(UdpRequest {
        version,
        ip_header_length: header,
        source,
        destination,
        source_port: read_u16(packet, header),
        destination_port: read_u16(packet, header + 2),
        payload: packet[header + UDP_HEADER..].to_vec(),
    })
}

pub(super) fn parse_tcp(packet: &[u8]) -> Option<TcpRequest> {
    let version = packet.first().map(|byte| byte >> 4)?;
    let (header, source, destination) = match version {
        4 => {
            if packet.len() < 40 || packet[9] != TCP_PROTOCOL {
                return None;
            }
            let header = usize::from(packet[0] & 0x0f) * 4;
            if !(20..=60).contains(&header) || read_u16(packet, 6) & 0x3fff != 0 {
                return None;
            }
            (header, packet[12..16].to_vec(), packet[16..20].to_vec())
        }
        6 => {
            if packet.len() < 60 || packet[6] != TCP_PROTOCOL {
                return None;
            }
            (40, packet[8..24].to_vec(), packet[24..40].to_vec())
        }
        _ => return None,
    };
    if packet.len() < header + TCP_HEADER {
        return None;
    }
    let tcp_header = usize::from(packet[header + 12] >> 4) * 4;
    if !(TCP_HEADER..=60).contains(&tcp_header) || packet.len() < header + tcp_header {
        return None;
    }
    Some(TcpRequest {
        version,
        source,
        destination,
        source_port: read_u16(packet, header),
        destination_port: read_u16(packet, header + 2),
        sequence: read_u32(packet, header + 4),
        flags: packet[header + 13] & 0x3f,
        payload: packet[header + tcp_header..].to_vec(),
    })
}

pub(super) fn build_udp_reply(request: &UdpRequest, dns: &[u8]) -> Vec<u8> {
    let header = if request.version == 4 { 20 } else { 40 };
    let udp_length = UDP_HEADER + dns.len();
    let mut output = vec![0; header + udp_length];
    if request.version == 4 {
        output[0] = 0x45;
        let output_length = u16::try_from(output.len()).unwrap_or(u16::MAX);
        write_u16(&mut output, 2, output_length);
        output[8] = 64;
        output[9] = UDP_PROTOCOL;
        output[12..16].copy_from_slice(&request.destination);
        output[16..20].copy_from_slice(&request.source);
        let checksum = checksum(&output, 0, 20, 0);
        write_u16(&mut output, 10, checksum);
    } else {
        output[0] = 0x60;
        write_u16(
            &mut output,
            4,
            u16::try_from(udp_length).unwrap_or(u16::MAX),
        );
        output[6] = UDP_PROTOCOL;
        output[7] = 64;
        output[8..24].copy_from_slice(&request.destination);
        output[24..40].copy_from_slice(&request.source);
    }
    write_u16(&mut output, header, request.destination_port);
    write_u16(&mut output, header + 2, request.source_port);
    write_u16(
        &mut output,
        header + 4,
        u16::try_from(udp_length).unwrap_or(u16::MAX),
    );
    output[header + UDP_HEADER..].copy_from_slice(dns);
    let pseudo = pseudo_header_sum(
        &request.destination,
        &request.source,
        UDP_PROTOCOL,
        udp_length,
    );
    let checksum = checksum(&output, header, udp_length, pseudo);
    write_u16(
        &mut output,
        header + 6,
        if checksum == 0 { u16::MAX } else { checksum },
    );
    output
}

pub(super) fn segment_tcp_response(
    mtu: usize,
    request: &TcpRequest,
    flow: &mut TcpFlow,
    framed: &[u8],
    start: u32,
    advance: bool,
) -> Vec<Vec<u8>> {
    let header = if request.version == 4 { 20 } else { 40 };
    let maximum = mtu.saturating_sub(header + TCP_HEADER).max(1);
    let chunks = framed.chunks(maximum).collect::<Vec<_>>();
    let replies = chunks
        .iter()
        .enumerate()
        .map(|(index, payload)| {
            let flags = TCP_ACK
                | if index + 1 == chunks.len() {
                    TCP_PSH
                } else {
                    0
                };
            build_tcp_reply(
                request,
                start.wrapping_add(u32::try_from(index * maximum).unwrap_or(u32::MAX)),
                flow.client_next,
                flags,
                payload,
            )
        })
        .collect();
    if advance {
        flow.server_next = start.wrapping_add(u32::try_from(framed.len()).unwrap_or(u32::MAX));
    }
    replies
}

pub(super) fn build_tcp_reset(request: &TcpRequest) -> Vec<u8> {
    build_tcp_reply(
        request,
        0,
        request.sequence.wrapping_add(
            u32::try_from(request.payload.len()).unwrap_or(u32::MAX)
                + u32::from(request.flags & TCP_SYN != 0),
        ),
        TCP_RST | TCP_ACK,
        &[],
    )
}

pub(super) fn build_tcp_reply(
    request: &TcpRequest,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let header = if request.version == 4 { 20 } else { 40 };
    let tcp_length = TCP_HEADER + payload.len();
    let mut output = vec![0; header + tcp_length];
    if request.version == 4 {
        output[0] = 0x45;
        let output_length = u16::try_from(output.len()).unwrap_or(u16::MAX);
        write_u16(&mut output, 2, output_length);
        output[8] = 64;
        output[9] = TCP_PROTOCOL;
        output[12..16].copy_from_slice(&request.destination);
        output[16..20].copy_from_slice(&request.source);
        let checksum = checksum(&output, 0, 20, 0);
        write_u16(&mut output, 10, checksum);
    } else {
        output[0] = 0x60;
        write_u16(
            &mut output,
            4,
            u16::try_from(tcp_length).unwrap_or(u16::MAX),
        );
        output[6] = TCP_PROTOCOL;
        output[7] = 64;
        output[8..24].copy_from_slice(&request.destination);
        output[24..40].copy_from_slice(&request.source);
    }
    write_u16(&mut output, header, request.destination_port);
    write_u16(&mut output, header + 2, request.source_port);
    write_u32(&mut output, header + 4, sequence);
    write_u32(&mut output, header + 8, acknowledgement);
    output[header + 12] = 0x50;
    output[header + 13] = flags;
    write_u16(&mut output, header + 14, u16::MAX);
    output[header + TCP_HEADER..].copy_from_slice(payload);
    let pseudo = pseudo_header_sum(
        &request.destination,
        &request.source,
        TCP_PROTOCOL,
        tcp_length,
    );
    let checksum = checksum(&output, header, tcp_length, pseudo);
    write_u16(
        &mut output,
        header + 16,
        if checksum == 0 { u16::MAX } else { checksum },
    );
    output
}

pub(super) fn error_reply(query: &[u8], code: u16, truncated: bool) -> Vec<u8> {
    if query.len() < 12 {
        return vec![0; 12];
    }
    let mut output = query.to_vec();
    let flags = 0x8000 | (read_u16(query, 2) & 0x0100) | code | (u16::from(truncated) * 0x0200);
    write_u16(&mut output, 2, flags);
    output[6..12].fill(0);
    output
}

pub(super) fn initial_sequence(key: &TcpKey) -> u32 {
    key.source
        .iter()
        .chain(&key.destination)
        .fold(u32::from(key.source_port), |hash, byte| {
            hash.wrapping_mul(16_777_619) ^ u32::from(*byte)
        })
}

fn pseudo_header_sum(source: &[u8], destination: &[u8], protocol: u8, length: usize) -> u64 {
    byte_words(source)
        + byte_words(destination)
        + u64::from(protocol)
        + u64::try_from(length).unwrap_or(u64::MAX)
}

fn byte_words(bytes: &[u8]) -> u64 {
    bytes
        .chunks_exact(2)
        .map(|word| u64::from(u16::from_be_bytes([word[0], word[1]])))
        .sum()
}

fn checksum(bytes: &[u8], offset: usize, length: usize, initial: u64) -> u16 {
    let mut sum = initial;
    let body = &bytes[offset..offset + length];
    for word in body.chunks_exact(2) {
        sum += u64::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if !length.is_multiple_of(2) {
        sum += u64::from(body[length - 1]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !u16::try_from(sum).expect("checksum was folded to sixteen bits")
}

pub(super) fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

pub(super) fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

pub(super) fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("four-byte slice"),
    )
}

pub(super) fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}
