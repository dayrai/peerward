use super::wire::{read_u32, write_u16, write_u32};
use super::*;

fn dns_query(id: u16) -> Vec<u8> {
    let mut query = vec![0; 12];
    write_u16(&mut query, 0, id);
    write_u16(&mut query, 2, 0x0100);
    write_u16(&mut query, 4, 1);
    query.extend_from_slice(&[4, b'm', b'e', b's', b'h', 4, b't', b'e', b's', b't', 0]);
    query.extend_from_slice(&1_u16.to_be_bytes());
    query.extend_from_slice(&1_u16.to_be_bytes());
    query
}

fn ipv4_udp(query: &[u8], destination_port: u16) -> Vec<u8> {
    let mut packet = vec![0; 28 + query.len()];
    packet[0] = 0x45;
    let packet_length = u16::try_from(packet.len()).expect("test packet");
    write_u16(&mut packet, 2, packet_length);
    packet[8] = 64;
    packet[9] = UDP_PROTOCOL;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
    write_u16(&mut packet, 20, 49_152);
    write_u16(&mut packet, 22, destination_port);
    write_u16(
        &mut packet,
        24,
        u16::try_from(query.len() + 8).expect("test query"),
    );
    packet[28..].copy_from_slice(query);
    packet
}

fn ipv4_tcp(sequence: u32, acknowledgement: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 40 + payload.len()];
    packet[0] = 0x45;
    let packet_length = u16::try_from(packet.len()).expect("test packet");
    write_u16(&mut packet, 2, packet_length);
    packet[8] = 64;
    packet[9] = TCP_PROTOCOL;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
    write_u16(&mut packet, 20, 49_152);
    write_u16(&mut packet, 22, 53);
    write_u32(&mut packet, 24, sequence);
    write_u32(&mut packet, 28, acknowledgement);
    packet[32] = 0x50;
    packet[33] = flags;
    write_u16(&mut packet, 34, u16::MAX);
    packet[40..].copy_from_slice(payload);
    packet
}

#[test]
fn udp_query_uses_one_shot_token_and_builds_tun_reply() {
    let mut proxy = TunDnsProxy::new(vec![vec![10, 0, 0, 1]], 1_380).unwrap();
    let query = dns_query(0x1234);
    let TunDnsDecision::Resolve {
        token,
        source,
        query: extracted,
        transport,
    } = proxy.inspect(&ipv4_udp(&query, 53)).unwrap()
    else {
        panic!("expected query");
    };
    assert_eq!(transport, TunDnsTransport::Udp);
    assert_eq!(source, [10, 0, 0, 2]);
    assert_eq!(extracted, query);
    let response = proxy.complete(token, &query).unwrap();
    assert_eq!(&response[0][12..20], &[10, 0, 0, 1, 10, 0, 0, 2]);
    assert_eq!(read_u16(&response[0], 20), 53);
    assert!(proxy.complete(token, &query).is_err());
}

#[test]
fn unrelated_packet_passes_without_allocating_a_query() {
    let mut proxy = TunDnsProxy::new(vec![vec![10, 0, 0, 1]], 1_380).unwrap();
    assert_eq!(
        proxy.inspect(&ipv4_udp(&dns_query(7), 443)).unwrap(),
        TunDnsDecision::Pass
    );
}

#[test]
fn tcp_handshake_and_query_state_are_owned_by_rust() {
    let mut proxy = TunDnsProxy::new(vec![vec![10, 0, 0, 1]], 576).unwrap();
    let TunDnsDecision::Replies(handshake) =
        proxy.inspect(&ipv4_tcp(100, 0, TCP_SYN, &[])).unwrap()
    else {
        panic!("expected SYN/ACK");
    };
    assert_eq!(handshake[0][33] & 0x3f, TCP_SYN | TCP_ACK);
    assert_eq!(read_u32(&handshake[0], 28), 101);
    let query = dns_query(0x7788);
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&u16::try_from(query.len()).unwrap().to_be_bytes());
    framed.extend_from_slice(&query);
    let acknowledgement = read_u32(&handshake[0], 24);
    let TunDnsDecision::Resolve {
        token, transport, ..
    } = proxy
        .inspect(&ipv4_tcp(101, acknowledgement, TCP_ACK | TCP_PSH, &framed))
        .unwrap()
    else {
        panic!("expected TCP query");
    };
    assert_eq!(transport, TunDnsTransport::Tcp);
    let replies = proxy.complete(token, &query).unwrap();
    assert!(replies.iter().all(|packet| packet.len() <= 576));
    let payload = replies
        .iter()
        .flat_map(|packet| packet[40..].iter().copied())
        .collect::<Vec<_>>();
    assert_eq!(usize::from(read_u16(&payload, 0)), payload.len() - 2);
    assert_eq!(read_u16(&payload, 2), 0x7788);
}

#[test]
fn split_tcp_query_and_empty_upstream_response_fail_closed() {
    let mut proxy = TunDnsProxy::new(vec![vec![10, 0, 0, 1]], 576).unwrap();
    let TunDnsDecision::Replies(handshake) =
        proxy.inspect(&ipv4_tcp(500, 0, TCP_SYN, &[])).unwrap()
    else {
        panic!("expected SYN/ACK");
    };
    let query = dns_query(0x5152);
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&u16::try_from(query.len()).unwrap().to_be_bytes());
    framed.extend_from_slice(&query);
    let acknowledgement = read_u32(&handshake[0], 24);
    assert!(matches!(
        proxy
            .inspect(&ipv4_tcp(501, acknowledgement, TCP_ACK, &framed[..1]))
            .unwrap(),
        TunDnsDecision::Replies(_)
    ));
    let TunDnsDecision::Resolve { token, .. } = proxy
        .inspect(&ipv4_tcp(
            502,
            acknowledgement,
            TCP_ACK | TCP_PSH,
            &framed[1..],
        ))
        .unwrap()
    else {
        panic!("expected completed split query");
    };
    let replies = proxy.complete(token, &[]).unwrap();
    let payload = replies
        .iter()
        .flat_map(|packet| packet[40..].iter().copied())
        .collect::<Vec<_>>();
    assert_eq!(read_u16(&payload, 4) & 0x000f, 2);
}
