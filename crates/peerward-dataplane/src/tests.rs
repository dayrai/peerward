use std::str::FromStr;

use super::*;

#[path = "reassembly_tests.rs"]
mod reassembly_tests;

#[path = "state_tests.rs"]
mod state_tests;

fn checksum(header: &mut [u8]) {
    header[10] = 0;
    header[11] = 0;
    let value = ipv4_checksum(header);
    header[10..12].copy_from_slice(&value.to_be_bytes());
}

fn set_transport_checksum(packet: &mut [u8], start: usize, protocol: u8, field: usize) {
    packet[start + field..start + field + 2].fill(0);
    let source = match packet[0] >> 4 {
        4 => IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )),
        6 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[8..24]).unwrap(),
        )),
        _ => unreachable!(),
    };
    let destination = match packet[0] >> 4 {
        4 => IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )),
        6 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[24..40]).unwrap(),
        )),
        _ => unreachable!(),
    };
    let payload = &packet[start..];
    let mut sum = 0_u32;
    match (source, destination) {
        (IpAddr::V4(source), IpAddr::V4(destination)) => {
            sum = checksum_words(sum, &source.octets());
            sum = checksum_words(sum, &destination.octets());
            sum += u32::from(protocol) + u32::try_from(payload.len()).unwrap();
        }
        (IpAddr::V6(source), IpAddr::V6(destination)) => {
            sum = checksum_words(sum, &source.octets());
            sum = checksum_words(sum, &destination.octets());
            sum = checksum_words(sum, &u32::try_from(payload.len()).unwrap().to_be_bytes());
            sum += u32::from(protocol);
        }
        _ => unreachable!(),
    }
    sum = checksum_words(sum, payload);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let value = !u16::try_from(sum).unwrap();
    packet[start + field..start + field + 2].copy_from_slice(&value.to_be_bytes());
}

fn ipv4_tcp(source: [u8; 4], destination: [u8; 4], flags: u8) -> Vec<u8> {
    let mut packet = vec![0_u8; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&40_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = TCP;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    checksum(&mut packet[..20]);
    packet[20..22].copy_from_slice(&50_000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&443_u16.to_be_bytes());
    packet[32] = 5 << 4;
    packet[33] = flags;
    set_transport_checksum(&mut packet, 20, TCP, 16);
    packet
}

fn reverse_tcp(packet: &[u8], flags: u8) -> Vec<u8> {
    let mut reversed = packet.to_vec();
    reversed[12..16].copy_from_slice(&packet[16..20]);
    reversed[16..20].copy_from_slice(&packet[12..16]);
    reversed[20..22].copy_from_slice(&packet[22..24]);
    reversed[22..24].copy_from_slice(&packet[20..22]);
    reversed[33] = flags;
    checksum(&mut reversed[..20]);
    set_transport_checksum(&mut reversed, 20, TCP, 16);
    reversed
}

fn allow_https() -> Rule {
    Rule {
        id: RuleId::new(),
        priority: 1,
        action: Action::Allow,
        source: Some(IpNet::from_str("10.0.0.0/24").unwrap()),
        destination: Some(IpNet::from_str("10.0.1.0/24").unwrap()),
        protocol: Some(TCP),
        destination_ports: vec![443..=443],
    }
}

fn ipv4_udp(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut packet = vec![0_u8; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = UDP;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&53_000_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&53_u16.to_be_bytes());
    packet[24..26].copy_from_slice(&8_u16.to_be_bytes());
    checksum(&mut packet[..20]);
    packet
}

fn fragmented_udp() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut complete = vec![0_u8; 44];
    complete[0] = 0x45;
    complete[2..4].copy_from_slice(&44_u16.to_be_bytes());
    complete[4..6].copy_from_slice(&91_u16.to_be_bytes());
    complete[8] = 64;
    complete[9] = UDP;
    complete[12..16].copy_from_slice(&[10, 0, 0, 2]);
    complete[16..20].copy_from_slice(&[10, 0, 1, 53]);
    complete[20..22].copy_from_slice(&53_000_u16.to_be_bytes());
    complete[22..24].copy_from_slice(&53_u16.to_be_bytes());
    complete[24..26].copy_from_slice(&24_u16.to_be_bytes());
    complete[28..].copy_from_slice(&[0x5a; 16]);
    set_transport_checksum(&mut complete, 20, UDP, 6);
    checksum(&mut complete[..20]);

    let mut first = complete[..36].to_vec();
    first[2..4].copy_from_slice(&36_u16.to_be_bytes());
    first[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
    checksum(&mut first[..20]);
    let mut last = complete[..20].to_vec();
    last.extend_from_slice(&complete[36..44]);
    last[2..4].copy_from_slice(&28_u16.to_be_bytes());
    last[6..8].copy_from_slice(&2_u16.to_be_bytes());
    checksum(&mut last[..20]);
    (complete, first, last)
}

#[test]
fn ipv4_checksum_lengths_and_tcp_are_strict() {
    let packet = ipv4_tcp([10, 0, 0, 2], [10, 0, 1, 2], TCP_SYN);
    let parsed = parse_packet(&packet).unwrap();
    assert_eq!(parsed.destination_port, Some(443));
    let mut corrupt = packet.clone();
    corrupt[8] ^= 1;
    assert_eq!(parse_packet(&corrupt), Err(ParseError::Malformed));
    assert_eq!(parse_packet(&packet[..39]), Err(ParseError::Malformed));
    let mut bad_tcp_checksum = packet.clone();
    bad_tcp_checksum[39] ^= 1;
    assert_eq!(parse_packet(&bad_tcp_checksum), Err(ParseError::Malformed));
    let mut bad_data_offset = packet.clone();
    bad_data_offset[32] = 4 << 4;
    set_transport_checksum(&mut bad_data_offset, 20, TCP, 16);
    assert_eq!(parse_packet(&bad_data_offset), Err(ParseError::Malformed));
}

#[test]
fn tcp_requires_handshake_and_denies_unsolicited_ack() {
    let firewall = Firewall::new(1, Action::Deny, vec![allow_https()], 32, 4);
    let syn = ipv4_tcp([10, 0, 0, 2], [10, 0, 1, 2], TCP_SYN);
    assert_eq!(
        firewall.evaluate(&parse_packet(&syn).unwrap(), 1).action,
        Action::Allow
    );
    let syn_ack = reverse_tcp(&syn, TCP_SYN | TCP_ACK);
    assert!(
        firewall
            .evaluate(&parse_packet(&syn_ack).unwrap(), 2)
            .stateful
    );
    let established_ack = ipv4_tcp([10, 0, 0, 2], [10, 0, 1, 2], TCP_ACK);
    assert!(
        firewall
            .evaluate(&parse_packet(&established_ack).unwrap(), 3)
            .stateful
    );
    let reset = reverse_tcp(&syn, TCP_RST | TCP_ACK);
    assert!(
        firewall
            .evaluate(&parse_packet(&reset).unwrap(), 4)
            .stateful
    );
    assert_eq!(
        firewall
            .evaluate(&parse_packet(&established_ack).unwrap(), 5)
            .action,
        Action::Deny
    );
    let ack = ipv4_tcp([10, 0, 0, 9], [10, 0, 1, 9], TCP_ACK);
    assert_eq!(
        firewall.evaluate(&parse_packet(&ack).unwrap(), 2).action,
        Action::Deny
    );
}

#[test]
fn related_icmp_error_requires_existing_udp_state() {
    let udp_rule = Rule {
        id: RuleId::new(),
        priority: 1,
        action: Action::Allow,
        source: None,
        destination: None,
        protocol: Some(UDP),
        destination_ports: vec![53..=53],
    };
    let firewall = Firewall::new(1, Action::Deny, vec![udp_rule], 16, 2);
    let udp = ipv4_udp([10, 0, 0, 2], [10, 0, 1, 53]);
    assert_eq!(
        firewall.evaluate(&parse_packet(&udp).unwrap(), 1).action,
        Action::Allow
    );
    let mut icmp = vec![0_u8; 56];
    icmp[0] = 0x45;
    icmp[2..4].copy_from_slice(&56_u16.to_be_bytes());
    icmp[8] = 64;
    icmp[9] = ICMP_V4;
    icmp[12..16].copy_from_slice(&[10, 0, 1, 53]);
    icmp[16..20].copy_from_slice(&[10, 0, 0, 2]);
    icmp[20] = 3;
    icmp[21] = 3;
    icmp[28..56].copy_from_slice(&udp);
    let icmp_checksum = internet_checksum(&icmp[20..]);
    icmp[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());
    checksum(&mut icmp[..20]);
    let parsed = parse_packet(&icmp).unwrap();
    assert!(parsed.related_flow.is_some());
    assert!(firewall.evaluate(&parsed, 2).stateful);
}

#[test]
fn tcp_handshake_retransmissions_preserve_direction_and_phase() {
    let mut firewall = Firewall::new(1, Action::Deny, vec![allow_https()], 16, 2);
    let syn = parse_packet(&ipv4_tcp([10, 0, 0, 2], [10, 0, 1, 2], TCP_SYN)).unwrap();
    let mut syn_ack = syn.clone();
    std::mem::swap(&mut syn_ack.source, &mut syn_ack.destination);
    std::mem::swap(&mut syn_ack.source_port, &mut syn_ack.destination_port);
    syn_ack.tcp_flags = Some(TCP_SYN | TCP_ACK);
    let mut ack = syn.clone();
    ack.tcp_flags = Some(TCP_ACK);
    assert_eq!(firewall.evaluate(&syn, 1).action, Action::Allow);
    assert_eq!(firewall.evaluate(&ack, 2).action, Action::Deny);
    for (now, packet) in [
        (3, &syn),
        (4, &syn_ack),
        (5, &syn),
        (6, &syn_ack),
        (7, &ack),
    ] {
        let decision = firewall.evaluate(packet, now);
        assert_eq!(decision.action, Action::Allow, "handshake step {now}");
        assert!(decision.stateful);
    }
    assert_eq!(firewall.state_len(), 1);
    assert!(firewall.replace(2, Action::Deny, Vec::new()));
    assert_eq!(firewall.evaluate(&syn, 8).action, Action::Deny);
    assert_eq!(firewall.evaluate(&syn_ack, 8).action, Action::Deny);
}

#[test]
fn fragments_need_a_permitted_first_fragment_and_expire() {
    let firewall = Firewall::new(1, Action::Deny, vec![allow_https()], 32, 2);
    let mut first = ipv4_tcp([10, 0, 0, 2], [10, 0, 1, 2], TCP_SYN);
    first[4..6].copy_from_slice(&77_u16.to_be_bytes());
    first[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
    checksum(&mut first[..20]);
    assert_eq!(
        firewall.evaluate(&parse_packet(&first).unwrap(), 5).action,
        Action::Allow
    );
    let mut later = vec![0_u8; 28];
    later[0] = 0x45;
    later[2..4].copy_from_slice(&28_u16.to_be_bytes());
    later[4..6].copy_from_slice(&77_u16.to_be_bytes());
    later[6..8].copy_from_slice(&1_u16.to_be_bytes());
    later[8] = 64;
    later[9] = TCP;
    later[12..16].copy_from_slice(&[10, 0, 0, 2]);
    later[16..20].copy_from_slice(&[10, 0, 1, 2]);
    checksum(&mut later[..20]);
    assert_eq!(
        firewall.evaluate(&parse_packet(&later).unwrap(), 6).action,
        Action::Allow
    );
    assert_eq!(
        firewall.evaluate(&parse_packet(&later).unwrap(), 21).action,
        Action::Deny
    );
}

#[test]
fn ipv6_udp_and_extension_bounds_parse() {
    let mut packet = vec![0_u8; 56];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&16_u16.to_be_bytes());
    packet[6] = 60;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    packet[24..40].copy_from_slice(&Ipv6Addr::from_str("fd00::2").unwrap().octets());
    packet[40] = UDP;
    packet[41] = 0;
    packet[48..50].copy_from_slice(&1000_u16.to_be_bytes());
    packet[50..52].copy_from_slice(&2000_u16.to_be_bytes());
    packet[52..54].copy_from_slice(&8_u16.to_be_bytes());
    set_transport_checksum(&mut packet, 48, UDP, 6);
    let parsed = parse_packet(&packet).unwrap();
    assert_eq!(parsed.protocol, UDP);
    assert_eq!(parsed.source_port, Some(1000));
    let mut missing_checksum = packet.clone();
    missing_checksum[54..56].fill(0);
    assert_eq!(parse_packet(&missing_checksum), Err(ParseError::Malformed));

    let ipv4_zero_checksum = ipv4_udp([10, 0, 0, 2], [10, 0, 1, 53]);
    assert!(parse_packet(&ipv4_zero_checksum).is_ok());
}

#[test]
fn fragment_reassembly_is_bounded_order_independent_and_checksum_strict() {
    let (complete, first, last) = fragmented_udp();
    let mut reassembler = FragmentReassembler::default();
    assert_eq!(
        reassembler.push(&last, 1).unwrap(),
        ReassemblyStatus::Pending
    );
    let ReassemblyStatus::Complete(datagram) = reassembler.push(&first, 2).unwrap() else {
        panic!("fragment set must complete")
    };
    assert_eq!(datagram.packet, complete);
    assert_eq!(datagram.original_fragments, vec![first.clone(), last]);
    assert_eq!(reassembler.retained_bytes(), 0);
    assert!(parse_packet(&datagram.packet).is_ok());

    let mut overlap = first.clone();
    overlap[6..8].copy_from_slice(&1_u16.to_be_bytes());
    checksum(&mut overlap[..20]);
    assert_eq!(
        reassembler.push(&first, 3).unwrap(),
        ReassemblyStatus::Pending
    );
    assert_eq!(reassembler.push(&overlap, 4), Err(ReassemblyError::Overlap));
    assert_eq!(reassembler.retained_bytes(), 0);

    assert_eq!(
        reassembler.push(&first, 5).unwrap(),
        ReassemblyStatus::Pending
    );
    let mut misaligned = first.clone();
    misaligned.push(0);
    misaligned[2..4].copy_from_slice(&37_u16.to_be_bytes());
    checksum(&mut misaligned[..20]);
    assert_eq!(
        reassembler.push(&misaligned, 6),
        Err(ReassemblyError::Malformed)
    );
    assert_eq!(reassembler.retained_bytes(), 0);

    let mut expiring = FragmentReassembler::new(128, 128, 15).unwrap();
    assert_eq!(
        expiring.push(&first, 10).unwrap(),
        ReassemblyStatus::Pending
    );
    assert_eq!(expiring.expire(25), 1);
    assert_eq!(expiring.retained_bytes(), 0);
}

#[test]
fn ipv6_fragmentable_extensions_reassemble_without_parsing_later_payload() {
    // Destination Options belongs to the fragmentable part and appears only
    // in offset zero. Later bytes deliberately resemble an invalid extension.
    let mut complete = vec![0_u8; 72];
    complete[0] = 0x60;
    complete[4..6].copy_from_slice(&32_u16.to_be_bytes());
    complete[6] = 60;
    complete[7] = 64;
    complete[8..24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
    complete[24..40].copy_from_slice(&Ipv6Addr::from_str("fd00::2").unwrap().octets());
    complete[40] = UDP;
    complete[48..50].copy_from_slice(&1000_u16.to_be_bytes());
    complete[50..52].copy_from_slice(&2000_u16.to_be_bytes());
    complete[52..54].copy_from_slice(&24_u16.to_be_bytes());
    complete[56..].fill(0xff);
    set_transport_checksum(&mut complete, 48, UDP, 6);
    assert!(parse_packet(&complete).is_ok());

    let fragment = |offset: u16, more: bool, payload: &[u8]| {
        let mut packet = complete[..40].to_vec();
        packet[4..6].copy_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
        packet[6] = 44;
        packet.extend_from_slice(&[60, 0]);
        packet.extend_from_slice(&((offset << 3) | u16::from(more)).to_be_bytes());
        packet.extend_from_slice(&77_u32.to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    };
    let first = fragment(0, true, &complete[40..56]);
    let last = fragment(2, false, &complete[56..]);
    assert!(
        parse_packet(&last).is_ok(),
        "later payload is not an extension header"
    );
    for next_header in [60, UDP, 44] {
        let mut last = last.clone();
        // RFC 8200 section 4.5 uses only offset zero's Next Header value.
        last[40] = next_header;
        for packets in [[&first, &last], [&last, &first]] {
            let mut reassembler = FragmentReassembler::default();
            assert_eq!(
                reassembler.push(packets[0], 1).unwrap(),
                ReassemblyStatus::Pending
            );
            let ReassemblyStatus::Complete(datagram) = reassembler.push(packets[1], 2).unwrap()
            else {
                panic!("IPv6 fragments must share the same reassembly identity")
            };
            assert_eq!(datagram.packet, complete);
            assert_eq!(
                datagram.original_fragments,
                vec![first.clone(), last.clone()]
            );
            assert_eq!(reassembler.retained_bytes(), 0);
        }
    }
    let firewall = Firewall::new(1, Action::Deny, vec![], 32, 1);
    let parsed_last = parse_packet(&last).unwrap();
    assert_eq!(firewall.evaluate(&parsed_last, 1).action, Action::Deny);
    firewall.evaluate_with_policy(&parse_packet(&first).unwrap(), 2, |_| (Action::Allow, None));
    assert_eq!(firewall.evaluate(&parsed_last, 3).action, Action::Allow);
    assert_eq!(firewall.evaluate(&parsed_last, 17).action, Action::Deny);
}

#[test]
fn expired_return_flow_is_denied_even_with_a_cleanup_backlog() {
    let firewall = Firewall::new(1, Action::Deny, vec![], 1_024, 1);
    let mut outgoing = parse_packet(&ipv4_udp([10, 0, 0, 2], [10, 0, 1, 53])).unwrap();
    // A lookup has two bounded cleanup sweeps (forward/reverse). Keep one more
    // expired entry than both sweeps can remove, using the production budget.
    let count = u16::try_from(firewall.expiry_budget * 2 + 1).unwrap();
    for port in 1_000..1_000 + count {
        outgoing.source_port = Some(port);
        assert_eq!(
            firewall
                .evaluate_with_policy(&outgoing, 1, |_| (Action::Allow, None))
                .action,
            Action::Allow,
        );
    }
    let delayed = firewall.shards[0]
        .lock()
        .unwrap()
        .flow_expirations
        .iter()
        .last()
        .unwrap()
        .1
        .clone();
    outgoing.source_port = delayed.source_port;
    let mut reply = outgoing.clone();
    reply.source = delayed.destination;
    reply.destination = delayed.source;
    reply.source_port = delayed.destination_port;
    reply.destination_port = delayed.source_port;
    let expired_at = 1 + firewall.flow_timeout;
    assert_eq!(firewall.evaluate(&reply, expired_at).action, Action::Deny);
    let restarted = firewall.evaluate_with_policy(&outgoing, expired_at, |_| (Action::Allow, None));
    assert_eq!(restarted.action, Action::Allow);
    assert!(
        !restarted.stateful,
        "expired flow was revived without checking initiation policy"
    );
    assert!(firewall.evaluate(&reply, expired_at + 1).stateful);
}
