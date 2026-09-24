use super::*;

fn fragment(complete: &[u8], start: usize, end: usize, more: bool) -> Vec<u8> {
    let mut packet = complete[..20].to_vec();
    packet.extend_from_slice(&complete[20 + start..20 + end]);
    let length = u16::try_from(packet.len()).unwrap();
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    let offset = u16::try_from(start / 8).unwrap() | if more { 0x2000 } else { 0 };
    packet[6..8].copy_from_slice(&offset.to_be_bytes());
    checksum(&mut packet[..20]);
    packet
}

#[test]
fn gaps_are_not_completed_until_every_byte_arrives_in_any_order() {
    let (complete, _, _) = fragmented_udp();
    let pieces = [
        fragment(&complete, 0, 8, true),
        fragment(&complete, 8, 16, true),
        fragment(&complete, 16, 24, false),
    ];
    for order in [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ] {
        let mut reassembler = FragmentReassembler::default();
        for index in &order[..2] {
            assert_eq!(
                reassembler.push(&pieces[*index], 1).unwrap(),
                ReassemblyStatus::Pending
            );
        }
        let ReassemblyStatus::Complete(datagram) = reassembler.push(&pieces[order[2]], 2).unwrap()
        else {
            panic!("all fragments must complete");
        };
        assert_eq!(datagram.packet, complete);
        assert_eq!(datagram.original_fragments, pieces);
        assert_eq!(reassembler.retained_bytes(), 0);
        assert!(reassembler.expirations.is_empty());
        assert!(reassembler.source_bytes.is_empty());
    }
}

#[test]
fn overlap_with_either_neighbor_discards_the_entire_set() {
    let (complete, _, _) = fragmented_udp();
    for (first, overlap) in [
        (
            fragment(&complete, 0, 16, true),
            fragment(&complete, 8, 24, false),
        ),
        (
            fragment(&complete, 16, 24, false),
            fragment(&complete, 8, 24, true),
        ),
        (
            fragment(&complete, 8, 16, true),
            fragment(&complete, 0, 24, true),
        ),
    ] {
        let mut reassembler = FragmentReassembler::default();
        reassembler.push(&first, 1).unwrap();
        assert_eq!(reassembler.push(&overlap, 2), Err(ReassemblyError::Overlap));
        assert!(reassembler.expirations.is_empty());
        assert!(reassembler.sets.is_empty());
        assert_eq!(reassembler.retained_bytes(), 0);
    }
}

#[test]
fn expiry_index_is_released_on_completion_rejection_and_key_reuse() {
    let (_, first, last) = fragmented_udp();
    let mut reassembler = FragmentReassembler::new(128, 256, 15).unwrap();
    reassembler.push(&first, 10).unwrap();
    reassembler.push(&last, 11).unwrap();
    reassembler.push(&first, 20).unwrap();
    assert_eq!(reassembler.expire(25), 0);
    assert_eq!(reassembler.expirations.len(), 1);
    assert_eq!(reassembler.push(&first, 26), Err(ReassemblyError::Overlap));
    assert!(reassembler.expirations.is_empty());

    // Repeated fragments cannot extend the lifetime of an incomplete set.
    reassembler.push(&first, 30).unwrap();
    assert_eq!(reassembler.expire(44), 0);
    assert_eq!(reassembler.expire(45), 1);
    assert_eq!(reassembler.expire(100), 0);
    assert!(reassembler.sets.is_empty());
    assert!(reassembler.source_bytes.is_empty());
    assert_eq!(reassembler.retained_bytes(), 0);

    let mut limited = FragmentReassembler::new(52, 52, 15).unwrap();
    limited.push(&first, 1).unwrap();
    assert_eq!(limited.push(&last, 2), Err(ReassemblyError::QuotaExceeded));
    assert!(limited.expirations.is_empty());
    assert_eq!(limited.retained_bytes(), 0);
}

#[test]
fn expiry_handles_equal_deadlines_and_nonmonotonic_insert_order() {
    let (_, mut first, _) = fragmented_udp();
    let mut reassembler = FragmentReassembler::default();
    for id in 0_u16..2_000 {
        first[4..6].copy_from_slice(&id.to_be_bytes());
        checksum(&mut first[..20]);
        reassembler
            .push(&first, if id < 1_000 { 20 } else { 10 })
            .unwrap();
    }
    assert_eq!(reassembler.expirations.len(), 2_000);
    assert_eq!(reassembler.expire(25), 1_000);
    assert_eq!(reassembler.expirations.len(), 1_000);
    assert_eq!(reassembler.expire(35), 1_000);
    assert!(reassembler.expirations.is_empty());
    assert!(reassembler.source_bytes.is_empty());
    assert_eq!(reassembler.retained_bytes(), 0);
}
