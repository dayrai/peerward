use super::*;

fn assembler() -> Reassembler {
    Reassembler::new(Budget::new(1024 * 1024), Budget::new(1024 * 1024))
}

#[test]
fn reverse_order_duplicates_and_maximum_ciphertext_roundtrip() {
    for size in [1, 1280 + 96, MAX_FRAME] {
        let payload = (0..size)
            .map(|i| u8::try_from(i % 251).unwrap())
            .collect::<Vec<_>>();
        let parts = split(1, &payload, 1150).unwrap();
        assert!(parts.iter().all(|part| part.len() <= 1150));
        let mut receiver = assembler();
        let now = Instant::now();
        for (index, part) in parts.iter().rev().enumerate() {
            let complete = receiver.push(part, now).unwrap();
            if index == parts.len() - 1 {
                assert_eq!(complete, Some(payload.clone()));
            } else {
                assert!(complete.is_none());
            }
            assert!(receiver.push(part, now).unwrap().is_none());
        }
        assert_eq!(receiver.buffered(), 0);
        assert_eq!(receiver.incomplete(), 0);
        assert_eq!(receiver.process.used(), 0);
        assert_eq!(receiver.mesh.used(), 0);
    }
}

#[test]
fn missing_fragment_expires_without_renewal_or_replay_resurrection() {
    let parts = split(1, &[7; 3000], 1100).unwrap();
    let mut receiver = assembler();
    let now = Instant::now();
    receiver.push(&parts[0], now).unwrap();
    receiver
        .push(&parts[0], now + Duration::from_secs(1))
        .unwrap();
    receiver
        .push(&parts[1], now + Duration::from_millis(1999))
        .unwrap();
    receiver.expire(now + LIFETIME);
    for part in &parts {
        assert!(receiver.push(part, now + LIFETIME).unwrap().is_none());
    }
    assert_eq!(receiver.buffered(), 0);
    assert_eq!(receiver.process.used(), 0);
}

#[test]
fn malformed_geometry_cannot_allocate_or_return_partial_ciphertext() {
    let original = split(1, &[1; 2000], 1100).unwrap().remove(0);
    let mut invalid = vec![
        vec![],
        vec![0; HEADER],
        original[..original.len() - 1].to_vec(),
    ];
    for (range, value) in [
        (0..4, vec![0; 4]),
        (4..12, vec![0; 8]),
        (12..16, 65_536_u32.to_be_bytes().to_vec()),
        (16..18, vec![0; 2]),
        (18..20, 2_u16.to_be_bytes().to_vec()),
        (20..22, 65_u16.to_be_bytes().to_vec()),
        (22..24, vec![1; 2]),
    ] {
        let mut bytes = original.clone();
        bytes[range].copy_from_slice(&value);
        invalid.push(bytes);
    }
    let mut receiver = assembler();
    for bytes in invalid {
        assert!(receiver.push(&bytes, Instant::now()).is_err());
        assert_eq!(receiver.buffered(), 0);
    }
    assert!(split(0, &[1], 1200).is_err());
    assert!(split(1, &[], 1200).is_err());
    assert!(split(1, &vec![1; MAX_FRAME + 1], 1200).is_err());
    assert!(split(1, &[1], HEADER).is_err());
    assert!(split(1, &vec![1; MAX_FRAME], HEADER + 1).is_err());
}

#[test]
fn conflicting_fragments_retire_the_whole_frame_and_release_budgets() {
    let now = Instant::now();
    let parts = split(1, &[1; 2000], 1100).unwrap();
    let mut receiver = assembler();
    receiver.push(&parts[0], now).unwrap();
    let mut altered = parts[0].clone();
    *altered.last_mut().unwrap() ^= 1;
    assert!(receiver.push(&altered, now).is_err());
    assert!(receiver.push(&parts[1], now).unwrap().is_none());
    assert_eq!(receiver.process.used(), 0);
    let first = split(2, &[1; 2000], 1100).unwrap().remove(0);
    let changed = split(2, &[1; 3000], 1100).unwrap().remove(0);
    receiver.push(&first, now).unwrap();
    assert!(receiver.push(&changed, now).is_err());
    assert_eq!(receiver.mesh.used(), 0);
}

#[test]
fn process_mesh_connection_and_frame_count_limits_release_on_drop() {
    let now = Instant::now();
    let process = Budget::new(5000);
    let mesh = Budget::new(3000);
    let mut a = Reassembler::new(process.clone(), mesh.clone());
    let mut b = Reassembler::new(process.clone(), mesh.clone());
    let frame = split(1, &[1; 2000], 1100).unwrap();
    a.push(&frame[0], now).unwrap();
    b.push(&frame[0], now).unwrap(); // Mesh reservation fails, process rolled back.
    assert_eq!(process.used(), 2000);
    assert_eq!(mesh.used(), 2000);
    let other_mesh = Budget::new(10_000);
    let mut c = Reassembler::new(process.clone(), other_mesh.clone());
    c.push(&frame[0], now).unwrap();
    c.push(&split(2, &[1; 2000], 1100).unwrap()[0], now)
        .unwrap();
    assert_eq!(process.used(), 4000);
    drop(a);
    drop(b);
    drop(c);
    assert_eq!(process.used(), 0);
    assert_eq!(mesh.used(), 0);
    assert_eq!(other_mesh.used(), 0);
    let mut receiver = assembler();
    for id in 1..=100 {
        receiver
            .push(&split(id, &[1; 2000], 1100).unwrap()[0], now)
            .unwrap();
    }
    assert_eq!(receiver.incomplete(), MAX_INCOMPLETE);
    assert_eq!(receiver.buffered(), MAX_INCOMPLETE * 2000);
    let mut receiver = assembler();
    for id in 1..=100 {
        receiver
            .push(&split(id, &vec![1; MAX_FRAME], 1200).unwrap()[0], now)
            .unwrap();
    }
    assert_eq!(receiver.incomplete(), 4);
    assert!(receiver.buffered() <= MAX_BUFFERED);
}

#[test]
fn retired_horizon_accepts_reordering_and_rejects_old_or_completed_ids() {
    let mut retired = Retired::default();
    for id in [1, 3, 2, 64, 66, 65, 1025] {
        assert!(!retired.contains(id));
        retired.insert(id);
    }
    for id in [1, 2, 3, 64, 65, 66, 1025] {
        assert!(retired.contains(id));
    }
    assert!(!retired.contains(63));
    assert!(!retired.contains(1026));
    retired.insert(u64::MAX);
    assert!(retired.contains(1026));
    assert!(retired.contains(u64::MAX));
    assert!(!retired.contains(u64::MAX - 1));
}

#[test]
fn concurrent_connections_cannot_exceed_the_shared_process_budget() {
    let budget = Budget::new(4096);
    std::thread::scope(|scope| {
        for _ in 0..16 {
            let budget = budget.clone();
            scope.spawn(move || {
                for _ in 0..1000 {
                    let reservation = budget.reserve(1000);
                    assert!(budget.used() <= 4096);
                    std::thread::yield_now();
                    drop(reservation);
                }
            });
        }
    });
    assert_eq!(budget.used(), 0);
}
