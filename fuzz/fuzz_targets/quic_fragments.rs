#![no_main]
use libfuzzer_sys::fuzz_target;
use peerward_carrier::fragments::{self, Budget, Reassembler};
use std::time::{Duration, Instant};

fuzz_target!(|data: &[u8]| {
    let process = Budget::new(128 * 1024);
    let mesh = Budget::new(96 * 1024);
    let mut left = Reassembler::new(process.clone(), mesh.clone());
    let mut right = Reassembler::new(process.clone(), mesh.clone());
    let mut now = Instant::now();
    if data.first().is_some_and(|byte| byte & 1 == 1) {
        let payload = &data[1..data.len().min(fragments::MAX_FRAME + 1)];
        let limit = data.get(1).map_or(1200, |byte| 1024 + usize::from(*byte));
        if let Ok(parts) = fragments::split(1, payload, limit) {
            let mut completed = None;
            for part in parts.iter().rev() {
                if let Some(frame) = left.push(part, now).unwrap() { completed = Some(frame); }
                assert!(left.push(part, now).unwrap().is_none());
            }
            assert_eq!(completed.as_deref(), Some(payload));
        }
    } else {
        let mut bytes = data.get(1..).unwrap_or_default();
        for index in 0..128 {
            if bytes.len() < 4 { break; }
            let count = usize::from(u16::from_be_bytes([bytes[0], bytes[1]])).min(bytes.len() - 4);
            now += Duration::from_millis(u64::from(u16::from_be_bytes([bytes[2], bytes[3]])));
            let target = if index % 2 == 0 { &mut left } else { &mut right };
            if let Ok(Some(frame)) = target.push(&bytes[4..4 + count], now) {
                assert!(!frame.is_empty() && frame.len() <= fragments::MAX_FRAME);
            }
            left.expire(now); right.expire(now);
            assert!(left.incomplete() <= fragments::MAX_INCOMPLETE);
            assert!(right.incomplete() <= fragments::MAX_INCOMPLETE);
            assert_eq!(left.buffered() + right.buffered(), process.used());
            assert_eq!(process.used(), mesh.used());
            assert!(process.used() <= 96 * 1024);
            bytes = &bytes[4 + count..];
        }
    }
    drop(left); drop(right);
    assert_eq!(process.used(), 0);
    assert_eq!(mesh.used(), 0);
});
