#![no_main]

use libfuzzer_sys::fuzz_target;
use peerward_dataplane::{FragmentReassembler, ReassemblyStatus, parse_packet};
use peerward_updater::ReleaseManifest;
use peerward_wire::RelayEnvelopeV2;
use prost::Message;

fuzz_target!(|bytes: &[u8]| {
    if let Ok(envelope) = RelayEnvelopeV2::decode(bytes) {
        let _ = envelope.validate_from_peer();
        let _ = envelope.validate_for_relay();
    }
    let now = bytes
        .get(..8)
        .and_then(|value| value.try_into().ok())
        .map(u64::from_le_bytes)
        .unwrap_or_default();
    let mut reassembler = FragmentReassembler::default();
    let _ = reassembler.push(bytes, now);
    let _ = reassembler.expire(now.saturating_add(16));

    // Length-prefixed sequences exercise pending/completion/overlap paths;
    // the original single-packet corpus remains valid above.
    if let Some(mut sequence) = bytes.strip_prefix(b"PWFR") {
        for tick in 0..64 {
            let Some(length) = sequence.get(..2) else {
                break;
            };
            let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
            sequence = &sequence[2..];
            let Some(packet) = sequence.get(..length) else {
                break;
            };
            if let Ok(ReassemblyStatus::Complete(datagram)) = reassembler.push(packet, tick) {
                assert!(parse_packet(&datagram.packet).is_ok());
                assert!(!datagram.original_fragments.is_empty());
            }
            sequence = &sequence[length..];
        }
        reassembler.expire(u64::MAX);
        assert_eq!(reassembler.retained_bytes(), 0);
    }

    if let Ok(manifest) = serde_json::from_slice::<ReleaseManifest>(bytes) {
        // Derive compatibility inputs from the document so the harness remains
        // useful across releases, and reaches beyond the timestamp gate.
        for time in [now, manifest.published_at, manifest.expires_at] {
            let _ = manifest.validate_candidate(
                time,
                0,
                &manifest.version,
                manifest.schema_compatibility.min,
                manifest.wire_compatibility.min,
            );
        }
        let candidate = |time, sequence, schema| {
            manifest.validate_candidate(
                time,
                sequence,
                &manifest.version,
                schema,
                manifest.wire_compatibility.min,
            )
        };
        let schema = manifest.schema_compatibility.min;
        if candidate(manifest.published_at, manifest.sequence, schema).is_ok() {
            assert!(candidate(manifest.expires_at, manifest.sequence, schema).is_err());
            assert!(candidate(manifest.published_at, manifest.sequence, schema - 1).is_err());
            if let Some(next_sequence) = manifest.sequence.checked_add(1) {
                assert!(candidate(manifest.published_at, next_sequence, schema).is_err());
            }
        }
    }
});
