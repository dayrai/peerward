#![no_main]

use libfuzzer_sys::fuzz_target;
use peerward_dataplane::parse_packet;
use peerward_directory::{decode_peer_directory, decode_policy, decode_relay_directory};

fuzz_target!(|bytes: &[u8]| {
    let _ = parse_packet(bytes);
    let _ = decode_peer_directory(bytes);
    let _ = decode_relay_directory(bytes);
    let _ = decode_policy(bytes);
});
