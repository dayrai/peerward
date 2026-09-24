#![no_main]

use libfuzzer_sys::fuzz_target;
use peerward_p2p::fuzz_mapping_codecs;

fuzz_target!(|bytes: &[u8]| {
    fuzz_mapping_codecs(bytes);
});
