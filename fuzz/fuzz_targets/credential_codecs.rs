#![no_main]

use libfuzzer_sys::fuzz_target;
use peerward_credentials::{AuthorityCertificate, DistributionCertificate, SubjectCredential};

fuzz_target!(|bytes: &[u8]| {
    let _ = AuthorityCertificate::decode(bytes);
    let _ = SubjectCredential::decode(bytes);
    let _ = DistributionCertificate::decode(bytes);
});
