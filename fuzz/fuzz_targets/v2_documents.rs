#![no_main]

use std::str::FromStr;

use libfuzzer_sys::fuzz_target;
use peerward_policy::decode_policy_document;
use peerward_service::{
    RemoteServiceTable, ServiceSnapshotSigningKey, SignedRemoteServiceSnapshot,
};
use peerward_types::{MeshId, NetworkEndpoint};

fuzz_target!(|bytes: &[u8]| {
    let _ = decode_policy_document(1, bytes);
    if let Ok(text) = std::str::from_utf8(bytes) {
        if let Ok(endpoint) = text.parse::<NetworkEndpoint>() {
            assert_eq!(
                endpoint.as_str().parse::<NetworkEndpoint>().unwrap(),
                endpoint
            );
            assert_eq!(
                serde_json::from_str::<NetworkEndpoint>(&serde_json::to_string(&endpoint).unwrap())
                    .unwrap(),
                endpoint
            );
        }
    }

    if let Ok(snapshot) = serde_json::from_slice::<SignedRemoteServiceSnapshot>(bytes) {
        let mesh =
            MeshId::from_str("4381ef28-b176-446b-9929-cd827d36f46f").expect("fixed mesh UUIDv4");
        let signing = ServiceSnapshotSigningKey::from_bytes(&[31; 32]);
        let mut table = RemoteServiceTable::new(mesh, signing.verifier());
        let _ = table.reconcile(&snapshot);
    }
});
