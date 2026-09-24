use super::*;

#[test]
fn connected_is_reserved_for_the_healthy_phase() {
    for phase in [
        ConnectionPhase::PermissionRequired,
        ConnectionPhase::Starting,
        ConnectionPhase::Connecting,
        ConnectionPhase::Degraded,
        ConnectionPhase::Reconnecting,
        ConnectionPhase::Failed,
    ] {
        assert_ne!(phase_label(Locale::EnUs, phase), "Connected");
    }
    assert_eq!(
        phase_label(Locale::EnUs, ConnectionPhase::Healthy),
        "Connected"
    );
}

#[test]
fn snapshot_sequence_is_not_deserialized_from_untrusted_payload() {
    let mut snapshot: MobileRuntimeSnapshot = serde_json::from_value(json!({
        "sequence": 999,
        "profile": null,
        "connection": "stopped",
        "tasks": {},
        "relays": {},
        "direct_peer_count": 0,
        "signed_state": {},
        "rotation": {},
        "last_error": null,
        "legacy_profile_present": false
    }))
    .unwrap();
    assert_eq!(snapshot.sequence, 0);
    snapshot.sequence = 4;
    assert_eq!(snapshot.sequence, 4);
}

#[test]
fn unknown_or_partial_system_observation_never_displays_verified_lock() {
    for value in [
        json!({}),
        json!({"always_on":true}),
        json!({"always_on":false,"lockdown":true}),
        json!({"always_on":true,"lockdown":false}),
    ] {
        let status: VpnProtectionStatus = serde_json::from_value(value).unwrap();
        assert_ne!(status.label(Locale::EnUs), "System VPN lock verified");
    }
    let status = VpnProtectionStatus {
        always_on: Some(true),
        lockdown: Some(true),
    };
    assert_eq!(status.label(Locale::EnUs), "System VPN lock verified");
}
