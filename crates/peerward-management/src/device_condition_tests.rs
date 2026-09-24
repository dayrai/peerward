use super::*;

#[test]
fn evidence_requires_known_fresh_software_and_verified_credential() {
    let mut conditions = DeviceConditions {
        enabled: true,
        minimum_version: Some(env!("CARGO_PKG_VERSION").into()),
        minimum_credential_seconds: 60,
        ..Default::default()
    };
    let mut evidence = DeviceEvidence::current(DevicePlatform::Linux);
    assert!(
        conditions
            .evaluate(Some(&evidence), 1000, 2000, 100)
            .permits(999)
    );
    assert!(
        !conditions
            .evaluate(Some(&evidence), 1000, 2000, 100)
            .permits(1000)
    );
    assert!(!conditions.evaluate(None, 1000, 2000, 100).allowed);
    assert!(!conditions.evaluate(Some(&evidence), 1000, 150, 100).allowed);
    evidence.version = "0.0.0".into();
    assert_eq!(
        conditions
            .evaluate(Some(&evidence), 1000, 2000, 100)
            .reasons,
        vec![AdmissionReason::Version]
    );
    evidence.version = format!("{}+build123", env!("CARGO_PKG_VERSION"));
    assert!(
        conditions
            .evaluate(Some(&evidence), 1000, 2000, 100)
            .allowed
    );
    conditions
        .required_capabilities
        .insert(DeviceCapability::SubnetGateway);
    assert!(
        !conditions
            .evaluate(
                Some(&DeviceEvidence::current(DevicePlatform::Android)),
                1000,
                2000,
                100
            )
            .allowed
    );
    conditions.platforms.insert(DevicePlatform::Android);
    assert!(
        conditions
            .evaluate(Some(&evidence), 1000, 2000, 100)
            .reasons
            .contains(&AdmissionReason::Platform)
    );
    let mut forged = DeviceEvidence::current(DevicePlatform::Android);
    forged.capabilities.insert(DeviceCapability::ExitGateway);
    assert!(forged.validate().is_err());
}

#[test]
fn admission_refresh_extends_deadline_but_does_not_undo_restrictions() {
    let peer = peerward_types::PeerId::new();
    let old = AdmissionConfiguration {
        enabled: true,
        peers: [(
            peer,
            AdmissionDecision {
                allowed: true,
                valid_until: Some(100),
                reasons: vec![],
            },
        )]
        .into(),
    };
    let mut new = old.clone();
    new.peers.get_mut(&peer).unwrap().valid_until = Some(200);
    assert!(old.same_requirements(&new));
    assert!(!new.same_requirements(&old));
    new.peers.get_mut(&peer).unwrap().allowed = false;
    assert!(!old.same_requirements(&new));
    assert!(!old.permits(peerward_types::PeerId::new(), 10));
    let old = DeviceConditions {
        enabled: true,
        minimum_version: Some("1.0.0".into()),
        ..Default::default()
    };
    let mut new = old.clone();
    new.minimum_version = Some("1.1.0".into());
    assert!(new.only_restricts(&old));
    assert!(!old.only_restricts(&new));
    new.enabled = false;
    assert!(!new.only_restricts(&old));
}
