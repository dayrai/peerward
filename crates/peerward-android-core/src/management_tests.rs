use super::*;
use ed25519_dalek::Signer as _;
use peerward_management::{DeviceCapability, DevicePlatform, PeerOperation, SignedPeerCommand};

fn fixture() -> (
    Fixture,
    SharedMobileWireguard,
    NativeSession,
    std::path::PathBuf,
) {
    let f = Fixture::new();
    let path = std::env::temp_dir().join(format!("peerward-evidence-{}", Uuid::new_v4()));
    let owner = f.mobile();
    owner
        .lock()
        .unwrap()
        .core
        .enable_checkpoint(&path, f.now)
        .unwrap();
    let (carrier, _) = f.carrier(&owner);
    (f, owner, carrier, path)
}

fn acknowledge(carrier: &mut NativeSession, committed: bool) {
    let request_id = carrier.pending_management.as_ref().unwrap().request_id;
    carrier.management_result(&peerward_wire::PeerManagementResult {
        request_id: request_id.as_bytes().to_vec(),
        committed,
        error: if committed {
            String::new()
        } else {
            "retry".into()
        },
    });
}

pub(super) fn acknowledge_evidence(
    carrier: &mut NativeSession,
    now: UnixTime,
) -> SignedPeerCommand {
    let transcript = carrier.management_transcript(now).unwrap();
    assert!(!transcript.is_empty());
    let signature = ed25519_dalek::SigningKey::from_bytes(&[11; 32]).sign(&transcript);
    let bytes = carrier.complete_management(signature.to_bytes()).unwrap();
    let envelope = ControlEnvelope::decode(bytes.as_slice()).unwrap();
    let Some(ControlMessage::PeerManagement(body)) = envelope.message else {
        panic!()
    };
    let signed: SignedPeerCommand = serde_json::from_slice(&body.body).unwrap();
    signed
        .verify(&carrier.current_credential.identity_public_key, now.0)
        .unwrap();
    let PeerOperation::DeviceEvidence { evidence } = &signed.command.operation else {
        panic!()
    };
    assert_eq!(evidence.platform, DevicePlatform::Android);
    assert_eq!(evidence.version, env!("CARGO_PKG_VERSION"));
    assert!(
        !evidence
            .capabilities
            .contains(&DeviceCapability::SubnetGateway)
    );
    assert!(
        !evidence
            .capabilities
            .contains(&DeviceCapability::ExitGateway)
    );
    evidence.validate().unwrap();
    acknowledge(carrier, true);
    signed
}

#[test]
fn evidence_is_signed_retried_and_renewed_only_after_matching_acknowledgement() {
    let (f, owner, mut carrier, path) = fixture();
    let initial = carrier.management_transcript(f.now).unwrap();
    assert!(carrier.complete_management([0; 64]).is_err());
    assert_eq!(carrier.management_transcript(f.now).unwrap(), initial);
    assert_eq!(
        carrier
            .management_transcript(UnixTime(f.now.0 + 25))
            .unwrap(),
        initial
    );
    let original_request = carrier.pending_management.clone().unwrap();
    let refreshed = carrier
        .management_transcript(UnixTime(f.now.0 + 26))
        .unwrap();
    assert_ne!(refreshed, initial);
    assert!(carrier.pending_management.as_ref().unwrap().sequence > original_request.sequence);
    // A wall-clock rollback also refreshes the transcript before completing it.
    assert_ne!(carrier.management_transcript(f.now).unwrap(), refreshed);
    let initial = carrier.management_transcript(f.now).unwrap();
    carrier.management_result(&peerward_wire::PeerManagementResult {
        request_id: Uuid::new_v4().as_bytes().to_vec(),
        committed: true,
        error: String::new(),
    });
    assert_eq!(carrier.management_transcript(f.now).unwrap(), initial);
    let first = carrier.pending_management.clone().unwrap();
    acknowledge(&mut carrier, false);
    let _ = carrier.management_transcript(f.now).unwrap();
    let retry = carrier.pending_management.clone().unwrap();
    assert_ne!(retry.request_id, first.request_id);
    assert!(retry.sequence > first.sequence);
    acknowledge_evidence(&mut carrier, f.now);
    // The independent configuration receipt is still delivered after software evidence.
    assert!(!carrier.management_transcript(f.now).unwrap().is_empty());
    assert!(matches!(
        carrier.pending_management.as_ref().unwrap().operation,
        PeerOperation::Applied { .. }
    ));
    acknowledge(&mut carrier, true);
    assert!(
        carrier
            .management_transcript(UnixTime(f.now.0 + 299))
            .unwrap()
            .is_empty()
    );
    assert!(
        !carrier
            .management_transcript(UnixTime(f.now.0 + 300))
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        carrier.pending_management.as_ref().unwrap().operation,
        PeerOperation::DeviceEvidence { .. }
    ));
    drop(carrier);
    drop(owner);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn expired_authorization_and_clock_rollback_do_not_prevent_evidence_recovery() {
    let (f, owner, mut carrier, path) = fixture();
    acknowledge_evidence(&mut carrier, f.now);
    // Data authorization has expired; evidence takes priority over rejected application receipts.
    let _ = carrier
        .management_transcript(UnixTime(f.now.0 + 901))
        .unwrap();
    assert!(matches!(
        carrier.pending_management.as_ref().unwrap().operation,
        PeerOperation::DeviceEvidence { .. }
    ));
    acknowledge(&mut carrier, true);
    let _ = carrier.management_transcript(f.now).unwrap();
    assert!(matches!(
        carrier.pending_management.as_ref().unwrap().operation,
        PeerOperation::DeviceEvidence { .. }
    ));
    carrier.close();
    assert!(carrier.management_transcript(f.now).is_err());
    assert!(carrier.complete_management([0; 64]).is_err());
    drop(carrier);
    drop(owner);
    std::fs::remove_dir_all(path).unwrap();
}

#[test]
fn replacement_attachment_and_new_credential_require_fresh_evidence() {
    let (f, owner, mut carrier, path) = fixture();
    let signed = acknowledge_evidence(&mut carrier, f.now);
    carrier.close();
    let (mut replacement, _) = f.carrier(&owner);
    let fresh = acknowledge_evidence(&mut replacement, f.now);
    assert!(fresh.command.sequence > signed.command.sequence);
    // A receipt for the old serial cannot suppress software evidence for a renewed identity.
    replacement.evidence_acknowledged = Some((CredentialSerial::new(), f.now.0));
    let _ = replacement.management_transcript(f.now).unwrap();
    assert!(matches!(
        replacement.pending_management.as_ref().unwrap().operation,
        PeerOperation::DeviceEvidence { .. }
    ));
    drop(replacement);
    drop(carrier);
    drop(owner);
    std::fs::remove_dir_all(path).unwrap();
}
