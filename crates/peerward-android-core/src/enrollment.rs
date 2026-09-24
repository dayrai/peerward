use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as ENROLLMENT_BASE64};
use peerward_credentials::{AuthorityCertificate, RootPublicKey};
use peerward_credentials::{JoinClaimProof, join_claim_transcript, verify_join_claim};
use peerward_types::validate_endpoint_list;
use sha2::{Digest as _, Sha256};

const MAX_ENROLLMENT_DRAFT: usize = 8 * 1024;
const SECRET_DIGEST_DOMAIN: &[u8] = b"peerward/stored-secret/v1\0";
const CLAIM_ID_DOMAIN: &[u8] = b"peerward/android-claim-id/v1\0";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MobileEnrollmentDraft {
    claim_id: uuid::Uuid,
    ticket_digest: [u8; 32],
    identity_public_key: [u8; 32],
    session_public_key: [u8; 32],
    wireguard_public_key: [u8; 32],
    client_version: String,
    nonce: Vec<u8>,
    device_name: String,
    device_model: String,
    platform_version: String,
}

impl MobileEnrollmentDraft {
    fn proof(&self) -> JoinClaimProof<'_> {
        JoinClaimProof {
            schema_version: 2,
            claim_id: self.claim_id,
            ticket_digest: self.ticket_digest,
            identity_public_key: self.identity_public_key,
            session_public_key: self.session_public_key,
            wireguard_public_key: self.wireguard_public_key,
            client_version: &self.client_version,
            supported_wire_major: peerward_wire::PROTOCOL_MAJOR,
            nonce: &self.nonce,
            device_name: &self.device_name,
            device_model: &self.device_model,
            platform: "android",
            platform_version: &self.platform_version,
        }
    }
}

fn enrollment_draft(bytes: &[u8]) -> Result<MobileEnrollmentDraft, MobileError> {
    if bytes.is_empty() || bytes.len() > MAX_ENROLLMENT_DRAFT {
        return Err(MobileError::InvalidInput);
    }
    let draft: MobileEnrollmentDraft =
        serde_json::from_slice(bytes).map_err(|_| MobileError::InvalidInput)?;
    join_claim_transcript(&draft.proof())?;
    Ok(draft)
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_mobile_enrollment(
    claim_url: &str,
    identity_public_key: [u8; 32],
    session_public_key: [u8; 32],
    wireguard_public_key: [u8; 32],
    client_version: String,
    nonce: Vec<u8>,
    device_name: String,
    device_model: String,
    platform_version: String,
) -> Result<Vec<u8>, MobileError> {
    let url = url::Url::parse(claim_url).map_err(|_| MobileError::InvalidInput)?;
    let loopback_http = url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
    if (url.scheme() != "https" && !loopback_http)
        || url.username() != ""
        || url.password().is_some()
        || url.fragment().is_some()
        || url.query().is_some()
    {
        return Err(MobileError::InvalidInput);
    }
    let segments = url
        .path_segments()
        .ok_or(MobileError::InvalidInput)?
        .collect::<Vec<_>>();
    if segments.len() < 4
        || segments.last() != Some(&"claim")
        || segments.get(segments.len() - 3) != Some(&"join")
    {
        return Err(MobileError::InvalidInput);
    }
    let ticket = ENROLLMENT_BASE64
        .decode(segments[segments.len() - 2])
        .map_err(|_| MobileError::InvalidInput)?;
    if !(16..=128).contains(&ticket.len()) {
        return Err(MobileError::InvalidInput);
    }
    let ticket_digest: [u8; 32] = Sha256::new()
        .chain_update(SECRET_DIGEST_DOMAIN)
        .chain_update(
            u64::try_from(ticket.len())
                .map_err(|_| MobileError::InvalidInput)?
                .to_be_bytes(),
        )
        .chain_update(&ticket)
        .finalize()
        .into();
    let mut claim_bytes: [u8; 16] = Sha256::new()
        .chain_update(CLAIM_ID_DOMAIN)
        .chain_update(identity_public_key)
        .chain_update(ticket_digest)
        .finalize()[..16]
        .try_into()
        .map_err(|_| MobileError::InvalidInput)?;
    claim_bytes[6] = (claim_bytes[6] & 0x0f) | 0x40;
    claim_bytes[8] = (claim_bytes[8] & 0x3f) | 0x80;
    let draft = MobileEnrollmentDraft {
        claim_id: uuid::Uuid::from_bytes(claim_bytes),
        ticket_digest,
        identity_public_key,
        session_public_key,
        wireguard_public_key,
        client_version,
        nonce,
        device_name,
        device_model,
        platform_version,
    };
    join_claim_transcript(&draft.proof())?;
    serde_json::to_vec(&draft).map_err(|_| MobileError::InvalidInput)
}

pub(crate) fn mobile_enrollment_transcript(draft: &[u8]) -> Result<Vec<u8>, MobileError> {
    join_claim_transcript(&enrollment_draft(draft)?.proof()).map_err(MobileError::from)
}

pub(crate) fn complete_mobile_enrollment(
    draft: &[u8],
    signature: [u8; 64],
) -> Result<Vec<u8>, MobileError> {
    let draft = enrollment_draft(draft)?;
    verify_join_claim(&draft.proof(), &signature)?;
    serde_json::to_vec(&peerward_api::JoinClaimRequest {
        schema_version: 2,
        claim_id: draft.claim_id,
        identity_public_key: ENROLLMENT_BASE64.encode(draft.identity_public_key),
        session_public_key: ENROLLMENT_BASE64.encode(draft.session_public_key),
        wireguard_public_key: ENROLLMENT_BASE64.encode(draft.wireguard_public_key),
        client_version: draft.client_version,
        supported_wire_major: peerward_wire::PROTOCOL_MAJOR,
        nonce: ENROLLMENT_BASE64.encode(draft.nonce),
        device_name: draft.device_name,
        device_model: draft.device_model,
        platform: "android".into(),
        platform_version: draft.platform_version,
        signature: ENROLLMENT_BASE64.encode(signature),
    })
    .map_err(|_| MobileError::InvalidInput)
}

#[cfg_attr(test, allow(dead_code))]
pub(crate) fn verify_mobile_join_response(
    response: &[u8],
    root_fingerprint: [u8; 32],
    local_identity: [u8; 32],
    local_session: [u8; 32],
    local_wireguard: [u8; 32],
    now: UnixTime,
) -> Result<Vec<u8>, MobileError> {
    if response.is_empty() || response.len() > 1_048_576 {
        return Err(MobileError::InvalidInput);
    }
    let response: peerward_api::JoinResponse =
        serde_json::from_slice(response).map_err(|_| MobileError::InvalidInput)?;
    if response.profile_id != response.peer_id
        || response.authority_revision == 0
        || response.mesh_name.trim().is_empty()
        || response.mesh_name.len() > 128
        || response.dns_suffix.trim().is_empty()
        || response.dns_suffix.len() > 253
        || response.relays.is_empty()
        || response.relays.len() > 64
        || response
            .relays
            .iter()
            .any(|relay| validate_endpoint_list(&relay.endpoints).is_err())
        || response.routes.is_empty()
        || response.routes.len() > 64
        || response.dns_servers.len() != 1
        || !(1280..=9000).contains(&response.mtu)
        || response.stun_servers.len() > 8
        || response.authority_certificates.is_empty()
        || response.authority_certificates.len() > 8
    {
        return Err(MobileError::InvalidInput);
    }
    let returned_root = decode_enrollment_key(&response.root_public_key)?;
    let actual_fingerprint: [u8; 32] = Sha256::digest(returned_root).into();
    if actual_fingerprint != root_fingerprint {
        return Err(MobileError::InvalidInput);
    }
    let mut trust = TrustSet::new(RootPublicKey::from_bytes(&returned_root)?, response.mesh_id);
    for encoded in &response.authority_certificates {
        let certificate = ENROLLMENT_BASE64
            .decode(encoded)
            .map_err(|_| MobileError::InvalidInput)?;
        trust
            .add_authority(AuthorityCertificate::decode(&certificate)?, now)
            .map_err(|error| MobileError::EnrollmentCredential("authority", error))?;
    }
    let credential = ENROLLMENT_BASE64
        .decode(&response.credential)
        .map_err(|_| MobileError::InvalidInput)?;
    let credential = SubjectCredential::decode(&credential)?;
    // TrustSet deliberately collapses failure of every possible issuer to an
    // invalid-signature result. Preserve the explicit time failure here, without
    // advancing the clock or accepting any otherwise unverified credential.
    if now < credential.not_before || now >= credential.not_after {
        return Err(MobileError::Credential(CredentialError::OutsideValidity));
    }
    trust
        .verify_subject(&credential, now)
        .map_err(|error| MobileError::EnrollmentCredential("subject", error))?;
    if credential.subject != SubjectId::Peer(response.peer_id)
        || credential.mesh_id != response.mesh_id
        || credential.identity_public_key != local_identity
        || credential.public_noise_key != local_session
        || credential.wireguard_public_key != local_wireguard
    {
        return Err(MobileError::InvalidInput);
    }
    let distribution_bytes = ENROLLMENT_BASE64
        .decode(&response.distribution_certificate)
        .map_err(|_| MobileError::InvalidInput)?;
    let distribution = DistributionCertificate::decode(&distribution_bytes)?;
    trust
        .verify_distribution(&distribution, now)
        .map_err(|error| MobileError::EnrollmentCredential("distribution", error))?;
    if distribution.directory_public_key
        != decode_enrollment_key(&response.distribution_public_key)?
        || distribution.service_public_key != decode_enrollment_key(&response.service_public_key)?
        || distribution.audit_public_key != decode_enrollment_key(&response.audit_public_key)?
        || response
            .relays
            .iter()
            .any(|relay| decode_enrollment_key(&relay.public_key).is_err())
    {
        return Err(MobileError::InvalidInput);
    }
    let address = response
        .address
        .parse::<ipnet::IpNet>()
        .map_err(|_| MobileError::InvalidInput)?;
    let routes = response
        .routes
        .iter()
        .map(|route| {
            route
                .parse::<ipnet::IpNet>()
                .map_err(|_| MobileError::InvalidInput)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let dns = response.dns_servers[0]
        .parse::<std::net::IpAddr>()
        .map_err(|_| MobileError::InvalidInput)?;
    let secondary_address = response
        .secondary_address
        .as_ref()
        .map(|value| {
            value
                .parse::<ipnet::IpNet>()
                .map_err(|_| MobileError::InvalidInput)
        })
        .transpose()?;
    peerward_management::validate_assignments(address, secondary_address, &routes)
        .map_err(|_| MobileError::InvalidInput)?;
    if !routes.iter().any(|route| route.contains(&dns)) {
        return Err(MobileError::InvalidInput);
    }
    let stun_servers = response
        .stun_servers
        .iter()
        .map(|server| server.parse::<peerward_types::StunEndpoint>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| MobileError::InvalidInput)?;
    peerward_types::validate_stun_servers(&stun_servers).map_err(|_| MobileError::InvalidInput)?;
    serde_json::to_vec(&response).map_err(|_| MobileError::InvalidInput)
}

#[cfg_attr(test, allow(dead_code))]
fn decode_enrollment_key(encoded: &str) -> Result<[u8; 32], MobileError> {
    ENROLLMENT_BASE64
        .decode(encoded)
        .map_err(|_| MobileError::InvalidInput)?
        .try_into()
        .map_err(|_| MobileError::InvalidInput)
}

#[cfg(test)]
mod enrollment_tests {
    use ed25519_dalek::{Signer as _, SigningKey};

    use super::*;

    #[test]
    fn rust_constructs_the_exact_signed_android_join_request() {
        let identity = SigningKey::from_bytes(&[7; 32]);
        let draft = prepare_mobile_enrollment(
            &format!(
                "https://control.example/api/v1/join/{}/claim",
                ENROLLMENT_BASE64.encode([9; 32])
            ),
            identity.verifying_key().to_bytes(),
            [8; 32],
            [9; 32],
            "1.0.0-technical-preview.1".into(),
            vec![6; 24],
            "phone".into(),
            "model".into(),
            "36".into(),
        )
        .unwrap();
        let transcript = mobile_enrollment_transcript(&draft).unwrap();
        let request: peerward_api::JoinClaimRequest = serde_json::from_slice(
            &complete_mobile_enrollment(&draft, identity.sign(&transcript).to_bytes()).unwrap(),
        )
        .unwrap();
        assert_eq!(request.platform, "android");
        assert_eq!(request.supported_wire_major, peerward_wire::PROTOCOL_MAJOR);
        assert!(request.claim_id.get_version_num() == 4);
    }
}

#[cfg(test)]
#[path = "enrollment_response_tests.rs"]
mod enrollment_response_tests;
