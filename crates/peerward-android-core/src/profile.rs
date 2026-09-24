use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ipnet::IpNet;
use zeroize::Zeroize;

const MOBILE_PROFILE_MAGIC: &[u8; 4] = b"PWMP";
const MOBILE_PROFILE_VERSION: u8 = 4;
const MAX_MOBILE_PROFILE_BYTES: usize = 1_048_576;

/// Rust-owned durable Android profile document. Android stores this as an opaque,
/// Keystore-wrapped blob and only materializes JSON after native validation.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MobileProfileDocument {
    config_version: u32,
    profile_id: String,
    device_key_id: String,
    mesh_id: String,
    peer_id: String,
    mesh_name: String,
    address: IpNet,
    #[serde(default)]
    secondary_address: Option<IpNet>,
    dns_suffix: String,
    credential: String,
    relays: Vec<MobileRelayTarget>,
    #[serde(
        default,
        skip_serializing_if = "peerward_carrier::ClientOptions::is_default"
    )]
    relay_transport: peerward_carrier::ClientOptions,
    #[serde(default)]
    stun_servers: Vec<peerward_types::StunEndpoint>,
    #[serde(default)]
    p2p_endpoints: Vec<std::net::SocketAddr>,
    #[serde(default, skip_serializing_if = "MobileNatMappingMode::is_auto")]
    nat_mapping: MobileNatMappingMode,
    #[serde(default, skip_serializing_if = "is_false")]
    symmetric_nat_prediction: bool,
    routes: Vec<IpNet>,
    dns_servers: Vec<std::net::IpAddr>,
    mtu: u16,
    #[serde(default)]
    local_identity_public: String,
    #[serde(default)]
    local_noise_public: String,
    local_wireguard_public: String,
    #[serde(default)]
    root_public_key: String,
    #[serde(default)]
    authority_certificates: Vec<String>,
    #[serde(default)]
    authority_revision: u64,
    #[serde(default)]
    distribution_public_key: String,
    #[serde(default)]
    service_public_key: String,
    #[serde(default)]
    audit_public_key: String,
    #[serde(default)]
    distribution_certificate: String,
    previous_device_key_id: Option<String>,
    pending_rotation_id: Option<String>,
    pending_device_key_id: Option<String>,
    pending_identity_public: Option<String>,
    pending_noise_public: Option<String>,
    pending_wireguard_public: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_credential: Option<String>,
}

impl Drop for MobileProfileDocument {
    fn drop(&mut self) {
        self.credential.zeroize();
        self.pending_credential.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MobileRelayTarget {
    relay_id: String,
    endpoints: Vec<peerward_types::NetworkEndpoint>,
    noise_public_key: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum MobileNatMappingMode {
    #[default]
    Auto,
    Off,
}

impl MobileNatMappingMode {
    #[allow(clippy::trivially_copy_pass_by_ref)]
    const fn is_auto(value: &Self) -> bool {
        matches!(value, Self::Auto)
    }
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_false(value: &bool) -> bool {
    !*value
}

pub(crate) struct MobileRotationPlan {
    pub request_id: [u8; 16],
    pub key_id: String,
    pub expected_identity: Option<[u8; 32]>,
    pub expected_noise: Option<[u8; 32]>,
    pub expected_wireguard: Option<[u8; 32]>,
    pub staged_blob: Option<Vec<u8>>,
}

pub(crate) struct MobilePreviousKeyCleanup {
    pub key_id: String,
    pub cleaned_blob: Vec<u8>,
}

impl MobileProfileDocument {
    fn validate(&self) -> Result<(), MobileError> {
        if self.config_version != u32::from(MOBILE_PROFILE_VERSION)
            || !safe_id(&self.profile_id)
            || !safe_id(&self.device_key_id)
            || !safe_id(&self.mesh_id)
            || !safe_id(&self.peer_id)
            || self.mesh_name.trim().is_empty()
            || self.mesh_name.len() > 128
            || self.dns_suffix.trim().is_empty()
            || self.dns_suffix.len() > 253
            || self.credential.is_empty()
            || self.credential.len() > 4096
            || self.relay_transport.validate().is_err()
            || self.relays.is_empty()
            || self.relays.len() > 64
            || self.routes.is_empty()
            || self.routes.len() > 64
            || self.dns_servers.is_empty()
            || self.dns_servers.len() > 8
            || !(1280..=9000).contains(&self.mtu)
            || peerward_types::validate_stun_servers(&self.stun_servers).is_err()
            || self.p2p_endpoints.len() > 8
            || peerward_management::validate_assignments(
                self.address,
                self.secondary_address,
                &self.routes,
            )
            .is_err()
            || self.relays.iter().any(|relay| !relay.valid())
            || self
                .dns_servers
                .iter()
                .any(|server| !self.routes.iter().any(|route| route.contains(server)))
            || self
                .optional_ids()
                .into_iter()
                .flatten()
                .any(|value| !safe_id(value))
            || self
                .public_keys()
                .into_iter()
                .any(|key| !key.is_empty() && decode_32(key).is_none())
            || decode_32(&self.local_wireguard_public).is_none_or(|key| key == [0; 32])
            || self.local_wireguard_public == self.local_noise_public
            || self.local_wireguard_public == self.local_identity_public
            || self.authority_certificates.len() > 9
            || self
                .authority_certificates
                .iter()
                .any(|certificate| certificate.len() > 512)
            || self.distribution_certificate.len() > 512
            || self.pending_credential.as_ref().is_some_and(|value| {
                value.len() != 300
                    || self.pending_rotation_id.is_none()
                    || self.pending_device_key_id.is_none()
                    || self.pending_identity_public.is_none()
                    || self.pending_noise_public.is_none()
                    || self.pending_wireguard_public.is_none()
                    || URL_SAFE_NO_PAD.decode(value).is_err()
            })
        {
            return Err(MobileError::InvalidInput);
        }
        Ok(())
    }

    fn optional_ids(&self) -> [Option<&str>; 3] {
        [
            self.previous_device_key_id.as_deref(),
            self.pending_rotation_id.as_deref(),
            self.pending_device_key_id.as_deref(),
        ]
    }

    fn public_keys(&self) -> [&str; 10] {
        [
            &self.local_identity_public,
            &self.local_noise_public,
            &self.local_wireguard_public,
            &self.root_public_key,
            &self.distribution_public_key,
            &self.service_public_key,
            &self.audit_public_key,
            self.pending_identity_public.as_deref().unwrap_or(""),
            self.pending_noise_public.as_deref().unwrap_or(""),
            self.pending_wireguard_public.as_deref().unwrap_or(""),
        ]
    }
}

impl MobileRelayTarget {
    fn valid(&self) -> bool {
        safe_id(&self.relay_id)
            && (1..=16).contains(&self.endpoints.len())
            && self
                .endpoints
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == self.endpoints.len()
            && (self.noise_public_key.is_empty() || decode_32(&self.noise_public_key).is_some())
    }
}

fn safe_id(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn decode_32(value: &str) -> Option<[u8; 32]> {
    URL_SAFE_NO_PAD.decode(value).ok()?.try_into().ok()
}

fn parse_profile_json(json: &[u8]) -> Result<MobileProfileDocument, MobileError> {
    if json.is_empty() || json.len() > MAX_MOBILE_PROFILE_BYTES {
        return Err(MobileError::InvalidInput);
    }
    let profile: MobileProfileDocument =
        serde_json::from_slice(json).map_err(|_| MobileError::InvalidInput)?;
    profile.validate()?;
    Ok(profile)
}

fn parse_profile_blob(blob: &[u8]) -> Result<MobileProfileDocument, MobileError> {
    if blob.len() < 9
        || blob.len() > MAX_MOBILE_PROFILE_BYTES + 9
        || blob.get(..4) != Some(MOBILE_PROFILE_MAGIC)
        || blob[4] != MOBILE_PROFILE_VERSION
    {
        return Err(MobileError::InvalidInput);
    }
    let length = u32::from_be_bytes(
        blob[5..9]
            .try_into()
            .map_err(|_| MobileError::InvalidInput)?,
    ) as usize;
    if length != blob.len() - 9 {
        return Err(MobileError::InvalidInput);
    }
    parse_profile_json(&blob[9..])
}

fn encode_profile_document(profile: &MobileProfileDocument) -> Result<Vec<u8>, MobileError> {
    profile.validate()?;
    let canonical = Zeroizing::new(
        serde_json::to_vec(profile).map_err(|_| MobileError::InvalidInput)?,
    );
    let length = u32::try_from(canonical.len()).map_err(|_| MobileError::InvalidInput)?;
    let mut blob = Vec::with_capacity(9 + canonical.len());
    blob.extend_from_slice(MOBILE_PROFILE_MAGIC);
    blob.push(MOBILE_PROFILE_VERSION);
    blob.extend_from_slice(&length.to_be_bytes());
    blob.extend_from_slice(&canonical);
    Ok(blob)
}

pub(crate) fn encode_mobile_profile(json: &[u8]) -> Result<Vec<u8>, MobileError> {
    let profile = parse_profile_json(json)?;
    encode_profile_document(&profile)
}

pub(crate) fn decode_mobile_profile(blob: &[u8]) -> Result<Vec<u8>, MobileError> {
    let profile = parse_profile_blob(blob)?;
    serde_json::to_vec(&profile).map_err(|_| MobileError::InvalidInput)
}

pub(crate) fn plan_mobile_rotation(blob: &[u8]) -> Result<MobileRotationPlan, MobileError> {
    let mut profile = parse_profile_blob(blob)?;
    let pending = match (
        profile.pending_rotation_id.as_deref(),
        profile.pending_device_key_id.as_deref(),
        profile.pending_identity_public.as_deref(),
        profile.pending_noise_public.as_deref(),
        profile.pending_wireguard_public.as_deref(),
    ) {
        (None, None, None, None, None) => None,
        (Some(request), Some(key), identity, noise, wireguard)
            if identity.is_some() == noise.is_some()
                && identity.is_some() == wireguard.is_some() =>
        {
            Some((request, key, identity, noise, wireguard))
        }
        _ => return Err(MobileError::InvalidState),
    };
    if let Some((request, key, identity, noise, wireguard)) = pending {
        let request = uuid::Uuid::parse_str(request).map_err(|_| MobileError::InvalidInput)?;
        if request.get_version_num() != 4 {
            return Err(MobileError::InvalidInput);
        }
        let request_id = request.into_bytes();
        return Ok(MobileRotationPlan {
            request_id,
            key_id: key.to_owned(),
            expected_identity: identity
                .map(|value| decode_32(value).ok_or(MobileError::InvalidInput))
                .transpose()?,
            expected_noise: noise
                .map(|value| decode_32(value).ok_or(MobileError::InvalidInput))
                .transpose()?,
            expected_wireguard: wireguard
                .map(|value| decode_32(value).ok_or(MobileError::InvalidInput))
                .transpose()?,
            staged_blob: None,
        });
    }
    let request = uuid::Uuid::new_v4();
    let key_id = format!("rotation-{}", request.simple());
    profile.pending_rotation_id = Some(request.to_string());
    profile.pending_device_key_id = Some(key_id.clone());
    Ok(MobileRotationPlan {
        request_id: request.into_bytes(),
        key_id,
        expected_identity: None,
        expected_noise: None,
        expected_wireguard: None,
        staged_blob: Some(encode_profile_document(&profile)?),
    })
}

pub(crate) fn install_mobile_rotation_publics(
    blob: &[u8],
    request_id: [u8; 16],
    key_id: &str,
    identity: [u8; 32],
    noise: [u8; 32],
    wireguard: [u8; 32],
) -> Result<Vec<u8>, MobileError> {
    if identity == [0; 32]
        || noise == [0; 32]
        || wireguard == [0; 32]
        || wireguard == noise
        || wireguard == identity
        || !safe_id(key_id)
    {
        return Err(MobileError::InvalidInput);
    }
    let mut profile = parse_profile_blob(blob)?;
    let expected_request = uuid::Uuid::from_bytes(request_id).to_string();
    if profile.pending_rotation_id.as_deref() != Some(expected_request.as_str())
        || profile.pending_device_key_id.as_deref() != Some(key_id)
        || profile.pending_identity_public.is_some()
        || profile.pending_noise_public.is_some()
        || profile.pending_wireguard_public.is_some()
        || decode_32(&profile.local_wireguard_public) == Some(wireguard)
    {
        return Err(MobileError::InvalidState);
    }
    profile.pending_identity_public = Some(URL_SAFE_NO_PAD.encode(identity));
    profile.pending_noise_public = Some(URL_SAFE_NO_PAD.encode(noise));
    profile.pending_wireguard_public = Some(URL_SAFE_NO_PAD.encode(wireguard));
    encode_profile_document(&profile)
}

pub(crate) fn commit_mobile_rotation(
    blob: &[u8],
    credential: &[u8],
) -> Result<Vec<u8>, MobileError> {
    let replacement = peerward_credentials::SubjectCredential::decode(credential)?;
    let canonical_credential = Zeroizing::new(replacement.encode());
    if canonical_credential.as_slice() != credential {
        return Err(MobileError::InvalidInput);
    }
    let mut profile = parse_profile_blob(blob)?;
    let mesh_id = profile
        .mesh_id
        .parse::<peerward_types::MeshId>()
        .map_err(|_| MobileError::InvalidInput)?;
    let peer_id = profile
        .peer_id
        .parse::<peerward_types::PeerId>()
        .map_err(|_| MobileError::InvalidInput)?;
    if replacement.mesh_id != mesh_id
        || replacement.subject != peerward_credentials::SubjectId::Peer(peer_id)
    {
        return Err(MobileError::InvalidInput);
    }
    let encoded_credential = URL_SAFE_NO_PAD.encode(credential);
    if profile.credential == encoded_credential
        && decode_32(&profile.local_identity_public) == Some(replacement.identity_public_key)
        && decode_32(&profile.local_noise_public) == Some(replacement.public_noise_key)
        && decode_32(&profile.local_wireguard_public) == Some(replacement.wireguard_public_key)
    {
        return encode_profile_document(&profile);
    }
    let key_id = profile
        .pending_device_key_id
        .clone()
        .ok_or(MobileError::InvalidState)?;
    let identity = profile
        .pending_identity_public
        .clone()
        .ok_or(MobileError::InvalidState)?;
    let noise = profile
        .pending_noise_public
        .clone()
        .ok_or(MobileError::InvalidState)?;
    let wireguard = profile
        .pending_wireguard_public
        .clone()
        .ok_or(MobileError::InvalidState)?;
    if decode_32(&identity) != Some(replacement.identity_public_key)
        || decode_32(&noise) != Some(replacement.public_noise_key)
        || decode_32(&wireguard) != Some(replacement.wireguard_public_key)
    {
        return Err(MobileError::InvalidInput);
    }
    profile.previous_device_key_id = Some(profile.device_key_id.clone());
    profile.device_key_id = key_id;
    profile.local_identity_public = identity;
    profile.local_noise_public = noise;
    profile.local_wireguard_public = wireguard;
    profile.credential = encoded_credential;
    profile.pending_rotation_id = None;
    profile.pending_device_key_id = None;
    profile.pending_identity_public = None;
    profile.pending_noise_public = None;
    profile.pending_wireguard_public = None;
    profile.pending_credential = None;
    encode_profile_document(&profile)
}

pub(crate) fn clean_mobile_previous_key(
    blob: &[u8],
    authenticated_device_key_id: &str,
) -> Result<Option<MobilePreviousKeyCleanup>, MobileError> {
    let mut profile = parse_profile_blob(blob)?;
    if profile.device_key_id != authenticated_device_key_id {
        return Err(MobileError::InvalidState);
    }
    let Some(key_id) = profile.previous_device_key_id.take() else {
        return Ok(None);
    };
    Ok(Some(MobilePreviousKeyCleanup {
        key_id,
        cleaned_blob: encode_profile_document(&profile)?,
    }))
}

pub(crate) fn install_mobile_authorities(
    blob: &[u8],
    revision: u64,
    certificates: &[[u8; 144]],
) -> Result<Vec<u8>, MobileError> {
    let mut profile = parse_profile_blob(blob)?;
    if revision < profile.authority_revision || certificates.is_empty() || certificates.len() > 9 {
        return Err(MobileError::InvalidState);
    }
    let encoded_certificates = certificates
        .iter()
        .map(|certificate| URL_SAFE_NO_PAD.encode(certificate))
        .collect::<Vec<_>>();
    if revision == profile.authority_revision {
        return if profile.authority_certificates == encoded_certificates {
            Ok(blob.to_vec())
        } else {
            Err(MobileError::InvalidState)
        };
    }
    profile.authority_revision = revision;
    profile.authority_certificates = encoded_certificates;
    encode_profile_document(&profile)
}

#[cfg(test)]
#[path = "profile_tests.rs"]
mod profile_tests;
