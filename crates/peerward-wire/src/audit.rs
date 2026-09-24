use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use prost::Message;
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{MAX_OPAQUE_FRAME_LEN, PROTOCOL_MAJOR, WireError};

/// Reserved destination used only for encrypted Peer-to-Control audit batches.
///
/// It is not a valid `UUIDv4` and can therefore never collide with a Peer identifier.
pub const CONTROL_AUDIT_DESTINATION: [u8; 16] = [0; 16];
/// Maximum policy/anomaly summaries carried in one batch.
pub const MAX_AUDIT_EVENTS: usize = 64;
const AUDIT_SCHEMA_VERSION: u32 = 1;
const AUDIT_INFO: &[u8] = b"peerward/audit/v1";
const AUDIT_SIGNATURE_DOMAIN: &[u8] = b"peerward/audit/signature/v1";
const KEM_SUITE_ID: &[u8] = b"KEM\x00\x20";
const HPKE_SUITE_ID: &[u8] = b"HPKE\x00\x20\x00\x01\x00\x03";

/// Derives the distributable X25519 recipient key for a Control audit private key.
pub fn audit_recipient_public(private: &[u8; 32]) -> [u8; 32] {
    X25519PublicKey::from(&StaticSecret::from(*private)).to_bytes()
}

/// Packet-processing side that produced a payload-free audit summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum AuditDirectionV1 {
    /// Packet originated at the local TUN.
    Egress = 0,
    /// Packet arrived from an authenticated Peer session.
    Ingress = 1,
    /// The event concerns a session or runtime rather than one packet direction.
    Runtime = 2,
}

/// Stable, non-sensitive audit category. Packet addresses, ports, DNS names, and payloads are
/// deliberately absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum AuditReasonV1 {
    /// A compiled policy rejected one or more packets.
    PolicyDenied = 0,
    /// Strict parsing, checksum validation, or fragment reassembly rejected input.
    MalformedPacket = 1,
    /// A session was unavailable or reached a fail-closed cryptographic bound.
    SessionUnavailable = 2,
    /// A bounded queue or other local resource limit rejected work.
    ResourceLimited = 3,
    /// A replay, source-binding mismatch, or other authenticated anomaly was rejected.
    SecurityAnomaly = 4,
}

/// Privacy-safe reason explaining why the local runtime is degraded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum RuntimeDegradedReasonV1 {
    RelayUnavailable = 0,
    SignedStateIncomplete = 1,
    DirectPathUnavailable = 2,
    DnsDegraded = 3,
    CredentialRotation = 4,
    UnderlayUnavailable = 5,
    PacketPumpUnavailable = 6,
}

/// Current-only runtime health. It deliberately carries no address, endpoint, DNS, or remote ID.
#[derive(Clone, PartialEq, Message)]
pub struct RuntimeHealthV1 {
    /// Strictly monotonic for one Peer profile.
    #[prost(uint64, tag = "1")]
    pub sequence: u64,
    /// Number of currently healthy direct paths, without their identities.
    #[prost(uint32, tag = "2")]
    pub direct_path_count: u32,
    /// Payload-free packet counters used only to derive an aggregate ratio.
    #[prost(uint64, tag = "3")]
    pub relay_packets: u64,
    #[prost(uint64, tag = "4")]
    pub direct_packets: u64,
    /// Bounded reason codes; never free-form diagnostics.
    #[prost(enumeration = "RuntimeDegradedReasonV1", repeated, tag = "5")]
    pub degraded_reasons: Vec<i32>,
    /// Last completely verified signed-state revision set.
    #[prost(uint64, tag = "6")]
    pub signed_revision: u64,
}

impl RuntimeHealthV1 {
    fn validate(&self) -> Result<(), WireError> {
        if self.sequence == 0
            || self.direct_path_count > 65_535
            || self.degraded_reasons.len() > 8
            || self
                .degraded_reasons
                .iter()
                .any(|reason| RuntimeDegradedReasonV1::try_from(*reason).is_err())
        {
            return Err(WireError::KindMismatch);
        }
        let unique = self
            .degraded_reasons
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        if unique.len() != self.degraded_reasons.len() {
            return Err(WireError::KindMismatch);
        }
        Ok(())
    }
}

/// Aggregated audit event containing no packet or service metadata.
#[derive(Clone, PartialEq, Message)]
pub struct AuditEventV1 {
    /// Stable direction enum.
    #[prost(enumeration = "AuditDirectionV1", tag = "1")]
    pub direction: i32,
    /// Stable reason enum.
    #[prost(enumeration = "AuditReasonV1", tag = "2")]
    pub reason: i32,
    /// Number of equivalent events represented by this record.
    #[prost(uint32, tag = "3")]
    pub count: u32,
}

/// Canonical plaintext encrypted for Control. Relay never decodes this document.
#[derive(Clone, PartialEq, Message)]
pub struct AuditBatchV1 {
    /// Exact wire major.
    #[prost(uint32, tag = "1")]
    pub major: u32,
    /// Exact audit schema version.
    #[prost(uint32, tag = "2")]
    pub schema_version: u32,
    /// Raw Mesh UUID.
    #[prost(bytes = "vec", tag = "3")]
    pub mesh_id: Vec<u8>,
    /// Raw authenticated source Peer UUID.
    #[prost(bytes = "vec", tag = "4")]
    pub source_peer: Vec<u8>,
    /// Random `UUIDv4` used for end-to-end idempotency.
    #[prost(bytes = "vec", tag = "5")]
    pub batch_id: Vec<u8>,
    /// Wall-clock observation time in Unix seconds.
    #[prost(uint64, tag = "6")]
    pub observed_at: u64,
    /// Bounded payload-free summaries.
    #[prost(message, repeated, tag = "7")]
    pub events: Vec<AuditEventV1>,
    /// Mutually exclusive current runtime health report.
    #[prost(message, optional, tag = "8")]
    pub runtime_health: Option<RuntimeHealthV1>,
}

impl AuditBatchV1 {
    /// Validates structural and resource invariants without interpreting network data.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.major != PROTOCOL_MAJOR {
            return Err(WireError::UnsupportedMajor);
        }
        if self.schema_version != AUDIT_SCHEMA_VERSION
            || self.mesh_id.len() != 16
            || self.source_peer.len() != 16
            || self.batch_id.len() != 16
            || self.events.len() > MAX_AUDIT_EVENTS
            || self.events.iter().any(|event| {
                AuditDirectionV1::try_from(event.direction).is_err()
                    || AuditReasonV1::try_from(event.reason).is_err()
                    || event.count == 0
            })
        {
            return Err(WireError::KindMismatch);
        }
        match (&self.runtime_health, self.events.is_empty()) {
            (None, false) => {}
            (Some(health), true) => health.validate()?,
            _ => return Err(WireError::KindMismatch),
        }
        if !is_uuid_v4(&self.batch_id) {
            return Err(WireError::KindMismatch);
        }
        Ok(())
    }
}

/// HPKE Base-mode ciphertext signed by the Peer identity key.
#[derive(Clone, PartialEq, Message)]
pub struct SealedAuditBatchV1 {
    /// Exact wire major.
    #[prost(uint32, tag = "1")]
    pub major: u32,
    /// Raw Mesh UUID authenticated as AEAD associated data.
    #[prost(bytes = "vec", tag = "2")]
    pub mesh_id: Vec<u8>,
    /// Raw Peer UUID authenticated as AEAD associated data and by the signature.
    #[prost(bytes = "vec", tag = "3")]
    pub source_peer: Vec<u8>,
    /// Random `UUIDv4` duplicated inside the ciphertext for deduplication.
    #[prost(bytes = "vec", tag = "4")]
    pub batch_id: Vec<u8>,
    /// DHKEM(X25519, HKDF-SHA256) encapsulated public key.
    #[prost(bytes = "vec", tag = "5")]
    pub encapsulated_key: Vec<u8>,
    /// ChaCha20-Poly1305 ciphertext and tag.
    #[prost(bytes = "vec", tag = "6")]
    pub ciphertext: Vec<u8>,
    /// Ed25519 signature covering all routing metadata and the complete ciphertext.
    #[prost(bytes = "vec", tag = "7")]
    pub signature: Vec<u8>,
}

impl SealedAuditBatchV1 {
    /// Applies bounds needed before signature verification or HPKE processing.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.major != PROTOCOL_MAJOR {
            return Err(WireError::UnsupportedMajor);
        }
        if self.mesh_id.len() != 16
            || self.source_peer.len() != 16
            || self.batch_id.len() != 16
            || self.encapsulated_key.len() != 32
            || self.signature.len() != 64
            || self.ciphertext.is_empty()
            || self.ciphertext.len() > MAX_OPAQUE_FRAME_LEN
            || !is_uuid_v4(&self.batch_id)
        {
            return Err(WireError::InvalidLength);
        }
        Ok(())
    }
}

/// Seals and signs one canonical audit batch using RFC 9180 Base mode with
/// DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and ChaCha20-Poly1305.
pub fn seal_audit_batch<R: RngCore + CryptoRng>(
    batch: &AuditBatchV1,
    recipient_public: &[u8; 32],
    identity: &SigningKey,
    rng: R,
) -> Result<SealedAuditBatchV1, WireError> {
    let (sealed, transcript) = prepare_audit_batch(batch, recipient_public, rng)?;
    let sealed = finish_audit_batch(
        sealed,
        &identity.sign(&transcript).to_bytes(),
        &identity.verifying_key().to_bytes(),
    )?;
    if batch.runtime_health.is_some() && sealed.encoded_len() > 4 * 1024 {
        return Err(WireError::InvalidLength);
    }
    Ok(sealed)
}

/// Encrypts a batch and returns the exact bounded transcript an external identity provider must
/// sign. This is used by Android Keystore-backed identities whose private seed never enters the
/// long-lived Rust session.
pub fn prepare_audit_batch<R: RngCore + CryptoRng>(
    batch: &AuditBatchV1,
    recipient_public: &[u8; 32],
    rng: R,
) -> Result<(SealedAuditBatchV1, Vec<u8>), WireError> {
    batch.validate()?;
    if *recipient_public == [0; 32] {
        return Err(WireError::KindMismatch);
    }
    let ephemeral = StaticSecret::random_from_rng(rng);
    let encapsulated_key = X25519PublicKey::from(&ephemeral).to_bytes();
    let recipient = X25519PublicKey::from(*recipient_public);
    let dh = ephemeral.diffie_hellman(&recipient).to_bytes();
    if dh == [0; 32] {
        return Err(WireError::Authentication);
    }
    let (key, nonce) = hpke_context(&dh, &encapsulated_key, recipient_public)?;
    let aad = audit_aad(
        &batch.mesh_id,
        &batch.source_peer,
        &batch.batch_id,
        &encapsulated_key,
    );
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &batch.encode_to_vec(),
                aad: &aad,
            },
        )
        .map_err(|_| WireError::Authentication)?;
    let transcript = audit_signature(&aad, &ciphertext);
    Ok((
        SealedAuditBatchV1 {
            major: PROTOCOL_MAJOR,
            mesh_id: batch.mesh_id.clone(),
            source_peer: batch.source_peer.clone(),
            batch_id: batch.batch_id.clone(),
            encapsulated_key: encapsulated_key.to_vec(),
            ciphertext,
            signature: Vec::new(),
        },
        transcript,
    ))
}

/// Installs and verifies an external Ed25519 signature before an audit envelope can be routed.
pub fn finish_audit_batch(
    mut sealed: SealedAuditBatchV1,
    signature: &[u8; 64],
    identity_public: &[u8; 32],
) -> Result<SealedAuditBatchV1, WireError> {
    if !sealed.signature.is_empty() {
        return Err(WireError::KindMismatch);
    }
    let encapsulated_key: [u8; 32] = sealed
        .encapsulated_key
        .as_slice()
        .try_into()
        .map_err(|_| WireError::InvalidLength)?;
    let aad = audit_aad(
        &sealed.mesh_id,
        &sealed.source_peer,
        &sealed.batch_id,
        &encapsulated_key,
    );
    VerifyingKey::from_bytes(identity_public)
        .map_err(|_| WireError::Authentication)?
        .verify(
            &audit_signature(&aad, &sealed.ciphertext),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| WireError::Authentication)?;
    sealed.signature = signature.to_vec();
    sealed.validate()?;
    Ok(sealed)
}

/// Verifies the authenticated Peer source and opens one HPKE audit batch.
pub fn open_audit_batch(
    sealed: &SealedAuditBatchV1,
    recipient_private: &[u8; 32],
    identity_public: &[u8; 32],
) -> Result<AuditBatchV1, WireError> {
    sealed.validate()?;
    let encapsulated_key: [u8; 32] = sealed
        .encapsulated_key
        .as_slice()
        .try_into()
        .map_err(|_| WireError::InvalidLength)?;
    let aad = audit_aad(
        &sealed.mesh_id,
        &sealed.source_peer,
        &sealed.batch_id,
        &encapsulated_key,
    );
    let verifier =
        VerifyingKey::from_bytes(identity_public).map_err(|_| WireError::Authentication)?;
    let signature =
        Signature::from_slice(&sealed.signature).map_err(|_| WireError::Authentication)?;
    verifier
        .verify(&audit_signature(&aad, &sealed.ciphertext), &signature)
        .map_err(|_| WireError::Authentication)?;
    let recipient = StaticSecret::from(*recipient_private);
    let recipient_public = X25519PublicKey::from(&recipient).to_bytes();
    let ephemeral = X25519PublicKey::from(encapsulated_key);
    let dh = recipient.diffie_hellman(&ephemeral).to_bytes();
    if dh == [0; 32] {
        return Err(WireError::Authentication);
    }
    let (key, nonce) = hpke_context(&dh, &encapsulated_key, &recipient_public)?;
    let plaintext = ChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &sealed.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| WireError::Authentication)?;
    let batch = AuditBatchV1::decode(plaintext.as_slice()).map_err(|_| WireError::KindMismatch)?;
    batch.validate()?;
    if batch.mesh_id != sealed.mesh_id
        || batch.source_peer != sealed.source_peer
        || batch.batch_id != sealed.batch_id
    {
        return Err(WireError::Authentication);
    }
    Ok(batch)
}

fn hpke_context(
    dh: &[u8; 32],
    encapsulated_key: &[u8; 32],
    recipient_public: &[u8; 32],
) -> Result<([u8; 32], [u8; 12]), WireError> {
    hpke_context_with_info(dh, encapsulated_key, recipient_public, AUDIT_INFO)
}

pub(crate) fn hpke_context_with_info(
    dh: &[u8; 32],
    encapsulated_key: &[u8; 32],
    recipient_public: &[u8; 32],
    info: &[u8],
) -> Result<([u8; 32], [u8; 12]), WireError> {
    let eae_prk = labeled_extract(&[], b"eae_prk", dh, KEM_SUITE_ID);
    let mut kem_context = Vec::with_capacity(64);
    kem_context.extend_from_slice(encapsulated_key);
    kem_context.extend_from_slice(recipient_public);
    let shared_secret =
        labeled_expand::<32>(&eae_prk, b"shared_secret", &kem_context, KEM_SUITE_ID)?;
    let psk_id_hash = labeled_extract(&[], b"psk_id_hash", &[], HPKE_SUITE_ID);
    let info_hash = labeled_extract(&[], b"info_hash", info, HPKE_SUITE_ID);
    let mut key_schedule_context = Vec::with_capacity(65);
    key_schedule_context.push(0); // Base mode.
    key_schedule_context.extend_from_slice(&psk_id_hash);
    key_schedule_context.extend_from_slice(&info_hash);
    let secret = labeled_extract(&shared_secret, b"secret", &[], HPKE_SUITE_ID);
    Ok((
        labeled_expand::<32>(&secret, b"key", &key_schedule_context, HPKE_SUITE_ID)?,
        labeled_expand::<12>(&secret, b"base_nonce", &key_schedule_context, HPKE_SUITE_ID)?,
    ))
}

fn labeled_extract(salt: &[u8], label: &[u8], input: &[u8], suite: &[u8]) -> [u8; 32] {
    let mut labeled = Vec::with_capacity(7 + suite.len() + label.len() + input.len());
    labeled.extend_from_slice(b"HPKE-v1");
    labeled.extend_from_slice(suite);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(input);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled);
    prk.into()
}

fn labeled_expand<const N: usize>(
    prk: &[u8; 32],
    label: &[u8],
    info: &[u8],
    suite: &[u8],
) -> Result<[u8; N], WireError> {
    let length = u16::try_from(N).map_err(|_| WireError::InvalidLength)?;
    let mut labeled = Vec::with_capacity(9 + suite.len() + label.len() + info.len());
    labeled.extend_from_slice(&length.to_be_bytes());
    labeled.extend_from_slice(b"HPKE-v1");
    labeled.extend_from_slice(suite);
    labeled.extend_from_slice(label);
    labeled.extend_from_slice(info);
    let mut output = [0; N];
    Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| WireError::Authentication)?
        .expand(&labeled, &mut output)
        .map_err(|_| WireError::Authentication)?;
    Ok(output)
}

fn audit_aad(mesh: &[u8], source: &[u8], batch: &[u8], enc: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AUDIT_INFO.len() + 80);
    aad.extend_from_slice(AUDIT_INFO);
    aad.extend_from_slice(mesh);
    aad.extend_from_slice(source);
    aad.extend_from_slice(batch);
    aad.extend_from_slice(enc);
    aad
}

fn audit_signature(aad: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let digest = Sha256::digest(ciphertext);
    let mut transcript = Vec::with_capacity(AUDIT_SIGNATURE_DOMAIN.len() + aad.len() + 32);
    transcript.extend_from_slice(AUDIT_SIGNATURE_DOMAIN);
    transcript.extend_from_slice(aad);
    transcript.extend_from_slice(&digest);
    transcript
}

fn is_uuid_v4(bytes: &[u8]) -> bool {
    bytes.len() == 16 && bytes[6] >> 4 == 4 && bytes[8] >> 6 == 2
}
