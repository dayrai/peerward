const PEER_ENTRY_DOMAIN: &[u8] = b"peerward/peer-directory-entry/v4\0";
const PEER_REVISION_DOMAIN: &[u8] = b"peerward/peer-directory-revision/v1\0";
const RELAY_DOMAIN: &[u8] = b"peerward/relay-directory/v2\0";
const RELAY_TOPOLOGY_DOMAIN: &[u8] = b"peerward/relay-topology/v1\0";
const POLICY_DOMAIN: &[u8] = b"peerward/policy-bundle/v1\0";
const REVOCATION_DOMAIN: &[u8] = b"peerward/revocation-bundle/v1\0";

/// Directory parsing, signature, or ordering failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DirectoryError {
    /// An Ed25519 signature did not authenticate its canonical transcript.
    #[error("directory signature is invalid")]
    InvalidSignature,
    /// A resource belongs to another mesh.
    #[error("directory resource belongs to another mesh")]
    WrongMesh,
    /// A revision would move an accepted resource backwards.
    #[error("directory revision rollback")]
    Rollback,
    /// Chunks disagree or have invalid bounds.
    #[error("directory chunk set is inconsistent")]
    MixedChunks,
    /// A canonical key is duplicated or out of order.
    #[error("directory entries are not canonical")]
    NonCanonical,
    /// A relay endpoint cannot be used for an internet transport.
    #[error("relay endpoint is invalid")]
    InvalidEndpoint,
    /// A serialized signed object is malformed.
    #[error("directory encoding is malformed")]
    Malformed,
}

/// Online signing key used only for revisioned distribution objects.
pub struct DirectorySigningKey(SigningKey);

impl DirectorySigningKey {
    /// Signs an exact bounded event body with a domain separated from network grants.
    pub fn sign_webhook(
        &self,
        notification: &peerward_management::WebhookNotification,
    ) -> Result<(Vec<u8>, [u8; 64]), peerward_management::ManagementError> {
        notification.sign(&self.0)
    }

    /// Signs the cross-component manifest using the rooted distribution identity.
    pub fn sign_manifest(
        &self,
        manifest: peerward_management::ConfigurationManifest,
    ) -> Result<peerward_management::SignedManifest, peerward_management::ManagementError> {
        peerward_management::SignedManifest::sign(manifest, &self.0)
    }
    /// Signs a time-bounded authorization lease independently of configuration version.
    pub fn sign_lease(
        &self,
        lease: peerward_management::AuthorizationLease,
    ) -> Result<peerward_management::SignedLease, peerward_management::ManagementError> {
        peerward_management::SignedLease::sign(lease, &self.0)
    }

    /// Imports a deterministic Ed25519 private seed.
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Self(SigningKey::from_bytes(seed))
    }

    /// Returns the verifier distributed through the rooted authority set.
    pub fn public_key(&self) -> DirectoryPublicKey {
        DirectoryPublicKey(self.0.verifying_key())
    }

    /// Signs one peer entry.
    pub fn sign_peer(&self, mut entry: PeerEntry) -> SignedPeerEntry {
        entry
            .accepted_credentials
            .sort_by_key(|credential| credential.serial);
        let signature = self.0.sign(&peer_entry_transcript(&entry)).to_bytes();
        SignedPeerEntry { entry, signature }
    }

    /// Signs a complete canonical peer-directory revision.
    pub fn sign_peers(
        &self,
        mesh_id: MeshId,
        revision: u64,
        mut entries: Vec<SignedPeerEntry>,
    ) -> Result<SignedPeerDirectory, DirectoryError> {
        entries.sort_by_key(|item| item.entry.peer_id);
        ensure_unique(entries.iter().map(|item| item.entry.peer_id))?;
        let unsigned = PeerDirectory {
            mesh_id,
            revision,
            entries,
        };
        let signature = self.0.sign(&peer_revision_transcript(&unsigned)).to_bytes();
        Ok(SignedPeerDirectory {
            directory: unsigned,
            signature,
        })
    }

    /// Signs a canonical relay-directory revision.
    pub fn sign_relays(
        &self,
        mesh_id: MeshId,
        revision: u64,
        mut entries: Vec<RelayEntry>,
    ) -> Result<SignedRelayDirectory, DirectoryError> {
        entries.sort_by_key(|item| item.relay_id);
        ensure_unique(entries.iter().map(|item| item.relay_id))?;
        for entry in &entries {
            validate_relay_endpoints(entry)?;
        }
        let directory = RelayDirectory {
            mesh_id,
            revision,
            entries,
        };
        let signature = self.0.sign(&relay_transcript(&directory)).to_bytes();
        Ok(SignedRelayDirectory {
            directory,
            signature,
        })
    }

    /// Signs a canonical Relay topology without changing the Relay Directory transcript.
    pub fn sign_relay_topology(
        &self,
        topology: RelayTopologyV1,
    ) -> Result<SignedRelayTopologyV1, DirectoryError> {
        topology.validate()?;
        let signature = self
            .0
            .sign(&relay_topology_transcript(&topology))
            .to_bytes();
        Ok(SignedRelayTopologyV1 {
            topology,
            signature,
        })
    }

    /// Signs an opaque, already validated policy representation.
    pub fn sign_policy(
        &self,
        mesh_id: MeshId,
        revision: u64,
        policy: Vec<u8>,
    ) -> SignedPolicyBundle {
        let bundle = PolicyBundle {
            mesh_id,
            revision,
            policy,
        };
        let signature = self.0.sign(&policy_transcript(&bundle)).to_bytes();
        SignedPolicyBundle { bundle, signature }
    }

    /// Signs the complete canonical set of exact credential revocations.
    pub fn sign_revocations(
        &self,
        mesh_id: MeshId,
        revision: u64,
        mut serials: Vec<CredentialSerial>,
    ) -> Result<SignedRevocationBundle, DirectoryError> {
        serials.sort_unstable();
        ensure_unique(serials.iter().copied())?;
        let bundle = RevocationBundle {
            mesh_id,
            revision,
            serials,
        };
        let signature = self.0.sign(&revocation_transcript(&bundle)).to_bytes();
        Ok(SignedRevocationBundle { bundle, signature })
    }
}

/// Ed25519 verifier for signed control-plane distribution objects.
#[derive(Debug, Clone, Copy)]
pub struct DirectoryPublicKey(VerifyingKey);

impl DirectoryPublicKey {
    /// Authenticates both management signatures and the embedded resource/DNS digests.
    pub fn verify_configuration(
        &self,
        delivery: &peerward_management::ConfigurationDelivery,
        mesh: MeshId,
    ) -> Result<(), peerward_management::ManagementError> {
        delivery.manifest.verify(&self.0, mesh)?;
        delivery.lease.verify(&self.0, mesh)?;
        delivery.validate_payload()
    }

    /// Imports exactly one Ed25519 public key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, DirectoryError> {
        VerifyingKey::from_bytes(bytes)
            .map(Self)
            .map_err(|_| DirectoryError::InvalidSignature)
    }

    /// Exports the verifier bytes.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Authenticates a peer entry and expected mesh.
    pub fn verify_peer(
        &self,
        signed: &SignedPeerEntry,
        mesh: MeshId,
    ) -> Result<(), DirectoryError> {
        if signed.entry.mesh_id != mesh {
            return Err(DirectoryError::WrongMesh);
        }
        if signed
            .entry
            .identity_public_key
            .iter()
            .all(|byte| *byte == 0)
            || signed.entry.noise_public_key.iter().all(|byte| *byte == 0)
        {
            return Err(DirectoryError::NonCanonical);
        }
        let entry = &signed.entry;
        if entry
            .secondary_address
            .is_some_and(|address| address.is_ipv4() == entry.address.is_ipv4())
        {
            return Err(DirectoryError::NonCanonical);
        }
        if !(1..=2).contains(&entry.accepted_credentials.len()) {
            return Err(DirectoryError::NonCanonical);
        }
        ensure_sorted_unique(
            entry
                .accepted_credentials
                .iter()
                .map(|credential| credential.serial),
        )?;
        ensure_unique(
            entry
                .accepted_credentials
                .iter()
                .map(|credential| credential.wireguard_public_key),
        )?;
        let active = entry
            .credential(entry.credential_serial)
            .ok_or(DirectoryError::NonCanonical)?;
        if active.identity_public_key != entry.identity_public_key
            || active.noise_public_key != entry.noise_public_key
            || active.not_after != entry.not_after
            || active.overlap_until.is_some()
        {
            return Err(DirectoryError::NonCanonical);
        }
        for credential in &entry.accepted_credentials {
            let wire = credential.subject(entry.mesh_id, entry.peer_id).encode();
            peerward_credentials::SubjectCredential::decode(&wire)
                .map_err(|_| DirectoryError::NonCanonical)?;
            if credential.serial != entry.credential_serial
                && credential.overlap_until.is_none_or(|until| {
                    until <= credential.not_before || until > credential.not_after
                })
            {
                return Err(DirectoryError::NonCanonical);
            }
        }
        verify(
            &self.0,
            &peer_entry_transcript(&signed.entry),
            &signed.signature,
        )
    }

    /// Authenticates a full peer directory, all entries, and monotonic revision.
    pub fn verify_peers(
        &self,
        signed: &SignedPeerDirectory,
        mesh: MeshId,
        accepted_revision: Option<u64>,
    ) -> Result<(), DirectoryError> {
        let directory = &signed.directory;
        ensure_scope_and_revision(
            directory.mesh_id,
            mesh,
            directory.revision,
            accepted_revision,
        )?;
        ensure_sorted_unique(directory.entries.iter().map(|item| item.entry.peer_id))?;
        ensure_unique(directory.entries.iter().flat_map(|entry| {
            entry
                .entry
                .accepted_credentials
                .iter()
                .map(|credential| credential.wireguard_public_key)
        }))?;
        ensure_unique(
            directory
                .entries
                .iter()
                .flat_map(|entry| entry.entry.addresses()),
        )?;
        for entry in &directory.entries {
            self.verify_peer(entry, mesh)?;
        }
        verify(
            &self.0,
            &peer_revision_transcript(directory),
            &signed.signature,
        )
    }

    /// Authenticates relay endpoints and monotonic revision.
    pub fn verify_relays(
        &self,
        signed: &SignedRelayDirectory,
        mesh: MeshId,
        accepted_revision: Option<u64>,
    ) -> Result<(), DirectoryError> {
        let directory = &signed.directory;
        ensure_scope_and_revision(
            directory.mesh_id,
            mesh,
            directory.revision,
            accepted_revision,
        )?;
        ensure_sorted_unique(directory.entries.iter().map(|entry| entry.relay_id))?;
        for entry in &directory.entries {
            validate_relay_endpoints(entry)?;
        }
        verify(&self.0, &relay_transcript(directory), &signed.signature)
    }

    /// Authenticates a separate Relay topology and its monotonic revision.
    pub fn verify_relay_topology(
        &self,
        signed: &SignedRelayTopologyV1,
        mesh: MeshId,
        accepted_revision: Option<u64>,
    ) -> Result<(), DirectoryError> {
        ensure_scope_and_revision(
            signed.topology.mesh_id,
            mesh,
            signed.topology.revision,
            accepted_revision,
        )?;
        signed.topology.validate()?;
        verify(
            &self.0,
            &relay_topology_transcript(&signed.topology),
            &signed.signature,
        )
    }

    /// Authenticates an ordered policy bundle.
    pub fn verify_policy(
        &self,
        signed: &SignedPolicyBundle,
        mesh: MeshId,
        accepted_revision: Option<u64>,
    ) -> Result<(), DirectoryError> {
        let bundle = &signed.bundle;
        ensure_scope_and_revision(bundle.mesh_id, mesh, bundle.revision, accepted_revision)?;
        verify(&self.0, &policy_transcript(bundle), &signed.signature)
    }

    /// Authenticates an exact, canonical revocation set and monotonic revision.
    pub fn verify_revocations(
        &self,
        signed: &SignedRevocationBundle,
        mesh: MeshId,
        accepted_revision: Option<u64>,
    ) -> Result<(), DirectoryError> {
        let bundle = &signed.bundle;
        ensure_scope_and_revision(bundle.mesh_id, mesh, bundle.revision, accepted_revision)?;
        ensure_sorted_unique(bundle.serials.iter().copied())?;
        verify(&self.0, &revocation_transcript(bundle), &signed.signature)
    }
}

/// One signed peer directory record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerEntry {
    /// Owning mesh.
    pub mesh_id: MeshId,
    /// Peer resource identifier.
    pub peer_id: PeerId,
    /// Stable assigned IPv4 or IPv6 address.
    pub address: IpAddr,
    /// Optional exact assignment in the other address family (Wire 5).
    pub secondary_address: Option<IpAddr>,
    /// Ed25519 identity verifier authenticated by the active credential.
    pub identity_public_key: [u8; 32],
    /// Active X25519 session key.
    pub noise_public_key: [u8; 32],
    /// Exact credential represented by this entry.
    pub credential_serial: CredentialSerial,
    /// Active credential plus every still-valid overlap credential.
    pub accepted_credentials: Vec<PeerCredentialBinding>,
    /// Administrative availability.
    pub enabled: bool,
    /// Canonically ordered selector labels.
    pub labels: BTreeMap<String, String>,
    /// Entry expiration bound.
    pub not_after: UnixTime,
}

/// Authority-signed credential and its directory-authorized overlap deadline.
/// An entry contains one active binding and at most one previous binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerCredentialBinding {
    /// Exact credential generation.
    pub serial: CredentialSerial,
    /// Device signing identity for this generation.
    pub identity_public_key: [u8; 32],
    /// Relay authentication public key for this generation.
    pub noise_public_key: [u8; 32],
    /// Independent `WireGuard` data public key for this generation.
    pub wireguard_public_key: [u8; 32],
    /// Inclusive credential validity start.
    pub not_before: UnixTime,
    /// Exclusive credential validity end.
    pub not_after: UnixTime,
    /// None for the active credential; exclusive deadline for the previous one.
    pub overlap_until: Option<UnixTime>,
    /// Original Authority signature, independently verified before key installation.
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
}

impl PeerCredentialBinding {
    /// Copies the authenticated fields of a Peer credential.
    pub fn from_subject(
        credential: &peerward_credentials::SubjectCredential,
        overlap_until: Option<UnixTime>,
    ) -> Self {
        Self {
            serial: credential.serial,
            identity_public_key: credential.identity_public_key,
            noise_public_key: credential.public_noise_key,
            wireguard_public_key: credential.wireguard_public_key,
            not_before: credential.not_before,
            not_after: credential.not_after,
            overlap_until,
            signature: credential.signature,
        }
    }

    /// Reconstructs the exact Authority-signed Peer credential for Root verification.
    pub fn subject(
        &self,
        mesh_id: MeshId,
        peer_id: PeerId,
    ) -> peerward_credentials::SubjectCredential {
        peerward_credentials::SubjectCredential {
            role: peerward_types::SubjectRole::Peer,
            subject: peerward_credentials::SubjectId::Peer(peer_id),
            mesh_id,
            identity_public_key: self.identity_public_key,
            public_noise_key: self.noise_public_key,
            wireguard_public_key: self.wireguard_public_key,
            serial: self.serial,
            not_before: self.not_before,
            not_after: self.not_after,
            signature: self.signature,
        }
    }

    /// Applies both the signed credential lifetime and the directory overlap bound.
    pub fn valid_at(&self, now: UnixTime) -> bool {
        self.not_before <= now
            && now < self.not_after
            && self.overlap_until.is_none_or(|until| now < until)
    }
}

impl PeerEntry {
    /// Exact assignments only; routes behind a provider never become Peer identity.
    pub fn addresses(&self) -> impl Iterator<Item = IpAddr> + use<> {
        std::iter::once(self.address).chain(self.secondary_address)
    }

    /// Finds a generation without substituting the active generation's key.
    pub fn credential(&self, serial: CredentialSerial) -> Option<&PeerCredentialBinding> {
        self.accepted_credentials
            .iter()
            .find(|credential| credential.serial == serial)
    }
}

/// Individually signed peer entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPeerEntry {
    /// Covered fields.
    pub entry: PeerEntry,
    /// Ed25519 signature.
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
}

/// Unsigned body of a peer-directory revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerDirectory {
    /// Owning mesh.
    pub mesh_id: MeshId,
    /// Monotonic revision.
    pub revision: u64,
    /// Entries sorted by raw peer UUID.
    pub entries: Vec<SignedPeerEntry>,
}

/// Signed peer-directory revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPeerDirectory {
    /// Covered directory.
    pub directory: PeerDirectory,
    /// Revision signature.
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
}

/// One relay advertised inside a mesh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayEntry {
    /// Relay resource identifier.
    pub relay_id: RelayId,
    /// Ordered peer-facing TCP endpoints.
    pub peer_endpoints: Vec<NetworkEndpoint>,
    /// Ordered Relay backbone TCP endpoints.
    pub backbone_endpoints: Vec<NetworkEndpoint>,
    /// X25519 static identity.
    pub noise_public_key: [u8; 32],
    /// Exact active credential.
    pub credential_serial: CredentialSerial,
}

/// Unsigned relay directory fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayDirectory {
    /// Owning mesh.
    pub mesh_id: MeshId,
    /// Monotonic revision.
    pub revision: u64,
    /// Entries sorted by raw relay UUID.
    pub entries: Vec<RelayEntry>,
}

/// Signed relay-directory revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRelayDirectory {
    /// Covered directory.
    pub directory: RelayDirectory,
    /// Ed25519 signature.
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
}

include!("relay_topology.rs");
/// Policy bundle fields signed independently of transport JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyBundle {
    /// Owning mesh.
    pub mesh_id: MeshId,
    /// Monotonic revision.
    pub revision: u64,
    /// Validated policy encoding.
    pub policy: Vec<u8>,
}

/// Signed policy update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPolicyBundle {
    /// Covered bundle.
    pub bundle: PolicyBundle,
    /// Ed25519 signature.
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
}

/// Complete exact credential revocation set for one mesh revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationBundle {
    /// Owning mesh.
    pub mesh_id: MeshId,
    /// Monotonic revocation revision.
    pub revision: u64,
    /// Canonically sorted exact credential serials.
    pub serials: Vec<CredentialSerial>,
}

/// Signed exact-revocation replacement bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRevocationBundle {
    /// Covered revocation set.
    pub bundle: RevocationBundle,
    /// Ed25519 signature over the fixed transcript.
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
}
