fn backbone_payload_envelope(
    mesh_id: MeshId,
    payload: &BackbonePayload,
) -> Result<ControlEnvelope, RelayError> {
    Ok(ControlEnvelope {
        trace_context: None,
        message: Some(ControlMessage::Forwarded(ForwardedPacket {
            mesh_id: mesh_id.as_bytes().to_vec(),
            body: encode_backbone_payload(payload)?,
        })),
    })
}

fn unix_time() -> UnixTime {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    UnixTime(seconds)
}

/// Monotonic keepalive state shared by peer and backbone connection drivers.
#[derive(Debug, Clone)]
pub struct ConnectionHealth {
    outstanding: Option<u64>,
    missed: u8,
    unhealthy_after: u8,
    rtt_millis: Option<u64>,
    samples: VecDeque<bool>,
}

impl ConnectionHealth {
    /// Creates a tracker with a nonzero missed-reply threshold.
    pub fn new(unhealthy_after: u8) -> Result<Self, RelayError> {
        if unhealthy_after == 0 {
            return Err(RelayError::InvalidConfig);
        }
        Ok(Self {
            outstanding: None,
            missed: 0,
            unhealthy_after,
            rtt_millis: None,
            samples: VecDeque::with_capacity(32),
        })
    }

    /// Starts a probe, counting any previous unanswered probe.
    pub fn probe(&mut self, monotonic_millis: u64) -> bool {
        if self.outstanding.replace(monotonic_millis).is_some() {
            self.missed = self.missed.saturating_add(1);
            self.record_sample(false);
        }
        self.missed >= self.unhealthy_after
    }

    /// Accepts only the exact echoed monotonic timestamp and records RTT.
    pub fn reply(&mut self, echoed: u64, now: u64) -> bool {
        if self.outstanding != Some(echoed) {
            return false;
        }
        self.outstanding = None;
        self.missed = 0;
        let sample = now.saturating_sub(echoed);
        self.rtt_millis = Some(
            self.rtt_millis
                .map_or(sample, |current| current.saturating_mul(7).saturating_add(sample) / 8),
        );
        self.record_sample(true);
        true
    }

    /// Last authenticated round-trip duration.
    pub const fn rtt_millis(&self) -> Option<u64> {
        self.rtt_millis
    }

    fn record_sample(&mut self, received: bool) {
        if self.samples.len() == 32 {
            self.samples.pop_front();
        }
        self.samples.push_back(received);
    }

    fn snapshot(&self, relay_id: RelayId) -> Option<RelayNeighborHealth> {
        let rtt_millis = u32::try_from(self.rtt_millis?).unwrap_or(u32::MAX);
        let lost = self.samples.iter().filter(|received| !**received).count();
        let loss_permyriad = u16::try_from(
            lost.saturating_mul(10_000)
                .checked_div(self.samples.len())
                .unwrap_or(0),
        )
        .unwrap_or(10_000);
        Some(RelayNeighborHealth {
            relay_id,
            rtt_millis,
            loss_permyriad,
            samples: u8::try_from(self.samples.len()).unwrap_or(32),
        })
    }
}

async fn record_backbone_health(
    shared: &RelayShared,
    remote: RelayId,
    health: &ConnectionHealth,
) {
    if let Some(snapshot) = health.snapshot(remote) {
        shared.backbone_health.lock().await.insert(remote, snapshot);
    }
}

/// Builds independently bounded Prost directory messages for one peer attachment.
pub fn peer_directory_delivery(
    directory: &SignedPeerDirectory,
    maximum_body: usize,
) -> Result<Vec<ControlEnvelope>, RelayError> {
    let bytes = encode_peer_directory(directory)?;
    split_chunks(
        directory.directory.mesh_id,
        directory.directory.revision,
        &bytes,
        maximum_body,
    )?
    .into_iter()
    .map(|chunk| {
        Ok(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::PeerDirectory(PeerDirectoryChunk {
                mesh_id: chunk.mesh_id.as_bytes().to_vec(),
                revision: chunk.revision,
                index: chunk.index,
                count: chunk.count,
                body: chunk.body,
            })),
        })
    })
    .collect()
}

/// Builds independently bounded Prost relay-directory messages.
pub fn relay_directory_delivery(
    directory: &SignedRelayDirectory,
    maximum_body: usize,
) -> Result<Vec<ControlEnvelope>, RelayError> {
    let bytes = encode_relay_directory(directory)?;
    split_chunks(
        directory.directory.mesh_id,
        directory.directory.revision,
        &bytes,
        maximum_body,
    )?
    .into_iter()
    .map(|chunk| {
        Ok(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::RelayDirectory(RelayDirectoryChunk {
                mesh_id: chunk.mesh_id.as_bytes().to_vec(),
                revision: chunk.revision,
                index: chunk.index,
                count: chunk.count,
                body: chunk.body,
            })),
        })
    })
    .collect()
}

/// Builds independently bounded signed-policy messages.
pub fn policy_delivery(
    policy: &SignedPolicyBundle,
    maximum_body: usize,
) -> Result<Vec<ControlEnvelope>, RelayError> {
    split_chunks(
        policy.bundle.mesh_id,
        policy.bundle.revision,
        &encode_policy(policy)?,
        maximum_body,
    )?
    .into_iter()
    .map(|chunk| {
        Ok(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Policy(WirePolicyBundle {
                mesh_id: chunk.mesh_id.as_bytes().to_vec(),
                revision: chunk.revision,
                index: chunk.index,
                count: chunk.count,
                body: chunk.body,
            })),
        })
    })
    .collect()
}

/// Builds independently bounded signed-service snapshot messages.
pub fn service_snapshot_delivery(
    snapshot: &SignedRemoteServiceSnapshot,
    maximum_body: usize,
) -> Result<Vec<ControlEnvelope>, RelayError> {
    let bytes = serde_json::to_vec(snapshot).map_err(|_| RelayError::InvalidConfig)?;
    split_chunks(
        snapshot.snapshot.mesh_id,
        snapshot.snapshot.revision,
        &bytes,
        maximum_body,
    )?
    .into_iter()
    .map(|chunk| {
        Ok(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Services(WireServiceSnapshot {
                mesh_id: chunk.mesh_id.as_bytes().to_vec(),
                revision: chunk.revision,
                index: chunk.index,
                count: chunk.count,
                body: chunk.body,
            })),
        })
    })
    .collect()
}

/// Builds independently bounded exact-revocation messages.
pub fn revocation_delivery(
    revocations: &SignedRevocationBundle,
    maximum_body: usize,
) -> Result<Vec<ControlEnvelope>, RelayError> {
    split_chunks(
        revocations.bundle.mesh_id,
        revocations.bundle.revision,
        &encode_revocations(revocations)?,
        maximum_body,
    )?
    .into_iter()
    .map(|chunk| {
        Ok(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Revocation(CredentialRevocation {
                mesh_id: chunk.mesh_id.as_bytes().to_vec(),
                revision: chunk.revision,
                index: chunk.index,
                count: chunk.count,
                body: chunk.body,
            })),
        })
    })
    .collect()
}

fn require_version_first(contents: &str) -> Result<(), RelayError> {
    let first = contents
        .lines()
        .find(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .map(str::trim);
    if first == Some("config_version = 1") {
        Ok(())
    } else {
        Err(RelayError::InvalidConfig)
    }
}
fn topology_neighbors(
    topology: &peerward_directory::RelayTopologyV1,
    local: RelayId,
) -> Option<BTreeSet<RelayId>> {
    topology
        .nodes
        .iter()
        .any(|node| node.relay_id == local)
        .then(|| {
            topology
                .edges
                .iter()
                .filter_map(|edge| edge.other(local))
                .collect()
        })
}
