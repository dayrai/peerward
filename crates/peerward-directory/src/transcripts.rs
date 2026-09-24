fn peer_entry_transcript(entry: &PeerEntry) -> Vec<u8> {
    let mut bytes = Vec::from(PEER_ENTRY_DOMAIN);
    bytes.extend_from_slice(entry.mesh_id.as_bytes());
    bytes.extend_from_slice(entry.peer_id.as_bytes());
    match entry.address {
        IpAddr::V4(address) => {
            bytes.push(4);
            bytes.extend_from_slice(&address.octets());
        }
        IpAddr::V6(address) => {
            bytes.push(6);
            bytes.extend_from_slice(&address.octets());
        }
    }
    match entry.secondary_address {
        None => bytes.push(0),
        Some(IpAddr::V4(address)) => {
            bytes.push(4);
            bytes.extend_from_slice(&address.octets());
        }
        Some(IpAddr::V6(address)) => {
            bytes.push(6);
            bytes.extend_from_slice(&address.octets());
        }
    }
    bytes.extend_from_slice(&entry.identity_public_key);
    bytes.extend_from_slice(&entry.noise_public_key);
    bytes.extend_from_slice(entry.credential_serial.as_bytes());
    put_u32(&mut bytes, entry.accepted_credentials.len());
    for credential in &entry.accepted_credentials {
        bytes.extend_from_slice(&credential.subject(entry.mesh_id, entry.peer_id).encode());
        match credential.overlap_until {
            None => bytes.push(0),
            Some(until) => {
                bytes.push(1);
                bytes.extend_from_slice(&until.0.to_be_bytes());
            }
        }
    }
    bytes.push(u8::from(entry.enabled));
    put_u32(&mut bytes, entry.labels.len());
    for (key, value) in &entry.labels {
        put_bytes(&mut bytes, key.as_bytes());
        put_bytes(&mut bytes, value.as_bytes());
    }
    bytes.extend_from_slice(&entry.not_after.0.to_be_bytes());
    bytes
}

fn peer_revision_transcript(directory: &PeerDirectory) -> Vec<u8> {
    let mut bytes = Vec::from(PEER_REVISION_DOMAIN);
    bytes.extend_from_slice(directory.mesh_id.as_bytes());
    bytes.extend_from_slice(&directory.revision.to_be_bytes());
    put_u32(&mut bytes, directory.entries.len());
    for item in &directory.entries {
        bytes.extend_from_slice(item.entry.peer_id.as_bytes());
        bytes.extend_from_slice(&item.signature);
    }
    bytes
}

fn relay_transcript(directory: &RelayDirectory) -> Vec<u8> {
    let mut bytes = Vec::from(RELAY_DOMAIN);
    bytes.extend_from_slice(directory.mesh_id.as_bytes());
    bytes.extend_from_slice(&directory.revision.to_be_bytes());
    put_u32(&mut bytes, directory.entries.len());
    for entry in &directory.entries {
        bytes.extend_from_slice(entry.relay_id.as_bytes());
        put_u32(&mut bytes, entry.peer_endpoints.len());
        for endpoint in &entry.peer_endpoints {
            put_bytes(&mut bytes, endpoint.as_str().as_bytes());
        }
        put_u32(&mut bytes, entry.backbone_endpoints.len());
        for endpoint in &entry.backbone_endpoints {
            put_bytes(&mut bytes, endpoint.as_str().as_bytes());
        }
        bytes.extend_from_slice(&entry.noise_public_key);
        bytes.extend_from_slice(entry.credential_serial.as_bytes());
    }
    bytes
}

fn relay_topology_transcript(topology: &RelayTopologyV1) -> Vec<u8> {
    let mut bytes = Vec::from(RELAY_TOPOLOGY_DOMAIN);
    bytes.extend_from_slice(topology.mesh_id.as_bytes());
    bytes.extend_from_slice(&topology.revision.to_be_bytes());
    bytes.push(match topology.mode {
        RelayTopologyMode::FullMesh => 0,
        RelayTopologyMode::Sparse => 1,
    });
    put_u32(&mut bytes, topology.nodes.len());
    for node in &topology.nodes {
        bytes.extend_from_slice(node.relay_id.as_bytes());
        put_bytes(&mut bytes, node.region.as_bytes());
        bytes.extend_from_slice(&node.routing_weight.to_be_bytes());
        bytes.extend_from_slice(&node.capabilities.to_be_bytes());
    }
    put_u32(&mut bytes, topology.edges.len());
    for edge in &topology.edges {
        bytes.extend_from_slice(edge.left.as_bytes());
        bytes.extend_from_slice(edge.right.as_bytes());
        bytes.extend_from_slice(&edge.rtt_millis.to_be_bytes());
        bytes.extend_from_slice(&edge.loss_permyriad.to_be_bytes());
    }
    bytes
}

fn policy_transcript(bundle: &PolicyBundle) -> Vec<u8> {
    let mut bytes = Vec::from(POLICY_DOMAIN);
    bytes.extend_from_slice(bundle.mesh_id.as_bytes());
    bytes.extend_from_slice(&bundle.revision.to_be_bytes());
    put_bytes(&mut bytes, &bundle.policy);
    bytes
}

fn revocation_transcript(bundle: &RevocationBundle) -> Vec<u8> {
    let mut bytes = Vec::from(REVOCATION_DOMAIN);
    bytes.extend_from_slice(bundle.mesh_id.as_bytes());
    bytes.extend_from_slice(&bundle.revision.to_be_bytes());
    put_u32(&mut bytes, bundle.serials.len());
    for serial in &bundle.serials {
        bytes.extend_from_slice(serial.as_bytes());
    }
    bytes
}

fn put_u32(bytes: &mut Vec<u8>, value: usize) {
    bytes.extend_from_slice(
        &u32::try_from(value)
            .expect("validated directory collection length")
            .to_be_bytes(),
    );
}

fn put_bytes(output: &mut Vec<u8>, value: &[u8]) {
    put_u32(output, value.len());
    output.extend_from_slice(value);
}

fn verify(key: &VerifyingKey, transcript: &[u8], bytes: &[u8; 64]) -> Result<(), DirectoryError> {
    key.verify(transcript, &Signature::from_bytes(bytes))
        .map_err(|_| DirectoryError::InvalidSignature)
}

fn ensure_scope_and_revision(
    actual_mesh: MeshId,
    expected_mesh: MeshId,
    revision: u64,
    accepted: Option<u64>,
) -> Result<(), DirectoryError> {
    if actual_mesh != expected_mesh {
        return Err(DirectoryError::WrongMesh);
    }
    if accepted.is_some_and(|value| revision <= value) {
        return Err(DirectoryError::Rollback);
    }
    Ok(())
}

fn ensure_unique<T: Ord>(items: impl Iterator<Item = T>) -> Result<(), DirectoryError> {
    let mut seen = BTreeSet::new();
    if items.into_iter().all(|item| seen.insert(item)) {
        Ok(())
    } else {
        Err(DirectoryError::NonCanonical)
    }
}

fn ensure_sorted_unique<T: Ord>(items: impl Iterator<Item = T>) -> Result<(), DirectoryError> {
    let mut previous = None;
    for item in items {
        if previous.as_ref().is_some_and(|old| old >= &item) {
            return Err(DirectoryError::NonCanonical);
        }
        previous = Some(item);
    }
    Ok(())
}

fn validate_relay_endpoints(entry: &RelayEntry) -> Result<(), DirectoryError> {
    validate_endpoint_list(&entry.peer_endpoints).map_err(|_| DirectoryError::InvalidEndpoint)?;
    validate_endpoint_list(&entry.backbone_endpoints).map_err(|_| DirectoryError::InvalidEndpoint)
}

mod signature_bytes {
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| de::Error::custom("signature must contain 64 bytes"))
    }
}
