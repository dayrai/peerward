#[allow(clippy::too_many_arguments)]
async fn assert_diagnostic_probe_preserves_presence(
    store: &Store,
    endpoint: std::net::SocketAddr,
    relay: RelayId,
    relay_public: &[u8; 32],
    private: &[u8; 32],
    credential: &peerward_credentials::SubjectCredential,
    root: peerward_credentials::RootPublicKey,
    authority: peerward_credentials::AuthorityCertificate,
    now: UnixTime,
) {
    let SubjectId::Peer(peer) = credential.subject else {
        panic!("test requires a Peer credential")
    };
    let mut trust = TrustSet::new(root, credential.mesh_id);
    trust.add_authority(authority, now).unwrap();
    let query = "SELECT attachment_id,fencing_generation FROM relay_presence WHERE mesh_id=$1 AND peer_id=$2";
    let before: (uuid::Uuid, i64) = sqlx::query_as(query)
        .bind(credential.mesh_id.into_uuid()).bind(peer.into_uuid())
        .fetch_one(store.pool()).await.unwrap();
    peerward_peer::probe_relay_endpoints_with_options(
        &[format!("tcp://{endpoint}").parse().unwrap()], private, relay_public,
        relay, credential.mesh_id, &trust, now,
        HandshakePayload {
            major: peerward_wire::PROTOCOL_MAJOR,
            minor: 0,
            capabilities: peerward_wire::SUPPORTED_CAPABILITIES
                | peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY,
            credential: credential.encode(),
            attachment_id: AttachmentId::new().as_bytes().to_vec(),
        },
        &peerward_carrier::ClientOptions::default(),
    ).await.unwrap();
    let after: Option<(uuid::Uuid, i64)> = sqlx::query_as(query)
        .bind(credential.mesh_id.into_uuid()).bind(peer.into_uuid())
        .fetch_optional(store.pool()).await.unwrap();
    assert_eq!(after, Some(before), "diagnostics replaced the live Peer attachment");
    // The caller next sends through the original connection, including over
    // the backbone, so retaining the database row alone is insufficient.
}
