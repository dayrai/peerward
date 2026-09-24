async fn publish_peer_service(
    shared: &RelayShared,
    peer_id: PeerId,
    serial: CredentialSerial,
    request: &peerward_wire::ServicePublish,
) -> ServiceMutationResult {
    let parsed = parse_service_request(
        shared.config.mesh_id,
        &request.mesh_id,
        &request.service_id,
    );
    let protocols = match request.protocols.as_slice() {
        [1] => Some(vec![ServiceProtocol::Tcp]),
        [2] => Some(vec![ServiceProtocol::Udp]),
        [1, 2] => Some(vec![ServiceProtocol::Tcp, ServiceProtocol::Udp]),
        _ => None,
    };
    let listen_port = u16::try_from(request.listen_port)
        .ok()
        .filter(|port| *port != 0);
    let result = match (parsed, protocols, listen_port) {
        (Ok(service_id), Some(protocols), Some(listen_port)) => shared
            .store
            .publish_peer_service(
                shared.config.mesh_id,
                peer_id,
                serial,
                service_id,
                &protocols,
                listen_port,
                (!request.alias.is_empty()).then_some(request.alias.as_str()),
            )
            .await
            .map(|()| service_id),
        _ => Err(StoreError::Invalid("service request")),
    };
    service_result(shared.config.mesh_id, &request.service_id, result)
}

async fn remove_peer_service(
    shared: &RelayShared,
    peer_id: PeerId,
    serial: CredentialSerial,
    request: &peerward_wire::ServiceRemove,
) -> ServiceMutationResult {
    let result = match parse_service_request(
        shared.config.mesh_id,
        &request.mesh_id,
        &request.service_id,
    ) {
        Ok(service_id) => shared
            .store
            .remove_peer_service(
                shared.config.mesh_id,
                peer_id,
                serial,
                service_id,
            )
            .await
            .map(|()| service_id),
        Err(error) => Err(error),
    };
    service_result(shared.config.mesh_id, &request.service_id, result)
}

fn parse_service_request(
    mesh_id: MeshId,
    message_mesh: &[u8],
    service_id: &[u8],
) -> Result<ServiceId, StoreError> {
    if message_mesh != mesh_id.as_bytes() {
        return Err(StoreError::Invalid("service mesh"));
    }
    let id = uuid::Uuid::from_slice(service_id)
        .map_err(|_| StoreError::Invalid("service ID"))?;
    ServiceId::from_uuid(id).map_err(|_| StoreError::Invalid("service ID"))
}

fn service_result(
    mesh_id: MeshId,
    requested_id: &[u8],
    result: Result<ServiceId, StoreError>,
) -> ServiceMutationResult {
    match result {
        Ok(service_id) => ServiceMutationResult {
            mesh_id: mesh_id.as_bytes().to_vec(),
            service_id: service_id.as_bytes().to_vec(),
            committed: true,
            error: String::new(),
        },
        Err(error) => ServiceMutationResult {
            mesh_id: mesh_id.as_bytes().to_vec(),
            service_id: requested_id.to_vec(),
            committed: false,
            error: match error {
                StoreError::NotFound => "not_found",
                StoreError::Conflict | StoreError::ConfigurationOwned | StoreError::SignedStateConflict { .. } => "conflict",
                StoreError::Invalid(_) => "invalid",
                StoreError::Database(_)
                | StoreError::EventCursorExpired
                | StoreError::PoolExhausted
                | StoreError::LegacySchemaUnsupported
                | StoreError::NewerSchemaUnsupported => "unavailable",
            }
            .into(),
        },
    }
}

fn validate_rotation_request(
    mesh_id: MeshId,
    authenticated_serial: CredentialSerial,
    request: &peerward_wire::CredentialRotationRequest,
) -> Result<RotationId, RelayError> {
    if request.mesh_id != mesh_id.as_bytes()
        || request.current_serial != authenticated_serial.as_bytes()
        || request.identity_public_key.len() != 32
        || request.session_public_key.len() != 32
        || request.wireguard_public_key.len() != 32
        || request.signature.len() != 64
    {
        return Err(RelayError::InvalidConfig);
    }
    let id = uuid::Uuid::from_slice(&request.request_id).map_err(|_| RelayError::InvalidConfig)?;
    RotationId::from_uuid(id).map_err(|_| RelayError::InvalidConfig)
}

async fn promote_standby(
    shared: &RelayShared,
    lease: &mut PresenceLease,
    generation: &mut i64,
    credential_serial: CredentialSerial,
) -> Result<(), RelayError> {
    if lease.role == PresenceRole::Primary {
        return Ok(());
    }
    shared
        .store
        .release_presence(lease, *generation)
        .await
        .map_err(|error| match error {
            StoreError::Conflict | StoreError::SignedStateConflict { .. } => RelayError::StaleFence,
            other => RelayError::Store(other),
        })?;
    let standby = PresenceCacheEntry {
        peer_id: lease.peer_id,
        relay_id: lease.relay_id,
        attachment_id: lease.attachment_id,
        role: lease.role,
        generation: *generation,
        lease_deadline: lease.lease_deadline,
    };
    shared.presence.lock().await.release_local(standby)?;
    broadcast_presence(
        shared,
        PresenceAnnouncement {
            entry: standby,
            released: true,
        },
    )
    .await;
    lease.role = PresenceRole::Primary;
    let presence_generation = shared.store.acquire_presence(lease).await?;
    let attachment = shared.router.lock().await.install_acquired(
        lease.clone(),
        credential_serial,
        presence_generation,
    )?;
    *generation = attachment.generation;
    let primary = PresenceCacheEntry {
        peer_id: lease.peer_id,
        relay_id: lease.relay_id,
        attachment_id: lease.attachment_id,
        role: lease.role,
        generation: *generation,
        lease_deadline: lease.lease_deadline,
    };
    shared.presence.lock().await.observe_local(primary)?;
    broadcast_presence(
        shared,
        PresenceAnnouncement {
            entry: primary,
            released: false,
        },
    )
    .await;
    Ok(())
}
