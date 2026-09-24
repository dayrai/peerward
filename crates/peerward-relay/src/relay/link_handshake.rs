async fn accept_peer_ik_prefaced(
    stream: &mut (impl peerward_carrier::RelayIo + ?Sized), local_private: &[u8; 32], local_credential: &[u8],
    local_capabilities: u64, preface: Option<peerward_wire::RelayPreface>,
) -> Result<AcceptedPeer, RelayError> {
    let mut handshake = match preface {
        Some(preface) => preface.handshake(false, local_private, None)?,
        None => ik_responder(local_private)?,
    };
    let request = read_handshake_frame(stream).await?;
    let mut plaintext = vec![0; 65_535];
    let length = handshake
        .read_message(&request, &mut plaintext)
        .map_err(WireError::Noise)?;
    plaintext.truncate(length);
    let hello =
        HandshakePayload::decode(plaintext.as_slice()).map_err(WireError::MalformedControl)?;
    let negotiated = hello.negotiate(local_capabilities)?;
    let remote_static: [u8; 32] = handshake
        .get_remote_static()
        .ok_or(WireError::KindMismatch)?
        .try_into()
        .map_err(|_| WireError::KindMismatch)?;
    let welcome = HandshakePayload {
        major: peerward_wire::PROTOCOL_MAJOR,
        minor: hello.minor,
        capabilities: negotiated,
        credential: local_credential.to_vec(),
        attachment_id: hello.attachment_id.clone(),
    };
    let mut response = vec![0; 65_535];
    let size = handshake
        .write_message(&welcome.encode_to_vec(), &mut response)
        .map_err(WireError::Noise)?;
    response.truncate(size);
    write_handshake_frame(stream, &response).await?;
    Ok(AcceptedPeer {
        hello,
        remote_static,
        transport: StreamTransport::from_handshake(handshake, monotonic_seconds())?,
    })
}

async fn authenticate_peer_prefaced(
    stream: &mut (impl peerward_carrier::RelayIo + ?Sized), local_private: &[u8; 32], local_credential: &[u8],
    local_capabilities: u64, gate: &CredentialGate, now: UnixTime,
    preface: Option<peerward_wire::RelayPreface>,
) -> Result<AuthenticatedPeer, RelayError> {
    let accepted = accept_peer_ik_prefaced(
        stream,
        local_private,
        local_credential,
        local_capabilities,
        preface,
    )
    .await?;
    let credential = SubjectCredential::decode(&accepted.hello.credential)?;
    let peer_id = gate.peer(&credential, &accepted.remote_static, now)?;
    let attachment_uuid = uuid::Uuid::from_slice(&accepted.hello.attachment_id)
        .map_err(|_| RelayError::Wire(WireError::KindMismatch))?;
    let attachment_id = AttachmentId::from_uuid(attachment_uuid)
        .map_err(|_| RelayError::Wire(WireError::KindMismatch))?;
    Ok(AuthenticatedPeer {
        peer_id,
        credential_serial: credential.serial,
        attachment_id,
        primary_attachment: accepted.hello.capabilities
            & peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY
            != 0,
        capabilities: accepted.hello.capabilities,
        transport: accepted.transport,
    })
}

async fn relay_kk_prefaced(
    stream: &mut (impl peerward_carrier::RelayIo + ?Sized), initiator: bool, local_private: &[u8; 32],
    remote_public: &[u8; 32], preface: Option<peerward_wire::RelayPreface>,
) -> Result<StreamTransport, RelayError> {
    let mut handshake = match preface {
        Some(preface) => preface.handshake(initiator, local_private, Some(remote_public))?,
        None => kk_handshake(initiator, local_private, remote_public)?,
    };
    let mut buffer = vec![0; 65_535];
    if initiator {
        let size = handshake
            .write_message(b"", &mut buffer)
            .map_err(WireError::Noise)?;
        write_handshake_frame(stream, &buffer[..size]).await?;
        let response = read_handshake_frame(stream).await?;
        handshake
            .read_message(&response, &mut buffer)
            .map_err(WireError::Noise)?;
    } else {
        let request = read_handshake_frame(stream).await?;
        handshake
            .read_message(&request, &mut buffer)
            .map_err(WireError::Noise)?;
        let size = handshake
            .write_message(b"", &mut buffer)
            .map_err(WireError::Noise)?;
        write_handshake_frame(stream, &buffer[..size]).await?;
    }
    Ok(StreamTransport::from_handshake(
        handshake,
        monotonic_seconds(),
    )?)
}

async fn read_handshake_frame(stream: &mut (impl peerward_carrier::RelayIo + ?Sized)) -> Result<Vec<u8>, RelayError> {
    let length = stream.read_u16().await?;
    if length == 0 {
        return Err(RelayError::Wire(WireError::InvalidLength));
    }
    let mut bytes = vec![0; usize::from(length)];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn write_handshake_frame(stream: &mut (impl peerward_carrier::RelayIo + ?Sized), bytes: &[u8]) -> Result<(), RelayError> {
    let length = u16::try_from(bytes.len()).map_err(|_| WireError::InvalidLength)?;
    if length == 0 {
        return Err(RelayError::Wire(WireError::InvalidLength));
    }
    stream.write_u16(length).await?;
    stream.write_all(bytes).await?;
    Ok(())
}

/// Fenced attachment registered at this relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attachment {
    /// Peer identity.
    pub peer_id: PeerId,
    /// Session UUID.
    pub attachment_id: AttachmentId,
    /// Primary or standby role.
    pub role: PresenceRole,
    /// Monotonic database fencing generation.
    pub generation: i64,
    /// Credential authorized for the session.
    pub credential_serial: CredentialSerial,
}

/// Authenticated Peer control message routed through one or more Relays.
#[derive(Clone, PartialEq)]
pub struct RoutedControl {
    /// Peer authenticated by the ingress Relay.
    pub source: PeerId,
    /// Exact signed-directory destination.
    pub destination: PeerId,
    /// Source primary-presence generation authenticated by the ingress Relay.
    pub generation: i64,
    /// Typed control payload after Relay routing fields were normalized.
    pub envelope: ControlEnvelope,
}

/// Bounded sparse-backbone routing metadata authenticated by every Noise hop.
#[derive(Clone, PartialEq, Eq)]
struct BackboneRoute {
    origin: RelayId,
    destination: Option<RelayId>,
    topology_revision: u64,
    hop_limit: u8,
    visited: Vec<RelayId>,
}

#[derive(Clone)]
enum BackbonePayload {
    Control(RoutedControl),
    Presence(PresenceAnnouncement),
    RoutedControl(RoutedControl, BackboneRoute),
    RoutedPresence(PresenceAnnouncement, BackboneRoute),
}
