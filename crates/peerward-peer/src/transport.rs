/// Routed handshake without client-side trust validation, for protocol probes.
/// Applications must use `connect_relay_ik_trusted`.
pub async fn connect_relay_ik_routed(endpoint: SocketAddr, local_private: &[u8;32], remote_public: &[u8;32],
    mesh: MeshId, relay: RelayId, hello: HandshakePayload) -> Result<(BoxStream, StreamTransport, HandshakePayload), PeerError> {
    let (mut socket, mut transport, welcome) = connect_relay_ik_with_underlay(endpoint, local_private, remote_public, hello, &LinuxUnderlayNetwork::default(),
        Some(peerward_wire::RelayPreface { mesh_id: mesh, target: relay, source: None }), None, None).await?;
    write_noise_record(&mut socket, &mut transport, &relay_admission(mesh)).await?;
    Ok((socket, transport, welcome))
}

type HeadlessRelayConnection = (BoxStream, StreamTransport, HandshakePayload);

async fn connect_relay_ik_with_underlay(
    endpoint: SocketAddr,
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
    hello: HandshakePayload,
    underlay: &dyn UnderlayNetwork,
    preface: Option<peerward_wire::RelayPreface>,
    terminal_trust: Option<&TrustSet>,
    carrier: Option<(&NetworkEndpoint, &peerward_carrier::ClientOptions)>,
) -> Result<(BoxStream, StreamTransport, HandshakePayload), PeerError> {
    let socket = dial_relay_carrier(endpoint, underlay, carrier).await?;
    connect_relay_ik_stream(socket, local_private, remote_public, hello, preface, terminal_trust).await
}

async fn dial_relay_carrier(endpoint: SocketAddr, underlay: &dyn UnderlayNetwork,
    carrier: Option<(&NetworkEndpoint, &peerward_carrier::ClientOptions)>) -> Result<BoxStream, PeerError> {
    let socket: BoxStream = if let Some((target, options)) = carrier.filter(|(target, _)| target.is_quic()) {
        let local = if endpoint.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }.parse().map_err(|_| PeerError::InvalidConfig)?;
        let socket = underlay.bind_udp(local).await.map_err(|error| PeerError::Io(std::io::Error::other(error)))?;
        peerward_carrier::quic::connect(socket.into_std()?, endpoint, &target.host(), options).await?.into_stream()
    } else {
        let socket = underlay.connect_tcp(endpoint).await.map_err(|error| PeerError::Io(std::io::Error::other(error)))?;
        socket.set_nodelay(true)?;
        let socket: BoxStream = Box::new(socket);
        if let Some((target, options)) = carrier { peerward_carrier::client(socket, target, options).await? } else { socket }
    };
    Ok(socket)
}

async fn connect_relay_ik_stream(mut socket: BoxStream, local_private: &[u8; 32], remote_public: &[u8; 32],
    hello: HandshakePayload, preface: Option<peerward_wire::RelayPreface>, terminal_trust: Option<&TrustSet>)
    -> Result<HeadlessRelayConnection, PeerError> {
    let mut handshake = if let Some(preface) = preface {
        socket.write_all(&preface.encode()).await?;
        preface.handshake(true, local_private, Some(remote_public))?
    } else { ik_initiator(local_private, remote_public)? };
    let mut ciphertext = vec![0; 65_535];
    let count = handshake
        .write_message(&hello.encode_to_vec(), &mut ciphertext)
        .map_err(WireError::Noise)?;
    write_handshake_frame(&mut socket, &ciphertext[..count]).await?;
    let response = read_handshake_frame(&mut socket).await?;
    if response.starts_with(b"PWM1") {
        let trust = terminal_trust.ok_or(PeerError::InvalidConfig)?;
        let terminal = peerward_credentials::MeshTermination::decode(&response)?;
        let now = peerward_types::UnixTime(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| PeerError::InvalidConfig)?.as_secs());
        trust.verify_termination(&terminal, 0, now)?;
        if socket.is_quic() { socket.write_all(b"PWTA").await?; socket.flush().await?; }
        return Err(PeerError::MeshTerminated(response));
    }
    let mut plaintext = vec![0; 65_535];
    let count = handshake
        .read_message(&response, &mut plaintext)
        .map_err(WireError::Noise)?;
    plaintext.truncate(count);
    let welcome =
        HandshakePayload::decode(plaintext.as_slice()).map_err(WireError::MalformedControl)?;
    welcome.negotiate(hello.capabilities)?;
    let transport = StreamTransport::from_handshake(handshake, monotonic_seconds())?;
    Ok((socket, transport, welcome))
}

/// Establishes IK and authenticates the Relay welcome through the configured Root.
pub async fn connect_relay_ik_trusted(
    endpoint: SocketAddr,
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
    expected_relay: RelayId,
    expected_mesh: MeshId,
    trust: &TrustSet,
    now: peerward_types::UnixTime,
    hello: HandshakePayload,
) -> Result<(BoxStream, StreamTransport, HandshakePayload), PeerError> {
    let underlay = LinuxUnderlayNetwork::default();
    connect_relay_ik_trusted_with_underlay(
        endpoint,
        local_private,
        remote_public,
        expected_relay,
        expected_mesh,
        trust,
        now,
        hello,
        &underlay,
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn connect_relay_ik_trusted_with_underlay(
    endpoint: SocketAddr,
    local_private: &[u8; 32],
    remote_public: &[u8; 32],
    expected_relay: RelayId,
    expected_mesh: MeshId,
    trust: &TrustSet,
    now: peerward_types::UnixTime,
    hello: HandshakePayload,
    underlay: &dyn UnderlayNetwork,
    carrier: Option<(&NetworkEndpoint, &peerward_carrier::ClientOptions)>,
) -> Result<(BoxStream, StreamTransport, HandshakePayload), PeerError> {
    let (socket, transport, welcome) =
        connect_relay_ik_with_underlay(endpoint, local_private, remote_public, hello, underlay, Some(peerward_wire::RelayPreface { mesh_id: expected_mesh, target: expected_relay, source: None }), Some(trust), carrier)
            .await?;
    let prepared = validate_relay_connection(socket, transport, welcome, remote_public, expected_relay, expected_mesh, trust, now).await?;
    commit_relay_connection(prepared, expected_mesh).await
}

async fn validate_relay_connection(mut socket: BoxStream, mut transport: StreamTransport, welcome: HandshakePayload,
    remote_public: &[u8; 32], expected_relay: RelayId, expected_mesh: MeshId, trust: &TrustSet, now: UnixTime)
    -> Result<HeadlessRelayConnection, PeerError> {
    let relay = SubjectCredential::decode(&welcome.credential)?;
    trust.verify_subject(&relay, now)?;
    if relay.subject != SubjectId::Relay(expected_relay)
        || relay.mesh_id != expected_mesh
        || relay.public_noise_key != *remote_public
    {
        return Err(PeerError::InvalidConfig);
    }
    let (upgraded_socket, upgraded_transport) = peerward_carrier::quic::activate(socket, transport,
        Some(peerward_wire::RelayPreface { mesh_id: expected_mesh, target: expected_relay, source: None }), monotonic_seconds()).await?;
    socket = upgraded_socket; transport = upgraded_transport;
    Ok((socket, transport, welcome))
}

fn relay_admission(mesh: MeshId) -> Record {
    Record::Control(ControlEnvelope { trace_context: None, message: Some(ControlMessage::Welcome(peerward_wire::Welcome {
        mesh_id: mesh.as_bytes().to_vec(), body: b"link_admit".to_vec(),
    })) })
}

async fn commit_relay_connection(connection: HeadlessRelayConnection, expected_mesh: MeshId) -> Result<HeadlessRelayConnection, PeerError> {
    let (mut socket, mut transport, welcome) = connection;
    write_noise_record(&mut socket, &mut transport, &relay_admission(expected_mesh)).await?;
    let ready = tokio::time::timeout(
        Duration::from_secs(5),
        read_noise_record(&mut socket, &mut transport),
    )
    .await
    .map_err(|_| PeerError::NoRelay)??;
    if !matches!(
        ready,
        Record::Control(ControlEnvelope {
            trace_context: _,
            message: Some(ControlMessage::Welcome(peerward_wire::Welcome {
                mesh_id,
                body,
            })),
        }) if mesh_id == expected_mesh.as_bytes() && body == b"link_ready"
    ) {
        return Err(PeerError::Wire(WireError::KindMismatch));
    }
    Ok((socket, transport, welcome))
}

async fn read_handshake_frame(stream: &mut BoxStream) -> Result<Vec<u8>, PeerError> {
    let length = stream.read_u16().await?;
    if length == 0 {
        return Err(PeerError::Wire(WireError::InvalidLength));
    }
    let mut bytes = vec![0; usize::from(length)];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn write_handshake_frame(stream: &mut BoxStream, bytes: &[u8]) -> Result<(), PeerError> {
    let length = u16::try_from(bytes.len()).map_err(|_| WireError::InvalidLength)?;
    if length == 0 {
        return Err(PeerError::Wire(WireError::InvalidLength));
    }
    stream.write_u16(length).await?;
    stream.write_all(bytes).await?;
    Ok(())
}

/// Runs the platform-neutral primary/standby transport portion until shutdown.
pub async fn run_transport(
    config: PeerConfig,
    local_private: [u8; 32],
    credential: Vec<u8>,
    trust: std::sync::Arc<TrustSet>,
) -> Result<(), PeerError> {
    let termination_path = config.private_key_file.with_extension("mesh-terminated");
    if termination_path.exists() {
        let bytes = peerward_credentials::private_files::read_private(&termination_path, 228)?;
        let terminal = peerward_credentials::MeshTermination::decode(&bytes)?;
        trust.verify_termination(&terminal, 0, UnixTime(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()))?;
        return Err(PeerError::MeshTerminated(bytes));
    }
    let mut tasks = tokio::task::JoinSet::new();
    for (slot, target) in config
        .relays
        .into_iter()
        .take(usize::from(config.relay_pool_size))
        .enumerate()
    {
        let credential = credential.clone();
        let private = local_private;
        let keepalive_seconds = config.keepalive_seconds;
        let unhealthy_after = config.unhealthy_after_missed;
        let trust = std::sync::Arc::clone(&trust);
        let mesh_id = config.mesh_id;
        let carrier_options = config.relay_transport.clone();
        tasks.spawn(async move {
            let public: [u8; 32] = hex::decode(&target.public_key)
                .map_err(|_| PeerError::InvalidConfig)?
                .try_into()
                .map_err(|_| PeerError::InvalidConfig)?;
            let mut attempt = 0_u8;
            let mut endpoint_pool = RelayEndpointPool::default().with_options(carrier_options.clone());
            let mut ready_connection = None;
            loop {
                let hello = HandshakePayload {
                    major: peerward_wire::PROTOCOL_MAJOR,
                    minor: 0,
                    capabilities: peerward_wire::SUPPORTED_CAPABILITIES
                        | if slot == 0 {
                            peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY
                        } else {
                            0
                        },
                    credential: credential.clone(),
                    attachment_id: AttachmentId::new().as_bytes().to_vec(),
                };
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(peerward_types::UnixTime(0), |value| {
                        peerward_types::UnixTime(value.as_secs())
                    });
                let connection = if let Some(connection) = ready_connection.take() {
                    Ok(connection)
                } else {
                    endpoint_pool
                        .connect_trusted(
                            &target.endpoints,
                            &private,
                            &public,
                            target.relay_id,
                            mesh_id,
                            &trust,
                            now,
                            hello,
                        )
                        .await
                };
                match connection {
                    Ok((mut socket, transport, _)) => {
                        attempt = 0;
                        match drive_relay_records(
                            &mut socket,
                            transport,
                            keepalive_seconds,
                            unhealthy_after,
                            target.clone(),
                            mesh_id,
                            private,
                            public,
                            credential.clone(),
                            Arc::clone(&trust),
                            slot == 0,
                            carrier_options.clone(),
                        )
                        .await
                        {
                            Ok(Some(connection)) => {
                                ready_connection = Some(connection);
                                continue;
                            }
                            Ok(None) => {}
                            Err(error @ PeerError::MeshTerminated(_)) => return Err(error),
                            Err(error) => {
                                tracing::warn!(relay_id = %target.relay_id, ?error, "Peer Relay session ended");
                            }
                        }
                    }
                    Err(error @ PeerError::MeshTerminated(_)) => return Err(error),
                    Err(error) => {
                        tracing::warn!(relay_id = %target.relay_id, ?error, "Peer Relay connection failed");
                        attempt = attempt.saturating_add(1);
                    }
                }
                tokio::time::sleep(SessionManager::reconnect_delay(attempt, target.relay_id)).await;
            }
            #[allow(unreachable_code)]
            Ok::<(), PeerError>(())
        });
    }
    let result = tokio::select! {
        signal = peerward_service::shutdown_signal() => signal.map_err(PeerError::Io),
        completed = tasks.join_next() => match completed {
            Some(Ok(result)) => result,
            _ => Err(PeerError::NoRelay),
        },
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    if let Err(PeerError::MeshTerminated(bytes)) = &result {
        peerward_credentials::private_files::write_private_atomic(&termination_path, bytes)?;
    }
    result
}

async fn drive_relay_records(
    socket: &mut BoxStream,
    mut transport: StreamTransport,
    keepalive_seconds: u64,
    unhealthy_after: u8,
    target: RelayTarget,
    mesh_id: MeshId,
    local_private: [u8; 32],
    remote_public: [u8; 32],
    credential: Vec<u8>,
    trust: Arc<TrustSet>,
    primary_attachment: bool,
    carrier_options: peerward_carrier::ClientOptions,
) -> Result<Option<HeadlessRelayConnection>, PeerError> {
    let started = tokio::time::Instant::now();
    let mut interval = tokio::time::interval(Duration::from_secs(keepalive_seconds));
    let mut epoch = tokio::time::interval(Duration::from_secs(1));
    epoch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut unanswered = 0_u8;
    let mut replacement = tokio::task::JoinSet::new();
    let mut retry_at = 0_u64;
    let mut attempt = 0_u8;
    loop {
        let now = monotonic_seconds();
        if transport.hard_expired(now) {
            replacement.abort_all();
            return Err(PeerError::Wire(WireError::RekeyRequired));
        }
        tokio::select! {
            _ = interval.tick() => {
                if unanswered >= unhealthy_after {
                    return Err(PeerError::NoRelay);
                }
                let timestamp = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                let probe = Record::Control(ControlEnvelope {
                    trace_context: None,
                    message: Some(ControlMessage::Keepalive(Keepalive {
                        monotonic_timestamp: timestamp,
                    })),
                });
                write_noise_record(socket, &mut transport, &probe).await?;
                unanswered = unanswered.saturating_add(1);
            }
            incoming = read_noise_record(socket, &mut transport) => {
                match incoming? {
                    Record::Control(ControlEnvelope {
                        trace_context: _,
                        message: Some(ControlMessage::Keepalive(_)),
                    }) => unanswered = 0,
                    Record::Control(ControlEnvelope {
                        trace_context: _,
                        message: Some(ControlMessage::Close(close)),
                    }) => {
                        if close.body.starts_with(b"PWM1") {
                            let terminal = peerward_credentials::MeshTermination::decode(&close.body)?;
                            trust.verify_termination(&terminal, 0, UnixTime(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()))?;
                            if close.mesh_id != mesh_id.as_bytes() { return Err(PeerError::InvalidConfig); }
                            return Err(PeerError::MeshTerminated(close.body));
                        }
                        return Ok(None);
                    },
                    Record::Control(_) | Record::Ipv4(_) | Record::Ipv6(_) => {}
                }
            }
            _ = epoch.tick(), if transport.rekey_due(now) && replacement.is_empty() && now >= retry_at => {
                let target = target.clone();
                let credential = credential.clone();
                let trust = Arc::clone(&trust);
                let carrier_options = carrier_options.clone();
                replacement.spawn(async move {
                    let hello = HandshakePayload {
                        major: peerward_wire::PROTOCOL_MAJOR,
                        minor: 0,
                        capabilities: peerward_wire::SUPPORTED_CAPABILITIES
                            | if primary_attachment {
                                peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY
                            } else {
                                0
                            },
                        credential,
                        attachment_id: AttachmentId::new().as_bytes().to_vec(),
                    };
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(UnixTime(0), |value| UnixTime(value.as_secs()));
                    connect_relay_endpoints_with_options(
                        &target.endpoints,
                        &local_private,
                        &remote_public,
                        target.relay_id,
                        mesh_id,
                        &trust,
                        now,
                        hello,
                        &carrier_options,
                    ).await
                });
            }
            completed = replacement.join_next(), if !replacement.is_empty() => {
                let completed = completed.ok_or(PeerError::NoRelay)?.map_err(|_| PeerError::NoRelay);
                match completed {
                    Ok(Ok(connection)) => {
                        let _ = write_noise_record(
                            socket,
                            &mut transport,
                            &Record::Control(ControlEnvelope {
                                trace_context: None,
                                message: Some(ControlMessage::Close(peerward_wire::GracefulClose {
                                    mesh_id: mesh_id.as_bytes().to_vec(),
                                    body: b"link_rekey".to_vec(),
                                })),
                            }),
                        ).await;
                        return Ok(Some(connection));
                    }
                    Ok(Err(error @ PeerError::MeshTerminated(_))) => return Err(error),
                    Ok(Err(error)) | Err(error) => {
                        tracing::warn!(relay_id = %target.relay_id, ?error, "Headless Relay link replacement failed");
                        attempt = attempt.saturating_add(1);
                        retry_at = monotonic_seconds().saturating_add(
                            SessionManager::reconnect_delay(attempt, target.relay_id).as_secs().max(1),
                        );
                    }
                }
            }
        }
    }
}

async fn read_noise_record(
    socket: &mut BoxStream,
    transport: &mut StreamTransport,
) -> Result<Record, PeerError> {
    let frame = transport.read_frame(socket).await?;
    Ok(transport.decode(&frame)?)
}

async fn write_noise_record(
    socket: &mut BoxStream,
    transport: &mut StreamTransport,
    record: &Record,
) -> Result<(), PeerError> {
    socket.write_all(&transport.encode(record)?).await?;
    socket.flush().await?;
    Ok(())
}
