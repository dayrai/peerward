async fn run_control(path: &Path) -> Result<(), CliError> {
    let contents = read_bounded_utf8(path, 1024 * 1024)?;
    let mut config = ControlConfig::parse(&contents, std::env::var("PEERWARD_DATABASE_URL").ok())
        .map_err(|_| CliError::invalid("invalid control configuration"))?;
    if let (Some(oidc), Ok(secret)) = (
        config.oidc.as_mut(),
        std::env::var("PEERWARD_OIDC_CLIENT_SECRET"),
    ) {
        oidc.client_secret = Some(secret);
    }
    let bootstrap = std::env::var("PEERWARD_BOOTSTRAP_TOKEN").ok();
    let auth = AuthConfig {
        oidc: config.oidc.clone(),
        development_bearer_token: std::env::var("PEERWARD_DEV_BEARER").ok(),
        bootstrap_token: bootstrap,
    };
    peerward_control::serve(config, auth)
        .await
        .map_err(|error| CliError {
            code: EXIT_UNAVAILABLE,
            message: format!("control startup failed: {error}"),
        })
}

async fn run_relay(path: &Path) -> Result<(), CliError> {
    let contents = read_bounded_utf8(path, 1024 * 1024)?;
    if toml::from_str::<toml::Value>(&contents)
        .ok()
        .and_then(|v| v.get("config_version").and_then(toml::Value::as_integer))
        == Some(2)
    {
        let config = peerward_relay::RelayHostConfig::parse(
            &contents,
            path,
            std::env::var("PEERWARD_DATABASE_URL").ok(),
        )
        .map_err(|_| CliError::invalid("invalid Relay host configuration"))?;
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            let _ = peerward_service::shutdown_signal().await;
            let _ = stop.send(true);
        });
        return peerward_relay::serve_host(config, shutdown)
            .await
            .map_err(|_| CliError::unavailable("Relay host failed"));
    }
    let config = RelayConfig::parse(&contents, path, std::env::var("PEERWARD_DATABASE_URL").ok())
        .map_err(|_| CliError::invalid("invalid relay configuration"))?;
    validate_private_permissions(&config.private_key_file)?;
    let key = Zeroizing::new(read_hex_32(&config.private_key_file)?);
    let root = RootPublicKey::from_bytes(&read_hex_32(&config.root_public_key_file)?)
        .map_err(|_| CliError::invalid("invalid relay root public key"))?;
    let authority = read_authority_certificate(&config.authority_certificate_file)?;
    if authority.mesh_id != config.mesh_id {
        return Err(CliError::invalid("authority certificate mesh mismatch"));
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliError::failure("system clock is before the Unix epoch"))?
        .as_secs();
    let mut trust = TrustSet::new(root, config.mesh_id);
    trust
        .add_authority(authority, UnixTime(now))
        .map_err(|_| CliError::invalid("authority certificate is not root anchored"))?;
    let relay_credential_bytes = read_bounded_regular_file(&config.credential_file, 65_536)?;
    let relay_credential = SubjectCredential::decode(&relay_credential_bytes)
        .map_err(|_| CliError::invalid("invalid relay credential"))?;
    trust
        .verify_subject(&relay_credential, UnixTime(now))
        .map_err(|_| CliError::invalid("relay credential is not currently trusted"))?;
    let noise_public = NoisePublicKey::from(&StaticSecret::from(*key)).to_bytes();
    if relay_credential.subject != SubjectId::Relay(config.relay_id)
        || relay_credential.public_noise_key != noise_public
    {
        return Err(CliError::invalid(
            "relay credential identity or Noise key mismatch",
        ));
    }
    let distribution_bytes =
        read_bounded_regular_file(&config.distribution_certificate_file, 65_536)?;
    let distribution = DistributionCertificate::decode(&distribution_bytes)
        .map_err(|_| CliError::invalid("invalid distribution certificate"))?;
    trust
        .verify_distribution(&distribution, UnixTime(now))
        .map_err(|_| CliError::invalid("distribution certificate is not currently trusted"))?;
    let gate = std::sync::Arc::new(peerward_relay::CredentialGate::new(trust));
    let database_url = config
        .database_url
        .as_deref()
        .ok_or_else(|| CliError::invalid("relay database URL is required"))?;
    let store = Store::connect(database_url, 8)
        .await
        .map_err(|_| CliError::unavailable("relay database is unavailable"))?;
    store
        .migrate()
        .await
        .map_err(|_| CliError::failure("relay database migration failed"))?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        let _ = peerward_service::shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });
    peerward_relay::serve(
        config,
        *key,
        relay_credential_bytes,
        distribution,
        gate,
        store,
        shutdown_rx,
    )
    .await
    .map_err(|_| CliError::unavailable("relay service failed"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorityDocument {
    schema_version: u32,
    mesh_id: MeshId,
    serial: CredentialSerial,
    public_key: String,
    not_before: u64,
    not_after: u64,
    signature: String,
}

fn read_authority_certificate(path: &Path) -> Result<AuthorityCertificate, CliError> {
    let bytes = read_bounded_regular_file(path, 65_536)?;
    if let Ok(certificate) = AuthorityCertificate::decode(&bytes) {
        return Ok(certificate);
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| CliError::invalid("invalid authority certificate encoding"))?;
    let document: AuthorityDocument = toml::from_str(text)
        .map_err(|_| CliError::invalid("invalid authority certificate document"))?;
    if document.schema_version != 1 {
        return Err(CliError::invalid(
            "unsupported authority certificate schema version",
        ));
    }
    Ok(AuthorityCertificate {
        mesh_id: document.mesh_id,
        serial: document.serial,
        public_key: decode_hex_array(&document.public_key, "authority public key")?,
        not_before: UnixTime(document.not_before),
        not_after: UnixTime(document.not_after),
        signature: decode_hex_array(&document.signature, "authority signature")?,
    })
}

fn decode_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], CliError> {
    hex::decode(value)
        .map_err(|_| CliError::invalid(format!("{label} is not hexadecimal")))?
        .try_into()
        .map_err(|_| CliError::invalid(format!("{label} has the wrong length")))
}

include!("bootstrap.rs");

fn verify_peer_trust(
    config: &PeerConfig,
    credential_bytes: &[u8],
    private_key: &[u8; 32],
) -> Result<std::sync::Arc<TrustSet>, CliError> {
    validate_private_permissions(&config.identity_private_key_file)?;
    let identity_private = Zeroizing::new(read_hex_32(&config.identity_private_key_file)?);
    let identity_public = IdentitySigningKey::from_bytes(&identity_private)
        .verifying_key()
        .to_bytes();
    let root_path = config
        .root_public_key_file
        .as_deref()
        .ok_or_else(|| CliError::invalid("peer Root public key file is required"))?;
    let root = RootPublicKey::from_bytes(&read_hex_32(root_path)?)
        .map_err(|_| CliError::invalid("peer Root public key is invalid"))?;
    if config.authority_certificate_files.is_empty() {
        return Err(CliError::invalid(
            "at least one peer Authority certificate is required",
        ));
    }
    let now = UnixTime(current_unix_time()?);
    let mut trust = TrustSet::new(root, config.mesh_id);
    for path in &config.authority_certificate_files {
        let authority = read_authority_certificate(path)?;
        trust
            .add_authority(authority, now)
            .map_err(|_| CliError::auth("peer Authority is not currently Root trusted"))?;
    }
    let credential = SubjectCredential::decode(credential_bytes)
        .map_err(|_| CliError::invalid("peer credential is malformed"))?;
    trust
        .verify_subject(&credential, now)
        .map_err(|_| CliError::auth("peer credential is not currently trusted"))?;
    let expected_public = NoisePublicKey::from(&StaticSecret::from(*private_key)).to_bytes();
    validate_private_permissions(&config.wireguard_private_key_file)?;
    let wireguard_private = Zeroizing::new(read_hex_32(&config.wireguard_private_key_file)?);
    let expected_wireguard =
        NoisePublicKey::from(&StaticSecret::from(*wireguard_private)).to_bytes();
    if credential.subject != SubjectId::Peer(config.peer_id)
        || credential.mesh_id != config.mesh_id
        || credential.identity_public_key != identity_public
        || credential.public_noise_key != expected_public
        || credential.wireguard_public_key != expected_wireguard
    {
        return Err(CliError::invalid(
            "peer credential, identity, Mesh, Noise key, and WireGuard key do not match",
        ));
    }
    let distribution_path = config
        .distribution_certificate_file
        .as_deref()
        .ok_or_else(|| CliError::invalid("peer distribution certificate file is required"))?;
    let distribution = read_bounded_regular_file(distribution_path, 65_536)?;
    let distribution = DistributionCertificate::decode(&distribution)
        .map_err(|_| CliError::invalid("peer distribution certificate is malformed"))?;
    trust
        .verify_distribution(&distribution, now)
        .map_err(|_| CliError::auth("peer distribution certificate is not trusted"))?;
    let directory_key = config
        .distribution_public_key
        .as_deref()
        .ok_or_else(|| CliError::invalid("peer directory verifier is required"))?;
    let service_key = config
        .service_distribution_public_key
        .as_deref()
        .ok_or_else(|| CliError::invalid("peer service verifier is required"))?;
    let audit_key = config
        .audit_public_key
        .as_deref()
        .ok_or_else(|| CliError::invalid("peer audit recipient is required"))?;
    if decode_hex_array::<32>(directory_key, "peer directory verifier")?
        != distribution.directory_public_key
        || decode_hex_array::<32>(service_key, "peer service verifier")?
            != distribution.service_public_key
        || decode_hex_array::<32>(audit_key, "peer audit recipient")?
            != distribution.audit_public_key
    {
        return Err(CliError::auth(
            "peer distribution verifier does not match its rooted certificate",
        ));
    }
    Ok(std::sync::Arc::new(trust))
}

async fn run_peer(path: &Path) -> Result<(), CliError> {
    let contents = read_bounded_utf8(path, 1024 * 1024)?;
    let mut config =
        PeerConfig::parse(&contents, path).map_err(|error| CliError::invalid(error.to_string()))?;
    let _runtime_lock = peerward_platform::LocalRuntimeLock::acquire(
        &config.management_socket.with_extension("runtime.lock"),
    )
    .map_err(|error| {
        peer_runtime_error("Peer runtime is already owned or lock is invalid", &error)
    })?;
    if let Some(linux) = &config.linux {
        peerward_platform::ExitProtection::new(
            LinuxCommandBackend,
            linux.platform_state_file.with_extension("exit-guard.json"),
        )
        .restore()
        .map_err(|error| {
            peer_runtime_error(
                "exit protection could not be restored; network startup stopped",
                &error,
            )
        })?;
    }
    peerward_peer::recover_peer_identity_files(
        &config.identity_private_key_file,
        &config.private_key_file,
        &config.wireguard_private_key_file,
        &config.credential_file,
    )
    .map_err(|_| CliError::failure("interrupted peer identity rotation could not be recovered"))?;
    if let Some(staged) = peerward_peer::staged_peer_identity_config(&config)
        .map_err(|_| CliError::failure("staged peer identity is invalid"))?
    {
        let staged_key = Zeroizing::new(read_hex_32(&staged.private_key_file)?);
        let staged_credential =
            peerward_credentials::private_files::read_private(&staged.credential_file, 225)
                .map_err(|_| CliError::failure("staged peer credential is unavailable"))?;
        let staged_trust = verify_peer_trust(&staged, &staged_credential, &staged_key)?;
        Box::pin(peerward_peer::recover_activated_peer_identity(
            &config,
            staged_trust,
        ))
        .await
        .map_err(|error| {
            peer_runtime_error("staged peer activation could not be recovered", &error)
        })?;
    }
    validate_private_permissions(&config.private_key_file)?;
    validate_private_permissions(&config.identity_private_key_file)?;
    let key = Zeroizing::new(read_hex_32(&config.private_key_file)?);
    let credential = read_bounded_regular_file(&config.credential_file, 65_536)?;
    if credential.is_empty() {
        return Err(CliError::invalid("peer credential file is empty"));
    }
    let trust = verify_peer_trust(&config, &credential, &key)?;
    tracing::info!(mesh_id = %config.mesh_id, peer_id = %config.peer_id, "Peer trust verified");
    let mut platform = if let Some(linux) = &config.linux {
        // Child DNS changes restore the base transaction's expected state first.
        for extension in ["dns.json", "resources.json", "exit-routes.json"] {
            StateCoordinator::with_journal(
                LinuxCommandBackend,
                linux.platform_state_file.with_extension(extension),
            )
            .recover()
            .map_err(|error| {
                peer_runtime_error(
                    "interrupted resource network state could not be recovered",
                    &error,
                )
            })?;
        }
        let mut coordinator =
            StateCoordinator::with_journal(LinuxCommandBackend, linux.platform_state_file.clone());
        coordinator.recover().map_err(|error| {
            peer_runtime_error(
                "interrupted Linux network state could not be recovered",
                &error,
            )
        })?;
        Some(coordinator)
    } else {
        None
    };
    if let Some(linux) = &mut config.linux {
        linux
            .populate_dns_upstreams()
            .map_err(|_| CliError::invalid("no safe recursive DNS upstream is available"))?;
    }
    let tun_halves = config
        .linux
        .as_ref()
        .map(peerward_peer::prepare_peer_tun)
        .transpose()
        .map_err(|error| peer_runtime_error("Linux TUN creation or attachment failed", &error))?;
    let platform_intent = config
        .linux
        .as_ref()
        .map(peerward_peer::LinuxConfig::platform_config)
        .transpose()
        .map_err(|_| CliError::invalid("invalid Linux peer configuration"))?;
    if let (Some(coordinator), Some(intent)) = (platform.as_mut(), platform_intent.as_ref()) {
        coordinator
            .prepare(intent)
            .map_err(|error| peer_runtime_error("Linux data plane preparation failed", &error))?;
    }
    let prebound_dns = if config.linux.is_some() {
        match peerward_peer::bind_peer_dns(&config).await {
            Ok(dns) => Some(dns),
            Err(error) => {
                let original = peer_runtime_error("Peer DNS listener could not be bound", &error);
                return finish_peer_runtime(
                    Err(original),
                    platform.as_mut().map_or(Ok(()), StateCoordinator::shutdown),
                );
            }
        }
    } else {
        None
    };
    if let (Some(coordinator), Some(intent)) = (platform.as_mut(), platform_intent.as_ref())
        && let Err(error) = coordinator
            .activate_firewall(intent)
            .and_then(|()| coordinator.commit())
    {
        let original = peer_runtime_error("Linux DNS activation failed", &error);
        return finish_peer_runtime(Err(original), coordinator.shutdown());
    }
    let socket_path = config.management_socket.clone();
    let state_path = config.service_state_file.clone();
    let service_address = config.linux.as_ref().map(|linux| linux.address.addr());
    let (service_changes, service_change_rx) = tokio::sync::mpsc::channel(64);
    let (service_shutdown, service_shutdown_rx) = tokio::sync::watch::channel(false);
    let (peer_shutdown, mut peer_shutdown_rx) = tokio::sync::watch::channel(false);
    let observability = peerward_service::PeerObservability::default();
    let transport_observability = observability.clone();
    let service_observability = observability.clone();
    let transport = async move {
        if let Some((reader, writer)) = tun_halves {
            Box::pin(peerward_peer::run_packet_runtime_managed(
                config,
                *key,
                credential,
                trust,
                reader,
                writer,
                service_change_rx,
                transport_observability,
                prebound_dns.expect("Linux packet runtime has a prebound DNS listener"),
                peer_shutdown_rx,
            ))
            .await
            .map(|_| ())
        } else {
            drop(service_change_rx);
            tokio::select! {
                result=peerward_peer::run_transport(config,*key,credential,trust)=>result,
                _=peer_shutdown_rx.changed()=>Ok(()),
            }
        }
    };
    let service = async move {
        if let Some(address) = service_address {
            peerward_service::serve_peer_management(
                &socket_path,
                state_path,
                address,
                service_changes,
                service_observability,
                service_shutdown_rx,
            )
            .await
        } else {
            peerward_service::serve(&socket_path, state_path, service_shutdown_rx).await
        }
    };
    tokio::pin!(transport);
    tokio::pin!(service);
    let runtime_result = tokio::select! {
        transport_result = &mut transport => {
            let transport_result = transport_result
                .map_err(|error| peer_runtime_error("peer transport failed", &error));
            let _ = service_shutdown.send(true);
            let service_result = (&mut service).await
                .map_err(|error| peer_runtime_error("local service socket failed", &error));
            match (transport_result, service_result) {
                (Err(mut original), Err(cleanup)) => {
                    original.message.push_str("; additionally, ");
                    original.message.push_str(&cleanup.message);
                    Err(original)
                }
                (Err(error), _) | (_, Err(error)) => Err(error),
                (Ok(()), Ok(())) => Ok(()),
            }
        }
        service_result = &mut service => {
            let _=peer_shutdown.send(true);
            // Child DNS/resource journals must finish before the base host transaction restores.
            if let Err(error)=(&mut transport).await {tracing::error!(?error,"peer shutdown after local management failure");}
            match service_result {
                Ok(()) => Err(CliError::failure("local service socket stopped unexpectedly")),
                Err(error) => Err(peer_runtime_error("local service socket failed", &error)),
            }
        }
    };
    finish_peer_runtime(
        runtime_result,
        platform.as_mut().map_or(Ok(()), StateCoordinator::shutdown),
    )
}

fn peer_runtime_error(context: &str, error: &dyn std::error::Error) -> CliError {
    let mut message = format!("{context}: {error}");
    let mut source = error.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    tracing::error!(error = %message, "Peer runtime failed");
    CliError {
        code: EXIT_UNAVAILABLE,
        message,
    }
}

fn finish_peer_runtime(
    runtime_result: Result<(), CliError>,
    rollback_result: Result<(), peerward_platform::PlatformError>,
) -> Result<(), CliError> {
    match (runtime_result, rollback_result) {
        (result, Ok(())) => result,
        (result, Err(error)) => {
            let mut rollback = peer_runtime_error("Linux data plane rollback failed", &error);
            rollback.code = EXIT_FAILURE;
            match result {
                Err(mut original) => {
                    original.message.push_str("; additionally, ");
                    original.message.push_str(&rollback.message);
                    Err(original)
                }
                Ok(()) => Err(rollback),
            }
        }
    }
}
