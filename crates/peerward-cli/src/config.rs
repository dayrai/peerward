async fn check_config(path: &Path, role: ConfigRole, online: bool) -> Result<(), CliError> {
    let contents = read_bounded_utf8(path, 1024 * 1024)?;
    let first = contents
        .lines()
        .find(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'));
    if !matches!(
        first.map(str::trim),
        Some("config_version = 1" | "config_version = 2" | "config_version = 4")
    ) {
        return Err(CliError::invalid(
            "configuration must begin with the supported config_version for its role (Peer: 4)",
        ));
    }
    match role {
        ConfigRole::Control => {
            let config =
                ControlConfig::parse(&contents, std::env::var("PEERWARD_DATABASE_URL").ok())
                    .map_err(|_| CliError::invalid("invalid control configuration"))?;
            if online {
                check_control_online(&config).await?;
            }
        }
        ConfigRole::Relay => {
            if contents
                .lines()
                .any(|line| line.trim() == "config_version = 2")
            {
                let config = peerward_relay::RelayHostConfig::parse(
                    &contents,
                    path,
                    std::env::var("PEERWARD_DATABASE_URL").ok(),
                )
                .map_err(|_| CliError::invalid("invalid shared Relay configuration"))?;
                validate_private_permissions(&config.private_key_file)?;
                if online {
                    check_database_online(config.database_url.as_deref()).await?;
                }
                println!("shared Relay configuration is valid");
                return Ok(());
            }
            let config =
                RelayConfig::parse(&contents, path, std::env::var("PEERWARD_DATABASE_URL").ok())
                    .map_err(|_| CliError::invalid("invalid relay configuration"))?;
            check_subject_key(
                &config.private_key_file,
                &config.credential_file,
                config.mesh_id,
                SubjectId::Relay(config.relay_id),
            )?;
            if online {
                check_database_online(config.database_url.as_deref()).await?;
                check_listener_available(config.peer_address, "Relay peer listener").await?;
                check_listener_available(config.backbone_address, "Relay backbone listener")
                    .await?;
                if let Some(address) = config.health_address {
                    check_listener_available(address, "Relay health listener").await?;
                }
            }
        }
        ConfigRole::Peer => {
            let config = PeerConfig::parse(&contents, path)
                .map_err(|error| CliError::invalid(error.to_string()))?;
            check_subject_key(
                &config.private_key_file,
                &config.credential_file,
                config.mesh_id,
                SubjectId::Peer(config.peer_id),
            )?;
            let private = Zeroizing::new(read_hex_32(&config.private_key_file)?);
            let credential = read_bounded_regular_file(&config.credential_file, 65_536)?;
            let trust = verify_peer_trust(&config, &credential, &private)?;
            if online {
                for relay in &config.relays {
                    let remote: [u8; 32] = hex::decode(&relay.public_key)
                        .map_err(|_| CliError::invalid("invalid Relay Noise key"))?
                        .try_into()
                        .map_err(|_| CliError::invalid("invalid Relay Noise key"))?;
                    let hello = peerward_wire::HandshakePayload {
                        major: peerward_wire::PROTOCOL_MAJOR,
                        minor: 0,
                        capabilities: peerward_wire::SUPPORTED_CAPABILITIES
                            | peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY,
                        credential: credential.clone(),
                        attachment_id: peerward_types::AttachmentId::new().as_bytes().to_vec(),
                    };
                    let now = UnixTime(current_unix_time()?);
                    let connection = peerward_peer::connect_relay_endpoints_with_options(
                        &relay.endpoints,
                        &private,
                        &remote,
                        relay.relay_id,
                        config.mesh_id,
                        &trust,
                        now,
                        hello,
                        &config.relay_transport,
                    );
                    tokio::time::timeout(std::time::Duration::from_secs(3), connection)
                        .await
                        .map_err(|_| CliError::unavailable("relay endpoint"))?
                        .map_err(|_| CliError::unavailable("relay endpoint"))?;
                }
            }
        }
    }
    println!("configuration is valid");
    Ok(())
}

fn check_subject_key(
    private_key: &Path,
    credential_path: &Path,
    mesh_id: MeshId,
    subject: SubjectId,
) -> Result<(), CliError> {
    validate_private_permissions(private_key)?;
    let private = Zeroizing::new(read_hex_32(private_key)?);
    let expected_public = NoisePublicKey::from(&StaticSecret::from(*private)).to_bytes();
    let credential = read_bounded_regular_file(credential_path, 65_536)?;
    let credential = SubjectCredential::decode(&credential)
        .map_err(|_| CliError::invalid("credential is malformed"))?;
    if credential.mesh_id != mesh_id
        || credential.subject != subject
        || credential.public_noise_key != expected_public
    {
        return Err(CliError::invalid(
            "credential, configured identity, and private key do not match",
        ));
    }
    Ok(())
}

async fn check_database_online(database_url: Option<&str>) -> Result<(), CliError> {
    let database_url = database_url.ok_or_else(|| CliError::invalid("database URL is required"))?;
    let store = Store::connect(database_url, 1)
        .await
        .map_err(|_| CliError::unavailable("database"))?;
    if !store.ready().await {
        return Err(CliError::unavailable("database"));
    }
    Ok(())
}

async fn check_control_online(config: &ControlConfig) -> Result<(), CliError> {
    let database_url = config
        .database_url
        .as_deref()
        .ok_or_else(|| CliError::invalid("database URL is required"))?;
    let store = Store::connect(database_url, 2)
        .await
        .map_err(|_| CliError::unavailable("database"))?;
    if !store.ready().await {
        return Err(CliError::unavailable("database"));
    }
    peerward_control::check_authority_configuration(config, &store)
        .await
        .map_err(|_| CliError::invalid("Authority key directory or database lifecycle mismatch"))?;
    if let Some(oidc) = &config.oidc {
        peerward_control::check_oidc_provider(oidc)
            .await
            .map_err(|_| CliError::unavailable("OIDC discovery"))?;
    }
    check_listener_available(config.http_address, "Control HTTP listener").await?;
    Ok(())
}

async fn check_listener_available(
    address: std::net::SocketAddr,
    label: &'static str,
) -> Result<(), CliError> {
    tokio::net::TcpListener::bind(address)
        .await
        .map(drop)
        .map_err(|_| CliError::unavailable(label))
}

async fn migrate_database(database_url: Option<&str>) -> Result<(), CliError> {
    let environment = std::env::var("PEERWARD_DATABASE_URL").ok();
    let database_url = database_url
        .or(environment.as_deref())
        .ok_or_else(|| CliError::invalid("database URL is required"))?;
    let store = Store::connect(database_url, 1)
        .await
        .map_err(|_| CliError::unavailable("database is unavailable"))?;
    store.migrate().await.map_err(|error| {
        CliError::failure(format!(
            "database migration failed: {}",
            peerward_control::ApiError::from(error)
        ))
    })?;
    println!("database migration complete");
    Ok(())
}
