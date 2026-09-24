async fn execute_update(command: UpdateCommand) -> Result<(), CliError> {
    match command {
        UpdateCommand::RunConfig { config } => {
            let document = read_bounded_regular_file(&config, 65_536)?;
            let document = std::str::from_utf8(&document)
                .map_err(|_| CliError::invalid("update configuration is not UTF-8"))?;
            let config: UnattendedUpdateConfig = toml::from_str(document)
                .map_err(|_| CliError::invalid("invalid unattended update configuration"))?;
            if config.config_version != 1 || !config.enabled {
                return Err(CliError::invalid(
                    "unattended updates are not explicitly enabled",
                ));
            }
            let channel = match config.channel.as_str() {
                "stable" => ReleaseChannel::Stable,
                "canary" => ReleaseChannel::Canary,
                _ => return Err(CliError::invalid("invalid unattended update channel")),
            };
            Box::pin(execute_update(UpdateCommand::Apply(UpdateApplyArgs {
                source: UpdateSourceArgs {
                    manifest: config.manifest,
                    signature: config.signature,
                    public_key: config.public_key,
                    channel,
                    platform: None,
                    architecture: None,
                },
                preview_digest: None,
                repair: false,
                artifact_file: config.artifact_file,
                install_path: None,
                installation_root: Some(config.installation_root),
                role: Some(config.role),
                health_url: Some(config.health_url),
                database_url: config.database_url,
            })))
            .await
        }
        UpdateCommand::Check(source) => {
            let (manifest, artifact) = load_update(&source).await?;
            validate_update_candidate(&manifest)?;
            println!(
                "{}",
                serde_json::json!({
                    "version": manifest.version,
                    "artifact": artifact.name,
                    "sha256": artifact.sha256,
                    "size": artifact.size,
                    "url": artifact.url,
                })
            );
            Ok(())
        }
        UpdateCommand::Preview(args) => execute_update_preview(&args).await,
        UpdateCommand::Apply(args) => {
            validate_update_arguments(&args)?;
            let _installation_lock = if let Some(root) = &args.installation_root {
                Some(
                    peerward_platform::LocalRuntimeLock::acquire(&root.join("update.lock"))
                        .map_err(|error| CliError::failure(error.to_string()))?,
                )
            } else {
                None
            };
            let (manifest, artifact) = load_update(&args.source).await?;
            let current_version = if let Some(root) = &args.installation_root {
                peerward_updater::installed_role_version(
                    root,
                    args.role.expect("validated role").name(),
                )
                .map_err(update_error)?
            } else {
                env!("CARGO_PKG_VERSION").to_owned()
            };
            manifest
                .validate_candidate(
                    update_now()?,
                    0,
                    &current_version,
                    peerward_store::SCHEMA_VERSION,
                    peerward_wire::PROTOCOL_MAJOR,
                )
                .map_err(update_error)?;
            let mut completed_retry = None;
            if let Some(root) = &args.installation_root {
                let role = args.role.expect("validated role");
                let current = root.join("roles").join(role.name()).join("current");
                let previous = UpdateTransaction::load(root, role.name()).map_err(update_error)?;
                if let Some(record) = previous.as_ref().filter(|record| {
                    record.matches_approved_request(
                        &manifest,
                        &artifact,
                        args.health_url.as_ref().expect("validated health").as_str(),
                        args.preview_digest.as_deref(),
                    )
                }) {
                    completed_retry = Some(record.clone());
                } else {
                    if args.repair {
                        if previous.as_ref().is_none_or(|record| {
                            record.stage() != peerward_updater::UpdateStage::RecoveryRequired
                        }) {
                            return Err(CliError::invalid(
                                "--repair requires a recovery_required transaction; inspect update status",
                            ));
                        }
                    } else {
                        if previous.is_some_and(|record| !record.is_terminal()) {
                            return Err(CliError::failure(
                                "an interrupted update must be reconciled with update recover first",
                            ));
                        }
                        if !updated_role_is_running(role, &current).await {
                            return Err(CliError::invalid(
                                "the selected systemd role must run the registered current binary before an update",
                            ));
                        }
                    }
                    check_update_database(role, args.database_url.as_deref()).await?;
                }
            }
            let state_path = if let Some(root) = &args.installation_root {
                root.join("accepted-update.json")
            } else {
                let destination = args
                    .install_path
                    .clone()
                    .map_or_else(std::env::current_exe, Ok)
                    .map_err(|error| {
                        CliError::failure(format!("cannot locate executable: {error}"))
                    })?;
                destination
                    .parent()
                    .ok_or_else(|| CliError::invalid("installed executable has no parent"))?
                    .join("accepted-update.json")
            };
            let binary = if let Some(path) = &args.artifact_file {
                read_bounded_regular_file(path, 256 * 1024 * 1024)?
            } else {
                fetch_update_source(&artifact.url, 256 * 1024 * 1024).await?
            };
            peerward_updater::verify_artifact(&binary, &artifact)
                .map_err(|error| CliError::invalid(error.to_string()))?;
            if let Some(record) = completed_retry.as_mut() {
                let root = args.installation_root.as_ref().expect("versioned retry");
                run_update_transaction(root, args.role.expect("versioned retry"), record).await?;
                if record.direction() == UpdateDirection::Rollback {
                    return Err(CliError::failure(
                        "this release already failed and was rolled back; select a repaired signed release",
                    ));
                }
                println!(
                    "{}",
                    serde_json::to_string(record)
                        .map_err(|error| CliError::failure(error.to_string()))?
                );
                return Ok(());
            }
            if args.installation_root.is_some() {
                let preview = versioned_update_preview(
                    &args,
                    &manifest,
                    &artifact,
                    &binary,
                    &current_version,
                )
                .await?;
                if args
                    .preview_digest
                    .as_ref()
                    .is_some_and(|expected| preview["digest"] != expected.as_str())
                {
                    return Err(CliError::invalid(
                        "update preview changed; review the new preview before applying",
                    ));
                }
            }
            let now = update_now()?;
            accept_manifest(
                &manifest,
                &state_path,
                now,
                &current_version,
                peerward_store::SCHEMA_VERSION,
                peerward_wire::PROTOCOL_MAJOR,
            )
            .map_err(|error| CliError::invalid(error.to_string()))?;
            if args.installation_root.is_some() || args.role.is_some() {
                let root = args.installation_root.as_ref().ok_or_else(|| {
                    CliError::invalid("versioned updates require --installation-root")
                })?;
                let role = args
                    .role
                    .ok_or_else(|| CliError::invalid("versioned updates require --role"))?;
                let health = args
                    .health_url
                    .as_ref()
                    .ok_or_else(|| CliError::invalid("versioned updates require --health-url"))?;
                let mut record = UpdateTransaction::prepare_approved(
                    root,
                    role.name(),
                    &binary,
                    &artifact,
                    &manifest,
                    peerward_updater::TransactionOptions {
                        health_url: health.as_str(),
                        repair: args.repair,
                        approved_preview: args.preview_digest.as_deref(),
                    },
                )
                .map_err(update_error)?;
                if record.is_terminal() && record.direction() == UpdateDirection::Rollback {
                    return Err(CliError::failure(
                        "this release already failed and was rolled back; select a repaired signed release",
                    ));
                }
                run_update_transaction(root, role, &mut record).await?;
                println!(
                    "{}",
                    serde_json::to_string(&record)
                        .map_err(|error| CliError::failure(error.to_string()))?
                );
                return Ok(());
            }
            let destination = args
                .install_path
                .map_or_else(std::env::current_exe, Ok)
                .map_err(|error| CliError::failure(format!("cannot locate executable: {error}")))?;
            let rollback_path = install_verified(&binary, &artifact, &destination)
                .map_err(|error| CliError::failure(error.to_string()))?;
            println!(
                "installed {} (rollback: {})",
                destination.display(),
                rollback_path.display()
            );
            Ok(())
        }
        UpdateCommand::Rollback {
            install_path,
            installation_root,
            role,
        } => {
            if installation_root.is_some() || role.is_some() {
                let root = installation_root.as_ref().ok_or_else(|| {
                    CliError::invalid("versioned rollback requires --installation-root")
                })?;
                let role =
                    role.ok_or_else(|| CliError::invalid("versioned rollback requires --role"))?;
                let _installation_lock =
                    peerward_platform::LocalRuntimeLock::acquire(&root.join("update.lock"))
                        .map_err(|error| CliError::failure(error.to_string()))?;
                if install_path.is_some() {
                    return Err(CliError::invalid(
                        "versioned rollback cannot use --install-path",
                    ));
                }
                let mut record = UpdateTransaction::load(root, role.name())
                    .map_err(update_error)?
                    .ok_or_else(|| {
                        CliError::invalid("there is no recorded versioned transaction to roll back")
                    })?;
                if !record.is_terminal() {
                    return Err(CliError::failure(
                        "reconcile the interrupted update with update recover before another rollback",
                    ));
                }
                record
                    .request_rollback(
                        root,
                        peerward_store::SCHEMA_VERSION,
                        peerward_wire::PROTOCOL_MAJOR,
                    )
                    .map_err(update_error)?;
                run_update_transaction(root, role, &mut record).await?;
                println!(
                    "{}",
                    serde_json::to_string(&record)
                        .map_err(|error| CliError::failure(error.to_string()))?
                );
                return Ok(());
            }
            let destination = install_path
                .map_or_else(std::env::current_exe, Ok)
                .map_err(|error| CliError::failure(format!("cannot locate executable: {error}")))?;
            rollback(&destination).map_err(|error| CliError::failure(error.to_string()))?;
            println!("restored {}", destination.display());
            Ok(())
        }
        UpdateCommand::Register {
            source,
            installation_root,
            role,
            binary,
        } => register_versioned_role(source, &installation_root, role, &binary).await,
        UpdateCommand::Status {
            installation_root,
            role,
        } => {
            // Read-only status takes no lock and does not create an absent installation.
            let record =
                UpdateTransaction::load(&installation_root, role.name()).map_err(update_error)?;
            println!(
                "{}",
                serde_json::json!({"transaction":record,"health":"not_observed"})
            );
            Ok(())
        }
        UpdateCommand::Recover {
            installation_root,
            role,
            database_url,
        } => {
            let _lock = peerward_platform::LocalRuntimeLock::acquire(
                &installation_root.join("update.lock"),
            )
            .map_err(|error| CliError::failure(error.to_string()))?;
            let mut record = UpdateTransaction::load(&installation_root, role.name())
                .map_err(update_error)?
                .ok_or_else(|| CliError::invalid("no interrupted role transaction is recorded"))?;
            check_update_database(role, database_url.as_deref()).await?;
            run_update_transaction(&installation_root, role, &mut record).await?;
            println!(
                "{}",
                serde_json::to_string(&record)
                    .map_err(|error| CliError::failure(error.to_string()))?
            );
            Ok(())
        }
        UpdateCommand::SignManifest {
            manifest,
            private_key,
            output,
        } => {
            validate_private_permissions(&private_key)?;
            let private = Zeroizing::new(read_hex_32(&private_key)?);
            let bytes = read_bounded_regular_file(&manifest, 4 * 1024 * 1024)?;
            let signature = sign_manifest(&bytes, &private);
            write_new(
                &output,
                format!("{}\n", hex::encode(signature)).as_bytes(),
                false,
            )
        }
    }
}

fn validate_update_candidate(manifest: &peerward_updater::ReleaseManifest) -> Result<(), CliError> {
    manifest
        .validate_candidate(
            update_now()?,
            0,
            env!("CARGO_PKG_VERSION"),
            peerward_store::SCHEMA_VERSION,
            peerward_wire::PROTOCOL_MAJOR,
        )
        .map_err(|error| CliError::invalid(error.to_string()))
}

fn update_now() -> Result<u64, CliError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CliError::failure("system clock predates Unix time"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnattendedUpdateConfig {
    config_version: u32,
    enabled: bool,
    manifest: String,
    signature: String,
    public_key: PathBuf,
    channel: String,
    installation_root: PathBuf,
    role: UpdateRole,
    health_url: Url,
    database_url: Option<String>,
    artifact_file: Option<PathBuf>,
}

async fn load_update(
    source: &UpdateSourceArgs,
) -> Result<
    (
        peerward_updater::ReleaseManifest,
        peerward_updater::ReleaseArtifact,
    ),
    CliError,
> {
    let manifest_bytes = fetch_update_source(&source.manifest, 4 * 1024 * 1024).await?;
    let signature_bytes = fetch_update_source(&source.signature, 1024).await?;
    let signature_text = std::str::from_utf8(&signature_bytes)
        .map_err(|_| CliError::invalid("update signature is not UTF-8"))?;
    let signature: [u8; 64] = hex::decode(signature_text.trim())
        .map_err(|_| CliError::invalid("update signature is not hexadecimal"))?
        .try_into()
        .map_err(|_| CliError::invalid("update signature must contain 64 bytes"))?;
    let public = read_hex_32(&source.public_key)?;
    let manifest = verify_manifest(&manifest_bytes, &signature, &public)
        .map_err(|error| CliError::invalid(error.to_string()))?;
    let platform = source.platform.as_deref().unwrap_or(std::env::consts::OS);
    let architecture = source
        .architecture
        .as_deref()
        .unwrap_or(std::env::consts::ARCH);
    let artifact = manifest
        .select(
            source.channel.into(),
            platform,
            architecture,
            ArtifactKind::Binary,
        )
        .map_err(|error| CliError::invalid(error.to_string()))?
        .clone();
    Ok((manifest, artifact))
}

async fn fetch_update_source(source: &str, maximum: usize) -> Result<Vec<u8>, CliError> {
    if source.starts_with("https://") {
        let response = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|_| CliError::failure("cannot initialize update client"))?
            .get(source)
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|_| CliError::unavailable("update source"))?;
        read_bounded_response(response, maximum, "update source").await
    } else if source.contains("://") {
        Err(CliError::invalid(
            "update sources must use HTTPS or a local path",
        ))
    } else {
        read_bounded_regular_file(Path::new(source), maximum as u64)
    }
}

async fn read_bounded_response(
    response: reqwest::Response,
    maximum: usize,
    label: &'static str,
) -> Result<Vec<u8>, CliError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(CliError::invalid(format!("{label} exceeds its size bound")));
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| CliError::unavailable(label))?;
        if chunk.len() > maximum.saturating_sub(bytes.len()) {
            return Err(CliError::invalid(format!("{label} exceeds its size bound")));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
