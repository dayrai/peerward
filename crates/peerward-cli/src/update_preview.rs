async fn execute_update_preview(args: &UpdateApplyArgs) -> Result<(), CliError> {
    validate_update_arguments(args)?;
    let root = args
        .installation_root
        .as_ref()
        .ok_or_else(|| CliError::invalid("preview requires a versioned role installation"))?;
    // Shared lock reads the existing registration. Preview cannot create an installation.
    let lock = fs::File::open(root.join("update.lock")).map_err(|_| {
        CliError::invalid("register this installation before requesting its preview")
    })?;
    lock.try_lock_shared().map_err(|_| {
        CliError::failure("an update is running; retry the preview after it completes")
    })?;
    let role = args.role.expect("validated role");
    let current =
        peerward_updater::installed_role_version(root, role.name()).map_err(update_error)?;
    let (manifest, artifact) = load_update(&args.source).await?;
    let bytes = if let Some(path) = &args.artifact_file {
        read_bounded_regular_file(path, 256 * 1024 * 1024)?
    } else {
        fetch_update_source(&artifact.url, 256 * 1024 * 1024).await?
    };
    check_update_database(role, args.database_url.as_deref()).await?;
    let result = versioned_update_preview(args, &manifest, &artifact, &bytes, &current).await?;
    println!("{result}");
    Ok(())
}

/// Called while holding the shared preview lock or the exclusive apply lock.
/// The digest binds the concrete process, artifact, release, health location and repair direction.
async fn versioned_update_preview(
    args: &UpdateApplyArgs,
    manifest: &peerward_updater::ReleaseManifest,
    artifact: &peerward_updater::ReleaseArtifact,
    bytes: &[u8],
    current_version: &str,
) -> Result<serde_json::Value, CliError> {
    let root = args
        .installation_root
        .as_ref()
        .ok_or_else(|| CliError::invalid("missing versioned root"))?;
    let role = args
        .role
        .ok_or_else(|| CliError::invalid("missing versioned role"))?;
    let health = args
        .health_url
        .as_ref()
        .ok_or_else(|| CliError::invalid("missing role health"))?;
    peerward_updater::verify_artifact(bytes, artifact).map_err(update_error)?;
    let floor = peerward_updater::preview_manifest(
        manifest,
        &root.join("accepted-update.json"),
        update_now()?,
        current_version,
        peerward_store::SCHEMA_VERSION,
        peerward_wire::PROTOCOL_MAJOR,
    )
    .map_err(update_error)?;
    let previous = UpdateTransaction::load(root, role.name()).map_err(update_error)?;
    if args.repair {
        if previous
            .as_ref()
            .is_none_or(|record| record.stage() != peerward_updater::UpdateStage::RecoveryRequired)
        {
            return Err(CliError::invalid(
                "repair preview requires a recovery_required transaction",
            ));
        }
    } else if previous
        .as_ref()
        .is_some_and(|record| !record.is_terminal())
    {
        return Err(CliError::failure(
            "recover the interrupted transaction before reviewing a new update",
        ));
    }
    let current = root.join("roles").join(role.name()).join("current");
    let process = update_role_pid(role).await;
    if !args.repair
        && !process.is_some_and(|pid| {
            same_executable(&PathBuf::from(format!("/proc/{pid}/exe")), &current)
        })
    {
        return Err(CliError::failure(
            "the selected role is not running its registered current binary",
        ));
    }
    let current_bytes = read_bounded_regular_file(&current, 256 * 1024 * 1024)?;
    let mut value = serde_json::json!({"operation":"native_upgrade","role":role.name(),"current_version":current_version,
        "version":manifest.version,"sequence":manifest.sequence,"manifest_sha256":hex::encode(Sha256::digest(serde_json::to_vec(manifest).map_err(|_|CliError::failure("cannot encode release"))?)),
        "artifact_sha256":artifact.sha256,"artifact_bytes":artifact.size,"current_sha256":hex::encode(Sha256::digest(&current_bytes)),
        "process_id":process,"rollback_floor":floor,"repair":args.repair,"health_url":health.as_str(),
        "previous_transaction":previous,"schema_version":peerward_store::SCHEMA_VERSION,"wire_major":peerward_wire::PROTOCOL_MAJOR});
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&value).map_err(|_| CliError::failure("cannot encode preview"))?,
    ));
    value["digest"] = serde_json::Value::String(digest);
    Ok(value)
}
