fn read_managed_issuer_configs(
    configured: &[JoinIssuerConfig],
    directory: Option<&std::path::Path>,
) -> Result<Vec<JoinIssuerConfig>, ApiError> {
    let mut configs = configured.to_vec();
    let Some(directory) = directory else {
        return Ok(configs);
    };
    let invalid = || {
        ApiError::invalid(
            "managed_issuer_invalid",
            "managed issuer directory or fragment is invalid",
        )
    };
    reject_symlink_components(directory)?;
    let metadata = match std::fs::symlink_metadata(directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(configs),
        Err(_) => return Err(invalid()),
    };
    if !metadata.is_dir() {
        return Err(invalid());
    }
    require_private_permissions(&metadata)?;
    let mut paths = std::fs::read_dir(directory)
        .map_err(|_| invalid())?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    if paths.len() > 4096 {
        return Err(invalid());
    }
    paths.sort();
    let mut identities: HashSet<_> = configs
        .iter()
        .map(|config| (config.mesh_id, config.authority_id))
        .collect();
    for path in paths {
        let metadata = std::fs::symlink_metadata(&path).map_err(|_| invalid())?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(invalid());
        }
        // Worker stages atomic replacements under dot-prefixed names.
        if path
            .file_name()
            .is_some_and(|name| name.to_string_lossy().starts_with('.'))
        {
            continue;
        }
        if path.extension().is_none_or(|extension| extension != "json") || metadata.len() > 65_536 {
            return Err(invalid());
        }
        require_private_permissions(&metadata)?;
        let bytes = peerward_credentials::private_files::read_private(&path, 65_536)
            .map_err(|_| invalid())?;
        let config: JoinIssuerConfig = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if path.file_stem().and_then(|stem| stem.to_str())
            != Some(config.mesh_id.to_string().as_str())
            || config.authority_private_key.is_some()
        {
            return Err(invalid());
        }
        if !identities.insert((config.mesh_id, config.authority_id)) {
            return Err(ApiError::invalid(
                "duplicate_join_issuer",
                "an Authority relation may only be configured once",
            ));
        }
        configs.push(config);
    }
    Ok(configs)
}

fn require_private_permissions(metadata: &std::fs::Metadata) -> Result<(), ApiError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ApiError::invalid(
                "managed_issuer_permissions",
                "managed issuer material must not be group or world accessible",
            ));
        }
    }
    Ok(())
}

fn reject_symlink_components(path: &std::path::Path) -> Result<(), ApiError> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(ApiError::invalid(
                    "issuer_path_symlink",
                    "issuer paths must not traverse symbolic links",
                ));
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(ApiError::invalid(
                    "issuer_path_unavailable",
                    "issuer path cannot be inspected",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn load_startup_join_issuers(
    config: &ControlConfig,
) -> Result<HashMap<MeshId, Vec<Arc<JoinIssuer>>>, ApiError> {
    let directory =
        std::env::var_os("PEERWARD_MANAGED_ISSUER_DIRECTORY").map(std::path::PathBuf::from);
    let configured = read_managed_issuer_configs(&config.join_issuers, directory.as_deref())?;
    load_join_issuers(&configured, config.authority_key_directory.as_deref())
}
