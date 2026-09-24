pub(crate) fn wall_clock_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn read_identity_private_key(path: &Path) -> Result<[u8; 32], PacketPumpError> {
    let bytes = zeroize::Zeroizing::new(peerward_credentials::private_files::read_private(
        path, 128,
    )?);
    let text = std::str::from_utf8(&bytes).map_err(|_| PacketPumpError::InvalidControl)?;
    let decoded = zeroize::Zeroizing::new(
        hex::decode(text.trim()).map_err(|_| PacketPumpError::InvalidControl)?,
    );
    decoded
        .as_slice()
        .try_into()
        .map_err(|_| PacketPumpError::InvalidControl)
}

/// Completes an interrupted four-file identity replacement before any key is read.
pub fn recover_peer_identity_files(
    identity_private_key_file: &Path,
    private_key_file: &Path,
    wireguard_private_key_file: &Path,
    credential_file: &Path,
) -> io::Result<()> {
    let marker = adjacent_path(private_key_file, "rotation");
    if !marker.exists() {
        return Ok(());
    }
    for path in [
        identity_private_key_file,
        private_key_file,
        wireguard_private_key_file,
        credential_file,
    ] {
        peerward_credentials::private_files::reject_symlinks(path)?;
        peerward_credentials::private_files::reject_symlinks(&adjacent_path(path, "next"))?;
    }
    let state = peerward_credentials::private_files::read_private(&marker, 128)?;
    let state =
        std::str::from_utf8(&state).map_err(|_| io::Error::other("invalid rotation journal"))?;
    let rotation = state
        .strip_prefix("staged:")
        .or_else(|| state.strip_prefix("committing:"))
        .or_else(|| state.strip_prefix("requested:"))
        .ok_or_else(|| io::Error::other("invalid rotation journal"))?;
    rotation
        .parse::<RotationId>()
        .map_err(|_| io::Error::other("invalid rotation journal ID"))?;
    let next_credential = adjacent_path(credential_file, "next");
    let next_identity_private = adjacent_path(identity_private_key_file, "next");
    let next_private = adjacent_path(private_key_file, "next");
    let next_wireguard = adjacent_path(wireguard_private_key_file, "next");
    if state.starts_with("committing:") {
        if next_credential.exists() {
            std::fs::rename(&next_credential, credential_file)?;
        }
        if next_wireguard.exists() {
            std::fs::rename(&next_wireguard, wireguard_private_key_file)?;
        }
        if next_private.exists() {
            std::fs::rename(&next_private, private_key_file)?;
        }
        if next_identity_private.exists() {
            std::fs::rename(&next_identity_private, identity_private_key_file)?;
        }
    } else {
        // The server may have activated this transaction before the crash.
        // Preserve its keys and ID until the same replacement is redelivered.
        let keys_complete = [&next_private, &next_wireguard, &next_identity_private]
            .iter()
            .all(|path| path.is_file());
        if !keys_complete || (state.starts_with("staged:") && !next_credential.is_file()) {
            return Err(io::Error::other(
                "incomplete rotation; preserve the journal and rejoin",
            ));
        }
        return Ok(());
    }
    sync_identity_directories(&[
        identity_private_key_file,
        private_key_file,
        wireguard_private_key_file,
        credential_file,
    ])?;
    peerward_credentials::private_files::remove_private(&marker)
}

fn stage_peer_identity(
    identity_private_key_file: &Path,
    private_key_file: &Path,
    wireguard_private_key_file: &Path,
    credential_file: &Path,
    rotation: RotationId,
    identity_private_key: &[u8; 32],
    session_private_key: &[u8; 32],
    wireguard_private_key: &[u8; 32],
    credential: &[u8],
) -> Result<(), PacketPumpError> {
    stage_rotation_keys(
        identity_private_key_file,
        private_key_file,
        wireguard_private_key_file,
        identity_private_key,
        session_private_key,
        wireguard_private_key,
    )?;
    let next_credential = adjacent_path(credential_file, "next");
    let marker = adjacent_path(private_key_file, "rotation");
    write_secure(&next_credential, credential)?;
    write_secure(&marker, format!("staged:{rotation}").as_bytes())?;
    Ok(())
}

fn commit_staged_peer_identity(
    identity_private_key_file: &Path,
    private_key_file: &Path,
    wireguard_private_key_file: &Path,
    credential_file: &Path,
) -> Result<(), PacketPumpError> {
    let next_private = adjacent_path(private_key_file, "next");
    let next_wireguard = adjacent_path(wireguard_private_key_file, "next");
    let next_identity_private = adjacent_path(identity_private_key_file, "next");
    let next_credential = adjacent_path(credential_file, "next");
    let marker = adjacent_path(private_key_file, "rotation");
    if !marker.exists()
        || !next_private.exists()
        || !next_wireguard.exists()
        || !next_identity_private.exists()
        || !next_credential.exists()
    {
        return Err(PacketPumpError::InvalidControl);
    }
    let state = peerward_credentials::private_files::read_private(&marker, 128)?;
    let state = std::str::from_utf8(&state).map_err(|_| PacketPumpError::InvalidControl)?;
    let rotation = state
        .strip_prefix("staged:")
        .ok_or(PacketPumpError::InvalidControl)?;
    write_secure(&marker, format!("committing:{rotation}").as_bytes())?;
    std::fs::rename(&next_credential, credential_file)?;
    std::fs::rename(&next_wireguard, wireguard_private_key_file)?;
    std::fs::rename(&next_private, private_key_file)?;
    std::fs::rename(&next_identity_private, identity_private_key_file)?;
    sync_identity_directories(&[
        identity_private_key_file,
        private_key_file,
        wireguard_private_key_file,
        credential_file,
    ])?;
    peerward_credentials::private_files::remove_private(&marker)?;
    Ok(())
}

fn adjacent_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(format!(".{suffix}"));
    name.into()
}

fn write_secure(path: &Path, bytes: &[u8]) -> io::Result<()> {
    peerward_credentials::private_files::write_private_atomic(path, bytes)
}

impl Drop for CredentialRotator {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.current_identity_private_key.zeroize();
    }
}

fn sync_identity_directories(paths: &[&Path]) -> io::Result<()> {
    let mut parents = std::collections::BTreeSet::new();
    for path in paths {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("invalid identity path"))?;
        if parents.insert(parent) {
            std::fs::File::open(parent)?.sync_all()?;
        }
    }
    Ok(())
}

fn stage_rotation_keys(
    identity_file: &Path,
    noise_file: &Path,
    wireguard_file: &Path,
    identity: &[u8; 32],
    noise: &[u8; 32],
    wireguard: &[u8; 32],
) -> io::Result<()> {
    for (path, key) in [
        (identity_file, identity),
        (noise_file, noise),
        (wireguard_file, wireguard),
    ] {
        write_secure(
            &adjacent_path(path, "next"),
            zeroize::Zeroizing::new(format!("{}\n", hex::encode(key))).as_bytes(),
        )?;
    }
    Ok(())
}
