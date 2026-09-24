#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedUpdateState {
    schema_version: u32,
    highest_sequence: u64,
    manifest_sha256: String,
    rollback_floor: String,
}

/// Validates and durably records the highest accepted signed manifest sequence.
///
/// Retrying the same sequence is allowed only for the exact same canonical manifest.
pub fn accept_manifest(
    manifest: &ReleaseManifest,
    state_path: &Path,
    now: u64,
    current_version: &str,
    schema_version: u32,
    wire_major: u32,
) -> Result<(), UpdateError> {
    let accepted = candidate_update_state(
        manifest,
        state_path,
        now,
        current_version,
        schema_version,
        wire_major,
    )?;
    if read_update_state(state_path)? == accepted {
        return Ok(());
    }
    write_update_state(state_path, &accepted)
}

/// Read-only acceptance check; returns the strongest floor without consuming a sequence.
pub fn preview_manifest(
    manifest: &ReleaseManifest,
    state_path: &Path,
    now: u64,
    current_version: &str,
    schema_version: u32,
    wire_major: u32,
) -> Result<String, UpdateError> {
    Ok(candidate_update_state(
        manifest,
        state_path,
        now,
        current_version,
        schema_version,
        wire_major,
    )?
    .rollback_floor)
}

fn candidate_update_state(
    manifest: &ReleaseManifest,
    state_path: &Path,
    now: u64,
    current_version: &str,
    schema_version: u32,
    wire_major: u32,
) -> Result<AcceptedUpdateState, UpdateError> {
    let previous = read_update_state(state_path)?;
    manifest.validate_candidate(
        now,
        previous.highest_sequence,
        current_version,
        schema_version,
        wire_major,
    )?;
    if previous.highest_sequence > 0
        && parsed_version(&manifest.version)?
            .cmp_precedence(&parsed_version(&previous.rollback_floor)?)
            .is_lt()
    {
        return Err(UpdateError::Rollback);
    }
    let rollback_floor = if previous.highest_sequence > 0
        && parsed_version(&previous.rollback_floor)?
            .cmp_precedence(&parsed_version(&manifest.rollback_floor)?)
            .is_gt()
    {
        previous.rollback_floor.clone()
    } else {
        manifest.rollback_floor.clone()
    };
    let canonical = serde_json::to_vec(manifest).map_err(|_| UpdateError::Malformed)?;
    let digest = hex::encode(Sha256::digest(canonical));
    if manifest.sequence == previous.highest_sequence {
        return if previous.manifest_sha256 == digest {
            Ok(previous)
        } else {
            Err(UpdateError::Rollback)
        };
    }
    Ok(AcceptedUpdateState {
        schema_version: 2,
        highest_sequence: manifest.sequence,
        manifest_sha256: digest,
        rollback_floor,
    })
}

fn read_update_state(path: &Path) -> Result<AcceptedUpdateState, UpdateError> {
    match peerward_credentials::private_files::read_private(path, 4096) {
        Ok(bytes) => {
            let state: AcceptedUpdateState =
                serde_json::from_slice(&bytes).map_err(|_| UpdateError::Malformed)?;
            if state.schema_version != 2
                || canonical_version(&state.rollback_floor).is_none()
                || state.highest_sequence == 0
                || state.manifest_sha256.len() != 64
                || hex::decode(&state.manifest_sha256).is_err()
                || serde_json::to_vec(&state).map_err(|_| UpdateError::Malformed)? != bytes
            {
                return Err(UpdateError::Malformed);
            }
            Ok(state)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(AcceptedUpdateState {
            schema_version: 2,
            ..AcceptedUpdateState::default()
        }),
        Err(error) => Err(error.into()),
    }
}

fn write_update_state(path: &Path, state: &AcceptedUpdateState) -> Result<(), UpdateError> {
    let parent = path.parent().ok_or(UpdateError::Malformed)?;
    fs::create_dir_all(parent)?;
    let temporary = unique_sibling(path, "state")?;
    let result = (|| {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&serde_json::to_vec(state).map_err(|_| UpdateError::Malformed)?)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        sync_directory(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

/// The strongest rollback floor accepted by this installation; absent state is rejected.
pub fn accepted_rollback_floor(root: &Path) -> Result<String, UpdateError> {
    let state = read_update_state(&root.join("accepted-update.json"))?;
    if state.highest_sequence == 0 {
        return Err(UpdateError::Rollback);
    }
    Ok(state.rollback_floor)
}
