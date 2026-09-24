/// Installs one immutable version and atomically switches a role-specific symlink.
///
/// Layout: `versions/<version>/peerward` plus `roles/<role>/{current,previous}`.
/// Existing immutable version bytes must match the signed artifact exactly.
#[cfg(unix)]
pub fn install_versioned_verified(
    bytes: &[u8],
    artifact: &ReleaseArtifact,
    version: &str,
    role: &str,
    root: &Path,
) -> Result<PathBuf, UpdateError> {
    install_versioned_inner(bytes, artifact, version, role, root, None)
}

/// Installs a verified release with the compatibility metadata required for rollback.
/// The caller must first authenticate the release manifest and select its artifact.
#[cfg(unix)]
pub fn install_versioned_release(
    bytes: &[u8],
    artifact: &ReleaseArtifact,
    manifest: &ReleaseManifest,
    role: &str,
    root: &Path,
) -> Result<PathBuf, UpdateError> {
    manifest.validate()?;
    if !manifest.artifacts.contains(artifact) {
        return Err(UpdateError::Malformed);
    }
    install_versioned_inner(
        bytes,
        artifact,
        &manifest.version,
        role,
        root,
        Some(manifest),
    )
}

#[cfg(unix)]
fn install_versioned_inner(
    bytes: &[u8],
    artifact: &ReleaseArtifact,
    version: &str,
    role: &str,
    root: &Path,
    manifest: Option<&ReleaseManifest>,
) -> Result<PathBuf, UpdateError> {
    if !valid_role(role) {
        return Err(UpdateError::Malformed);
    }
    stage_versioned(bytes, artifact, version, root, manifest)?;
    let role_dir = root.join("roles").join(role);
    fs::create_dir_all(&role_dir)?;
    let target = PathBuf::from("../../versions")
        .join(version)
        .join("peerward");
    let current = role_dir.join("current");
    if let Ok(old_target) = fs::read_link(&current) {
        // A lost response may retry an already-installed immutable release.
        // Preserve the real previous version instead of pointing both links here.
        if old_target == target {
            return Ok(current);
        }
        replace_symlink(&role_dir, "previous", &old_target)?;
    }
    replace_symlink(&role_dir, "current", &target)?;
    sync_directory(&role_dir)?;
    Ok(current)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledCompatibility {
    version: String,
    artifact: ReleaseArtifact,
    schema: CompatibilityRange,
    wire: CompatibilityRange,
}

/// Refuses automatic restoration of missing, modified, or incompatible releases.
/// Metadata is written only after the installing caller verifies the manifest.
#[cfg(unix)]
pub fn rollback_versioned_checked(
    root: &Path,
    role: &str,
    schema: u32,
    wire: u32,
    floor: &str,
) -> Result<PathBuf, UpdateError> {
    if !valid_role(role) {
        return Err(UpdateError::Malformed);
    }
    let role_dir = root.join("roles").join(role);
    let previous = fs::read_link(role_dir.join("previous"))?;
    let version = previous
        .parent()
        .and_then(Path::file_name)
        .and_then(|value| value.to_str())
        .ok_or(UpdateError::Malformed)?;
    if canonical_version(version).is_none()
        || previous
            != PathBuf::from("../../versions")
                .join(version)
                .join("peerward")
    {
        return Err(UpdateError::Malformed);
    }
    let version_dir = root.join("versions").join(version);
    let metadata_path = version_dir.join("compatibility.json");
    let bytes = peerward_credentials::private_files::read_private(
        &metadata_path,
        MAX_MANIFEST_BYTES as u64,
    )
    .map_err(|_| UpdateError::Incompatible)?;
    let metadata: InstalledCompatibility =
        serde_json::from_slice(&bytes).map_err(|_| UpdateError::Malformed)?;
    if metadata.version != version
        || !metadata.schema.contains(schema)
        || !metadata.wire.contains(wire)
        || parsed_version(version)?
            .cmp_precedence(&parsed_version(floor)?)
            .is_lt()
    {
        return Err(UpdateError::Incompatible);
    }
    verify_artifact_file(&version_dir.join("peerward"), &metadata.artifact)?;
    rollback_versioned(root, role)
}

/// Swaps a role back to its retained previous immutable version.
#[cfg(unix)]
pub fn rollback_versioned(root: &Path, role: &str) -> Result<PathBuf, UpdateError> {
    if !valid_role(role) {
        return Err(UpdateError::Malformed);
    }
    let role_dir = root.join("roles").join(role);
    let current = role_dir.join("current");
    let previous = role_dir.join("previous");
    let current_target = fs::read_link(&current)?;
    let previous_target = fs::read_link(&previous)?;
    replace_symlink(&role_dir, "current", &previous_target)?;
    replace_symlink(&role_dir, "previous", &current_target)?;
    sync_directory(&role_dir)?;
    Ok(current)
}

#[cfg(unix)]
fn stage_versioned(
    bytes: &[u8],
    artifact: &ReleaseArtifact,
    version: &str,
    root: &Path,
    manifest: Option<&ReleaseManifest>,
) -> Result<PathBuf, UpdateError> {
    use std::os::unix::fs::PermissionsExt as _;

    verify_artifact(bytes, artifact)?;
    if canonical_version(version).is_none() {
        return Err(UpdateError::Malformed);
    }
    let versions = root.join("versions");
    let version_dir = versions.join(version);
    let binary = version_dir.join("peerward");
    fs::create_dir_all(&version_dir)?;
    if binary.exists() {
        verify_artifact_file(&binary, artifact)?;
    } else {
        let temporary = version_dir.join(format!(".peerward.incoming.{}", std::process::id()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            file.set_permissions(fs::Permissions::from_mode(0o755))?;
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, &binary)?;
            sync_directory(&version_dir)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result?;
    }
    if let Some(manifest) = manifest {
        let metadata = serde_json::to_vec(&InstalledCompatibility {
            version: version.to_owned(),
            artifact: artifact.clone(),
            schema: manifest.schema_compatibility,
            wire: manifest.wire_compatibility,
        })
        .map_err(|_| UpdateError::Malformed)?;
        let path = version_dir.join("compatibility.json");
        if path.exists() {
            if peerward_credentials::private_files::read_private(
                &path,
                MAX_MANIFEST_BYTES as u64,
            )? != metadata
            {
                return Err(UpdateError::Incompatible);
            }
        } else {
            let temporary = unique_sibling(&path, "incoming")?;
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&temporary)?;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            file.write_all(&metadata)?;
            file.sync_all()?;
            fs::rename(&temporary, &path)?;
            sync_directory(&version_dir)?;
        }
    }
    sync_directory(&versions)?;
    sync_directory(root)?;
    Ok(binary)
}
