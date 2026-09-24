//! Durable intent for a single role. The caller holds the installation lock.
use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStage {
    Prepared,
    RestartPending,
    RecoveryRequired,
    Succeeded,
    RolledBack,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateDirection {
    Install,
    Rollback,
}

/// Validated request context persisted with the initial intent, before any link changes.
pub struct TransactionOptions<'a> {
    pub health_url: &'a str,
    pub repair: bool,
    pub approved_preview: Option<&'a str>,
}

/// Private local journal, not proof of current service health or a signed release.
/// Only `prepare` accepts authenticated release material; no secrets are recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateTransaction {
    format: u32,
    role: String,
    manifest: ReleaseManifest,
    artifact: ReleaseArtifact,
    previous_version: String,
    health_url: String,
    direction: UpdateDirection,
    stage: UpdateStage,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    approved_preview: Option<String>,
}

impl UpdateTransaction {
    pub fn role(&self) -> &str {
        &self.role
    }
    pub fn version(&self) -> &str {
        &self.manifest.version
    }
    pub fn health_url(&self) -> &str {
        &self.health_url
    }
    pub fn stage(&self) -> UpdateStage {
        self.stage
    }
    pub fn direction(&self) -> UpdateDirection {
        self.direction
    }
    pub fn is_terminal(&self) -> bool {
        matches!(self.stage, UpdateStage::Succeeded | UpdateStage::RolledBack)
    }

    pub fn load(root: &Path, role: &str) -> Result<Option<Self>, UpdateError> {
        let path = journal_path(root, role)?;
        let bytes = match peerward_credentials::private_files::read_private(
            &path,
            MAX_MANIFEST_BYTES as u64,
        ) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let record: Self = serde_json::from_slice(&bytes).map_err(|_| UpdateError::Malformed)?;
        record.manifest.validate()?;
        if record.format != 1
            || record.role != role
            || canonical_version(&record.previous_version).is_none()
            || !record.manifest.artifacts.contains(&record.artifact)
            || record.health_url.len() > 4096
            || serde_json::to_vec(&record).map_err(|_| UpdateError::Malformed)? != bytes
        {
            return Err(UpdateError::Malformed);
        }
        Ok(Some(record))
    }

    /// Stage authenticated bytes before any pointer change. An unfinished request
    /// must be recovered, never replaced by a second upgrade or another health URL.
    pub fn prepare(
        root: &Path,
        role: &str,
        bytes: &[u8],
        artifact: &ReleaseArtifact,
        manifest: &ReleaseManifest,
        health_url: &str,
    ) -> Result<Self, UpdateError> {
        Self::prepare_approved(
            root,
            role,
            bytes,
            artifact,
            manifest,
            TransactionOptions {
                health_url,
                repair: false,
                approved_preview: None,
            },
        )
    }

    /// Explicitly supersede failed work with a newer authenticated release.
    /// The previous failed record is retained; active or completed work is never replaced.
    pub fn prepare_repair(
        root: &Path,
        role: &str,
        bytes: &[u8],
        artifact: &ReleaseArtifact,
        manifest: &ReleaseManifest,
        health_url: &str,
    ) -> Result<Self, UpdateError> {
        Self::prepare_approved(
            root,
            role,
            bytes,
            artifact,
            manifest,
            TransactionOptions {
                health_url,
                repair: true,
                approved_preview: None,
            },
        )
    }

    pub fn prepare_approved(
        root: &Path,
        role: &str,
        bytes: &[u8],
        artifact: &ReleaseArtifact,
        manifest: &ReleaseManifest,
        options: TransactionOptions<'_>,
    ) -> Result<Self, UpdateError> {
        let TransactionOptions {
            health_url,
            repair,
            approved_preview,
        } = options;
        if approved_preview.is_some_and(|value| {
            value.len() != 64
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }) {
            return Err(UpdateError::Malformed);
        }
        if !matches!(role, "control" | "relay" | "peer") || health_url.len() > 4096 {
            return Err(UpdateError::Malformed);
        }
        manifest.validate()?;
        if !manifest.artifacts.contains(artifact) {
            return Err(UpdateError::Malformed);
        }
        verify_artifact(bytes, artifact)?;
        let accepted = read_update_state(&root.join("accepted-update.json"))?;
        let digest = hex::encode(Sha256::digest(
            serde_json::to_vec(manifest).map_err(|_| UpdateError::Malformed)?,
        ));
        if accepted.highest_sequence != manifest.sequence || accepted.manifest_sha256 != digest {
            return Err(UpdateError::Rollback);
        }
        let existing = Self::load(root, role)?;
        if repair
            && existing
                .as_ref()
                .is_none_or(|record| record.stage != UpdateStage::RecoveryRequired)
        {
            return Err(UpdateError::RecoveryRequired);
        }
        if let Some(existing) = &existing {
            if existing.manifest == *manifest
                && existing.artifact == *artifact
                && existing.health_url == health_url
                && existing.approved_preview.as_deref() == approved_preview
            {
                return if repair {
                    Err(UpdateError::RecoveryRequired)
                } else {
                    Ok(existing.clone())
                };
            }
            if repair {
                if manifest.sequence <= existing.manifest.sequence
                    || manifest.version == existing.manifest.version
                    || parsed_version(&manifest.version)?
                        .cmp_precedence(&parsed_version(&existing.manifest.version)?)
                        .is_lt()
                {
                    return Err(UpdateError::Rollback);
                }
            } else if !existing.is_terminal() {
                return Err(UpdateError::RecoveryRequired);
            }
        }
        let previous_version = target_version(&fs::read_link(
            root.join("roles").join(role).join("current"),
        )?)?;
        if previous_version == manifest.version {
            return Err(UpdateError::Incompatible);
        }
        stage_versioned(bytes, artifact, &manifest.version, root, Some(manifest))?;
        let record = Self {
            format: 1,
            role: role.into(),
            manifest: manifest.clone(),
            artifact: artifact.clone(),
            previous_version,
            health_url: health_url.into(),
            direction: UpdateDirection::Install,
            stage: UpdateStage::Prepared,
            approved_preview: approved_preview.map(str::to_owned),
        };
        if repair {
            existing
                .as_ref()
                .ok_or(UpdateError::RecoveryRequired)?
                .save_at(
                    &journal_path(root, role)?.with_file_name("previous-update-transaction.json"),
                )?;
        }
        record.save(root)?;
        Ok(record)
    }

    /// Retain the approved preview so an exact completed retry does not fail
    /// merely because the first execution changed process and journal state.
    pub fn bind_preview(&mut self, root: &Path, digest: &str) -> Result<(), UpdateError> {
        self.require_current_record(root)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(UpdateError::Malformed);
        }
        if self.approved_preview.as_deref() == Some(digest) {
            return Ok(());
        }
        if self.stage != UpdateStage::Prepared || self.approved_preview.is_some() {
            return Err(UpdateError::RecoveryRequired);
        }
        self.approved_preview = Some(digest.into());
        self.save(root)
    }

    pub fn matches_approved_request(
        &self,
        manifest: &ReleaseManifest,
        artifact: &ReleaseArtifact,
        health: &str,
        digest: Option<&str>,
    ) -> bool {
        self.is_terminal()
            && self.manifest == *manifest
            && self.artifact == *artifact
            && self.health_url == health
            && self.approved_preview.as_deref() == digest
    }

    /// Reconcile both links from the recorded intent. Repeating after any link
    /// rename is safe; unlike swapping links, this cannot toggle a failed release back.
    pub fn activate(
        &mut self,
        root: &Path,
        schema: u32,
        wire: u32,
    ) -> Result<PathBuf, UpdateError> {
        self.require_current_record(root)?;
        let target = self.selected_version();
        verify_installed_version(root, target, schema, wire, &accepted_rollback_floor(root)?)?;
        let directory = root.join("roles").join(&self.role);
        let current = target_version(&fs::read_link(directory.join("current"))?)?;
        if current != self.previous_version && current != self.manifest.version {
            return Err(UpdateError::RecoveryRequired);
        }
        if self.is_terminal() {
            return if current == target {
                Ok(directory.join("current"))
            } else {
                Err(UpdateError::RecoveryRequired)
            };
        }
        let retained = if self.direction == UpdateDirection::Install {
            &self.previous_version
        } else {
            &self.manifest.version
        };
        replace_symlink(&directory, "previous", &version_target(retained))?;
        sync_directory(&directory)?;
        replace_symlink(&directory, "current", &version_target(target))?;
        sync_directory(&directory)?;
        self.stage = UpdateStage::RestartPending;
        self.save(root)?;
        Ok(directory.join("current"))
    }

    /// Prepare an explicit rollback, retaining the exact original target on retries.
    /// Control requires forward repair: this journal cannot undo database migrations.
    pub fn request_rollback(
        &mut self,
        root: &Path,
        schema: u32,
        wire: u32,
    ) -> Result<(), UpdateError> {
        self.require_current_record(root)?;
        if self.role == "control" {
            return Err(UpdateError::Incompatible);
        }
        if self.direction == UpdateDirection::Rollback {
            return Ok(());
        }
        verify_installed_version(
            root,
            &self.previous_version,
            schema,
            wire,
            &accepted_rollback_floor(root)?,
        )?;
        self.direction = UpdateDirection::Rollback;
        self.stage = UpdateStage::Prepared;
        self.save(root)
    }

    pub fn record_failure(&mut self, root: &Path) -> Result<(), UpdateError> {
        self.require_current_record(root)?;
        if self.is_terminal() {
            return Err(UpdateError::Malformed);
        }
        self.stage = UpdateStage::RecoveryRequired;
        self.save(root)
    }

    /// Called only after the caller checks both readiness and the actual executable.
    pub fn record_ready(&mut self, root: &Path) -> Result<(), UpdateError> {
        self.require_current_record(root)?;
        if self.stage != UpdateStage::RestartPending {
            return Err(UpdateError::Malformed);
        }
        let current = fs::read_link(root.join("roles").join(&self.role).join("current"))?;
        if target_version(&current)? != self.selected_version() {
            return Err(UpdateError::RecoveryRequired);
        }
        self.stage = if self.direction == UpdateDirection::Install {
            UpdateStage::Succeeded
        } else {
            UpdateStage::RolledBack
        };
        self.save(root)
    }

    fn selected_version(&self) -> &str {
        if self.direction == UpdateDirection::Install {
            &self.manifest.version
        } else {
            &self.previous_version
        }
    }

    fn require_current_record(&self, root: &Path) -> Result<(), UpdateError> {
        if Self::load(root, &self.role)?.as_ref() != Some(self) {
            return Err(UpdateError::RecoveryRequired);
        }
        Ok(())
    }

    fn save(&self, root: &Path) -> Result<(), UpdateError> {
        self.save_at(&journal_path(root, &self.role)?)
    }
    fn save_at(&self, path: &Path) -> Result<(), UpdateError> {
        let bytes = serde_json::to_vec(self).map_err(|_| UpdateError::Malformed)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(UpdateError::Malformed);
        }
        let temporary = unique_sibling(path, "journal")?;
        let result = (|| {
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, path)?;
            sync_directory(path.parent().ok_or(UpdateError::Malformed)?)
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

fn journal_path(root: &Path, role: &str) -> Result<PathBuf, UpdateError> {
    if !matches!(role, "control" | "relay" | "peer") {
        return Err(UpdateError::Malformed);
    }
    Ok(root
        .join("roles")
        .join(role)
        .join("update-transaction.json"))
}

/// Read the selected canonical role version without trusting the updater executable's version.
pub fn installed_role_version(root: &Path, role: &str) -> Result<String, UpdateError> {
    let path = journal_path(root, role)?;
    target_version(&fs::read_link(path.with_file_name("current"))?)
}

fn version_target(version: &str) -> PathBuf {
    PathBuf::from("../../versions")
        .join(version)
        .join("peerward")
}

fn target_version(target: &Path) -> Result<String, UpdateError> {
    let version = target
        .parent()
        .and_then(Path::file_name)
        .and_then(|v| v.to_str())
        .ok_or(UpdateError::Malformed)?;
    if canonical_version(version).is_none() || target != version_target(version) {
        return Err(UpdateError::Malformed);
    }
    Ok(version.into())
}

fn verify_installed_version(
    root: &Path,
    version: &str,
    schema: u32,
    wire: u32,
    floor: &str,
) -> Result<(), UpdateError> {
    let directory = root.join("versions").join(version);
    let path = directory.join("compatibility.json");
    let bytes = peerward_credentials::private_files::read_private(&path, MAX_MANIFEST_BYTES as u64)
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
    verify_artifact_file(&directory.join("peerward"), &metadata.artifact)
}
