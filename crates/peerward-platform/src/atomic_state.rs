/// Durable peer state persisted without exposing private keys or tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalState {
    /// Local state schema.
    pub schema_version: u32,
    /// Peer identity.
    pub peer_id: PeerId,
    /// Last verified peer directory.
    pub directory_revision: u64,
    /// Last verified policy.
    pub policy_revision: u64,
    /// Last verified relay directory.
    pub relay_revision: u64,
}

/// Same-directory write, fsync, rename, and directory-fsync persistence.
pub struct AtomicStateStore {
    path: PathBuf,
}

impl AtomicStateStore {
    /// Targets one regular file.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// Loads one strict JSON document.
    pub fn load<T: DeserializeOwned>(&self) -> Result<T, PlatformError> {
        let bytes = peerward_credentials::private_files::read_bounded_regular_file(
            &self.path,
            1024 * 1024,
        )?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Whether the target state exists.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Removes a committed document and fsyncs its parent directory.
    pub fn remove(&self) -> Result<(), PlatformError> {
        match fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    }

    /// Atomically replaces the document with mode 0600 on Unix.
    pub fn save<T: Serialize>(&self, value: &T) -> Result<(), PlatformError> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)?;
        let filename = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(PlatformError::InvalidName)?;
        let temporary = parent.join(format!(".{filename}.{}.tmp", Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| {
            let mut file = options.open(&temporary)?;
            let encoded = serde_json::to_vec(value)?;
            if encoded.len() > 1024 * 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "local state exceeds its size bound",
                )
                .into());
            }
            file.write_all(&encoded)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            fs::rename(&temporary, &self.path)?;
            fs::File::open(parent)?.sync_all()?;
            Ok::<(), PlatformError>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
}

#[cfg(test)]
mod atomic_state_bounds_tests {
    use super::*;

    #[test]
    fn refuses_to_persist_state_that_cannot_be_loaded() {
        let directory = std::env::temp_dir().join(format!(
            "peerward-atomic-state-bound-{}",
            Uuid::new_v4()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("state.json");
        let oversized = "x".repeat(1024 * 1024);
        assert!(AtomicStateStore::new(&path).save(&oversized).is_err());
        assert!(!path.exists());
        fs::remove_dir_all(directory).unwrap();
    }
}
