//! One OS-owned runtime and durable optimistic local preferences per profile.
use crate::{AtomicStateStore, PlatformError};
#[cfg(test)]
use peerward_management::ClientPreferences;
use peerward_management::PreferenceChange;
pub use peerward_management::SavedClientPreferences;
use peerward_types::{MeshId, PeerId};
use std::{
    fs::{File, OpenOptions},
    io::Read as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _},
    path::Path,
};

pub struct LocalRuntimeLock {
    _file: File,
}
impl LocalRuntimeLock {
    /// Keep the inode for the lifetime of the runtime; never unlink an advisory lock.
    pub fn acquire(path: &Path) -> Result<Self, PlatformError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)?;
        private_metadata(&file)?;
        file.try_lock().map_err(|_| {
            PlatformError::Command("another runtime or offline operation owns this profile".into())
        })?;
        Ok(Self { _file: file })
    }
}
pub struct ClientPreferenceStore {
    file: AtomicStateStore,
    saved: SavedClientPreferences,
}
impl ClientPreferenceStore {
    pub fn load(path: &Path, mesh: MeshId, peer: PeerId) -> Result<Self, PlatformError> {
        let saved = match read_private_json(path) {
            Ok(bytes) => {
                let saved: SavedClientPreferences = serde_json::from_slice(&bytes)?;
                saved
                    .validate(mesh, peer)
                    .map_err(|_| PlatformError::OwnershipConflict)?;
                saved
            }
            Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                SavedClientPreferences::new(mesh, peer)
            }
            Err(error) => return Err(error),
        };
        Ok(Self {
            file: AtomicStateStore::new(path),
            saved,
        })
    }
    pub fn saved(&self) -> &SavedClientPreferences {
        &self.saved
    }
    /// Returns false for the exact latest retry. Reused IDs with a different body fail.
    pub fn validate_change(&self, change: &PreferenceChange) -> Result<bool, PlatformError> {
        self.saved
            .validate_change(change)
            .map_err(|_| PlatformError::OwnershipConflict)
    }

    /// Called under the profile's exclusive runtime lock. Save success means persisted,
    /// not that the host has applied it or that an Internet endpoint is reachable.
    pub fn commit(&mut self, change: PreferenceChange) -> Result<(), PlatformError> {
        if !self.validate_change(&change)? {
            return Ok(());
        }
        let mut saved = self.saved.clone();
        saved.version += 1;
        saved.preferences = change.preferences.clone();
        saved.last_change = Some(change);
        self.file.save(&saved)?;
        self.saved = saved;
        Ok(())
    }
}
fn private_metadata(file: &File) -> Result<(), PlatformError> {
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.mode() & 0o077 != 0
        || meta.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(PlatformError::OwnershipConflict);
    }
    Ok(())
}
fn read_private_json(path: &Path) -> Result<Vec<u8>, PlatformError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    private_metadata(&file)?;
    let mut bytes = Vec::new();
    file.take(65_537).read_to_end(&mut bytes)?;
    if bytes.len() > 65_536 {
        return Err(PlatformError::OwnershipConflict);
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "client_preferences_tests.rs"]
mod tests;
