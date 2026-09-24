//! Bounded private key persistence shared by installation and running services.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

pub fn reject_symlinks(path: &Path) -> io::Result<()> {
    for part in path.ancestors() {
        if part.as_os_str().is_empty() {
            continue;
        }
        match fs::symlink_metadata(part) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(io::Error::other("symlink in key path"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub fn private_dir(path: &Path) -> io::Result<()> {
    reject_symlinks(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)?;
        check_private(&fs::metadata(path)?)?;
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path)?;
    Ok(())
}

fn check_private(meta: &fs::Metadata) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::other(
                "key material must not be group/world accessible",
            ));
        }
    }
    Ok(())
}

pub fn read_private(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    reject_symlinks(path)?;
    let file = open_nonblocking(path, true)?;
    let meta = file.metadata()?;
    check_private(&meta)?;
    read_opened_bounded(file, &meta, limit)
}

/// Reads a public configuration or certificate without following special files
/// into an unbounded allocation or waiting for a FIFO writer. Symlinks remain
/// supported for system-managed public files such as TLS certificate chains.
pub fn read_bounded_regular_file(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let file = open_nonblocking(path, false)?;
    let meta = file.metadata()?;
    read_opened_bounded(file, &meta, limit)
}

fn open_nonblocking(path: &Path, no_follow: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK | if no_follow { libc::O_NOFOLLOW } else { 0 });
    }
    options.open(path)
}

fn read_opened_bounded(mut file: File, meta: &fs::Metadata, limit: u64) -> io::Result<Vec<u8>> {
    if !meta.is_file() || meta.len() > limit {
        return Err(io::Error::other("invalid file size/type"));
    }
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other("file too large"));
    }
    Ok(bytes)
}

pub fn write_private_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    reject_symlinks(path)?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("key path has no parent"))?;
    private_dir(parent)?;
    let temporary = parent.join(format!(".write-{}", uuid::Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn remove_private(path: &Path) -> io::Result<()> {
    reject_symlinks(path)?;
    match fs::remove_file(path) {
        Ok(()) => File::open(
            path.parent()
                .ok_or_else(|| io::Error::other("invalid key path"))?,
        )?
        .sync_all(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory() -> std::path::PathBuf {
        std::env::temp_dir().join(format!("peerward-bounded-file-{}", uuid::Uuid::new_v4()))
    }

    #[test]
    fn bounded_reader_rejects_non_regular_and_oversized_files() {
        let directory = temporary_directory();
        fs::create_dir(&directory).unwrap();
        let path = directory.join("input");
        File::create(&path).unwrap().set_len(1_048_576).unwrap();
        assert!(read_bounded_regular_file(&path, 65_536).is_err());
        assert!(read_bounded_regular_file(&directory, 65_536).is_err());
        fs::write(&path, b"bounded").unwrap();
        assert_eq!(read_bounded_regular_file(&path, 7).unwrap(), b"bounded");
        assert!(read_bounded_regular_file(&path, 6).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_does_not_wait_for_fifo_writer() {
        use std::{process::Command, time::Instant};

        let directory = temporary_directory();
        fs::create_dir(&directory).unwrap();
        let path = directory.join("input.fifo");
        assert!(
            Command::new("mkfifo")
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
        let started = Instant::now();
        assert!(read_bounded_regular_file(&path, 65_536).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        fs::remove_dir_all(directory).unwrap();
    }
}
