//! Install a stopped profile without replacing identities or their trust checkpoints.
use super::{CliError, PeerConfig, inspect_saved_configuration, read_hex_32, verify_peer_trust};
use peerward_credentials::private_files;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Component, Path, PathBuf},
    process::Command,
};
use zeroize::Zeroizing;

const FILE_LIMIT: u64 = 16 * 1024 * 1024;
const TREE_LIMIT: u64 = 64 * 1024 * 1024;
const INSTALLED_CONFIG: &str = ".installed-peer.toml";

struct Layout {
    config: PathBuf,
    profile: PathBuf,
    socket: PathBuf,
    uid: u32,
    gid: u32,
}

pub(super) fn install(source: &Path) -> Result<(), CliError> {
    let caller = fs::metadata("/proc/self").map_err(io_error)?;
    if caller.uid() != 0 {
        return Err(CliError::auth(
            "peer install requires root; run sudo peerward peer install --profile DIRECTORY",
        ));
    }
    if !Path::new("/usr/bin/peerward").is_file()
        || !Path::new("/usr/lib/systemd/system/peerward-peer.service").is_file()
    {
        return Err(CliError::invalid(
            "install the Peerward native package before peer install; the package supplies the binary, service account and systemd unit",
        ));
    }
    let account = |flag| -> Result<u32, CliError> {
        let result = Command::new("/usr/bin/id")
            .args([flag, "peerward"])
            .output()
            .map_err(io_error)?;
        if !result.status.success() {
            return Err(CliError::invalid(
                "the packaged peerward service account is missing; repair the native package",
            ));
        }
        String::from_utf8_lossy(&result.stdout)
            .trim()
            .parse()
            .map_err(|_| CliError::invalid("invalid peerward service account"))
    };
    let layout = Layout {
        config: "/etc/peerward/peer.toml".into(),
        profile: "/var/lib/peerward/peer".into(),
        socket: "/run/peerward/peer.sock".into(),
        uid: account("-u")?,
        gid: account("-g")?,
    };
    let created = install_profile(source, &layout)?;
    println!(
        "{}",
        if created {
            "Peer profile installed."
        } else {
            "The same Peer is already installed; its current identity and state were retained."
        }
    );
    println!("Start and enable: sudo systemctl enable --now peerward-peer.service");
    println!("Check: sudo -u peerward peerward doctor --config /etc/peerward/peer.toml --json");
    Ok(())
}

fn io_error(error: std::io::Error) -> CliError {
    // Avoid including the contents of profiles, command output or private key bytes.
    CliError::failure(format!(
        "peer installation filesystem operation failed ({:?}); source profile retained",
        error.kind()
    ))
}

fn install_profile(source: &Path, layout: &Layout) -> Result<bool, CliError> {
    private_files::reject_symlinks(source).map_err(io_error)?;
    let source = fs::canonicalize(source).map_err(io_error)?;
    for path in [&layout.config, &layout.profile, &layout.socket] {
        private_files::reject_symlinks(path).map_err(io_error)?;
    }
    if layout.profile.starts_with(&source) || source.starts_with(&layout.profile) {
        return Err(CliError::invalid(
            "source and installed profile directories must be separate",
        ));
    }
    let source_config = inspect_saved_configuration(&source.join("peer.toml"))?;
    if source_config.linux.is_none() {
        return Err(CliError::invalid(
            "peer install requires a Linux TUN profile",
        ));
    }
    let parent = layout
        .profile
        .parent()
        .ok_or_else(|| CliError::invalid("invalid installation path"))?;
    fs::create_dir_all(parent).map_err(io_error)?;
    let _install_lock =
        peerward_platform::LocalRuntimeLock::acquire(&parent.join("peer-install.lock"))
            .map_err(|_| CliError::failure("another peer installation owns this destination"))?;
    let target_lock = layout.socket.with_extension("runtime.lock");
    let _target_lock = runtime_lock(&target_lock, layout.uid)?;
    if layout.config.try_exists().map_err(io_error)? {
        let installed = inspect_saved_configuration(&layout.config)?;
        same_identity(&source_config, &installed)?;
        if installed
            .private_key_file
            .strip_prefix(&layout.profile)
            .is_err()
            || installed.management_socket != layout.socket
        {
            return Err(CliError::invalid(
                "the existing Peer configuration is managed separately; it was not replaced",
            ));
        }
        validate_installed_paths(&installed, layout)?;
        verify_identity(&installed)?;
        return Ok(false);
    }
    // A completed directory survives an interruption before /etc configuration publication.
    if layout.profile.try_exists().map_err(io_error)? {
        let prepared = layout.profile.join(INSTALLED_CONFIG);
        let contents = read_regular(&prepared, 256 * 1024)?;
        let installed = PeerConfig::parse(
            std::str::from_utf8(&contents)
                .map_err(|_| CliError::invalid("invalid prepared profile text"))?,
            &prepared,
        )
        .map_err(|_| CliError::invalid("invalid prepared profile configuration"))?;
        same_identity(&source_config, &installed)?;
        validate_installed_paths(&installed, layout)?;
        verify_identity(&installed)?;
        own(&target_lock, layout)?;
        publish_config(&contents, layout)?;
        return Ok(true);
    }
    let source_lock = source_config
        .management_socket
        .with_extension("runtime.lock");
    private_files::reject_symlinks(&source_lock).map_err(io_error)?;
    let _source_lock = if source_lock == target_lock {
        None
    } else {
        Some(runtime_lock(
            &source_lock,
            fs::metadata(&source).map_err(io_error)?.uid(),
        )?)
    };
    ensure_network_restored(&source_config)?;
    let contents = read_regular(&source.join("peer.toml"), 256 * 1024)?;
    let document = render_config(&contents, &source, &source_config, layout)?;
    verify_identity(&source_config)?;
    let staging = parent.join(format!(".peer-install-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&staging)
            .map_err(io_error)?;
        let mut budget = (0_u64, 0_usize);
        copy_tree(&source, &staging, 0, &mut budget)?;
        if staging.join(INSTALLED_CONFIG).exists() || staging.join("runtime").exists() {
            return Err(CliError::invalid(
                "source profile uses a reserved installation filename",
            ));
        }
        let runtime = staging.join("runtime");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&runtime)
            .map_err(io_error)?;
        copy_optional(
            &source_config.service_state_file,
            &runtime.join("services.json"),
        )?;
        let linux = source_config.linux.as_ref().expect("checked Linux profile");
        let preferences = linux.platform_state_file.with_extension("preferences.json");
        if preferences.try_exists().map_err(io_error)? {
            let bytes = read_regular(&preferences, 65_536)?;
            let saved: peerward_management::SavedClientPreferences = serde_json::from_slice(&bytes)
                .map_err(|_| CliError::invalid("invalid source client preferences"))?;
            saved
                .validate(source_config.mesh_id, source_config.peer_id)
                .map_err(|_| CliError::invalid("source preferences belong to another Peer"))?;
            write_new(&runtime.join("network-state-v1.preferences.json"), &bytes)?;
        }
        write_new(&staging.join(INSTALLED_CONFIG), document.as_bytes())?;
        own_tree(&staging, layout)?;
        fs::rename(&staging, &layout.profile).map_err(io_error)?;
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(io_error)?;
        // The service must be able to reopen the stable runtime-lock inode created above.
        own(&target_lock, layout)?;
        publish_config(document.as_bytes(), layout)
    })();
    if staging.exists() {
        let _ = fs::remove_dir_all(&staging);
    }
    result.map(|()| true)
}

fn same_identity(source: &PeerConfig, installed: &PeerConfig) -> Result<(), CliError> {
    if source.mesh_id != installed.mesh_id
        || source.peer_id != installed.peer_id
        || read_regular(
            source
                .root_public_key_file
                .as_deref()
                .ok_or_else(|| CliError::invalid("missing Root verifier"))?,
            128,
        )? != read_regular(
            installed
                .root_public_key_file
                .as_deref()
                .ok_or_else(|| CliError::invalid("missing installed Root verifier"))?,
            128,
        )?
    {
        return Err(CliError::invalid(
            "another Peer identity is already installed; no configuration or keys were replaced",
        ));
    }
    Ok(())
}

fn verify_identity(config: &PeerConfig) -> Result<(), CliError> {
    match fs::symlink_metadata(config.private_key_file.with_extension("mesh-terminated")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        _ => {
            return Err(CliError::auth(
                "this profile has a terminal Mesh marker; join a new Mesh identity before installation",
            ));
        }
    }
    for path in [
        &config.private_key_file,
        &config.identity_private_key_file,
        &config.wireguard_private_key_file,
    ]
    .into_iter()
    .chain(config.root_public_key_file.iter())
    .chain(config.distribution_certificate_file.iter())
    .chain(config.authority_certificate_files.iter())
    {
        let _ = read_regular(path, 4096)?;
    }
    super::validate_private_permissions(&config.private_key_file)?;
    let key = Zeroizing::new(read_hex_32(&config.private_key_file)?);
    let credential = read_regular(&config.credential_file, 1024)?;
    verify_peer_trust(config, &credential, &key).map(|_| ())
}

/// The installer runs as root but locks the same inode used by a non-root runtime.
/// It never unlinks or changes ownership of a source lock.
fn runtime_lock(path: &Path, owner: u32) -> Result<File, CliError> {
    private_files::reject_symlinks(path).map_err(io_error)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(io_error)?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(io_error)?;
    let metadata = file.metadata().map_err(io_error)?;
    let caller = fs::metadata("/proc/self").map_err(io_error)?.uid();
    if !metadata.is_file()
        || metadata.mode() & 0o077 != 0
        || ![owner, caller].contains(&metadata.uid())
    {
        return Err(CliError::invalid(
            "runtime lock must be a private regular file owned by its profile or the installer",
        ));
    }
    file.try_lock().map_err(|_| CliError::failure("stop the source and installed Peer services before installation; a runtime still owns the profile"))?;
    Ok(file)
}

fn ensure_network_restored(config: &PeerConfig) -> Result<(), CliError> {
    let linux = config.linux.as_ref().expect("checked Linux profile");
    for path in std::iter::once(linux.platform_state_file.clone()).chain(
        [
            "exit-guard.json",
            "exit-routes.json",
            "dns.json",
            "resources.json",
        ]
        .map(|extension| linux.platform_state_file.with_extension(extension)),
    ) {
        match fs::symlink_metadata(path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => {
                return Err(CliError::failure(
                    "source profile has unfinished or inaccessible network recovery state; stop it and run client exit off --config PATH --offline in its original environment before installation",
                ));
            }
        }
    }
    Ok(())
}

fn relocated(path: &Path, source: &Path, target: &Path) -> Result<PathBuf, CliError> {
    let relative = path.strip_prefix(source).map_err(|_| {
        CliError::invalid(
            "keep identity and trust files inside the source profile before installation",
        )
    })?;
    if relative.as_os_str().is_empty()
        || relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(CliError::invalid(
            "profile paths must not traverse parent directories",
        ));
    }
    private_files::reject_symlinks(path).map_err(io_error)?;
    Ok(target.join(relative))
}

fn path_value(path: &Path) -> Result<toml::Value, CliError> {
    path.to_str()
        .map(|s| toml::Value::String(s.into()))
        .ok_or_else(|| CliError::invalid("profile paths must be UTF-8"))
}

fn render_config(
    bytes: &[u8],
    source: &Path,
    config: &PeerConfig,
    layout: &Layout,
) -> Result<String, CliError> {
    let text = std::str::from_utf8(bytes).map_err(|_| CliError::invalid("invalid profile text"))?;
    let mut document: toml::Table =
        toml::from_str(text).map_err(|_| CliError::invalid("invalid profile TOML"))?;
    document.remove("config_version");
    for (name, path) in [
        ("credential_file", &config.credential_file),
        (
            "identity_private_key_file",
            &config.identity_private_key_file,
        ),
        ("private_key_file", &config.private_key_file),
        (
            "wireguard_private_key_file",
            &config.wireguard_private_key_file,
        ),
        (
            "root_public_key_file",
            config
                .root_public_key_file
                .as_ref()
                .ok_or_else(|| CliError::invalid("missing Root verifier"))?,
        ),
        (
            "distribution_certificate_file",
            config
                .distribution_certificate_file
                .as_ref()
                .ok_or_else(|| CliError::invalid("missing distribution verifier"))?,
        ),
    ] {
        document.insert(
            name.into(),
            path_value(&relocated(path, source, &layout.profile)?)?,
        );
    }
    let authorities = config
        .authority_certificate_files
        .iter()
        .map(|path| path_value(&relocated(path, source, &layout.profile)?))
        .collect::<Result<Vec<_>, CliError>>()?;
    document.insert(
        "authority_certificate_files".into(),
        toml::Value::Array(authorities),
    );
    document.insert("management_socket".into(), path_value(&layout.socket)?);
    document.insert(
        "service_state_file".into(),
        path_value(&layout.profile.join("runtime/services.json"))?,
    );
    document
        .get_mut("linux")
        .and_then(toml::Value::as_table_mut)
        .ok_or_else(|| CliError::invalid("missing Linux configuration"))?
        .insert(
            "platform_state_file".into(),
            path_value(&layout.profile.join("runtime/network-state-v1.json"))?,
        );
    let rendered = format!(
        "config_version = 4\n{}",
        toml::to_string(&document)
            .map_err(|_| CliError::invalid("cannot render service configuration"))?
    );
    let parsed = PeerConfig::parse(&rendered, &layout.config)
        .map_err(|_| CliError::invalid("invalid rendered service configuration"))?;
    validate_installed_paths(&parsed, layout)?;
    Ok(rendered)
}

fn validate_installed_paths(config: &PeerConfig, layout: &Layout) -> Result<(), CliError> {
    for path in [
        &config.credential_file,
        &config.identity_private_key_file,
        &config.private_key_file,
        &config.wireguard_private_key_file,
    ]
    .into_iter()
    .chain(config.root_public_key_file.iter())
    .chain(config.distribution_certificate_file.iter())
    .chain(config.authority_certificate_files.iter())
    {
        relocated(path, &layout.profile, &layout.profile)?;
    }
    if config.management_socket != layout.socket
        || config.service_state_file != layout.profile.join("runtime/services.json")
        || config.linux.as_ref().map(|l| &l.platform_state_file)
            != Some(&layout.profile.join("runtime/network-state-v1.json"))
    {
        return Err(CliError::invalid(
            "interrupted installation paths differ from the packaged service",
        ));
    }
    Ok(())
}

fn read_regular(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>, CliError> {
    private_files::reject_symlinks(path).map_err(io_error)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(io_error)?;
    let metadata = file.metadata().map_err(io_error)?;
    if !metadata.is_file() || metadata.len() > limit || metadata.mode() & 0o022 != 0 {
        return Err(CliError::invalid(
            "installation input must be a bounded regular file, not writable by group or others",
        ));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() as u64 > limit {
        return Err(CliError::invalid(
            "installation input exceeds its size limit",
        ));
    }
    Ok(bytes)
}

fn copy_optional(source: &Path, target: &Path) -> Result<(), CliError> {
    match fs::symlink_metadata(source) {
        Ok(_) => write_new(target, &read_regular(source, FILE_LIMIT)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error(error)),
    }
}

fn copy_tree(
    source: &Path,
    target: &Path,
    depth: usize,
    budget: &mut (u64, usize),
) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(source).map_err(io_error)?;
    if !metadata.is_dir() || metadata.mode() & 0o022 != 0 || depth > 8 {
        return Err(CliError::invalid(
            "profile directories must be bounded, non-symlinked and not writable by group or others",
        ));
    }
    for entry in fs::read_dir(source).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        budget.1 += 1;
        if budget.1 > 2048 {
            return Err(CliError::invalid("profile exceeds 2048 entries"));
        }
        let destination = target.join(entry.file_name());
        let metadata = fs::symlink_metadata(entry.path()).map_err(io_error)?;
        if metadata.is_dir() {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&destination)
                .map_err(io_error)?;
            copy_tree(&entry.path(), &destination, depth + 1, budget)?;
        } else {
            let bytes = read_regular(&entry.path(), FILE_LIMIT)?;
            budget.0 = budget.0.saturating_add(bytes.len() as u64);
            if budget.0 > TREE_LIMIT {
                return Err(CliError::invalid("profile exceeds 64 MiB"));
            }
            write_new(&destination, &bytes)?;
        }
    }
    File::open(target)
        .and_then(|dir| dir.sync_all())
        .map_err(io_error)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), CliError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(io_error)?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(io_error)
}

fn own(path: &Path, layout: &Layout) -> Result<(), CliError> {
    std::os::unix::fs::chown(path, Some(layout.uid), Some(layout.gid)).map_err(io_error)
}

fn own_tree(path: &Path, layout: &Layout) -> Result<(), CliError> {
    if path.is_dir() {
        for entry in fs::read_dir(path).map_err(io_error)? {
            own_tree(&entry.map_err(io_error)?.path(), layout)?;
        }
    }
    own(path, layout)
}

fn publish_config(bytes: &[u8], layout: &Layout) -> Result<(), CliError> {
    let parent = layout
        .config
        .parent()
        .ok_or_else(|| CliError::invalid("invalid configuration path"))?;
    fs::create_dir_all(parent).map_err(io_error)?;
    let temporary = parent.join(format!(".peer-config-{}", uuid::Uuid::new_v4()));
    let result = (|| {
        write_new(&temporary, bytes)?;
        std::os::unix::fs::chown(&temporary, None, Some(layout.gid)).map_err(io_error)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o640)).map_err(io_error)?;
        // Publish without replacing a configuration installed by another operator.
        fs::hard_link(&temporary, &layout.config).map_err(io_error)?;
        File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(io_error)
    })();
    let _ = fs::remove_file(temporary);
    result
}

#[cfg(test)]
#[path = "peer_install_tests.rs"]
mod tests;
