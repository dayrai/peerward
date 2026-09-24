#[derive(Debug, Args)]
pub struct PeerRunGroup {
    #[command(subcommand)]
    pub command: PeerRunCommand,
}
#[derive(Debug, Subcommand)]
pub enum PeerRunCommand {
    /// Install a joined, stopped profile for the packaged Linux systemd service.
    Install {
        /// Directory containing peer.toml and its identity and trust history.
        #[arg(long)]
        profile: PathBuf,
    },
    /// Run an explicit configuration or the single active saved profile.
    Run {
        #[arg(long, required_unless_present = "catalog", conflicts_with = "catalog")]
        config: Option<PathBuf>,
        #[arg(long, required_unless_present = "config", conflicts_with = "config")]
        catalog: Option<PathBuf>,
    },
}
#[derive(Debug, Args)]
pub struct ProfileGroup {
    #[command(subcommand)]
    pub command: ProfileCommand,
}
#[derive(Debug, Subcommand)]
pub enum ProfileCommand {
    /// List saved configurations and the selected one; no credentials are exported.
    List {
        #[arg(long)]
        catalog: PathBuf,
    },
    /// Register an existing joined configuration by name; no new identity is created.
    Save {
        #[arg(long)]
        catalog: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        config: PathBuf,
    },
    /// Select a saved network while all catalog runtimes are stopped.
    Select {
        #[arg(long)]
        catalog: PathBuf,
        #[arg(long)]
        name: String,
    },
    /// Clear the active choice without removing any saved files.
    Deactivate {
        #[arg(long)]
        catalog: PathBuf,
    },
    /// Remove an inactive catalog entry. Its configuration, keys and trust history remain.
    Remove {
        #[arg(long)]
        catalog: PathBuf,
        #[arg(long)]
        name: String,
    },
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedPeerProfile {
    name: String,
    mesh_id: MeshId,
    peer_id: peerward_types::PeerId,
    configuration: PathBuf,
    management_socket: PathBuf,
    platform_state_file: Option<PathBuf>,
}
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedPeerCatalog {
    version: u32,
    active: Option<peerward_types::PeerId>,
    profiles: Vec<SavedPeerProfile>,
}
impl Default for SavedPeerCatalog {
    fn default() -> Self {
        Self {
            version: 4,
            active: None,
            profiles: vec![],
        }
    }
}
struct SavedCatalogFile {
    folder: PathBuf,
    _lock: peerward_platform::LocalRuntimeLock,
}
impl SavedCatalogFile {
    fn open(folder: &Path) -> Result<(Self, SavedPeerCatalog), CliError> {
        use peerward_credentials::private_files;
        private_files::private_dir(folder)
            .map_err(|_| CliError::invalid("catalog needs a private directory without symlinks"))?;
        let lock=peerward_platform::LocalRuntimeLock::acquire(&folder.join("catalog.lock"))
            .map_err(|_|CliError::failure("a saved-profile daemon or another catalog operation is active; stop it before switching"))?;
        let state = read_saved_catalog(folder)?;
        Ok((
            Self {
                folder: folder.to_path_buf(),
                _lock: lock,
            },
            state,
        ))
    }
    fn save(&self, state: &SavedPeerCatalog) -> Result<(), CliError> {
        validate_saved_catalog(state)?;
        let bytes = serde_json::to_vec_pretty(state)
            .map_err(|_| CliError::failure("cannot encode profile catalog"))?;
        peerward_credentials::private_files::write_private_atomic(
            &self.folder.join("profiles.json"),
            &bytes,
        )
        .map_err(|_| CliError::failure("cannot atomically save profile catalog"))
    }
}
fn read_saved_catalog(folder: &Path) -> Result<SavedPeerCatalog, CliError> {
    let state = match peerward_credentials::private_files::read_private(
        &folder.join("profiles.json"),
        256 * 1024,
    ) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|_| CliError::invalid("invalid saved profile catalog"))?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => SavedPeerCatalog::default(),
        Err(_) => {
            return Err(CliError::invalid(
                "cannot safely read saved profile catalog",
            ));
        }
    };
    validate_saved_catalog(&state)?;
    Ok(state)
}
fn validate_saved_catalog(state: &SavedPeerCatalog) -> Result<(), CliError> {
    let mut names = std::collections::BTreeSet::new();
    let mut ids = std::collections::BTreeSet::new();
    if state.version != 4 || state.profiles.len() > 32 {
        return Err(CliError::invalid(
            "expected catalog format 4 with at most 32 profiles",
        ));
    }
    for entry in &state.profiles {
        if !peerward_management::name_valid(&entry.name)
            || !entry.configuration.is_absolute()
            || !entry.management_socket.is_absolute()
            || entry
                .platform_state_file
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
            || !names.insert(&entry.name)
            || !ids.insert(entry.peer_id)
        {
            return Err(CliError::invalid("invalid or duplicate saved profile"));
        }
    }
    if state.active.is_some_and(|active| !ids.contains(&active)) {
        return Err(CliError::invalid(
            "active profile is missing from the catalog",
        ));
    }
    Ok(())
}
fn inspect_saved_configuration(path: &Path) -> Result<PeerConfig, CliError> {
    use std::io::Read as _;
    peerward_credentials::private_files::reject_symlinks(path)
        .map_err(|_| CliError::invalid("saved configuration path must not contain symlinks"))?;
    let file =
        fs::File::open(path).map_err(|_| CliError::invalid("saved configuration is missing"))?;
    let metadata = file
        .metadata()
        .map_err(|_| CliError::invalid("cannot inspect saved configuration"))?;
    if !metadata.is_file() || metadata.len() > 256 * 1024 {
        return Err(CliError::invalid("saved configuration exceeds its bound"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(CliError::invalid(
                "saved configuration must not be writable by group or others",
            ));
        }
    }
    let mut contents = String::new();
    file.take(256 * 1024 + 1)
        .read_to_string(&mut contents)
        .map_err(|_| CliError::invalid("saved configuration is not UTF-8"))?;
    PeerConfig::parse(&contents, path).map_err(|_| {
        CliError::invalid("saved configuration requires current format and valid fields")
    })
}
fn load_saved_entry(entry: &SavedPeerProfile) -> Result<PeerConfig, CliError> {
    let config = inspect_saved_configuration(&entry.configuration)?;
    if config.mesh_id != entry.mesh_id
        || config.peer_id != entry.peer_id
        || config.management_socket != entry.management_socket
        || config
            .linux
            .as_ref()
            .map(|linux| &linux.platform_state_file)
            != entry.platform_state_file.as_ref()
    {
        return Err(CliError::invalid(
            "saved configuration identity or runtime socket changed; register it explicitly again",
        ));
    }
    Ok(config)
}
fn lock_saved_runtimes(
    state: &SavedPeerCatalog,
) -> Result<Vec<peerward_platform::LocalRuntimeLock>, CliError> {
    let paths: std::collections::BTreeSet<_> = state
        .profiles
        .iter()
        .map(|entry| entry.management_socket.with_extension("runtime.lock"))
        .collect();
    paths
        .iter()
        .map(|path| {
            peerward_platform::LocalRuntimeLock::acquire(path).map_err(|_| {
                CliError::failure(
                    "stop saved profile runtimes before modifying the active selection",
                )
            })
        })
        .collect()
}
fn ensure_profile_exit_is_off(state: &SavedPeerCatalog) -> Result<(), CliError> {
    if let Some(entry) = state
        .profiles
        .iter()
        .find(|entry| Some(entry.peer_id) == state.active)
        && entry.platform_state_file.as_ref().is_some_and(|path| {
            std::iter::once(path.clone())
                .chain(
                    [
                        "exit-guard.json",
                        "exit-routes.json",
                        "dns.json",
                        "resources.json",
                    ]
                    .map(|extension| path.with_extension(extension)),
                )
                .any(|journal| match fs::symlink_metadata(journal) {
                    Ok(_) => true,
                    Err(error) => error.kind() != std::io::ErrorKind::NotFound,
                })
        })
    {
        return Err(CliError::failure(
            "the selected profile still has network recovery state or exit protection; run client exit off --config PATH --offline in its original network environment before switching",
        ));
    }
    Ok(())
}
fn execute_profile_command(command: ProfileCommand) -> Result<(), CliError> {
    let folder = match &command {
        ProfileCommand::List { catalog }
        | ProfileCommand::Save { catalog, .. }
        | ProfileCommand::Select { catalog, .. }
        | ProfileCommand::Deactivate { catalog }
        | ProfileCommand::Remove { catalog, .. } => catalog,
    };
    if matches!(command, ProfileCommand::List { .. }) {
        let state = read_saved_catalog(folder)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&state)
                .map_err(|_| CliError::failure("cannot encode saved profiles"))?
        );
        return Ok(());
    }
    let (file, mut state) = SavedCatalogFile::open(folder)?;
    let _runtime_locks = lock_saved_runtimes(&state)?;
    match command {
        ProfileCommand::Save { name, config, .. } => {
            peerward_credentials::private_files::reject_symlinks(&config).map_err(|_| {
                CliError::invalid("saved configuration path must not contain symlinks")
            })?;
            let config = fs::canonicalize(config)
                .map_err(|_| CliError::invalid("configuration path is missing"))?;
            let parsed = inspect_saved_configuration(&config)?;
            if state.profiles.iter().any(|entry| {
                Some(entry.peer_id) == state.active
                    && entry.peer_id == parsed.peer_id
                    && entry.platform_state_file.as_ref()
                        != parsed
                            .linux
                            .as_ref()
                            .map(|linux| &linux.platform_state_file)
            }) {
                ensure_profile_exit_is_off(&state)?;
            }
            let _new_lock = if state
                .profiles
                .iter()
                .any(|entry| entry.management_socket == parsed.management_socket)
            {
                None
            } else {
                Some(
                    peerward_platform::LocalRuntimeLock::acquire(
                        &parsed.management_socket.with_extension("runtime.lock"),
                    )
                    .map_err(|_| {
                        CliError::failure(
                            "stop this runtime before registering its saved configuration",
                        )
                    })?,
                )
            };
            let entry = SavedPeerProfile {
                name,
                mesh_id: parsed.mesh_id,
                peer_id: parsed.peer_id,
                configuration: config,
                management_socket: parsed.management_socket,
                platform_state_file: parsed.linux.map(|linux| linux.platform_state_file),
            };
            if state
                .profiles
                .iter()
                .any(|old| old.peer_id == entry.peer_id && old.mesh_id != entry.mesh_id)
            {
                return Err(CliError::invalid(
                    "peer identity is already saved for another Mesh",
                ));
            }
            state.profiles.retain(|old| old.peer_id != entry.peer_id);
            if state.active.is_none() {
                state.active = Some(entry.peer_id);
            }
            state.profiles.push(entry);
            state.profiles.sort_by(|a, b| a.name.cmp(&b.name));
        }
        ProfileCommand::Select { name, .. } => {
            let entry = state
                .profiles
                .iter()
                .find(|entry| entry.name == name)
                .ok_or_else(|| CliError::invalid("saved profile name was not found"))?;
            if state.active != Some(entry.peer_id) {
                ensure_profile_exit_is_off(&state)?;
                state.active = Some(entry.peer_id);
            }
        }
        ProfileCommand::Deactivate { .. } => {
            ensure_profile_exit_is_off(&state)?;
            state.active = None;
        }
        ProfileCommand::Remove { name, .. } => {
            let entry = state
                .profiles
                .iter()
                .find(|entry| entry.name == name)
                .ok_or_else(|| CliError::invalid("saved profile name was not found"))?;
            if state.active == Some(entry.peer_id) {
                return Err(CliError::failure(
                    "select another profile or deactivate before removing the active entry",
                ));
            }
            state.profiles.retain(|entry| entry.name != name);
        }
        ProfileCommand::List { .. } => {}
    }
    file.save(&state)?;
    println!(
        "Saved profile selection updated. Start peer run --catalog PATH to connect; saved configuration and trust history were retained."
    );
    Ok(())
}
async fn run_selected_peer(config: Option<&Path>, catalog: Option<&Path>) -> Result<(), CliError> {
    match (config, catalog) {
        (Some(path), None) => run_peer(path).await,
        (None, Some(folder)) => {
            let (_catalog_lock, state) = SavedCatalogFile::open(folder)?;
            let entry = state
                .profiles
                .iter()
                .find(|entry| Some(entry.peer_id) == state.active)
                .ok_or_else(|| CliError::invalid("select a saved profile before connecting"))?;
            load_saved_entry(entry)?;
            let mut other_profiles = state.clone();
            other_profiles
                .profiles
                .retain(|other| other.management_socket != entry.management_socket);
            let _other_runtimes = lock_saved_runtimes(&other_profiles)?;
            run_peer(&entry.configuration).await
        }
        _ => Err(CliError::invalid(
            "choose exactly one of --config or --catalog",
        )),
    }
}
