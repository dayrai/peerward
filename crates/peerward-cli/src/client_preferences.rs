#[derive(Debug, Args)]
pub struct ClientGroup {
    #[command(subcommand)]
    pub command: ClientCommand,
}
#[derive(Debug, Subcommand)]
pub enum ClientCommand {
    /// Save and select local network configurations; switching requires a stopped daemon.
    Profiles(ProfileGroup),
    /// Show saved preferences, eligible exits and actual application state.
    Preferences {
        #[arg(long)]
        config: PathBuf,
    },
    /// Change explicit local preferences. Boolean options take true or false.
    Set {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        accept_routes: Option<bool>,
        #[arg(long)]
        dns: Option<bool>,
        #[arg(long)]
        inbound: Option<bool>,
    },
    /// Select or explicitly disable an Internet exit.
    Exit(ClientExitGroup),
}
#[derive(Debug, Args)]
pub struct ClientExitGroup {
    #[command(subcommand)]
    pub command: ClientExitCommand,
}
#[derive(Debug, Subcommand)]
pub enum ClientExitCommand {
    /// List approved exit resources by name.
    List {
        #[arg(long)]
        config: PathBuf,
    },
    /// Select one exact name or UUID; local LAN bypass is disabled by default.
    Select {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        resource: String,
        #[arg(long)]
        allow_local_lan: bool,
    },
    /// Restore direct access. Offline mode requires the daemon to be stopped.
    Off {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        offline: bool,
    },
}
fn local_peer_config(path: &Path) -> Result<PeerConfig, CliError> {
    let contents = read_bounded_utf8(path, 1024 * 1024)
        .map_err(|_| CliError::invalid("cannot read peer configuration"))?;
    PeerConfig::parse(&contents, path).map_err(|error| CliError::invalid(error.to_string()))
}
async fn query_preferences(
    config: &PeerConfig,
    request: peerward_management::ClientPreferenceRequest,
) -> Result<peerward_management::ClientPreferenceView, CliError> {
    let response=peerward_service::client(&config.management_socket,&ServiceRequest::ClientPreferences {request}).await
        .map_err(|_|CliError::failure("local runtime unavailable; use client exit off --offline only after stopping the daemon"))?;
    if !response.ok {
        return Err(CliError::failure(
            response
                .error
                .unwrap_or_else(|| "local preference update failed".into()),
        ));
    }
    serde_json::from_value(response.detail)
        .map_err(|_| CliError::failure("invalid local preference response"))
}
async fn execute_client_preferences(command: ClientCommand) -> Result<(), CliError> {
    use peerward_management::{ClientPreferenceRequest, PreferenceChange};
    if let ClientCommand::Profiles(group) = command {
        return execute_profile_command(group.command);
    }
    let path = match &command {
        ClientCommand::Profiles(_) => return Err(CliError::invalid("invalid profile dispatch")),
        ClientCommand::Preferences { config }
        | ClientCommand::Set { config, .. }
        | ClientCommand::Exit(ClientExitGroup {
            command:
                ClientExitCommand::List { config }
                | ClientExitCommand::Select { config, .. }
                | ClientExitCommand::Off { config, .. },
        }) => config,
    };
    let config = local_peer_config(path)?;
    if matches!(
        &command,
        ClientCommand::Exit(ClientExitGroup {
            command: ClientExitCommand::Off { offline: true, .. }
        })
    ) {
        disable_exit_offline(&config)?;
        println!("Exit disabled; owned network state restored.");
        return Ok(());
    }
    let current = query_preferences(&config, ClientPreferenceRequest::Get {}).await?;
    let mut preferences = current.preferences.clone();
    match command {
        ClientCommand::Profiles(_) => return Err(CliError::invalid("invalid profile dispatch")),
        ClientCommand::Preferences { .. } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&current)
                    .map_err(|_| CliError::failure("preference formatting failed"))?
            );
            return Ok(());
        }
        ClientCommand::Set {
            accept_routes,
            dns,
            inbound,
            ..
        } => {
            if accept_routes.is_none() && dns.is_none() && inbound.is_none() {
                return Err(CliError::invalid(
                    "provide --accept-routes, --dns or --inbound",
                ));
            }
            if let Some(value) = accept_routes {
                preferences.accept_private_routes = value;
            }
            if let Some(value) = dns {
                preferences.accept_dns = value;
            }
            if let Some(value) = inbound {
                preferences.allow_inbound = value;
            }
        }
        ClientCommand::Exit(ClientExitGroup {
            command: ClientExitCommand::List { .. },
        }) => {
            if current.exits.is_empty() {
                println!(
                    "No approved exit is available; check configuration and provider approval."
                );
            }
            for exit in current.exits {
                println!(
                    "{}\t{}\tIPv4={} IPv6={} providers={}",
                    exit.name, exit.resource_id, exit.ipv4, exit.ipv6, exit.providers
                );
            }
            return Ok(());
        }
        ClientCommand::Exit(ClientExitGroup {
            command:
                ClientExitCommand::Select {
                    resource,
                    allow_local_lan,
                    ..
                },
        }) => {
            let matches: Vec<_> = current
                .exits
                .iter()
                .filter(|exit| exit.name == resource || exit.resource_id.to_string() == resource)
                .collect();
            let [selected] = matches.as_slice() else {
                return Err(CliError::invalid(
                    "exit name must match one approved resource; use client exit list",
                ));
            };
            preferences.exit_resource = Some(selected.resource_id);
            preferences.allow_local_lan = allow_local_lan;
            preferences.accept_dns = true;
        }
        ClientCommand::Exit(ClientExitGroup {
            command: ClientExitCommand::Off { .. },
        }) => {
            preferences.exit_resource = None;
            preferences.allow_local_lan = false;
        }
    }
    preferences.validate().map_err(|_| {
        CliError::invalid("exit mode requires DNS acceptance and valid preferences")
    })?;
    let view = query_preferences(
        &config,
        ClientPreferenceRequest::Set {
            change: PreferenceChange {
                request_id: Uuid::new_v4(),
                expected_version: current.version,
                preferences,
            },
        },
    )
    .await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&view)
            .map_err(|_| CliError::failure("preference formatting failed"))?
    );
    Ok(())
}
fn disable_exit_offline(config: &PeerConfig) -> Result<(), CliError> {
    let linux = config
        .linux
        .as_ref()
        .ok_or_else(|| CliError::invalid("offline exit recovery requires a Linux profile"))?;
    let result = (|| -> Result<(), peerward_platform::PlatformError> {
        let _lock = peerward_platform::LocalRuntimeLock::acquire(
            &config.management_socket.with_extension("runtime.lock"),
        )?;
        let mut guard = peerward_platform::ExitProtection::new(
            LinuxCommandBackend,
            linux.platform_state_file.with_extension("exit-guard.json"),
        );
        guard.restore()?;
        let mut store = peerward_platform::ClientPreferenceStore::load(
            &linux.platform_state_file.with_extension("preferences.json"),
            config.mesh_id,
            config.peer_id,
        )?;
        let mut preferences = store.saved().preferences.clone();
        preferences.exit_resource = None;
        preferences.allow_local_lan = false;
        store.commit(peerward_management::PreferenceChange {
            request_id: Uuid::new_v4(),
            expected_version: store.saved().version,
            preferences,
        })?;
        for path in [
            linux.platform_state_file.with_extension("exit-routes.json"),
            linux.platform_state_file.with_extension("dns.json"),
            linux.platform_state_file.with_extension("resources.json"),
            linux.platform_state_file.clone(),
        ] {
            StateCoordinator::with_journal(LinuxCommandBackend, path).recover()?;
        }
        guard.disarm()
    })();
    result.map_err(|error| {
        peer_runtime_error(
            "offline exit recovery failed; protection remains until owned cleanup succeeds",
            &error,
        )
    })
}
