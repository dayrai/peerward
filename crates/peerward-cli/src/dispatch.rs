/// Runs one parsed command and returns its specified exit code.
pub async fn execute(cli: Cli) -> u8 {
    match execute_inner(cli).await {
        Ok(()) => EXIT_SUCCESS,
        Err(error) => {
            eprintln!("{}", error.message);
            error.code
        }
    }
}

#[derive(Debug)]
struct CliError {
    code: u8,
    message: String,
}

impl CliError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_INVALID,
            message: message.into(),
        }
    }

    fn failure(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_FAILURE,
            message: message.into(),
        }
    }

    fn unavailable(feature: &str) -> Self {
        Self {
            code: EXIT_UNAVAILABLE,
            message: format!("{feature} is unavailable"),
        }
    }

    fn auth(message: impl Into<String>) -> Self {
        Self {
            code: EXIT_AUTH,
            message: message.into(),
        }
    }
}

async fn execute_inner(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Command::Identity(group) => execute_identity(group.command),
        Command::Client(group) => execute_client_preferences(group.command).await,
        Command::Config(ConfigGroup {
            command: ConfigCommand::Check { path, role, online },
        }) => check_config(&path, role, online).await,
        Command::Doctor(args) => doctor(&args).await,
        Command::Health => execute_local_query(ServiceRequest::Health).await,
        Command::Status => execute_local_query(ServiceRequest::Status).await,
        Command::Metrics => execute_local_query(ServiceRequest::Metrics).await,
        Command::Control(RunGroup {
            command: RunCommand::Run { config },
        }) => run_control(&config).await,
        Command::Relay(RunGroup {
            command: RunCommand::Run { config },
        }) => run_relay(&config).await,
        Command::Peer(PeerRunGroup {
            command: PeerRunCommand::Run { config, catalog },
        }) => Box::pin(run_selected_peer(config.as_deref(), catalog.as_deref())).await,
        Command::Peer(PeerRunGroup {
            command: PeerRunCommand::Install { profile },
        }) => peer_install::install(&profile),
        Command::Db(DbGroup {
            command: DbCommand::Migrate { database_url },
        }) => migrate_database(database_url.as_deref()).await,
        Command::Join(JoinGroup {
            command: JoinCommand::Prepare { output_dir },
        }) => prepare_join(&output_dir),
        Command::Join(JoinGroup {
            command:
                JoinCommand::Accept {
                    bundle,
                    bundle_file,
                    output_dir,
                },
        }) => {
            let invitation = read_join_invitation(bundle, bundle_file.as_deref())?;
            accept_join(&invitation, &output_dir).await
        }
        Command::Service(group) => execute_service(group.command).await,
        Command::Update(group) => execute_update(group.command).await,
        Command::Bootstrap(group) => execute_bootstrap(group.command).await,
    }
}
