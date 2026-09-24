/// Signed release updater group.
#[derive(Debug, Args)]
pub struct UpdateGroup {
    /// Update operation.
    #[command(subcommand)]
    pub command: UpdateCommand,
}

/// Signed release updater operations.
#[derive(Debug, Subcommand)]
pub enum UpdateCommand {
    /// Apply the explicitly enabled unattended-update configuration.
    RunConfig {
        /// Strict TOML configuration, normally `/etc/peerward/update.toml`.
        #[arg(long, default_value = "/etc/peerward/update.toml")]
        config: PathBuf,
    },
    /// Verify a manifest and print the selected binary without installing it.
    Check(UpdateSourceArgs),
    /// Download, verify, and atomically install the selected binary.
    Apply(UpdateApplyArgs),
    /// Verify the complete versioned intent and print a digest without changing installation state.
    Preview(UpdateApplyArgs),
    /// Read the last durable versioned role transaction; this is historical status.
    Status {
        #[arg(long)]
        installation_root: PathBuf,
        #[arg(long, value_enum)]
        role: UpdateRole,
    },
    /// Reconcile the recorded role transaction after an interrupted update.
    Recover {
        #[arg(long)]
        installation_root: PathBuf,
        #[arg(long, value_enum)]
        role: UpdateRole,
        /// Database reachability check for Control; prefer `PEERWARD_DATABASE_URL`.
        #[arg(long)]
        database_url: Option<String>,
    },
    /// Stage a signed installed binary and render a reviewable systemd drop-in.
    Register {
        #[command(flatten)]
        source: UpdateSourceArgs,
        #[arg(long)]
        installation_root: PathBuf,
        #[arg(long, value_enum)]
        role: UpdateRole,
        #[arg(long)]
        binary: PathBuf,
    },
    /// Restore the last binary retained by a successful update.
    Rollback {
        /// Installed executable, defaulting to the running executable.
        #[arg(long)]
        install_path: Option<PathBuf>,
        /// Versioned installation root used by role-aware updates.
        #[arg(long)]
        installation_root: Option<PathBuf>,
        /// Role-specific symlink to roll back.
        #[arg(long, value_enum)]
        role: Option<UpdateRole>,
    },
    /// Domain-separate and sign an exact release manifest for publication.
    SignManifest {
        /// Exact JSON manifest to sign.
        #[arg(long)]
        manifest: PathBuf,
        /// Hex Ed25519 seed readable only by its owner.
        #[arg(long)]
        private_key: PathBuf,
        /// New hexadecimal signature file.
        #[arg(long)]
        output: PathBuf,
    },
}

/// Inputs common to update checking and application.
#[derive(Debug, Clone, Args)]
pub struct UpdateSourceArgs {
    /// HTTPS URL or local path containing the exact JSON manifest.
    #[arg(long)]
    manifest: String,
    /// HTTPS URL or local path containing its hexadecimal Ed25519 signature.
    #[arg(long)]
    signature: String,
    /// Hex Ed25519 updater public key.
    #[arg(long)]
    public_key: PathBuf,
    /// Release channel.
    #[arg(long, value_enum, default_value = "stable")]
    channel: ReleaseChannel,
    /// Target platform, defaulting to the current build target.
    #[arg(long)]
    platform: Option<String>,
    /// Target architecture, defaulting to the current build target.
    #[arg(long)]
    architecture: Option<String>,
}

/// Update application inputs.
#[derive(Debug, Args)]
pub struct UpdateApplyArgs {
    /// Signed release selection.
    #[command(flatten)]
    source: UpdateSourceArgs,
    /// Require the unchanged digest returned by update preview before applying.
    #[arg(long)]
    preview_digest: Option<String>,
    /// Explicitly replace a recovery-required transaction with a newer signed release.
    #[arg(long)]
    repair: bool,
    /// Verified local artifact for offline installation; digest still comes from the signed manifest.
    #[arg(long)]
    artifact_file: Option<PathBuf>,
    /// Installed executable, defaulting to the running executable.
    #[arg(long)]
    install_path: Option<PathBuf>,
    /// Root containing immutable versions and role symlinks.
    #[arg(long)]
    installation_root: Option<PathBuf>,
    /// Role to restart and health-check after a versioned switch.
    #[arg(long, value_enum)]
    role: Option<UpdateRole>,
    /// Readiness URL; Peer uses `unix:///run/peerward/peer.sock`.
    #[arg(long)]
    health_url: Option<Url>,
    /// `PostgreSQL` URL checked before Control restarts; prefer `PEERWARD_DATABASE_URL`.
    #[arg(long)]
    database_url: Option<String>,
}

/// Independently switchable runtime role.
#[derive(Debug, Clone, Copy, ValueEnum, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateRole {
    /// Control API and publisher.
    Control,
    /// Relay data-plane process.
    Relay,
    /// Linux Peer daemon.
    Peer,
    /// Console proxy/web application.
    Console,
}

impl UpdateRole {
    const fn name(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Relay => "relay",
            Self::Peer => "peer",
            Self::Console => "console",
        }
    }
}

/// User-facing release channels.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ReleaseChannel {
    /// Production releases.
    Stable,
    /// Explicit canary rollout.
    Canary,
    /// Preview releases.
    Beta,
    /// Development releases.
    Nightly,
}

impl From<ReleaseChannel> for UpdateChannel {
    fn from(value: ReleaseChannel) -> Self {
        match value {
            ReleaseChannel::Stable => Self::Stable,
            ReleaseChannel::Canary => Self::Canary,
            ReleaseChannel::Beta => Self::Beta,
            ReleaseChannel::Nightly => Self::Nightly,
        }
    }
}

/// Doctor options.
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Optional role configuration.
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Private Control management base URL; defaults to `PEERWARD_CONTROL_URL`.
    #[arg(long)]
    pub control_url: Option<Url>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}
