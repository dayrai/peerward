/// Unified command-line entry point.
#[derive(Debug, Parser)]
#[command(name = "peerward", version, about)]
pub struct Cli {
    /// Operation group.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level operation groups.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run the control service.
    Control(RunGroup),
    /// Run a relay.
    Relay(RunGroup),
    /// Run a peer.
    Peer(PeerRunGroup),
    /// Manage local routing, DNS, inbound traffic and Internet exit preferences.
    Client(ClientGroup),
    /// Database operations.
    Db(DbGroup),
    /// Root, authority, and Noise identity operations.
    Identity(IdentityGroup),
    /// Accept a join bundle.
    Join(JoinGroup),
    /// Publish and manage local services.
    Service(ServiceGroup),
    /// Configuration validation.
    Config(ConfigGroup),
    /// Diagnose this installation.
    Doctor(DoctorArgs),
    /// Read the local Peer health view over its protected socket.
    Health,
    /// Read the local peer daemon status over its protected socket.
    Status,
    /// Read local peer daemon counters over its protected socket.
    Metrics,
    /// Verify, select, install, or roll back signed releases.
    Update(UpdateGroup),
    /// Generate and initialize a secure first-installation bundle.
    Bootstrap(BootstrapGroup),
}

/// First-installation operations.
#[derive(Debug, Args)]
pub struct BootstrapGroup {
    /// Bootstrap operation.
    #[command(subcommand)]
    pub command: BootstrapCommand,
}

/// First-installation commands.
#[derive(Debug, Subcommand)]
pub enum BootstrapCommand {
    /// Import a staged online Authority into a running dynamic Control installation.
    AuthorityImport {
        #[arg(long)]
        dynamic_config: PathBuf,
        #[arg(long)]
        mesh_id: MeshId,
        #[arg(long)]
        authority_id: Uuid,
        #[arg(long)]
        private_key: PathBuf,
        #[arg(long)]
        certificate: PathBuf,
    },
    /// Decrypt and verify a Mesh root recovery package on an offline machine.
    RecoveryOpen {
        #[arg(long)]
        package: PathBuf,
        #[arg(long)]
        mesh_id: MeshId,
        #[arg(long)]
        root_public: String,
        #[arg(long)]
        recovery_key: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Certify a new online Authority using an offline recovered root.
    CertifyAuthority {
        #[arg(long)]
        root_key: PathBuf,
        #[arg(long)]
        mesh_id: MeshId,
        #[arg(long)]
        authority_public: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 365)]
        validity_days: u32,
    },
    /// Generate new Root, Authority, distribution, Relay, and deployment files.
    Generate {
        /// New destination directory; it must not already exist.
        #[arg(long)]
        output_dir: PathBuf,
        /// Mesh identity and configuration.
        #[command(flatten)]
        mesh: BootstrapMeshOptions,
        /// Relay endpoint advertised to enrolled Peers.
        #[arg(long, default_value = "tcp://127.0.0.1:7777")]
        peer_endpoint: Vec<String>,
        /// Relay-to-Relay endpoint advertised in the signed directory.
        #[arg(long, default_value = "tcp://127.0.0.1:7778")]
        backbone_endpoint: Vec<String>,
    },
    /// Atomically install an already generated, signature-verified manifest.
    Initialize {
        /// `PostgreSQL` URL, falling back to `PEERWARD_DATABASE_URL`.
        #[arg(long)]
        database_url: Option<String>,
        /// Generated non-secret initialization manifest.
        #[arg(long)]
        manifest: PathBuf,
        /// Install identities into an existing empty Mesh while preserving its settings.
        #[arg(long)]
        complete_empty_mesh: bool,
    },
}

/// A role whose only subcommand is `run`.
#[derive(Debug, Args)]
pub struct RunGroup {
    /// Role command.
    #[command(subcommand)]
    pub command: RunCommand,
}

/// Runtime command.
#[derive(Debug, Subcommand)]
pub enum RunCommand {
    /// Start the selected role.
    Run {
        /// TOML configuration path.
        #[arg(long)]
        config: PathBuf,
    },
}

/// Database group.
#[derive(Debug, Args)]
pub struct DbGroup {
    /// Database command.
    #[command(subcommand)]
    pub command: DbCommand,
}

/// Database commands.
#[derive(Debug, Subcommand)]
pub enum DbCommand {
    /// Apply all pending migrations.
    Migrate {
        /// `PostgreSQL` connection URL, falling back to `PEERWARD_DATABASE_URL`.
        #[arg(long)]
        database_url: Option<String>,
    },
}

/// Identity group.
#[derive(Debug, Args)]
pub struct IdentityGroup {
    /// Identity kind.
    #[command(subcommand)]
    pub command: IdentityCommand,
}

/// Identity kinds.
#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    /// Verify a Root-anchored Authority, credential, and distribution chain.
    Verify(IdentityVerifyArgs),
    /// Offline root operations.
    Root(RootGroup),
    /// Online authority operations.
    Authority(AuthorityGroup),
    /// X25519 static Noise operations.
    Noise(NoiseGroup),
}

/// Rooted identity material to verify without exposing any private key.
#[derive(Debug, Args)]
pub struct IdentityVerifyArgs {
    /// Hex-encoded offline Root public key.
    #[arg(long)]
    pub root_public: PathBuf,
    /// Expected Mesh `UUIDv4`.
    #[arg(long)]
    pub mesh_id: Uuid,
    /// Root-signed Authority certificate; repeat during overlap.
    #[arg(long = "authority-certificate", required = true)]
    pub authority_certificates: Vec<PathBuf>,
    /// Optional Authority-signed Peer or Relay credential; repeat as needed.
    #[arg(long = "credential")]
    pub credentials: Vec<PathBuf>,
    /// Optional Authority-signed distribution certificate.
    #[arg(long)]
    pub distribution_certificate: Option<PathBuf>,
}

/// Offline-root group.
#[derive(Debug, Args)]
pub struct RootGroup {
    /// Root command.
    #[command(subcommand)]
    pub command: RootCommand,
}

/// Offline-root commands.
#[derive(Debug, Subcommand)]
pub enum RootCommand {
    /// Generate an Ed25519 root keypair.
    Generate(KeyOutputArgs),
}

/// Noise-key group.
#[derive(Debug, Args)]
pub struct NoiseGroup {
    /// Noise command.
    #[command(subcommand)]
    pub command: NoiseCommand,
}

/// Noise-key commands.
#[derive(Debug, Subcommand)]
pub enum NoiseCommand {
    /// Generate an X25519 static keypair.
    Generate(KeyOutputArgs),
}

/// Authority group.
#[derive(Debug, Args)]
pub struct AuthorityGroup {
    /// Authority command.
    #[command(subcommand)]
    pub command: AuthorityCommand,
}

/// Authority commands.
#[derive(Debug, Subcommand)]
pub enum AuthorityCommand {
    /// Generate an online Ed25519 Authority keypair before offline certification.
    Generate(KeyOutputArgs),
    /// Issue a root-signed authority certificate.
    Issue(AuthorityIssueArgs),
}

/// Private and public key output paths.
#[derive(Debug, Args)]
pub struct KeyOutputArgs {
    /// Private-key destination.
    #[arg(long)]
    pub private: PathBuf,
    /// Public-key destination.
    #[arg(long)]
    pub public: PathBuf,
}

/// Authority issuance inputs.
#[derive(Debug, Args)]
pub struct AuthorityIssueArgs {
    /// Hex-encoded root private-key file.
    #[arg(long)]
    pub root_private: PathBuf,
    /// Mesh `UUIDv4`.
    #[arg(long)]
    pub mesh_id: Uuid,
    /// Hex-encoded authority public-key file.
    #[arg(long)]
    pub authority_public: PathBuf,
    /// Certificate destination.
    #[arg(long)]
    pub output: PathBuf,
}

/// Join group.
#[derive(Debug, Args)]
pub struct JoinGroup {
    /// Join command.
    #[command(subcommand)]
    pub command: JoinCommand,
}

/// Join commands.
#[derive(Debug, Subcommand)]
pub enum JoinCommand {
    /// Prepare and retain device keys, printing the fingerprint for trusted prebinding.
    Prepare {
        /// Use this same destination when accepting the invitation.
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Claim and store a join bundle.
    Accept {
        /// `peerward://join` bundle; prefer --bundle-file to keep it out of process arguments.
        #[arg(
            required_unless_present = "bundle_file",
            conflicts_with = "bundle_file"
        )]
        bundle: Option<String>,
        /// Private invitation file, or '-' to read the invitation from standard input.
        #[arg(long, conflicts_with = "bundle")]
        bundle_file: Option<PathBuf>,
        /// Profile destination directory.
        #[arg(long)]
        output_dir: PathBuf,
    },
}

/// Service group.
#[derive(Debug, Args)]
pub struct ServiceGroup {
    /// Service command.
    #[command(subcommand)]
    pub command: ServiceCommand,
}

/// Service commands.
#[derive(Debug, Subcommand)]
pub enum ServiceCommand {
    /// Publish a loopback service.
    Publish {
        /// Mesh-visible port.
        #[arg(long)]
        listen_port: u16,
        /// Loopback-only target address.
        #[arg(long)]
        target: std::net::SocketAddr,
        /// Transport protocol set.
        #[arg(long, default_value = "tcp")]
        protocol: ServiceProtocol,
        /// Mesh DNS alias.
        #[arg(long = "name")]
        name: Option<String>,
    },
    /// List published services.
    List,
    /// Remove a published service.
    Remove {
        /// Service `UUIDv4`.
        service_id: Uuid,
    },
}

/// CLI service protocols.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ServiceProtocol {
    /// TCP service.
    Tcp,
    /// UDP service.
    Udp,
    /// Atomic TCP and UDP publication.
    Both,
}

/// Configuration group.
#[derive(Debug, Args)]
pub struct ConfigGroup {
    /// Configuration command.
    #[command(subcommand)]
    pub command: ConfigCommand,
}

/// Configuration commands.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Validate a role configuration.
    Check {
        /// Expected role.
        #[arg(long)]
        role: ConfigRole,
        /// Test online dependencies as well.
        #[arg(long)]
        online: bool,
        /// TOML configuration file.
        path: PathBuf,
    },
}

/// Configured daemon role.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ConfigRole {
    /// Control service.
    Control,
    /// Relay.
    Relay,
    /// Peer.
    Peer,
}

include!("update_arguments.rs");
