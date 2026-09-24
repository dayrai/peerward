//! Transactional platform changes and atomic local-state persistence.

use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

use async_trait::async_trait;
use ipnet::IpNet;
use peerward_types::PeerId;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, UdpSocket},
    sync::watch,
};
use uuid::Uuid;

const MAX_KERNEL_TABLE_BYTES: u64 = 4 * 1024 * 1024;

fn read_regular_bounded(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(std::io::Error::other(
            "file exceeds its bounded regular-file contract",
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other("file grew beyond its bound"));
    }
    Ok(bytes)
}

fn read_text_bounded(path: &Path, limit: u64) -> std::io::Result<String> {
    String::from_utf8(read_regular_bounded(path, limit)?)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))
}

/// Platform command or persistence failure.
#[derive(Debug, Error)]
pub enum PlatformError {
    /// Interface, connection, or table name was unsafe.
    #[error("invalid platform identifier")]
    InvalidName,
    /// A command could not be started or returned failure.
    #[error("platform command failed: {0}")]
    Command(String),
    /// A link disappeared, for example when a non-persistent TUN was closed.
    #[error("interface {0} does not exist")]
    InterfaceMissing(String),
    /// State serialization or parsing failed.
    #[error("local state encoding failed")]
    Encoding(#[from] serde_json::Error),
    /// Atomic file operation failed.
    #[error("local state I/O failed")]
    Io(#[from] std::io::Error),
    /// One or more rollback commands failed after the initiating error.
    #[error("platform rollback was incomplete")]
    Rollback,
    /// A resource changed after Peerward installed it and was deliberately preserved.
    #[error("platform resource ownership changed outside Peerward")]
    OwnershipConflict,
}

/// One executable and its already separated arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    /// Program found through the service's controlled PATH.
    pub program: String,
    /// Individual arguments; never interpreted by a shell.
    pub arguments: Vec<String>,
    /// Optional standard input, used for one atomic nftables transaction.
    pub input: Option<String>,
}

impl CommandSpec {
    fn new(
        program: impl Into<String>,
        arguments: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            arguments: arguments.into_iter().map(Into::into).collect(),
            input: None,
        }
    }

    fn with_input(mut self, input: String) -> Self {
        self.input = Some(input);
        self
    }
}

/// Platform-neutral layer-3 packet device consumed by the Peer runtime.
pub trait TunnelDevice: Send {
    /// Read half returned to the packet pump.
    type Reader: AsyncRead + Unpin + Send + 'static;
    /// Write half returned to the packet pump.
    type Writer: AsyncWrite + Unpin + Send + 'static;

    /// Configured device MTU.
    fn mtu(&self) -> u16;
    /// Transfers ownership of the packet streams to the runtime.
    fn split(self) -> (Self::Reader, Self::Writer);
}

include!("tunnel.rs");

/// Transactional host-network lifecycle shared by Linux and future desktop adapters.
pub trait HostNetworkTransaction {
    /// Platform-specific validated intent.
    type Intent;

    /// Recovers an interrupted prior transaction before any new mutation.
    fn recover(&mut self) -> Result<(), PlatformError>;
    /// Applies device, address, and route preparation without redirecting DNS.
    fn prepare(&mut self, intent: &Self::Intent) -> Result<(), PlatformError>;
    /// Activates firewall and host DNS after the local DNS sockets are bound.
    fn activate_dns(&mut self, intent: &Self::Intent) -> Result<(), PlatformError>;
    /// Marks the prepared transaction as live.
    fn commit(&mut self) -> Result<(), PlatformError>;
    /// Restores every Peerward-owned host resource in reverse order.
    fn rollback(&mut self) -> Result<(), PlatformError>;
}

include!("underlay.rs");
mod underlay_addresses;
pub use underlay_addresses::{
    UnderlayAddress, linux_gateways, linux_ipv4_gateways, linux_underlay_addresses,
};

/// Injectable command executor used by real Linux and deterministic tests.
pub trait CommandBackend {
    /// Executes one program without a shell and returns trimmed standard output.
    fn run(&mut self, command: &CommandSpec) -> Result<String, PlatformError>;
}

/// Production command executor.
#[derive(Debug, Default)]
pub struct LinuxCommandBackend;

impl CommandBackend for LinuxCommandBackend {
    fn run(&mut self, command: &CommandSpec) -> Result<String, PlatformError> {
        if command.program == "peerward-resolv-conf" {
            return run_resolv_conf_mutation(command);
        }
        if command.program == "peerward-forwarding" {
            return resource_network::run_forwarding(command);
        }
        if command.program == "peerward-ipv6-ra" {
            return resource_network::run_ipv6_ra(command);
        }
        if command.program == "peerward-exit-routing" {
            return exit_routes::run(command);
        }
        if command.program == "ip" {
            return native_netlink::run(&command.arguments);
        }
        if command.program == "resolvectl" || command.program == "peerward-resolved" {
            return resolved_dbus::run(&command.arguments, command.input.as_deref());
        }
        if command.program == "nmcli" || command.program == "peerward-network-manager" {
            return network_manager_dbus::run(&command.arguments, command.input.as_deref());
        }
        let mut child = Command::new(&command.program)
            .args(&command.arguments)
            .stdin(if command.input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(input) = &command.input {
            child
                .stdin
                .take()
                .ok_or_else(|| PlatformError::Command("command stdin is unavailable".into()))?
                .write_all(input.as_bytes())?;
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Err(PlatformError::Command(format!(
                "{} exited with {}: {message}",
                command.program, output.status
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }
}

/// Split DNS integration selected for the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsBackend {
    /// Probe managed resolvers first, then openresolv and a direct resolv.conf fallback.
    Auto {
        /// Optional `NetworkManager` profile considered during probing.
        connection: Option<String>,
        /// Last-resort resolver file.
        resolv_conf: PathBuf,
    },
    /// Per-link `systemd-resolved` configuration.
    SystemdResolved,
    /// Existing `NetworkManager` connection profile.
    NetworkManager {
        /// Profile identifier passed as one argument to `nmcli`.
        connection: String,
    },
    /// Register the local resolver through openresolv.
    OpenResolv,
    /// Transactionally replace nameserver entries in one resolver file.
    ResolvConf {
        /// Resolver file, normally `/etc/resolv.conf`.
        path: PathBuf,
    },
}

/// Validated nftables allow item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NftAllow {
    /// Destination prefix.
    pub destination: IpNet,
    /// Optional TCP or UDP protocol.
    pub protocol: Option<&'static str>,
    /// Optional destination port.
    pub destination_port: Option<u16>,
}

/// Complete Linux peer network intent.
#[derive(Debug, Clone)]
pub struct LinuxNetworkConfig {
    /// TUN interface name.
    pub interface: String,
    /// Interface descriptor is already owned by the in-process or inherited-fd backend.
    pub interface_precreated: bool,
    /// Mesh address and prefix assigned to the TUN.
    pub address: IpNet,
    /// Optional exact assignment in the opposite address family.
    pub secondary_address: Option<IpNet>,
    /// Peer interface MTU.
    pub mtu: u16,
    /// Mesh routes installed through the TUN.
    pub routes: Vec<IpNet>,
    /// Mesh DNS suffix without a leading routing marker.
    pub dns_suffix: String,
    /// Mesh DNS gateway.
    pub dns_server: IpAddr,
    /// Host DNS mechanism.
    pub dns_backend: DnsBackend,
    /// Typed nftables destination rules.
    pub nft_allow: Vec<NftAllow>,
}

#[derive(Debug, Clone)]
struct Operation {
    apply: CommandSpec,
    rollback: CommandSpec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TransactionPhase {
    Prepared,
    Active,
    RollingBack,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkJournal {
    schema_version: u32,
    phase: TransactionPhase,
    rollback: Vec<CommandSpec>,
}

/// Applies a plan atomically and remembers exact reverse operations for shutdown.
pub struct StateCoordinator<B> {
    backend: B,
    applied: Vec<CommandSpec>,
    journal: Option<AtomicStateStore>,
    phase: Option<TransactionPhase>,
}

impl<B: CommandBackend> StateCoordinator<B> {
    /// Creates an idle coordinator.
    pub const fn new(backend: B) -> Self {
        Self {
            backend,
            applied: Vec::new(),
            journal: None,
            phase: None,
        }
    }

    /// Creates a coordinator whose exact rollback plan survives process termination.
    pub fn with_journal(backend: B, path: impl Into<PathBuf>) -> Self {
        Self {
            backend,
            applied: Vec::new(),
            journal: Some(AtomicStateStore::new(path)),
            phase: None,
        }
    }

    /// Restores a transaction left by an interrupted prior process.
    pub fn recover(&mut self) -> Result<(), PlatformError> {
        let Some(journal) = &self.journal else {
            return Ok(());
        };
        if !journal.exists() {
            return Ok(());
        }
        let saved: NetworkJournal = journal.load()?;
        if saved.schema_version != 1
            || saved.rollback.len() > 256
            || saved
                .rollback
                .iter()
                .any(|command| !safe_journal_command(command))
        {
            return Err(PlatformError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid network journal",
            )));
        }
        self.applied = saved.rollback;
        self.phase = Some(TransactionPhase::RollingBack);
        self.rollback_all()
    }

    /// Applies only TUN, addresses, and routes; host DNS remains untouched.
    pub fn prepare(&mut self, config: &LinuxNetworkConfig) -> Result<(), PlatformError> {
        validate_config(config)?;
        if !self.applied.is_empty() {
            self.shutdown()?;
        }
        self.phase = Some(TransactionPhase::Prepared);
        self.apply_operations(build_prepare_operations(config))
    }

    /// Activates nftables and host DNS after the DNS listener is ready to bind.
    pub fn activate_dns(&mut self, config: &LinuxNetworkConfig) -> Result<(), PlatformError> {
        if self.phase != Some(TransactionPhase::Prepared) {
            return Err(PlatformError::Command(
                "platform transaction was not prepared".into(),
            ));
        }
        let table = nft_table(&config.interface);
        let mut operations = nft_operations(config, &table);
        operations.extend(dns_operations(&mut self.backend, config)?);
        self.apply_operations(operations)
    }

    /// Linux managed clients own DNS in a separate preference-controlled journal.
    pub fn activate_firewall(&mut self, config: &LinuxNetworkConfig) -> Result<(), PlatformError> {
        if self.phase != Some(TransactionPhase::Prepared) {
            return Err(PlatformError::InvalidName);
        }
        self.apply_operations(nft_operations(config, &nft_table(&config.interface)))
    }

    /// Marks a prepared network transaction as active in the durable journal.
    pub fn commit(&mut self) -> Result<(), PlatformError> {
        if self.phase != Some(TransactionPhase::Prepared) {
            return Err(PlatformError::Command(
                "platform transaction was not prepared".into(),
            ));
        }
        self.phase = Some(TransactionPhase::Active);
        self.persist_journal()
    }

    /// Applies TUN, addresses, routes, nftables, and split DNS as one rollback domain.
    pub fn apply(&mut self, config: &LinuxNetworkConfig) -> Result<(), PlatformError> {
        self.prepare(config)?;
        self.activate_dns(config)?;
        self.commit()
    }

    fn apply_operations(&mut self, operations: Vec<Operation>) -> Result<(), PlatformError> {
        self.apply_operations_journaled(operations, false)
    }

    fn apply_operations_journaled(
        &mut self,
        operations: Vec<Operation>,
        before_mutation: bool,
    ) -> Result<(), PlatformError> {
        for operation in operations {
            let prejournaled = before_mutation
                || matches!(
                    operation.apply.program.as_str(),
                    "peerward-resolv-conf" | "peerward-resolved" | "peerward-network-manager"
                );
            if prejournaled {
                self.applied.push(operation.rollback.clone());
                if let Err(error) = self.persist_journal() {
                    self.applied.pop();
                    return Err(error);
                }
            }
            if let Err(original) = self.backend.run(&operation.apply) {
                tracing::error!(program = %operation.apply.program, arguments = ?operation.apply.arguments, error = ?original, "Platform operation failed");
                if self.rollback_all().is_err() {
                    return Err(PlatformError::Rollback);
                }
                return Err(original);
            }
            if !prejournaled {
                self.applied.push(operation.rollback);
                if let Err(error) = self.persist_journal() {
                    let _ = self.rollback_all();
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    /// Reverses every successful change in strict reverse order.
    pub fn shutdown(&mut self) -> Result<(), PlatformError> {
        self.rollback_all()
    }

    /// Returns the backend after shutdown, useful for audit assertions.
    pub fn into_backend(mut self) -> Result<B, PlatformError> {
        self.shutdown()?;
        Ok(self.backend)
    }

    fn rollback_all(&mut self) -> Result<(), PlatformError> {
        self.phase = Some(TransactionPhase::RollingBack);
        let mut failed = false;
        let mut ownership_conflict = false;
        for index in (0..self.applied.len()).rev() {
            let command = self.applied[index].clone();
            match self.backend.run(&command) {
                // Closing a non-persistent TUN also removes its addresses, routes,
                // and resolved link state. These resources are already cleaned up.
                Ok(_) | Err(PlatformError::InterfaceMissing(_)) => {
                    self.applied.remove(index);
                    if let Err(error) = self.persist_journal() {
                        tracing::error!(error = %error, "Could not persist network rollback progress");
                        failed = true;
                    }
                }
                Err(PlatformError::OwnershipConflict) => {
                    tracing::error!(program = %command.program, arguments = ?command.arguments, "Platform rollback preserved a resource changed outside Peerward");
                    ownership_conflict = true;
                }
                Err(error) => {
                    tracing::error!(program = %command.program, arguments = ?command.arguments, error = ?error, "Platform rollback operation failed");
                    failed = true;
                }
            }
        }
        if self.applied.is_empty() {
            self.phase = None;
            if let Some(journal) = &self.journal {
                journal.remove()?;
            }
        } else {
            self.persist_journal()?;
        }
        if ownership_conflict {
            Err(PlatformError::OwnershipConflict)
        } else if failed {
            Err(PlatformError::Rollback)
        } else {
            Ok(())
        }
    }

    fn persist_journal(&self) -> Result<(), PlatformError> {
        let Some(journal) = &self.journal else {
            return Ok(());
        };
        if self.applied.is_empty() {
            return Ok(());
        }
        journal.save(&NetworkJournal {
            schema_version: 1,
            phase: self.phase.unwrap_or(TransactionPhase::Prepared),
            rollback: self.applied.clone(),
        })
    }
}

impl<B: CommandBackend> HostNetworkTransaction for StateCoordinator<B> {
    type Intent = LinuxNetworkConfig;

    fn recover(&mut self) -> Result<(), PlatformError> {
        Self::recover(self)
    }

    fn prepare(&mut self, intent: &Self::Intent) -> Result<(), PlatformError> {
        Self::prepare(self, intent)
    }

    fn activate_dns(&mut self, intent: &Self::Intent) -> Result<(), PlatformError> {
        Self::activate_dns(self, intent)
    }

    fn commit(&mut self) -> Result<(), PlatformError> {
        Self::commit(self)
    }

    fn rollback(&mut self) -> Result<(), PlatformError> {
        self.shutdown()
    }
}

include!("linux_operations.rs");
const fn operation(apply: CommandSpec, rollback: CommandSpec) -> Operation {
    Operation { apply, rollback }
}

fn nft_table(interface: &str) -> String {
    format!("peerward_{}", interface.replace('-', "_"))
}

fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn safe_profile(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.contains(['\n', '\r', '\0'])
}

fn safe_resolver_path(path: &Path) -> bool {
    path.is_absolute() && path.as_os_str().len() <= 4_096 && !path.to_string_lossy().contains('\0')
}

fn safe_journal_command(command: &CommandSpec) -> bool {
    matches!(
        command.program.as_str(),
        "ip" | "nft"
            | "resolvectl"
            | "nmcli"
            | "resolvconf"
            | "peerward-resolv-conf"
            | "peerward-resolved"
            | "peerward-network-manager"
            | "peerward-forwarding"
            | "peerward-ipv6-ra"
            | "peerward-exit-routing"
    ) && command.arguments.len() <= 32
        && command
            .arguments
            .iter()
            .all(|argument| argument.len() <= 4_096 && !argument.contains('\0'))
        && command
            .input
            .as_ref()
            .is_none_or(|input| input.len() <= 131_072)
}

include!("atomic_state.rs");
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

mod managed_dns;
mod native_netlink;
mod resource_network;
pub use managed_dns::LinuxDnsIntent;
pub use resource_network::{GatewayForward, HostRoute, ResourceNetworkIntent};
mod exit_protection;
mod resource_routes;
pub use exit_protection::{EXIT_UNDERLAY_MARK, ExitProtection, ExitProtectionIntent};
mod client_preferences;
mod exit_routes;
pub use client_preferences::{ClientPreferenceStore, LocalRuntimeLock, SavedClientPreferences};
mod exit_routes_native;
pub use exit_routes::ExitRoutingIntent;
pub use resource_routes::linux_resource_routes;
mod network_manager_dbus;
mod resolved_dbus;
