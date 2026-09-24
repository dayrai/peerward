//! Exit blocking has a separate lifetime from ordinary network rollback.
use super::*;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

/// Set only on protected underlay sockets, never on application traffic.
pub const EXIT_UNDERLAY_MARK: u32 = 0x5057_0005;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitProtectionIntent {
    pub interface: String,
    pub exit_resource: Uuid,
    /// Explicitly selected, verified directly-connected networks; empty by default.
    pub local_lan: Vec<IpNet>,
}
impl ExitProtectionIntent {
    pub(crate) fn validate(&self) -> Result<(), PlatformError> {
        if !safe_name(&self.interface)
            || self.exit_resource.get_version_num() != 4
            || self.local_lan.len() > 128
            || self.local_lan.iter().any(|prefix| {
                prefix.prefix_len() == 0
                    || prefix.network() != prefix.addr()
                    || prefix.addr().is_unspecified()
                    || prefix.addr().is_loopback()
                    || prefix.addr().is_multicast()
            })
        {
            return Err(PlatformError::InvalidName);
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExitJournal {
    schema_version: u32,
    guard_id: Uuid,
    intent: ExitProtectionIntent,
}

/// No Drop cleanup: a crash, transport failure, or ordinary daemon shutdown must
/// leave the guard in place. The caller removes capture routing BEFORE explicitly
/// disarming, and restores this guard BEFORE restoring any normal network journal.
pub struct ExitProtection<B> {
    backend: B,
    path: PathBuf,
}
impl<B: CommandBackend> ExitProtection<B> {
    pub fn new(backend: B, path: impl Into<PathBuf>) -> Self {
        Self {
            backend,
            path: path.into(),
        }
    }

    fn load(&self) -> Result<Option<ExitJournal>, PlatformError> {
        let file = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.len() > 65_536
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != rustix::process::geteuid().as_raw()
        {
            return Err(PlatformError::OwnershipConflict);
        }
        let mut bytes = Vec::new();
        file.take(65_537).read_to_end(&mut bytes)?;
        if bytes.len() > 65_536 {
            return Err(PlatformError::OwnershipConflict);
        }
        let saved: ExitJournal = serde_json::from_slice(&bytes)?;
        if saved.schema_version != 4 || saved.guard_id.get_version_num() != 4 {
            return Err(PlatformError::OwnershipConflict);
        }
        saved.intent.validate()?;
        Ok(Some(saved))
    }

    /// Reapply the saved blocking intent, including when the TUN no longer exists.
    pub fn saved_intent(&self) -> Result<Option<ExitProtectionIntent>, PlatformError> {
        Ok(self.load()?.map(|saved| saved.intent))
    }

    /// Reapply the saved blocking intent, including when the TUN no longer exists.
    pub fn restore(&mut self) -> Result<Option<ExitProtectionIntent>, PlatformError> {
        let Some(saved) = self.load()? else {
            return Ok(None);
        };
        self.verify_table(&saved.intent.interface, Some(saved.guard_id))?;
        self.install(&saved)?;
        Ok(Some(saved.intent))
    }

    /// Persist before applying; a failed mutation must retain recoverable blocking intent.
    pub fn arm(&mut self, intent: ExitProtectionIntent) -> Result<(), PlatformError> {
        intent.validate()?;
        let previous = self.load()?;
        if previous
            .as_ref()
            .is_some_and(|saved| saved.intent.interface != intent.interface)
        {
            return Err(PlatformError::OwnershipConflict);
        }
        self.verify_table(
            &intent.interface,
            previous.as_ref().map(|saved| saved.guard_id),
        )?;
        let saved = ExitJournal {
            schema_version: 4,
            guard_id: previous.map_or_else(Uuid::new_v4, |saved| saved.guard_id),
            intent,
        };
        AtomicStateStore::new(&self.path).save(&saved)?;
        self.install(&saved)
    }

    /// Only an explicit exit-mode disable may call this; never error cleanup.
    pub fn disarm(&mut self) -> Result<(), PlatformError> {
        let Some(saved) = self.load()? else {
            return Ok(());
        };
        self.verify_table(&saved.intent.interface, Some(saved.guard_id))?;
        self.backend.run(
            &CommandSpec::new("nft", ["--file", "-"]).with_input(format!(
                "destroy table inet {}\n",
                table_name(&saved.intent.interface)
            )),
        )?;
        AtomicStateStore::new(&self.path).remove()
    }

    fn install(&mut self, saved: &ExitJournal) -> Result<(), PlatformError> {
        self.backend
            .run(&CommandSpec::new("nft", ["--file", "-"]).with_input(guard_rules(saved)))?;
        Ok(())
    }

    fn verify_table(&mut self, interface: &str, owner: Option<Uuid>) -> Result<(), PlatformError> {
        let output = self
            .backend
            .run(&CommandSpec::new("nft", ["--json", "list", "tables"]))?;
        if output.len() > 1_048_576 {
            return Err(PlatformError::OwnershipConflict);
        }
        let document: serde_json::Value = serde_json::from_str(&output)?;
        let tables = document["nftables"]
            .as_array()
            .ok_or(PlatformError::OwnershipConflict)?;
        for entry in tables {
            let table = &entry["table"];
            if table["family"] == "inet" && table["name"] == table_name(interface) {
                let owner = owner.ok_or(PlatformError::OwnershipConflict)?;
                let output = self.backend.run(&CommandSpec::new(
                    "nft",
                    ["--json", "list", "table", "inet", &table_name(interface)],
                ))?;
                if output.len() > 65_536 {
                    return Err(PlatformError::OwnershipConflict);
                }
                let detail: serde_json::Value = serde_json::from_str(&output)?;
                let entries = detail["nftables"]
                    .as_array()
                    .ok_or(PlatformError::OwnershipConflict)?;
                if !entries.iter().any(|entry| {
                    entry["table"]["family"] == "inet"
                        && entry["table"]["name"] == table_name(interface)
                        && entry["table"]["comment"] == format!("peerward-exit:{owner}")
                }) {
                    return Err(PlatformError::OwnershipConflict);
                }
            }
        }
        Ok(())
    }
}
fn table_name(interface: &str) -> String {
    format!("pw_exit_{}", interface.replace('-', "_"))
}
fn guard_rules(saved: &ExitJournal) -> String {
    use std::fmt::Write as _;
    let intent = &saved.intent;
    let table = table_name(&intent.interface);
    let mut rules = format!(
        "destroy table inet {table}\nadd table inet {table} {{ comment \"peerward-exit:{}\"; }}\nadd chain inet {table} egress {{ type filter hook output priority -50; policy accept; }}\n",
        saved.guard_id
    );
    writeln!(&mut rules,"add rule inet {table} egress oifname \"lo\" accept\nadd rule inet {table} egress meta mark {EXIT_UNDERLAY_MARK} accept\nadd rule inet {table} egress oifname \"{}\" accept",intent.interface).expect("String write");
    // Link configuration remains possible after roaming; these do not carry ordinary Internet traffic.
    writeln!(&mut rules,"add rule inet {table} egress ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept\nadd rule inet {table} egress ip6 daddr ff02::1:2 udp sport 546 udp dport 547 accept\nadd rule inet {table} egress ip6 hoplimit 255 ip6 daddr {{ fe80::/10, ff02::/16 }} icmpv6 type {{ nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert }} accept").expect("String write");
    for prefix in &intent.local_lan {
        let family = if prefix.addr().is_ipv4() { "ip" } else { "ip6" };
        writeln!(
            &mut rules,
            "add rule inet {table} egress {family} daddr {prefix} accept"
        )
        .expect("String write");
    }
    writeln!(&mut rules, "add rule inet {table} egress counter drop").expect("String write");
    rules
}

#[cfg(test)]
#[path = "exit_protection_tests.rs"]
mod tests;
