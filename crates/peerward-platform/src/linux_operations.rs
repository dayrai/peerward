fn validate_config(config: &LinuxNetworkConfig) -> Result<(), PlatformError> {
    if peerward_management::validate_assignments(
        config.address,
        config.secondary_address,
        &config.routes,
    )
    .is_err()
        || !safe_name(&config.interface)
        || config.mtu < 576
        || config.mtu > 9_000
        || config.dns_suffix.is_empty()
        || config.dns_suffix.starts_with('.')
        || config.dns_suffix.contains(char::is_whitespace)
        || config.address.addr().is_ipv4() != config.dns_server.is_ipv4()
    {
        return Err(PlatformError::InvalidName);
    }
    match &config.dns_backend {
        DnsBackend::NetworkManager { connection } if !safe_profile(connection) => {
            return Err(PlatformError::InvalidName);
        }
        DnsBackend::Auto {
            connection,
            resolv_conf,
        } if (connection
            .as_ref()
            .is_some_and(|value| !safe_profile(value))
            || !safe_resolver_path(resolv_conf)) =>
        {
            return Err(PlatformError::InvalidName);
        }
        DnsBackend::ResolvConf { path } if !safe_resolver_path(path) => {
            return Err(PlatformError::InvalidName);
        }
        _ => {}
    }
    if config.nft_allow.iter().any(|rule| {
        rule.protocol
            .is_some_and(|protocol| !matches!(protocol, "tcp" | "udp"))
            || rule.destination_port == Some(0)
    }) {
        return Err(PlatformError::InvalidName);
    }
    if !config
        .routes
        .iter()
        .any(|route| route.contains(&config.dns_server))
    {
        return Err(PlatformError::InvalidName);
    }
    Ok(())
}

fn build_prepare_operations(config: &LinuxNetworkConfig) -> Vec<Operation> {
    let interface = &config.interface;
    let mut operations = Vec::new();
    if !config.interface_precreated {
        operations.push(operation(
            CommandSpec::new("ip", ["tuntap", "add", "dev", interface, "mode", "tun"]),
            CommandSpec::new("ip", ["tuntap", "del", "dev", interface, "mode", "tun"]),
        ));
    }
    operations.extend([
        operation(
            CommandSpec::new(
                "ip",
                [
                    "address",
                    "add",
                    &config.address.to_string(),
                    "dev",
                    interface,
                ],
            ),
            CommandSpec::new(
                "ip",
                [
                    "address",
                    "del",
                    &config.address.to_string(),
                    "dev",
                    interface,
                ],
            ),
        ),
        operation(
            CommandSpec::new(
                "ip",
                [
                    "link",
                    "set",
                    "dev",
                    interface,
                    "mtu",
                    &config.mtu.to_string(),
                    "up",
                ],
            ),
            CommandSpec::new("ip", ["link", "set", "dev", interface, "down"]),
        ),
    ]);
    if let Some(address) = config.secondary_address {
        operations.push(operation(
            CommandSpec::new(
                "ip",
                ["address", "add", &address.to_string(), "dev", interface],
            ),
            CommandSpec::new(
                "ip",
                ["address", "del", &address.to_string(), "dev", interface],
            ),
        ));
    }
    if config.address.addr() != config.dns_server {
        let dns_address = if config.dns_server.is_ipv4() {
            format!("{}/32", config.dns_server)
        } else {
            format!("{}/128", config.dns_server)
        };
        operations.push(operation(
            CommandSpec::new("ip", ["address", "add", &dns_address, "dev", interface]),
            CommandSpec::new("ip", ["address", "del", &dns_address, "dev", interface]),
        ));
    }
    for route in &config.routes {
        operations.push(operation(
            CommandSpec::new("ip", ["route", "add", &route.to_string(), "dev", interface]),
            CommandSpec::new("ip", ["route", "del", &route.to_string(), "dev", interface]),
        ));
    }
    operations
}

fn nft_operations(config: &LinuxNetworkConfig, table: &str) -> Vec<Operation> {
    let mut batch = format!(
        "destroy table inet {table}\nadd table inet {table}\nadd chain inet {table} egress {{ type filter hook output priority -10; policy accept; }}\n"
    );
    for rule in &config.nft_allow {
        let family = if rule.destination.addr().is_ipv4() {
            "ip"
        } else {
            "ip6"
        };
        let mut statement = format!(
            "add rule inet {table} egress oifname \"{}\" {family} daddr {}",
            config.interface, rule.destination
        );
        if let Some(protocol) = rule.protocol {
            statement.push(' ');
            statement.push_str(protocol);
            if let Some(port) = rule.destination_port {
                use std::fmt::Write as _;
                write!(&mut statement, " dport {port}").expect("String writes cannot fail");
            }
        }
        statement.push_str(" accept\n");
        batch.push_str(&statement);
    }
    vec![operation(
        CommandSpec::new("nft", ["--file", "-"]).with_input(batch),
        CommandSpec::new("nft", ["--file", "-"])
            .with_input(format!("destroy table inet {table}\n")),
    )]
}

fn dns_operations<B: CommandBackend>(
    backend: &mut B,
    config: &LinuxNetworkConfig,
) -> Result<Vec<Operation>, PlatformError> {
    // All managed queries enter the local resolver. Changing split profiles then
    // cannot expose a newly private name through a temporarily stale OS suffix list.
    dns_operations_scoped(
        backend,
        config,
        &[(".".into(), true), (config.dns_suffix.clone(), true)],
        None,
    )
}

fn dns_operations_scoped<B: CommandBackend>(
    backend: &mut B,
    config: &LinuxNetworkConfig,
    domains: &[(String, bool)],
    record_label: Option<&str>,
) -> Result<Vec<Operation>, PlatformError> {
    let interface = &config.interface;
    let server = config.dns_server.to_string();
    let route_domain = domains
        .iter()
        .map(|(name, route_only)| {
            if *route_only {
                format!("~{name}")
            } else {
                name.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(",");
    match &config.dns_backend {
        DnsBackend::Auto {
            connection,
            resolv_conf,
        } => {
            let selected = if backend
                .run(&CommandSpec::new("resolvectl", ["probe", interface]))
                .is_ok()
            {
                DnsBackend::SystemdResolved
            } else if let Some(connection) = connection
                && backend
                    .run(&CommandSpec::new(
                        "nmcli",
                        ["-g", "connection.id", "connection", "show", connection],
                    ))
                    .is_ok_and(|profile| !profile.trim().is_empty())
            {
                DnsBackend::NetworkManager {
                    connection: connection.clone(),
                }
            } else if backend.run(&CommandSpec::new("resolvconf", ["-v"])).is_ok() {
                DnsBackend::OpenResolv
            } else {
                DnsBackend::ResolvConf {
                    path: resolv_conf.clone(),
                }
            };
            let mut selected_config = config.clone();
            selected_config.dns_backend = selected;
            dns_operations_scoped(backend, &selected_config, domains, record_label)
        }
        DnsBackend::SystemdResolved => {
            let original: ResolvedLinkState = serde_json::from_str(
                &backend.run(&CommandSpec::new("resolvectl", ["snapshot", interface]))?,
            )?;
            let address = config.dns_server;
            let replacement = ResolvedLinkState {
                dns: vec![(
                    if address.is_ipv4() { 2 } else { 10 },
                    match address {
                        IpAddr::V4(value) => value.octets().to_vec(),
                        IpAddr::V6(value) => value.octets().to_vec(),
                    },
                )],
                domains: domains.to_vec(),
                default_route: false,
            };
            let apply = serde_json::to_string(&ResolvedLinkMutation {
                expected: original.clone(),
                replacement: replacement.clone(),
            })?;
            let rollback = serde_json::to_string(&ResolvedLinkMutation {
                expected: replacement,
                replacement: original,
            })?;
            Ok(vec![operation(
                CommandSpec::new("peerward-resolved", ["replace", interface]).with_input(apply),
                CommandSpec::new("peerward-resolved", ["replace", interface]).with_input(rollback),
            )])
        }
        DnsBackend::NetworkManager { connection } => {
            let family = if config.dns_server.is_ipv4() {
                "ipv4"
            } else {
                "ipv6"
            };
            let dns_property = format!("{family}.dns");
            let search_property = format!("{family}.dns-search");
            let old_dns = backend.run(&CommandSpec::new(
                "nmcli",
                ["-g", &dns_property, "connection", "show", connection],
            ))?;
            let old_search = backend.run(&CommandSpec::new(
                "nmcli",
                ["-g", &search_property, "connection", "show", connection],
            ))?;
            let original = NetworkManagerDnsState {
                family: family.into(),
                dns: old_dns,
                search: old_search,
            };
            let replacement = NetworkManagerDnsState {
                family: family.into(),
                dns: server,
                search: route_domain,
            };
            let apply = serde_json::to_string(&NetworkManagerDnsMutation {
                expected: original.clone(),
                replacement: replacement.clone(),
            })?;
            let rollback = serde_json::to_string(&NetworkManagerDnsMutation {
                expected: replacement,
                replacement: original,
            })?;
            Ok(vec![operation(
                CommandSpec::new("peerward-network-manager", ["replace", connection])
                    .with_input(apply),
                CommandSpec::new("peerward-network-manager", ["replace", connection])
                    .with_input(rollback),
            )])
        }
        DnsBackend::OpenResolv => {
            let search = domains
                .iter()
                .filter(|(_, route_only)| !*route_only)
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            let search = if search.is_empty() {
                config.dns_suffix.as_str()
            } else {
                search.as_str()
            };
            let record = format!("nameserver {server}\nsearch {search}\n");
            let label = record_label
                .map_or_else(|| format!("{}.peerward", config.interface), str::to_owned);
            Ok(vec![operation(
                CommandSpec::new("resolvconf", ["-a", &label]).with_input(record),
                CommandSpec::new("resolvconf", ["-d", &label]),
            )])
        }
        DnsBackend::ResolvConf { path } => {
            let search = domains
                .iter()
                .filter(|(_, route_only)| !*route_only)
                .map(|(name, _)| name.clone())
                .collect::<Vec<_>>();
            resolv_conf_operations_search(
                path,
                &server,
                (!search.is_empty()).then_some(search.as_slice()),
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedLinkState {
    dns: Vec<(i32, Vec<u8>)>,
    domains: Vec<(String, bool)>,
    default_route: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedLinkMutation {
    expected: ResolvedLinkState,
    replacement: ResolvedLinkState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkManagerDnsState {
    family: String,
    dns: String,
    search: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkManagerDnsMutation {
    expected: NetworkManagerDnsState,
    replacement: NetworkManagerDnsState,
}

const MAX_RESOLV_CONF_BYTES: usize = 65_536;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvConfMutation {
    expected: String,
    replacement: String,
}

#[cfg(test)]
fn resolv_conf_operations(path: &Path, server: &str) -> Result<Vec<Operation>, PlatformError> {
    resolv_conf_operations_search(path, server, None)
}

fn resolv_conf_operations_search(
    path: &Path,
    server: &str,
    search: Option<&[String]>,
) -> Result<Vec<Operation>, PlatformError> {
    let original = read_text_bounded(path, MAX_RESOLV_CONF_BYTES as u64).map_err(|error| {
        if error.kind() == std::io::ErrorKind::InvalidData {
            PlatformError::Command("resolv.conf is not valid UTF-8".into())
        } else {
            PlatformError::Io(error)
        }
    })?;
    let mut replacement = format!("# Managed temporarily by Peerward\nnameserver {server}\n");
    if let Some(search) = search {
        replacement.push_str("search ");
        replacement.push_str(&search.join(" "));
        replacement.push('\n');
    }
    for line in original.lines() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("nameserver")
            && trimmed != "# Managed temporarily by Peerward"
            && !(search.is_some()
                && matches!(trimmed.split_whitespace().next(), Some("search" | "domain")))
        {
            replacement.push_str(line);
            replacement.push('\n');
        }
    }
    let apply = serde_json::to_string(&ResolvConfMutation {
        expected: original.clone(),
        replacement: replacement.clone(),
    })?;
    let rollback = serde_json::to_string(&ResolvConfMutation {
        expected: replacement,
        replacement: original,
    })?;
    let path = path.to_string_lossy().into_owned();
    Ok(vec![operation(
        CommandSpec::new("peerward-resolv-conf", ["replace", &path]).with_input(apply),
        CommandSpec::new("peerward-resolv-conf", ["replace", &path]).with_input(rollback),
    )])
}

fn run_resolv_conf_mutation(command: &CommandSpec) -> Result<String, PlatformError> {
    let [operation, path] = command.arguments.as_slice() else {
        return Err(PlatformError::Command(
            "invalid resolv.conf mutation command".into(),
        ));
    };
    if operation != "replace" {
        return Err(PlatformError::Command(
            "invalid resolv.conf mutation operation".into(),
        ));
    }
    let path = Path::new(path);
    if !safe_resolver_path(path) {
        return Err(PlatformError::InvalidName);
    }
    let encoded = command
        .input
        .as_deref()
        .ok_or_else(|| PlatformError::Command("missing resolv.conf mutation".into()))?;
    let mutation: ResolvConfMutation = serde_json::from_str(encoded)?;
    if mutation.expected.len() > MAX_RESOLV_CONF_BYTES
        || mutation.replacement.len() > MAX_RESOLV_CONF_BYTES
    {
        return Err(PlatformError::Command(
            "resolv.conf exceeds safety limit".into(),
        ));
    }
    let target = fs::canonicalize(path)?;
    let current = read_text_bounded(&target, MAX_RESOLV_CONF_BYTES as u64)?;
    if current == mutation.replacement {
        return Ok(String::new());
    }
    if current != mutation.expected {
        return Err(PlatformError::OwnershipConflict);
    }
    replace_resolver_file(&target, mutation.replacement.as_bytes())?;
    Ok(String::new())
}

fn replace_resolver_file(path: &Path, contents: &[u8]) -> Result<(), PlatformError> {
    let parent = path.parent().ok_or(PlatformError::InvalidName)?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(PlatformError::InvalidName)?;
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(PlatformError::InvalidName);
    }
    let temporary = parent.join(format!(".{name}.{}.peerward", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        options.mode(metadata.permissions().mode());
    }
    let result = (|| {
        let mut file = options.open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        match fs::rename(&temporary, path) {
            Ok(()) => {}
            Err(error)
                if error.raw_os_error().is_some_and(|code| {
                    matches!(code, libc::EBUSY | libc::EXDEV | libc::EPERM)
                }) =>
            {
                let mut target = OpenOptions::new().write(true).truncate(true).open(path)?;
                target.write_all(contents)?;
                target.sync_all()?;
                fs::remove_file(&temporary)?;
            }
            Err(error) => return Err(error),
        }
        fs::File::open(parent)?.sync_all()?;
        Ok::<(), std::io::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(PlatformError::Io)
}
