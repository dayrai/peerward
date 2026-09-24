use super::*;
use std::collections::BTreeSet;

/// Host intent compiled from the locally verified configuration and client preferences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceNetworkIntent {
    pub interface: String,
    pub local_addresses: Vec<IpAddr>,
    pub mesh_prefixes: Vec<IpNet>,
    pub accepted_routes: Vec<IpNet>,
    pub gateway_routes: Vec<GatewayForward>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayForward {
    pub prefix: IpNet,
    pub masquerade: bool,
}

/// Bounded native route observation; retained to explain local conflicts and provider paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRoute {
    pub prefix: IpNet,
    pub interface: String,
    pub protocol: u8,
}

impl ResourceNetworkIntent {
    pub fn validate(&self, routes: &[HostRoute]) -> Result<(), PlatformError> {
        if !safe_name(&self.interface)
            || self.local_addresses.is_empty()
            || self.local_addresses.len() > 4
            || self.mesh_prefixes.is_empty()
            || self.mesh_prefixes.len() > 4
            || self.accepted_routes.len() > 128
            || self.gateway_routes.len() > 128
            || self
                .accepted_routes
                .iter()
                .any(|prefix| prefix.prefix_len() == 0 || prefix.network() != prefix.addr())
            || self.gateway_routes.iter().any(|route| {
                route.prefix.network() != route.prefix.addr()
                    || (route.prefix.prefix_len() == 0 && !route.masquerade)
            })
        {
            return Err(PlatformError::InvalidName);
        }
        if self
            .gateway_routes
            .iter()
            .enumerate()
            .any(|(index, route)| {
                self.gateway_routes[index + 1..].iter().any(|other| {
                    other.prefix == route.prefix && other.masquerade != route.masquerade
                })
            })
        {
            return Err(PlatformError::Command(
                "same gateway prefix has conflicting forwarding modes".into(),
            ));
        }
        for accepted in &self.accepted_routes {
            if self
                .mesh_prefixes
                .iter()
                .any(|mesh| overlaps(mesh, accepted))
                || routes.iter().any(|route| {
                    route.prefix.prefix_len() > 0
                        && overlaps(&route.prefix, accepted)
                        && (route.interface != self.interface || route.protocol != 99)
                })
            {
                return Err(PlatformError::Command(format!(
                    "route {accepted} conflicts with a local network or another VPN"
                )));
            }
        }
        for gateway in &self.gateway_routes {
            if gateway.prefix.prefix_len() == 0 {
                if !routes.iter().any(|route| {
                    route.interface != self.interface
                        && route.prefix.prefix_len() == 0
                        && route.prefix.addr().is_ipv4() == gateway.prefix.addr().is_ipv4()
                }) {
                    return Err(PlatformError::Command(format!(
                        "no underlay default route reaches Internet family {}",
                        gateway.prefix
                    )));
                }
                continue;
            }
            if self
                .mesh_prefixes
                .iter()
                .any(|mesh| overlaps(mesh, &gateway.prefix))
            {
                return Err(PlatformError::InvalidName);
            }
            if !routes.iter().any(|route| {
                route.interface != self.interface
                    && route.prefix.prefix_len() > 0
                    && route.prefix.prefix_len() <= gateway.prefix.prefix_len()
                    && route.prefix.contains(&gateway.prefix.network())
            }) {
                return Err(PlatformError::Command(format!(
                    "no local route reaches gateway target {}",
                    gateway.prefix
                )));
            }
        }
        Ok(())
    }
}
fn overlaps(left: &IpNet, right: &IpNet) -> bool {
    left.contains(&right.network()) || right.contains(&left.network())
}

impl<B: CommandBackend> StateCoordinator<B> {
    /// Uses the existing durable rollback framework with a separate resource journal.
    /// It must not share a coordinator with the base TUN/address transaction.
    pub fn apply_resource_network(
        &mut self,
        intent: &ResourceNetworkIntent,
        routes: &[HostRoute],
    ) -> Result<(), PlatformError> {
        intent.validate(routes)?;
        self.shutdown()?;
        self.phase = Some(TransactionPhase::Prepared);
        let table = format!("pw_shared_{}", intent.interface);
        let mut operations = vec![operation(
            CommandSpec::new("nft", ["--file", "-"]).with_input(resource_nft(intent, &table)),
            CommandSpec::new("nft", ["--file", "-"])
                .with_input(format!("destroy table inet {table}\n")),
        )];
        let families: BTreeSet<_> = intent
            .gateway_routes
            .iter()
            .map(|route| {
                if route.prefix.addr().is_ipv4() {
                    "ipv4"
                } else {
                    "ipv6"
                }
            })
            .collect();
        if families.contains("ipv6") {
            let interfaces: BTreeSet<_> = routes
                .iter()
                .filter(|route| {
                    route.prefix.addr().is_ipv6()
                        && route.prefix.prefix_len() == 0
                        && route.interface != intent.interface
                })
                .map(|route| &route.interface)
                .collect();
            for interface in interfaces {
                let previous = self
                    .backend
                    .run(&CommandSpec::new("peerward-ipv6-ra", ["read", interface]))?;
                if previous == "1" {
                    operations.push(operation(
                        CommandSpec::new("peerward-ipv6-ra", ["replace", interface, "1", "2"]),
                        CommandSpec::new("peerward-ipv6-ra", ["replace", interface, "2", "1"]),
                    ));
                } else if !["0", "2"].contains(&previous.as_str()) {
                    return Err(PlatformError::OwnershipConflict);
                }
            }
        }
        for family in families {
            let previous = self
                .backend
                .run(&CommandSpec::new("peerward-forwarding", ["read", family]))?;
            if previous == "1" {
                continue;
            }
            if previous != "0" {
                return Err(PlatformError::OwnershipConflict);
            }
            operations.push(operation(
                CommandSpec::new("peerward-forwarding", ["replace", family, "0", "1"]),
                CommandSpec::new("peerward-forwarding", ["replace", family, "1", "0"]),
            ));
        }
        for prefix in &intent.accepted_routes {
            operations.push(operation(
                CommandSpec::new(
                    "ip",
                    [
                        "route",
                        "add",
                        &prefix.to_string(),
                        "dev",
                        &intent.interface,
                    ],
                ),
                CommandSpec::new(
                    "ip",
                    [
                        "route",
                        "del",
                        &prefix.to_string(),
                        "dev",
                        &intent.interface,
                    ],
                ),
            ));
        }
        // Every rollback is idempotent and scoped to owned objects. Persist intent
        // before a host mutation so a kill between syscall and journal write is recoverable.
        self.apply_operations_journaled(operations, true)?;
        self.commit()
    }
}

fn resource_nft(intent: &ResourceNetworkIntent, table: &str) -> String {
    use std::fmt::Write as _;
    let interface = &intent.interface;
    let mut text = format!(
        "destroy table inet {table}\nadd table inet {table}\nadd chain inet {table} transit {{ type filter hook forward priority -20; policy accept; }}\nadd chain inet {table} local {{ type filter hook input priority -20; policy accept; }}\nadd chain inet {table} nat {{ type nat hook postrouting priority srcnat; policy accept; }}\n"
    );
    // Resource prefixes never grant access to the gateway host's LAN addresses.
    for address in &intent.local_addresses {
        let family = if address.is_ipv4() { "ip" } else { "ip6" };
        writeln!(
            &mut text,
            "add rule inet {table} local iifname \"{interface}\" {family} daddr {address} accept"
        )
        .expect("String write");
    }
    writeln!(
        &mut text,
        "add rule inet {table} local iifname \"{interface}\" drop"
    )
    .expect("String write");
    let mut gateway_routes: Vec<_> = intent.gateway_routes.iter().collect();
    gateway_routes
        .sort_by_key(|route| (std::cmp::Reverse(route.prefix.prefix_len()), route.prefix));
    for route in gateway_routes {
        let family = if route.prefix.addr().is_ipv4() {
            "ip"
        } else {
            "ip6"
        };
        for source in intent
            .mesh_prefixes
            .iter()
            .filter(|source| source.addr().is_ipv4() == route.prefix.addr().is_ipv4())
        {
            writeln!(&mut text,"add rule inet {table} transit iifname \"{interface}\" oifname != \"{interface}\" {family} saddr {source} {family} daddr {} accept",route.prefix).expect("String write");
            let nat_action = if route.masquerade {
                "masquerade"
            } else {
                "return"
            };
            writeln!(&mut text,"add rule inet {table} nat iifname \"{interface}\" oifname != \"{interface}\" {family} saddr {source} {family} daddr {} {nat_action}",route.prefix).expect("String write");
        }
    }
    writeln!(&mut text,"add rule inet {table} transit oifname \"{interface}\" ct state established,related accept\nadd rule inet {table} transit iifname \"{interface}\" drop\nadd rule inet {table} transit oifname \"{interface}\" drop").expect("String write");
    text
}

pub(super) fn run_forwarding(command: &CommandSpec) -> Result<String, PlatformError> {
    let Some(family) = command.arguments.get(1) else {
        return Err(PlatformError::InvalidName);
    };
    let path = match family.as_str() {
        "ipv4" => "/proc/sys/net/ipv4/ip_forward",
        "ipv6" => "/proc/sys/net/ipv6/conf/all/forwarding",
        _ => return Err(PlatformError::InvalidName),
    };
    let current = read_text_bounded(Path::new(path), 64)?.trim().to_owned();
    match command.arguments.as_slice() {
        [operation, _] if operation == "read" => Ok(current),
        [operation, _, expected, replacement]
            if operation == "replace"
                && ["0", "1"].contains(&expected.as_str())
                && ["0", "1"].contains(&replacement.as_str()) =>
        {
            if current != *expected && current != *replacement {
                return Err(PlatformError::OwnershipConflict);
            }
            if current != *replacement {
                std::fs::write(path, replacement)?;
            }
            Ok(String::new())
        }
        _ => Err(PlatformError::InvalidName),
    }
}

/// Preserve dynamic IPv6 default routing when forwarding would suppress RAs.
pub(super) fn run_ipv6_ra(command: &CommandSpec) -> Result<String, PlatformError> {
    let interface = command
        .arguments
        .get(1)
        .filter(|name| safe_name(name))
        .ok_or(PlatformError::InvalidName)?;
    let path = format!("/proc/sys/net/ipv6/conf/{interface}/accept_ra");
    let current = read_text_bounded(Path::new(&path), 64)?.trim().to_owned();
    match command.arguments.as_slice() {
        [operation, _] if operation == "read" => Ok(current),
        [operation, _, expected, replacement]
            if operation == "replace"
                && matches!(
                    (expected.as_str(), replacement.as_str()),
                    ("1", "2") | ("2", "1")
                ) =>
        {
            if current != *expected && current != *replacement {
                return Err(PlatformError::OwnershipConflict);
            }
            if current != *replacement {
                std::fs::write(path, replacement)?;
            }
            Ok(String::new())
        }
        _ => Err(PlatformError::InvalidName),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Backend {
        commands: Vec<CommandSpec>,
        fail_route: bool,
    }
    impl CommandBackend for Backend {
        fn run(&mut self, command: &CommandSpec) -> Result<String, PlatformError> {
            self.commands.push(command.clone());
            if command.program == "peerward-ipv6-ra" && command.arguments[0] == "read" {
                return Ok("1".into());
            }
            if command.program == "peerward-forwarding" && command.arguments[0] == "read" {
                return Ok("0".into());
            }
            if self.fail_route && command.program == "ip" && command.arguments[1] == "add" {
                return Err(PlatformError::Command("injected route conflict".into()));
            }
            Ok(String::new())
        }
    }
    fn intent() -> ResourceNetworkIntent {
        ResourceNetworkIntent {
            interface: "pwtest0".into(),
            local_addresses: vec!["10.42.0.2".parse().unwrap()],
            mesh_prefixes: vec!["10.42.0.0/24".parse().unwrap()],
            accepted_routes: vec!["192.168.45.0/24".parse().unwrap()],
            gateway_routes: vec![GatewayForward {
                prefix: "192.168.46.0/24".parse().unwrap(),
                masquerade: true,
            }],
        }
    }
    fn route(prefix: &str, interface: &str, protocol: u8) -> HostRoute {
        HostRoute {
            prefix: prefix.parse().unwrap(),
            interface: interface.into(),
            protocol,
        }
    }
    #[test]
    fn exit_provider_requires_each_default_route_and_preserves_ipv6_router_advertisements() {
        let request = ResourceNetworkIntent {
            interface: "pwexit0".into(),
            local_addresses: vec!["10.42.0.2".parse().unwrap(), "fd42::2".parse().unwrap()],
            mesh_prefixes: vec![
                "10.42.0.0/24".parse().unwrap(),
                "fd42::/64".parse().unwrap(),
            ],
            accepted_routes: vec![],
            gateway_routes: vec![
                GatewayForward {
                    prefix: "0.0.0.0/0".parse().unwrap(),
                    masquerade: true,
                },
                GatewayForward {
                    prefix: "::/0".parse().unwrap(),
                    masquerade: true,
                },
            ],
        };
        let mut coordinator = StateCoordinator::new(Backend::default());
        assert!(
            coordinator
                .apply_resource_network(&request, &[route("0.0.0.0/0", "eth0", 2)])
                .is_err()
        );
        assert!(coordinator.backend.commands.is_empty());
        let routes = [route("0.0.0.0/0", "eth0", 2), route("::/0", "eth0", 9)];
        coordinator
            .apply_resource_network(&request, &routes)
            .unwrap();
        assert!(
            coordinator
                .backend
                .commands
                .iter()
                .any(|cmd| cmd.program == "peerward-ipv6-ra"
                    && cmd.arguments == ["replace", "eth0", "1", "2"])
        );
        let mut invalid = request.clone();
        invalid.gateway_routes[0].masquerade = false;
        assert!(invalid.validate(&routes).is_err());
        coordinator.shutdown().unwrap();
        assert!(
            coordinator
                .backend
                .commands
                .iter()
                .any(|cmd| cmd.program == "peerward-ipv6-ra"
                    && cmd.arguments == ["replace", "eth0", "2", "1"])
        );
    }
    #[test]
    fn conflict_and_missing_lan_path_are_rejected_before_any_mutation() {
        let request = intent();
        let mut coordinator = StateCoordinator::new(Backend::default());
        assert!(coordinator.apply_resource_network(&request, &[]).is_err());
        assert!(coordinator.backend.commands.is_empty());
        let routes = vec![
            route("192.168.46.0/24", "eth0", 2),
            route("192.168.45.0/24", "another-vpn", 99),
        ];
        assert!(
            coordinator
                .apply_resource_network(&request, &routes)
                .is_err()
        );
        assert!(coordinator.backend.commands.is_empty());
        assert!(
            request
                .validate(&[
                    route("192.168.46.0/24", "eth0", 2),
                    route("192.168.45.0/24", "pwtest0", 99)
                ])
                .is_ok()
        );
    }
    #[test]
    fn forwarding_failure_rolls_back_only_owned_firewall_sysctl_and_routes() {
        let mut coordinator = StateCoordinator::new(Backend {
            fail_route: true,
            ..Backend::default()
        });
        assert!(
            coordinator
                .apply_resource_network(&intent(), &[route("192.168.46.0/24", "eth0", 2)])
                .is_err()
        );
        let commands = &coordinator.backend.commands;
        assert!(
            commands
                .iter()
                .any(|command| command.arguments == ["replace", "ipv4", "1", "0"])
        );
        assert!(
            commands.iter().any(|command| command.input.as_deref()
                == Some("destroy table inet pw_shared_pwtest0\n"))
        );
        let rules = commands
            .iter()
            .find_map(|command| {
                command
                    .input
                    .as_ref()
                    .filter(|input| input.contains("hook forward"))
            })
            .unwrap();
        assert!(rules.contains("iifname \"pwtest0\" ip daddr 10.42.0.2 accept"));
        assert!(rules.contains("local iifname \"pwtest0\" drop"));
        assert!(rules.contains("daddr 192.168.46.0/24 masquerade"));
        assert!(!rules.contains("flush ruleset"));
        assert!(coordinator.applied.is_empty());
    }
    #[test]
    fn committed_gateway_state_can_be_recovered_by_a_new_process() {
        let path =
            std::env::temp_dir().join(format!("peerward-resource-journal-{}.json", Uuid::new_v4()));
        {
            let mut coordinator = StateCoordinator::with_journal(Backend::default(), &path);
            coordinator
                .apply_resource_network(&intent(), &[route("192.168.46.0/24", "eth0", 2)])
                .unwrap();
            assert!(path.exists());
        }
        let mut recovered = StateCoordinator::with_journal(Backend::default(), &path);
        recovered.recover().unwrap();
        assert!(!path.exists());
        assert_eq!(
            recovered.backend.commands.first().unwrap().arguments,
            ["route", "del", "192.168.45.0/24", "dev", "pwtest0"]
        );
    }
}
