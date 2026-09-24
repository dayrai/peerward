// Linux exit host operations. The blocking guard deliberately outlives this worker.
use peerward_platform::{ExitProtection, ExitProtectionIntent, ExitRoutingIntent};

struct ExitHost {
    guard: ExitProtection<LinuxCommandBackend>,
    routing: StateCoordinator<LinuxCommandBackend>,
    applied: Option<ExitRoutingIntent>,
}
impl ExitHost {
    fn new(config: &LinuxConfig) -> Self {
        Self {
            guard: ExitProtection::new(
                LinuxCommandBackend,
                config.platform_state_file.with_extension("exit-guard.json"),
            ),
            routing: StateCoordinator::with_journal(
                LinuxCommandBackend,
                config
                    .platform_state_file
                    .with_extension("exit-routes.json"),
            ),
            applied: None,
        }
    }
    fn arm(
        &mut self,
        config: &LinuxConfig,
        selected: uuid::Uuid,
        lan: Vec<ipnet::IpNet>,
    ) -> Result<(), peerward_platform::PlatformError> {
        self.guard.arm(ExitProtectionIntent {
            interface: config.interface.clone(),
            exit_resource: selected,
            local_lan: lan,
        })
    }
    fn apply(
        &mut self,
        config: &LinuxConfig,
        preferences: &peerward_management::ClientPreferences,
        lan: Vec<ipnet::IpNet>,
        explicit_disable: bool,
    ) -> Result<(), peerward_platform::PlatformError> {
        let Some(selected) = preferences.exit_resource else {
            self.routing.shutdown()?;
            self.applied = None;
            if explicit_disable {
                self.guard.disarm()?;
            } else if self.guard.saved_intent()?.is_some() {
                return Err(peerward_platform::PlatformError::Command(
                    "exit guard retained; explicitly turn exit off to restore direct access".into(),
                ));
            }
            return Ok(());
        };
        self.arm(config, selected, lan.clone())?;
        let addresses: Vec<_> = std::iter::once(config.address.addr())
            .chain(config.secondary_address.map(|address| address.addr()))
            .collect();
        let ipv4 = addresses
            .iter()
            .find_map(|address| {
                if let IpAddr::V4(ip) = address {
                    Some(*ip)
                } else {
                    None
                }
            })
            .ok_or(peerward_platform::PlatformError::InvalidName)?;
        let ipv6 = addresses
            .iter()
            .find_map(|address| {
                if let IpAddr::V6(ip) = address {
                    Some(*ip)
                } else {
                    None
                }
            })
            .ok_or(peerward_platform::PlatformError::InvalidName)?;
        let intent = ExitRoutingIntent {
            interface: config.interface.clone(),
            ipv4,
            ipv6,
            local_lan: lan,
        };
        if self.applied.as_ref() != Some(&intent) {
            self.applied = None;
            self.routing.apply_exit_routing(&intent)?;
            self.applied = Some(intent);
        }
        Ok(())
    }
}
async fn selected_lan(
    config: &LinuxConfig,
    preferences: &peerward_management::ClientPreferences,
) -> Result<Vec<ipnet::IpNet>, PacketPumpError> {
    if preferences.exit_resource.is_none() || !preferences.allow_local_lan {
        return Ok(Vec::new());
    }
    let addresses = peerward_platform::linux_underlay_addresses()
        .await
        .map_err(platform_packet_error)?;
    let routes = peerward_platform::linux_resource_routes()
        .await
        .map_err(platform_packet_error)?;
    let mut prefixes: BTreeSet<_> = routes
        .into_iter()
        .filter(|route| {
            route.protocol == 2
                && route.interface != config.interface
                && route.prefix.prefix_len() > 0
                && !route.prefix.addr().is_loopback()
                && !route.prefix.addr().is_multicast()
                && addresses.iter().any(|address| {
                    address.interface == route.interface && route.prefix.contains(&address.address)
                })
                && !config.routes.iter().any(|mesh| {
                    mesh.contains(&route.prefix.network()) || route.prefix.contains(&mesh.network())
                })
        })
        .map(|route| route.prefix)
        .collect();
    let all = prefixes.clone();
    prefixes.retain(|prefix| {
        !all.iter().any(|other| {
            other != prefix
                && other.prefix_len() < prefix.prefix_len()
                && other.contains(&prefix.network())
        })
    });
    if prefixes.len() > 128 {
        return Err(PacketPumpError::InvalidControl);
    }
    Ok(prefixes.into_iter().collect())
}
fn platform_packet_error(error: peerward_platform::PlatformError) -> PacketPumpError {
    PacketPumpError::Io(std::io::Error::other(error))
}
