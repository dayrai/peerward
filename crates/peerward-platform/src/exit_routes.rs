//! Capture local application traffic without changing the main routing table.
use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};

pub(crate) const EXIT_TABLE: u32 = 20_567;
pub(crate) const EXIT_RULE_START: u32 = 5_100;
pub(crate) const EXIT_RULE_CAPTURE: u32 = 5_400;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExitRoutingIntent {
    pub interface: String,
    pub ipv4: Ipv4Addr,
    pub ipv6: Ipv6Addr,
    /// Same explicitly verified exceptions as the separately persistent exit guard.
    pub local_lan: Vec<IpNet>,
}
impl ExitRoutingIntent {
    pub(crate) fn validate(&self) -> Result<(), PlatformError> {
        let guard = ExitProtectionIntent {
            interface: self.interface.clone(),
            exit_resource: Uuid::new_v4(),
            local_lan: self.local_lan.clone(),
        };
        guard.validate()?;
        if self.ipv4.is_unspecified()
            || self.ipv4.is_loopback()
            || self.ipv4.is_multicast()
            || self.ipv6.is_unspecified()
            || self.ipv6.is_loopback()
            || self.ipv6.is_multicast()
            || self.local_lan.iter().any(|prefix| {
                prefix.contains(&IpAddr::V4(self.ipv4)) || prefix.contains(&IpAddr::V6(self.ipv6))
            })
        {
            return Err(PlatformError::InvalidName);
        }
        Ok(())
    }
}
impl<B: CommandBackend> StateCoordinator<B> {
    /// Caller arms `ExitProtection` first. Ordinary cleanup restores routing but deliberately
    /// cannot disarm that guard. Conflicting operator/VPN policy is never overwritten.
    pub fn apply_exit_routing(&mut self, intent: &ExitRoutingIntent) -> Result<(), PlatformError> {
        intent.validate()?;
        self.shutdown()?;
        let input = serde_json::to_string(intent)?;
        self.backend
            .run(&CommandSpec::new("peerward-exit-routing", ["check"]).with_input(input.clone()))?;
        self.phase = Some(TransactionPhase::Prepared);
        self.apply_operations_journaled(
            vec![operation(
                CommandSpec::new("peerward-exit-routing", ["apply"]).with_input(input.clone()),
                CommandSpec::new("peerward-exit-routing", ["remove"]).with_input(input),
            )],
            true,
        )?;
        self.commit()
    }
}

pub(crate) fn run(command: &CommandSpec) -> Result<String, PlatformError> {
    let [action] = command.arguments.as_slice() else {
        return Err(PlatformError::InvalidName);
    };
    if !matches!(action.as_str(), "check" | "apply" | "remove") {
        return Err(PlatformError::InvalidName);
    }
    let input = command
        .input
        .as_deref()
        .filter(|input| input.len() <= 65_536)
        .ok_or(PlatformError::InvalidName)?;
    let intent: ExitRoutingIntent = serde_json::from_str(input)?;
    intent.validate()?;
    let action = action.clone();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    super::exit_routes_native::change(&intent, &action),
                )
                .await
                .map_err(|_| {
                    PlatformError::Command(
                        "exit policy routing timed out; blocking guard retained".into(),
                    )
                })?
            })
    })
    .join()
    .map_err(|_| PlatformError::Command("exit route worker panicked".into()))??;
    Ok(String::new())
}
