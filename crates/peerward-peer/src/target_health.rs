/// Target reachability is diagnostic evidence, independent of transport HA and policy.
/// This worker never sends application data and cannot change a gateway grant.
async fn run_target_health<C: ControlSender>(
    relay: C,
    rotator: Arc<Mutex<CredentialRotator>>,
    wireguard: WireguardPath,
    mut shutdown: watch::Receiver<bool>,
) {
    use futures_util::{StreamExt as _, stream};
    use peerward_management::{PeerOperation, TargetProbeResult};
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! { _=interval.tick()=>{}, _=shutdown.changed()=>return }
        if *shutdown.borrow() {
            return;
        }
        let candidates = {
            let mut core = wireguard.core.lock().await;
            if !core.resource_platform_ready() {
                continue;
            }
            let Some((resources, _)) =
                core.resource_network_configuration(UnixTime(wall_clock_seconds()))
            else {
                continue;
            };
            resources
                .bindings
                .iter()
                .filter(|b| b.approved && b.peer_id == core.local_peer())
                .filter_map(|b| {
                    resources
                        .resources
                        .iter()
                        .find(|r| r.id == b.resource_id)
                        .and_then(|r| {
                            r.definition
                                .health_probe
                                .clone()
                                .map(|probe| (b.clone(), r.version, probe))
                        })
                })
                .collect::<Vec<_>>()
        };
        let probes = stream::iter(candidates)
            .map(|(binding, version, probe)| {
                let wireguard = wireguard.clone();
                async move {
                    if !target_probe_current(&wireguard, &binding, version, &probe).await {
                        return None;
                    }
                    let result = match tokio::time::timeout(
                        Duration::from_secs(2),
                        tokio::net::TcpStream::connect((probe.address, probe.port)),
                    )
                    .await
                    {
                        Ok(Ok(stream)) => {
                            drop(stream);
                            TargetProbeResult::Reachable
                        }
                        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                            TargetProbeResult::Refused
                        }
                        Ok(Err(_)) => TargetProbeResult::Unavailable,
                        Err(_) => TargetProbeResult::Timeout,
                    };
                    Some((binding, version, probe, result))
                }
            })
            .buffer_unordered(8);
        tokio::pin!(probes);
        loop {
            let observation =
                tokio::select! {value=probes.next()=>value,_=shutdown.changed()=>return};
            let Some(observation) = observation else {
                break;
            };
            let Some((binding, version, probe, result)) = observation else {
                continue;
            };
            // Do not publish success from an obsolete target or expired local lease.
            let current = target_probe_current(&wireguard, &binding, version, &probe).await;
            if current {
                let operation = PeerOperation::TargetHealth {
                    binding_id: binding.id,
                    binding_version: binding.version,
                    resource_version: version,
                    result,
                };
                tokio::select! {
                    _=send_management_operation(&relay,&rotator,&wireguard,operation)=>{},
                    _=shutdown.changed()=>return,
                }
            }
        }
    }
}

async fn target_probe_current(
    wireguard: &WireguardPath,
    binding: &peerward_management::GatewayBinding,
    version: u64,
    probe: &peerward_management::TargetProbe,
) -> bool {
    let mut core = wireguard.core.lock().await;
    core.resource_platform_ready()
        && core.device_admitted(core.local_peer(), UnixTime(wall_clock_seconds()))
        && core
            .resource_network_configuration(UnixTime(wall_clock_seconds()))
            .is_some_and(|(resources, _)| {
                resources.bindings.contains(binding)
                    && resources.resources.iter().any(|r| {
                        r.id == binding.resource_id
                            && r.version == version
                            && r.definition.health_probe.as_ref() == Some(probe)
                    })
            })
}
