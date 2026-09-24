use crate::LinuxConfig;
use peerward_platform::{
    GatewayForward, LinuxCommandBackend, ResourceNetworkIntent, StateCoordinator,
};

fn resource_intent(
    config: &LinuxConfig,
    local: PeerId,
    resources: &peerward_management::ResourceConfiguration,
    preferences: &peerward_management::ClientPreferences,
    _wall: u64,
) -> ResourceNetworkIntent {
    let accepted = resources.private_capture_routes(local, preferences);
    let mut gateway = Vec::new();
    for resource in &resources.resources {
        let local_bindings: Vec<_> = resources
            .bindings
            .iter()
            .filter(|binding| {
                binding.resource_id == resource.id && binding.peer_id == local && binding.approved
            })
            .collect();
        if local_bindings.is_empty() {
            continue;
        }
        let prefixes = match resource.definition.target {
            peerward_management::ResourceTarget::Subnet { prefix, .. } => vec![prefix],
            peerward_management::ResourceTarget::Internet { ipv4, ipv6 } => {
                let mut prefixes = Vec::new();
                if ipv4 {
                    prefixes.push(ipnet::IpNet::V4(ipnet::Ipv4Net::default()));
                }
                if ipv6 {
                    prefixes.push(ipnet::IpNet::V6(ipnet::Ipv6Net::default()));
                }
                prefixes
            }
        };
        for prefix in prefixes {
            gateway.push(GatewayForward {
                prefix,
                masquerade: local_bindings
                    .iter()
                    .any(|binding| binding.forwarding == peerward_management::ForwardingMode::Snat),
            });
        }
    }
    gateway.sort_by_key(|route| route.prefix);
    gateway.dedup();
    ResourceNetworkIntent {
        interface: config.interface.clone(),
        local_addresses: std::iter::once(config.address.addr())
            .chain(config.secondary_address.map(|address| address.addr()))
            .collect(),
        mesh_prefixes: config.routes.clone(),
        accepted_routes: accepted.into_iter().collect(),
        gateway_routes: gateway,
    }
}

async fn send_management_operation<C: ControlSender>(
    relay: &C,
    rotator: &Arc<Mutex<CredentialRotator>>,
    wireguard: &WireguardPath,
    operation: peerward_management::PeerOperation,
) -> Result<(), PacketPumpError> {
    let rotation = rotator.lock().await;
    let sequence = wireguard
        .core
        .lock()
        .await
        .next_management_sequence()
        .map_err(core_packet_error)?;
    let command = peerward_management::PeerCommand {
        mesh_id: rotation.mesh_id,
        peer_id: rotation.peer_id,
        credential_serial: rotation.current.serial,
        request_id: uuid::Uuid::new_v4(),
        sequence,
        issued_at: wall_clock_seconds(),
        operation,
    };
    let signed = peerward_management::SignedPeerCommand::sign(
        command,
        &IdentitySigningKey::from_bytes(&rotation.current_identity_private_key),
    )
    .map_err(|_| PacketPumpError::InvalidControl)?;
    drop(rotation);
    let body = serde_json::to_vec(&signed).map_err(|_| PacketPumpError::InvalidControl)?;
    relay
        .send_control(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::PeerManagement(
                peerward_wire::PeerManagement { body },
            )),
        })
        .await
}

async fn resource_platform_result<C: ControlSender>(
    relay: &C,
    rotator: &Arc<Mutex<CredentialRotator>>,
    wireguard: &WireguardPath,
    version: u64,
    applied: bool,
) {
    let Some(receipt) = wireguard
        .core
        .lock()
        .await
        .core_application_receipt(UnixTime(wall_clock_seconds()))
    else {
        return;
    };
    if !matches!(&receipt,peerward_management::PeerOperation::Applied{configuration_version,..} if *configuration_version==version)
    {
        return;
    }
    for category in [
        peerward_management::ApplicationCategory::Routes,
        peerward_management::ApplicationCategory::Firewall,
    ] {
        let mut receipt = receipt.clone();
        if let peerward_management::PeerOperation::Applied {
            category: part,
            result,
            reason,
            ..
        } = &mut receipt
        {
            *part = category;
            *result = if applied {
                peerward_management::ApplicationResult::Applied
            } else {
                peerward_management::ApplicationResult::Rejected
            };
            *reason=(!applied).then(||"resource execution unavailable; inspect routing, DNS, forwarding and exit protection diagnostics".into());
        }
        if let Err(error) = send_management_operation(relay, rotator, wireguard, receipt).await {
            tracing::debug!(?error, "platform receipt deferred");
        }
    }
}

async fn advertise_resources<C: ControlSender>(
    relay: &C,
    rotator: &Arc<Mutex<CredentialRotator>>,
    wireguard: &WireguardPath,
    resources: &peerward_management::ResourceConfiguration,
    ready: bool,
) {
    let local = wireguard.core.lock().await.local_peer();
    for binding in resources.bindings.iter().filter(|binding| {
        binding.peer_id == local
            && binding.approved
            && resources
                .resources
                .iter()
                .any(|resource| resource.id == binding.resource_id)
    }) {
        if let Err(error) = send_management_operation(
            relay,
            rotator,
            wireguard,
            peerward_management::PeerOperation::Advertise {
                binding_id: binding.id,
                binding_version: binding.version,
                published: true,
                forwarding_ready: ready,
            },
        )
        .await
        {
            tracing::debug!(?error, "gateway publication deferred");
        }
    }
}

/// Separate platform transaction, driven only by a live shared-core intent. Lease expiry
/// retains capture routes while the core drops traffic, preventing an implicit direct fallback.
async fn run_resource_platform<C: ControlSender>(
    config: LinuxConfig,
    relay: C,
    rotator: Arc<Mutex<CredentialRotator>>,
    wireguard: WireguardPath,
    mut shutdown: watch::Receiver<bool>,
    preferences: ClientPreferenceStore,
    mut client_commands: mpsc::Receiver<LocalClientCommand>,
) -> Result<(), PacketPumpError> {
    if let Some(observed) = &wireguard.observability {
        observed.set_dns_host_ready(false);
    }
    let mut client = LinuxClientState::new(&config, preferences);
    let mut dns = DnsPlatform::recover(&config).await?;
    let coordinator = StateCoordinator::with_journal(
        LinuxCommandBackend,
        config.platform_state_file.with_extension("resources.json"),
    );
    let mut coordinator = tokio::task::spawn_blocking(move || {
        let mut coordinator = coordinator;
        coordinator.recover().map(|()| coordinator)
    })
    .await
    .map_err(|_| PacketPumpError::InvalidControl)?
    .map_err(|error| PacketPumpError::Io(std::io::Error::other(error)))?;
    let mut applied: Option<ResourceNetworkIntent> = None;
    let mut advertised: Option<(Instant, bool)> = None;
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _=interval.tick()=>{}, _=shutdown.changed()=>break,
            Some(command)=client_commands.recv()=>client.command(command,&config,&wireguard).await,
        }
        if *shutdown.borrow() {
            break;
        }
        client.reconcile(&config, false).await;
        dns.update(&config, &relay, &rotator, &wireguard).await?;
        if let Some(observed) = &wireguard.observability {
            observed.set_dns_host_ready(dns.ready);
        }
        let wall = UnixTime(wall_clock_seconds());
        let mut core = wireguard.core.lock().await;
        let Some((resources, preferences)) = core.resource_network_configuration(wall) else {
            continue;
        };
        let Some((version, _, _)) = core.configuration_status() else {
            continue;
        };
        drop(core);
        let intent = resource_intent(
            &config,
            wireguard.core.lock().await.local_peer(),
            &resources,
            &preferences,
            wall.0,
        );
        if applied.as_ref() != Some(&intent) {
            wireguard
                .core
                .lock()
                .await
                .set_resource_platform_ready(false);
            let routes = match peerward_platform::linux_resource_routes().await {
                Ok(routes) => routes,
                Err(error) => {
                    tracing::warn!(?error, "resource route observation failed");
                    resource_platform_result(&relay, &rotator, &wireguard, version, false).await;
                    advertise_resources(&relay, &rotator, &wireguard, &resources, false).await;
                    continue;
                }
            };
            let candidate = intent.clone();
            let (returned, result) = tokio::task::spawn_blocking(move || {
                let result = coordinator.apply_resource_network(&candidate, &routes);
                (coordinator, result)
            })
            .await
            .map_err(|_| PacketPumpError::InvalidControl)?;
            coordinator = returned;
            if let Err(error) = result {
                applied = None;
                tracing::warn!(?error, "resource platform configuration rejected");
                resource_platform_result(&relay, &rotator, &wireguard, version, false).await;
                advertise_resources(&relay, &rotator, &wireguard, &resources, false).await;
                continue;
            }
            applied = Some(intent);
            advertised = None;
        }
        {
            let mut core = wireguard.core.lock().await;
            let wall = wall_clock_seconds();
            let ready = core
                .resource_network_configuration(UnixTime(wall))
                .is_some_and(|(current, preferences)| {
                    applied.as_ref()
                        == Some(&resource_intent(
                            &config,
                            core.local_peer(),
                            &current,
                            &preferences,
                            wall,
                        ))
                });
            core.set_resource_platform_ready(ready && client.failure.is_none() && dns.ready);
        }
        let ready = wireguard.core.lock().await.resource_platform_ready();
        if advertised.is_none_or(|(last, previous)| {
            previous != ready || last.elapsed() >= std::time::Duration::from_secs(30)
        }) {
            // A configuration may have changed while the blocking platform transaction ran.
            let mut core = wireguard.core.lock().await;
            let wall = wall_clock_seconds();
            let Some((current, preferences)) = core.resource_network_configuration(UnixTime(wall))
            else {
                continue;
            };
            let current_intent =
                resource_intent(&config, core.local_peer(), &current, &preferences, wall);
            let Some((version, _, _)) = core.configuration_status() else {
                continue;
            };
            drop(core);
            if applied.as_ref() != Some(&current_intent) {
                continue;
            }
            resource_platform_result(&relay, &rotator, &wireguard, version, ready).await;
            advertise_resources(&relay, &rotator, &wireguard, &current, ready).await;
            advertised = Some((Instant::now(), ready));
        }
    }
    let dns_result = dns.shutdown().await;
    let exit_result = client.shutdown().await;
    let network_result = tokio::task::spawn_blocking(move || coordinator.shutdown())
        .await
        .map_err(|_| PacketPumpError::InvalidControl)?
        .map_err(|error| PacketPumpError::Io(std::io::Error::other(error)));
    dns_result.and(exit_result).and(network_result)
}
