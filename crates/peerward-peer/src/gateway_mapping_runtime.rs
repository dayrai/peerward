struct ActiveGatewayMapping {
    lease: peerward_p2p::MappingLease,
    expires_at: Instant,
    renew_at: Instant,
}
impl ActiveGatewayMapping {
    fn new(lease: peerward_p2p::MappingLease) -> Self {
        let now = Instant::now();
        let lifetime = Duration::from_secs(u64::from(lease.lifetime_seconds));
        Self {
            renew_at: now + lease.renew_after(),
            expires_at: now.checked_add(lifetime).unwrap_or(now),
            lease,
        }
    }
}

#[derive(Default)]
struct GatewayMappings {
    leases: BTreeMap<IpAddr, ActiveGatewayMapping>,
    retries: BTreeMap<IpAddr, Instant>,
}
impl GatewayMappings {
    async fn refresh(
        &mut self,
        gateways: &[IpAddr],
        internal: SocketAddr,
        observed: Option<&peerward_service::PeerObservability>,
        transport: &dyn peerward_p2p::MappingTransport,
    ) {
        let retired: Vec<_> = self
            .leases
            .keys()
            .filter(|gateway| !gateways.contains(gateway))
            .copied()
            .collect();
        for gateway in retired {
            if let Some(previous) = self.leases.remove(&gateway) {
                delete_mapping(gateway, previous.lease, transport).await;
            }
        }
        self.retries.retain(|gateway, _| gateways.contains(gateway));
        for gateway in gateways.iter().take(4).copied() {
            let now = Instant::now();
            if self.retries.get(&gateway).is_some_and(|retry| now < *retry) {
                continue;
            }
            if self
                .leases
                .get(&gateway)
                .is_some_and(|active| active.renew_at > now)
            {
                continue;
            }
            let mut restarted = false;
            let result = if let Some(active) = self.leases.get(&gateway) {
                match peerward_p2p::renew_port_mapping_with_transport(
                    gateway,
                    &active.lease,
                    Duration::from_secs(2),
                    Some(transport),
                )
                .await
                {
                    Ok(lease) => Ok(lease),
                    Err(error) => {
                        restarted = matches!(error, peerward_p2p::P2pError::GatewayRestarted);
                        peerward_p2p::discover_port_mapping_with_transport(
                            gateway,
                            internal,
                            600,
                            Duration::from_secs(2),
                            Some(transport),
                        )
                        .await
                    }
                }
            } else {
                peerward_p2p::discover_port_mapping_with_transport(
                    gateway,
                    internal,
                    600,
                    Duration::from_secs(2),
                    Some(transport),
                )
                .await
            };
            if let Some(observed) = observed {
                observed.record_gateway_mapping(result.is_ok());
                if restarted {
                    observed.record_gateway_restart();
                }
            }
            if let Ok(lease) = result {
                if let Some(previous) = self
                    .leases
                    .insert(gateway, ActiveGatewayMapping::new(lease.clone()))
                    && previous.lease.independently_deletable(&lease)
                {
                    delete_mapping(gateway, previous.lease, transport).await;
                }
                self.retries.remove(&gateway);
            } else {
                self.retries.insert(gateway, now + Duration::from_secs(30));
                if (restarted
                    || self
                        .leases
                        .get(&gateway)
                        .is_some_and(|lease| lease.expires_at <= now))
                    && let Some(previous) = self.leases.remove(&gateway)
                {
                    delete_mapping(gateway, previous.lease, transport).await;
                }
            }
        }
    }

    fn candidates(&self) -> Vec<SocketAddr> {
        self.leases
            .values()
            .filter(|lease| lease.expires_at > Instant::now())
            .map(|lease| lease.lease.external)
            .collect()
    }

    fn next_refresh(&self) -> Duration {
        let now = Instant::now();
        self.leases
            .iter()
            .map(|(gateway, lease)| {
                self.retries
                    .get(gateway)
                    .copied()
                    .unwrap_or(lease.renew_at)
                    .min(lease.expires_at)
            })
            .chain(self.retries.values().copied())
            .min()
            .map_or(Duration::from_secs(30), |next| {
                next.saturating_duration_since(now)
                    .max(Duration::from_secs(1))
            })
    }

    async fn close(&mut self, transport: &dyn peerward_p2p::MappingTransport) {
        for (gateway, active) in std::mem::take(&mut self.leases) {
            delete_mapping(gateway, active.lease, transport).await;
        }
        self.retries.clear();
    }
}

async fn delete_mapping(
    gateway: IpAddr,
    lease: peerward_p2p::MappingLease,
    transport: &dyn peerward_p2p::MappingTransport,
) {
    let _ = peerward_p2p::delete_port_mapping_with_transport(
        gateway,
        &lease,
        Duration::from_millis(500),
        Some(transport),
    )
    .await;
}
