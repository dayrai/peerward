struct DnsPlatform {
    coordinator: Option<StateCoordinator<LinuxCommandBackend>>,
    applied: Option<peerward_platform::LinuxDnsIntent>,
    reported: Option<Instant>,
    ready: bool,
}
impl DnsPlatform {
    async fn recover(config: &LinuxConfig) -> Result<Self, PacketPumpError> {
        let mut coordinator = StateCoordinator::with_journal(
            LinuxCommandBackend,
            config.platform_state_file.with_extension("dns.json"),
        );
        let coordinator =
            tokio::task::spawn_blocking(move || coordinator.recover().map(|()| coordinator))
                .await
                .map_err(|_| PacketPumpError::InvalidControl)?
                .map_err(|error| PacketPumpError::Io(std::io::Error::other(error)))?;
        Ok(Self {
            coordinator: Some(coordinator),
            applied: None,
            reported: None,
            ready: false,
        })
    }
    async fn update<C: ControlSender>(
        &mut self,
        config: &LinuxConfig,
        relay: &C,
        rotator: &Arc<Mutex<CredentialRotator>>,
        wireguard: &WireguardPath,
    ) -> Result<(), PacketPumpError> {
        self.ready = false;
        let wall = UnixTime(wall_clock_seconds());
        let mut core = wireguard.core.lock().await;
        let mut receipt = core.core_application_receipt(wall);
        let accept = core.preferences().accept_dns;
        let view = core.effective_dns(config.address.addr(), wall);
        drop(core);
        if !accept {
            let mut coordinator = self
                .coordinator
                .take()
                .ok_or(PacketPumpError::InvalidControl)?;
            let (coordinator, result) = tokio::task::spawn_blocking(move || {
                let result = coordinator.shutdown();
                (coordinator, result)
            })
            .await
            .map_err(|_| PacketPumpError::InvalidControl)?;
            self.coordinator = Some(coordinator);
            result.map_err(|error| PacketPumpError::Io(std::io::Error::other(error)))?;
            self.applied = None;
            self.reported = None;
            self.ready = true;
            return Ok(());
        }
        let intent = view
            .as_ref()
            .map(|(_, dns)| peerward_platform::LinuxDnsIntent {
                search_domains: dns.search_domains.clone(),
            })
            .or_else(|_| {
                if self.applied.is_none() {
                    Ok(peerward_platform::LinuxDnsIntent {
                        search_domains: vec![],
                    })
                } else {
                    Err(())
                }
            });
        let mut applied = false;
        if let Ok(intent) = intent {
            if self.applied.as_ref() != Some(&intent) {
                let base = config
                    .platform_config()
                    .map_err(|_| PacketPumpError::InvalidControl)?;
                let mut coordinator = self
                    .coordinator
                    .take()
                    .ok_or(PacketPumpError::InvalidControl)?;
                let candidate = intent.clone();
                let (coordinator, result) = tokio::task::spawn_blocking(move || {
                    let result = coordinator.apply_dns_profile(&base, &candidate);
                    (coordinator, result)
                })
                .await
                .map_err(|_| PacketPumpError::InvalidControl)?;
                self.coordinator = Some(coordinator);
                self.applied = match result {
                    Ok(()) => Some(intent.clone()),
                    Err(error) => {
                        tracing::warn!(?error, "managed DNS host configuration rejected");
                        None
                    }
                };
                self.reported = None;
            }
            applied = self.applied.as_ref() == Some(&intent);
        }
        self.ready = applied;
        if self
            .reported
            .is_none_or(|last| last.elapsed() >= Duration::from_secs(30))
        {
            if let Some(peerward_management::PeerOperation::Applied {
                category,
                result,
                reason,
                ..
            }) = &mut receipt
            {
                *category = peerward_management::ApplicationCategory::Dns;
                *result = if applied {
                    peerward_management::ApplicationResult::Applied
                } else {
                    peerward_management::ApplicationResult::Rejected
                };
                *reason=(!applied).then(||"DNS scope conflict or host DNS transaction failed; inspect local diagnostics".into());
            }
            // Receipt retains the exact version observed before the host operation.
            // A concurrent publication therefore appears pending until its own application.
            if let Some(receipt) = receipt
                && let Err(error) =
                    send_management_operation(relay, rotator, wireguard, receipt).await
            {
                tracing::debug!(?error, "DNS receipt deferred");
            }
            self.reported = Some(Instant::now());
        }
        Ok(())
    }
    async fn shutdown(mut self) -> Result<(), PacketPumpError> {
        let mut coordinator = self
            .coordinator
            .take()
            .ok_or(PacketPumpError::InvalidControl)?;
        tokio::task::spawn_blocking(move || coordinator.shutdown())
            .await
            .map_err(|_| PacketPumpError::InvalidControl)?
            .map_err(|error| PacketPumpError::Io(std::io::Error::other(error)))
    }
}
