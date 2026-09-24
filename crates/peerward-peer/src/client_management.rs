use peerward_management::{
    ClientPreferenceRequest, ClientPreferenceView, ExitChoice, PreferenceApplication,
};
use peerward_platform::ClientPreferenceStore;

struct LocalClientCommand {
    request: ClientPreferenceRequest,
    reply: oneshot::Sender<Result<ClientPreferenceView, String>>,
}
struct LocalClientHandle {
    sender: mpsc::Sender<LocalClientCommand>,
}
#[async_trait::async_trait]
impl peerward_service::ClientManagement for LocalClientHandle {
    async fn execute(
        &self,
        request: ClientPreferenceRequest,
    ) -> Result<ClientPreferenceView, String> {
        let (reply, result) = oneshot::channel();
        self.sender
            .try_send(LocalClientCommand { request, reply })
            .map_err(|_| "client_runtime_busy_or_stopped".to_owned())?;
        result
            .await
            .map_err(|_| "client_runtime_stopped".to_owned())?
    }
}
struct LinuxClientState {
    store: ClientPreferenceStore,
    exit: Option<ExitHost>,
    lan: Vec<ipnet::IpNet>,
    failure: Option<String>,
}
impl LinuxClientState {
    fn new(config: &LinuxConfig, store: ClientPreferenceStore) -> Self {
        Self {
            store,
            exit: Some(ExitHost::new(config)),
            lan: vec![],
            failure: None,
        }
    }
    async fn command(
        &mut self,
        command: LocalClientCommand,
        config: &LinuxConfig,
        wireguard: &WireguardPath,
    ) {
        let result = match command.request {
            ClientPreferenceRequest::Get {} => Ok(()),
            ClientPreferenceRequest::Set { change } => self.change(change, config, wireguard).await,
        };
        let view = match result {
            Ok(()) => Ok(self.view(wireguard).await),
            Err(error) => Err(error),
        };
        let _ = command.reply.send(view);
    }
    async fn change(
        &mut self,
        change: peerward_management::PreferenceChange,
        config: &LinuxConfig,
        wireguard: &WireguardPath,
    ) -> Result<(), String> {
        let changed = self.store.validate_change(&change).map_err(|error| {
            match error {
                peerward_platform::PlatformError::OwnershipConflict => {
                    "preferences_version_conflict"
                }
                _ => "invalid_client_preferences",
            }
            .to_owned()
        })?;
        if !changed {
            self.reconcile(config, change.preferences.exit_resource.is_none())
                .await;
            return Ok(());
        }
        let explicit_disable = change.preferences.exit_resource.is_none();
        if let Some(selected) = change.preferences.exit_resource {
            let mut core = wireguard.core.lock().await;
            let local = core.local_peer();
            let Some((resources, _)) =
                core.resource_network_configuration(UnixTime(wall_clock_seconds()))
            else {
                return Err("configuration_unavailable_retry_after_authorization".into());
            };
            if !resources.resources.iter().any(|resource| {
                resource.id == selected
                    && matches!(
                        resource.definition.target,
                        peerward_management::ResourceTarget::Internet { .. }
                    )
            }) || !resources.bindings.iter().any(|binding| {
                binding.resource_id == selected && binding.peer_id != local && binding.approved
            }) {
                return Err("exit_not_approved_for_remote_provider".into());
            }
        }
        let lan = selected_lan(config, &change.preferences)
            .await
            .map_err(|_| "local_lan_observation_failed".to_owned())?;
        wireguard
            .core
            .lock()
            .await
            .set_resource_platform_ready(false);
        if let Some(selected) = change.preferences.exit_resource {
            let mut exit = self.exit.take().ok_or("exit_operation_unavailable")?;
            let config = config.clone();
            let lan = lan.clone();
            let (exit, result) = tokio::task::spawn_blocking(move || {
                let result = exit.arm(&config, selected, lan);
                (exit, result)
            })
            .await
            .map_err(|_| "exit_operation_failed".to_owned())?;
            self.exit = Some(exit);
            result.map_err(|error| {
                self.failure = Some(format!("exit_guard_failed: {error}"));
                "exit_guard_failed_protection_requires_attention".to_owned()
            })?;
        }
        // Persistence completes even if the requesting local socket disconnects.
        self.store
            .commit(change)
            .map_err(|_| "preferences_save_failed_existing_exit_guard_retained".to_owned())?;
        wireguard
            .core
            .lock()
            .await
            .set_preferences(self.store.saved().preferences.clone())
            .map_err(|_| "invalid_client_preferences".to_owned())?;
        self.lan = lan;
        self.failure = None;
        self.reconcile(config, explicit_disable).await;
        Ok(())
    }
    async fn reconcile(&mut self, config: &LinuxConfig, explicit_disable: bool) {
        let preferences = self.store.saved().preferences.clone();
        let Ok(lan) = selected_lan(config, &preferences).await else {
            self.failure = Some("local_lan_observation_failed".into());
            return;
        };
        let Some(mut exit) = self.exit.take() else {
            self.failure = Some("exit_operation_unavailable".into());
            return;
        };
        let config = config.clone();
        let candidate_lan = lan.clone();
        match tokio::task::spawn_blocking(move || {
            let result = exit.apply(&config, &preferences, candidate_lan, explicit_disable);
            (exit, result)
        })
        .await
        {
            Ok((exit, result)) => {
                self.exit = Some(exit);
                self.failure = result
                    .err()
                    .map(|error| format!("exit_host_application_failed: {error}"));
                self.lan = lan;
            }
            Err(_) => self.failure = Some("exit_operation_failed_guard_retained".into()),
        }
    }
    async fn view(&self, wireguard: &WireguardPath) -> ClientPreferenceView {
        let mut core = wireguard.core.lock().await;
        let local = core.local_peer();
        let configuration = core.resource_network_configuration(UnixTime(wall_clock_seconds()));
        let exits = configuration
            .as_ref()
            .map_or_else(Vec::new, |(resources, _)| {
                resources
                    .resources
                    .iter()
                    .filter_map(|resource| {
                        if let peerward_management::ResourceTarget::Internet { ipv4, ipv6 } =
                            resource.definition.target
                        {
                            let providers = resources
                                .bindings
                                .iter()
                                .filter(|binding| {
                                    binding.resource_id == resource.id
                                        && binding.peer_id != local
                                        && binding.approved
                                })
                                .count();
                            (providers > 0).then(|| ExitChoice {
                                resource_id: resource.id,
                                name: resource.definition.name.clone(),
                                ipv4,
                                ipv6,
                                providers,
                            })
                        } else {
                            None
                        }
                    })
                    .collect()
            });
        ClientPreferenceView {
            version: self.store.saved().version,
            preferences: self.store.saved().preferences.clone(),
            application: if self.failure.is_some() {
                PreferenceApplication::Rejected
            } else if configuration.is_none() {
                PreferenceApplication::Unknown
            } else if core.resource_platform_ready() {
                PreferenceApplication::Applied
            } else {
                PreferenceApplication::Pending
            },
            reason: self
                .failure
                .clone()
                .or_else(|| {
                    (configuration.is_some()
                        && !core.device_admitted(local, UnixTime(wall_clock_seconds())))
                    .then(|| "device_conditions_restricted_check_control_evidence".into())
                })
                .or_else(|| {
                    configuration
                        .is_none()
                        .then(|| "authorization_or_configuration_unavailable".into())
                }),
            exits,
            local_lan: self.lan.clone(),
            gateway_paths: core.gateway_path_observations(Instant::now()),
        }
    }
    async fn shutdown(mut self) -> Result<(), PacketPumpError> {
        let Some(mut exit) = self.exit.take() else {
            return Err(PacketPumpError::InvalidControl);
        };
        tokio::task::spawn_blocking(move || exit.routing.shutdown())
            .await
            .map_err(|_| PacketPumpError::InvalidControl)?
            .map_err(platform_packet_error)
    }
}
