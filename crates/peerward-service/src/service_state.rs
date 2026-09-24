#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceState {
    config_version: u32,
    services: Vec<ServiceRecord>,
}

struct Registry {
    state: ServiceState,
    store: AtomicStateStore,
}

impl Registry {
    fn load(path: PathBuf) -> Result<Self, ServiceError> {
        let store = AtomicStateStore::new(path);
        let state = match store.load::<ServiceState>() {
            Ok(value) if value.config_version == 1 => value,
            Ok(_) | Err(PlatformError::Encoding(_)) => return Err(ServiceError::Invalid),
            Err(PlatformError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                ServiceState {
                    config_version: 1,
                    services: Vec::new(),
                }
            }
            Err(error) => return Err(error.into()),
        };
        Ok(Self { state, store })
    }

    fn publish(
        &mut self,
        listen_port: u16,
        target: SocketAddr,
        protocols: Vec<ServiceProtocol>,
        alias: Option<String>,
    ) -> Result<ServiceRecord, ServiceError> {
        if listen_port == 0
            || target.port() == 0
            || !target.ip().is_loopback()
            || !valid_protocols(&protocols)
            || alias.as_deref().is_some_and(|name| !valid_label(name))
        {
            return Err(ServiceError::Invalid);
        }
        if let Some(name) = &alias
            && self.state.services.iter().any(|service| {
                service
                    .alias
                    .as_ref()
                    .is_some_and(|old| old.eq_ignore_ascii_case(name))
            })
        {
            return Err(ServiceError::Invalid);
        }
        let record = ServiceRecord {
            id: ServiceId::new(),
            protocols,
            listen_port,
            target,
            alias,
        };
        self.state.services.push(record.clone());
        self.persist()?;
        Ok(record)
    }

    fn remove(&mut self, id: ServiceId) -> Result<ServiceRecord, ServiceError> {
        let index = self
            .state
            .services
            .iter()
            .position(|service| service.id == id)
            .ok_or(ServiceError::NotFound)?;
        let removed = self.state.services.remove(index);
        self.persist()?;
        Ok(removed)
    }

    fn persist(&self) -> Result<(), ServiceError> {
        self.store.save(&self.state)?;
        Ok(())
    }
}
