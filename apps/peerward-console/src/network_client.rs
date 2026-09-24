#[derive(Clone, Default, PartialEq)]
struct NetworkPanelData {
    resources: Vec<peerward_management::NetworkResource>,
    bindings: Vec<peerward_management::GatewayBinding>,
    peers: Vec<PeerResource>,
    next_cursor: Option<String>,
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
impl ApiClient {
    async fn network_panel(
        &self,
        mesh: &str,
        cursor: Option<&str>,
    ) -> Result<NetworkPanelData, ConsoleApiError> {
        let base = format!("/api/v1/meshes/{mesh}");
        let resources: Page<peerward_management::NetworkResource> = self
            .list(&format!("{base}/network-resources"), cursor, 50)
            .await?;
        // Selectors must not silently treat a truncated list as the full approved set.
        let bindings = self
            .bounded_network_list(&format!("{base}/gateway-bindings"), 8192)
            .await?;
        let peers = self
            .bounded_network_list(&format!("{base}/peers"), 4096)
            .await?;
        Ok(NetworkPanelData {
            resources: resources.items,
            bindings,
            peers,
            next_cursor: resources.next_cursor,
        })
    }

    async fn bounded_network_list<T: DeserializeOwned>(
        &self,
        path: &str,
        limit: usize,
    ) -> Result<Vec<T>, ConsoleApiError> {
        let mut items = Vec::new();
        let mut cursor = None;
        let mut seen = HashSet::new();
        loop {
            let page: Page<T> = self.list(path, cursor.as_deref(), 100).await?;
            items.extend(page.items);
            if items.len() > limit {
                return Err(ConsoleApiError::ResponseTooLarge);
            }
            cursor = page.next_cursor;
            let Some(next) = &cursor else {
                return Ok(items);
            };
            if !seen.insert(next.clone()) {
                return Err(ConsoleApiError::InvalidResponse);
            }
        }
    }
}

#[derive(Clone, PartialEq)]
struct NetworkDraft {
    id: uuid::Uuid,
    name: String,
    prefix: String,
    site: uuid::Uuid,
    version: Option<u64>,
    labels: BTreeMap<String, String>,
    kind: String,
    probe_address: String,
    probe_port: String,
}
impl Default for NetworkDraft {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            name: String::new(),
            prefix: String::new(),
            site: uuid::Uuid::new_v4(),
            version: None,
            labels: BTreeMap::new(),
            kind: "subnet".into(),
            probe_address: String::new(),
            probe_port: String::new(),
        }
    }
}
impl NetworkDraft {
    fn from_resource(resource: &peerward_management::NetworkResource) -> Self {
        let mut draft = Self {
            id: resource.id,
            name: resource.definition.name.clone(),
            version: Some(resource.version),
            labels: resource.definition.labels.clone(),
            ..Self::default()
        };
        if let Some(probe) = &resource.definition.health_probe {
            draft.probe_address = probe.address.to_string();
            draft.probe_port = probe.port.to_string();
        }
        match resource.definition.target {
            peerward_management::ResourceTarget::Subnet { prefix, site_id } => {
                draft.prefix = prefix.to_string();
                draft.site = site_id;
            }
            peerward_management::ResourceTarget::Internet { ipv4, ipv6 } => {
                draft.kind = match (ipv4, ipv6) {
                    (true, true) => "internet_dual",
                    (true, false) => "internet_v4",
                    _ => "internet_v6",
                }
                .into();
            }
        }
        draft
    }
    fn definition(&self) -> Result<peerward_management::ResourceDefinition, &'static str> {
        let target = match self.kind.as_str() {
            "internet_dual" => peerward_management::ResourceTarget::Internet {
                ipv4: true,
                ipv6: true,
            },
            "internet_v4" => peerward_management::ResourceTarget::Internet {
                ipv4: true,
                ipv6: false,
            },
            "internet_v6" => peerward_management::ResourceTarget::Internet {
                ipv4: false,
                ipv6: true,
            },
            "subnet" => {
                let prefix = self
                    .prefix
                    .parse::<ipnet::IpNet>()
                    .or_else(|_| {
                        self.prefix
                            .parse::<std::net::IpAddr>()
                            .map(ipnet::IpNet::from)
                    })
                    .map_err(|_| "network-invalid-prefix")?;
                peerward_management::ResourceTarget::Subnet {
                    prefix,
                    site_id: self.site,
                }
            }
            _ => return Err("network-invalid-target"),
        };
        let definition = peerward_management::ResourceDefinition {
            name: self.name.trim().into(),
            target,
            labels: self.labels.clone(),
            health_probe: if self.probe_address.trim().is_empty()
                && self.probe_port.trim().is_empty()
            {
                None
            } else {
                Some(peerward_management::TargetProbe {
                    address: self
                        .probe_address
                        .trim()
                        .parse()
                        .map_err(|_| "network-invalid-probe")?,
                    port: self
                        .probe_port
                        .trim()
                        .parse()
                        .map_err(|_| "network-invalid-probe")?,
                })
            },
        };
        definition
            .validate()
            .map_err(|_| "network-invalid-target")?;
        Ok(definition)
    }
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
#[derive(Clone)]
enum NetworkOperation {
    Automatic {
        id: uuid::Uuid,
        version: u64,
    },
    Save(NetworkDraft),
    Priority {
        id: uuid::Uuid,
        version: u64,
        priority: u32,
    },
    Bind {
        id: uuid::Uuid,
        resource: uuid::Uuid,
        peer: uuid::Uuid,
        preserve: bool,
        confirmed: bool,
        priority: u32,
    },
    Approve {
        id: uuid::Uuid,
        version: u64,
        approved: bool,
    },
    Delete {
        id: uuid::Uuid,
        version: u64,
    },
    TargetHealth {
        resource: uuid::Uuid,
    },
    Observe {
        peer: uuid::Uuid,
    },
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
impl ApiClient {
    async fn network_operation(
        &self,
        mesh: &str,
        operation: NetworkOperation,
    ) -> Result<Value, ConsoleApiError> {
        let base = format!("/api/v1/meshes/{mesh}");
        match operation {
            NetworkOperation::Automatic{id,version}=>self.conditional_request(Method::POST,&format!("{base}/gateway-bindings/{id}/automatic-approval"),Some(json!({})),version).await,
            NetworkOperation::Save(draft) => {
                let definition = draft.definition().map_err(|_|ConsoleApiError::InvalidResponse)?;
                if let Some(version) = draft.version {
                    self.conditional_request(Method::PUT,&format!("{base}/network-resources/{}",draft.id),Some(body_value(&definition)?),version).await
                } else {
                    self.request(Method::POST,&format!("{base}/network-resources"),Some(json!({"id":draft.id,"definition":definition}))).await
                }
            }
            NetworkOperation::Bind { id,resource,peer,preserve,confirmed,priority } => self.request(Method::POST,&format!("{base}/gateway-bindings"),Some(json!({"id":id,"resource_id":resource,"peer_id":peer,"priority":priority,"forwarding":if preserve {"preserve_source"} else {"snat"},"return_route_confirmed":confirmed}))).await,
            NetworkOperation::Priority { id,version,priority } => self.conditional_request(Method::PATCH,&format!("{base}/gateway-bindings/{id}"),Some(json!({"priority":priority})),version).await,
            NetworkOperation::Approve { id,version,approved } => self.conditional_request(Method::PUT,&format!("{base}/gateway-bindings/{id}/approval"),Some(json!({"approved":approved})),version).await,
            NetworkOperation::Delete { id,version } => self.conditional_request(Method::DELETE,&format!("{base}/network-resources/{id}"),None,version).await,
            NetworkOperation::TargetHealth { resource } => self.request(Method::GET,&format!("{base}/network-resources/{resource}/health"),None).await,
            NetworkOperation::Observe { peer } => self.request(Method::GET,&format!("{base}/peers/{peer}/configuration-receipts"),None).await,
        }
    }
}
