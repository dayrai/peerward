impl ApiClient {
    async fn topology_resources(&self, mesh: &str) -> Result<Vec<ResourceSummary>, ConsoleApiError> {
        let summary = self.topology_summary(mesh).await?;
        let relays = self.topology_nodes(mesh, "relay", None, None, None, 200).await?;
        let edges = self.topology_edges(mesh, "backbone", None, 200).await?;
        Ok(topology_aggregate_summaries(summary, relays.items, edges.items))
    }

    /// Activates a staged Mesh Authority with an exact captured version.
    pub async fn activate_authority(
        &self,
        mesh: &str,
        authority: &str,
        version: u64,
    ) -> Result<Value, ConsoleApiError> {
        self.conditional_request(
            Method::POST,
            &format!("/api/v1/meshes/{mesh}/authorities/{authority}/activate"),
            None,
            version,
        )
        .await
    }

    async fn route_lookups(
        &self,
        route: ConsoleRoute,
        mesh: &str,
    ) -> Result<Vec<ResourceSummary>, ConsoleApiError> {
        if mesh.is_empty() || !matches!(route, ConsoleRoute::Services | ConsoleRoute::Policy) {
            return Ok(Vec::new());
        }
        let mut lookups = self
            .mesh_resources(mesh, ResourceFamily::Peers, None, 500)
            .await?
            .items;
        for resource in &mut lookups {
            resource.details.insert("lookup_kind".into(), json!("peer"));
        }
        if route == ConsoleRoute::Policy {
            let mut services = self
                .mesh_resources(mesh, ResourceFamily::Services, None, 500)
                .await?
                .items;
            for resource in &mut services {
                resource
                    .details
                    .insert("lookup_kind".into(), json!("service"));
            }
            lookups.extend(services);
        }
        Ok(lookups)
    }

    /// Loads the privacy-safe Peer-to-Relay presence and current health projection.
    pub async fn topology(&self, mesh: &str) -> Result<TopologyResource, ConsoleApiError> {
        self.request(
            Method::GET,
            &format!("/api/v1/meshes/{mesh}/topology"),
            None,
        )
        .await
    }

    /// Loads only database aggregates for the large-mesh topology landing view.
    pub async fn topology_summary(&self, mesh: &str) -> Result<TopologySummary, ConsoleApiError> {
        self.request(
            Method::GET,
            &format!("/api/v1/meshes/{mesh}/topology/summary"),
            None,
        )
        .await
    }

    /// Loads one bounded keyset page of topology nodes.
    pub async fn topology_nodes(
        &self,
        mesh: &str,
        kind: &str,
        relay_id: Option<&str>,
        region: Option<&str>,
        cursor: Option<&str>,
        limit: u16,
    ) -> Result<Page<TopologyNodeItem>, ConsoleApiError> {
        let query = {
            let mut serializer = url::form_urlencoded::Serializer::new(String::new());
            serializer.append_pair("kind", kind);
            serializer.append_pair("limit", &limit.to_string());
            if let Some(relay_id) = relay_id {
                serializer.append_pair("relay_id", relay_id);
            }
            if let Some(region) = region {
                serializer.append_pair("region", region);
            }
            if let Some(cursor) = cursor {
                serializer.append_pair("cursor", cursor);
            }
            serializer.finish()
        };
        let path = format!("/api/v1/meshes/{mesh}/topology/nodes?{query}");
        self.request(Method::GET, &path, None).await
    }

    /// Loads one bounded keyset page of topology edges.
    pub async fn topology_edges(
        &self,
        mesh: &str,
        kind: &str,
        cursor: Option<&str>,
        limit: u16,
    ) -> Result<Page<TopologyEdgeItem>, ConsoleApiError> {
        let mut path = format!("/api/v1/meshes/{mesh}/topology/edges?kind={kind}&limit={limit}");
        if let Some(cursor) = cursor {
            path.push_str("&cursor=");
            path.push_str(cursor);
        }
        self.request(Method::GET, &path, None).await
    }

    /// Uses the production evaluator to explain one source-to-service decision.
    pub async fn simulate_policy(
        &self,
        mesh: &str,
        body: &PolicySimulationRequest,
    ) -> Result<PolicySimulationResponse, ConsoleApiError> {
        self.request(
            Method::POST,
            &format!("/api/v1/meshes/{mesh}/policy/simulate"),
            Some(body_value(body)?),
        )
        .await
    }

    /// Validates up to 100 same-family mutations without changing state.
    pub async fn preview_bulk(
        &self,
        mesh: &str,
        body: &BulkRequest,
    ) -> Result<BulkPreviewResponse, ConsoleApiError> {
        self.request(
            Method::POST,
            &format!("/api/v1/meshes/{mesh}/bulk/preview"),
            Some(body_value(body)?),
        )
        .await
    }

    /// Commits exactly the versions returned by a successful bulk preview.
    pub async fn commit_bulk(
        &self,
        mesh: &str,
        body: &BulkRequest,
    ) -> Result<BulkCommitResponse, ConsoleApiError> {
        self.request(
            Method::POST,
            &format!("/api/v1/meshes/{mesh}/bulk/commit"),
            Some(body_value(body)?),
        )
        .await
    }

    async fn conditional_request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
        version: u64,
    ) -> Result<T, ConsoleApiError> {
        let mut request = self
            .authorized(self.http.request(method, self.url(path)))
            .header(reqwest::header::IF_MATCH, format!("\"{version}\""));
        if let Some(token) = &self.csrf {
            request = request.header("x-csrf-token", token);
        }
        if let Some(value) = body {
            request = request.json(&value);
        }
        self.decode(
            request
                .timeout(std::time::Duration::from_secs(15))
                .send()
                .await?,
        )
        .await
    }

    /// Lists metadata-only audit records in one Mesh.
    pub async fn audit(
        &self,
        mesh: &str,
        cursor: Option<&str>,
        limit: u16,
    ) -> Result<Page<ResourceSummary>, ConsoleApiError> {
        self.list::<AuditResource>(&format!("/api/v1/meshes/{mesh}/audit"), cursor, limit)
            .await
            .map(summary_page)
    }

    /// Lists metadata-only audit records without requiring resource visibility.
    pub async fn global_audit(
        &self,
        cursor: Option<&str>,
        limit: u16,
    ) -> Result<Page<ResourceSummary>, ConsoleApiError> {
        self.list::<AuditResource>("/api/v1/audit", cursor, limit)
            .await
            .map(summary_page)
    }

    /// Refreshes only route-scoped data while retaining the independent auth and Mesh caches.
    pub async fn route_resource_snapshot(
        &self,
        route: ConsoleRoute,
        current: &ConsoleSnapshot,
        selected_mesh: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<ConsoleSnapshot, ConsoleApiError> {
        let mut meshes = current.meshes.clone();
        if let Some(id) = selected_mesh.filter(|id| !id.is_empty())
            && !meshes.iter().any(|mesh| mesh.id == id)
        {
            match self.mesh(id).await {
                Ok(mesh) if mesh.lifecycle != "deleted" => {
                    // Keep the independent selector cache bounded while permitting a
                    // search result outside its first page to become the active Mesh.
                    meshes.truncate(100);
                    meshes.push(mesh.into());
                }
                Ok(_) => {}
                Err(ConsoleApiError::Server(error)) if error.code == "not_found" => {}
                Err(error) => return Err(error),
            }
        }
        let selected = selected_mesh.and_then(|id| {
            meshes
                .iter()
                .find(|mesh| mesh.id == id)
                .map(|mesh| (id.to_owned(), mesh.name.clone()))
        });
        let (mesh_id, mesh_name) =
            selected.unwrap_or_else(|| (String::new(), "No mesh selected".into()));
        let (resources, next_cursor) = match route {
            ConsoleRoute::Meshes | ConsoleRoute::Networks => (meshes.clone(), None),
            ConsoleRoute::Operations if !mesh_id.is_empty() => {
                (self.topology_resources(&mesh_id).await?, None)
            }
            ConsoleRoute::Peers if !mesh_id.is_empty() && current.relay_filter.is_some() => {
                let page = self
                    .topology_nodes(
                        &mesh_id,
                        "peer",
                        current.relay_filter.as_deref(),
                        None,
                        cursor,
                        50,
                    )
                    .await?;
                (
                    self.peer_node_resources(&mesh_id, page.items).await?,
                    page.next_cursor,
                )
            }
            ConsoleRoute::Peers
            | ConsoleRoute::Relays
            | ConsoleRoute::Authorities
            | ConsoleRoute::JoinTickets
            | ConsoleRoute::Services
                if !mesh_id.is_empty() =>
            {
                let family = match route {
                    ConsoleRoute::Authorities => ResourceFamily::Authorities,
                    ConsoleRoute::Peers => ResourceFamily::Peers,
                    ConsoleRoute::Relays => ResourceFamily::Relays,
                    ConsoleRoute::JoinTickets => ResourceFamily::JoinTickets,
                    ConsoleRoute::Services => ResourceFamily::Services,
                    _ => unreachable!(),
                };
                let page = self.mesh_resources(&mesh_id, family, cursor, 50).await?;
                (page.items, page.next_cursor)
            }
            ConsoleRoute::Audit if !mesh_id.is_empty() => {
                let page = self.audit(&mesh_id, cursor, 50).await?;
                (page.items, page.next_cursor)
            }
            ConsoleRoute::Audit => {
                let page = self.global_audit(cursor, 50).await?;
                (page.items, page.next_cursor)
            }
            ConsoleRoute::Policy if !mesh_id.is_empty() => {
                let policy = body_value(&self.policy(&mesh_id).await?)?;
                (
                    vec![ResourceSummary {
                        id: mesh_id.clone(),
                        name: "Current policy".into(),
                        details: policy.as_object().map_or_else(BTreeMap::new, |object| {
                            object
                                .iter()
                                .map(|(key, value)| (key.clone(), value.clone()))
                                .collect()
                        }),
                    }],
                    None,
                )
            }
            _ => (Vec::new(), None),
        };
        let lookups = self.route_lookups(route, &mesh_id).await?;
        Ok(ConsoleSnapshot {
            meshes,
            mesh_id,
            mesh_name,
            role: current.role.clone(),
            capabilities: current.capabilities.clone(),
            csrf_token: current.csrf_token.clone(),
            healthy: true,
            resources,
            lookups,
            error: None,
            next_cursor,
            relay_filter: current.relay_filter.clone(),
        })
    }
}

/// Appends one keyset page, deduplicates updates, and evicts old rows above 1,000.
pub fn append_resource_page(
    current: &ConsoleSnapshot,
    mut page: ConsoleSnapshot,
) -> ConsoleSnapshot {
    const MAX_CACHED_RESOURCE_ROWS: usize = 1_000;
    if current.mesh_id != page.mesh_id || current.relay_filter != page.relay_filter {
        return page;
    }
    let mut merged = current.resources.clone();
    for resource in page.resources.drain(..) {
        if let Some(existing) = merged.iter_mut().find(|item| item.id == resource.id) {
            *existing = resource;
        } else {
            merged.push(resource);
        }
    }
    if merged.len() > MAX_CACHED_RESOURCE_ROWS {
        merged.drain(..merged.len() - MAX_CACHED_RESOURCE_ROWS);
    }
    page.resources = merged;
    page
}

fn topology_aggregate_summaries(
    summary: TopologySummary,
    relays: Vec<TopologyNodeItem>,
    edges: Vec<TopologyEdgeItem>,
) -> Vec<ResourceSummary> {
    let mut overview = BTreeMap::new();
    overview.insert("kind".into(), json!("topology_summary"));
    overview.insert("peer_count".into(), json!(summary.peer_count));
    overview.insert("online_peer_count".into(), json!(summary.online_peer_count));
    overview.insert("relay_count".into(), json!(summary.relay_count));
    overview.insert(
        "online_relay_count".into(),
        json!(summary.online_relay_count),
    );
    overview.insert("presence_count".into(), json!(summary.presence_count));
    overview.insert("backbone_revision".into(), json!(summary.backbone_revision));
    overview.insert("backbone_mode".into(), json!(summary.backbone_mode));
    overview.insert(
        "backbone_edge_count".into(),
        json!(summary.backbone_edge_count),
    );
    let mut resources = vec![ResourceSummary {
        id: "topology-summary".into(),
        name: "Mesh topology".into(),
        details: overview,
    }];
    resources.extend(summary.regions.into_iter().map(|region| {
        let mut details = BTreeMap::new();
        details.insert("kind".into(), json!("region"));
        details.insert("region".into(), json!(region.region));
        details.insert("relay_count".into(), json!(region.relay_count));
        details.insert(
            "online_relay_count".into(),
            json!(region.online_relay_count),
        );
        details.insert("presence_count".into(), json!(region.presence_count));
        ResourceSummary {
            id: format!("region:{}", region.region),
            name: region.region,
            details,
        }
    }));
    resources.extend(relays.into_iter().map(|relay| {
        let mut details = BTreeMap::new();
        details.insert("kind".into(), json!("relay"));
        details.insert("online".into(), json!(relay.online));
        details.insert("region".into(), json!(relay.region));
        details.insert("routing_weight".into(), json!(relay.routing_weight));
        details.insert("presence_count".into(), json!(relay.presence_count));
        details.insert("credential_status".into(), json!(relay.credential_status));
        ResourceSummary {
            id: relay.id.to_string(),
            name: relay.name,
            details,
        }
    }));
    resources.extend(edges.into_iter().map(|edge| {
        let mut details = BTreeMap::new();
        details.insert("kind".into(), json!("backbone"));
        details.insert("source_id".into(), json!(edge.source_id));
        details.insert("target_id".into(), json!(edge.target_id));
        details.insert("revision".into(), json!(edge.revision));
        ResourceSummary {
            id: format!("{}:{}", edge.source_id, edge.target_id),
            name: "Backbone link".into(),
            details,
        }
    }));
    resources
}
