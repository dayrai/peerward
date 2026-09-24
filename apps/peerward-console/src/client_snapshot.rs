impl ApiClient {
    /// Loads one complete route snapshot without exposing transport details to UI code.
    pub async fn route_snapshot(
        &self,
        route: ConsoleRoute,
        selected_mesh: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<ConsoleSnapshot, ConsoleApiError> {
        self.route_snapshot_filtered(route, selected_mesh, cursor, None)
            .await
    }

    /// Loads a complete route snapshot with an optional Relay-scoped Peer drill-down.
    pub async fn route_snapshot_filtered(
        &self,
        route: ConsoleRoute,
        selected_mesh: Option<&str>,
        cursor: Option<&str>,
        relay_filter: Option<&str>,
    ) -> Result<ConsoleSnapshot, ConsoleApiError> {
        let session = self.auth_session().await?;
        let meshes = if session.capabilities.iter().any(|capability| capability == "resource_read") {
            self.mesh_page_with_selection(selected_mesh).await?
        } else {
            Page { items: Vec::new(), next_cursor: None }
        };
        let mesh_options = meshes
            .items
            .iter()
            .cloned()
            .map(ResourceSummary::from)
            .collect();
        let selected = selected_mesh.and_then(|id| {
            meshes
                .items
                .iter()
                .find(|mesh| mesh.id.to_string() == id)
        });
        let mesh_id = selected.map_or_else(String::new, |mesh| mesh.id.to_string());
        let mesh_name =
            selected.map_or_else(|| "No mesh selected".into(), |mesh| mesh.name.clone());
        let (resources, next_cursor) = match route {
            ConsoleRoute::Operations if !mesh_id.is_empty() => {
                (self.topology_resources(&mesh_id).await?, None)
            }
            ConsoleRoute::Meshes | ConsoleRoute::Networks => (
                meshes
                    .items
                    .into_iter()
                    .map(ResourceSummary::from)
                    .collect(),
                meshes.next_cursor,
            ),
            ConsoleRoute::Peers if !mesh_id.is_empty() && relay_filter.is_some() => {
                let page = self
                    .topology_nodes(&mesh_id, "peer", relay_filter, None, cursor, 50)
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
                let policy = self.policy(&mesh_id).await?;
                let policy = body_value(&policy)?;
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
            meshes: mesh_options,
            mesh_id,
            mesh_name,
            role: session.role,
            capabilities: session.capabilities,
            csrf_token: session.csrf_token,
            healthy: true,
            resources,
            lookups,
            error: None,
            next_cursor,
            relay_filter: relay_filter.map(str::to_owned),
        })
    }

    async fn list<T: DeserializeOwned>(
        &self,
        path: &str,
        cursor: Option<&str>,
        limit: u16,
    ) -> Result<Page<T>, ConsoleApiError> {
        let bounded = limit.clamp(1, 500);
        let mut request = self
            .authorized(self.http.get(self.url(path)))
            .query(&[("limit", bounded)]);
        if let Some(value) = cursor {
            request = request.query(&[("cursor", value)]);
        }
        self.decode(
            request
                .timeout(std::time::Duration::from_secs(15))
                .send()
                .await?,
        )
        .await
    }

    async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> Result<T, ConsoleApiError> {
        let mutation = !matches!(method, Method::GET | Method::HEAD);
        let mut request = self.authorized(self.http.request(method, self.url(path)));
        if mutation
            && let Some(token) = &self.csrf {
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

    fn authorized(&self, mut request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(cookie) = &self.cookie {
            request = request.header(reqwest::header::COOKIE, cookie);
        }
        if let Some(token) = &self.development_bearer {
            request = request.bearer_auth(token);
        }
        apply_outbound_correlation(request, self.correlation)
    }

    async fn decode<T: DeserializeOwned>(
        &self,
        response: reqwest::Response,
    ) -> Result<T, ConsoleApiError> {
        if response.status().is_success() {
            if response.status() == StatusCode::NO_CONTENT {
                return serde_json::from_value(json!({}))
                    .map_err(|_| ConsoleApiError::InvalidResponse);
            }
            let bytes = read_bounded_response(response, 2 * 1024 * 1024).await?;
            return serde_json::from_slice(&bytes).map_err(|_| ConsoleApiError::InvalidResponse);
        }
        Err(self.decode_error(response).await)
    }

    async fn decode_error(&self, response: reqwest::Response) -> ConsoleApiError {
        match read_bounded_response(response, 64 * 1024).await {
            Ok(bytes) => serde_json::from_slice::<ErrorEnvelope>(&bytes).map_or(
                ConsoleApiError::InvalidResponse,
                |body| ConsoleApiError::Server(body.error),
            ),
            Err(error) => error,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
}

include!("response_limits.rs");
include!("resource_refresh.rs");
include!("peer_client.rs");

fn body_value<T: Serialize>(body: &T) -> Result<Value, ConsoleApiError> {
    serde_json::to_value(body).map_err(|_| ConsoleApiError::InvalidResponse)
}
