include!("client_types.rs");
/// Cookie-session and development-bearer aware typed client.
#[derive(Clone)]
pub struct ApiClient {
    base: String,
    http: reqwest::Client,
    csrf: Option<String>,
    cookie: Option<String>,
    development_bearer: Option<String>,
    correlation: CorrelationContext,
}

impl ApiClient {
    /// Creates a same-origin client rooted at the control service.
    pub fn new(base: impl Into<String>) -> Result<Self, ConsoleApiError> {
        let base = base.into();
        let parsed = url::Url::parse(&base).map_err(|_| ConsoleApiError::InvalidBaseUrl)?;
        if !matches!(parsed.scheme(), "http" | "https")
            || parsed.host_str().is_none()
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || parsed.path() != "/"
        {
            return Err(ConsoleApiError::InvalidBaseUrl);
        }
        let builder = reqwest::Client::builder();
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder
            .connect_timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none());
        let http = builder.build()?;
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            http,
            csrf: None,
            cookie: None,
            development_bearer: None,
            correlation: CorrelationContext::root(false),
        })
    }

    /// Installs the non-cookie CSRF value returned by `/auth/session`.
    #[must_use]
    pub fn with_csrf(mut self, token: impl Into<String>) -> Self {
        self.csrf = Some(token.into());
        self
    }

    /// Forwards the incoming browser cookie during server-side rendering.
    #[must_use]
    pub fn with_cookie_header(mut self, cookie: impl Into<String>) -> Self {
        self.cookie = Some(cookie.into());
        self
    }

    /// Enables the explicit development bearer flow when OIDC is disabled.
    #[must_use]
    pub fn with_development_bearer(mut self, token: impl Into<String>) -> Self {
        self.development_bearer = Some(token.into());
        self
    }

    /// Loads the current role and CSRF token.
    pub async fn auth_session(&self) -> Result<AuthSession, ConsoleApiError> {
        self.request(Method::GET, "/auth/session", None).await
    }

    /// Invalidates the server-side session using CSRF protection.
    pub async fn logout(&self) -> Result<Value, ConsoleApiError> {
        self.request(Method::POST, "/auth/logout", Some(json!({})))
            .await
    }

    /// Lists meshes with cursor pagination.
    pub async fn meshes(
        &self,
        cursor: Option<&str>,
        limit: u16,
    ) -> Result<Page<MeshResource>, ConsoleApiError> {
        self.list("/api/v1/meshes", cursor, limit).await
    }

    /// Creates a mesh.
    pub async fn create_mesh(
        &self,
        body: &MeshCreateRequest,
    ) -> Result<MeshResource, ConsoleApiError> {
        self.request(Method::POST, "/api/v1/meshes", Some(body_value(body)?))
            .await
    }

    /// Reads one mesh.
    pub async fn mesh(&self, mesh: &str) -> Result<MeshResource, ConsoleApiError> {
        self.request(Method::GET, &format!("/api/v1/meshes/{mesh}"), None)
            .await
    }

    /// Updates one mesh.
    pub async fn update_mesh(
        &self,
        mesh: &str,
        body: &MeshPatchRequest,
        version: u64,
    ) -> Result<MeshResource, ConsoleApiError> {
        self.conditional_request(
            Method::PATCH,
            &format!("/api/v1/meshes/{mesh}"),
            Some(body_value(body)?),
            version,
        )
            .await
    }

    /// Deletes an empty mesh after exact-name confirmation.
    pub async fn delete_mesh(
        &self,
        mesh: &str,
        body: &MeshDeleteRequest,
        version: u64,
    ) -> Result<Value, ConsoleApiError> {
        self.conditional_request(
            Method::DELETE,
            &format!("/api/v1/meshes/{mesh}"),
            Some(body_value(body)?),
            version,
        ).await
    }

    /// Lists one mesh-scoped resource family.
    pub async fn mesh_resources(
        &self,
        mesh: &str,
        family: ResourceFamily,
        cursor: Option<&str>,
        limit: u16,
    ) -> Result<Page<ResourceSummary>, ConsoleApiError> {
        let path = family.collection_path(mesh);
        match family {
            ResourceFamily::Authorities => self
                .list::<AuthorityResource>(&path, cursor, limit)
                .await
                .map(summary_page),
            ResourceFamily::Peers => self
                .list::<PeerResource>(&path, cursor, limit)
                .await
                .map(summary_page),
            ResourceFamily::Relays => self
                .list::<RelayResource>(&path, cursor, limit)
                .await
                .map(summary_page),
            ResourceFamily::JoinTickets => self
                .list::<JoinTicketResource>(&path, cursor, limit)
                .await
                .map(summary_page),
            ResourceFamily::Services => self
                .list::<ServiceResource>(&path, cursor, limit)
                .await
                .map(summary_page),
        }
    }

    /// Creates a Peer using the shared `/api/v1` contract.
    pub async fn create_peer(
        &self,
        mesh: &str,
        body: &PeerCreateRequest,
    ) -> Result<PeerResource, ConsoleApiError> {
        self.request(
            Method::POST,
            &ResourceFamily::Peers.collection_path(mesh),
            Some(body_value(body)?),
        )
        .await
    }

    /// Stages one Root-signed Authority certificate.
    pub async fn stage_authority(
        &self,
        mesh: &str,
        body: &AuthorityStageRequest,
    ) -> Result<AuthorityResource, ConsoleApiError> {
        self.request(
            Method::POST,
            &ResourceFamily::Authorities.collection_path(mesh),
            Some(body_value(body)?),
        )
        .await
    }

    /// Creates a Relay with validated endpoint sets.
    pub async fn create_relay(
        &self,
        mesh: &str,
        body: &RelayCreateRequest,
    ) -> Result<RelayResource, ConsoleApiError> {
        self.request(
            Method::POST,
            &ResourceFamily::Relays.collection_path(mesh),
            Some(body_value(body)?),
        )
        .await
    }

    /// Atomically creates one TCP, UDP, or dual-protocol service.
    pub async fn create_service(
        &self,
        mesh: &str,
        body: &ServiceCreateRequest,
    ) -> Result<ServiceResource, ConsoleApiError> {
        self.request(
            Method::POST,
            &ResourceFamily::Services.collection_path(mesh),
            Some(body_value(body)?),
        )
        .await
    }

    pub async fn create_join_ticket(
        &self,
        mesh: &str,
        body: &JoinTicketCreateRequest,
    ) -> Result<peerward_api::JoinTicketCreateResponse, ConsoleApiError> {
        self.request(
            Method::POST,
            &ResourceFamily::JoinTickets.collection_path(mesh),
            Some(body_value(body)?),
        )
        .await
    }

    pub async fn update_peer(
        &self,
        mesh: &str,
        id: &str,
        body: &PeerPatchRequest,
        version: u64,
    ) -> Result<PeerResource, ConsoleApiError> {
        self.conditional_request(
            Method::PATCH,
            &ResourceFamily::Peers.member_path(mesh, id),
            Some(body_value(body)?),
            version,
        )
        .await
    }

    pub async fn update_relay(
        &self,
        mesh: &str,
        id: &str,
        body: &RelayPatchRequest,
        version: u64,
    ) -> Result<RelayResource, ConsoleApiError> {
        self.conditional_request(
            Method::PATCH,
            &ResourceFamily::Relays.member_path(mesh, id),
            Some(body_value(body)?),
            version,
        )
        .await
    }

    pub async fn delete_resource(
        &self,
        mesh: &str,
        family: ResourceFamily,
        id: &str,
        version: u64,
    ) -> Result<Value, ConsoleApiError> {
        self.conditional_request(Method::DELETE, &family.member_path(mesh, id), None, version)
            .await
    }

    pub async fn rotate_credential(
        &self,
        mesh: &str,
        family: CredentialSubject,
        id: &str,
        body: &CredentialRotationRequest,
        version: u64,
    ) -> Result<CredentialResource, ConsoleApiError> {
        let path = format!("{}/credentials/rotate", family.member_path(mesh, id));
        self.conditional_request(Method::POST, &path, Some(body_value(body)?), version).await
    }

    pub async fn credentials(
        &self,
        mesh: &str,
        family: CredentialSubject,
        id: &str,
        cursor: Option<&str>,
        limit: u16,
    ) -> Result<Page<ResourceSummary>, ConsoleApiError> {
        let path = format!("{}/credentials", family.member_path(mesh, id));
        self.list::<CredentialResource>(&path, cursor, limit)
            .await
            .map(summary_page)
    }

    /// Activates one staged peer or relay credential by serial.
    pub async fn activate_credential(
        &self,
        mesh: &str,
        family: CredentialSubject,
        id: &str,
        serial: &str,
        version: u64,
    ) -> Result<Value, ConsoleApiError> {
        let path = format!("{}/credentials/{serial}", family.member_path(mesh, id));
        self.conditional_request(Method::POST, &path, None, version).await
    }

    /// Revokes one peer or relay credential by serial.
    pub async fn revoke_credential(
        &self,
        mesh: &str,
        family: CredentialSubject,
        id: &str,
        serial: &str,
        version: u64,
    ) -> Result<Value, ConsoleApiError> {
        let path = format!("{}/credentials/{serial}", family.member_path(mesh, id));
        self.conditional_request(Method::DELETE, &path, None, version).await
    }

    /// Reads the complete current policy document.
    pub async fn policy(&self, mesh: &str) -> Result<PolicyPutRequest, ConsoleApiError> {
        self.request(Method::GET, &format!("/api/v1/meshes/{mesh}/policy"), None)
            .await
    }

    /// Validates and normalizes a policy without changing authoritative state.
    pub async fn validate_policy(
        &self,
        mesh: &str,
        body: &PolicyPutRequest,
    ) -> Result<PolicyValidationResponse, ConsoleApiError> {
        self.request(
            Method::POST,
            &format!("/api/v1/meshes/{mesh}/policy/validate"),
            Some(body_value(body)?),
        )
        .await
    }

    /// Atomically replaces the mesh policy.
    pub async fn replace_policy(
        &self,
        mesh: &str,
        body: &PolicyPutRequest,
    ) -> Result<PolicyPutRequest, ConsoleApiError> {
        self.request(
            Method::PUT,
            &format!("/api/v1/meshes/{mesh}/policy"),
            Some(body_value(body)?),
        )
        .await
    }

    /// Opens the SSE endpoint with optional cursor replay.
    pub async fn events(
        &self,
        last_event_id: Option<&str>,
    ) -> Result<reqwest::Response, ConsoleApiError> {
        let mut request = self.authorized(self.http.get(self.url("/api/v1/events")));
        // A cached 410 must not survive clearing Last-Event-ID on reconnect.
        #[cfg(target_arch = "wasm32")]
        {
            request = request.fetch_cache_no_store();
        }
        if let Some(cursor) = last_event_id {
            request = request.header("Last-Event-ID", cursor);
        }
        let response = request.send().await?;
        if response.status().is_success() {
            Ok(response)
        } else {
            Err(self.decode_error(response).await)
        }
    }

}
include!("client_snapshot.rs");
