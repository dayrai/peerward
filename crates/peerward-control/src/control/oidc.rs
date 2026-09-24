#[derive(Deserialize, Default)]
struct LoginQuery {
    return_to: Option<String>,
    #[serde(default)]
    reauthenticate: bool,
}

fn safe_console_return(value: Option<&str>) -> String {
    let Some(value) = value.filter(|v| {
        v.len() <= 2048
            && v.starts_with('/')
            && !v.starts_with("//")
            && !v.contains('\\')
            && !v.chars().any(char::is_control)
    }) else {
        return "/".into();
    };
    let Ok(url) = url::Url::parse(&format!("https://console.invalid{value}")) else {
        return "/".into();
    };
    if url.host_str() != Some("console.invalid")
        || !matches!(
            url.path(),
            "/" | "/peers"
                | "/services"
                | "/policy"
                | "/operations"
                | "/meshes"
                | "/join-tickets"
                | "/relays"
                | "/authorities"
                | "/audit"
                | "/webhooks"
                | "/networks"
        )
    {
        return "/".into();
    }
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in url.query_pairs() {
        if matches!(k.as_ref(), "mesh" | "resource" | "relay") && Uuid::parse_str(&v).is_ok() {
            query.append_pair(&k, &v);
        }
    }
    let query = query.finish();
    if query.is_empty() {
        url.path().into()
    } else {
        format!("{}?{query}", url.path())
    }
}
async fn auth_login(
    State(state): State<AppState>,
    Query(query): Query<LoginQuery>,
) -> Result<Response, ApiError> {
    let oidc = state
        .auth
        .oidc
        .clone()
        .ok_or_else(|| ApiError::invalid("oidc_disabled", "OIDC is disabled"))?;
    let http = oidc_http_client()?;
    let provider = discover_provider(&oidc, &http).await?;
    let client = CoreClient::from_provider_metadata(
        provider,
        ClientId::new(oidc.client_id.clone()),
        oidc.client_secret.clone().map(ClientSecret::new),
    )
    .set_redirect_uri(
        RedirectUrl::new(oidc.redirect_uri.to_string())
            .map_err(|_| ApiError::invalid("invalid_oidc_config", "invalid callback URL"))?,
    );
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let mut request = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(challenge);
    if query.reauthenticate {
        request = request
            .add_extra_param("prompt", "login")
            .set_max_age(Duration::ZERO);
    }
    for scope in oidc.scopes.split_whitespace() {
        request = request.add_scope(Scope::new(scope.to_owned()));
    }
    let (destination, state_secret, nonce) = request.url();
    state
        .store
        .create_oidc_flow(&NewOidcFlow {
            state: state_secret.secret().clone(),
            return_to: safe_console_return(query.return_to.as_deref()),
            reauthenticate: query.reauthenticate,
            nonce: nonce.secret().clone(),
            pkce_verifier: verifier.secret().clone(),
            redirect_uri: oidc.redirect_uri.to_string(),
            expires_at: OffsetDateTime::now_utc() + TimeDuration::minutes(10),
        })
        .await?;
    Ok((
        StatusCode::FOUND,
        [(header::LOCATION, destination.to_string())],
    )
        .into_response())
}

#[derive(Deserialize)]
struct CallbackQuery {
    state: String,
    code: Option<String>,
    error: Option<String>,
}

async fn auth_callback(
    State(state): State<AppState>,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, ApiError> {
    if let Some(error) = query.error {
        return Err(ApiError::unauthorized(
            "oidc_provider_error",
            if error.is_empty() {
                "OIDC provider rejected authentication"
            } else {
                "OIDC provider returned an authentication error"
            },
        ));
    }
    let code = query
        .code
        .filter(|code| !code.is_empty())
        .ok_or_else(|| ApiError::unauthorized("invalid_code", "authorization code missing"))?;
    let flow = state
        .store
        .consume_oidc_flow(&query.state)
        .await
        .map_err(|error| match error {
            StoreError::Conflict | StoreError::SignedStateConflict { .. } => {
                ApiError::unauthorized("invalid_state", "OIDC state invalid")
            }
            other => ApiError::from(other),
        })?;
    let oidc = state
        .auth
        .oidc
        .clone()
        .ok_or_else(|| ApiError::invalid("oidc_disabled", "OIDC is disabled"))?;
    if flow.redirect_uri != oidc.redirect_uri.as_str() {
        return Err(ApiError::unauthorized(
            "invalid_redirect",
            "OIDC callback binding changed",
        ));
    }
    let http = oidc_http_client()?;
    let provider = discover_provider(&oidc, &http).await?;
    let client = CoreClient::from_provider_metadata(
        provider,
        ClientId::new(oidc.client_id.clone()),
        oidc.client_secret.clone().map(ClientSecret::new),
    )
    .set_redirect_uri(
        RedirectUrl::new(oidc.redirect_uri.to_string())
            .map_err(|_| ApiError::invalid("invalid_oidc_config", "invalid callback URL"))?,
    );
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|_| ApiError::unavailable("oidc_exchange", "OIDC token endpoint unavailable"))?
        .set_pkce_verifier(PkceCodeVerifier::new(flow.pkce_verifier))
        .request_async(&http)
        .await
        .map_err(|_| ApiError::unauthorized("oidc_exchange", "OIDC code exchange failed"))?;
    let id_token = token_response
        .extra_fields()
        .id_token()
        .ok_or_else(|| ApiError::unauthorized("missing_id_token", "OIDC ID token missing"))?;
    let claims = id_token
        .claims(&client.id_token_verifier(), &Nonce::new(flow.nonce))
        .map_err(|_| ApiError::unauthorized("invalid_id_token", "OIDC ID token invalid"))?;
    if flow.reauthenticate
        && claims
            .auth_time()
            .is_none_or(|time| time.timestamp() < flow.created_at.unix_timestamp() - 30)
    {
        return Err(ApiError::unauthorized(
            "reauthentication_required",
            "identity provider did not confirm a fresh authentication",
        ));
    }
    let groups = token_groups(&id_token.to_string(), &oidc.groups_claim)?;
    let role = mapped_role(&groups, &oidc);
    let token = random_secret();
    let csrf = random_secret();
    state
        .store
        .create_session(&NewSession {
            token: token.clone(),
            csrf_token: csrf.clone(),
            subject: claims.subject().as_str().to_owned(),
            role,
            expires_at: OffsetDateTime::now_utc() + TimeDuration::hours(8),
        })
        .await?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::LOCATION,
        HeaderValue::from_str(&safe_console_return(Some(&flow.return_to)))
            .map_err(|_| publisher_error())?,
    );
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "peerward_session={token}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=28800"
        ))
        .map_err(|_| ApiError::unavailable("session_cookie", "session cookie unavailable"))?,
    );
    headers.append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "peerward_csrf={csrf}; Path=/; Secure; SameSite=Strict; Max-Age=28800"
        ))
        .map_err(|_| ApiError::unavailable("session_cookie", "CSRF cookie unavailable"))?,
    );
    Ok((StatusCode::FOUND, headers).into_response())
}

fn oidc_http_client() -> Result<oidc_reqwest::Client, ApiError> {
    oidc_reqwest::ClientBuilder::new()
        .redirect(oidc_reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| ApiError::unavailable("oidc_http", "OIDC HTTP client unavailable"))
}

/// Verifies issuer discovery using the same strict client as interactive login.
pub async fn check_oidc_provider(oidc: &OidcConfig) -> Result<(), ApiError> {
    let http = oidc_http_client()?;
    discover_provider(oidc, &http).await.map(|_| ())
}

async fn discover_provider(
    oidc: &OidcConfig,
    http: &oidc_reqwest::Client,
) -> Result<CoreProviderMetadata, ApiError> {
    let issuer = IssuerUrl::new(oidc.issuer_url.to_string())
        .map_err(|_| ApiError::invalid("invalid_oidc_config", "invalid issuer URL"))?;
    CoreProviderMetadata::discover_async(issuer, http)
        .await
        .map_err(|_| ApiError::unavailable("oidc_discovery", "OIDC discovery failed"))
}

fn token_groups(token: &str, claim: &str) -> Result<Vec<String>, ApiError> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or_else(|| ApiError::unauthorized("invalid_id_token", "OIDC ID token malformed"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| ApiError::unauthorized("invalid_id_token", "OIDC ID token malformed"))?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::unauthorized("invalid_id_token", "OIDC ID token malformed"))?;
    let groups = match value.get(claim) {
        Some(Value::String(group)) => vec![group.clone()],
        Some(Value::Array(groups)) => groups
            .iter()
            .map(|group| {
                group.as_str().map(str::to_owned).ok_or_else(|| {
                    ApiError::unauthorized("invalid_groups", "OIDC groups claim is invalid")
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        None => Vec::new(),
        _ => {
            return Err(ApiError::unauthorized(
                "invalid_groups",
                "OIDC groups claim is invalid",
            ));
        }
    };
    Ok(groups)
}

fn mapped_role(groups: &[String], oidc: &OidcConfig) -> Role {
    if groups.iter().any(|group| oidc.admin_groups.contains(group)) {
        Role::Admin
    } else if groups
        .iter()
        .any(|group| oidc.operator_groups.contains(group))
    {
        Role::Operator
    } else if groups
        .iter()
        .any(|group| oidc.auditor_groups.contains(group))
    {
        Role::Auditor
    } else {
        Role::Viewer
    }
}

#[derive(Deserialize)]
struct BootstrapBody {
    token: String,
    #[serde(default = "empty_object")]
    oidc: Value,
}

async fn auth_bootstrap(
    State(state): State<AppState>,
    ApiJson(body): ApiJson<BootstrapBody>,
) -> Result<Json<Value>, ApiError> {
    let expected = state.auth.bootstrap_digest.ok_or_else(|| {
        ApiError::forbidden("bootstrap_disabled", "bootstrap token is not configured")
    })?;
    if !constant_time_digest_eq(secret_digest(body.token.as_bytes()), expected) {
        return Err(ApiError::unauthorized(
            "invalid_bootstrap",
            "invalid bootstrap token",
        ));
    }
    state
        .store
        .complete_bootstrap("bootstrap-token", &body.oidc)
        .await?;
    Ok(Json(json!({"status":"bootstrapped"})))
}

async fn auth_session(
    Extension(context): Extension<AuthContext>,
    headers: HeaderMap,
) -> Result<Json<Value>, ApiError> {
    let csrf_token = match context.source {
        AuthSource::Bearer => None,
        AuthSource::Machine(_) | AuthSource::DeploymentRunner(_) => {
            return Err(ApiError::forbidden(
                "machine_session_forbidden",
                "machine credentials cannot create browser sessions",
            ));
        }
        AuthSource::Session(expected) => {
            let token = cookie_value(&headers, "peerward_csrf").ok_or_else(|| {
                ApiError::forbidden("csrf_cookie_required", "CSRF cookie required")
            })?;
            if !constant_time_digest_eq(secret_digest(token.as_bytes()), expected) {
                return Err(ApiError::forbidden(
                    "csrf_cookie_invalid",
                    "CSRF cookie invalid",
                ));
            }
            Some(token)
        }
    };
    Ok(Json(json!({
        "authenticated": true,
        "actor": context.actor,
        "role": context.role,
        "capabilities": context.role.capabilities().iter().map(|capability| capability.as_str()).collect::<Vec<_>>(),
        "csrf_token": csrf_token,
    })))
}

async fn logout(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    authorize(&context, &headers, Capability::StatusAuditRead, true)?;
    if let Some(token) = cookie_value(&headers, "peerward_session") {
        state.store.revoke_session(token, &context.actor).await?;
    }
    let mut response_headers = HeaderMap::new();
    response_headers.append(
        header::SET_COOKIE,
        HeaderValue::from_static(
            "peerward_session=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0",
        ),
    );
    response_headers.append(
        header::SET_COOKIE,
        HeaderValue::from_static("peerward_csrf=; Path=/; Secure; SameSite=Strict; Max-Age=0"),
    );
    Ok((StatusCode::NO_CONTENT, response_headers).into_response())
}
