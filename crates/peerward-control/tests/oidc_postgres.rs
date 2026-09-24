use std::{
    collections::HashMap,
    env,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    Form, Json, Router,
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode, header},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer as _, SigningKey};
use http_body_util::BodyExt as _;
use openidconnect::{IssuerUrl, core::CoreProviderMetadata, reqwest as oidc_reqwest};
use peerward_control::{AuthConfig, OidcConfig, router};
use peerward_store::Store;
use rand::{RngCore as _, rngs::OsRng};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use tower::ServiceExt as _;
use url::Url;

const CLIENT_ID: &str = "peerward-oidc-test";
const CLIENT_SECRET: &str = "peerward-oidc-test-secret";

#[derive(Clone)]
struct ProviderState {
    issuer: String,
    flow: Arc<Mutex<ProviderFlow>>,
    signing: Arc<Mutex<SigningMaterial>>,
}

struct SigningMaterial {
    private_key: SigningKey,
    key_id: String,
}

impl SigningMaterial {
    fn generate(key_id: &str) -> Self {
        let mut seed = [0_u8; 32];
        OsRng.fill_bytes(&mut seed);
        Self {
            private_key: SigningKey::from_bytes(&seed),
            key_id: key_id.into(),
        }
    }
}

#[derive(Default)]
struct ProviderFlow {
    nonce: String,
    challenge: String,
    claim_mode: ClaimMode,
    exchanges: u32,
}

#[derive(Clone, Copy, Default)]
enum ClaimMode {
    #[default]
    Valid,
    InvalidNonce,
    InvalidAudience,
    InvalidIssuer,
    Expired,
    StaleAuthTime,
}

fn database_url() -> String {
    let value = env::var("PEERWARD_TEST_DATABASE_URL")
        .expect("PEERWARD_TEST_DATABASE_URL must identify an ephemeral PostgreSQL database");
    assert!(
        value
            .parse::<sqlx::postgres::PgConnectOptions>()
            .is_ok_and(|options| options.get_database() == Some("peerward_test")),
        "OIDC integration test refuses a database not named peerward_test"
    );
    value
}

async fn discovery(State(state): State<ProviderState>) -> Json<Value> {
    Json(json!({
        "issuer": state.issuer,
        "authorization_endpoint": format!("{}authorize", state.issuer),
        "token_endpoint": format!("{}token", state.issuer),
        "jwks_uri": format!("{}jwks", state.issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["EdDSA"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        "scopes_supported": ["openid", "profile", "email"],
        "claims_supported": ["iss", "sub", "aud", "exp", "iat", "nonce", "groups"],
        "code_challenge_methods_supported": ["S256"],
    }))
}

async fn jwks(State(state): State<ProviderState>) -> Json<Value> {
    let signing = state.signing.lock().expect("provider signing lock");
    let public_key = signing.private_key.verifying_key();
    Json(json!({"keys": [{
        "kty": "OKP",
        "crv": "Ed25519",
        "use": "sig",
        "alg": "EdDSA",
        "kid": signing.key_id,
        "x": URL_SAFE_NO_PAD.encode(public_key.to_bytes()),
    }]}))
}

async fn token(
    State(state): State<ProviderState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let expected_authorization = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    );
    if headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        != Some(expected_authorization.as_str())
        || form.get("grant_type").map(String::as_str) != Some("authorization_code")
        || form.get("code").map(String::as_str) != Some("test-code")
    {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let verifier = form.get("code_verifier").ok_or(StatusCode::BAD_REQUEST)?;
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let (nonce, mode) = {
        let mut flow = state.flow.lock().expect("provider flow lock");
        if challenge != flow.challenge {
            return Err(StatusCode::BAD_REQUEST);
        }
        flow.exchanges += 1;
        (flow.nonce.clone(), flow.claim_mode)
    };
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let (issuer, audience, nonce, expiry) = match mode {
        ClaimMode::Valid | ClaimMode::StaleAuthTime => {
            (state.issuer.clone(), CLIENT_ID, nonce, now + 300)
        }
        ClaimMode::InvalidNonce => (
            state.issuer.clone(),
            CLIENT_ID,
            "wrong-nonce".into(),
            now + 300,
        ),
        ClaimMode::InvalidAudience => (state.issuer.clone(), "different-client", nonce, now + 300),
        ClaimMode::InvalidIssuer => (
            "https://different-issuer.invalid".into(),
            CLIENT_ID,
            nonce,
            now + 300,
        ),
        ClaimMode::Expired => (state.issuer.clone(), CLIENT_ID, nonce, now - 60),
    };
    let id_token = {
        let signing = state.signing.lock().expect("provider signing lock");
        signed_id_token(
            &signing,
            &issuer,
            audience,
            &nonce,
            now,
            expiry,
            if matches!(mode, ClaimMode::StaleAuthTime) {
                now - 600
            } else {
                now
            },
        )
    };
    Ok(Json(json!({
        "access_token": "opaque-access-token",
        "token_type": "Bearer",
        "expires_in": 300,
        "id_token": id_token,
    })))
}

fn signed_id_token(
    signing: &SigningMaterial,
    provider_issuer: &str,
    audience: &str,
    nonce: &str,
    token_iat: i64,
    expiry: i64,
    auth_time: i64,
) -> String {
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg":"EdDSA",
            "typ":"JWT",
            "kid": signing.key_id,
        }))
        .unwrap(),
    );
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": provider_issuer,
            "sub": "oidc-subject-1",
            "aud": audience,
            "exp": expiry,
            "iat": token_iat,
            "nonce": nonce,
            "auth_time":auth_time,
            "groups": ["peerward-admin"],
        }))
        .unwrap(),
    );
    let signing_input = format!("{header}.{claims}");
    let signature = URL_SAFE_NO_PAD.encode(
        signing
            .private_key
            .sign(signing_input.as_bytes())
            .to_bytes(),
    );
    format!("{signing_input}.{signature}")
}

async fn login(
    application: &Router,
    provider: &ProviderState,
    mode: ClaimMode,
) -> (String, String) {
    login_at(application, provider, mode, "/api/v1/auth/login").await
}
async fn login_at(
    application: &Router,
    provider: &ProviderState,
    mode: ClaimMode,
    path: &str,
) -> (String, String) {
    let response = application
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    if response.status() != StatusCode::FOUND {
        let status = response.status();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        panic!(
            "OIDC login failed with {status}: {}",
            String::from_utf8_lossy(&body)
        );
    }
    let destination = Url::parse(
        response
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
    )
    .unwrap();
    let query: HashMap<_, _> = destination.query_pairs().into_owned().collect();
    assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
    assert_eq!(
        query.get("code_challenge_method").map(String::as_str),
        Some("S256")
    );
    if path.contains("reauthenticate=true") {
        assert_eq!(query.get("prompt").map(String::as_str), Some("login"));
        assert_eq!(query.get("max_age").map(String::as_str), Some("0"));
    }
    let state = query.get("state").unwrap().clone();
    let nonce = query.get("nonce").unwrap().clone();
    let challenge = query.get("code_challenge").unwrap().clone();
    *provider.flow.lock().unwrap() = ProviderFlow {
        nonce,
        challenge,
        claim_mode: mode,
        exchanges: 0,
    };
    (state, "test-code".into())
}

async fn callback(application: &Router, state: &str, code: &str) -> axum::response::Response {
    application
        .clone()
        .oneshot(
            Request::get(format!("/auth/callback?state={state}&code={code}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

fn cookie_value(headers: &HeaderMap, name: &str) -> String {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(|cookie| {
            let (key, rest) = cookie.split_once('=')?;
            (key == name).then(|| rest.split(';').next().unwrap_or_default().to_owned())
        })
        .expect("expected response cookie")
}

#[tokio::test]
async fn authorization_code_pkce_sessions_and_claim_rejection_are_end_to_end() {
    let store = Store::connect(&database_url(), 8).await.unwrap();
    sqlx::raw_sql("DROP SCHEMA public CASCADE; CREATE SCHEMA public")
        .execute(store.pool())
        .await
        .unwrap();
    store.migrate().await.unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}/", listener.local_addr().unwrap());
    let provider = ProviderState {
        issuer: issuer.clone(),
        flow: Arc::new(Mutex::new(ProviderFlow::default())),
        signing: Arc::new(Mutex::new(SigningMaterial::generate("provider-key-1"))),
    };
    let provider_app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .with_state(provider.clone());
    let provider_task = tokio::spawn(async move { axum::serve(listener, provider_app).await });
    let oidc_http = oidc_reqwest::ClientBuilder::new()
        .redirect(oidc_reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    CoreProviderMetadata::discover_async(IssuerUrl::new(issuer.clone()).unwrap(), &oidc_http)
        .await
        .unwrap();

    let application = router(
        store.clone(),
        AuthConfig {
            oidc: Some(OidcConfig {
                issuer_url: Url::parse(&issuer).unwrap(),
                client_id: CLIENT_ID.into(),
                client_secret: Some(CLIENT_SECRET.into()),
                redirect_uri: Url::parse("http://127.0.0.1/auth/callback").unwrap(),
                scopes: "openid profile email".into(),
                groups_claim: "groups".into(),
                operator_groups: vec!["peerward-operator".into()],
                auditor_groups: vec!["peerward-auditor".into()],
                admin_groups: vec!["peerward-admin".into()],
            }),
            development_bearer_token: Some("must-be-disabled".into()),
            bootstrap_token: None,
        },
    );

    let (state, code) = login(&application, &provider, ClaimMode::Valid).await;
    *provider.signing.lock().unwrap() = SigningMaterial::generate("provider-key-2");
    let response = callback(&application, &state, &code).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    let cookies: Vec<_> = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap().to_owned())
        .collect();
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax"))
    );
    assert!(
        cookies
            .iter()
            .any(|cookie| cookie.starts_with("peerward_csrf=")
                && cookie.contains("SameSite=Strict")
                && !cookie.contains("HttpOnly"))
    );
    let session = cookie_value(response.headers(), "peerward_session");
    let csrf = cookie_value(response.headers(), "peerward_csrf");
    assert!(!session.is_empty() && !csrf.is_empty() && session != csrf);

    let cookie = format!("peerward_session={session}; peerward_csrf={csrf}");
    let response = application
        .clone()
        .oneshot(
            Request::get("/auth/session")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["authenticated"], true);
    assert_eq!(body["role"], "admin");
    assert_eq!(body["csrf_token"], csrf);

    let response = application
        .clone()
        .oneshot(
            Request::post("/auth/logout")
                .header(header::COOKIE, &cookie)
                .header("x-csrf-token", &csrf)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let response = application
        .clone()
        .oneshot(
            Request::get("/auth/session")
                .header(header::COOKIE, &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let replay = callback(&application, &state, &code).await;
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    for mode in [
        ClaimMode::InvalidNonce,
        ClaimMode::InvalidAudience,
        ClaimMode::InvalidIssuer,
        ClaimMode::Expired,
    ] {
        let (state, code) = login(&application, &provider, mode).await;
        let response = callback(&application, &state, &code).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    assert_eq!(provider.flow.lock().unwrap().exchanges, 1);
    let mesh = uuid::Uuid::new_v4();
    let target = format!("/networks?mesh={mesh}");
    let path = format!(
        "/api/v1/auth/login?reauthenticate=true&return_to={}",
        url::form_urlencoded::byte_serialize(target.as_bytes()).collect::<String>()
    );
    let (state, code) = login_at(&application, &provider, ClaimMode::Valid, &path).await;
    let unlocked = callback(&application, &state, &code).await;
    assert_eq!(unlocked.status(), StatusCode::FOUND);
    assert_eq!(
        unlocked
            .headers()
            .get(header::LOCATION)
            .unwrap()
            .to_str()
            .unwrap(),
        target
    );
    let (state, code) = login_at(&application, &provider, ClaimMode::StaleAuthTime, &path).await;
    assert_eq!(
        callback(&application, &state, &code).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let (state, code) = login_at(
        &application,
        &provider,
        ClaimMode::Valid,
        "/api/v1/auth/login?return_to=https%3A%2F%2Fattacker.invalid%2F",
    )
    .await;
    assert_eq!(
        callback(&application, &state, &code)
            .await
            .headers()
            .get(header::LOCATION)
            .unwrap(),
        "/"
    );
    provider_task.abort();
}
