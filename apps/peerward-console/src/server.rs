//! HTTP server used by the Web Console.

use std::collections::BTreeMap;
use std::time::Duration;

use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    extract::{OriginalUri, State},
    http::{Request, StatusCode, header},
    middleware,
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::{any, get},
};
use opentelemetry::{
    Context as OpenTelemetryContext,
    trace::{
        SpanContext as OpenTelemetrySpanContext, SpanId as OpenTelemetrySpanId,
        TraceContextExt as _, TraceFlags as OpenTelemetryTraceFlags,
        TraceId as OpenTelemetryTraceId, TraceState as OpenTelemetryTraceState,
    },
};
use peerward_types::CorrelationContext;
use tower_http::{compression::CompressionLayer, services::ServeDir};
use tracing::Instrument as _;
use tracing_opentelemetry::OpenTelemetrySpanExt as _;

use crate::{
    ApiClient, ApiErrorBody, ConsoleApiError, ConsoleRoute, ConsoleSnapshot, read_bounded_response,
    render_document_with_nonce,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

/// Runtime settings for one console proxy instance.
#[derive(Clone, Debug)]
pub struct ConsoleServerConfig {
    /// Base URL of the Peerward Control service.
    pub control_url: String,
    /// Static asset directory generated for the browser console.
    pub asset_dir: String,
    /// Optional development-only Control bearer token.
    pub development_bearer: Option<String>,
}

impl Default for ConsoleServerConfig {
    fn default() -> Self {
        Self {
            control_url: "http://127.0.0.1:8080".into(),
            asset_dir: "apps/peerward-console/dist".into(),
            development_bearer: None,
        }
    }
}

#[derive(Clone)]
struct ConsoleState {
    control_url: String,
    api: ApiClient,
    development_bearer: Option<String>,
    proxy: reqwest::Client,
}

/// Serve the console on an already-bound listener.
pub async fn serve(
    listener: tokio::net::TcpListener,
    config: ConsoleServerConfig,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = router(config)?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn router(config: ConsoleServerConfig) -> Result<Router, Box<dyn std::error::Error + Send + Sync>> {
    let api = ApiClient::new(&config.control_url)?;
    let state = ConsoleState {
        api,
        control_url: config.control_url.trim_end_matches('/').to_owned(),
        development_bearer: config.development_bearer,
        proxy: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(5))
            .build()?,
    };
    Ok(Router::new()
        .route(
            crate::stylesheet_path(),
            get(|| async {
                (
                    [
                        (header::CONTENT_TYPE, "text/css; charset=utf-8"),
                        (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
                    ],
                    crate::stylesheet(),
                )
            }),
        )
        .route(
            "/console-interactions.js",
            get(|| async {
                (
                    [
                        (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
                        (header::CACHE_CONTROL, "no-store"),
                    ],
                    include_str!("../assets/console-interactions.js"),
                )
            }),
        )
        .route("/locked", get(locked_console))
        .route("/manifest.webmanifest", get(manifest))
        .route("/service-worker.js", get(service_worker))
        .nest_service("/assets", ServeDir::new(config.asset_dir))
        .route("/api/v1/{*path}", any(proxy_control))
        .route("/auth/{*path}", any(proxy_control))
        .fallback(get(page))
        .with_state(state)
        .layer(CompressionLayer::new())
        .layer(middleware::from_fn(console_request_context)))
}

async fn manifest() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/manifest+json"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        r##"{"name":"Peerward Console","short_name":"Peerward","start_url":"/mobile","display":"standalone","background_color":"#ffffff","theme_color":"#3157d5"}"##,
    )
}

async fn service_worker() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-store"),
        ],
        format!(
            r"const CACHE='peerward-static-{}';
const CACHEABLE=/^\/assets\/(?:[^/?]+-[0-9a-f]{{8,}}\.[^/?]+|peerward-console-web(?:\.js|_bg\.wasm))$/;
self.addEventListener('install',event=>event.waitUntil(caches.open(CACHE).then(cache=>cache.add('{}')).then(()=>self.skipWaiting())));
self.addEventListener('activate',event=>event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(key=>key.startsWith('peerward-static-')&&key!==CACHE).map(key=>caches.delete(key)))).then(()=>self.clients.claim())));
self.addEventListener('fetch',event=>{{
  const request=event.request;
  const url=new URL(request.url);
  if(request.method!=='GET'||url.origin!==self.location.origin) return;
  const sensitive=request.mode==='navigate'||url.pathname.startsWith('/api/')||url.pathname.startsWith('/auth/')||url.pathname.includes('/events')||url.pathname.includes('/topology');
  if(sensitive){{event.respondWith(fetch(request).catch(()=>new Response('Peerward Console is unavailable offline.',{{status:503,headers:{{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'no-store'}}}})));return;}}
  if(CACHEABLE.test(url.pathname)) event.respondWith(caches.open(CACHE).then(async cache=>{{const hit=await cache.match(request);if(hit)return hit;const response=await fetch(request);if(response.ok)await cache.put(request,response.clone());return response;}}));
}});",
            crate::CLIENT_ASSET_VERSION,
            crate::stylesheet_path()
        ),
    )
}

async fn locked_console(OriginalUri(uri): OriginalUri) -> Response {
    let return_to = url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
        .find(|(k, _)| k == "return_to")
        .map(|(_, v)| v.into_owned())
        .filter(|v| v.len() <= 2048)
        .unwrap_or_else(|| "/".into());
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("reauthenticate", "true")
        .append_pair("return_to", &return_to);
    let href = format!("/api/v1/auth/login?{}", query.finish()).replace('&', "&amp;");
    let html = format!(
        r#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Peerward · 已锁定</title><link rel="stylesheet" href="{}"></head><body><main class="locked-console"><div class="logo-mark">P</div><h1>控制台已锁定</h1><p>当前服务端会话已退出。重新验证身份后将返回原页面及网络。</p><p>Your session has ended. Authenticate again to return to your workspace.</p><a class="primary-link" href="{href}">重新验证身份 / Sign in again</a></main></body></html>"#,
        crate::stylesheet_path()
    );
    (
        [
            (header::CACHE_CONTROL, "no-store"),
            (
                header::CONTENT_SECURITY_POLICY,
                "default-src 'none'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'",
            ),
        ],
        Html(html),
    )
        .into_response()
}

async fn page(
    State(state): State<ConsoleState>,
    Extension(correlation): Extension<CorrelationContext>,
    OriginalUri(uri): OriginalUri,
    headers: axum::http::HeaderMap,
) -> Response {
    let route = ConsoleRoute::from_path(uri.path());
    let read_only_mobile = uri.path() == "/mobile";
    let client = state.api.clone().with_correlation_parent(correlation);
    let client = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .map_or(client.clone(), |cookie| client.with_cookie_header(cookie));
    let client = state
        .development_bearer
        .as_ref()
        .map_or(client.clone(), |token| {
            client.with_development_bearer(token)
        });
    let selected_mesh = query_value(uri.query(), "mesh");
    let relay_filter = query_value(uri.query(), "relay_id");
    let mut snapshot = client
        .route_snapshot_filtered(
            route,
            selected_mesh.as_deref(),
            query_value(uri.query(), "cursor").as_deref(),
            relay_filter.as_deref(),
        )
        .await
        .unwrap_or_else(snapshot_error);
    if read_only_mobile
        && snapshot.mesh_id.is_empty()
        && let Some(mesh_id) = snapshot.meshes.first().map(|mesh| mesh.id.clone())
    {
        snapshot = client
            .route_snapshot(route, Some(&mesh_id), None)
            .await
            .unwrap_or_else(snapshot_error);
    }
    if read_only_mobile {
        snapshot
            .capabilities
            .retain(|capability| capability == "resource_read");
    }
    let nonce = URL_SAFE_NO_PAD.encode(uuid::Uuid::new_v4().as_bytes());
    let mut response = Html(render_document_with_nonce(route, snapshot, &nonce)).into_response();
    let headers = response.headers_mut();
    let csp = format!(
        "default-src 'none'; script-src 'nonce-{nonce}' 'strict-dynamic' 'wasm-unsafe-eval'; worker-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
    );
    if let Ok(value) = csp.parse() {
        headers.insert(header::CONTENT_SECURITY_POLICY, value);
    }
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=63072000; includeSubDomains"
            .parse()
            .expect("static header"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        "nosniff".parse().expect("static header"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        "no-referrer".parse().expect("static header"),
    );
    headers.insert(
        "permissions-policy",
        "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
            .parse()
            .expect("static header"),
    );
    response
}

fn query_value(query: Option<&str>, name: &str) -> Option<String> {
    url::form_urlencoded::parse(query?.as_bytes())
        .find_map(|(key, value)| (key == name).then(|| value.into_owned()))
}

fn snapshot_error(error: ConsoleApiError) -> ConsoleSnapshot {
    let body = match error {
        ConsoleApiError::Server(body) => body,
        ConsoleApiError::Transport(_) => ApiErrorBody {
            code: "control_unavailable".into(),
            message: "The control service is unavailable.".into(),
            request_id: uuid::Uuid::new_v4().to_string(),
            field_errors: BTreeMap::new(),
            retryable: true,
        },
        ConsoleApiError::InvalidResponse => ApiErrorBody {
            code: "invalid_control_response".into(),
            message: "The control service returned an invalid response.".into(),
            request_id: uuid::Uuid::new_v4().to_string(),
            field_errors: BTreeMap::new(),
            retryable: false,
        },
        ConsoleApiError::InvalidBaseUrl => ApiErrorBody {
            code: "invalid_control_url".into(),
            message: "The control service URL is invalid.".into(),
            request_id: uuid::Uuid::new_v4().to_string(),
            field_errors: BTreeMap::new(),
            retryable: false,
        },
        ConsoleApiError::ResponseTooLarge => ApiErrorBody {
            code: "control_response_too_large".into(),
            message: "The control service response exceeded its size bound.".into(),
            request_id: uuid::Uuid::new_v4().to_string(),
            field_errors: BTreeMap::new(),
            retryable: false,
        },
    };
    ConsoleSnapshot {
        healthy: false,
        error: Some(body),
        ..ConsoleSnapshot::default()
    }
}

async fn proxy_control(
    State(state): State<ConsoleState>,
    Extension(correlation): Extension<CorrelationContext>,
    OriginalUri(uri): OriginalUri,
    request: Request<Body>,
) -> Response {
    let target = format!(
        "{}{}",
        state.control_url,
        uri.path_and_query().map_or("/", |value| value.as_str())
    );
    let (parts, body) = request.into_parts();
    let mut outbound = state.proxy.request(parts.method, target);
    let outbound_correlation = crate::outbound_correlation(correlation);
    let connection_headers = connection_header_names(&parts.headers);
    for (name, value) in &parts.headers {
        if name != "x-request-id"
            && name != "traceparent"
            && !hop_by_hop(name.as_str())
            && !connection_headers.iter().any(|item| item == name.as_str())
        {
            outbound = outbound.header(name, value);
        }
    }
    outbound = outbound
        .header("x-request-id", outbound_correlation.request_id.to_string())
        .header("traceparent", outbound_correlation.traceparent());
    if !parts.headers.contains_key(header::AUTHORIZATION)
        && let Some(token) = &state.development_bearer
    {
        outbound = outbound.bearer_auth(token);
    }
    let Ok(bytes) = to_bytes(body, peerward_api::MAX_REQUEST_BYTES).await else {
        return StatusCode::PAYLOAD_TOO_LARGE.into_response();
    };
    let event_stream = uri.path() == "/api/v1/events";
    if !event_stream {
        outbound = outbound.timeout(Duration::from_secs(15));
    }
    let upstream = if event_stream {
        match tokio::time::timeout(Duration::from_secs(45), outbound.body(bytes).send()).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
        }
    } else {
        let Ok(response) = outbound.body(bytes).send().await else {
            return StatusCode::BAD_GATEWAY.into_response();
        };
        response
    };
    let status = upstream.status();
    let headers = upstream.headers().clone();
    let response_connection_headers = connection_header_names(&headers);
    let mut response = Response::builder().status(status);
    for name in [
        header::CONTENT_TYPE,
        header::CONTENT_DISPOSITION,
        header::CACHE_CONTROL,
        header::LOCATION,
        header::SET_COOKIE,
        header::HeaderName::from_static("x-request-id"),
        header::HeaderName::from_static("traceparent"),
    ] {
        if !response_connection_headers
            .iter()
            .any(|item| item == name.as_str())
        {
            for value in headers.get_all(&name) {
                response = response.header(&name, value);
            }
        }
    }
    if event_stream {
        use futures_util::StreamExt as _;
        let mut stream = upstream.bytes_stream();
        let bounded = async_stream::stream! {
            loop {
                match tokio::time::timeout(Duration::from_secs(45), stream.next()).await {
                    Ok(Some(Ok(chunk))) => yield Ok::<_, std::io::Error>(chunk),
                    Ok(Some(Err(error))) => {
                        yield Err(std::io::Error::other(error));
                        break;
                    }
                    Ok(None) | Err(_) => break,
                }
            }
        };
        response
            .body(Body::from_stream(bounded))
            .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response())
    } else {
        let maximum = if status.is_success() {
            2 * 1024 * 1024
        } else {
            64 * 1024
        };
        match read_bounded_response(upstream, maximum).await {
            Ok(bytes) => response
                .body(Body::from(bytes))
                .unwrap_or_else(|_| StatusCode::BAD_GATEWAY.into_response()),
            Err(_) => StatusCode::BAD_GATEWAY.into_response(),
        }
    }
}

async fn console_request_context(mut request: Request<Body>, next: Next) -> Response {
    let path = request.uri().path();
    let no_store_response = console_response_requires_no_store(path);
    let immutable_response = console_response_is_immutable(path);
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<uuid::Uuid>().ok())
        .filter(|value| value.get_version_num() == 4)
        .unwrap_or_else(uuid::Uuid::new_v4);
    let inbound = request
        .headers()
        .get("traceparent")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| CorrelationContext::from_traceparent(request_id, value).ok());
    let fallback = inbound.map_or_else(
        || {
            let root = CorrelationContext::root(false);
            CorrelationContext { request_id, ..root }
        },
        CorrelationContext::child,
    );
    let span = tracing::info_span!(
        "console.http.server",
        request_id = %request_id,
        trace_id = tracing::field::Empty,
        span_id = tracing::field::Empty,
        http.request.method = %request.method(),
        url.path = request.uri().path(),
        http.response.status_code = tracing::field::Empty,
    );
    if let Some(parent) = inbound {
        let _ = span.set_parent(open_telemetry_parent(parent));
    }
    let correlation = correlation_from_span(&span, request_id).unwrap_or(fallback);
    span.record("trace_id", hex::encode(correlation.trace_id));
    span.record("span_id", hex::encode(correlation.span_id));
    request.extensions_mut().insert(correlation);
    async move {
        let mut response = next.run(request).await;
        response.headers_mut().insert(
            "x-request-id",
            request_id
                .to_string()
                .parse()
                .expect("UUID is a valid header"),
        );
        response.headers_mut().insert(
            "traceparent",
            correlation
                .traceparent()
                .parse()
                .expect("traceparent is a valid header"),
        );
        if no_store_response {
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                "no-store".parse().expect("static cache policy is valid"),
            );
        } else if immutable_response {
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                "public, max-age=31536000, immutable"
                    .parse()
                    .expect("static cache policy is valid"),
            );
        }
        tracing::Span::current().record("http.response.status_code", response.status().as_u16());
        response
    }
    .instrument(span)
    .await
}

pub(crate) fn console_response_requires_no_store(path: &str) -> bool {
    let console_document = !path.starts_with("/api/")
        && !path.starts_with("/auth/")
        && !path.starts_with("/assets/")
        && path != "/manifest.webmanifest"
        && path != "/service-worker.js";
    // This also covers proxy errors: a 410 cursor-expired response is otherwise
    // cacheable and can be reused even after the browser clears Last-Event-ID.
    console_document || path.starts_with("/api/") || path.starts_with("/auth/")
}

pub(crate) fn console_response_is_immutable(path: &str) -> bool {
    matches!(
        path,
        "/assets/peerward-console-web.js" | "/assets/peerward-console-web_bg.wasm"
    )
}

fn open_telemetry_parent(correlation: CorrelationContext) -> OpenTelemetryContext {
    OpenTelemetryContext::new().with_remote_span_context(OpenTelemetrySpanContext::new(
        OpenTelemetryTraceId::from_bytes(correlation.trace_id),
        OpenTelemetrySpanId::from_bytes(correlation.span_id),
        OpenTelemetryTraceFlags::new(correlation.flags),
        true,
        OpenTelemetryTraceState::default(),
    ))
}

fn correlation_from_span(
    span: &tracing::Span,
    request_id: uuid::Uuid,
) -> Option<CorrelationContext> {
    let context = span.context();
    let span = context.span();
    let span_context = span.span_context();
    span_context.is_valid().then(|| {
        CorrelationContext::from_parts(
            request_id,
            span_context.trace_id().to_bytes(),
            span_context.span_id().to_bytes(),
            span_context.trace_flags().to_u8(),
        )
        .expect("OpenTelemetry emitted valid correlation")
    })
}

pub(crate) fn connection_header_names(headers: &axum::http::HeaderMap) -> Vec<String> {
    headers
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| {
            value
                .split(',')
                .map(|name| name.trim().to_ascii_lowercase())
                .filter(|name| !name.is_empty())
        })
        .collect()
}

fn hop_by_hop(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "host"
            | "content-length"
    )
}
