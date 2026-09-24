use std::{
    collections::BTreeSet,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use axum::{Json, extract::ConnectInfo, response::Redirect};
use serde_json::json;

use super::*;

#[tokio::test]
async fn typed_client_rejects_redirects_without_contacting_the_target() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let contacts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let app = Router::new()
        .route("/auth/session", get(|| async { Redirect::temporary("/redirect-target") }))
        .route("/redirect-target", get({
            let contacts = contacts.clone();
            move || {
                contacts.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                async { Json(json!({"authenticated":false,"actor":"anonymous","role":"viewer","capabilities":[],"csrf_token":null})) }
            }
        }));
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let result = ApiClient::new(format!("http://{address}"))
        .unwrap()
        .with_cookie_header("peerward_session=private")
        .auth_session()
        .await;
    server.abort();
    assert!(matches!(result, Err(ConsoleApiError::InvalidResponse)));
    assert_eq!(contacts.load(std::sync::atomic::Ordering::Relaxed), 0);
}

#[tokio::test]
async fn rendered_pages_reuse_control_connections_without_reusing_cookies() {
    let observed = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new()
        .route("/auth/session", get({
            let observed = observed.clone();
            move |ConnectInfo(source): ConnectInfo<SocketAddr>, headers: axum::http::HeaderMap| {
                observed.lock().unwrap().push((source, headers.get(header::COOKIE).cloned()));
                async { Json(json!({"authenticated":true,"actor":"operator","role":"viewer","capabilities":["resource_read"],"csrf_token":null})) }
            }
        }))
        .route("/api/v1/meshes", get(|| async { Json(json!({"items":[],"next_cursor":null})) }));
    let control = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_url = format!("http://{}", control.local_addr().unwrap());
    let control_task = tokio::spawn(async move {
        axum::serve(
            control,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let console = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", console.local_addr().unwrap());
    let console_task = tokio::spawn(serve(
        console,
        ConsoleServerConfig {
            control_url,
            ..ConsoleServerConfig::default()
        },
    ));
    let browser = reqwest::Client::new();
    for cookie in [
        Some("peerward_session=alice"),
        Some("peerward_session=bob"),
        None,
    ] {
        let mut request = browser.get(&url);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.text().await.unwrap().contains("Peerward"));
    }
    console_task.abort();
    control_task.abort();
    let observed = observed.lock().unwrap();
    assert_eq!(observed.len(), 3);
    assert_eq!(
        observed
            .iter()
            .map(|(address, _)| *address)
            .collect::<BTreeSet<_>>()
            .len(),
        1
    );
    assert_eq!(
        observed
            .iter()
            .map(|(_, cookie)| cookie.as_ref().map(|value| value.to_str().unwrap()))
            .collect::<Vec<_>>(),
        [
            Some("peerward_session=alice"),
            Some("peerward_session=bob"),
            None
        ]
    );
}
