#[cfg(test)]
mod webhook_http_tests {
    use super::*;
    use peerward_management::{WebhookEvent, WebhookNotification};
    use std::sync::atomic::AtomicUsize;
    #[tokio::test]
    async fn real_http_body_verification_duplicate_delivery_and_redirect_refusal() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[51; 32]);
        let verifier = key.verifying_key();
        let mesh = MeshId::new();
        let hook = Uuid::new_v4();
        let id = Uuid::new_v4();
        let seen = Arc::new(std::sync::Mutex::new(
            std::collections::BTreeSet::<Uuid>::new(),
        ));
        let accepted = Arc::new(AtomicUsize::new(0));
        let redirected = Arc::new(AtomicUsize::new(0));
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let receiver_seen = seen.clone();
        let receiver_count = accepted.clone();
        let redirect_count = redirected.clone();
        let router = Router::new()
            .route(
                "/receive",
                post(move |headers: HeaderMap, body: axum::body::Bytes| {
                    let seen = receiver_seen.clone();
                    let count = receiver_count.clone();
                    async move {
                        let signature = headers
                            .get("peerward-signature")
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .strip_prefix("ed25519=")
                            .unwrap();
                        let signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
                        let notice = WebhookNotification::verify(
                            &body,
                            &signature,
                            &verifier,
                            mesh,
                            hook,
                            current_unix_seconds(),
                        )
                        .unwrap();
                        assert_eq!(
                            headers
                                .get("peerward-delivery-id")
                                .unwrap()
                                .to_str()
                                .unwrap(),
                            notice.delivery_id.to_string()
                        );
                        if seen.lock().unwrap().insert(notice.delivery_id) {
                            count.fetch_add(1, Ordering::SeqCst);
                        }
                        StatusCode::NO_CONTENT
                    }
                }),
            )
            .route(
                "/redirect",
                post(move || async move {
                    (
                        StatusCode::TEMPORARY_REDIRECT,
                        [(header::LOCATION, format!("http://{address}/unexpected"))],
                    )
                }),
            )
            .route(
                "/unexpected",
                post(move || {
                    let count = redirect_count.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        StatusCode::OK
                    }
                }),
            )
            .route("/busy", post(|| async { StatusCode::TOO_MANY_REQUESTS }));
        let server = tokio::spawn(async move {
            axum::serve(target, router).await.unwrap();
        });
        // Loopback plaintext is a test-only transport fixture, not an accepted
        // production webhook URL. Destination/TLS policy is exercised separately.
        let client = oidc_reqwest::Client::builder()
            .no_proxy()
            .redirect(oidc_reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap();
        let mut notice = WebhookNotification {
            version: 1,
            mesh_id: mesh,
            webhook_id: hook,
            delivery_id: id,
            attempt: 1,
            sent_at: current_unix_seconds(),
            event: WebhookEvent {
                id: Uuid::new_v4(),
                sequence: 1,
                occurred_at: current_unix_seconds(),
                kind: "peer.disabled".into(),
                resource_kind: "peer".into(),
                resource_id: None,
            },
        };
        for attempt in 1..=2 {
            notice.attempt = attempt;
            let (body, signature) = notice.sign(&key).unwrap();
            let result = webhook_http_send(
                &client,
                format!("http://{address}/receive").parse().unwrap(),
                id,
                body,
                signature,
            )
            .await
            .unwrap_or_else(|_| panic!("local receiver unavailable"));
            assert!(result.success);
        }
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "the stable delivery identity permits transactional deduplication"
        );
        let (body, signature) = notice.sign(&key).unwrap();
        let result = webhook_http_send(
            &client,
            format!("http://{address}/redirect").parse().unwrap(),
            id,
            body,
            signature,
        )
        .await
        .unwrap_or_else(|_| panic!("local redirect fixture unavailable"));
        assert!(!result.success && result.permanent);
        assert_eq!(result.code, "redirect_rejected");
        assert_eq!(
            redirected.load(Ordering::SeqCst),
            0,
            "a receiver cannot redirect to private infrastructure"
        );
        let (body, signature) = notice.sign(&key).unwrap();
        let result = webhook_http_send(
            &client,
            format!("http://{address}/busy").parse().unwrap(),
            id,
            body,
            signature,
        )
        .await
        .unwrap_or_else(|_| panic!("local rate-limit fixture unavailable"));
        assert!(!result.success && !result.permanent);
        assert_eq!(result.status, Some(429));
        server.abort();
    }
}
