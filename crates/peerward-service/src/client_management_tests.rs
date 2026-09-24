use super::*;
struct TestClient;
#[async_trait::async_trait]
impl ClientManagement for TestClient {
    async fn execute(
        &self,
        request: ClientPreferenceRequest,
    ) -> Result<ClientPreferenceView, String> {
        if matches!(request, ClientPreferenceRequest::Set { .. }) {
            return Err("preferences_version_conflict".into());
        }
        Ok(ClientPreferenceView {
            version: 7,
            preferences: peerward_management::ClientPreferences::default(),
            application: peerward_management::PreferenceApplication::Unknown,
            reason: Some("authorization_unavailable".into()),
            exits: vec![],
            local_lan: vec![],
            gateway_paths: vec![],
        })
    }
}
#[tokio::test]
async fn preferences_share_the_authenticated_socket_without_control_registration() {
    let directory = std::env::temp_dir().join(format!("pw-local-client-{}", ServiceId::new()));
    std::fs::create_dir(&directory).unwrap();
    let socket = directory.join("peer.sock");
    let path = socket.clone();
    let state = directory.join("services.json");
    let observed = PeerObservability::default();
    observed.set_client_management(Arc::new(TestClient));
    let (changes, _received) = mpsc::channel(1);
    let (shutdown, stopped) = watch::channel(false);
    let worker = tokio::spawn(async move {
        serve_peer_management(
            &path,
            state,
            "127.0.0.1".parse().unwrap(),
            changes,
            observed,
            stopped,
        )
        .await
    });
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let reply = client(
        &socket,
        &Request::ClientPreferences {
            request: ClientPreferenceRequest::Get {},
        },
    )
    .await
    .unwrap();
    assert!(reply.ok);
    assert_eq!(reply.detail["version"], 7);
    assert_eq!(reply.detail["application"], "unknown");
    // Device identifiers and arbitrary request fields cannot enter a local preference mutation.
    assert!(serde_json::from_value::<Request>(serde_json::json!({"operation":"client_preferences","request":{"operation":"get","peer_id":"anything"}})).is_err());
    assert!(
        client(&socket, &Request::List)
            .await
            .unwrap()
            .services
            .is_empty()
    );
    shutdown.send(true).unwrap();
    worker.await.unwrap().unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}
