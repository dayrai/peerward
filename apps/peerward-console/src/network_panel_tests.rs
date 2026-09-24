use super::*;

#[test]
fn internet_form_keeps_address_family_and_resource_identity_when_edited() {
    for (kind, ipv4, ipv6) in [
        ("internet_dual", true, true),
        ("internet_v4", true, false),
        ("internet_v6", false, true),
    ] {
        let draft = NetworkDraft {
            name: "Office exit".into(),
            kind: kind.into(),
            ..NetworkDraft::default()
        };
        let definition = draft.definition().unwrap();
        assert_eq!(
            definition.target,
            peerward_management::ResourceTarget::Internet { ipv4, ipv6 }
        );
        let resource = peerward_management::NetworkResource {
            id: draft.id,
            mesh_id: peerward_types::MeshId::new(),
            version: 3,
            definition,
        };
        let edit = NetworkDraft::from_resource(&resource);
        assert_eq!(edit.id, resource.id);
        assert_eq!(edit.version, Some(3));
        assert_eq!(edit.definition().unwrap(), resource.definition);
    }
}

#[test]
fn resource_forms_preserve_labels_and_require_explicit_sources_and_ports() {
    let draft = NetworkDraft {
        name: "Printer".into(),
        prefix: "192.168.45.50".into(),
        labels: BTreeMap::from([("room".into(), "office".into())]),
        ..NetworkDraft::default()
    };
    let definition = draft.definition().unwrap();
    assert_eq!(definition.labels["room"], "office");
    assert!(
        matches!(definition.target,peerward_management::ResourceTarget::Subnet{prefix,..} if prefix.to_string()=="192.168.45.50/32")
    );
    assert!(
        NetworkDraft {
            prefix: "192.168.45.50/24".into(),
            ..draft
        }
        .definition()
        .is_err()
    );
    let mut form = ResourceRuleForm::default();
    assert!(form.rule().is_err());
    let peer = peerward_types::PeerId::new();
    form.source = peer.to_string();
    form.target = uuid::Uuid::new_v4().to_string();
    form.port = "631".into();
    let rule = form.rule().unwrap();
    assert_eq!(rule.source.peers, [peer].into());
    assert_eq!(rule.destination_ports, [(631, 631)]);
    form.port = "0".into();
    assert!(form.rule().is_err());
    form.port = "443-80".into();
    assert!(form.rule().is_err());
    form.port = "1-65535".into();
    assert!(form.rule().is_ok());
    assert!(resource_policy_draft(r#"{"rules":[],"tests":[],"default":"allow"}"#).is_err());
}

#[test]
fn management_panels_render_localized_steps_and_do_not_claim_connectivity() {
    let html = dioxus::ssr::render_element(
        rsx! {NetworkPanel{mesh:uuid::Uuid::new_v4().to_string(),csrf:None,can_write:false,locale:Locale::ZhCn}},
    );
    assert!(html.contains("网络资源"));
    assert!(html.contains("选择网关"));
    assert!(!html.contains("新建资源"));
    let html = dioxus::ssr::render_element(
        rsx! {NetworkObservation{value:json!({"categories":{"routes":{"status":"unknown"}}}),locale:Locale::ZhCn}},
    );
    assert!(html.contains("实际可访问性：未知"));
    let html = dioxus::ssr::render_element(
        rsx! {DnsPanel{mesh:uuid::Uuid::new_v4().to_string(),csrf:None,can_write:false,locale:Locale::ZhCn}},
    );
    assert!(html.contains("网络 DNS 设置"));
    assert!(!html.contains("保存 DNS 配置"));
    assert!(console_catalog_complete());
}

#[tokio::test]
async fn resource_and_policy_actions_use_exact_mesh_versions_and_csrf() {
    use axum::{
        Json, Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, Method, Uri},
    };
    use std::sync::{Arc, Mutex};
    type Recorded = Arc<Mutex<Vec<(Method, String, HeaderMap, Value)>>>;
    async fn record(
        State(records): State<Recorded>,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Bytes,
    ) -> Json<Value> {
        let value = if body.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&body).unwrap()
        };
        records
            .lock()
            .unwrap()
            .push((method, uri.to_string(), headers, value));
        Json(json!({}))
    }
    let records: Recorded = Arc::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .fallback(record)
        .with_state(Arc::clone(&records));
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let api = ApiClient::new(format!("http://{address}"))
        .unwrap()
        .with_csrf("test-csrf")
        .with_development_bearer("test-token");
    let mesh = uuid::Uuid::new_v4().to_string();
    let binding = uuid::Uuid::new_v4();
    api.network_operation(
        &mesh,
        NetworkOperation::Approve {
            id: binding,
            version: 7,
            approved: false,
        },
    )
    .await
    .unwrap();
    api.resource_policy_operation(
        &mesh,
        ResourcePolicyOperation::Publish,
        9,
        json!({"rules":[],"tests":[]}),
    )
    .await
    .unwrap();
    api.resource_policy_operation(&mesh, ResourcePolicyOperation::History(3), 0, Value::Null)
        .await
        .unwrap();
    let records = records.lock().unwrap();
    assert_eq!(records[0].0, Method::PUT);
    assert_eq!(
        records[0].1,
        format!("/api/v1/meshes/{mesh}/gateway-bindings/{binding}/approval")
    );
    assert_eq!(records[0].2["if-match"], "\"7\"");
    assert_eq!(records[0].2["x-csrf-token"], "test-csrf");
    assert_eq!(records[0].3, json!({"approved":false}));
    assert_eq!(records[1].2["if-match"], "\"9\"");
    assert_eq!(records[1].3, json!({"rules":[],"tests":[]}));
    assert_eq!(records[2].0, Method::GET);
    assert_eq!(
        records[2].1,
        format!("/api/v1/meshes/{mesh}/resource-policy/history/3")
    );
    task.abort();
}

#[test]
fn device_conditions_preserve_scope_version_and_reject_invalid_drafts() {
    let value = json!({"version":3,"definition":{"enabled":true,"scope":{"labels":{"team":"finance"}},"minimum_version":"1.0.0-technical-preview.4","platforms":["linux"],"required_capabilities":["managed_dns"],"minimum_credential_seconds":60}});
    let mut draft = DeviceConditionDraft::from_response(&value).unwrap();
    assert_eq!(draft.version, Some(3));
    assert_eq!(draft.value().unwrap().scope.labels["team"], "finance");
    draft.minimum_version = "latest".into();
    assert!(draft.value().is_none());
    draft.minimum_version.clear();
    draft.scope = "{\"user\":\"admin\"}".into();
    assert!(draft.value().is_none());
    let html = dioxus::ssr::render_element(
        rsx! {DeviceConditionsPanel {mesh:uuid::Uuid::new_v4().to_string(),csrf:None,can_write:false,locale:Locale::ZhCn}},
    );
    assert!(html.contains("设备条件"));
    assert!(html.contains("class=\"plain-fieldset\" disabled"));
}
