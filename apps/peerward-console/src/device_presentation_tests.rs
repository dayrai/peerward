#[test]
fn device_rows_show_allocated_ip_and_human_description_without_inventing_location() {
    let resource = ResourceSummary {
        id: uuid::Uuid::new_v4().to_string(),
        name: "home-nas".into(),
        details: BTreeMap::from([
            ("display_name".into(), json!("家庭记忆库")),
            ("location".into(), json!("书房")),
            ("mesh_addresses".into(), json!(["100.96.195.2", "fd00::2"])),
            ("online".into(), json!(false)),
            (
                "labels".into(),
                json!({"platform":"linux","device_model":"x86_64"}),
            ),
        ]),
    };
    let html = render_route(
        ConsoleRoute::Peers,
        ConsoleSnapshot {
            resources: vec![resource.clone()],
            ..ConsoleSnapshot::sample()
        },
    );
    for text in [
        "家庭记忆库",
        "home-nas",
        "100.96.195.2",
        "fd00::2",
        "书房",
        "linux",
        "Offline",
    ] {
        assert!(html.contains(text), "missing device information: {text}");
    }
    let document = editor_document_for_resource(ConsoleRoute::Peers, &resource);
    let edit = operation_body(
        ConsoleRoute::Peers,
        BrowserOperation::Edit,
        "home-nas",
        &document,
    )
    .unwrap();
    assert_eq!(edit["display_name"], "家庭记忆库");
    assert_eq!(edit["location"], "书房");
    assert_eq!(edit["labels"], resource.details["labels"]);
    let empty = ResourceSummary {
        details: BTreeMap::new(),
        ..resource
    };
    assert_eq!(peer_location(&empty, Locale::ZhCn), "未设置");
    assert!(peer_addresses(&empty).is_empty());
}

#[test]
fn finished_lifecycle_jobs_are_not_presented_as_existing_meshes() {
    let mut job: MeshProvisioningResource = serde_json::from_value(json!({
        "id":uuid::Uuid::new_v4(), "mesh_id":uuid::Uuid::new_v4(), "name":"old-mesh",
        "status":"succeeded", "stage":"complete", "operation":"delete",
        "existing_mesh":false, "created_at":"2026-09-08T00:00:00Z", "updated_at":"2026-09-08T00:00:00Z"
    })).unwrap();
    assert!(!visible_lifecycle_job(&job));
    job.operation = "create".into();
    assert!(!visible_lifecycle_job(&job));
    job.status = "failed".into();
    assert!(visible_lifecycle_job(&job));
    job.error_code = Some("mesh_deleted".into());
    assert!(!visible_lifecycle_job(&job));
    job.error_code = None;
    job.status = "running".into();
    job.operation = "delete".into();
    job.stage = "waiting_for_relay".into();
    assert!(visible_lifecycle_job(&job));
    assert_eq!(provisioning_stage_key(&job), "deletion-waiting-relay");
}

#[test]
fn trust_management_is_under_system_tools_and_requires_capability() {
    let mut snapshot = ConsoleSnapshot::sample();
    snapshot.capabilities.retain(|cap| cap != "trust_manage");
    let html = render_route(ConsoleRoute::Audit, snapshot.clone());
    assert!(!html.contains("href=\"/authorities"));
    snapshot.capabilities.push("trust_manage".into());
    let html = render_route(ConsoleRoute::Audit, snapshot);
    let primary = html
        .split("aria-label=\"Primary navigation\"")
        .nth(1)
        .unwrap()
        .split("</nav>")
        .next()
        .unwrap();
    assert!(!primary.contains("/authorities"));
    assert_eq!(primary.matches("href=").count(), 5);
    assert!(html.contains("Credentials and authorities"));
    assert!(html.contains("System tools"));
}

#[test]
fn read_only_mode_is_explicit_and_does_not_offer_mutating_shortcuts() {
    let snapshot = ConsoleSnapshot::sample();

    let overview = render_route(ConsoleRoute::Overview, snapshot.clone());
    assert!(overview.contains("Read-only mode"));
    // SSR has no live overview query yet; navigation remains available while loading.
    assert!(overview.contains("Loading network status"));
    for route in ["/peers?", "/services?", "/policy?"] {
        assert!(overview.contains(&format!("href=\"{route}")));
    }
    assert!(!overview.contains("＋ Add device"));
    assert!(!overview.contains("Add share"));
    assert!(!overview.contains("Adjust access"));

    let peers = render_route(ConsoleRoute::Peers, snapshot.clone());
    assert!(peers.contains("Read-only mode"));
    assert!(peers.contains("Advanced device information"));
    assert!(!peers.contains("＋ Add device"));

    let services = render_route(ConsoleRoute::Services, snapshot.clone());
    assert!(services.contains("Read-only mode"));
    assert!(services.contains("Advanced sharing information"));
    assert!(!services.contains("＋ Add share"));

    let policy = render_route(ConsoleRoute::Policy, snapshot);
    assert!(policy.contains("Read-only mode"));
    assert!(policy.contains("Advanced access information"));
}

#[test]
fn write_capability_restores_mutating_shortcuts_without_read_only_banner() {
    let mut snapshot = ConsoleSnapshot::sample();
    snapshot.capabilities.push("resource_write".into());
    snapshot.csrf_token = Some("test-csrf".into());

    let peers = render_route(ConsoleRoute::Peers, snapshot.clone());
    assert!(!peers.contains("Read-only mode"));
    assert!(peers.contains("＋ Add device"));
    assert!(peers.contains("Advanced device tools"));

    let services = render_route(ConsoleRoute::Services, snapshot);
    assert!(!services.contains("Read-only mode"));
    assert!(services.contains("＋ Add share"));
    assert!(services.contains("Advanced sharing tools"));
}
