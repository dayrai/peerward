use super::*;

fn existing_policy() -> PolicyPutRequest {
    serde_json::from_value(json!({"revision":7,"default_action":"deny","rules":[{
        "id":uuid::Uuid::new_v4(),"priority":10,"action":"deny","enabled":true,"log":true,
        "source":{"peer_ids":[],"cidrs":["192.168.0.0/16"],"labels":{"scope":"restricted"}},
        "destination":{"peer_ids":[],"cidrs":[],"labels":{}},
        "protocol":"tcp","destination_ports":[{"first":80,"last":90}]
    }]}))
    .unwrap()
}

#[test]
fn policy_editor_loads_complete_document_and_preserves_existing_selectors() {
    let original = existing_policy();
    let document = policy_editor_document(&original);
    assert!(!policy_editor_dirty(&document, &original));
    let a = uuid::Uuid::new_v4().to_string();
    let b = uuid::Uuid::new_v4().to_string();
    let edited = append_device_rules(&document, &a, &b, "ping", true).unwrap();
    let request = policy_editor_request(&edited, 8).unwrap();
    assert_eq!(request.rules.len(), 3);
    assert_eq!(request.rules[0], original.rules[0]);
    assert_eq!(request.default_action, "deny");
    assert_eq!(request.revision, 8);
    assert!(policy_editor_dirty(&edited, &original));
    let rules = policy_rules(&edited);
    assert_eq!(rules[1]["source"]["peer_ids"], json!([a]));
    assert_eq!(rules[1]["destination"]["peer_ids"], json!([b]));
    assert_eq!(rules[2]["source"]["peer_ids"], json!([b]));
    assert_eq!(rules[2]["destination"]["peer_ids"], json!([a]));
    assert_eq!(rules[1]["protocol"], "icmp");
    assert_eq!(rules[1]["destination_ports"], json!([]));
    assert_eq!(rules[1]["priority"], 20);
    assert_eq!(rules[2]["priority"], 30);
    assert_eq!(
        append_device_rules(&edited, &a, &b, "ping", true).unwrap(),
        edited
    );
}

#[test]
fn policy_editor_rejects_invalid_drafts_and_same_device_without_losing_rules() {
    let a = uuid::Uuid::new_v4().to_string();
    let b = uuid::Uuid::new_v4().to_string();
    let document = policy_editor_document(&existing_policy());
    assert!(append_device_rules(&document, &a, &a, "ping", true).is_err());
    assert!(append_device_rules(&document, "", &b, "ping", true).is_err());
    let mut corrupt: Value = serde_json::from_str(&document).unwrap();
    corrupt["rules"] = json!("[");
    assert!(append_device_rules(&corrupt.to_string(), &a, &b, "ping", true).is_err());
    assert!(policy_editor_request(&corrupt.to_string(), 8).is_err());
}

#[test]
fn policy_editor_service_preset_only_adds_requested_port_and_direction() {
    let document = policy_editor_document(&existing_policy());
    let a = uuid::Uuid::new_v4().to_string();
    let b = uuid::Uuid::new_v4().to_string();
    for (preset, port) in [("ssh", 22), ("http", 80), ("https", 443)] {
        let edited = append_device_rules(&document, &a, &b, preset, false).unwrap();
        let rules = policy_rules(&edited);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[1]["protocol"], "tcp");
        assert_eq!(
            rules[1]["destination_ports"],
            json!([{"first":port,"last":port}])
        );
    }
}
