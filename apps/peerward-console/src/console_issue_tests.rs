#[test]
fn actionable_issue_copy_distinguishes_impact_and_routes_to_the_object() {
    let mesh = uuid::Uuid::new_v4();
    let resource = uuid::Uuid::new_v4();
    let issue = peerward_api::ConsoleIssue {
        id: format!("device_offline:{resource}"),
        fingerprint: "presence:offline".into(),
        mesh_id: mesh,
        kind: "device_offline".into(),
        severity: "warning".into(),
        name: "desk-laptop".into(),
        resource_id: resource,
        href: format!("/peers?mesh={mesh}&resource={resource}"),
        observed_at: None,
        known: false,
        read: false,
    };
    assert_eq!(issue_impact(Locale::ZhCn, &issue.kind, &issue.severity), "影响这台设备");
    assert_eq!(issue_action_label(Locale::ZhCn, &issue.kind), "检查设备");
    assert_eq!(issue_action_href(&issue), issue.href);

    let mut pending = issue.clone();
    pending.kind = "join_pending".into();
    pending.href = format!("/join-tickets?mesh={mesh}&resource={resource}");
    assert_eq!(issue_impact(Locale::ZhCn, &pending.kind, &pending.severity), "不影响现有设备");
    assert_eq!(issue_action_href(&pending), pending.href);

    assert_eq!(
        issue_title(Locale::ZhCn, "credential_expiring", "critical"),
        "设备身份已经过期"
    );
    assert_eq!(
        issue_impact(Locale::ZhCn, "credential_expiring", "warning"),
        "暂不影响使用"
    );
    assert_eq!(
        issue_impact(Locale::ZhCn, "credential_expiring", "critical"),
        "可能阻止新连接"
    );
}
