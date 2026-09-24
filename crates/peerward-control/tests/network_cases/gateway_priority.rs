use super::*;

pub async fn verify(store: &Store, app: &Router, mesh: Uuid, binding: Uuid) {
    let path = format!("/api/v1/meshes/{mesh}/gateway-bindings/{binding}");
    assert_eq!(
        request(app, "PATCH", &path, None, json!({"priority":50}))
            .await
            .status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    assert_eq!(
        request(
            app,
            "PATCH",
            &path,
            Some(2),
            json!({"priority":50,"approved":false})
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    let (first, second) = tokio::join!(
        request(app, "PATCH", &path, Some(2), json!({"priority":50})),
        request(app, "PATCH", &path, Some(2), json!({"priority":u32::MAX})),
    );
    assert!([first.status(), second.status()].contains(&StatusCode::OK));
    assert!([first.status(), second.status()].contains(&StatusCode::CONFLICT));
    let current = json_body(request(app, "GET", &path, None, Value::Null).await).await;
    assert_eq!(current["version"], 3);
    assert_eq!(
        current["approved"], true,
        "priority is not a new approval source"
    );
    assert!([json!(50), json!(u32::MAX)].contains(&current["priority"]));
    let audits: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_log WHERE mesh_id=$1 AND target_id=$2 AND action='gateway_binding.priority'")
        .bind(mesh).bind(binding).fetch_one(store.pool()).await.unwrap();
    assert_eq!(
        audits, 1,
        "the losing version conflict produces no successful mutation"
    );
}
