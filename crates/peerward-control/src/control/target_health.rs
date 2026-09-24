async fn get_target_health(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
) -> Result<Json<Value>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let resource = load_network_resource(&state.store, mesh, id).await?;
    let bindings: Vec<Value> = sqlx::query_scalar(
        "SELECT jsonb_build_object('binding_id',b.id,'peer_id',b.peer_id,'peer_name',p.name,
            'binding_version',b.version,'resource_version',r.version,
            'status',CASE WHEN h.binding_version=b.version AND h.resource_version=r.version
                AND h.valid_until>clock_timestamp() AND h.observed_at<=clock_timestamp()
                AND b.approved AND p.administrative_state='enabled'
                AND c.lifecycle IN ('active','overlap') AND (c.lifecycle='active' OR c.overlap_deadline>clock_timestamp())
                AND c.not_before<=clock_timestamp() AND c.not_after>clock_timestamp()
                AND a.lifecycle IN ('active','overlap') AND (a.lifecycle='active' OR a.overlap_deadline>clock_timestamp())
                AND a.not_before<=clock_timestamp() AND a.not_after>clock_timestamp()
                THEN h.result ELSE 'unknown' END,
            'source','gateway_tcp_connect','observed_at',h.observed_at,'valid_until',h.valid_until)
         FROM gateway_bindings b JOIN peers p ON p.mesh_id=b.mesh_id AND p.id=b.peer_id
         JOIN network_resources r ON r.mesh_id=b.mesh_id AND r.id=b.resource_id
         LEFT JOIN target_health_observations h ON h.mesh_id=b.mesh_id AND h.binding_id=b.id
         LEFT JOIN peer_credentials c ON c.mesh_id=b.mesh_id AND c.peer_id=b.peer_id AND c.serial=h.credential_serial
         LEFT JOIN mesh_authorities a ON a.mesh_id=c.mesh_id AND a.id=c.authority_id
         WHERE b.mesh_id=$1 AND b.resource_id=$2 ORDER BY b.priority,b.peer_id,b.id",
    ).bind(mesh).bind(id).fetch_all(state.store.pool()).await?;
    Ok(Json(
        json!({"resource_id":id,"resource_version":resource.version,
        "probe":resource.definition.health_probe,"bindings":bindings,
        "authorization_evaluated":false,"application_authentication":"not_tested"}),
    ))
}
