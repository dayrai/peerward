#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AssignRelayHostRequest { host_id: Uuid }

async fn list_relay_hosts(Extension(context): Extension<AuthContext>, State(state): State<AppState>) -> Result<Json<Value>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::TrustManage, false)?;
    let rows = sqlx::query("SELECT id,name,enabled,is_default,revision,peer_endpoints,backbone_endpoints,maintenance_state,last_seen FROM relay_hosts ORDER BY id")
        .fetch_all(state.store.pool()).await?;
    let items = rows.into_iter().map(|row| -> Result<Value, ApiError> {
        Ok(json!({"id":row.try_get::<Uuid,_>("id")?,"name":row.try_get::<String,_>("name")?,
            "maintenance_state":row.try_get::<String,_>("maintenance_state")?,"last_seen":row.try_get::<Option<OffsetDateTime>,_>("last_seen")?,
            "enabled":row.try_get::<bool,_>("enabled")?,"is_default":row.try_get::<bool,_>("is_default")?,
            "revision":row.try_get::<i64,_>("revision")?,"peer_endpoints":row.try_get::<Vec<String>,_>("peer_endpoints")?,
            "backbone_endpoints":row.try_get::<Vec<String>,_>("backbone_endpoints")?}))
    }).collect::<Result<Vec<_>,_>>()?;
    Ok(Json(json!({"items":items,"next_cursor":null})))
}

async fn assign_relay_host(Extension(context): Extension<AuthContext>, State(state): State<AppState>, headers: HeaderMap,
    Path(mesh): Path<Uuid>, ApiJson(body): ApiJson<AssignRelayHostRequest>) -> Result<(StatusCode,Json<Value>),ApiError> {
    authorize(&context,&headers,Capability::TrustManage,true)?;
    let mesh_id = mesh_id(mesh)?;
    let mut tx = state.store.begin_mutation().await?;
    let live: Option<String> = sqlx::query_scalar("SELECT lifecycle FROM meshes WHERE id=$1 FOR UPDATE")
        .bind(mesh).fetch_optional(&mut *tx).await?;
    if live.as_deref()!=Some("active") { return Err(ApiError::conflict("mesh_not_active","Mesh is not active")); }
    let host = sqlx::query("SELECT id FROM relay_hosts WHERE id=$1 AND enabled AND maintenance_state='active'
        AND NOT EXISTS(SELECT 1 FROM maintenance_tasks WHERE host_id=$1 AND status IN ('queued','waiting','failed')) FOR UPDATE")
        .bind(body.host_id).fetch_optional(&mut *tx).await?;
    if host.is_none() { return Err(ApiError::not_found()); }
    let inserted = sqlx::query("INSERT INTO relay_host_assignments(host_id,mesh_id,relay_id) VALUES($1,$2,$3)
        ON CONFLICT(host_id,mesh_id) DO NOTHING")
        .bind(body.host_id).bind(mesh).bind(Uuid::new_v4()).execute(&mut *tx).await?.rows_affected();
    if inserted > 0 {
        sqlx::query("UPDATE relay_hosts SET revision=revision+1 WHERE id=$1").bind(body.host_id).execute(&mut *tx).await?;
    }
    let row = sqlx::query("SELECT relay_id,revision,state FROM relay_host_assignments WHERE host_id=$1 AND mesh_id=$2")
        .bind(body.host_id).bind(mesh).fetch_one(&mut *tx).await?;
    let result = json!({"host_id":body.host_id,"mesh_id":mesh,"relay_id":row.try_get::<Uuid,_>("relay_id")?,
        "revision":row.try_get::<i64,_>("revision")?,"state":row.try_get::<String,_>("state")?});
    state.store.commit_mutation(tx,&lifecycle_record(mesh_id,&context.actor,"relay.host_assigned","relay.host_assigned")).await?;
    Ok((StatusCode::ACCEPTED,Json(result)))
}
