#[derive(Deserialize)]
struct JoinApplicationQuery {
    cursor: Option<String>,
    limit: Option<u16>,
    ticket: Option<Uuid>,
}

async fn list_join_applications(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path(mesh): Path<Uuid>,
    Query(query): Query<JoinApplicationQuery>,
) -> Result<Json<ApiPage<peerward_management::JoinApplication>>, ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    let pagination = ListQuery {
        cursor: query.cursor,
        limit: query.limit,
    };
    let page = state
        .store
        .list_join_applications_for_ticket(
            mesh_id(mesh)?,
            query.ticket,
            pagination.cursor()?.map(|c| peerward_store::PageCursor {
                timestamp: c.timestamp,
                id: c.id,
            }),
            pagination.limit()?,
        )
        .await?;
    Ok(Json(ApiPage {
        items: page.items,
        next_cursor: page.next_cursor.map(|c| {
            encode_page_cursor(ApiPageCursor {
                timestamp: c.timestamp,
                id: c.id,
            })
        }),
    }))
}

async fn get_join_application(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<peerward_management::JoinApplication>), ApiError> {
    authorize(&context, &HeaderMap::new(), Capability::ResourceRead, false)?;
    mesh_id(mesh)?;
    let value = state.store.join_application(mesh, id).await?;
    Ok((etag_headers(value.version)?, Json(value)))
}

async fn approve_join_application(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
    ApiJson(body): ApiJson<peerward_management::JoinApprovalRequest>,
) -> Result<(HeaderMap, Json<peerward_management::JoinApplication>), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let expected = require_if_match(&headers)?;
    if !peerward_management::valid_identity_fingerprint(&body.identity_fingerprint) {
        return Err(ApiError::invalid(
            "invalid_fingerprint",
            "enter the full lowercase SHA-256 identity fingerprint verified through a trusted channel",
        ));
    }
    let mesh_id = mesh_id(mesh)?;
    let current = state.store.join_application(mesh, id).await?;
    if current.status == peerward_management::JoinApplicationStatus::Approved {
        state
            .store
            .approve_join_application(
                mesh_id,
                id,
                expected,
                &body.identity_fingerprint,
                &context.actor,
                |_, _, _, _, _| Err(StoreError::Conflict),
            )
            .await?;
    } else {
        let claim = state.store.pending_join_claim(mesh_id, id).await?;
        let issue = join_enrollment_issuer(&state, mesh_id, &claim).await?;
        state
            .store
            .approve_join_application(
                mesh_id,
                id,
                expected,
                &body.identity_fingerprint,
                &context.actor,
                issue,
            )
            .await?;
    }
    let value = state.store.join_application(mesh, id).await?;
    Ok((etag_headers(value.version)?, Json(value)))
}

async fn reject_join_application(
    Extension(context): Extension<AuthContext>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((mesh, id)): Path<(Uuid, Uuid)>,
) -> Result<(HeaderMap, Json<peerward_management::JoinApplication>), ApiError> {
    authorize(&context, &headers, Capability::ResourceWrite, true)?;
    let value = state
        .store
        .reject_join_application(
            mesh_id(mesh)?,
            id,
            require_if_match(&headers)?,
            &context.actor,
        )
        .await?;
    Ok((etag_headers(value.version)?, Json(value)))
}
