/// Trusted approval context, loaded and checked again inside the issuance transaction.
struct JoinApproval {
    application_id: Uuid,
    version: i64,
    actor: String,
}

const JOIN_APPLICATION_PROJECTION: &str = "SELECT jsonb_build_object(
    'id',a.id,'mesh_id',a.mesh_id,'ticket_id',a.ticket_id,'version',a.version,
    'claim_id',a.claim_id,'name',COALESCE(t.settings->>'name',a.request_document->>'name'),
    'identity_fingerprint',a.identity_fingerprint,
    'status',CASE WHEN a.status='pending' AND a.expires_at<=clock_timestamp() THEN 'expired' ELSE a.status END,
    'created_at',floor(extract(epoch FROM a.created_at))::bigint,
    'expires_at',floor(extract(epoch FROM a.expires_at))::bigint,'peer_id',a.peer_id)
    FROM join_applications a JOIN join_tickets t ON t.id=a.ticket_id";

impl Store {
    /// Reserves an approval invitation for the first authenticated claim. The
    /// caller has verified `PoP`; the persisted projection deliberately omits token.
    /// Ordinary and prebound tickets are checked again by atomic final issuance.
    pub async fn submit_join_application(
        &self,
        request: &PublicJoinClaim,
        signed_request: &Value,
    ) -> Result<Option<peerward_management::JoinApplication>, StoreError> {
        let digest = secret_digest(&request.token);
        let mesh: Uuid =
            sqlx::query_scalar("SELECT mesh_id FROM join_tickets WHERE token_digest=$1")
                .bind(digest.as_slice())
                .fetch_optional(&self.pool)
                .await?
                .ok_or(StoreError::NotFound)?;
        let mut tx = self.pool.begin().await?;
        lock_join_mesh(&mut tx, mesh).await?;
        let ticket=sqlx::query("SELECT id,settings,expires_at,cancelled_at,consumed_at FROM join_tickets WHERE token_digest=$1 FOR UPDATE")
            .bind(digest.as_slice()).fetch_one(&mut *tx).await?;
        let settings: peerward_management::JoinSettings =
            serde_json::from_value(ticket.try_get("settings")?)
                .map_err(|_| StoreError::Invalid("invitation settings"))?;
        if settings.mode != peerward_management::JoinMode::Approval {
            return Ok(None);
        }
        let ticket_id: Uuid = ticket.try_get("id")?;
        if let Some(existing) = sqlx::query(
            "SELECT id,claim_id,request_digest FROM join_applications WHERE ticket_id=$1",
        )
        .bind(ticket_id)
        .fetch_optional(&mut *tx)
        .await?
        {
            if existing.try_get::<Uuid, _>("claim_id")? != request.claim_id
                || existing.try_get::<Vec<u8>, _>("request_digest")? != request.request_digest
            {
                return Err(StoreError::Conflict);
            }
            let id = existing.try_get("id")?;
            tx.rollback().await?;
            return Ok(Some(self.join_application(mesh, id).await?));
        }
        if ticket
            .try_get::<Option<OffsetDateTime>, _>("cancelled_at")?
            .is_some()
        {
            return Err(StoreError::Conflict);
        }
        if ticket.try_get::<OffsetDateTime, _>("expires_at")? <= OffsetDateTime::now_utc()
            || ticket
                .try_get::<Option<OffsetDateTime>, _>("consumed_at")?
                .is_some()
        {
            return Err(StoreError::Conflict);
        }
        let id = Uuid::new_v4();
        let fingerprint = hex::encode(Sha256::digest(&request.identity_public_key));
        sqlx::query("INSERT INTO join_applications(id,mesh_id,ticket_id,claim_id,request_digest,request_document,identity_fingerprint,signed_request) VALUES($1,$2,$3,$4,$5,$6,$7,$8)")
            .bind(id).bind(mesh).bind(ticket_id).bind(request.claim_id).bind(request.request_digest.as_slice())
            .bind(serde_json::to_value(request).map_err(|_|StoreError::Invalid("join application"))?)
            .bind(fingerprint).bind(signed_request).execute(&mut *tx).await?;
        // Version changes once at reservation; no TTL is extended by polling.
        sqlx::query("UPDATE join_tickets SET version=version WHERE id=$1")
            .bind(ticket_id)
            .execute(&mut *tx)
            .await?;
        let mesh_id = MeshId::from_uuid(mesh).map_err(|_| StoreError::Invalid("mesh id"))?;
        mutation_records(
            &mut tx,
            mesh_id,
            "join-ticket",
            "join.application.submit",
            "join.application.pending",
            "join_application",
            id,
            json!({"ticket_id":ticket_id,"claim_id":request.claim_id}),
        )
        .await?;
        tx.commit().await?;
        Ok(Some(self.join_application(mesh, id).await?))
    }

    /// Metadata is available to authenticated administrators only; claim holders
    /// retrieve their own status by replaying the original signed request.
    pub async fn join_application(
        &self,
        mesh: Uuid,
        id: Uuid,
    ) -> Result<peerward_management::JoinApplication, StoreError> {
        let value: Value = sqlx::query_scalar(&format!(
            "{JOIN_APPLICATION_PROJECTION} WHERE a.mesh_id=$1 AND a.id=$2"
        ))
        .bind(mesh)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)?;
        serde_json::from_value(value).map_err(|_| StoreError::Invalid("join application"))
    }

    /// Page through complete retained application history using the shared cursor.
    pub async fn list_join_applications(
        &self,
        mesh: MeshId,
        after: Option<PageCursor>,
        limit: u16,
    ) -> Result<Page<peerward_management::JoinApplication>, StoreError> {
        self.list_join_applications_for_ticket(mesh, None, after, limit)
            .await
    }

    /// Filter before pagination so a current invitation cannot select an unrelated claim.
    pub async fn list_join_applications_for_ticket(
        &self,
        mesh: MeshId,
        ticket: Option<Uuid>,
        after: Option<PageCursor>,
        limit: u16,
    ) -> Result<Page<peerward_management::JoinApplication>, StoreError> {
        validate_limit(limit)?;
        // Wrap the projection to keep stable cursor metadata separate from the response.
        let projection = JOIN_APPLICATION_PROJECTION
            .replacen(
                "SELECT jsonb_build_object(",
                "SELECT a.id,a.created_at AS cursor_time,jsonb_build_object(",
                1,
            )
            .replacen(
                "FROM join_applications",
                "AS item FROM join_applications",
                1,
            );
        let rows=sqlx::query(&format!("{projection} WHERE a.mesh_id=$1 AND ($2::timestamptz IS NULL OR (a.created_at,a.id)>($2,$3)) AND ($5::uuid IS NULL OR a.ticket_id=$5) ORDER BY a.created_at,a.id LIMIT $4"))
            .bind(mesh.into_uuid()).bind(after.map(|c|c.timestamp)).bind(after.map(|c|c.id))
            .bind(i64::from(limit)+1).bind(ticket).fetch_all(&self.pool).await?;
        page_from_rows(rows, limit, |row| {
            serde_json::from_value(row.try_get("item")?)
                .map_err(|_| StoreError::Invalid("join application"))
        })
    }

    /// Loads the token-free verified projection so the issuer can select matching
    /// keys. Revalidation and all issuance writes happen under the original locks.
    pub async fn pending_join_claim(
        &self,
        mesh: MeshId,
        id: Uuid,
    ) -> Result<PublicJoinClaim, StoreError> {
        let document: Value = sqlx::query_scalar(
            "SELECT request_document FROM join_applications WHERE mesh_id=$1 AND id=$2",
        )
        .bind(mesh.into_uuid())
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)?;
        serde_json::from_value(document).map_err(|_| StoreError::Invalid("join application"))
    }

    /// Approval atomically fixes Peer, both addresses, credential, canonical
    /// response and audit. Repeating the original version returns the same result.
    pub async fn approve_join_application<F>(
        &self,
        mesh: MeshId,
        id: Uuid,
        version: i64,
        fingerprint: &str,
        actor: &str,
        issue: F,
    ) -> Result<ClaimedPeer, StoreError>
    where
        F: FnOnce(
            MeshId,
            PeerId,
            IpAddr,
            IpAddr,
            Option<u64>,
        ) -> Result<IssuedPeerEnrollment, StoreError>,
    {
        let row=sqlx::query("SELECT t.token_digest,a.request_document,a.identity_fingerprint FROM join_applications a JOIN join_tickets t ON t.id=a.ticket_id WHERE a.mesh_id=$1 AND a.id=$2")
            .bind(mesh.into_uuid()).bind(id).fetch_optional(&self.pool).await?.ok_or(StoreError::NotFound)?;
        if row.try_get::<String, _>("identity_fingerprint")? != fingerprint {
            return Err(StoreError::Invalid("confirmed fingerprint"));
        }
        let request: PublicJoinClaim = serde_json::from_value(row.try_get("request_document")?)
            .map_err(|_| StoreError::Invalid("join application"))?;
        let digest: [u8; 32] = row
            .try_get::<Vec<u8>, _>("token_digest")?
            .try_into()
            .map_err(|_| StoreError::Invalid("ticket digest"))?;
        self.claim_public_join_inner(
            &request,
            digest,
            Some(JoinApproval {
                application_id: id,
                version,
                actor: actor.to_owned(),
            }),
            issue,
        )
        .await
    }

    /// Rejecting never frees the single-use reservation. The original version is
    /// accepted on exact retries; a concurrent approval wins or loses atomically.
    pub async fn reject_join_application(
        &self,
        mesh: MeshId,
        id: Uuid,
        version: i64,
        actor: &str,
    ) -> Result<peerward_management::JoinApplication, StoreError> {
        let mut tx = self.pool.begin().await?;
        lock_join_mesh(&mut tx, mesh.into_uuid()).await?;
        sqlx::query("SELECT t.id FROM join_tickets t JOIN join_applications a ON a.ticket_id=t.id WHERE a.mesh_id=$1 AND a.id=$2 FOR UPDATE OF t")
            .bind(mesh.into_uuid()).bind(id).fetch_optional(&mut *tx).await?.ok_or(StoreError::NotFound)?;
        let row=sqlx::query("SELECT version,status,decision_version,expires_at FROM join_applications WHERE mesh_id=$1 AND id=$2 FOR UPDATE")
            .bind(mesh.into_uuid()).bind(id).fetch_one(&mut *tx).await?;
        if row.try_get::<String, _>("status")? == "rejected"
            && row.try_get::<Option<i64>, _>("decision_version")? == Some(version)
        {
            tx.rollback().await?;
            return self.join_application(mesh.into_uuid(), id).await;
        }
        if row.try_get::<i64, _>("version")? != version
            || row.try_get::<String, _>("status")? != "pending"
            || row.try_get::<OffsetDateTime, _>("expires_at")? <= OffsetDateTime::now_utc()
        {
            return Err(StoreError::Conflict);
        }
        sqlx::query("UPDATE join_applications SET status='rejected',decided_at=clock_timestamp(),decision_version=version,decision_actor=$3 WHERE mesh_id=$1 AND id=$2")
            .bind(mesh.into_uuid()).bind(id).bind(actor).execute(&mut *tx).await?;
        sqlx::query("UPDATE join_tickets SET version=version WHERE id=(SELECT ticket_id FROM join_applications WHERE id=$1)").bind(id).execute(&mut *tx).await?;
        mutation_records(
            &mut tx,
            mesh,
            actor,
            "join.application.reject",
            "join.application.rejected",
            "join_application",
            id,
            json!({}),
        )
        .await?;
        tx.commit().await?;
        self.join_application(mesh.into_uuid(), id).await
    }
}

async fn lock_join_mesh(tx: &mut Transaction<'_, Postgres>, mesh: Uuid) -> Result<(), StoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(mesh.to_string())
        .execute(&mut **tx)
        .await?;
    let lifecycle: Option<String> =
        sqlx::query_scalar("SELECT lifecycle FROM meshes WHERE id=$1 FOR UPDATE")
            .bind(mesh)
            .fetch_optional(&mut **tx)
            .await?;
    if lifecycle.as_deref() != Some("active") {
        return Err(StoreError::Invalid("mesh is not active"));
    }
    Ok(())
}

async fn validate_join_approval(
    tx: &mut Transaction<'_, Postgres>,
    ticket: Uuid,
    request: &PublicJoinClaim,
    approval: &JoinApproval,
    consumed: bool,
) -> Result<(), StoreError> {
    let row=sqlx::query("SELECT version,status,claim_id,request_digest,expires_at,decision_version FROM join_applications WHERE id=$1 AND ticket_id=$2 FOR UPDATE")
        .bind(approval.application_id).bind(ticket).fetch_optional(&mut **tx).await?.ok_or(StoreError::Conflict)?;
    if row.try_get::<Uuid, _>("claim_id")? != request.claim_id
        || row.try_get::<Vec<u8>, _>("request_digest")? != request.request_digest
    {
        return Err(StoreError::Conflict);
    }
    let valid = if consumed {
        row.try_get::<String, _>("status")? == "approved"
            && row.try_get::<Option<i64>, _>("decision_version")? == Some(approval.version)
    } else {
        row.try_get::<String, _>("status")? == "pending"
            && row.try_get::<i64, _>("version")? == approval.version
            && row.try_get::<OffsetDateTime, _>("expires_at")? > OffsetDateTime::now_utc()
    };
    if !valid {
        return Err(StoreError::Conflict);
    }
    Ok(())
}
