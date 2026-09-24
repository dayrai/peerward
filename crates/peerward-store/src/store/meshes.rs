impl Store {
    /// Atomically creates a mesh, its empty policy, audit, and outbox event.
    pub async fn create_mesh(
        &self,
        request: &NewMesh,
        actor: &str,
    ) -> Result<MeshRecord, StoreError> {
        self.create_mesh_with_job(request, actor, None).await
    }

    /// Creates a complete lifecycle request and its default host assignment atomically.
    pub async fn create_mesh_with_job(
        &self,
        request: &NewMesh,
        actor: &str,
        job: Option<Uuid>,
    ) -> Result<MeshRecord, StoreError> {
        self.create_mesh_with_identifier(request, actor, job, None)
            .await
    }

    /// Creates the network and reserves its optional identifier in the same transaction.
    pub async fn create_mesh_with_identifier(
        &self,
        request: &NewMesh,
        actor: &str,
        job: Option<Uuid>,
        identifier: Option<&str>,
    ) -> Result<MeshRecord, StoreError> {
        request.validate()?;
        let policy_document = encode_policy_document(&Policy::new(
            1,
            match request.default_policy {
                DefaultPolicy::Allow => PolicyAction::Allow,
                DefaultPolicy::Deny => PolicyAction::Deny,
            },
            Vec::new(),
        ))
        .map_err(|_| StoreError::Invalid("default policy"))?;
        let mut transaction = self.pool.begin().await?;
        if let Some(job) = job {
            if job.get_version_num() != 4 {
                return Err(StoreError::Invalid("request UUID"));
            }
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind(format!("mesh-create/{job}"))
                .execute(&mut *transaction)
                .await?;
            if let Some(row) = sqlx::query(
                "SELECT mesh_id,request,network_identifier FROM mesh_lifecycle_jobs WHERE id=$1",
            )
            .bind(job)
            .fetch_optional(&mut *transaction)
            .await?
            {
                if row
                    .try_get::<Option<String>, _>("network_identifier")?
                    .as_deref()
                    != identifier
                    || row.try_get::<Value, _>("request")?
                        != serde_json::to_value(request)
                            .map_err(|_| StoreError::Invalid("mesh request"))?
                {
                    return Err(StoreError::Conflict);
                }
                let mesh = MeshId::from_uuid(row.try_get("mesh_id")?)
                    .map_err(|_| StoreError::Invalid("mesh ID"))?;
                transaction.rollback().await?;
                return self.mesh(mesh).await;
            }
        }
        if job.is_some() {
            sqlx::query(
                "SELECT pg_advisory_xact_lock(hashtextextended('mesh-prefix-allocation',0))",
            )
            .execute(&mut *transaction)
            .await?;
            let overlaps: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM meshes WHERE address_cidr && $1::cidr OR secondary_cidr && $1::cidr)",
            )
            .bind(request.address_cidr.to_string())
            .fetch_one(&mut *transaction)
            .await?;
            if overlaps {
                return Err(StoreError::Invalid("mesh prefix overlaps"));
            }
        }
        if let Some(identifier) = identifier {
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
                .bind(format!("network-identifier/{identifier}"))
                .execute(&mut *transaction)
                .await?;
            let exists: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM meshes WHERE network_identifier=$1)",
            )
            .bind(identifier)
            .fetch_one(&mut *transaction)
            .await?;
            if exists {
                return Err(StoreError::Invalid("network identifier exists"));
            }
        }
        let host = if job.is_some() {
            Some(
                sqlx::query_scalar::<_, Uuid>(
                    "SELECT id FROM relay_hosts WHERE is_default AND enabled AND maintenance_state='active' FOR UPDATE",
                )
                .fetch_optional(&mut *transaction)
                .await?
                .ok_or(StoreError::Invalid("no default Relay host"))?,
            )
        } else {
            None
        };
        let id = MeshId::new();
        let reserved: Vec<String> = request.reserved.iter().map(ToString::to_string).collect();
        sqlx::query(
            "INSERT INTO meshes
             (id, name, address_cidr, gateway, dns_suffix, mtu, reserved_addresses,
              default_policy, quarantine_seconds, rotation_overlap_seconds,
              policy_revision, service_revision, revocation_revision, lifecycle, network_identifier)
             VALUES ($1, $2, $3::cidr, $4::inet, $5, $6, $7::text[]::inet[], $8, $9, $10, 1, 1, 1, $11, $12)",
        )
        .bind(id.into_uuid())
        .bind(&request.name)
        .bind(request.address_cidr.to_string())
        .bind(request.gateway.to_string())
        .bind(&request.dns_suffix)
        .bind(i32::from(request.mtu))
        .bind(reserved)
        .bind(request.default_policy.as_str())
        .bind(
            i64::try_from(request.quarantine_seconds)
                .map_err(|_| StoreError::Invalid("quarantine"))?,
        )
        .bind(
            i64::try_from(request.rotation_overlap_seconds)
                .map_err(|_| StoreError::Invalid("rotation overlap"))?,
        )
        .bind(if job.is_some() { "creating" } else { "active" })
        .bind(identifier)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO policies (mesh_id, revision, default_action, document, current)
             VALUES ($1, 1, $2, $3, true)",
        )
        .bind(id.into_uuid())
        .bind(request.default_policy.as_str())
        .bind(policy_document)
        .execute(&mut *transaction)
        .await?;
        // Acquire assignment/host locks before the global audit/outbox locks.
        if let (Some(job), Some(host)) = (job, host) {
            sqlx::query("INSERT INTO mesh_lifecycle_jobs(id,mesh_id,operation,request,actor,network_identifier) VALUES($1,$2,'create',$3,$4,$5)")
                .bind(job).bind(id.into_uuid()).bind(serde_json::to_value(request).map_err(|_| StoreError::Invalid("mesh request"))?)
                .bind(actor).bind(identifier).execute(&mut *transaction).await?;
            sqlx::query(
                "INSERT INTO relay_host_assignments(host_id,mesh_id,relay_id) VALUES($1,$2,$3)",
            )
            .bind(host)
            .bind(id.into_uuid())
            .bind(RelayId::new().into_uuid())
            .execute(&mut *transaction)
            .await?;
            sqlx::query("UPDATE relay_hosts SET revision=revision+1 WHERE id=$1")
                .bind(host)
                .execute(&mut *transaction)
                .await?;
        }
        append_audit(
            &mut transaction,
            Some(id),
            actor,
            "mesh.create",
            "mesh",
            Some(id.into_uuid()),
            "success",
            json!({"name": request.name, "network_identifier": identifier}),
        )
        .await?;
        append_event(
            &mut transaction,
            Some(id),
            "mesh.created",
            "mesh",
            Some(id.into_uuid()),
            json!({"mesh_id": id, "name": request.name}),
        )
        .await?;
        transaction.commit().await?;
        self.mesh(id).await
    }

    /// Lists meshes using stable UUID ordering and a bounded cursor.
    pub async fn list_meshes(
        &self,
        after: Option<PageCursor>,
        limit: u16,
    ) -> Result<Page<MeshRecord>, StoreError> {
        validate_limit(limit)?;
        let rows = sqlx::query(
            "SELECT id, name, network_identifier, address_cidr::text AS cidr, host(gateway) AS gateway,
                    secondary_cidr::text AS secondary_cidr, host(secondary_gateway) AS secondary_gateway,
                    dns_suffix, mtu, default_policy, version, policy_revision, authority_revision, lease_seconds,
                    directory_revision, relay_revision,
                    service_revision, revocation_revision, lifecycle, lifecycle_revision,
                    (SELECT id FROM mesh_lifecycle_jobs j WHERE j.mesh_id=meshes.id ORDER BY created_at DESC LIMIT 1) AS lifecycle_job, created_at AS cursor_time
             FROM meshes WHERE lifecycle<>'deleted' AND ($1::timestamptz IS NULL OR (created_at,id) > ($1,$2))
             ORDER BY created_at,id LIMIT $3",
        )
        .bind(after.map(|cursor| cursor.timestamp))
        .bind(after.map(|cursor| cursor.id))
        .bind(i64::from(limit) + 1)
        .fetch_all(&self.pool)
        .await?;
        page_from_rows(rows, limit, mesh_from_row)
    }

    /// Fetches one mesh.
    pub async fn mesh(&self, id: MeshId) -> Result<MeshRecord, StoreError> {
        let row = sqlx::query(
            "SELECT id, name, network_identifier, address_cidr::text AS cidr, host(gateway) AS gateway,
                    secondary_cidr::text AS secondary_cidr, host(secondary_gateway) AS secondary_gateway,
                    dns_suffix, mtu, default_policy, version, policy_revision, authority_revision, lease_seconds,
                    directory_revision, relay_revision,
                    service_revision, revocation_revision, lifecycle, lifecycle_revision,
                    (SELECT id FROM mesh_lifecycle_jobs j WHERE j.mesh_id=meshes.id ORDER BY created_at DESC LIMIT 1) AS lifecycle_job
             FROM meshes WHERE id = $1",
        )
        .bind(id.into_uuid())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)?;
        mesh_from_row(row)
    }
}
