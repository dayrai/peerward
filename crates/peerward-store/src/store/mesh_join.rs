impl Store {
    /// Claims a ticket exactly once and allocates a stable usable address atomically.
    pub async fn claim_join(&self, request: &JoinClaim) -> Result<ClaimedPeer, StoreError> {
        let public = PublicJoinClaim {
            token: request.token.clone(),
            claim_id: request.claim_id,
            request_digest: request.request_digest,
            name: request.name.clone(),
            labels: request.labels.clone(),
            identity_public_key: request.identity_public_key.clone(),
            public_noise_key: request.public_key.clone(),
            wireguard_public_key: request.wireguard_public_key.clone(),
        };
        self.claim_public_join(&public, |_, _, _, _, _| {
            Ok(IssuedPeerEnrollment {
                credential: IssuedPeerCredential {
                    authority_id: request.authority_id,
                    authority_public_key: None,
                    serial: request.serial,
                    not_before: request.not_before,
                    not_after: request.not_after,
                    signature: request.signature.clone(),
                },
                response_document: b"{}".to_vec(),
            })
        })
        .await
    }

    /// Atomically claims a public-key-only enrollment and invokes the trusted
    /// online issuer only after the mesh, peer ID, and address are fixed.
    pub async fn claim_public_join<F>(
        &self,
        request: &PublicJoinClaim,
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
        self.claim_public_join_inner(request, secret_digest(&request.token), None, issue)
            .await
    }

    async fn claim_public_join_inner<F>(
        &self,
        request: &PublicJoinClaim,
        digest: [u8; 32],
        approval: Option<JoinApproval>,
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
        validate_dns_label(&request.name)?;
        validate_json_labels(&request.labels)?;
        if request.claim_id.get_version_num() != 4
            || request.identity_public_key.len() != 32
            || request.public_noise_key.len() != 32
            || request.wireguard_public_key.len() != 32
            || request.wireguard_public_key.iter().all(|byte| *byte == 0)
            || request.wireguard_public_key == request.public_noise_key
            || request.wireguard_public_key == request.identity_public_key
        {
            return Err(StoreError::Invalid("join identity"));
        }
        let _admission = self
            .join_admission
            .acquire()
            .await
            .map_err(|_| StoreError::Conflict)?;
        let mut transaction = self.pool.begin().await?;
        // Inspect without locking, rejecting competing replays before joining
        // the allocator queue. Then lock parent before ticket, as deletion does.
        let observed = sqlx::query("SELECT mesh_id,consumed_at,claim_id,claim_request_digest FROM join_tickets WHERE token_digest=$1")
            .bind(digest.as_slice()).fetch_optional(&mut *transaction).await?.ok_or(StoreError::NotFound)?;
        if observed
            .try_get::<Option<OffsetDateTime>, _>("consumed_at")?
            .is_some()
            && (observed.try_get::<Option<Uuid>, _>("claim_id")? != Some(request.claim_id)
                || observed
                    .try_get::<Option<Vec<u8>>, _>("claim_request_digest")?
                    .as_deref()
                    != Some(request.request_digest.as_slice()))
        {
            return Err(StoreError::Conflict);
        }
        let mesh_uuid: Uuid = observed.try_get("mesh_id")?;
        lock_join_mesh(&mut transaction, mesh_uuid).await?;
        let ticket = sqlx::query(
            "SELECT id, mesh_id, expires_at, consumed_at, cancelled_at, claimed_peer_id,
                    claimed_credential_id, claim_id, claim_request_digest, response_document, settings
             FROM join_tickets
             WHERE token_digest = $1 FOR UPDATE",
        )
        .bind(digest.as_slice())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(StoreError::NotFound)?;
        let ticket_id: Uuid = ticket.try_get("id")?;

        let expiry: OffsetDateTime = ticket.try_get("expires_at")?;
        let consumed: Option<OffsetDateTime> = ticket.try_get("consumed_at")?;
        if ticket
            .try_get::<Option<OffsetDateTime>, _>("cancelled_at")?
            .is_some()
        {
            return Err(StoreError::NotFound);
        }
        let settings: peerward_management::JoinSettings =
            serde_json::from_value(ticket.try_get("settings")?)
                .map_err(|_| StoreError::Invalid("invitation settings"))?;
        settings
            .validate()
            .map_err(|_| StoreError::Invalid("invitation settings"))?;
        match &settings.mode {
            peerward_management::JoinMode::Prebound {
                identity_fingerprint,
            } => {
                if identity_fingerprint
                    != &hex::encode(Sha256::digest(&request.identity_public_key))
                {
                    return Err(StoreError::Invalid("prebound identity"));
                }
            }
            peerward_management::JoinMode::Approval => {
                validate_join_approval(
                    &mut transaction,
                    ticket_id,
                    request,
                    approval.as_ref().ok_or(StoreError::Conflict)?,
                    consumed.is_some(),
                )
                .await?;
            }
            peerward_management::JoinMode::Bearer => {}
        }
        if consumed.is_some() {
            let expected_claim: Option<Uuid> = ticket.try_get("claim_id")?;
            let expected_digest: Option<Vec<u8>> = ticket.try_get("claim_request_digest")?;
            let claimed_peer: Option<Uuid> = ticket.try_get("claimed_peer_id")?;
            let credential_id: Option<Uuid> = ticket.try_get("claimed_credential_id")?;
            let response_document: Option<Vec<u8>> = ticket.try_get("response_document")?;
            if expected_claim != Some(request.claim_id)
                || expected_digest.as_deref() != Some(request.request_digest.as_slice())
            {
                return Err(StoreError::Conflict);
            }
            let row = sqlx::query(
                "SELECT host(a.address) AS address
                 FROM peer_addresses a JOIN meshes m ON m.id=a.mesh_id
                 WHERE a.mesh_id=$1 AND a.peer_id=$2 AND a.state='active'
                   AND family(a.address)=family(m.address_cidr)",
            )
            .bind(mesh_uuid)
            .bind(claimed_peer.ok_or(StoreError::Conflict)?)
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(StoreError::Conflict)?;
            let peer_id = PeerId::from_uuid(claimed_peer.ok_or(StoreError::Conflict)?)
                .map_err(|_| StoreError::Invalid("peer id"))?;
            let mesh_id =
                MeshId::from_uuid(mesh_uuid).map_err(|_| StoreError::Invalid("mesh id"))?;
            let address = row
                .try_get::<String, _>("address")?
                .parse()
                .map_err(|_| StoreError::Invalid("peer address"))?;
            transaction.commit().await?;
            return Ok(ClaimedPeer {
                peer_id,
                mesh_id,
                address,
                credential_id: credential_id.ok_or(StoreError::Conflict)?,
                response_document: response_document.ok_or(StoreError::Conflict)?,
                replayed: true,
            });
        }
        if approval.is_none() && expiry <= OffsetDateTime::now_utc() {
            return Err(StoreError::Conflict);
        }
        let address = allocate_address(&mut transaction, mesh_uuid, false).await?;
        let secondary_address = allocate_address(&mut transaction, mesh_uuid, true).await?;
        let peer_id = PeerId::new();
        let mesh_id = MeshId::from_uuid(mesh_uuid).map_err(|_| StoreError::Invalid("mesh id"))?;
        let admission_until = settings
            .lifecycle
            .deadline()
            .map(|seconds| {
                i64::try_from(seconds)
                    .map_err(|_| StoreError::Invalid("admission deadline"))
                    .and_then(|seconds| {
                        OffsetDateTime::from_unix_timestamp(seconds)
                            .map_err(|_| StoreError::Invalid("admission deadline"))
                    })
            })
            .transpose()?;
        if admission_until.is_some_and(|deadline| deadline <= OffsetDateTime::now_utc()) {
            return Err(StoreError::Invalid("admission expired"));
        }
        let enrollment = issue(
            mesh_id,
            peer_id,
            address,
            secondary_address,
            settings.lifecycle.deadline(),
        )?;
        let issued = enrollment.credential;
        if issued.signature.len() != 64 || issued.not_before >= issued.not_after {
            return Err(StoreError::Invalid("credential"));
        }
        if !(2..=1_048_576).contains(&enrollment.response_document.len())
            || serde_json::from_slice::<Value>(&enrollment.response_document).is_err()
        {
            return Err(StoreError::Invalid("join response"));
        }
        let authority_valid: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM mesh_authorities
             WHERE id=$1 AND mesh_id=$2 AND lifecycle IN ('active','overlap')
               AND ($3::bytea IS NULL OR public_key=$3)
               AND not_before <= clock_timestamp() AND not_after > clock_timestamp())",
        )
        .bind(issued.authority_id)
        .bind(mesh_uuid)
        .bind(&issued.authority_public_key)
        .fetch_one(&mut *transaction)
        .await?;
        if !authority_valid {
            return Err(StoreError::Conflict);
        }
        let assigned_name = settings.name.as_deref().unwrap_or(&request.name);
        let mut assigned_labels = request.labels.clone();
        let labels = assigned_labels
            .as_object_mut()
            .ok_or(StoreError::Invalid("join labels"))?;
        for (key, value) in &settings.labels {
            labels.insert(key.clone(), Value::String(value.clone()));
        }
        validate_json_labels(&assigned_labels)?;
        sqlx::query("INSERT INTO peers (id, mesh_id, name, labels,admission_kind,admission_until,display_name) VALUES ($1, $2, $3, $4,$5,$6,$7)")
            .bind(peer_id.into_uuid())
            .bind(mesh_uuid)
            .bind(assigned_name)
            .bind(&assigned_labels)
            .bind(settings.lifecycle.kind()).bind(admission_until)
            .bind(&settings.display_name)
            .execute(&mut *transaction)
            .await?;
        enroll_device_groups(
            &mut transaction,
            mesh_id,
            peer_id,
            ticket_id,
            &settings.device_groups,
            approval
                .as_ref()
                .map_or("join-ticket", |approval| approval.actor.as_str()),
        )
        .await?;
        for assigned in [address, secondary_address] {
            sqlx::query(
                "INSERT INTO peer_addresses (id, mesh_id, peer_id, address, state)
             VALUES ($1, $2, $3, $4::inet, 'active')",
            )
            .bind(Uuid::new_v4())
            .bind(mesh_uuid)
            .bind(peer_id.into_uuid())
            .bind(assigned.to_string())
            .execute(&mut *transaction)
            .await?;
        }
        let credential_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO peer_credentials
             (id, mesh_id, peer_id, authority_id, serial, identity_public_key, public_key, not_before,
              not_after, lifecycle, signature, wireguard_public_key)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',$10,$11)",
        )
        .bind(credential_id)
        .bind(mesh_uuid)
        .bind(peer_id.into_uuid())
        .bind(issued.authority_id)
        .bind(issued.serial.into_uuid())
        .bind(&request.identity_public_key)
        .bind(&request.public_noise_key)
        .bind(issued.not_before)
        .bind(issued.not_after)
        .bind(&issued.signature)
        .bind(&request.wireguard_public_key)
        .execute(&mut *transaction)
        .await?;
        let changed = sqlx::query(
            "UPDATE join_tickets SET consumed_at = clock_timestamp(), claimed_peer_id = $1,
             claimed_credential_id=$2, claim_id=$3, claim_request_digest=$4,
             response_document=$5 WHERE id = $6 AND consumed_at IS NULL",
        )
        .bind(peer_id.into_uuid())
        .bind(credential_id)
        .bind(request.claim_id)
        .bind(request.request_digest.as_slice())
        .bind(&enrollment.response_document)
        .bind(ticket_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(StoreError::Conflict);
        }
        if let Some(approval) = &approval {
            let approved=sqlx::query("UPDATE join_applications SET status='approved',peer_id=$2,decided_at=clock_timestamp(),decision_version=version,decision_actor=$3 WHERE id=$1 AND status='pending' AND expires_at>clock_timestamp()")
                .bind(approval.application_id).bind(peer_id.into_uuid()).bind(&approval.actor).execute(&mut *transaction).await?.rows_affected();
            if approved != 1 {
                return Err(StoreError::Conflict);
            }
            mutation_records(
                &mut transaction,
                mesh_id,
                &approval.actor,
                "join.application.approve",
                "join.application.approved",
                "join_application",
                approval.application_id,
                json!({"peer_id":peer_id,"claim_id":request.claim_id}),
            )
            .await?;
        }
        sqlx::query("UPDATE meshes SET directory_revision = directory_revision + 1 WHERE id = $1")
            .bind(mesh_uuid)
            .execute(&mut *transaction)
            .await?;
        mutation_records(
            &mut transaction,
            mesh_id,
            "join-ticket",
            "join.claim",
            "peer.joined",
            "peer",
            peer_id.into_uuid(),
            json!({"peer_id": peer_id, "address": address}),
        )
        .await?;
        transaction.commit().await?;
        Ok(ClaimedPeer {
            peer_id,
            mesh_id,
            address,
            credential_id,
            response_document: enrollment.response_document,
            replayed: false,
        })
    }

    /// Returns the exact committed Join response without requiring the original online issuer.
    pub async fn replay_public_join(
        &self,
        request: &PublicJoinClaim,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let row = sqlx::query(
            "SELECT claim_id,claim_request_digest,response_document
             FROM join_tickets t JOIN meshes m ON m.id=t.mesh_id
             WHERE token_digest=$1 AND consumed_at IS NOT NULL AND m.lifecycle='active'",
        )
        .bind(secret_digest(&request.token).as_slice())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let claim_id: Option<Uuid> = row.try_get("claim_id")?;
        let digest: Option<Vec<u8>> = row.try_get("claim_request_digest")?;
        if claim_id != Some(request.claim_id)
            || digest.as_deref() != Some(request.request_digest.as_slice())
        {
            return Err(StoreError::Conflict);
        }
        let response: Option<Vec<u8>> = row.try_get("response_document")?;
        Ok(Some(response.ok_or(StoreError::Conflict)?))
    }

    /// Releases the active address into the mesh quarantine interval.
    pub async fn release_address(
        &self,
        mesh_id: MeshId,
        peer_id: PeerId,
        actor: &str,
    ) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT id FROM meshes WHERE id=$1 FOR UPDATE")
            .bind(mesh_id.into_uuid())
            .fetch_optional(&mut *transaction)
            .await?
            .ok_or(StoreError::NotFound)?;
        let changed = sqlx::query(
            "UPDATE peer_addresses a SET state = 'quarantine', released_at = clock_timestamp(),
                    quarantine_until = clock_timestamp() + make_interval(secs => m.quarantine_seconds::double precision)
             FROM meshes m WHERE a.mesh_id = $1 AND a.peer_id = $2 AND a.state = 'active'
               AND m.id = a.mesh_id",
        )
        .bind(mesh_id.into_uuid())
        .bind(peer_id.into_uuid())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        sqlx::query("UPDATE meshes SET directory_revision=directory_revision+1,service_revision=service_revision+1,management_revision=management_revision+1 WHERE id=$1").bind(mesh_id.into_uuid()).execute(&mut *transaction).await?;
        mutation_records(
            &mut transaction,
            mesh_id,
            actor,
            "peer.address.release",
            "peer.address_released",
            "peer",
            peer_id.into_uuid(),
            json!({"peer_id": peer_id}),
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }
}
