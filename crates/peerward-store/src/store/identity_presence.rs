impl Store {
    /// Acquires the runtime lease for one unique relay process generation.
    pub async fn acquire_relay_runtime(
        &self,
        mesh_id: MeshId,
        relay_id: RelayId,
        instance_id: Uuid,
        lease_deadline: OffsetDateTime,
    ) -> Result<i64, StoreError> {
        self.acquire_relay_runtime_with_capabilities(
            mesh_id,
            relay_id,
            instance_id,
            lease_deadline,
            0,
        )
        .await
    }

    /// Acquires a Relay lease and atomically advertises its named Wire capabilities.
    pub async fn acquire_relay_runtime_with_capabilities(
        &self,
        mesh_id: MeshId,
        relay_id: RelayId,
        instance_id: Uuid,
        lease_deadline: OffsetDateTime,
        wire_capabilities: u64,
    ) -> Result<i64, StoreError> {
        if instance_id.get_version_num() != 4 || lease_deadline <= OffsetDateTime::now_utc() {
            return Err(StoreError::Invalid("relay runtime lease"));
        }
        let wire_capabilities = i64::try_from(wire_capabilities)
            .map_err(|_| StoreError::Invalid("Relay capabilities"))?;
        let generation = sqlx::query_scalar(
            "INSERT INTO relay_runtime_leases
             (mesh_id,relay_id,instance_id,fencing_generation,lease_deadline,wire_capabilities,neighbor_health)
             VALUES($1,$2,$3,1,$4,$5,'[]'::jsonb)
             ON CONFLICT(mesh_id,relay_id) DO UPDATE SET
               instance_id=EXCLUDED.instance_id,
               fencing_generation=relay_runtime_leases.fencing_generation+1,
               lease_deadline=EXCLUDED.lease_deadline,
               wire_capabilities=EXCLUDED.wire_capabilities,
               neighbor_health=EXCLUDED.neighbor_health,updated_at=clock_timestamp()
             RETURNING fencing_generation",
        )
        .bind(mesh_id.into_uuid())
        .bind(relay_id.into_uuid())
        .bind(instance_id)
        .bind(lease_deadline)
        .bind(wire_capabilities)
        .fetch_one(&self.pool)
        .await?;
        Ok(generation)
    }

    /// Renews one exact runtime and atomically publishes bounded neighbor health.
    pub async fn renew_relay_runtime_with_health(
        &self,
        mesh_id: MeshId,
        relay_id: RelayId,
        instance_id: Uuid,
        generation: i64,
        lease_deadline: OffsetDateTime,
        neighbor_health: &[RelayNeighborHealth],
    ) -> Result<(), StoreError> {
        validate_neighbor_health(relay_id, neighbor_health)?;
        let neighbor_health = serde_json::to_value(neighbor_health)
            .map_err(|_| StoreError::Invalid("Relay neighbor health"))?;
        let changed = sqlx::query(
            "UPDATE relay_runtime_leases SET lease_deadline=$1,neighbor_health=$2,
               updated_at=clock_timestamp()
             WHERE mesh_id=$3 AND relay_id=$4 AND instance_id=$5 AND fencing_generation=$6",
        )
        .bind(lease_deadline)
        .bind(neighbor_health)
        .bind(mesh_id.into_uuid())
        .bind(relay_id.into_uuid())
        .bind(instance_id)
        .bind(generation)
        .execute(&self.pool)
        .await?
        .rows_affected();
        if changed == 1 {
            Ok(())
        } else {
            Err(StoreError::Conflict)
        }
    }

    /// Releases only the exact relay process generation.
    pub async fn release_relay_runtime(
        &self,
        mesh_id: MeshId,
        relay_id: RelayId,
        instance_id: Uuid,
        generation: i64,
    ) -> Result<(), StoreError> {
        sqlx::query(
            "DELETE FROM relay_runtime_leases WHERE mesh_id=$1 AND relay_id=$2
             AND instance_id=$3 AND fencing_generation=$4",
        )
        .bind(mesh_id.into_uuid())
        .bind(relay_id.into_uuid())
        .bind(instance_id)
        .bind(generation)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Inserts a rooted authority in staged lifecycle state.
    pub async fn stage_authority(
        &self,
        authority: &NewAuthority,
        actor: &str,
    ) -> Result<Uuid, StoreError> {
        if authority.public_key.len() != 32
            || authority.certificate.is_empty()
            || authority.not_before >= authority.not_after
        {
            return Err(StoreError::Invalid("authority credential"));
        }
        let id = Uuid::new_v4();
        let mut transaction = self.pool.begin().await?;
        sqlx::query(
            "INSERT INTO mesh_authorities
             (id, mesh_id, serial, public_key, not_before, not_after, lifecycle,
              replacement_id, overlap_deadline, certificate)
             VALUES ($1,$2,$3,$4,$5,$6,'staged',$7,$8,$9)",
        )
        .bind(id)
        .bind(authority.mesh_id.into_uuid())
        .bind(authority.serial.into_uuid())
        .bind(&authority.public_key)
        .bind(authority.not_before)
        .bind(authority.not_after)
        .bind(authority.replaces)
        .bind(authority.overlap_deadline)
        .bind(&authority.certificate)
        .execute(&mut *transaction)
        .await?;
        mutation_records(
            &mut transaction,
            authority.mesh_id,
            actor,
            "authority.stage",
            "authority.staged",
            "authority",
            id,
            json!({"authority_id": id, "serial": authority.serial}),
        )
        .await?;
        transaction.commit().await?;
        Ok(id)
    }

    /// Transitions an authority while keeping revocation exact to its serial.
    pub async fn transition_authority(
        &self,
        mesh_id: MeshId,
        serial: CredentialSerial,
        lifecycle: Lifecycle,
        actor: &str,
    ) -> Result<(), StoreError> {
        transition_credential(
            &self.pool,
            "mesh_authorities",
            mesh_id,
            serial,
            lifecycle,
            actor,
            "authority",
            None,
        )
        .await
    }

    /// Transitions an Authority only while its resource version matches.
    pub async fn transition_authority_if_version(
        &self,
        mesh_id: MeshId,
        authority_id: Uuid,
        expected_version: i64,
        serial: CredentialSerial,
        lifecycle: Lifecycle,
        actor: &str,
    ) -> Result<(), StoreError> {
        transition_credential(
            &self.pool,
            "mesh_authorities",
            mesh_id,
            serial,
            lifecycle,
            actor,
            "authority",
            Some((authority_id, expected_version)),
        )
        .await
    }

    /// Transitions a peer credential only while its owning Peer version matches.
    pub async fn transition_peer_credential_if_version(
        &self,
        mesh_id: MeshId,
        peer_id: Uuid,
        expected_version: i64,
        serial: CredentialSerial,
        lifecycle: Lifecycle,
        actor: &str,
    ) -> Result<(), StoreError> {
        transition_credential(
            &self.pool,
            "peer_credentials",
            mesh_id,
            serial,
            lifecycle,
            actor,
            "peer_credential",
            Some((peer_id, expected_version)),
        )
        .await
    }

    /// Transitions a relay credential only while its owning Relay version matches.
    pub async fn transition_relay_credential_if_version(
        &self,
        mesh_id: MeshId,
        relay_id: Uuid,
        expected_version: i64,
        serial: CredentialSerial,
        lifecycle: Lifecycle,
        actor: &str,
    ) -> Result<(), StoreError> {
        transition_credential(
            &self.pool,
            "relay_credentials",
            mesh_id,
            serial,
            lifecycle,
            actor,
            "relay_credential",
            Some((relay_id, expected_version)),
        )
        .await
    }

    /// Revokes active or overlap credentials whose acceptance window has elapsed.
    ///
    /// This is separate from retention cleanup: signed directories contain accepted serials, so
    /// crossing an overlap deadline or `not_after` must advance the relevant revisions before old
    /// rows are eventually deleted. A cluster-wide advisory election and per-table limits keep
    /// the reconciliation bounded when several Control instances run concurrently.
    pub async fn expire_credentials(&self, limit: u16) -> Result<u64, StoreError> {
        validate_limit(limit)?;
        let mut transaction = self.pool.begin().await?;
        let elected: bool = sqlx::query_scalar(
            "SELECT pg_try_advisory_xact_lock(hashtextextended('peerward/lifecycle-expiry/v1',0))",
        )
        .fetch_one(&mut *transaction)
        .await?;
        if !elected {
            transaction.rollback().await?;
            return Ok(0);
        }

        // authority, peer directory, relay directory, services, revocations
        let mut revisions = std::collections::BTreeMap::<Uuid, [bool; 5]>::new();
        let mut expired = 0_u64;
        for (table, resource_type, event_type, affected) in [
            (
                "mesh_authorities",
                "authority",
                "authority.expired",
                [true, true, true, true, true],
            ),
            (
                "peer_credentials",
                "peer_credential",
                "peer_credential.expired",
                [false, true, false, true, true],
            ),
            (
                "relay_credentials",
                "relay_credential",
                "relay_credential.expired",
                [false, false, true, false, true],
            ),
        ] {
            let statement = format!(
                "WITH candidates AS (
                   SELECT id,CASE WHEN not_after<=clock_timestamp()
                     THEN 'not_after' ELSE 'overlap_deadline' END AS reason
                   FROM {table} WHERE lifecycle IN ('active','overlap') AND
                     (not_after<=clock_timestamp() OR
                      (lifecycle='overlap' AND overlap_deadline<=clock_timestamp()))
                   ORDER BY LEAST(not_after,COALESCE(overlap_deadline,'infinity')),id
                   FOR UPDATE SKIP LOCKED LIMIT $1)
                 UPDATE {table} credential SET lifecycle='revoked',overlap_deadline=NULL
                 FROM candidates WHERE credential.id=candidates.id
                 RETURNING credential.id,credential.mesh_id,credential.serial,candidates.reason"
            );
            let rows = sqlx::query(&statement)
                .bind(i64::from(limit))
                .fetch_all(&mut *transaction)
                .await?;
            for row in rows {
                let id: Uuid = row.try_get("id")?;
                let mesh_uuid: Uuid = row.try_get("mesh_id")?;
                let serial = CredentialSerial::from_uuid(row.try_get("serial")?)
                    .map_err(|_| StoreError::Invalid("stored credential serial"))?;
                let reason: String = row.try_get("reason")?;
                let flags = revisions.entry(mesh_uuid).or_insert([false; 5]);
                for (flag, changed) in flags.iter_mut().zip(affected) {
                    *flag |= changed;
                }
                mutation_records(
                    &mut transaction,
                    MeshId::from_uuid(mesh_uuid)
                        .map_err(|_| StoreError::Invalid("stored mesh ID"))?,
                    "lifecycle-expiry",
                    event_type,
                    event_type,
                    resource_type,
                    id,
                    json!({"serial":serial,"lifecycle":"revoked","reason":reason}),
                )
                .await?;
                expired = expired.saturating_add(1);
            }
        }

        for (mesh_id, [authorities, peers, relays, services, revocations]) in revisions {
            sqlx::query(
                "UPDATE meshes SET authority_revision=authority_revision+$1,
                   directory_revision=directory_revision+$2,relay_revision=relay_revision+$3,
                   service_revision=service_revision+$4,revocation_revision=revocation_revision+$5,
                   updated_at=clock_timestamp() WHERE id=$6",
            )
            .bind(i64::from(authorities))
            .bind(i64::from(peers))
            .bind(i64::from(relays))
            .bind(i64::from(services))
            .bind(i64::from(revocations))
            .bind(mesh_id)
            .execute(&mut *transaction)
            .await?;
        }
        transaction.commit().await?;
        Ok(expired)
    }

    /// Acquires a fenced presence role and returns the new generation.
    pub async fn acquire_presence(&self, request: &PresenceLease) -> Result<i64, StoreError> {
        if request.lease_deadline <= OffsetDateTime::now_utc() {
            return Err(StoreError::Invalid("presence deadline"));
        }
        let mut transaction = self.pool.begin().await?;
        if !lock_enabled_peer(&mut transaction, request.mesh_id, request.peer_id).await? {
            return Err(StoreError::NotFound);
        }
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(format!(
                "{}:{}:{}",
                request.mesh_id, request.peer_id, request.role
            ))
            .execute(&mut *transaction)
            .await?;
        // Leases can be deleted on disconnect or expiry. Allocate the fence from
        // the durable identity so a reconnect never reuses a released generation.
        let generation: i64 = sqlx::query_scalar(
            "INSERT INTO peer_presence_generations(mesh_id,peer_id,generation)
             VALUES($1,$2,COALESCE((SELECT max(fencing_generation) FROM relay_presence_all
                                   WHERE mesh_id=$1 AND peer_id=$2),0)+1)
             ON CONFLICT(mesh_id,peer_id) DO UPDATE SET generation=GREATEST(
               peer_presence_generations.generation+1,EXCLUDED.generation)
             RETURNING generation",
        )
        .bind(request.mesh_id.into_uuid())
        .bind(request.peer_id.into_uuid())
        .fetch_one(&mut *transaction)
        .await?;
        let _persisted_generation: i64 = match request.role {
            PresenceRole::Primary => {
                sqlx::query_scalar(
                    "INSERT INTO relay_presence
                 (mesh_id,peer_id,relay_id,attachment_id,role,fencing_generation,lease_deadline)
                 VALUES($1,$2,$3,$4,'primary',$6,$5)
                 ON CONFLICT(mesh_id,peer_id,role) DO UPDATE SET
                   relay_id=EXCLUDED.relay_id,attachment_id=EXCLUDED.attachment_id,
                   fencing_generation=EXCLUDED.fencing_generation,
                   lease_deadline=EXCLUDED.lease_deadline,updated_at=clock_timestamp()
                 RETURNING fencing_generation",
                )
                .bind(request.mesh_id.into_uuid())
                .bind(request.peer_id.into_uuid())
                .bind(request.relay_id.into_uuid())
                .bind(request.attachment_id.into_uuid())
                .bind(request.lease_deadline)
                .bind(generation)
                .fetch_one(&mut *transaction)
                .await?
            }
            PresenceRole::Standby => {
                sqlx::query_scalar(
                    "INSERT INTO relay_standby_presence_v1
                 (mesh_id,peer_id,relay_id,attachment_id,fencing_generation,lease_deadline)
                 VALUES($1,$2,$3,$4,$6,$5)
                 ON CONFLICT(mesh_id,peer_id,relay_id) DO UPDATE SET
                   attachment_id=EXCLUDED.attachment_id,
                   fencing_generation=EXCLUDED.fencing_generation,
                   lease_deadline=EXCLUDED.lease_deadline,updated_at=clock_timestamp()
                 RETURNING fencing_generation",
                )
                .bind(request.mesh_id.into_uuid())
                .bind(request.peer_id.into_uuid())
                .bind(request.relay_id.into_uuid())
                .bind(request.attachment_id.into_uuid())
                .bind(request.lease_deadline)
                .bind(generation)
                .fetch_one(&mut *transaction)
                .await?
            }
        };
        append_event(
            &mut transaction,
            Some(request.mesh_id),
            "presence.acquired",
            "peer",
            Some(request.peer_id.into_uuid()),
            json!({"generation": generation, "role": request.role}),
        )
        .await?;
        transaction.commit().await?;
        Ok(generation)
    }

    /// Renews only the exact relay, attachment, role, and generation tuple.
    pub async fn renew_presence(
        &self,
        request: &PresenceLease,
        generation: i64,
    ) -> Result<(), StoreError> {
        if request.lease_deadline <= OffsetDateTime::now_utc() {
            return Err(StoreError::Invalid("presence deadline"));
        }
        let mut transaction = self.pool.begin().await?;
        if !lock_enabled_peer(&mut transaction, request.mesh_id, request.peer_id).await? {
            return Err(StoreError::NotFound);
        }
        let statement = match request.role {
            PresenceRole::Primary => {
                "UPDATE relay_presence SET lease_deadline=$1,updated_at=clock_timestamp()
                 WHERE mesh_id=$2 AND peer_id=$3 AND relay_id=$4 AND attachment_id=$5
                   AND role='primary' AND fencing_generation=$6"
            }
            PresenceRole::Standby => {
                "UPDATE relay_standby_presence_v1
                 SET lease_deadline=$1,updated_at=clock_timestamp()
                 WHERE mesh_id=$2 AND peer_id=$3 AND relay_id=$4 AND attachment_id=$5
                   AND fencing_generation=$6"
            }
        };
        let changed = sqlx::query(statement)
            .bind(request.lease_deadline)
            .bind(request.mesh_id.into_uuid())
            .bind(request.peer_id.into_uuid())
            .bind(request.relay_id.into_uuid())
            .bind(request.attachment_id.into_uuid())
            .bind(generation)
            .execute(&mut *transaction)
            .await?
            .rows_affected();
        if changed == 1 {
            transaction.commit().await?;
            Ok(())
        } else {
            Err(StoreError::Conflict)
        }
    }

    /// Releases only the exact fenced attachment owned by the calling relay session.
    pub async fn release_presence(
        &self,
        request: &PresenceLease,
        generation: i64,
    ) -> Result<(), StoreError> {
        let statement = match request.role {
            PresenceRole::Primary => {
                "DELETE FROM relay_presence WHERE mesh_id=$1 AND peer_id=$2 AND relay_id=$3
                 AND attachment_id=$4 AND role='primary' AND fencing_generation=$5"
            }
            PresenceRole::Standby => {
                "DELETE FROM relay_standby_presence_v1
                 WHERE mesh_id=$1 AND peer_id=$2 AND relay_id=$3
                   AND attachment_id=$4 AND fencing_generation=$5"
            }
        };
        let changed = sqlx::query(statement)
            .bind(request.mesh_id.into_uuid())
            .bind(request.peer_id.into_uuid())
            .bind(request.relay_id.into_uuid())
            .bind(request.attachment_id.into_uuid())
            .bind(generation)
            .execute(&self.pool)
            .await?
            .rows_affected();
        if changed == 1 {
            Ok(())
        } else {
            Err(StoreError::Conflict)
        }
    }

    /// Resolves the current non-expired primary owner for one peer.
    pub async fn active_presence(
        &self,
        mesh_id: MeshId,
        peer_id: PeerId,
    ) -> Result<PresenceOwner, StoreError> {
        let row = sqlx::query(
            "SELECT relay_id,fencing_generation FROM relay_presence
             WHERE mesh_id=$1 AND peer_id=$2 AND role='primary'
               AND lease_deadline>clock_timestamp()",
        )
        .bind(mesh_id.into_uuid())
        .bind(peer_id.into_uuid())
        .fetch_optional(&self.pool)
        .await?
        .ok_or(StoreError::NotFound)?;
        Ok(PresenceOwner {
            relay_id: RelayId::from_uuid(row.try_get("relay_id")?)
                .map_err(|_| StoreError::Invalid("stored relay ID"))?,
            generation: row.try_get("fencing_generation")?,
        })
    }
}

include!("neighbor_health.rs");
