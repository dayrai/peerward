impl Store {
    /// Returns low-cost `PostgreSQL` audit-table capacity statistics for operational metrics.
    pub async fn audit_storage_stats(&self) -> Result<AuditStorageStats, StoreError> {
        let row = sqlx::query(
            "SELECT COALESCE(stats.n_live_tup,0)::bigint AS estimated_rows,
                    pg_total_relation_size('audit_log'::regclass)::bigint AS total_bytes,
                    COALESCE(stats.n_tup_ins,0)::bigint AS inserted_rows,
                    (SELECT stats_reset FROM pg_stat_database WHERE datname=current_database()) AS stats_reset
             FROM pg_stat_user_tables stats
             WHERE stats.relid='audit_log'::regclass",
        )
        .fetch_one(&self.pool)
        .await?;
        Ok(AuditStorageStats {
            stats_reset: row.try_get("stats_reset")?,
            estimated_rows: u64::try_from(row.try_get::<i64, _>("estimated_rows")?)
                .map_err(|_| StoreError::Invalid("audit row estimate"))?,
            total_bytes: u64::try_from(row.try_get::<i64, _>("total_bytes")?)
                .map_err(|_| StoreError::Invalid("audit table bytes"))?,
            inserted_rows: u64::try_from(row.try_get::<i64, _>("inserted_rows")?)
                .map_err(|_| StoreError::Invalid("audit inserted rows"))?,
        })
    }

    /// Idempotently queues one opaque audit envelope received on an authenticated Relay link.
    pub async fn queue_encrypted_audit(
        &self,
        mesh_id: MeshId,
        source_peer: PeerId,
        envelope: &[u8],
    ) -> Result<bool, StoreError> {
        if envelope.is_empty() || envelope.len() > 65_535 {
            return Err(StoreError::Invalid("encrypted audit envelope"));
        }
        let result = sqlx::query(
            "INSERT INTO encrypted_audit_inbox
             (id,mesh_id,source_peer,ciphertext_digest,envelope)
             VALUES ($1,$2,$3,$4,$5)
             ON CONFLICT (mesh_id,source_peer,ciphertext_digest) DO NOTHING",
        )
        .bind(Uuid::new_v4())
        .bind(mesh_id.into_uuid())
        .bind(source_peer.into_uuid())
        .bind(Sha256::digest(envelope).to_vec())
        .bind(envelope)
        .execute(&self.pool)
        .await?;
        Ok(result.rows_affected() == 1)
    }

    /// Leases a bounded set of ciphertexts without holding locks during decryption.
    pub async fn claim_encrypted_audits(
        &self,
        mesh_id: MeshId,
        limit: u32,
    ) -> Result<Vec<EncryptedAuditRecord>, StoreError> {
        if !(1..=256).contains(&limit) {
            return Err(StoreError::Invalid("encrypted audit claim limit"));
        }
        let rows = sqlx::query(
            "WITH candidates AS (
               SELECT id FROM encrypted_audit_inbox
               WHERE mesh_id=$1 AND (claimed_until IS NULL OR claimed_until < clock_timestamp())
               ORDER BY received_at,id FOR UPDATE SKIP LOCKED LIMIT $2
             )
             UPDATE encrypted_audit_inbox inbox
             SET claimed_until=clock_timestamp()+interval '30 seconds',attempts=attempts+1
             FROM candidates WHERE inbox.id=candidates.id
             RETURNING inbox.id,inbox.mesh_id,inbox.source_peer,inbox.envelope,inbox.attempts",
        )
        .bind(mesh_id.into_uuid())
        .bind(i64::from(limit))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(EncryptedAuditRecord {
                    id: row.try_get("id")?,
                    mesh_id: MeshId::from_uuid(row.try_get("mesh_id")?)
                        .map_err(|_| StoreError::Invalid("stored audit mesh"))?,
                    source_peer: PeerId::from_uuid(row.try_get("source_peer")?)
                        .map_err(|_| StoreError::Invalid("stored audit peer"))?,
                    envelope: row.try_get("envelope")?,
                    attempts: u32::try_from(row.try_get::<i32, _>("attempts")?)
                        .map_err(|_| StoreError::Invalid("stored audit attempts"))?,
                })
            })
            .collect()
    }

    /// Releases a malformed or temporarily unverifiable ciphertext with bounded diagnostics.
    pub async fn reject_encrypted_audit(
        &self,
        id: Uuid,
        diagnostic: &'static str,
    ) -> Result<(), StoreError> {
        if id.get_version_num() != 4 || diagnostic.len() > 128 {
            return Err(StoreError::Invalid("encrypted audit rejection"));
        }
        sqlx::query(
            "UPDATE encrypted_audit_inbox SET claimed_until=clock_timestamp()+
               make_interval(secs => LEAST(300, attempts*5)),last_error=$2 WHERE id=$1",
        )
        .bind(id)
        .bind(diagnostic)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Removes a terminally invalid ciphertext after bounded verification retries.
    pub async fn discard_encrypted_audit(&self, id: Uuid) -> Result<(), StoreError> {
        if id.get_version_num() != 4 {
            return Err(StoreError::Invalid("encrypted audit discard"));
        }
        sqlx::query("DELETE FROM encrypted_audit_inbox WHERE id=$1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Atomically deduplicates a decrypted batch, appends immutable audit entries, and removes its
    /// ciphertext inbox row. Replays become successful no-ops.
    pub async fn commit_peer_audit_batch(
        &self,
        inbox_id: Uuid,
        mesh_id: MeshId,
        source_peer: PeerId,
        batch_id: Uuid,
        occurred_at: OffsetDateTime,
        events: &[PeerAuditEventRecord],
    ) -> Result<bool, StoreError> {
        if inbox_id.get_version_num() != 4
            || batch_id.get_version_num() != 4
            || events.is_empty()
            || events.len() > 64
            || events.iter().any(|event| {
                event.count == 0
                    || event.direction.len() > 16
                    || event.reason.len() > 64
            })
        {
            return Err(StoreError::Invalid("decrypted audit batch"));
        }
        let mut transaction = self.pool.begin().await?;
        let inserted = sqlx::query(
            "INSERT INTO processed_peer_audit_batches(mesh_id,source_peer,batch_id)
             VALUES($1,$2,$3) ON CONFLICT DO NOTHING",
        )
        .bind(mesh_id.into_uuid())
        .bind(source_peer.into_uuid())
        .bind(batch_id)
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            == 1;
        if inserted {
            let actor = format!("peer:{source_peer}");
            for event in events {
                sqlx::query(
                    "INSERT INTO audit_log
                     (id,mesh_id,retained_mesh_id,actor,action,target_type,target_id,
                      occurred_at,result,metadata)
                     VALUES($1,$2,$2,$3,'peer.security_event','peer',$4,$5,'denied',$6)",
                )
                .bind(Uuid::new_v4())
                .bind(mesh_id.into_uuid())
                .bind(&actor)
                .bind(source_peer.into_uuid())
                .bind(occurred_at)
                .bind(json!({
                    "batch_id": batch_id,
                    "direction": event.direction,
                    "reason": event.reason,
                    "count": event.count,
                }))
                .execute(&mut *transaction)
                .await?;
            }
        }
        sqlx::query(
            "DELETE FROM encrypted_audit_inbox
             WHERE id=$1 AND mesh_id=$2 AND source_peer=$3",
        )
        .bind(inbox_id)
        .bind(mesh_id.into_uuid())
        .bind(source_peer.into_uuid())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(inserted)
    }

    /// Replaces the single current runtime-health value and consumes its encrypted inbox row.
    /// Lower or replayed sequences are consumed without changing the current value.
    pub async fn commit_peer_runtime_health(
        &self,
        inbox_id: Uuid,
        mesh_id: MeshId,
        source_peer: PeerId,
        health: &PeerRuntimeHealthRecord,
    ) -> Result<bool, StoreError> {
        if inbox_id.get_version_num() != 4
            || health.sequence == 0
            || health.direct_path_count > 65_535
            || health.degraded_reasons.len() > 8
            || health.degraded_reasons.iter().any(|reason| reason.len() > 64)
        {
            return Err(StoreError::Invalid("runtime health report"));
        }
        let sequence = i64::try_from(health.sequence)
            .map_err(|_| StoreError::Invalid("runtime health sequence"))?;
        let direct_path_count = i32::try_from(health.direct_path_count)
            .map_err(|_| StoreError::Invalid("runtime direct path count"))?;
        let relay_packets = i64::try_from(health.relay_packets)
            .map_err(|_| StoreError::Invalid("runtime relay packets"))?;
        let direct_packets = i64::try_from(health.direct_packets)
            .map_err(|_| StoreError::Invalid("runtime direct packets"))?;
        let signed_revision = i64::try_from(health.signed_revision)
            .map_err(|_| StoreError::Invalid("runtime signed revision"))?;
        let mut transaction = self.pool.begin().await?;
        let changed = if lock_enabled_peer(&mut transaction, mesh_id, source_peer).await? {
            sqlx::query(
            "INSERT INTO current_peer_runtime_health
             (mesh_id,peer_id,sequence,observed_at,expires_at,direct_path_count,
              relay_packets,direct_packets,degraded_reasons,signed_revision)
             SELECT $1,$2,$3,$4,$4::timestamptz+interval '90 seconds',$5,$6,$7,$8,$9
             WHERE $4::timestamptz>clock_timestamp()-interval '90 seconds'
               AND $4::timestamptz<=clock_timestamp()+interval '30 seconds'
             ON CONFLICT(mesh_id,peer_id) DO UPDATE SET
               sequence=EXCLUDED.sequence,observed_at=EXCLUDED.observed_at,
               expires_at=EXCLUDED.expires_at,direct_path_count=EXCLUDED.direct_path_count,
               relay_packets=EXCLUDED.relay_packets,direct_packets=EXCLUDED.direct_packets,
               degraded_reasons=EXCLUDED.degraded_reasons,signed_revision=EXCLUDED.signed_revision
             WHERE current_peer_runtime_health.sequence < EXCLUDED.sequence",
        )
        .bind(mesh_id.into_uuid())
        .bind(source_peer.into_uuid())
        .bind(sequence)
        .bind(health.observed_at)
        .bind(direct_path_count)
        .bind(relay_packets)
        .bind(direct_packets)
        .bind(&health.degraded_reasons)
        .bind(signed_revision)
        .execute(&mut *transaction)
        .await?
        .rows_affected()
            == 1
        } else {
            false
        };
        sqlx::query(
            "DELETE FROM encrypted_audit_inbox WHERE id=$1 AND mesh_id=$2 AND source_peer=$3",
        )
        .bind(inbox_id)
        .bind(mesh_id.into_uuid())
        .bind(source_peer.into_uuid())
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(changed)
    }
}
