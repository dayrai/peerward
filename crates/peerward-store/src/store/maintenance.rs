impl MaintenancePolicy {
    fn validate(self) -> Result<Self, StoreError> {
        if !(100..=10_000).contains(&self.batch_size)
            || !(3_600..=604_800).contains(&self.event_retention_seconds)
            || !(10_000..=1_000_000).contains(&self.event_max_rows)
            || !(1..=10).contains(&self.signed_state_versions)
            || !(3_600..=604_800).contains(&self.terminal_retention_seconds)
        {
            return Err(StoreError::Invalid("maintenance policy"));
        }
        Ok(self)
    }
}

impl Store {
    /// Deletes bounded batches of expired operational state under a cluster-wide election lock.
    pub async fn maintain(
        &self,
        policy: MaintenancePolicy,
    ) -> Result<MaintenanceReport, StoreError> {
        let policy = policy.validate()?;
        let mut transaction = self.pool.begin().await?;
        let elected: bool = sqlx::query_scalar(
            "SELECT pg_try_advisory_xact_lock(hashtextextended('peerward/maintenance/v1',0))",
        )
        .fetch_one(&mut *transaction)
        .await?;
        if !elected {
            transaction.rollback().await?;
            return Ok(MaintenanceReport::default());
        }
        let batch = i64::from(policy.batch_size);
        let terminal = seconds_i64(policy.terminal_retention_seconds)?;
        let event_age = seconds_i64(policy.event_retention_seconds)?;
        let event_max = i64::try_from(policy.event_max_rows)
            .map_err(|_| StoreError::Invalid("event maximum"))?;
        let versions = i64::from(policy.signed_state_versions);
        let mut deleted = 0_u64;
        let mut backlog_tables = 0_u32;

        let rows = sqlx::query(
            "WITH doomed AS (
               SELECT event.sequence FROM event_outbox event CROSS JOIN event_stream_state state
               WHERE event.committed_at < clock_timestamp()-make_interval(secs=>$1::double precision)
                  OR event.sequence <= GREATEST(state.high_water_sequence-$2,0)
               ORDER BY event.sequence LIMIT $3)
             DELETE FROM event_outbox event USING doomed WHERE event.sequence=doomed.sequence",
        )
        .bind(event_age)
        .bind(event_max)
        .bind(batch)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        record_maintenance(rows, batch, &mut deleted, &mut backlog_tables);
        sqlx::query(
            "UPDATE event_stream_state state SET oldest_retained_sequence=COALESCE(
               (SELECT min(sequence) FROM event_outbox),state.high_water_sequence+1)
             WHERE singleton",
        )
        .execute(&mut *transaction)
        .await?;

        let rows = sqlx::query(
            "DELETE FROM current_peer_runtime_health WHERE (mesh_id,peer_id) IN
             (SELECT mesh_id,peer_id FROM current_peer_runtime_health
              WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT $1)",
        )
        .bind(batch)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        record_maintenance(rows, batch, &mut deleted, &mut backlog_tables);

        for statement in [
            // Signed commands are stale after five minutes. Keep the persistent sequence
            // floor even when compacting retry digests; stale commands can never reapply.
            "DELETE FROM peer_management_requests WHERE request_id IN (SELECT request_id FROM peer_management_requests WHERE committed_at<clock_timestamp()-interval '8 days' AND $1::bigint>0 ORDER BY committed_at LIMIT $2)",
            "DELETE FROM oidc_flows WHERE id IN (SELECT id FROM oidc_flows WHERE COALESCE(consumed_at,expires_at)<clock_timestamp()-make_interval(secs=>$1::double precision) ORDER BY COALESCE(consumed_at,expires_at),id LIMIT $2)",
            "DELETE FROM web_sessions WHERE id IN (SELECT id FROM web_sessions WHERE LEAST(expires_at,COALESCE(revoked_at,expires_at))<clock_timestamp()-make_interval(secs=>$1::double precision) ORDER BY LEAST(expires_at,COALESCE(revoked_at,expires_at)),id LIMIT $2)",
            "DELETE FROM relay_presence WHERE (mesh_id,peer_id,role) IN (SELECT mesh_id,peer_id,role FROM relay_presence WHERE lease_deadline<clock_timestamp()-make_interval(secs=>$1::double precision) ORDER BY lease_deadline LIMIT $2)",
            "DELETE FROM relay_standby_presence_v1 WHERE (mesh_id,peer_id,relay_id) IN (SELECT mesh_id,peer_id,relay_id FROM relay_standby_presence_v1 WHERE lease_deadline<clock_timestamp()-make_interval(secs=>$1::double precision) ORDER BY lease_deadline LIMIT $2)",
            "DELETE FROM relay_runtime_leases WHERE (mesh_id,relay_id) IN (SELECT mesh_id,relay_id FROM relay_runtime_leases WHERE lease_deadline<clock_timestamp()-make_interval(secs=>$1::double precision) ORDER BY lease_deadline LIMIT $2)",
            "DELETE FROM peer_credential_rotation_requests WHERE id IN (SELECT id FROM peer_credential_rotation_requests WHERE status IN ('activated','cancelled') AND COALESCE(activated_at,cancelled_at,issued_at,created_at)<clock_timestamp()-make_interval(secs=>$1::double precision) ORDER BY COALESCE(activated_at,cancelled_at,issued_at,created_at),id LIMIT $2)",
        ] {
            let rows = sqlx::query(statement)
                .bind(terminal)
                .bind(batch)
                .execute(&mut *transaction)
                .await?
                .rows_affected();
            record_maintenance(rows, batch, &mut deleted, &mut backlog_tables);
        }

        // Invitations and their approval decisions are durable management history,
        // not expiring operational rows. Never release their single-use identities.
        // Compact only old configuration responses; retain the digest/actor tombstone
        // so a late retry cannot be interpreted as a fresh (including no-op) apply.
        let rows = sqlx::query(
            "WITH candidates AS (
               SELECT mesh_id,request_id FROM configuration_applications
               WHERE response IS NOT NULL AND created_at<clock_timestamp()-interval '30 days'
               ORDER BY created_at,mesh_id,request_id FOR UPDATE SKIP LOCKED LIMIT $1)
             UPDATE configuration_applications application SET response=NULL,archived_at=clock_timestamp()
             FROM candidates WHERE application.mesh_id=candidates.mesh_id
               AND application.request_id=candidates.request_id",
        )
        .bind(batch)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        // Compaction frees response bytes, not request rows. Only backlog uses this count.
        if rows >= u64::try_from(batch).unwrap_or(u64::MAX) {
            backlog_tables = backlog_tables.saturating_add(1);
        }

        // Address history first leaves quarantine, then remains as released metadata for the
        // configured terminal window. One candidate CTE bounds both transitions and deletions to
        // a single per-table batch.
        let address_rows = sqlx::query(
            "WITH candidates AS (
               SELECT id,state FROM peer_addresses
               WHERE quarantine_until IS NOT NULL AND
                 ((state='quarantine' AND quarantine_until<=clock_timestamp()) OR
                  (state='released' AND quarantine_until<clock_timestamp()-make_interval(secs=>$1::double precision)))
               ORDER BY quarantine_until,id FOR UPDATE SKIP LOCKED LIMIT $2),
             transitioned AS (
               UPDATE peer_addresses address SET state='released' FROM candidates candidate
               WHERE address.id=candidate.id AND candidate.state='quarantine' RETURNING address.id),
             removed AS (
               DELETE FROM peer_addresses address USING candidates candidate
               WHERE address.id=candidate.id AND candidate.state='released' RETURNING address.id)
             SELECT (SELECT count(*) FROM candidates) AS processed,
                    (SELECT count(*) FROM removed) AS deleted",
        )
        .bind(terminal)
        .bind(batch)
        .fetch_one(&mut *transaction)
        .await?;
        let address_processed: i64 = address_rows.try_get("processed")?;
        let address_deleted: i64 = address_rows.try_get("deleted")?;
        deleted = deleted.saturating_add(u64::try_from(address_deleted).unwrap_or(0));
        if address_processed >= batch {
            backlog_tables = backlog_tables.saturating_add(1);
        }

        let rows = sqlx::query(
            "DELETE FROM peer_credentials credential WHERE credential.id IN (
               SELECT candidate.id FROM peer_credentials candidate
               WHERE candidate.lifecycle<>'active'
                 AND candidate.not_after<clock_timestamp()-make_interval(secs=>$1::double precision)
                 AND NOT EXISTS (SELECT 1 FROM join_tickets ticket
                   WHERE ticket.mesh_id=candidate.mesh_id AND ticket.claimed_credential_id=candidate.id)
                 AND NOT EXISTS (SELECT 1 FROM peer_credential_rotation_requests request
                   WHERE request.mesh_id=candidate.mesh_id AND
                     (request.authenticated_serial=candidate.serial OR request.issued_serial=candidate.serial))
                 AND NOT EXISTS (SELECT 1 FROM peer_credentials reference
                   WHERE reference.mesh_id=candidate.mesh_id AND reference.replacement_id=candidate.id)
               ORDER BY candidate.not_after,candidate.id LIMIT $2)",
        )
        .bind(terminal)
        .bind(batch)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        record_maintenance(rows, batch, &mut deleted, &mut backlog_tables);
        let rows = sqlx::query(
            "DELETE FROM relay_credentials credential WHERE credential.id IN (
               SELECT candidate.id FROM relay_credentials candidate
               WHERE candidate.lifecycle<>'active'
                 AND candidate.not_after<clock_timestamp()-make_interval(secs=>$1::double precision)
                 AND NOT EXISTS (SELECT 1 FROM relay_credentials reference
                   WHERE reference.mesh_id=candidate.mesh_id AND reference.replacement_id=candidate.id)
               ORDER BY candidate.not_after,candidate.id LIMIT $2)",
        )
        .bind(terminal)
        .bind(batch)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        record_maintenance(rows, batch, &mut deleted, &mut backlog_tables);
        let rows = sqlx::query(
            "DELETE FROM mesh_authorities authority WHERE authority.id IN (
               SELECT candidate.id FROM mesh_authorities candidate
               WHERE candidate.lifecycle<>'active'
                 AND candidate.not_after<clock_timestamp()-make_interval(secs=>$1::double precision)
                 AND NOT EXISTS (SELECT 1 FROM peer_credentials credential
                   WHERE credential.mesh_id=candidate.mesh_id AND credential.authority_id=candidate.id)
                 AND NOT EXISTS (SELECT 1 FROM relay_credentials credential
                   WHERE credential.mesh_id=candidate.mesh_id AND credential.authority_id=candidate.id)
                 AND NOT EXISTS (SELECT 1 FROM mesh_authorities reference
                   WHERE reference.mesh_id=candidate.mesh_id AND reference.replacement_id=candidate.id)
               ORDER BY candidate.not_after,candidate.id LIMIT $2)",
        )
        .bind(terminal)
        .bind(batch)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        record_maintenance(rows, batch, &mut deleted, &mut backlog_tables);

        let processed_age = 8 * 24 * 60 * 60_i64;
        let rows = sqlx::query(
            "DELETE FROM processed_peer_audit_batches WHERE (mesh_id,source_peer,batch_id) IN
             (SELECT mesh_id,source_peer,batch_id FROM processed_peer_audit_batches
              WHERE processed_at<clock_timestamp()-make_interval(secs=>$1::double precision)
              ORDER BY processed_at,batch_id LIMIT $2)",
        )
        .bind(processed_age)
        .bind(batch)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        record_maintenance(rows, batch, &mut deleted, &mut backlog_tables);

        let rows = sqlx::query(
            "WITH ranked AS (SELECT mesh_id,kind,revision,row_number() OVER
               (PARTITION BY mesh_id,kind ORDER BY revision DESC) AS position
               FROM signed_state_revisions), doomed AS
               (SELECT mesh_id,kind,revision FROM ranked WHERE position>$1 LIMIT $2)
             DELETE FROM signed_state_revisions state USING doomed
             WHERE state.mesh_id=doomed.mesh_id AND state.kind=doomed.kind
               AND state.revision=doomed.revision",
        )
        .bind(versions)
        .bind(batch)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        record_maintenance(rows, batch, &mut deleted, &mut backlog_tables);

        let rows = sqlx::query(
            "WITH ranked AS (SELECT mesh_id,revision,row_number() OVER
               (PARTITION BY mesh_id ORDER BY revision DESC) AS position FROM policies),
             doomed AS (SELECT item.ctid FROM policy_rule_peers item JOIN ranked
               ON item.mesh_id=ranked.mesh_id AND item.policy_revision=ranked.revision
               WHERE ranked.position>$1 LIMIT $2)
             DELETE FROM policy_rule_peers item USING doomed WHERE item.ctid=doomed.ctid",
        )
        .bind(versions)
        .bind(batch)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        record_maintenance(rows, batch, &mut deleted, &mut backlog_tables);
        let rows = sqlx::query(
            "WITH ranked AS (SELECT mesh_id,revision,row_number() OVER
               (PARTITION BY mesh_id ORDER BY revision DESC) AS position FROM policies),
             doomed AS (SELECT item.ctid FROM policy_rules item JOIN ranked
               ON item.mesh_id=ranked.mesh_id AND item.policy_revision=ranked.revision
               WHERE ranked.position>$1 AND NOT EXISTS
                 (SELECT 1 FROM policy_rule_peers peer WHERE peer.mesh_id=item.mesh_id
                   AND peer.policy_revision=item.policy_revision AND peer.rule_id=item.id)
               LIMIT $2)
             DELETE FROM policy_rules item USING doomed WHERE item.ctid=doomed.ctid",
        )
        .bind(versions)
        .bind(batch)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        record_maintenance(rows, batch, &mut deleted, &mut backlog_tables);
        let rows = sqlx::query(
            "WITH ranked AS (SELECT mesh_id,revision,row_number() OVER
               (PARTITION BY mesh_id ORDER BY revision DESC) AS position FROM policies),
             doomed AS (SELECT ranked.mesh_id,ranked.revision FROM ranked
               WHERE position>$1 AND NOT EXISTS
                 (SELECT 1 FROM policy_rules rule WHERE rule.mesh_id=ranked.mesh_id
                   AND rule.policy_revision=ranked.revision)
               LIMIT $2)
             DELETE FROM policies item USING doomed
             WHERE item.mesh_id=doomed.mesh_id AND item.revision=doomed.revision",
        )
        .bind(versions)
        .bind(batch)
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        record_maintenance(rows, batch, &mut deleted, &mut backlog_tables);

        transaction.commit().await?;
        Ok(MaintenanceReport {
            elected: true,
            deleted_rows: deleted,
            backlog_tables,
        })
    }
}

fn seconds_i64(value: u64) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::Invalid("maintenance duration"))
}

fn record_maintenance(rows: u64, batch: i64, deleted: &mut u64, backlog_tables: &mut u32) {
    *deleted = (*deleted).saturating_add(rows);
    if rows >= u64::try_from(batch).unwrap_or(u64::MAX) {
        *backlog_tables = (*backlog_tables).saturating_add(1);
    }
}
