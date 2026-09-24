impl Store {
    /// Expiring access is already bounded by every signed credential. This job
    /// retires metadata and quarantines addresses independently from online health.
    pub async fn expire_device_admissions(&self, limit: u16) -> Result<u64, StoreError> {
        validate_limit(limit)?;
        let rows:Vec<(Uuid,Uuid)>=sqlx::query_as("SELECT mesh_id,id FROM peers WHERE administrative_state='enabled' AND admission_until<=clock_timestamp() ORDER BY admission_until,id LIMIT $1")
            .bind(i64::from(limit)).fetch_all(&self.pool).await?;
        let mut meshes = std::collections::BTreeMap::<Uuid, Vec<Uuid>>::new();
        for (mesh, peer) in rows {
            meshes.entry(mesh).or_default().push(peer);
        }
        let mut retired = 0;
        for (mesh, peers) in meshes {
            let mut tx = self.pool.begin().await?;
            sqlx::query("SELECT id FROM meshes WHERE id=$1 FOR UPDATE")
                .bind(mesh)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(StoreError::NotFound)?;
            for peer in peers {
                let due:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM peers WHERE mesh_id=$1 AND id=$2 AND administrative_state='enabled' AND admission_until<=clock_timestamp())")
                    .bind(mesh).bind(peer).fetch_one(&mut *tx).await?;
                if due {
                    retire_device_admission(&mut tx, mesh, peer, "expired").await?;
                    retired += 1;
                }
            }
            tx.commit().await?;
        }
        Ok(retired)
    }

    /// A successful publisher pass can observe ephemeral devices only while all
    /// enabled Relay runtimes are reporting. Process restarts, failed passes,
    /// stale observations and clock anomalies reset the continuous offline span.
    /// One observer owns each Mesh for 15 seconds; takeover starts a fresh span.
    pub async fn observe_ephemeral_peers(
        &self,
        mesh: MeshId,
        observer: Uuid,
        elapsed: Option<std::time::Duration>,
    ) -> Result<u64, StoreError> {
        if observer.get_version_num() != 4 {
            return Err(StoreError::Invalid("admission observer"));
        }
        let mut tx = self.pool.begin().await?;
        let active =
            sqlx::query("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
                .bind(mesh.into_uuid())
                .fetch_optional(&mut *tx)
                .await?;
        if active.is_none() {
            tx.rollback().await?;
            return Ok(0);
        }
        let now: OffsetDateTime = sqlx::query_scalar("SELECT clock_timestamp()")
            .fetch_one(&mut *tx)
            .await?;
        let previous:Option<(Uuid,OffsetDateTime,bool,String)>=sqlx::query_as("SELECT observer_id,observed_at,healthy,runtime_fingerprint FROM device_admission_observers WHERE mesh_id=$1 FOR UPDATE")
            .bind(mesh.into_uuid()).fetch_optional(&mut *tx).await?;
        if let Some((owner, at, _, _)) = &previous
            && *owner != observer
            && *at <= now
            && now - *at < time::Duration::seconds(15)
        {
            tx.rollback().await?;
            return Ok(0);
        }
        let healthy:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM relays WHERE mesh_id=$1 AND administrative_state='enabled')
            AND NOT EXISTS(SELECT 1 FROM relays r WHERE r.mesh_id=$1 AND r.administrative_state='enabled' AND NOT EXISTS(
                SELECT 1 FROM relay_runtime_leases l JOIN relay_credentials c ON c.mesh_id=l.mesh_id AND c.relay_id=l.relay_id
                JOIN mesh_authorities a ON a.mesh_id=c.mesh_id AND a.id=c.authority_id
                WHERE l.mesh_id=r.mesh_id AND l.relay_id=r.id AND l.lease_deadline>clock_timestamp()
                AND l.updated_at>clock_timestamp()-interval '45 seconds' AND c.lifecycle IN ('active','overlap')
                AND c.not_before<=clock_timestamp() AND c.not_after>clock_timestamp()
                AND (c.lifecycle='active' OR c.overlap_deadline>clock_timestamp())
                AND a.lifecycle IN ('active','overlap') AND (a.lifecycle='active' OR a.overlap_deadline>clock_timestamp()) AND a.not_before<=clock_timestamp() AND a.not_after>clock_timestamp()))")
            .bind(mesh.into_uuid()).fetch_one(&mut *tx).await?;
        let fingerprint: String = sqlx::query_scalar("SELECT COALESCE(string_agg(r.id::text || ':' || COALESCE(l.instance_id::text,'missing') || ':' || COALESCE(l.fencing_generation::text,'missing'),',' ORDER BY r.id),'') FROM relays r LEFT JOIN relay_runtime_leases l ON l.mesh_id=r.mesh_id AND l.relay_id=r.id WHERE r.mesh_id=$1 AND r.administrative_state='enabled'")
            .bind(mesh.into_uuid()).fetch_one(&mut *tx).await?;
        let seconds = match previous {
            Some((owner, at, true, previous_fingerprint))
                if owner == observer
                    && previous_fingerprint == fingerprint
                    && elapsed.is_some_and(|elapsed| {
                        elapsed <= std::time::Duration::from_secs(15)
                            && ((now - at).as_seconds_f64() - elapsed.as_secs_f64()).abs() <= 1.0
                    })
                    && healthy
                    && now >= at
                    && now - at <= time::Duration::seconds(15) =>
            {
                (now - at)
                    .as_seconds_f64()
                    .min(elapsed.map_or(0.0, |elapsed| elapsed.as_secs_f64()))
            }
            _ => 0.0,
        };
        sqlx::query("INSERT INTO device_admission_observers(mesh_id,observer_id,observed_at,healthy,runtime_fingerprint) VALUES($1,$2,$3,$4,$5)
            ON CONFLICT(mesh_id) DO UPDATE SET observer_id=EXCLUDED.observer_id,observed_at=EXCLUDED.observed_at,healthy=EXCLUDED.healthy,runtime_fingerprint=EXCLUDED.runtime_fingerprint")
            .bind(mesh.into_uuid()).bind(observer).bind(now).bind(healthy).bind(fingerprint).execute(&mut *tx).await?;
        // Zero time means an unknown/discontinuous interval, never a pause that
        // could later be mistaken for continuously observed offline time.
        if seconds <= 0.0 {
            sqlx::query("UPDATE ephemeral_peer_observations SET offline_seconds=0 WHERE mesh_id=$1 AND offline_seconds<>0")
                .bind(mesh.into_uuid()).execute(&mut *tx).await?;
        }
        sqlx::query("INSERT INTO ephemeral_peer_observations(mesh_id,peer_id,offline_seconds)
            SELECT p.mesh_id,p.id,CASE WHEN $2::double precision<=0 OR EXISTS(SELECT 1 FROM relay_presence_all a
                JOIN relay_runtime_leases l ON l.mesh_id=a.mesh_id AND l.relay_id=a.relay_id
                JOIN relays r ON r.mesh_id=l.mesh_id AND r.id=l.relay_id AND r.administrative_state='enabled'
                WHERE a.mesh_id=p.mesh_id AND a.peer_id=p.id AND a.lease_deadline>clock_timestamp() AND l.lease_deadline>clock_timestamp()) THEN 0
                ELSE LEAST(1800,COALESCE(o.offline_seconds,0)+$2::double precision) END
            FROM peers p LEFT JOIN ephemeral_peer_observations o ON o.mesh_id=p.mesh_id AND o.peer_id=p.id
            WHERE p.mesh_id=$1 AND p.admission_kind='ephemeral' AND p.administrative_state='enabled'
            ON CONFLICT(mesh_id,peer_id) DO UPDATE SET offline_seconds=EXCLUDED.offline_seconds
            WHERE ephemeral_peer_observations.offline_seconds<>EXCLUDED.offline_seconds")
            .bind(mesh.into_uuid()).bind(seconds).execute(&mut *tx).await?;
        let due:Vec<Uuid>=sqlx::query_scalar("SELECT p.id FROM peers p JOIN ephemeral_peer_observations o ON o.mesh_id=p.mesh_id AND o.peer_id=p.id
            WHERE p.mesh_id=$1 AND p.admission_kind='ephemeral' AND p.administrative_state='enabled' AND o.offline_seconds>=1800 ORDER BY p.id LIMIT 128")
            .bind(mesh.into_uuid()).fetch_all(&mut *tx).await?;
        for peer in &due {
            retire_device_admission(&mut tx, mesh.into_uuid(), *peer, "ephemeral_offline").await?;
        }
        tx.commit().await?;
        u64::try_from(due.len()).map_err(|_| StoreError::Invalid("admission batch"))
    }
}

async fn retire_device_admission(
    tx: &mut Transaction<'_, Postgres>,
    mesh: Uuid,
    peer: Uuid,
    reason: &str,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE peers SET administrative_state='disabled',admission_ended_at=clock_timestamp(),admission_end_reason=$3,updated_at=clock_timestamp() WHERE mesh_id=$1 AND id=$2")
        .bind(mesh).bind(peer).bind(reason).execute(&mut **tx).await?;
    revoke_peer_access(tx, mesh, peer).await?;
    mutation_records(
        tx,
        MeshId::from_uuid(mesh).map_err(|_| StoreError::Invalid("mesh"))?,
        "device-lifecycle",
        "peer.admission.end",
        "peer.admission.ended",
        "peer",
        peer,
        json!({"reason":reason}),
    )
    .await
}

/// Shared access teardown for administrative stop and automatic retirement.
/// The caller holds the Mesh mutation lock and commits audit in the same transaction.
pub async fn revoke_peer_access(
    transaction: &mut Transaction<'_, Postgres>,
    mesh: Uuid,
    peer: Uuid,
) -> Result<(), StoreError> {
    sqlx::query("UPDATE peer_credentials SET lifecycle='revoked' WHERE mesh_id=$1 AND peer_id=$2 AND lifecycle<>'revoked'")
        .bind(mesh).bind(peer).execute(&mut **transaction).await?;
    sqlx::query("UPDATE peer_credential_rotation_requests SET status='cancelled',cancelled_at=clock_timestamp() WHERE mesh_id=$1 AND peer_id=$2 AND status IN ('pending','issued')")
        .bind(mesh).bind(peer).execute(&mut **transaction).await?;
    sqlx::query("UPDATE services SET state='disabled',updated_at=clock_timestamp() WHERE mesh_id=$1 AND peer_id=$2 AND state='enabled'")
        .bind(mesh).bind(peer).execute(&mut **transaction).await?;
    sqlx::query("DELETE FROM relay_presence WHERE mesh_id=$1 AND peer_id=$2")
        .bind(mesh)
        .bind(peer)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("DELETE FROM relay_standby_presence_v1 WHERE mesh_id=$1 AND peer_id=$2")
        .bind(mesh)
        .bind(peer)
        .execute(&mut **transaction)
        .await?;
    sqlx::query("UPDATE peer_addresses a SET state='quarantine',released_at=clock_timestamp(),
        quarantine_until=clock_timestamp()+make_interval(secs=>m.quarantine_seconds::double precision)
        FROM meshes m WHERE a.mesh_id=$1 AND a.peer_id=$2 AND a.state='active' AND m.id=a.mesh_id")
        .bind(mesh).bind(peer).execute(&mut **transaction).await?;
    sqlx::query("UPDATE meshes SET directory_revision=directory_revision+1,service_revision=service_revision+1,revocation_revision=revocation_revision+1,management_revision=management_revision+1,updated_at=clock_timestamp() WHERE id=$1")
        .bind(mesh).execute(&mut **transaction).await?;
    Ok(())
}
