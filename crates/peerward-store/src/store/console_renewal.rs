impl Store {
    /// Called only after an authenticated Relay handshake. A new authenticated
    /// credential proves the device committed its keys and recovered its profile.
    pub async fn observe_peer_renewal_capability(
        &self,
        mesh: MeshId,
        peer: PeerId,
        serial: CredentialSerial,
        supported: bool,
    ) -> Result<(), StoreError> {
        let mut tx = self.pool.begin().await?;
        if !lock_enabled_peer(&mut tx, mesh, peer).await? {
            return Err(StoreError::Conflict);
        }
        let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM peer_credentials WHERE mesh_id=$1 AND peer_id=$2 AND serial=$3 AND lifecycle='active' AND not_after>clock_timestamp() AND not_before<=clock_timestamp())")
            .bind(mesh.into_uuid()).bind(peer.into_uuid()).bind(serial.into_uuid()).fetch_one(&mut *tx).await?;
        if !valid {
            tx.rollback().await?;
            return Ok(());
        }
        sqlx::query("INSERT INTO console_device_capabilities(mesh_id,peer_id,credential_serial,credential_renewal) VALUES($1,$2,$3,$4)
            ON CONFLICT(mesh_id,peer_id) DO UPDATE SET credential_serial=$3,credential_renewal=$4,observed_at=clock_timestamp()")
            .bind(mesh.into_uuid()).bind(peer.into_uuid()).bind(serial.into_uuid()).bind(supported).execute(&mut *tx).await?;
        let ids:Vec<Uuid>=sqlx::query_scalar("UPDATE console_credential_renewals c SET completed_at=clock_timestamp(),completed_serial=$3
            WHERE c.mesh_id=$1 AND c.peer_id=$2 AND c.completed_at IS NULL AND EXISTS(SELECT 1 FROM peer_credential_rotation_requests r
                WHERE r.mesh_id=c.mesh_id AND r.peer_id=c.peer_id AND r.authenticated_serial=c.current_serial AND r.issued_serial=$3 AND r.status='activated') RETURNING c.id")
            .bind(mesh.into_uuid()).bind(peer.into_uuid()).bind(serial.into_uuid()).fetch_all(&mut *tx).await?;
        for id in ids {
            append_audit(
                &mut tx,
                Some(mesh),
                "credential-renewal-observer",
                "credential_renewal.completed",
                "credential_renewal",
                Some(id),
                "success",
                json!({"peer_id":peer,"authenticated_serial":serial}),
            )
            .await?;
            append_event(
                &mut tx,
                Some(mesh),
                "credential_renewal.completed",
                "credential_renewal",
                Some(id),
                json!({"peer_id":peer}),
            )
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }
    /// Capability-gated delivery; an unsupported attachment is never sent a new Wire family.
    pub async fn pending_credential_renewal(
        &self,
        mesh: MeshId,
        peer: PeerId,
        serial: CredentialSerial,
    ) -> Result<Option<peerward_management::SignedCredentialRenewal>, StoreError> {
        let value:Option<Value>=sqlx::query_scalar("SELECT c.command FROM console_credential_renewals c JOIN peers p ON p.mesh_id=c.mesh_id AND p.id=c.peer_id
            JOIN meshes m ON m.id=c.mesh_id WHERE c.mesh_id=$1 AND c.peer_id=$2 AND c.current_serial=$3 AND c.completed_at IS NULL AND c.expires_at>clock_timestamp()
            AND p.administrative_state='enabled' AND m.lifecycle='active' ORDER BY c.created_at LIMIT 1")
            .bind(mesh.into_uuid()).bind(peer.into_uuid()).bind(serial.into_uuid()).fetch_optional(&self.pool).await?;
        value
            .map(|v| {
                serde_json::from_value(v).map_err(|_| StoreError::Invalid("credential renewal"))
            })
            .transpose()
    }
    pub async fn mark_credential_renewal_delivered(
        &self,
        mesh: MeshId,
        peer: PeerId,
        id: Uuid,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE console_credential_renewals SET delivered_at=COALESCE(delivered_at,clock_timestamp()) WHERE mesh_id=$1 AND peer_id=$2 AND id=$3")
            .bind(mesh.into_uuid()).bind(peer.into_uuid()).bind(id).execute(&self.pool).await?;
        Ok(())
    }
}
