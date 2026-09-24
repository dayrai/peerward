impl Store {
    /// Publishes one service only for the Peer authenticated by a current credential.
    pub async fn publish_peer_service(
        &self,
        mesh_id: MeshId,
        peer_id: PeerId,
        authenticated_serial: CredentialSerial,
        service_id: ServiceId,
        protocols: &[ServiceProtocol],
        listen_port: u16,
        alias: Option<&str>,
    ) -> Result<(), StoreError> {
        if !matches!(
            protocols,
            [ServiceProtocol::Tcp | ServiceProtocol::Udp]
                | [ServiceProtocol::Tcp, ServiceProtocol::Udp]
        ) || listen_port == 0
            || alias.is_some_and(|alias| validate_dns_label(alias).is_err())
        {
            return Err(StoreError::Invalid("service"));
        }
        let alias = alias.map(str::to_ascii_lowercase);
        let protocols = protocols
            .iter()
            .map(|protocol| match protocol {
                ServiceProtocol::Tcp => "tcp",
                ServiceProtocol::Udp => "udp",
            })
            .collect::<Vec<_>>();
        let mut transaction = self.pool.begin().await?;
        ensure_authenticated_peer(&mut transaction, mesh_id, peer_id, authenticated_serial).await?;
        let existing = sqlx::query(
            "SELECT peer_id,protocols,listen_port,alias FROM services
             WHERE mesh_id=$1 AND id=$2 FOR UPDATE",
        )
        .bind(mesh_id.into_uuid())
        .bind(service_id.into_uuid())
        .fetch_optional(&mut *transaction)
        .await?;
        if let Some(row) = existing {
            let exact = row.try_get::<Uuid, _>("peer_id")? == peer_id.into_uuid()
                && row.try_get::<Vec<String>, _>("protocols")? == protocols
                && row.try_get::<i32, _>("listen_port")? == i32::from(listen_port)
                && row.try_get::<Option<String>, _>("alias")? == alias;
            if !exact {
                return Err(StoreError::Conflict);
            }
            sqlx::query(
                "UPDATE services SET state='enabled',updated_at=clock_timestamp()
                 WHERE mesh_id=$1 AND id=$2",
            )
            .bind(mesh_id.into_uuid())
            .bind(service_id.into_uuid())
            .execute(&mut *transaction)
            .await?;
        } else {
            sqlx::query(
                "INSERT INTO services(id,mesh_id,peer_id,protocols,listen_port,alias)
                 VALUES($1,$2,$3,$4,$5,$6)",
            )
            .bind(service_id.into_uuid())
            .bind(mesh_id.into_uuid())
            .bind(peer_id.into_uuid())
            .bind(&protocols)
            .bind(i32::from(listen_port))
            .bind(&alias)
            .execute(&mut *transaction)
            .await?;
        }
        update_service_revisions(&mut transaction, mesh_id).await?;
        append_event(
            &mut transaction,
            Some(mesh_id),
            "service.published_by_peer",
            "service",
            Some(service_id.into_uuid()),
            json!({"peer_id":peer_id,"protocols":protocols,
                "listen_port":listen_port,"alias":alias}),
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Withdraws one service only when it belongs to the authenticated Peer.
    pub async fn remove_peer_service(
        &self,
        mesh_id: MeshId,
        peer_id: PeerId,
        authenticated_serial: CredentialSerial,
        service_id: ServiceId,
    ) -> Result<(), StoreError> {
        let mut transaction = self.pool.begin().await?;
        ensure_authenticated_peer(&mut transaction, mesh_id, peer_id, authenticated_serial).await?;
        let changed = sqlx::query(
            "UPDATE services SET state='disabled',updated_at=clock_timestamp()
             WHERE mesh_id=$1 AND peer_id=$2 AND id=$3 AND state='enabled'",
        )
        .bind(mesh_id.into_uuid())
        .bind(peer_id.into_uuid())
        .bind(service_id.into_uuid())
        .execute(&mut *transaction)
        .await?
        .rows_affected();
        if changed != 1 {
            return Err(StoreError::NotFound);
        }
        update_service_revisions(&mut transaction, mesh_id).await?;
        append_event(
            &mut transaction,
            Some(mesh_id),
            "service.removed_by_peer",
            "service",
            Some(service_id.into_uuid()),
            json!({"peer_id":peer_id}),
        )
        .await?;
        transaction.commit().await?;
        Ok(())
    }
}

async fn ensure_authenticated_peer(
    transaction: &mut Transaction<'_, Postgres>,
    mesh_id: MeshId,
    peer_id: PeerId,
    serial: CredentialSerial,
) -> Result<(), StoreError> {
    let active: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM meshes WHERE id=$1 AND lifecycle='active' FOR UPDATE")
            .bind(mesh_id.into_uuid())
            .fetch_optional(&mut **transaction)
            .await?;
    if active.is_none() {
        return Err(StoreError::Conflict);
    }
    let valid: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM peer_credentials c JOIN peers p
          ON p.mesh_id=c.mesh_id AND p.id=c.peer_id
         WHERE c.mesh_id=$1 AND c.peer_id=$2 AND c.serial=$3
           AND c.lifecycle IN ('active','overlap')
           AND (c.lifecycle='active' OR c.overlap_deadline>clock_timestamp())
           AND c.not_before<=clock_timestamp() AND c.not_after>clock_timestamp()
           AND p.administrative_state='enabled')",
    )
    .bind(mesh_id.into_uuid())
    .bind(peer_id.into_uuid())
    .bind(serial.into_uuid())
    .fetch_one(&mut **transaction)
    .await?;
    if valid {
        Ok(())
    } else {
        Err(StoreError::Conflict)
    }
}

async fn update_service_revisions(
    transaction: &mut Transaction<'_, Postgres>,
    mesh_id: MeshId,
) -> Result<(), StoreError> {
    sqlx::query(
        "UPDATE meshes SET service_revision=service_revision+1,
         directory_revision=directory_revision+1,updated_at=clock_timestamp() WHERE id=$1",
    )
    .bind(mesh_id.into_uuid())
    .execute(&mut **transaction)
    .await?;
    Ok(())
}
