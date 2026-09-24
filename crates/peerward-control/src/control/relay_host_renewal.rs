// Renew credentials in Control using the host's previously registered public key.
// A host cannot change its identity or acquire a Mesh through this path.
async fn renew_host_credentials(store: &Store, registry: &IssuerRegistry) -> Result<(), ApiError> {
    let rows = sqlx::query("SELECT a.host_id,a.mesh_id,a.relay_id FROM relay_host_assignments a
        JOIN meshes m ON m.id=a.mesh_id AND m.lifecycle='active'
        JOIN relay_credentials c ON c.mesh_id=a.mesh_id AND c.relay_id=a.relay_id AND c.lifecycle='active'
        JOIN mesh_authorities authority ON authority.mesh_id=m.id AND authority.lifecycle='active'
        WHERE a.desired='active' AND a.public_key IS NOT NULL
          AND (c.authority_id<>authority.id OR c.not_after<clock_timestamp()+interval '7 days')
        ORDER BY c.not_after LIMIT 8").fetch_all(store.pool()).await?;
    for row in rows {
        let mesh = mesh_id(row.try_get("mesh_id")?)?;
        let candidates = registry.get(&mesh).ok_or_else(dynamic_invalid)?;
        let host: Uuid = row.try_get("host_id")?;
        let relay: Uuid = row.try_get("relay_id")?;
        let mut tx = store.begin_mutation().await?;
        let live: Option<String> = sqlx::query_scalar("SELECT lifecycle FROM meshes WHERE id=$1 FOR UPDATE")
            .bind(mesh.into_uuid()).fetch_optional(&mut *tx).await?;
        if live.as_deref()!=Some("active") { continue; }
        let issuer = active_issuer_with_executor(&mut *tx, mesh, &candidates).await?;
        let assigned: Option<Vec<u8>> = sqlx::query_scalar("SELECT public_key FROM relay_host_assignments
            WHERE host_id=$1 AND mesh_id=$2 AND desired='active' FOR UPDATE")
            .bind(host).bind(mesh.into_uuid()).fetch_optional(&mut *tx).await?;
        let Some(public) = assigned else { continue; };
        let current = sqlx::query("SELECT id,authority_id,not_after FROM relay_credentials
            WHERE mesh_id=$1 AND relay_id=$2 AND lifecycle='active' FOR UPDATE")
            .bind(mesh.into_uuid()).bind(relay).fetch_optional(&mut *tx).await?;
        let Some(current) = current else { continue; };
        let now = current_unix_seconds();
        if current.try_get::<Uuid,_>("authority_id")? == issuer.authority_id &&
           current.try_get::<OffsetDateTime,_>("not_after")?.unix_timestamp() > i64::try_from(now+7*86400).map_err(|_| dynamic_invalid())? { continue; }
        // Refuse to endlessly issue near-expired certificates: an administrator
        // must rotate the Authority before its remaining lifetime reaches a week.
        if issuer.authority_certificate.not_after.0 <= now+7*86400 { continue; }
        let credential = issuer.authority.issue(UnsignedSubject { subject: SubjectId::Relay(relay_id(relay)?), mesh_id: mesh,
            identity_public_key:[0;32], public_noise_key:public.as_slice().try_into().map_err(|_| dynamic_invalid())?,
            wireguard_public_key: [0; 32],
            serial:CredentialSerial::new(), not_before:UnixTime(now.saturating_sub(30)),
            not_after:UnixTime((now+30*86400).min(issuer.authority_certificate.not_after.0)),
        }).map_err(|_| dynamic_invalid())?;
        let replacement = Uuid::new_v4();
        sqlx::query("UPDATE relay_credentials SET lifecycle='overlap',replacement_id=$3,
            overlap_deadline=LEAST(not_after,clock_timestamp()+interval '1 day') WHERE mesh_id=$1 AND id=$2")
            .bind(mesh.into_uuid()).bind(current.try_get::<Uuid,_>("id")?).bind(replacement).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO relay_credentials(id,mesh_id,relay_id,authority_id,serial,public_key,not_before,not_after,lifecycle,signature)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9)")
            .bind(replacement).bind(mesh.into_uuid()).bind(relay).bind(issuer.authority_id).bind(credential.serial.into_uuid())
            .bind(public).bind(timestamp(credential.not_before)?).bind(timestamp(credential.not_after)?).bind(credential.signature.to_vec())
            .execute(&mut *tx).await?;
        sqlx::query("UPDATE relay_host_assignments SET credential=$3,revision=revision+1,state='pending' WHERE host_id=$1 AND mesh_id=$2")
            .bind(host).bind(mesh.into_uuid()).bind(credential.encode()).execute(&mut *tx).await?;
        sqlx::query("UPDATE relay_hosts SET revision=revision+1 WHERE id=$1").bind(host).execute(&mut *tx).await?;
        sqlx::query("UPDATE meshes SET relay_revision=relay_revision+1 WHERE id=$1").bind(mesh.into_uuid()).execute(&mut *tx).await?;
        store.commit_mutation(tx,&lifecycle_record(mesh,"lifecycle","relay.credential_renewed","relay.credential_renewed")).await?;
    }
    Ok(())
}
