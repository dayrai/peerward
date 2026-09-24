async fn store_device_evidence(
    tx: &mut Transaction<'_, Postgres>,
    signed: &peerward_management::SignedPeerCommand,
    now: u64,
) -> Result<bool, StoreError> {
    let command = &signed.command;
    let peerward_management::PeerOperation::DeviceEvidence { evidence } = &command.operation else {
        return Err(StoreError::Invalid("device evidence operation"));
    };
    // A delayed report cannot refresh an old software statement for another 15 minutes.
    if now.abs_diff(command.issued_at) > 30 {
        return Err(StoreError::Conflict);
    }
    evidence
        .validate()
        .map_err(|_| StoreError::Invalid("device evidence"))?;
    let value =
        serde_json::to_value(evidence).map_err(|_| StoreError::Invalid("device evidence"))?;
    let mesh = command.mesh_id.into_uuid();
    let peer = command.peer_id.into_uuid();
    let serial = command.credential_serial.into_uuid();
    let sequence = i64::try_from(command.sequence).map_err(|_| StoreError::Invalid("sequence"))?;
    let unchanged: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM device_evidence WHERE mesh_id=$1 AND peer_id=$2 AND evidence=$3 AND credential_serial=$4 AND valid_until>clock_timestamp())")
        .bind(mesh).bind(peer).bind(&value).bind(serial).fetch_one(&mut **tx).await?;
    sqlx::query("INSERT INTO device_evidence(mesh_id,peer_id,credential_serial,sequence,evidence,observed_at,valid_until) VALUES($1,$2,$3,$4,$5,statement_timestamp(),statement_timestamp()+interval '900 seconds') ON CONFLICT(mesh_id,peer_id) DO UPDATE SET credential_serial=EXCLUDED.credential_serial,sequence=EXCLUDED.sequence,evidence=EXCLUDED.evidence,observed_at=EXCLUDED.observed_at,valid_until=EXCLUDED.valid_until")
        .bind(mesh).bind(peer).bind(serial).bind(sequence).bind(value).execute(&mut **tx).await?;
    sqlx::query("UPDATE meshes SET management_revision=management_revision+1 WHERE id=$1")
        .bind(mesh)
        .execute(&mut **tx)
        .await?;
    Ok(!unchanged)
}
