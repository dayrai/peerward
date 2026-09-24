async fn initial_mesh_configuration_matches(
    transaction: &mut Transaction<'_, Postgres>,
    value: &InitialInstallation,
) -> Result<bool, StoreError> {
    let reserved: Vec<String> = value
        .mesh
        .reserved
        .iter()
        .map(ToString::to_string)
        .collect();
    let exact = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM meshes WHERE id=$1 AND name=$2
         AND address_cidr=$3::cidr AND gateway=$4::inet AND dns_suffix=$5 AND mtu=$6
         AND reserved_addresses=$7::text[]::inet[] AND default_policy=$8
         AND quarantine_seconds=$9 AND rotation_overlap_seconds=$10)",
    )
    .bind(value.mesh_id.into_uuid())
    .bind(&value.mesh.name)
    .bind(value.mesh.address_cidr.to_string())
    .bind(value.mesh.gateway.to_string())
    .bind(&value.mesh.dns_suffix)
    .bind(i32::from(value.mesh.mtu))
    .bind(reserved)
    .bind(value.mesh.default_policy.as_str())
    .bind(
        i64::try_from(value.mesh.quarantine_seconds)
            .map_err(|_| StoreError::Invalid("quarantine"))?,
    )
    .bind(
        i64::try_from(value.mesh.rotation_overlap_seconds)
            .map_err(|_| StoreError::Invalid("rotation overlap"))?,
    )
    .fetch_one(&mut **transaction)
    .await?;
    Ok(exact)
}
