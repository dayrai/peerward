const FOLLOWUP_MIGRATIONS: &[(i32, &str)] = &[
    // Ordered below by migration number; historical migrations remain immutable.
    (2, include_str!("../../migrations/0002_auditor_role.sql")),
    (
        3,
        include_str!("../../migrations/0003_resource_versions.sql"),
    ),
    (
        4,
        include_str!("../../migrations/0004_current_runtime_health.sql"),
    ),
    (
        5,
        include_str!("../../migrations/0005_authority_versions.sql"),
    ),
    (6, include_str!("../../migrations/0006_relay_routing.sql")),
    (7, include_str!("../../migrations/0007_trace_context.sql")),
    (
        8,
        include_str!("../../migrations/0008_multi_relay_presence.sql"),
    ),
    (
        9,
        include_str!("../../migrations/0009_initial_revisions.sql"),
    ),
    (
        10,
        include_str!("../../migrations/0010_presence_generation.sql"),
    ),
    (
        11,
        include_str!("../../migrations/0011_mesh_provisioning.sql"),
    ),
    (
        12,
        include_str!("../../migrations/0012_mesh_history_retention.sql"),
    ),
    (13, include_str!("../../migrations/0013_dynamic_meshes.sql")),
    (
        14,
        include_str!("../../migrations/0014_lifecycle_fencing.sql"),
    ),
    (
        15,
        include_str!("../../migrations/0015_restore_function_paths.sql"),
    ),
    (
        16,
        include_str!("../../migrations/0016_peer_device_details.sql"),
    ),
    (
        17,
        include_str!("../../migrations/0017_default_tunnel_mtu.sql"),
    ),
    (
        18,
        include_str!("../../migrations/0018_wireguard_credentials.sql"),
    ),
    (19, include_str!("../../migrations/0019_wss_endpoints.sql")),
    (20, include_str!("../../migrations/0020_quic_endpoints.sql")),
    (
        21,
        include_str!("../../migrations/0021_management_resources.sql"),
    ),
    (
        22,
        include_str!("../../migrations/0022_peer_management.sql"),
    ),
    (
        23,
        include_str!("../../migrations/0023_management_policy.sql"),
    ),
    (
        24,
        include_str!("../../migrations/0024_configuration_receipt_categories.sql"),
    ),
    (
        25,
        include_str!("../../migrations/0025_route_advertisement_versions.sql"),
    ),
    (
        26,
        include_str!("../../migrations/0026_resource_withdrawals.sql"),
    ),
    (
        27,
        include_str!("../../migrations/0027_dns_name_reservations.sql"),
    ),
    (
        28,
        include_str!("../../migrations/0028_management_collections.sql"),
    ),
    (29, include_str!("../../migrations/0029_dual_stack.sql")),
    (
        30,
        include_str!("../../migrations/0030_controlled_enrollment.sql"),
    ),
    (
        31,
        include_str!("../../migrations/0031_device_admission_lifecycle.sql"),
    ),
    (
        32,
        include_str!("../../migrations/0032_dns_delegation_names.sql"),
    ),
    (
        33,
        include_str!("../../migrations/0033_machine_credentials.sql"),
    ),
    (34, include_str!("../../migrations/0034_auto_approval.sql")),
    (
        35,
        include_str!("../../migrations/0035_withdrawal_providers.sql"),
    ),
    (
        36,
        include_str!("../../migrations/0036_configuration_ownership.sql"),
    ),
    (
        37,
        include_str!("../../migrations/0037_provider_capture_exclusions.sql"),
    ),
    (38, include_str!("../../migrations/0038_webhooks.sql")),
    (
        39,
        include_str!("../../migrations/0039_configuration_response_retention.sql"),
    ),
    (40, include_str!("../../migrations/0040_target_health.sql")),
    (
        41,
        include_str!("../../migrations/0041_device_conditions.sql"),
    ),
    (
        42,
        include_str!("../../migrations/0042_relay_maintenance.sql"),
    ),
    (
        43,
        include_str!("../../migrations/0043_deployment_tasks.sql"),
    ),
    (44, include_str!("../../migrations/0044_relay_capacity.sql")),
    (
        45,
        include_str!("../../migrations/0045_native_upgrade_tasks.sql"),
    ),
    (
        46,
        include_str!("../../migrations/0046_native_upgrade_recovery.sql"),
    ),
    (47, include_str!("../../migrations/0047_console_state.sql")),
    (
        48,
        include_str!("../../migrations/0048_console_sharing.sql"),
    ),
    (
        49,
        include_str!("../../migrations/0049_console_credential_renewal.sql"),
    ),
    (
        50,
        include_str!("../../migrations/0050_console_oidc_context.sql"),
    ),
    (
        51,
        include_str!("../../migrations/0051_console_evidence_generation.sql"),
    ),
    (
        52,
        include_str!("../../migrations/0052_network_identifier.sql"),
    ),
    (53, include_str!("../../migrations/0053_device_purpose.sql")),
    (
        54,
        include_str!("../../migrations/0054_enrollment_device_groups.sql"),
    ),
];

async fn apply_followup_migrations(connection: &mut sqlx::PgConnection) -> Result<(), sqlx::Error> {
    for (version, migration) in FOLLOWUP_MIGRATIONS {
        let checksum = Sha256::digest(migration.as_bytes()).to_vec();
        let existing = sqlx::query_scalar::<_, Vec<u8>>(
            "SELECT checksum FROM peerward_schema_migrations WHERE version=$1",
        )
        .bind(version)
        .fetch_optional(&mut *connection)
        .await?;
        if let Some(existing) = existing {
            if existing != checksum {
                return Err(sqlx::Error::Protocol(format!(
                    "Peerward migration {version} checksum mismatch"
                )));
            }
            continue;
        }
        let mut transaction = connection.begin().await?;
        sqlx::raw_sql(migration).execute(&mut *transaction).await?;
        sqlx::query("INSERT INTO peerward_schema_migrations(version,checksum) VALUES($1,$2)")
            .bind(version)
            .bind(checksum)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
    }
    Ok(())
}
