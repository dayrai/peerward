/// Root-verified authority material used to initialize a new installation.
#[derive(Debug, Clone)]
pub struct InitialAuthority {
    /// Stable database relation identifier.
    pub id: Uuid,
    /// Exact revocable credential serial.
    pub serial: CredentialSerial,
    /// Ed25519 verifier certified by the offline root.
    pub public_key: Vec<u8>,
    /// Inclusive validity start.
    pub not_before: OffsetDateTime,
    /// Exclusive validity end.
    pub not_after: OffsetDateTime,
    /// Canonical root-signed certificate bytes.
    pub certificate: Vec<u8>,
}

/// Authority-verified initial Relay and its active credential.
#[derive(Debug, Clone)]
pub struct InitialRelay {
    /// Stable Relay identifier.
    pub id: RelayId,
    /// Human-readable Relay name.
    pub name: String,
    /// Public peer listeners advertised in the signed directory.
    pub peer_endpoints: Vec<NetworkEndpoint>,
    /// Public backbone listeners advertised in the signed directory.
    pub backbone_endpoints: Vec<NetworkEndpoint>,
    /// Stable credential row identifier.
    pub credential_id: Uuid,
    /// Exact revocable credential serial.
    pub credential_serial: CredentialSerial,
    /// X25519 static public key.
    pub public_key: Vec<u8>,
    /// Inclusive credential validity start.
    pub not_before: OffsetDateTime,
    /// Exclusive credential validity end.
    pub not_after: OffsetDateTime,
    /// Authority signature over the fixed subject transcript.
    pub signature: Vec<u8>,
}

/// Complete, already cryptographically verified first-installation state.
#[derive(Debug, Clone)]
pub struct InitialInstallation {
    /// Caller-generated stable Mesh identifier.
    pub mesh_id: MeshId,
    /// Validated Mesh settings.
    pub mesh: NewMesh,
    /// Rooted online Authority.
    pub authority: InitialAuthority,
    /// First Relay.
    pub relay: InitialRelay,
}

impl Store {
    /// Installs a complete first Mesh atomically and is idempotent for the exact manifest.
    ///
    /// The caller must verify all signatures before invoking this persistence boundary. A
    /// repeated exact manifest is accepted; any partial or different state is rejected.
    pub async fn initialize_installation(
        &self,
        installation: &InitialInstallation,
    ) -> Result<bool, StoreError> {
        self.initialize_installation_mode(installation, false).await
    }

    /// Adds initial identities to an existing empty Mesh without changing its settings,
    /// policy, or revisions. An exact retry succeeds without inserting duplicate records.
    /// The caller must verify the supplied certificate chain before this boundary.
    pub async fn complete_empty_mesh_installation(
        &self,
        installation: &InitialInstallation,
    ) -> Result<bool, StoreError> {
        self.initialize_installation_mode(installation, true).await
    }

    async fn initialize_installation_mode(
        &self,
        installation: &InitialInstallation,
        complete_empty_mesh: bool,
    ) -> Result<bool, StoreError> {
        validate_initial_installation(installation)?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended('peerward/initialize/v1', 0))")
            .execute(&mut *transaction)
            .await?;

        let mesh_uuid = installation.mesh_id.into_uuid();
        // FOR UPDATE also blocks concurrent FK insertions into identities and Peers.
        // The empty-state check therefore remains true until our transaction commits.
        let exists = sqlx::query_scalar::<_, Uuid>("SELECT id FROM meshes WHERE id=$1 FOR UPDATE")
            .bind(mesh_uuid)
            .fetch_optional(&mut *transaction)
            .await?
            .is_some();
        if exists {
            if complete_empty_mesh
                && !initial_mesh_configuration_matches(&mut transaction, installation).await?
            {
                return Err(StoreError::Conflict);
            }
            if initial_installation_matches(&mut transaction, installation).await? {
                transaction.commit().await?;
                return Ok(false);
            }
            if !complete_empty_mesh {
                return Err(StoreError::Conflict);
            }
            let occupied: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM mesh_authorities WHERE mesh_id=$1)
                    OR EXISTS(SELECT 1 FROM relays WHERE mesh_id=$1)
                    OR EXISTS(SELECT 1 FROM peers WHERE mesh_id=$1)",
            )
            .bind(mesh_uuid)
            .fetch_one(&mut *transaction)
            .await?;
            if occupied {
                return Err(StoreError::Conflict);
            }
        } else if complete_empty_mesh {
            return Err(StoreError::NotFound);
        }

        if !exists {
            let policy_document = encode_policy_document(&Policy::new(
                1,
                match installation.mesh.default_policy {
                    DefaultPolicy::Allow => PolicyAction::Allow,
                    DefaultPolicy::Deny => PolicyAction::Deny,
                },
                Vec::new(),
            ))
            .map_err(|_| StoreError::Invalid("default policy"))?;
            let reserved: Vec<String> = installation
                .mesh
                .reserved
                .iter()
                .map(ToString::to_string)
                .collect();
            sqlx::query(
                "INSERT INTO meshes
                 (id,name,address_cidr,gateway,dns_suffix,mtu,reserved_addresses,default_policy,
                  quarantine_seconds,rotation_overlap_seconds,authority_revision,relay_revision,
                  policy_revision,service_revision,revocation_revision)
                 VALUES($1,$2,$3::cidr,$4::inet,$5,$6,$7::text[]::inet[],$8,$9,$10,1,1,1,1,1)",
            )
            .bind(mesh_uuid)
            .bind(&installation.mesh.name)
            .bind(installation.mesh.address_cidr.to_string())
            .bind(installation.mesh.gateway.to_string())
            .bind(&installation.mesh.dns_suffix)
            .bind(i32::from(installation.mesh.mtu))
            .bind(reserved)
            .bind(installation.mesh.default_policy.as_str())
            .bind(
                i64::try_from(installation.mesh.quarantine_seconds)
                    .map_err(|_| StoreError::Invalid("quarantine"))?,
            )
            .bind(
                i64::try_from(installation.mesh.rotation_overlap_seconds)
                    .map_err(|_| StoreError::Invalid("rotation overlap"))?,
            )
            .execute(&mut *transaction)
            .await?;
            sqlx::query(
                "INSERT INTO policies(mesh_id,revision,default_action,document,current)
                 VALUES($1,1,$2,$3,true)",
            )
            .bind(mesh_uuid)
            .bind(installation.mesh.default_policy.as_str())
            .bind(policy_document)
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query(
            "INSERT INTO mesh_authorities
             (id,mesh_id,serial,public_key,not_before,not_after,lifecycle,certificate)
             VALUES($1,$2,$3,$4,$5,$6,'active',$7)",
        )
        .bind(installation.authority.id)
        .bind(mesh_uuid)
        .bind(installation.authority.serial.into_uuid())
        .bind(&installation.authority.public_key)
        .bind(installation.authority.not_before)
        .bind(installation.authority.not_after)
        .bind(&installation.authority.certificate)
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO relays(id,mesh_id,name,peer_endpoints,backbone_endpoints)
             VALUES($1,$2,$3,$4,$5)",
        )
        .bind(installation.relay.id.into_uuid())
        .bind(mesh_uuid)
        .bind(&installation.relay.name)
        .bind(endpoint_strings(&installation.relay.peer_endpoints))
        .bind(endpoint_strings(&installation.relay.backbone_endpoints))
        .execute(&mut *transaction)
        .await?;
        sqlx::query(
            "INSERT INTO relay_credentials
             (id,mesh_id,relay_id,authority_id,serial,public_key,not_before,not_after,
              lifecycle,signature)
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,'active',$9)",
        )
        .bind(installation.relay.credential_id)
        .bind(mesh_uuid)
        .bind(installation.relay.id.into_uuid())
        .bind(installation.authority.id)
        .bind(installation.relay.credential_serial.into_uuid())
        .bind(&installation.relay.public_key)
        .bind(installation.relay.not_before)
        .bind(installation.relay.not_after)
        .bind(&installation.relay.signature)
        .execute(&mut *transaction)
        .await?;
        append_audit(
            &mut transaction,
            Some(installation.mesh_id),
            "bootstrap",
            "installation.initialize",
            "installation",
            Some(mesh_uuid),
            "success",
            json!({"mesh_id":installation.mesh_id,"relay_id":installation.relay.id}),
        )
        .await?;
        append_event(
            &mut transaction,
            Some(installation.mesh_id),
            "installation.initialized",
            "installation",
            Some(mesh_uuid),
            json!({"mesh_id":installation.mesh_id,"relay_id":installation.relay.id}),
        )
        .await?;
        transaction.commit().await?;
        Ok(true)
    }
}

fn validate_initial_installation(value: &InitialInstallation) -> Result<(), StoreError> {
    value.mesh.validate()?;
    if value.authority.id.get_version_num() != 4
        || value.relay.credential_id.get_version_num() != 4
        || value.authority.public_key.len() != 32
        || value.authority.certificate.is_empty()
        || value.authority.not_before >= value.authority.not_after
        || value.relay.name.trim().is_empty()
        || value.relay.name.len() > 128
        || validate_endpoint_list(&value.relay.peer_endpoints).is_err()
        || validate_endpoint_list(&value.relay.backbone_endpoints).is_err()
        || value.relay.public_key.len() != 32
        || value.relay.signature.len() != 64
        || value.relay.not_before >= value.relay.not_after
    {
        return Err(StoreError::Invalid("initial installation"));
    }
    Ok(())
}

async fn initial_installation_matches(
    transaction: &mut Transaction<'_, Postgres>,
    value: &InitialInstallation,
) -> Result<bool, StoreError> {
    let exact: bool = sqlx::query_scalar(
        "SELECT EXISTS(
           SELECT 1 FROM meshes m
           JOIN mesh_authorities a ON a.mesh_id=m.id AND a.id=$2
           JOIN relays r ON r.mesh_id=m.id AND r.id=$3
           JOIN relay_credentials c ON c.mesh_id=m.id AND c.relay_id=r.id AND c.id=$4
           WHERE m.id=$1 AND m.name=$5 AND m.address_cidr=$6::cidr AND m.gateway=$7::inet
             AND m.dns_suffix=$8 AND m.mtu=$9 AND m.default_policy=$10
             AND a.serial=$11 AND a.public_key=$12 AND a.certificate=$13 AND a.lifecycle='active'
             AND r.name=$14 AND r.peer_endpoints=$15 AND r.backbone_endpoints=$16
             AND c.authority_id=a.id AND c.serial=$17 AND c.public_key=$18
             AND c.signature=$19 AND c.lifecycle='active')",
    )
    .bind(value.mesh_id.into_uuid())
    .bind(value.authority.id)
    .bind(value.relay.id.into_uuid())
    .bind(value.relay.credential_id)
    .bind(&value.mesh.name)
    .bind(value.mesh.address_cidr.to_string())
    .bind(value.mesh.gateway.to_string())
    .bind(&value.mesh.dns_suffix)
    .bind(i32::from(value.mesh.mtu))
    .bind(value.mesh.default_policy.as_str())
    .bind(value.authority.serial.into_uuid())
    .bind(&value.authority.public_key)
    .bind(&value.authority.certificate)
    .bind(&value.relay.name)
    .bind(endpoint_strings(&value.relay.peer_endpoints))
    .bind(endpoint_strings(&value.relay.backbone_endpoints))
    .bind(value.relay.credential_serial.into_uuid())
    .bind(&value.relay.public_key)
    .bind(&value.relay.signature)
    .fetch_one(&mut **transaction)
    .await?;
    Ok(exact)
}

fn endpoint_strings(endpoints: &[NetworkEndpoint]) -> Vec<String> {
    endpoints.iter().map(ToString::to_string).collect()
}

include!("provision_config.rs");
