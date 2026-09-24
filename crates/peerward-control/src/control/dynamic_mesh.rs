use peerward_credentials::{RootSigningKey, UnsignedAuthority};
use peerward_credentials::private_files::{private_dir, read_private, remove_private, write_private_atomic};
use peerward_store::MeshLifecycleJob;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicMeshConfig {
    #[serde(default)]
    pub hosts: Vec<InitialRelayHost>,
    /// Installation-wide discovery services, shared across all dynamic Meshes.
    #[serde(default)]
    pub stun_servers: Vec<peerward_types::StunEndpoint>,
    pub state_directory: std::path::PathBuf,
    pub recovery_directory: std::path::PathBuf,
    pub recovery_public_key: String,
    pub host_address: SocketAddr,
    pub ca_file: std::path::PathBuf,
    pub certificate_file: std::path::PathBuf,
    pub private_key_file: std::path::PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InitialRelayHost {
    pub id: Uuid,
    pub name: String,
    pub certificate_sha256: String,
    pub peer_endpoints: Vec<String>,
    pub backbone_endpoints: Vec<String>,
    #[serde(default)]
    pub is_default: bool,
}

async fn register_initial_hosts(config: &DynamicMeshConfig, store: &Store) -> Result<(), ApiError> {
    let mut tx = store.begin_mutation().await?;
    for host in &config.hosts {
        if host.id.get_version_num()!=4 || !valid_display_name(&host.name) { return Err(dynamic_invalid()); }
        let fingerprint = decode_config_key(&host.certificate_sha256)?;
        for endpoints in [&host.peer_endpoints, &host.backbone_endpoints] {
            let parsed = endpoints.iter().map(|s| s.parse::<NetworkEndpoint>().map_err(|_| dynamic_invalid())).collect::<Result<Vec<_>,_>>()?;
            validate_endpoint_list(&parsed).map_err(|_| dynamic_invalid())?;
        }
        sqlx::query("INSERT INTO relay_hosts(id,name,certificate_sha256,peer_endpoints,backbone_endpoints,is_default)
            VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(id) DO NOTHING")
            .bind(host.id).bind(&host.name).bind(fingerprint.to_vec()).bind(&host.peer_endpoints).bind(&host.backbone_endpoints)
            .bind(host.is_default).execute(&mut *tx).await?;
        let saved: Vec<u8> = sqlx::query_scalar("SELECT certificate_sha256 FROM relay_hosts WHERE id=$1")
            .bind(host.id).fetch_one(&mut *tx).await?;
        if saved != fingerprint { return Err(ApiError::conflict("host_identity_changed", "Installed Relay host identity does not match configuration")); }
    }
    tx.commit().await?;
    Ok(())
}

impl DynamicMeshConfig {
    fn from_environment() -> Result<Option<Self>, ApiError> {
        let Some(path) = std::env::var_os("PEERWARD_DYNAMIC_CONFIG") else { return Ok(None); };
        let bytes = read_private(std::path::Path::new(&path), 65_536).map_err(dynamic_io)?;
        let config: Self = toml::from_str(std::str::from_utf8(&bytes).map_err(|_| dynamic_invalid())?)
            .map_err(|_| dynamic_invalid())?;
        decode_config_key(&config.recovery_public_key)?;
        peerward_types::validate_stun_servers(&config.stun_servers).map_err(|_| dynamic_invalid())?;
        private_dir(&config.state_directory).map_err(dynamic_io)?;
        private_dir(&config.recovery_directory).map_err(dynamic_io)?;
        Ok(Some(config))
    }
    fn bundle_path(&self, mesh: MeshId) -> std::path::PathBuf {
        self.state_directory.join(mesh.to_string()).join("issuer.json")
    }
}

fn dynamic_invalid() -> ApiError { ApiError::invalid("dynamic_mesh_invalid", "Mesh lifecycle configuration or material is invalid") }
fn dynamic_io(_: std::io::Error) -> ApiError { ApiError::unavailable("mesh_key_storage", "Mesh key storage operation failed") }

#[derive(serde::Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedMeshBundle {
    issuer: JoinIssuerConfig,
    recovery: Vec<u8>,
    #[serde(default)]
    additional_issuers: Vec<JoinIssuerConfig>,
}

fn read_managed_bundle(config: &DynamicMeshConfig, mesh: MeshId) -> Result<ManagedMeshBundle, ApiError> {
    let bytes = Zeroizing::new(read_private(&config.bundle_path(mesh), 65_536).map_err(dynamic_io)?);
    let mut bundle: ManagedMeshBundle = serde_json::from_slice(&bytes).map_err(|_| dynamic_invalid())?;
    if bundle.issuer.mesh_id != mesh { return Err(dynamic_invalid()); }
    peerward_types::validate_stun_servers(&config.stun_servers).map_err(|_| dynamic_invalid())?;
    // Discovery settings are installation metadata, not credential-generation material.
    // Existing Meshes pick up the configured services without rewriting their keys/bundles.
    bundle.issuer.stun_servers.clone_from(&config.stun_servers);
    for issuer in &mut bundle.additional_issuers {
        issuer.stun_servers.clone_from(&config.stun_servers);
    }
    Ok(bundle)
}

fn prepare_managed_bundle(config: &DynamicMeshConfig, mesh: MeshId) -> Result<ManagedMeshBundle, ApiError> {
    if config.bundle_path(mesh).exists() { return read_managed_bundle(config, mesh); }
    peerward_types::validate_stun_servers(&config.stun_servers).map_err(|_| dynamic_invalid())?;
    let root = RootSigningKey::generate();
    let authority = AuthoritySigningKey::generate();
    let now = current_unix_seconds();
    let certificate = root.certify(UnsignedAuthority { mesh_id: mesh, serial: CredentialSerial::new(),
        public_key: authority.public_key(), not_before: UnixTime(now.saturating_sub(60)),
        not_after: UnixTime(now + 365 * 86400) }).map_err(|_| dynamic_invalid())?;
    let seed = Zeroizing::new(root.to_bytes());
    let recovery = peerward_wire::seal_root_recovery(mesh, &seed, &decode_config_key(&config.recovery_public_key)?)
        .map_err(|_| dynamic_invalid())?;
    let random_seed = || { let mut seed = Zeroizing::new([0; 32]); OsRng.fill_bytes(seed.as_mut()); hex::encode(seed.as_ref()) };
    let bundle = ManagedMeshBundle { issuer: JoinIssuerConfig {
        mesh_id: mesh, authority_id: Uuid::new_v4(), authority_private_key: Some(hex::encode(Zeroizing::new(authority.to_bytes()).as_ref())),
        root_public_key: hex::encode(root.public_key().to_bytes()), authority_certificate: URL_SAFE_NO_PAD.encode(certificate.encode()),
        directory_private_key: random_seed(), service_private_key: random_seed(), audit_private_key: random_seed(),
        credential_validity_seconds: 86400, stun_servers: config.stun_servers.clone(),
    }, recovery, additional_issuers: Vec::new() };
    let bytes = Zeroizing::new(serde_json::to_vec(&bundle).map_err(|_| dynamic_invalid())?);
    write_private_atomic(&config.bundle_path(mesh), &bytes).map_err(dynamic_io)?;
    Ok(bundle)
}

fn bundle_issuer(bundle: &ManagedMeshBundle) -> Result<Arc<JoinIssuer>, ApiError> {
    load_join_issuers(std::slice::from_ref(&bundle.issuer), None)?
        .remove(&bundle.issuer.mesh_id).and_then(|mut values| values.pop()).ok_or_else(dynamic_invalid)
}

async fn reload_managed_issuers(config: &DynamicMeshConfig, store: &Store, registry: &IssuerRegistry) -> Result<(), ApiError> {
    let rows: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM meshes WHERE lifecycle IN ('creating','active','deleting') ORDER BY id")
        .fetch_all(store.pool()).await?;
    for id in rows {
        let mesh = mesh_id(id)?;
        if !config.bundle_path(mesh).exists() { continue; }
        match read_managed_bundle(config, mesh).and_then(|bundle| {
            let root = bundle.issuer.root_public_key.clone();
            let mut candidates = vec![bundle.issuer.clone()];
            candidates.extend(bundle.additional_issuers.iter().cloned());
            if candidates.iter().any(|issuer| issuer.mesh_id != mesh || issuer.root_public_key != root) { return Err(dynamic_invalid()); }
            let mut loaded = Vec::new();
            for candidate in candidates {
                if let Ok(mut entries) = load_join_issuers(&[candidate], None) {
                    loaded.extend(entries.remove(&mesh).unwrap_or_default());
                }
            }
            if loaded.is_empty() { return Err(dynamic_invalid()); }
            Ok(loaded)
        }) {
            Ok(issuers) => registry.install(mesh, issuers),
            Err(error) => tracing::warn!(%mesh, ?error, "Mesh signer reload deferred"),
        }
    }
    Ok(())
}

async fn lock_lifecycle_step<'a>(store: &'a Store, job: &MeshLifecycleJob, owner: Uuid) -> Result<sqlx::Transaction<'a, sqlx::Postgres>, ApiError> {
    let mut tx = store.begin_mutation().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("mesh-lifecycle/{}", job.mesh_id)).execute(&mut *tx).await?;
    let valid = sqlx::query("SELECT id FROM mesh_lifecycle_jobs
        WHERE id=$1 AND generation=$2 AND lease_owner=$3 AND status='running' AND lease_until>clock_timestamp() FOR UPDATE")
        .bind(job.id).bind(job.generation).bind(owner).fetch_optional(&mut *tx).await?;
    if valid.is_none() { return Err(ApiError::conflict("job_fenced", "Lifecycle worker lease was replaced")); }
    sqlx::query("SELECT id FROM meshes WHERE id=$1 FOR UPDATE").bind(job.mesh_id.into_uuid()).execute(&mut *tx).await?;
    Ok(tx)
}

async fn run_mesh_lifecycle(config: DynamicMeshConfig, store: Store, registry: IssuerRegistry) {
    let owner = Uuid::new_v4();
    let mut reload_at = tokio::time::Instant::now();
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        if reload_at.elapsed() >= Duration::from_secs(5) {
            let _ = reload_managed_issuers(&config, &store, &registry).await;
            if let Err(error) = renew_host_credentials(&store, &registry).await {
                tracing::warn!(?error, "Relay credential renewal deferred");
            }
            reload_at = tokio::time::Instant::now();
        }
        let jobs = match store.claim_mesh_jobs(owner, 8).await {
            Ok(jobs) => jobs,
            Err(error) => { tracing::warn!(?error, "Mesh lifecycle queue unavailable"); continue; }
        };
        for job in jobs {
            let result = if job.operation == "create" {
                create_mesh_step(&config, &store, &registry, &job, owner).await
            } else { delete_mesh_step(&config, &store, &registry, &job, owner).await };
            let (stage, status, error) = match result {
                Ok((stage, done)) => (stage, if done { "succeeded" } else { "waiting" }, None),
                Err(error) => {
                    tracing::warn!(mesh = %job.mesh_id, job = %job.id, ?error, "Mesh lifecycle step failed");
                    (job.stage.as_str(), if job.consecutive_failures >= 9 { "failed" } else { "waiting" }, Some("mesh_step_failed"))
                }
            };
            let _ = store.finish_mesh_job_step(&job, owner, stage, status, error).await;
        }
    }
}

async fn create_mesh_step(config: &DynamicMeshConfig, store: &Store, registry: &IssuerRegistry,
    job: &MeshLifecycleJob, owner: Uuid) -> Result<(&'static str, bool), ApiError> {
    let mut tx = lock_lifecycle_step(store, job, owner).await?;
    let lifecycle: String = sqlx::query_scalar("SELECT lifecycle FROM meshes WHERE id=$1")
        .bind(job.mesh_id.into_uuid()).fetch_one(&mut *tx).await?;
    if lifecycle == "active" { return Ok(("complete", true)); }
    if lifecycle != "creating" { return Err(ApiError::conflict("mesh_terminal", "Mesh is being deleted")); }
    let bundle = prepare_managed_bundle(config, job.mesh_id)?;
    write_private_atomic(&config.recovery_directory.join(format!("{}.recovery", job.mesh_id)), &bundle.recovery).map_err(dynamic_io)?;
    let issuer = bundle_issuer(&bundle)?;
    let certificate = &issuer.authority_certificate;
    let inserted = sqlx::query("INSERT INTO mesh_authorities(id,mesh_id,serial,public_key,not_before,not_after,lifecycle,certificate)
        VALUES($1,$2,$3,$4,$5,$6,'active',$7) ON CONFLICT(id) DO NOTHING")
        .bind(issuer.authority_id).bind(job.mesh_id.into_uuid()).bind(certificate.serial.into_uuid())
        .bind(certificate.public_key.to_vec()).bind(timestamp(certificate.not_before)?).bind(timestamp(certificate.not_after)?)
        .bind(certificate.encode()).execute(&mut *tx).await?.rows_affected();
    if inserted > 0 {
        sqlx::query("UPDATE meshes SET authority_revision=authority_revision+1 WHERE id=$1")
            .bind(job.mesh_id.into_uuid()).execute(&mut *tx).await?;
    }
    let ready: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM relay_host_assignments WHERE mesh_id=$1 AND desired='active')
        AND NOT EXISTS(SELECT 1 FROM relay_host_assignments WHERE mesh_id=$1 AND desired='active' AND (state<>'ready' OR applied_revision<>revision))")
        .bind(job.mesh_id.into_uuid()).fetch_one(&mut *tx).await?;
    if ready {
        sqlx::query("UPDATE meshes SET lifecycle='active',lifecycle_revision=lifecycle_revision+1 WHERE id=$1")
            .bind(job.mesh_id.into_uuid()).execute(&mut *tx).await?;
    }
    let mut record = lifecycle_record(job.mesh_id, &job.actor, "mesh.lifecycle", if ready { "mesh.ready" } else { "mesh.initializing" });
    record.metadata = json!({"job_id":job.id,"stage":if ready {"complete"} else {"relay"}});
    if inserted > 0 || ready { store.commit_mutation(tx, &record).await?; } else { tx.commit().await?; }
    registry.install(job.mesh_id, vec![issuer.clone()]);
    // Signed states must exist before Relay can acknowledge readiness.
    publish_mesh_state(store, job.mesh_id, &issuer).await?;
    Ok((if ready { "complete" } else { "relay" }, ready))
}

fn timestamp(time: UnixTime) -> Result<OffsetDateTime, ApiError> {
    OffsetDateTime::from_unix_timestamp(i64::try_from(time.0).map_err(|_| dynamic_invalid())?).map_err(|_| dynamic_invalid())
}

async fn delete_mesh_step(config: &DynamicMeshConfig, store: &Store, registry: &IssuerRegistry,
    job: &MeshLifecycleJob, owner: Uuid) -> Result<(&'static str, bool), ApiError> {
    let mut tx = lock_lifecycle_step(store, job, owner).await?;
    let existing = sqlx::query("SELECT termination,cleaned_at FROM mesh_tombstones WHERE mesh_id=$1")
        .bind(job.mesh_id.into_uuid()).fetch_optional(&mut *tx).await?;
    if existing.as_ref().is_some_and(|r| r.try_get::<Option<OffsetDateTime>,_>("cleaned_at").ok().flatten().is_some()) {
        registry.remove(&job.mesh_id);
        remove_private(&config.bundle_path(job.mesh_id)).map_err(dynamic_io)?;
        return Ok(("complete", true));
    }
    if existing.is_none() {
        let bundle = prepare_managed_bundle(config, job.mesh_id)?;
        // Deletion may win before the creation worker ever archives the Root.
        write_private_atomic(&config.recovery_directory.join(format!("{}.recovery", job.mesh_id)), &bundle.recovery).map_err(dynamic_io)?;
        let issuer = match registry.get(&job.mesh_id) {
            Some(candidates) => active_issuer_with_executor(&mut *tx, job.mesh_id, &candidates).await?,
            None => bundle_issuer(&bundle)?,
        };
        let row = sqlx::query("SELECT name,lifecycle_revision FROM meshes WHERE id=$1 AND lifecycle='deleting'")
            .bind(job.mesh_id.into_uuid()).fetch_one(&mut *tx).await?;
        let revision: i64 = row.try_get("lifecycle_revision")?;
        let terminal = issuer.authority.terminate_mesh(issuer.authority_certificate.clone(),
            u64::try_from(revision).map_err(|_| dynamic_invalid())?, UnixTime(current_unix_seconds())).map_err(|_| dynamic_invalid())?;
        sqlx::query("INSERT INTO mesh_tombstones(mesh_id,name,revision,root_public_key,termination,terminated_at) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(job.mesh_id.into_uuid()).bind(row.try_get::<String,_>("name")?).bind(revision)
            .bind(issuer.root_public_key.to_vec()).bind(terminal.encode()).bind(timestamp(terminal.terminated_at)?)
            .execute(&mut *tx).await?;
        sqlx::query("UPDATE relay_host_assignments SET desired='removed',revision=revision+1,state='pending',updated_at=clock_timestamp() WHERE mesh_id=$1")
            .bind(job.mesh_id.into_uuid()).execute(&mut *tx).await?;
        sqlx::query("UPDATE relay_hosts SET revision=revision+1 WHERE id IN (SELECT host_id FROM relay_host_assignments WHERE mesh_id=$1)")
            .bind(job.mesh_id.into_uuid()).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(("stopping", false));
    }
    let waiting: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM relay_host_assignments WHERE mesh_id=$1 AND (state<>'removed' OR applied_revision<>revision))")
        .bind(job.mesh_id.into_uuid()).fetch_one(&mut *tx).await?;
    if waiting { return Ok(("waiting_for_relay", false)); }
    // Remove references to credentials before identities and Authorities.
    sqlx::query("DELETE FROM join_tickets WHERE mesh_id=$1").bind(job.mesh_id.into_uuid()).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM peer_credential_rotation_requests WHERE mesh_id=$1").bind(job.mesh_id.into_uuid()).execute(&mut *tx).await?;
    // Child identities precede Authorities because their trust FKs are restrictive.
    sqlx::query("DELETE FROM peer_credentials WHERE mesh_id=$1").bind(job.mesh_id.into_uuid()).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM relay_credentials WHERE mesh_id=$1").bind(job.mesh_id.into_uuid()).execute(&mut *tx).await?;
    sqlx::query("DELETE FROM meshes WHERE id=$1").bind(job.mesh_id.into_uuid()).execute(&mut *tx).await?;
    sqlx::query("UPDATE mesh_tombstones SET cleaned_at=clock_timestamp() WHERE mesh_id=$1")
        .bind(job.mesh_id.into_uuid()).execute(&mut *tx).await?;
    let record = lifecycle_record(job.mesh_id, &job.actor, "mesh.delete", "mesh.deleted");
    store.commit_mutation(tx, &record).await?;
    registry.remove(&job.mesh_id);
    remove_private(&config.bundle_path(job.mesh_id)).map_err(dynamic_io)?;
    Ok(("complete", true))
}

fn lifecycle_record(mesh: MeshId, actor: &str, action: &str, event: &str) -> MutationRecord {
    MutationRecord { mesh_id: Some(mesh), actor: actor.into(), action: action.into(), event_type: event.into(),
        resource_type: "mesh".into(), resource_id: Some(mesh.into_uuid()), result: "success".into(),
        metadata: json!({"mesh_id":mesh}), correlation: None }
}

/// Local administrator import. Only online Authority material is read; Root seeds
/// remain offline. The public certificate must already be staged through the API.
pub async fn import_managed_authority(config_path: &std::path::Path, mesh: MeshId, authority_id: Uuid,
    key_path: &std::path::Path, certificate_path: &std::path::Path, database: &str) -> Result<(), ApiError> {
    let config_bytes = read_private(config_path, 65_536).map_err(dynamic_io)?;
    let config: DynamicMeshConfig = toml::from_str(std::str::from_utf8(&config_bytes).map_err(|_| dynamic_invalid())?).map_err(|_| dynamic_invalid())?;
    let store = Store::connect(database, 2).await?;
    let mut tx = store.begin_mutation().await?;
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1,0))")
        .bind(format!("mesh-lifecycle/{mesh}")).execute(&mut *tx).await?;
    let live: Option<String> = sqlx::query_scalar("SELECT lifecycle FROM meshes WHERE id=$1 FOR UPDATE")
        .bind(mesh.into_uuid()).fetch_optional(&mut *tx).await?;
    if live.as_deref()!=Some("active") { return Err(ApiError::conflict("mesh_not_active", "Mesh is not active")); }
    let mut bundle = read_managed_bundle(&config, mesh)?;
    let certificate = read_private(certificate_path, 144).map_err(dynamic_io)?;
    let stored: Option<Vec<u8>> = sqlx::query_scalar("SELECT certificate FROM mesh_authorities WHERE mesh_id=$1 AND id=$2 AND lifecycle IN ('staged','active')")
        .bind(mesh.into_uuid()).bind(authority_id).fetch_optional(&mut *tx).await?;
    if stored.as_deref()!=Some(certificate.as_slice()) { return Err(dynamic_invalid()); }
    let seed = Zeroizing::new(read_private(key_path, 128).map_err(dynamic_io)?);
    let mut issuer = bundle.issuer.clone();
    issuer.authority_id = authority_id;
    issuer.authority_certificate = URL_SAFE_NO_PAD.encode(&certificate);
    issuer.authority_private_key = Some(std::str::from_utf8(&seed).map_err(|_| dynamic_invalid())?.trim().to_owned());
    load_join_issuers(std::slice::from_ref(&issuer), None)?;
    bundle.additional_issuers.retain(|candidate| candidate.authority_id!=authority_id);
    bundle.additional_issuers.push(issuer);
    if bundle.additional_issuers.len()>16 { return Err(dynamic_invalid()); }
    let encoded = Zeroizing::new(serde_json::to_vec(&bundle).map_err(|_| dynamic_invalid())?);
    write_private_atomic(&config.bundle_path(mesh), &encoded).map_err(dynamic_io)?;
    store.commit_mutation(tx, &lifecycle_record(mesh, "local-administrator", "authority.key_import", "authority.key_imported")).await?;
    Ok(())
}

impl Drop for ManagedMeshBundle {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for issuer in std::iter::once(&mut self.issuer).chain(self.additional_issuers.iter_mut()) {
            if let Some(seed) = &mut issuer.authority_private_key { seed.zeroize(); }
            issuer.directory_private_key.zeroize();
            issuer.service_private_key.zeroize();
            issuer.audit_private_key.zeroize();
        }
    }
}
