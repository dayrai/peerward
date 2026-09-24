include!("bootstrap_options.rs");

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapManifest {
    schema_version: u32,
    mesh_id: MeshId,
    mesh: NewMesh,
    root_public_key: String,
    authority_id: Uuid,
    authority_certificate: String,
    relay_id: RelayId,
    relay_name: String,
    #[serde(
        alias = "relay_peer_endpoint",
        deserialize_with = "deserialize_bootstrap_endpoints"
    )]
    relay_peer_endpoints: Vec<NetworkEndpoint>,
    #[serde(
        alias = "relay_backbone_endpoint",
        deserialize_with = "deserialize_bootstrap_endpoints"
    )]
    relay_backbone_endpoints: Vec<NetworkEndpoint>,
    relay_credential_id: Uuid,
    relay_credential: String,
}

async fn execute_bootstrap(command: BootstrapCommand) -> Result<(), CliError> {
    match command {
        BootstrapCommand::AuthorityImport { dynamic_config, mesh_id, authority_id, private_key, certificate } => {
            let database = std::env::var("PEERWARD_DATABASE_URL").map_err(|_| CliError::invalid("PEERWARD_DATABASE_URL is required"))?;
            peerward_control::import_managed_authority(&dynamic_config, mesh_id, authority_id, &private_key, &certificate, &database).await
                .map_err(|_| CliError::invalid("Authority import failed; check staged certificate, Mesh state, and private file permissions"))?;
            println!("Authority imported; Control reloads within five seconds. Activate through the API after reload.");
            Ok(())
        }
        BootstrapCommand::RecoveryOpen { package, mesh_id, root_public, recovery_key, output } => {
            if output.exists() { return Err(CliError::invalid("recovery destination already exists")); }
            let expected = hex::decode(root_public).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| CliError::invalid("invalid root public key"))?;
            validate_private_permissions(&recovery_key)?;
            let key = Zeroizing::new(read_hex_32(&recovery_key)?);
            let bytes = peerward_credentials::private_files::read_private(&package, peerward_wire::ROOT_RECOVERY_LEN as u64)
                .map_err(|_| CliError::invalid("cannot read recovery package"))?;
            let root = peerward_wire::open_root_recovery(&bytes, mesh_id, &expected, &key)
                .map_err(|_| CliError::auth("recovery package verification failed"))?;
            let encoded = Zeroizing::new(hex::encode(root.as_ref()));
            peerward_credentials::private_files::write_private_atomic(&output, encoded.as_bytes())
                .map_err(|_| CliError::failure("cannot write recovered root"))?;
            println!("Verified root written to {}", output.display());
            Ok(())
        }
        BootstrapCommand::CertifyAuthority { root_key, mesh_id, authority_public, output, validity_days } => {
            if output.exists() || validity_days==0 || validity_days>3650 { return Err(CliError::invalid("invalid certificate output or lifetime")); }
            validate_private_permissions(&root_key)?;
            let seed = Zeroizing::new(read_hex_32(&root_key)?);
            let root = RootSigningKey::from_bytes(&seed);
            let public = hex::decode(authority_public).ok().and_then(|v| v.try_into().ok()).ok_or_else(|| CliError::invalid("invalid Authority public key"))?;
            let now = current_unix_time()?;
            let certificate = root.certify(UnsignedAuthority { mesh_id, serial: CredentialSerial::new(), public_key: public,
                not_before: UnixTime(now.saturating_sub(60)), not_after: UnixTime(now+u64::from(validity_days)*86400) })
                .map_err(|_| CliError::invalid("invalid Authority certificate"))?;
            peerward_credentials::private_files::write_private_atomic(&output, &certificate.encode())
                .map_err(|_| CliError::failure("cannot write Authority certificate"))?;
            Ok(())
        }
        BootstrapCommand::Generate {
            output_dir,
            peer_endpoint,
            backbone_endpoint,
            mesh,
        } => generate_bootstrap(&output_dir, &peer_endpoint, &backbone_endpoint, mesh),
        BootstrapCommand::Initialize {
            database_url,
            manifest,
            complete_empty_mesh,
        } => initialize_bootstrap(database_url.as_deref(), &manifest, complete_empty_mesh).await,
    }
}

fn generate_bootstrap(
    output_dir: &Path,
    peer_endpoints: &[String],
    backbone_endpoints: &[String],
    options: BootstrapMeshOptions,
) -> Result<(), CliError> {
    let (mesh_id, mesh) = options.resolve()?;
    let peer_endpoints = parse_bootstrap_endpoints(peer_endpoints, "peer")?;
    let backbone_endpoints = parse_bootstrap_endpoints(backbone_endpoints, "backbone")?;
    if peer_endpoints
        .iter()
        .any(|endpoint| backbone_endpoints.contains(endpoint))
    {
        return Err(CliError::invalid(
            "Relay peer and backbone endpoints must differ",
        ));
    }
    if output_dir.exists() {
        return Err(CliError::invalid(
            "bootstrap output directory already exists",
        ));
    }
    let parent = output_dir.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| {
        CliError::failure(format!("cannot create {}: {error}", parent.display()))
    })?;
    let temporary = parent.join(format!(".peerward-bootstrap-{}", Uuid::new_v4()));
    create_private_directory(&temporary)?;
    let result = write_bootstrap_bundle(
        &temporary,
        peer_endpoints,
        backbone_endpoints,
        mesh_id,
        mesh,
    );
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&temporary);
        return Err(error);
    }
    fs::rename(&temporary, output_dir).map_err(|error| {
        CliError::failure(format!(
            "cannot install bootstrap directory {}: {error}",
            output_dir.display()
        ))
    })?;
    println!("bootstrap bundle written to {}", output_dir.display());
    println!("offline Root private key: {}/root/root.key", output_dir.display());
    Ok(())
}

fn write_bootstrap_bundle(
    root_dir: &Path,
    peer_endpoints: Vec<NetworkEndpoint>,
    backbone_endpoints: Vec<NetworkEndpoint>,
    mesh_id: MeshId,
    mesh: NewMesh,
) -> Result<(), CliError> {
    let now = current_unix_time()?;
    let not_before = UnixTime(now.saturating_sub(60));
    let authority_not_after = UnixTime(now.saturating_add(365 * 24 * 60 * 60));
    let relay_not_after = UnixTime(now.saturating_add(30 * 24 * 60 * 60));
    let authority_id = Uuid::new_v4();
    let relay_id = RelayId::new();
    let relay_credential_id = Uuid::new_v4();

    let root = RootSigningKey::generate();
    let authority = AuthoritySigningKey::generate();
    let authority_certificate = root
        .certify(UnsignedAuthority {
            mesh_id,
            serial: CredentialSerial::new(),
            public_key: authority.public_key(),
            not_before,
            not_after: authority_not_after,
        })
        .map_err(|_| CliError::failure("cannot certify initial Authority"))?;

    let mut directory_seed = Zeroizing::new([0_u8; 32]);
    let mut service_seed = Zeroizing::new([0_u8; 32]);
    let mut audit_seed = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(directory_seed.as_mut());
    OsRng.fill_bytes(service_seed.as_mut());
    OsRng.fill_bytes(audit_seed.as_mut());
    let directory = DirectorySigningKey::from_bytes(&directory_seed);
    let services = ServiceSnapshotSigningKey::from_bytes(&service_seed);
    let distribution = authority.certify_distribution(
        mesh_id,
        directory.public_key().to_bytes(),
        services.verifier().to_bytes(),
        peerward_wire::audit_recipient_public(&audit_seed),
    );

    let relay_private = StaticSecret::random_from_rng(OsRng);
    let relay_private_bytes = Zeroizing::new(relay_private.to_bytes());
    let relay_public = NoisePublicKey::from(&relay_private).to_bytes();
    let relay_credential = authority
        .issue(UnsignedSubject {
            subject: SubjectId::Relay(relay_id),
            mesh_id,
            identity_public_key: [0; 32],
            public_noise_key: relay_public,
            wireguard_public_key: [0; 32],
            serial: CredentialSerial::new(),
            not_before,
            not_after: relay_not_after,
        })
        .map_err(|_| CliError::failure("cannot issue initial Relay credential"))?;

    let manifest = BootstrapManifest {
        schema_version: 1,
        mesh_id,
        mesh,
        root_public_key: hex::encode(root.public_key().to_bytes()),
        authority_id,
        authority_certificate: URL_SAFE_NO_PAD.encode(authority_certificate.encode()),
        relay_id,
        relay_name: "relay-1".into(),
        relay_peer_endpoints: peer_endpoints,
        relay_backbone_endpoints: backbone_endpoints,
        relay_credential_id,
        relay_credential: URL_SAFE_NO_PAD.encode(relay_credential.encode()),
    };

    create_private_directory(&root_dir.join("root"))?;
    create_private_directory(&root_dir.join("control"))?;
    create_private_directory(&root_dir.join("control/authority-keys"))?;
    create_private_directory(
        &root_dir
            .join("control/authority-keys")
            .join(mesh_id.to_string()),
    )?;
    create_private_directory(&root_dir.join("relay"))?;
    create_private_directory(&root_dir.join("relay/identity"))?;
    bootstrap_write(
        &root_dir.join("root/root.key"),
        format!("{}\n", hex::encode(root.to_bytes())).as_bytes(),
        true,
    )?;
    bootstrap_write(
        &root_dir.join("root/root.pub"),
        format!("{}\n", manifest.root_public_key).as_bytes(),
        false,
    )?;
    let authority_document = authority_document(&authority_certificate);
    bootstrap_write(
        &root_dir.join("relay/identity/root.pub"),
        format!("{}\n", manifest.root_public_key).as_bytes(),
        false,
    )?;
    bootstrap_write(
        &root_dir.join("relay/identity/authority.cert"),
        authority_document.as_bytes(),
        false,
    )?;
    bootstrap_write(
        &root_dir.join("relay/identity/distribution.cert"),
        &distribution.encode(),
        false,
    )?;
    bootstrap_write(
        &root_dir.join("relay/identity/relay.credential"),
        &relay_credential.encode(),
        false,
    )?;
    bootstrap_write(
        &root_dir.join("relay/identity/noise.key"),
        format!("{}\n", hex::encode(relay_private_bytes.as_ref())).as_bytes(),
        true,
    )?;
    bootstrap_write(
        &root_dir
            .join("control/authority-keys")
            .join(mesh_id.to_string())
            .join(format!("{authority_id}.key")),
        format!("{}\n", hex::encode(authority.to_bytes())).as_bytes(),
        true,
    )?;

    let control = format!(
        "config_version = 1\nhttp_address = \"0.0.0.0:8080\"\nmax_connections = 16\nauthority_key_directory = \"/etc/peerward/authority-keys\"\n\n[[join_issuers]]\nmesh_id = \"{mesh_id}\"\nauthority_id = \"{authority_id}\"\nroot_public_key = \"{}\"\nauthority_certificate = \"{}\"\ndirectory_private_key = \"{}\"\nservice_private_key = \"{}\"\naudit_private_key = \"{}\"\ncredential_validity_seconds = 86400\n",
        manifest.root_public_key,
        manifest.authority_certificate,
        hex::encode(directory_seed.as_ref()),
        hex::encode(service_seed.as_ref()),
        hex::encode(audit_seed.as_ref()),
    );
    bootstrap_write(&root_dir.join("control/control.toml"), control.as_bytes(), true)?;
    let relay = format!(
        "config_version = 1\nrelay_id = \"{relay_id}\"\nmesh_id = \"{mesh_id}\"\npeer_address = \"0.0.0.0:7777\"\nbackbone_address = \"0.0.0.0:7778\"\nhealth_address = \"0.0.0.0:9090\"\nprivate_key_file = \"/var/lib/peerward/identity/noise.key\"\ncredential_file = \"/var/lib/peerward/identity/relay.credential\"\nroot_public_key_file = \"/var/lib/peerward/identity/root.pub\"\nauthority_certificate_file = \"/var/lib/peerward/identity/authority.cert\"\ndistribution_certificate_file = \"/var/lib/peerward/identity/distribution.cert\"\nqueue_capacity = 512\nlease_seconds = 30\nkeepalive_seconds = 10\n"
    );
    bootstrap_write(&root_dir.join("relay/relay.toml"), relay.as_bytes(), false)?;
    let manifest_document = toml::to_string_pretty(&manifest)
        .map_err(|_| CliError::failure("cannot encode bootstrap manifest"))?;
    bootstrap_write(
        &root_dir.join("initialize.toml"),
        manifest_document.as_bytes(),
        false,
    )?;
    let environment = bootstrap_environment();
    bootstrap_write(&root_dir.join(".env"), environment.as_bytes(), true)?;
    Ok(())
}

async fn initialize_bootstrap(
    database_url: Option<&str>,
    manifest_path: &Path,
    complete_empty_mesh: bool,
) -> Result<(), CliError> {
    let bytes = read_bounded_regular_file(manifest_path, 256 * 1024)?;
    let document = std::str::from_utf8(&bytes)
        .map_err(|_| CliError::invalid("bootstrap manifest must be UTF-8"))?;
    let manifest: BootstrapManifest = toml::from_str(document)
        .map_err(|_| CliError::invalid("invalid bootstrap manifest"))?;
    if manifest.schema_version != 1 {
        return Err(CliError::invalid(
            "unsupported bootstrap schema version",
        ));
    }
    let installation = verify_bootstrap_manifest(manifest)?;
    let environment = std::env::var("PEERWARD_DATABASE_URL").ok();
    let database_url = database_url
        .or(environment.as_deref())
        .ok_or_else(|| CliError::invalid("database URL is required"))?;
    let store = Store::connect(database_url, 2)
        .await
        .map_err(|_| CliError::unavailable("database is unavailable"))?;
    store
        .migrate()
        .await
        .map_err(|_| CliError::failure("database migration failed"))?;
    let created = if complete_empty_mesh {
        store.complete_empty_mesh_installation(&installation).await
    } else {
        store.initialize_installation(&installation).await
    }
    .map_err(|_| CliError::failure("bootstrap state conflicts with the database"))?;
    println!(
        "bootstrap database state {}",
        if created { "initialized" } else { "already current" }
    );
    Ok(())
}

fn verify_bootstrap_manifest(
    manifest: BootstrapManifest,
) -> Result<InitialInstallation, CliError> {
    let root_bytes = decode_hex_array(&manifest.root_public_key, "bootstrap Root public key")?;
    let root = RootPublicKey::from_bytes(&root_bytes)
        .map_err(|_| CliError::invalid("bootstrap Root public key is invalid"))?;
    let authority_bytes = URL_SAFE_NO_PAD
        .decode(&manifest.authority_certificate)
        .map_err(|_| CliError::invalid("bootstrap Authority certificate is not base64url"))?;
    let authority = AuthorityCertificate::decode(&authority_bytes)
        .map_err(|_| CliError::invalid("bootstrap Authority certificate is malformed"))?;
    let now = UnixTime(current_unix_time()?);
    root.verify_authority(&authority, manifest.mesh_id, now)
        .map_err(|_| CliError::auth("bootstrap Authority is not currently Root trusted"))?;
    let mut trust = TrustSet::new(root, manifest.mesh_id);
    trust
        .add_authority(authority.clone(), now)
        .map_err(|_| CliError::auth("bootstrap Authority trust installation failed"))?;
    let relay_bytes = URL_SAFE_NO_PAD
        .decode(&manifest.relay_credential)
        .map_err(|_| CliError::invalid("bootstrap Relay credential is not base64url"))?;
    let relay = SubjectCredential::decode(&relay_bytes)
        .map_err(|_| CliError::invalid("bootstrap Relay credential is malformed"))?;
    trust
        .verify_subject(&relay, now)
        .map_err(|_| CliError::auth("bootstrap Relay credential is not trusted"))?;
    if relay.subject != SubjectId::Relay(manifest.relay_id)
        || relay.mesh_id != manifest.mesh_id
    {
        return Err(CliError::invalid(
            "bootstrap Relay identity does not match the manifest",
        ));
    }
    Ok(InitialInstallation {
        mesh_id: manifest.mesh_id,
        mesh: manifest.mesh,
        authority: InitialAuthority {
            id: manifest.authority_id,
            serial: authority.serial,
            public_key: authority.public_key.to_vec(),
            not_before: offset_time(authority.not_before)?,
            not_after: offset_time(authority.not_after)?,
            certificate: authority_bytes,
        },
        relay: InitialRelay {
            id: manifest.relay_id,
            name: manifest.relay_name,
            peer_endpoints: manifest.relay_peer_endpoints,
            backbone_endpoints: manifest.relay_backbone_endpoints,
            credential_id: manifest.relay_credential_id,
            credential_serial: relay.serial,
            public_key: relay.public_noise_key.to_vec(),
            not_before: offset_time(relay.not_before)?,
            not_after: offset_time(relay.not_after)?,
            signature: relay.signature.to_vec(),
        },
    })
}

fn parse_bootstrap_endpoints(
    values: &[String],
    name: &str,
) -> Result<Vec<NetworkEndpoint>, CliError> {
    let endpoints = values
        .iter()
        .map(|value| {
            value
                .parse()
                .map_err(|_| CliError::invalid(format!("invalid Relay {name} endpoint")))
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_endpoint_list(&endpoints)
        .map_err(|_| CliError::invalid(format!("invalid Relay {name} endpoint list")))?;
    Ok(endpoints)
}

fn deserialize_bootstrap_endpoints<'de, D>(
    deserializer: D,
) -> Result<Vec<NetworkEndpoint>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Encoded {
        One(String),
        Many(Vec<String>),
    }
    let values = match Encoded::deserialize(deserializer)? {
        Encoded::One(value) => vec![value],
        Encoded::Many(values) => values,
    };
    values
        .into_iter()
        .map(|value| {
            let canonical = if value.contains("://") {
                value
            } else {
                format!("tcp://{value}")
            };
            canonical.parse().map_err(serde::de::Error::custom)
        })
        .collect()
}

fn current_unix_time() -> Result<u64, CliError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| CliError::failure("system clock is before the Unix epoch"))
}

fn offset_time(value: UnixTime) -> Result<time::OffsetDateTime, CliError> {
    i64::try_from(value.0)
        .ok()
        .and_then(|timestamp| time::OffsetDateTime::from_unix_timestamp(timestamp).ok())
        .ok_or_else(|| CliError::invalid("bootstrap validity is outside the supported range"))
}

fn authority_document(certificate: &AuthorityCertificate) -> String {
    format!(
        "schema_version = 1\nmesh_id = \"{}\"\nserial = \"{}\"\npublic_key = \"{}\"\nnot_before = {}\nnot_after = {}\nsignature = \"{}\"\n",
        certificate.mesh_id,
        certificate.serial,
        hex::encode(certificate.public_key),
        certificate.not_before.0,
        certificate.not_after.0,
        hex::encode(certificate.signature),
    )
}

fn bootstrap_environment() -> String {
    let mut password = [0_u8; 24];
    let mut development = [0_u8; 32];
    let mut bootstrap = [0_u8; 32];
    OsRng.fill_bytes(&mut password);
    OsRng.fill_bytes(&mut development);
    OsRng.fill_bytes(&mut bootstrap);
    let password = hex::encode(password);
    format!(
        "POSTGRES_DB=peerward\nPOSTGRES_USER=peerward\nPOSTGRES_PASSWORD={password}\nPEERWARD_DATABASE_URL=postgres://peerward:{password}@postgres:5432/peerward\nPEERWARD_DEV_BEARER={}\nPEERWARD_BOOTSTRAP_TOKEN={}\nPEERWARD_POSTGRES_PORT=5432\nPEERWARD_CONTROL_PORT=28080\nPEERWARD_CONSOLE_PORT=28081\n",
        URL_SAFE_NO_PAD.encode(development),
        URL_SAFE_NO_PAD.encode(bootstrap),
    )
}

fn create_private_directory(path: &Path) -> Result<(), CliError> {
    fs::create_dir(path).map_err(|error| {
        CliError::failure(format!("cannot create {}: {error}", path.display()))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|error| {
            CliError::failure(format!(
                "cannot protect directory {}: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
}

fn bootstrap_write(path: &Path, contents: &[u8], private: bool) -> Result<(), CliError> {
    write_new(path, contents, private)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = if private { 0o600 } else { 0o644 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|error| {
            CliError::failure(format!("cannot set permissions on {}: {error}", path.display()))
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod bootstrap_tests {
    use super::*;

    #[test]
    fn generated_bundle_is_self_verifying_and_keeps_root_offline() {
        let output = std::env::temp_dir().join(format!("peerward-bootstrap-{}", Uuid::new_v4()));
        generate_bootstrap(
            &output,
            &["tcp://127.0.0.1:7777".into()],
            &["tcp://127.0.0.1:7778".into()],
            BootstrapMeshOptions::default(),
        )
        .unwrap();
        let document = fs::read_to_string(output.join("initialize.toml")).unwrap();
        let manifest: BootstrapManifest = toml::from_str(&document).unwrap();
        let mesh_id = manifest.mesh_id;
        let authority_id = manifest.authority_id;
        let verified = verify_bootstrap_manifest(manifest).unwrap();
        assert_eq!(verified.relay.name, "relay-1");
        assert_eq!(verified.relay.peer_endpoints.len(), 1);
        let control = fs::read_to_string(output.join("control/control.toml")).unwrap();
        assert!(!control.contains("root/root.key"));
        assert!(!control.contains("authority_private_key"));
        let authority_key = output
            .join("control/authority-keys")
            .join(mesh_id.to_string())
            .join(format!("{authority_id}.key"));
        assert!(authority_key.is_file());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(authority_key).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let relay = fs::read_to_string(output.join("relay/relay.toml")).unwrap();
        assert!(!relay.contains("root.key"));
        fs::remove_dir_all(output).unwrap();
    }

    #[test]
    fn bootstrap_manifest_is_a_bounded_regular_file() {
        let directory =
            std::env::temp_dir().join(format!("peerward-bootstrap-input-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("initialize.toml");
        fs::File::create(&path)
            .unwrap()
            .set_len(256 * 1024 + 1)
            .unwrap();
        assert!(read_bounded_regular_file(&path, 256 * 1024).is_err());
        assert!(read_bounded_regular_file(&directory, 256 * 1024).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}

include!("bootstrap_option_tests.rs");
