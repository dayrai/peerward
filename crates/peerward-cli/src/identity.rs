fn execute_identity(command: IdentityCommand) -> Result<(), CliError> {
    match command {
        IdentityCommand::Verify(args) => verify_identity(&args),
        IdentityCommand::Root(RootGroup {
            command: RootCommand::Generate(paths),
        }) => {
            let key = RootSigningKey::generate();
            let private = Zeroizing::new(key.to_bytes());
            write_keypair(&paths, private.as_ref(), &key.public_key().to_bytes())
        }
        IdentityCommand::Noise(NoiseGroup {
            command: NoiseCommand::Generate(paths),
        }) => {
            let params = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
                .parse()
                .map_err(|_| CliError::failure("Noise suite initialization failed"))?;
            let pair = Builder::new(params)
                .generate_keypair()
                .map_err(|_| CliError::failure("Noise key generation failed"))?;
            let private = Zeroizing::new(pair.private);
            write_keypair(&paths, private.as_ref(), &pair.public)
        }
        IdentityCommand::Authority(AuthorityGroup {
            command: AuthorityCommand::Generate(paths),
        }) => {
            let key = AuthoritySigningKey::generate();
            let private = Zeroizing::new(key.to_bytes());
            write_keypair(&paths, private.as_ref(), &key.public_key())
        }
        IdentityCommand::Authority(AuthorityGroup {
            command: AuthorityCommand::Issue(args),
        }) => issue_authority(&args),
    }
}

fn verify_identity(args: &IdentityVerifyArgs) -> Result<(), CliError> {
    let mesh_id =
        MeshId::from_uuid(args.mesh_id).map_err(|error| CliError::invalid(error.to_string()))?;
    let root = RootPublicKey::from_bytes(&read_hex_32(&args.root_public)?)
        .map_err(|_| CliError::invalid("invalid Root public key"))?;
    let now = UnixTime(current_unix_time()?);
    let mut trust = TrustSet::new(root, mesh_id);
    for path in &args.authority_certificates {
        let certificate = read_authority_certificate(path)?;
        trust
            .add_authority(certificate, now)
            .map_err(|_| CliError::auth("Authority certificate is not currently Root trusted"))?;
    }
    for path in &args.credentials {
        let bytes = read_bounded_regular_file(path, 65_536)?;
        let credential = SubjectCredential::decode(&bytes)
            .map_err(|_| CliError::invalid("subject credential is malformed"))?;
        trust
            .verify_subject(&credential, now)
            .map_err(|_| CliError::auth("subject credential is not currently Authority trusted"))?;
    }
    if let Some(path) = &args.distribution_certificate {
        let bytes = read_bounded_regular_file(path, 65_536)?;
        let certificate = DistributionCertificate::decode(&bytes)
            .map_err(|_| CliError::invalid("distribution certificate is malformed"))?;
        trust.verify_distribution(&certificate, now).map_err(|_| {
            CliError::auth("distribution certificate is not currently Authority trusted")
        })?;
    }
    println!("identity chain verified for Mesh {mesh_id}");
    Ok(())
}

fn issue_authority(args: &AuthorityIssueArgs) -> Result<(), CliError> {
    validate_private_permissions(&args.root_private)?;
    let root_bytes = Zeroizing::new(read_hex_32(&args.root_private)?);
    let authority_public = read_hex_32(&args.authority_public)?;
    let mesh_id =
        MeshId::from_uuid(args.mesh_id).map_err(|error| CliError::invalid(error.to_string()))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| CliError::failure("system clock is before the Unix epoch"))?
        .as_secs();
    let root = RootSigningKey::from_bytes(&root_bytes);
    let certificate = root
        .certify(UnsignedAuthority {
            mesh_id,
            serial: CredentialSerial::new(),
            public_key: authority_public,
            not_before: UnixTime(now),
            not_after: UnixTime(now.saturating_add(31_536_000)),
        })
        .map_err(|error| CliError::invalid(error.to_string()))?;
    let document = format!(
        "schema_version = 1\nmesh_id = \"{}\"\nserial = \"{}\"\npublic_key = \"{}\"\nnot_before = {}\nnot_after = {}\nsignature = \"{}\"\n",
        certificate.mesh_id,
        certificate.serial,
        hex::encode(certificate.public_key),
        certificate.not_before.0,
        certificate.not_after.0,
        hex::encode(certificate.signature),
    );
    write_new(&args.output, document.as_bytes(), false)
}

fn write_keypair(paths: &KeyOutputArgs, private: &[u8], public: &[u8]) -> Result<(), CliError> {
    write_new(
        &paths.private,
        format!("{}\n", hex::encode(private)).as_bytes(),
        true,
    )?;
    if let Err(error) = write_new(
        &paths.public,
        format!("{}\n", hex::encode(public)).as_bytes(),
        false,
    ) {
        let _ = fs::remove_file(&paths.private);
        return Err(error);
    }
    Ok(())
}

fn write_new(path: &Path, contents: &[u8], private: bool) -> Result<(), CliError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| CliError::failure(format!("cannot create {}: {error}", path.display())))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| CliError::failure(format!("cannot write {}: {error}", path.display())))
}

fn read_hex_32(path: &Path) -> Result<[u8; 32], CliError> {
    let text = read_bounded_utf8(path, 1024)?;
    let decoded = hex::decode(text.trim())
        .map_err(|_| CliError::invalid(format!("{} is not a hex key", path.display())))?;
    decoded
        .try_into()
        .map_err(|_| CliError::invalid(format!("{} must contain 32 key bytes", path.display())))
}

use peerward_api::{JoinClaimRequest, JoinResponse};

struct ParsedJoinBundle {
    claim_url: Url,
    token: String,
    mesh_id: MeshId,
    root_pin: RootPin,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RootPin {
    PublicKey([u8; 32]),
    Fingerprint([u8; 32]),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EncodedJoinBundle {
    claim_url: String,
    root_fingerprint: String,
    expires_at: u64,
    nonce: String,
    mesh_id: Option<String>,
}

async fn accept_join(bundle: &str, output_dir: &Path) -> Result<(), CliError> {
    let (pending_file, mut pending) = PendingEnrollmentFile::open(output_dir)?;
    let invitation_digest: [u8; 32] = Sha256::digest(bundle.as_bytes()).into();
    if pending
        .invitation_digest
        .is_some_and(|digest| digest != invitation_digest)
    {
        return Err(CliError::invalid(
            "this output directory has a pending claim for a different invitation",
        ));
    }
    let bundle = parse_join_bundle_for_resume(bundle, pending.request.is_some())?;
    let session_private_bytes = Zeroizing::new(pending.session_private);
    let wireguard_private_bytes = Zeroizing::new(pending.wireguard_private);
    let identity_private_bytes = Zeroizing::new(pending.identity_private);
    let session_public =
        NoisePublicKey::from(&StaticSecret::from(*session_private_bytes)).to_bytes();
    let wireguard_public =
        NoisePublicKey::from(&StaticSecret::from(*wireguard_private_bytes)).to_bytes();
    let identity_public = IdentitySigningKey::from_bytes(&identity_private_bytes)
        .verifying_key()
        .to_bytes();
    let mut nonce = [0_u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let ticket = URL_SAFE_NO_PAD
        .decode(&bundle.token)
        .map_err(|_| CliError::invalid("join token is invalid"))?;
    let claim_id = Uuid::new_v4();
    let client_version = env!("CARGO_PKG_VERSION").to_owned();
    let device_name = "peerward-device".to_owned();
    let device_model = std::env::consts::ARCH.to_owned();
    let platform = std::env::consts::OS.to_owned();
    let platform_version = "unknown".to_owned();
    let proof = JoinClaimProof {
        schema_version: 2,
        claim_id,
        ticket_digest: secret_digest(&ticket),
        identity_public_key: identity_public,
        session_public_key: session_public,
        wireguard_public_key: wireguard_public,
        client_version: &client_version,
        supported_wire_major: peerward_wire::PROTOCOL_MAJOR,
        nonce: &nonce,
        device_name: &device_name,
        device_model: &device_model,
        platform: &platform,
        platform_version: &platform_version,
    };
    let signature = sign_join_claim(&identity_private_bytes, &proof)
        .map_err(|_| CliError::failure("cannot sign Join claim"))?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|_| CliError::failure("cannot initialize join HTTP client"))?;
    if pending.request.is_none() {
        pending.invitation_digest = Some(invitation_digest);
        pending.request = Some(JoinClaimRequest {
            schema_version: 2,
            claim_id,
            identity_public_key: URL_SAFE_NO_PAD.encode(identity_public),
            session_public_key: URL_SAFE_NO_PAD.encode(session_public),
            wireguard_public_key: URL_SAFE_NO_PAD.encode(wireguard_public),
            client_version,
            supported_wire_major: peerward_wire::PROTOCOL_MAJOR,
            device_name,
            device_model,
            platform,
            platform_version,
            nonce: URL_SAFE_NO_PAD.encode(nonce),
            signature: URL_SAFE_NO_PAD.encode(signature),
        });
        pending_file.save(&pending)?;
    }
    let response = submit_pending_claim(&client, &bundle, &pending).await?;
    let verified = verify_join_response(
        &bundle,
        &response,
        identity_public,
        session_public,
        wireguard_public,
    )?;
    persist_join_profile(
        output_dir,
        &response,
        &verified,
        &identity_private_bytes,
        &session_private_bytes,
        &wireguard_private_bytes,
    )?;
    pending_file.complete()?;
    println!(
        "joined mesh {} as peer {}; profile written to {}",
        response.mesh_id,
        response.peer_id,
        output_dir.display()
    );
    Ok(())
}

include!("join_parse.rs");

include!("join_pending.rs");
