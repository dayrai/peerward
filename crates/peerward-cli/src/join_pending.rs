#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingEnrollment {
    version: u32,
    identity_private: [u8; 32],
    session_private: [u8; 32],
    wireguard_private: [u8; 32],
    invitation_digest: Option<[u8; 32]>,
    request: Option<JoinClaimRequest>,
}
impl Drop for PendingEnrollment {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        self.identity_private.zeroize();
        self.session_private.zeroize();
        self.wireguard_private.zeroize();
    }
}
impl PendingEnrollment {
    fn new() -> Self {
        Self {
            version: 4,
            identity_private: IdentitySigningKey::generate(&mut OsRng).to_bytes(),
            session_private: StaticSecret::random_from_rng(OsRng).to_bytes(),
            wireguard_private: StaticSecret::random_from_rng(OsRng).to_bytes(),
            invitation_digest: None,
            request: None,
        }
    }
    fn fingerprint(&self) -> String {
        hex::encode(Sha256::digest(
            IdentitySigningKey::from_bytes(&self.identity_private)
                .verifying_key()
                .to_bytes(),
        ))
    }
}

/// A separate lock inode stays stable while state is atomically replaced. Both
/// files are confined to a private sibling directory, outside the final profile.
struct PendingEnrollmentFile {
    folder: PathBuf,
    _lock: std::fs::File,
}
impl PendingEnrollmentFile {
    fn open(output: &Path) -> Result<(Self, PendingEnrollment), CliError> {
        use std::io::Read as _;
        if output.exists() {
            return Err(CliError::invalid(
                "profile already exists; inspect it before starting another enrollment",
            ));
        }
        let parent = output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .map_err(|_| CliError::failure("cannot create enrollment parent"))?;
        let name = output
            .file_name()
            .ok_or_else(|| CliError::invalid("profile directory needs a name"))?;
        let mut pending_name = name.to_os_string();
        pending_name.push(".peerward-join");
        let folder = parent.join(pending_name);
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        match builder.create(&folder) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => {
                return Err(CliError::failure(
                    "cannot create pending enrollment directory",
                ));
            }
        }
        let metadata = fs::symlink_metadata(&folder)
            .map_err(|_| CliError::failure("cannot inspect pending enrollment"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(CliError::invalid(
                "pending enrollment must be a private directory",
            ));
        }
        ensure_join_private(&metadata)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let lock = options
            .open(folder.join("lock"))
            .map_err(|_| CliError::failure("cannot lock pending enrollment"))?;
        let metadata = lock
            .metadata()
            .map_err(|_| CliError::failure("cannot inspect enrollment lock"))?;
        if !metadata.is_file() {
            return Err(CliError::invalid("invalid enrollment lock"));
        }
        ensure_join_private(&metadata)?;
        lock.try_lock()
            .map_err(|_| CliError::failure("another process is using this pending enrollment"))?;
        let handle = Self {
            folder,
            _lock: lock,
        };
        let path = handle.folder.join("state.json");
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let state = match options.open(&path) {
            Ok(file) => {
                let metadata = file
                    .metadata()
                    .map_err(|_| CliError::failure("cannot inspect pending state"))?;
                if !metadata.is_file() || metadata.len() > 16 * 1024 {
                    return Err(CliError::invalid("invalid pending enrollment file"));
                }
                ensure_join_private(&metadata)?;
                let mut bytes = Zeroizing::new(Vec::new());
                file.take(16 * 1024 + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| CliError::failure("cannot read pending state"))?;
                let state:PendingEnrollment=serde_json::from_slice(&bytes).map_err(|_|CliError::invalid("pending enrollment is damaged; do not create replacement keys for the same invitation"))?;
                if state.version != 4
                    || state.invitation_digest.is_some() != state.request.is_some()
                {
                    return Err(CliError::invalid("incompatible pending enrollment"));
                }
                state
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let state = PendingEnrollment::new();
                handle.save(&state)?;
                state
            }
            Err(_) => return Err(CliError::failure("cannot open pending enrollment")),
        };
        Ok((handle, state))
    }
    fn save(&self, state: &PendingEnrollment) -> Result<(), CliError> {
        let bytes = Zeroizing::new(
            serde_json::to_vec(state)
                .map_err(|_| CliError::failure("cannot encode pending enrollment"))?,
        );
        let temporary = self.folder.join(format!("state-{}.tmp", Uuid::new_v4()));
        write_new(&temporary, &bytes, true)?;
        fs::rename(&temporary, self.folder.join("state.json"))
            .map_err(|_| CliError::failure("cannot persist pending enrollment"))?;
        std::fs::File::open(&self.folder)
            .and_then(|f| f.sync_all())
            .map_err(|_| CliError::failure("cannot sync pending enrollment"))
    }
    fn complete(self) -> Result<(), CliError> {
        fs::remove_file(self.folder.join("state.json")).map_err(|_| {
            CliError::failure("profile saved but pending private state needs cleanup")
        })?;
        // Keep the harmless lock inode; removing it could let a concurrent process
        // bypass an already-open lock. It contains no invitation or private key.
        std::fs::File::open(&self.folder)
            .and_then(|f| f.sync_all())
            .map_err(|_| CliError::failure("cannot sync enrollment cleanup"))
    }
}
fn ensure_join_private(metadata: &std::fs::Metadata) -> Result<(), CliError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(CliError::invalid(
                "pending enrollment must not be accessible to group or others",
            ));
        }
    }
    Ok(())
}

fn prepare_join(output: &Path) -> Result<(), CliError> {
    let (_handle, state) = PendingEnrollmentFile::open(output)?;
    println!("Ed25519 identity SHA-256: {}", state.fingerprint());
    println!(
        "Verify this fingerprint through a trusted channel. Use the same --output-dir when accepting the invitation."
    );
    Ok(())
}

async fn submit_pending_claim(
    client: &reqwest::Client,
    bundle: &ParsedJoinBundle,
    state: &PendingEnrollment,
) -> Result<JoinResponse, CliError> {
    let request = state
        .request
        .as_ref()
        .ok_or_else(|| CliError::failure("pending enrollment has no signed request"))?;
    if request.identity_public_key
        != URL_SAFE_NO_PAD.encode(
            IdentitySigningKey::from_bytes(&state.identity_private)
                .verifying_key()
                .to_bytes(),
        )
        || request.session_public_key
            != URL_SAFE_NO_PAD
                .encode(NoisePublicKey::from(&StaticSecret::from(state.session_private)).to_bytes())
        || request.wireguard_public_key
            != URL_SAFE_NO_PAD.encode(
                NoisePublicKey::from(&StaticSecret::from(state.wireguard_private)).to_bytes(),
            )
    {
        return Err(CliError::auth(
            "retained claim does not match retained device keys",
        ));
    }
    let mut deadline = None::<u64>;
    let started = std::time::Instant::now();
    loop {
        if started.elapsed() > std::time::Duration::from_mins(31)
            || deadline.is_some_and(|d| current_unix_time().map_or(true, |now| now >= d))
        {
            return Err(CliError::failure(
                "approval wait expired; pending keys were preserved, request a new invitation after checking the application",
            ));
        }
        let response=client.post(bundle.claim_url.clone()).json(request).send().await.map_err(|_|CliError::unavailable("join service unavailable; retry the same invitation and --output-dir to resume"))?;
        let status = response.status();
        if matches!(status.as_u16(), 401 | 403) {
            return Err(CliError::auth(
                "join ticket was rejected; pending keys were preserved",
            ));
        }
        if status == reqwest::StatusCode::ACCEPTED {
            let body = read_bounded_response(response, 16 * 1024, "pending join response").await?;
            let pending: peerward_management::PendingJoinResponse =
                serde_json::from_slice(&body)
                    .map_err(|_| CliError::failure("invalid approval response"))?;
            let application = &pending.application;
            if application.mesh_id != bundle.mesh_id
                || application.claim_id != request.claim_id
                || application.identity_fingerprint != state.fingerprint()
                || application.status != peerward_management::JoinApplicationStatus::Pending
                || application.expires_at <= application.created_at
                || application.expires_at - application.created_at > 1800
                || deadline.is_some_and(|d| d != application.expires_at)
            {
                return Err(CliError::auth(
                    "approval status does not match the original claim",
                ));
            }
            if deadline.is_none() {
                println!(
                    "Awaiting verification for application {}. Ed25519 identity SHA-256: {}. Keep this command running or resume with the same invitation and output directory.",
                    application.id,
                    state.fingerprint()
                );
            }
            deadline = Some(application.expires_at);
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            continue;
        }
        if !matches!(
            status,
            reqwest::StatusCode::CREATED | reqwest::StatusCode::OK
        ) {
            let body = read_bounded_response(response, 16 * 1024, "join failure").await?;
            let failure = serde_json::from_slice::<peerward_api::ErrorEnvelope>(&body).ok();
            let reason = match failure.as_ref().map(|e| e.error.code.as_str()) {
                Some("application_rejected") => {
                    "the administrator rejected this application; request a new invitation"
                }
                Some("application_cancelled") => {
                    "the invitation was cancelled; request a new invitation"
                }
                Some("application_expired") => {
                    "the approval deadline passed; request a new invitation"
                }
                Some("prebound_identity_mismatch") => {
                    "invitation fingerprint does not match these prepared keys; verify the intended device"
                }
                Some("state_conflict") => {
                    "the invitation is reserved or its state changed; ask the administrator to inspect its history"
                }
                _ => "check the invitation and service availability before retrying",
            };
            return Err(CliError::failure(format!(
                "join returned HTTP {}: {reason}; original keys and claim retained",
                status.as_u16()
            )));
        }
        let body = read_bounded_response(response, 1024 * 1024, "join response").await?;
        return serde_json::from_slice(&body)
            .map_err(|_| CliError::failure("join response is malformed"));
    }
}

#[cfg(test)]
#[path = "join_pending_tests.rs"]
mod join_pending_tests;
