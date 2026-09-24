fn persist_join_profile(
    output_dir: &Path,
    response: &JoinResponse,
    verified: &VerifiedJoinResponse,
    identity_private_key: &[u8; 32],
    session_private_key: &[u8; 32],
    wireguard_private_key: &[u8; 32],
) -> Result<(), CliError> {
    let parent = output_dir
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| CliError::failure(format!("cannot create profile parent: {error}")))?;
    let staging = parent.join(format!(".peerward-profile-{}", Uuid::new_v4()));
    fs::create_dir(&staging)
        .map_err(|error| CliError::failure(format!("cannot create profile staging: {error}")))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&staging, fs::Permissions::from_mode(0o700)).map_err(|error| {
            CliError::failure(format!("cannot secure profile staging: {error}"))
        })?;
    }
    let result = (|| {
        write_profile_file(
            &staging.join("peer.key"),
            format!("{}\n", hex::encode(session_private_key)).as_bytes(),
            true,
        )?;
        write_profile_file(
            &staging.join("peer.identity.key"),
            format!("{}\n", hex::encode(identity_private_key)).as_bytes(),
            true,
        )?;
        write_profile_file(&staging.join("peer.credential"), &verified.credential, true)?;
        let encoded_wireguard = Zeroizing::new(format!("{}\n", hex::encode(wireguard_private_key)));
        write_profile_file(
            &staging.join("peer.wireguard.key"),
            encoded_wireguard.as_bytes(),
            true,
        )?;
        write_profile_file(
            &staging.join("root.pub"),
            format!("{}\n", hex::encode(verified.root_public_key)).as_bytes(),
            false,
        )?;
        for (index, certificate) in verified.authority_certificates.iter().enumerate() {
            write_profile_file(
                &staging.join(format!("authority-{index}.cert")),
                certificate,
                false,
            )?;
        }
        write_profile_file(
            &staging.join("distribution.cert"),
            &verified.distribution_certificate,
            false,
        )?;
        let mut profile = format!(
            "config_version = 4\nmesh_id = \"{}\"\npeer_id = \"{}\"\ncredential_file = \"peer.credential\"\nidentity_private_key_file = \"peer.identity.key\"\nprivate_key_file = \"peer.key\"\nwireguard_private_key_file = \"peer.wireguard.key\"\nroot_public_key_file = \"root.pub\"\ndistribution_certificate_file = \"distribution.cert\"\nauthority_certificate_files = [{}]\ndistribution_public_key = \"{}\"\nservice_distribution_public_key = \"{}\"\naudit_public_key = \"{}\"\n# Assigned address: {}\n# Mesh DNS suffix: {}\n",
            response.mesh_id,
            response.peer_id,
            (0..verified.authority_certificates.len())
                .map(|index| format!("\"authority-{index}.cert\""))
                .collect::<Vec<_>>()
                .join(", "),
            hex::encode(verified.directory_public_key),
            hex::encode(verified.service_public_key),
            hex::encode(verified.audit_public_key),
            response.address,
            response.dns_suffix,
        );
        if !verified.stun_servers.is_empty() {
            use std::fmt::Write as _;
            writeln!(
                profile,
                "\nstun_servers = [{}]",
                verified
                    .stun_servers
                    .iter()
                    .map(|server| format!("\"{server}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .map_err(|_| CliError::failure("cannot encode STUN profile"))?;
        }
        for (relay_id, endpoints, public_key) in &verified.relays {
            use std::fmt::Write as _;
            write!(
                profile,
                "\n[[relays]]\nrelay_id = \"{relay_id}\"\nendpoints = [{}]\npublic_key = \"{}\"\n",
                endpoints
                    .iter()
                    .map(|endpoint| format!("\"{endpoint}\""))
                    .collect::<Vec<_>>()
                    .join(", "),
                hex::encode(public_key)
            )
            .map_err(|_| CliError::failure("cannot encode peer profile"))?;
        }
        {
            use std::fmt::Write as _;
            writeln!(
                profile,
                "\n[linux]\ninterface = \"pwd0\"\naddress = \"{}\"\nroutes = [{}]\ndns_suffix = \"{}\"\ndns_server = \"{}\"\ndns_backend = \"auto\"\nmtu = {}\npacket_state_limit = 65536\npacket_state_shards = 16",
                verified.address,
                verified
                    .routes
                    .iter()
                    .map(|route| format!("\"{route}\""))
                    .collect::<Vec<_>>()
                    .join(", "),
                response.dns_suffix,
                verified.dns_server,
                verified.mtu,
            )
            .map_err(|_| CliError::failure("cannot encode Linux profile"))?;
        }
        if let Some(address) = verified.secondary_address {
            use std::fmt::Write as _;
            writeln!(profile, "secondary_address = \"{address}\"")
                .map_err(|_| CliError::failure("cannot encode secondary address"))?;
        }
        write_profile_file(&staging.join("peer.toml"), profile.as_bytes(), false)?;
        fs::rename(&staging, output_dir)
            .map_err(|error| CliError::failure(format!("cannot commit profile: {error}")))?;
        Ok(())
    })();
    if result.is_err() && staging.exists() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

fn write_profile_file(path: &Path, contents: &[u8], private: bool) -> Result<(), CliError> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options
        .open(path)
        .map_err(|error| CliError::failure(format!("cannot create {}: {error}", path.display())))?;
    file.write_all(contents)
        .and_then(|()| file.sync_all())
        .map_err(|error| CliError::failure(format!("cannot write {}: {error}", path.display())))
}

#[cfg(unix)]
fn validate_private_permissions(path: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)
        .map_err(|error| CliError::invalid(format!("cannot inspect {}: {error}", path.display())))?
        .permissions()
        .mode();
    if mode & 0o077 != 0 {
        return Err(CliError::invalid(format!(
            "private key {} is readable by group or other users",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_permissions(_: &Path) -> Result<(), CliError> {
    Ok(())
}
