fn update_health_url_valid(url: &Url) -> bool {
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    (url.scheme() == "unix"
        && url.host().is_none()
        && url.path().starts_with('/')
        && url.path().len() > 1)
        || url.scheme() == "https"
        || (url.scheme() == "http"
            && url.host().is_some_and(|host| match host {
                url::Host::Ipv4(ip) => ip.is_loopback(),
                url::Host::Ipv6(ip) => ip.is_loopback(),
                url::Host::Domain(name) => name == "localhost",
            }))
}

fn validate_update_arguments(args: &UpdateApplyArgs) -> Result<(), CliError> {
    if args.installation_root.is_some() || args.role.is_some() {
        if args.install_path.is_some() || args.installation_root.is_none() || args.role.is_none() {
            return Err(CliError::invalid(
                "versioned updates require --installation-root and --role without --install-path",
            ));
        }
        if args
            .health_url
            .as_ref()
            .is_none_or(|url| !role_health_url_valid(args.role.expect("validated role"), url))
        {
            return Err(CliError::invalid(
                "versioned updates require Peer unix socket health or credential-free HTTPS/loopback role health",
            ));
        }
        if matches!(args.role, Some(UpdateRole::Console)) {
            return Err(CliError::invalid(
                "the unified binary cannot update Console; install its separately verified Console package",
            ));
        }
        if matches!(args.role, Some(UpdateRole::Control))
            && args.database_url.as_deref().is_none_or(str::is_empty)
            && std::env::var("PEERWARD_DATABASE_URL")
                .ok()
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err(CliError::invalid(
                "Control updates require a database URL before switching binaries",
            ));
        }
    } else if args.health_url.is_some()
        || args.database_url.is_some()
        || args.repair
        || args.preview_digest.is_some()
    {
        return Err(CliError::invalid(
            "health and database options require a versioned role update",
        ));
    }
    Ok(())
}

fn role_health_url_valid(role: UpdateRole, url: &Url) -> bool {
    update_health_url_valid(url) && (matches!(role, UpdateRole::Peer) == (url.scheme() == "unix"))
}
async fn updated_role_is_running(role: UpdateRole, binary: &Path) -> bool {
    update_role_pid(role)
        .await
        .is_some_and(|pid| same_executable(&PathBuf::from(format!("/proc/{pid}/exe")), binary))
}
async fn update_role_pid(role: UpdateRole) -> Option<u32> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::process::Command::new("systemctl")
            .kill_on_drop(true)
            .args([
                "show",
                &format!("peerward-{}.service", role.name()),
                "--property=MainPID",
                "--value",
            ])
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    if !output.status.success() {
        return None;
    }
    std::str::from_utf8(&output.stdout)
        .ok()?
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 1)
}

fn same_executable(running: &Path, selected: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let (Ok(running), Ok(selected)) = (fs::metadata(running), fs::metadata(selected)) else {
            return false;
        };
        running.is_file()
            && selected.is_file()
            && running.dev() == selected.dev()
            && running.ino() == selected.ino()
    }
    #[cfg(not(unix))]
    {
        let _ = (running, selected);
        false
    }
}

#[cfg(test)]
mod update_preflight_tests {
    use super::*;
    #[test]
    fn health_origins_and_process_ownership_are_explicit() {
        for value in [
            "http://127.0.0.1:9090/readyz",
            "http://[::1]:9090/readyz",
            "https://health.example/readyz",
        ] {
            assert!(update_health_url_valid(&Url::parse(value).unwrap()));
        }
        for value in [
            "http://public.example/readyz",
            "https://user:secret@example/readyz",
            "https://example/readyz?token=secret",
            "http://127.0.0.1/readyz#fragment",
        ] {
            assert!(!update_health_url_valid(&Url::parse(value).unwrap()));
        }
        assert!(same_executable(
            Path::new("/proc/self/exe"),
            &std::env::current_exe().unwrap()
        ));
        assert!(!same_executable(
            Path::new("/proc/self/exe"),
            Path::new("/etc/hosts")
        ));
    }
    #[tokio::test]
    async fn invalid_versioned_inputs_cannot_create_installation_state() {
        let root = std::env::temp_dir().join(format!(
            "peerward-update-preflight-{}",
            uuid::Uuid::new_v4()
        ));
        for (role, health) in [
            (None, None),
            (Some(UpdateRole::Relay), None),
            (
                Some(UpdateRole::Console),
                Some(Url::parse("http://127.0.0.1/readyz").unwrap()),
            ),
        ] {
            let result = execute_update(UpdateCommand::Apply(UpdateApplyArgs {
                source: UpdateSourceArgs {
                    manifest: "missing-manifest".into(),
                    signature: "missing-signature".into(),
                    public_key: root.join("key"),
                    channel: ReleaseChannel::Canary,
                    platform: None,
                    architecture: None,
                },
                preview_digest: None,
                repair: false,
                artifact_file: None,
                install_path: None,
                installation_root: Some(root.clone()),
                role,
                health_url: health,
                database_url: None,
            }))
            .await;
            assert!(result.is_err());
            assert!(!root.exists());
        }
    }
}
