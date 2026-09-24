/// Query the existing protected API as the daemon UID. The updater remains root;
/// only a fixed `health` subprocess drops privilege, with an empty environment.
async fn peer_update_health(binary: &Path, url: &Url) -> bool {
    let Some(pid) = update_role_pid(UpdateRole::Peer).await else {
        return false;
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        peer_socket_health(binary, url, pid),
    )
    .await
    .unwrap_or(false)
}

async fn peer_socket_health(binary: &Path, url: &Url, pid: u32) -> bool {
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _};
    use tokio::io::AsyncReadExt as _;
    if !role_health_url_valid(UpdateRole::Peer, url) {
        return false;
    }
    let Some(path) = Url::parse(&format!("file://{}", url.path()))
        .ok()
        .and_then(|value| value.to_file_path().ok())
    else {
        return false;
    };
    let (Ok(socket), Ok(process), Ok(own)) = (
        fs::symlink_metadata(&path),
        fs::metadata(format!("/proc/{pid}")),
        fs::metadata("/proc/self"),
    ) else {
        return false;
    };
    if !socket.file_type().is_socket()
        || socket.uid() != process.uid()
        || socket.mode() & 0o007 != 0
        || !same_executable(&PathBuf::from(format!("/proc/{pid}/exe")), binary)
    {
        return false;
    }
    // SO_PEERCRED pins the socket to the same process whose executable we checked.
    let Ok(stream) = tokio::net::UnixStream::connect(&path).await else {
        return false;
    };
    if !stream.peer_cred().is_ok_and(|cred| {
        cred.pid().and_then(|id| u32::try_from(id).ok()) == Some(pid) && cred.uid() == process.uid()
    }) {
        return false;
    }
    drop(stream);
    let mut command = tokio::process::Command::new(binary);
    command
        .arg("health")
        .env_clear()
        .env("PEERWARD_PEER_SOCKET", &path)
        .current_dir("/")
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    if own.uid() == 0 {
        // Rust's uid setter also removes supplementary groups before exec.
        command.uid(process.uid()).gid(process.gid());
    } else if own.uid() != process.uid() {
        return false;
    }
    let Ok(mut child) = command.spawn() else {
        return false;
    };
    let Some(output) = child.stdout.take() else {
        return false;
    };
    let mut bytes = Vec::new();
    if output.take(65_537).read_to_end(&mut bytes).await.is_err() || bytes.len() > 65_536 {
        let _ = child.kill().await;
        return false;
    }
    if !child.wait().await.is_ok_and(|status| status.success()) {
        return false;
    }
    serde_json::from_slice::<serde_json::Value>(&bytes).is_ok_and(|value| {
        value.get("status").and_then(serde_json::Value::as_str) == Some("ok")
            && ["tun_up", "tasks_alive", "signed_state_complete"]
                .iter()
                .all(|key| value.get(key).and_then(serde_json::Value::as_bool) == Some(true))
    })
}
