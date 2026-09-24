fn update_error(error: peerward_updater::UpdateError) -> CliError {
    CliError::failure(error.to_string())
}

async fn check_update_database(role: UpdateRole, supplied: Option<&str>) -> Result<(), CliError> {
    if !matches!(role, UpdateRole::Control) {
        return Ok(());
    }
    let database = supplied
        .map(str::to_owned)
        .or_else(|| std::env::var("PEERWARD_DATABASE_URL").ok())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            CliError::invalid("Control recovery requires PEERWARD_DATABASE_URL or --database-url")
        })?;
    let check = async {
        let store = Store::connect(&database, 2)
            .await
            .map_err(|_| CliError::unavailable("database"))?;
        if !store.ready().await {
            return Err(CliError::unavailable("database"));
        }
        Ok(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), check)
        .await
        .map_err(|_| CliError::unavailable("database"))?
}

async fn restart_role(role: UpdateRole) -> bool {
    tokio::time::timeout(
        std::time::Duration::from_mins(1),
        tokio::process::Command::new("systemctl")
            .kill_on_drop(true)
            .args(["restart", &format!("peerward-{}.service", role.name())])
            .status(),
    )
    .await
    .is_ok_and(|result| result.is_ok_and(|status| status.success()))
}

async fn wait_for_role_health(role: UpdateRole, binary: &Path, url: &Url) -> bool {
    if !update_health_url_valid(url) {
        return false;
    }
    let Ok(client) = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(2))
        .build()
    else {
        return false;
    };
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        loop {
            let healthy = if url.scheme() == "unix" {
                peer_update_health(binary, url).await
            } else {
                client
                    .get(url.clone())
                    .send()
                    .await
                    .is_ok_and(|response| response.status().is_success())
            };
            if healthy && updated_role_is_running(role, binary).await {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    })
    .await
    .unwrap_or(false)
}

/// A restart is always preceded by durable intent. No database password enters
/// the journal, and recovery never needs to download or re-accept a manifest.
async fn run_update_transaction(
    root: &Path,
    role: UpdateRole,
    record: &mut UpdateTransaction,
) -> Result<(), CliError> {
    let url = Url::parse(record.health_url())
        .map_err(|_| CliError::invalid("recorded health URL is invalid"))?;
    if !role_health_url_valid(role, &url) || record.role() != role.name() {
        return Err(CliError::invalid("recorded update target is invalid"));
    }
    if record.is_terminal() {
        // A repeated completed operation must not restart or roll back a second time.
        record
            .activate(
                root,
                peerward_store::SCHEMA_VERSION,
                peerward_wire::PROTOCOL_MAJOR,
            )
            .map_err(update_error)?;
        return Ok(());
    }
    for attempt in 0..2 {
        let current = match record.activate(
            root,
            peerward_store::SCHEMA_VERSION,
            peerward_wire::PROTOCOL_MAJOR,
        ) {
            Ok(current) => current,
            Err(error) => {
                record.record_failure(root).map_err(update_error)?;
                return Err(update_error(error));
            }
        };
        if restart_role(role).await && wait_for_role_health(role, &current, &url).await {
            record.record_ready(root).map_err(update_error)?;
            return if attempt == 0 {
                Ok(())
            } else {
                Err(CliError::failure(
                    "updated role failed readiness; its recorded previous version was restored and checked",
                ))
            };
        }
        record.record_failure(root).map_err(update_error)?;
        if matches!(role, UpdateRole::Control) {
            return Err(CliError::failure(
                "Control readiness failed; the selected binary and database are retained for forward recovery. Inspect update status and service logs, then run update recover",
            ));
        }
        if record.direction() == UpdateDirection::Rollback {
            return Err(CliError::failure(
                "previous role readiness failed; recovery is required, run update status and inspect service logs",
            ));
        }
        record
            .request_rollback(
                root,
                peerward_store::SCHEMA_VERSION,
                peerward_wire::PROTOCOL_MAJOR,
            )
            .map_err(update_error)?;
    }
    Err(CliError::failure("update requires recovery"))
}
