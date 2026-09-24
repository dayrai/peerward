#[derive(Debug, Serialize)]
struct DiagnosticCheck {
    name: &'static str,
    ok: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
struct DiagnosticReport {
    status: &'static str,
    role: Option<&'static str>,
    checks: Vec<DiagnosticCheck>,
    local_status: Option<serde_json::Value>,
    local_metrics: Option<serde_json::Value>,
    secrets_redacted: bool,
}

enum DoctorConfig {
    Control(ControlConfig),
    Relay(RelayConfig),
    RelayHost(peerward_relay::RelayHostConfig),
    Peer(Box<PeerConfig>),
}

impl DoctorConfig {
    const fn role(&self) -> &'static str {
        match self {
            Self::Control(_) => "control",
            Self::Relay(_) | Self::RelayHost(_) => "relay",
            Self::Peer(_) => "peer",
        }
    }
}

async fn doctor(args: &DoctorArgs) -> Result<(), CliError> {
    let configuration = args.config.as_deref().map(read_doctor_config).transpose()?;
    let peer_required = matches!(configuration, Some(DoctorConfig::Peer(_)));
    let mut checks = Vec::new();
    push_bool(
        &mut checks,
        "tun_device",
        !peer_required || Path::new("/dev/net/tun").exists(),
        if peer_required {
            "/dev/net/tun must exist for a Linux Peer"
        } else {
            "not required for this role"
        },
    );
    push_bool(
        &mut checks,
        "ip_command",
        !peer_required || command_available("ip"),
        "Linux route and link management",
    );
    push_bool(
        &mut checks,
        "nft_command",
        !peer_required || command_available("nft"),
        "Linux atomic packet-filter management",
    );

    if let Some(config) = &configuration {
        match config {
            DoctorConfig::Control(config) => diagnose_control(config, &mut checks).await,
            DoctorConfig::Relay(config) => diagnose_relay(config, &mut checks).await,
            DoctorConfig::RelayHost(config) => {
                push_result(
                    &mut checks,
                    "relay_database",
                    check_database_online(config.database_url.as_deref())
                        .await
                        .map_err(|error| error.message),
                );
                push_result(
                    &mut checks,
                    "relay_peer_listener",
                    probe_tcp(config.peer_address).await,
                );
                push_result(
                    &mut checks,
                    "relay_backbone_listener",
                    probe_tcp(config.backbone_address).await,
                );
                push_bool(
                    &mut checks,
                    "relay_host_tls_files",
                    [
                        &config.ca_file,
                        &config.certificate_file,
                        &config.private_key_file,
                    ]
                    .iter()
                    .all(|path| path.is_file()),
                    "registered host certificate, key and trusted CA",
                );
            }
            DoctorConfig::Peer(config) => diagnose_peer(config, &mut checks).await,
        }
    }

    let control_url = args.control_url.clone().or_else(|| {
        std::env::var("PEERWARD_CONTROL_URL")
            .ok()
            .and_then(|value| Url::parse(&value).ok())
    });
    if let Some(url) = control_url {
        diagnose_control_endpoints(&url, &mut checks).await;
    }

    let management_socket = match &configuration {
        Some(DoctorConfig::Peer(config)) => config.management_socket.clone(),
        _ => peer_socket_path(),
    };
    let (local_status, local_metrics) = diagnose_local_peer(
        &management_socket,
        peer_required || management_socket.exists(),
        &mut checks,
    )
    .await;
    let status = if checks.iter().all(|check| check.ok) {
        "ok"
    } else {
        "degraded"
    };
    let report = DiagnosticReport {
        status,
        role: configuration.as_ref().map(DoctorConfig::role),
        checks,
        local_status,
        local_metrics,
        secrets_redacted: true,
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string(&report)
                .map_err(|_| CliError::failure("cannot encode diagnostic report"))?
        );
    } else {
        println!("Peerward diagnostics: {status}");
        for check in &report.checks {
            println!(
                "  {}: {} ({})",
                check.name,
                if check.ok { "ok" } else { "failed" },
                check.detail
            );
        }
        println!("  secrets: redacted");
    }
    Ok(())
}

async fn diagnose_control_endpoints(url: &Url, checks: &mut Vec<DiagnosticCheck>) {
    push_result(checks, "control_live", probe_http(url, "/livez").await);
    push_result(checks, "control_ready", probe_http(url, "/readyz").await);
}

fn read_doctor_config(path: &Path) -> Result<DoctorConfig, CliError> {
    let contents = read_bounded_utf8(path, 1024 * 1024)?;
    let first = contents
        .lines()
        .find(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'));
    if !matches!(
        first.map(str::trim),
        Some("config_version = 1" | "config_version = 2" | "config_version = 4")
    ) {
        return Err(CliError::invalid(
            "configuration must begin with a supported config_version",
        ));
    }
    if let Ok(config) = peerward_relay::RelayHostConfig::parse(
        &contents,
        path,
        std::env::var("PEERWARD_DATABASE_URL").ok(),
    ) {
        return Ok(DoctorConfig::RelayHost(config));
    }
    if let Ok(config) = PeerConfig::parse(&contents, path) {
        return Ok(DoctorConfig::Peer(Box::new(config)));
    }
    if let Ok(config) =
        RelayConfig::parse(&contents, path, std::env::var("PEERWARD_DATABASE_URL").ok())
    {
        return Ok(DoctorConfig::Relay(config));
    }
    ControlConfig::parse(&contents, std::env::var("PEERWARD_DATABASE_URL").ok())
        .map(DoctorConfig::Control)
        .map_err(|_| CliError::invalid("configuration does not match a Peerward role"))
}

async fn diagnose_control(config: &ControlConfig, checks: &mut Vec<DiagnosticCheck>) {
    let database = async {
        let url = config
            .database_url
            .as_deref()
            .ok_or_else(|| "database URL is missing".to_owned())?;
        let store = Store::connect(url, 2)
            .await
            .map_err(|_| "database connection failed".to_owned())?;
        if !store.ready().await {
            return Err("database readiness failed".to_owned());
        }
        peerward_control::check_authority_configuration(config, &store)
            .await
            .map_err(|_| "Authority key/database lifecycle mismatch".to_owned())
    }
    .await;
    push_result(checks, "control_database_authority", database);
    if let Some(oidc) = &config.oidc {
        push_result(
            checks,
            "oidc_discovery",
            peerward_control::check_oidc_provider(oidc)
                .await
                .map_err(|_| "OIDC discovery or metadata validation failed".to_owned()),
        );
    }
}

async fn diagnose_relay(config: &RelayConfig, checks: &mut Vec<DiagnosticCheck>) {
    push_result(
        checks,
        "relay_key_credential",
        check_subject_key(
            &config.private_key_file,
            &config.credential_file,
            config.mesh_id,
            SubjectId::Relay(config.relay_id),
        )
        .map_err(|error| error.message),
    );
    push_result(
        checks,
        "relay_database",
        check_database_online(config.database_url.as_deref())
            .await
            .map_err(|error| error.message),
    );
    push_result(
        checks,
        "relay_peer_listener",
        probe_tcp(config.peer_address).await,
    );
    push_result(
        checks,
        "relay_backbone_listener",
        probe_tcp(config.backbone_address).await,
    );
}

async fn diagnose_peer(config: &PeerConfig, checks: &mut Vec<DiagnosticCheck>) {
    let private = validate_private_permissions(&config.private_key_file)
        .and_then(|()| read_hex_32(&config.private_key_file))
        .map(Zeroizing::new);
    let credential = read_bounded_regular_file(&config.credential_file, 65_536)
        .map_err(|_| CliError::invalid("cannot read Peer credential"));
    let verified = match (&private, &credential) {
        (Ok(private), Ok(credential)) => verify_peer_trust(config, credential, private),
        (Err(error), _) | (_, Err(error)) => Err(CliError::invalid(error.message.clone())),
    };
    push_result(
        checks,
        "peer_key_trust",
        verified
            .as_ref()
            .map(|_| ())
            .map_err(|error| error.message.clone()),
    );
    if let (Ok(private), Ok(credential), Ok(trust)) = (&private, &credential, &verified) {
        for relay in &config.relays {
            let result =
                probe_peer_relay(config, relay, private, credential, Arc::clone(trust)).await;
            push_result(checks, "relay_noise", result);
        }
    }
    if let Some(linux) = &config.linux {
        push_result(
            checks,
            "tun_interface",
            command_status("ip", &["link", "show", "dev", &linux.interface]),
        );
        let destination = linux.dns_server.to_string();
        let family = if linux.dns_server.is_ipv6() {
            "-6"
        } else {
            "-4"
        };
        push_result(
            checks,
            "mesh_route",
            command_status("ip", &[family, "route", "get", &destination]),
        );
        let table = format!("peerward_{}", linux.interface.replace('-', "_"));
        push_result(
            checks,
            "nftables",
            command_status("nft", &["list", "table", "inet", &table]),
        );
        let dns_backend = match linux.dns_backend {
            peerward_peer::LinuxDnsBackend::Auto => {
                let resolved = command_status("resolvectl", &["status", &linux.interface]);
                if resolved.is_ok() {
                    resolved
                } else if let Some(profile) = linux.network_manager_connection.as_deref() {
                    command_status("nmcli", &["connection", "show", profile])
                } else {
                    command_status("resolvconf", &["-v"]).or_else(|_| {
                        std::fs::metadata(&linux.resolv_conf_path)
                            .map(|_| ())
                            .map_err(|error| error.to_string())
                    })
                }
            }
            peerward_peer::LinuxDnsBackend::SystemdResolved => {
                command_status("resolvectl", &["status", &linux.interface])
            }
            peerward_peer::LinuxDnsBackend::NetworkManager => linux
                .network_manager_connection
                .as_deref()
                .ok_or_else(|| "NetworkManager profile is missing".to_owned())
                .and_then(|profile| command_status("nmcli", &["connection", "show", profile])),
            peerward_peer::LinuxDnsBackend::OpenResolv => command_status("resolvconf", &["-v"]),
            peerward_peer::LinuxDnsBackend::ResolvConf => {
                std::fs::metadata(&linux.resolv_conf_path)
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
        };
        push_result(checks, "split_dns_backend", dns_backend);
        push_result(
            checks,
            "mesh_dns",
            probe_dns(
                std::net::SocketAddr::new(linux.dns_server, 53),
                &format!("doctor.{}", linux.dns_suffix.trim_end_matches('.')),
            )
            .await,
        );
    }
}

async fn probe_peer_relay(
    config: &PeerConfig,
    relay: &peerward_peer::RelayTarget,
    private: &[u8; 32],
    credential: &[u8],
    trust: Arc<TrustSet>,
) -> Result<(), String> {
    let remote: [u8; 32] = hex::decode(&relay.public_key)
        .map_err(|_| "Relay Noise key is invalid".to_owned())?
        .try_into()
        .map_err(|_| "Relay Noise key is invalid".to_owned())?;
    let connection = peerward_peer::probe_relay_endpoints_with_options(
        &relay.endpoints,
        private,
        &remote,
        relay.relay_id,
        config.mesh_id,
        &trust,
        UnixTime(current_unix_time().map_err(|_| "system clock is invalid".to_owned())?),
        peerward_wire::HandshakePayload {
            major: peerward_wire::PROTOCOL_MAJOR,
            minor: 0,
            capabilities: peerward_wire::SUPPORTED_CAPABILITIES
                | peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY,
            credential: credential.to_vec(),
            attachment_id: peerward_types::AttachmentId::new().as_bytes().to_vec(),
        },
        &config.relay_transport,
    );
    tokio::time::timeout(std::time::Duration::from_secs(3), connection)
        .await
        .map_err(|_| "Relay Noise handshake timed out".to_owned())?
        .map_err(|_| "Relay Noise authentication failed".to_owned())
}

async fn diagnose_local_peer(
    socket: &Path,
    required: bool,
    checks: &mut Vec<DiagnosticCheck>,
) -> (Option<serde_json::Value>, Option<serde_json::Value>) {
    if !socket.exists() {
        push_bool(
            checks,
            "local_peer_daemon",
            !required,
            if required {
                "management socket is missing"
            } else {
                "not running on this host"
            },
        );
        return (None, None);
    }
    let health = peerward_service::client(socket, &ServiceRequest::Health).await;
    let health_ok = health
        .as_ref()
        .is_ok_and(|response| response.ok && response.detail["status"].as_str() == Some("ok"));
    push_bool(
        checks,
        "local_peer_health",
        health_ok,
        "TUN, tasks, Relay attachments, and signed state",
    );
    let status = peerward_service::client(socket, &ServiceRequest::Status)
        .await
        .ok()
        .filter(|response| response.ok)
        .map(|response| response.detail);
    let metrics = peerward_service::client(socket, &ServiceRequest::Metrics)
        .await
        .ok()
        .filter(|response| response.ok)
        .map(|response| response.detail);
    (status, metrics)
}

async fn probe_http(base: &Url, path: &str) -> Result<(), String> {
    let url = base
        .join(path)
        .map_err(|_| "Control URL is invalid".to_owned())?;
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|_| "HTTP client initialization failed".to_owned())?
        .get(url)
        .send()
        .await
        .map_err(|_| "Control endpoint is unavailable".to_owned())?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("Control endpoint returned {}", response.status()))
    }
}

async fn probe_tcp(address: std::net::SocketAddr) -> Result<(), String> {
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::TcpStream::connect(address),
    )
    .await
    .map_err(|_| "TCP probe timed out".to_owned())?
    .map(|_| ())
    .map_err(|_| "TCP endpoint is unavailable".to_owned())
}

async fn probe_dns(server: std::net::SocketAddr, name: &str) -> Result<(), String> {
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(|_| "DNS probe socket failed".to_owned())?;
    socket
        .connect(server)
        .await
        .map_err(|_| "DNS endpoint is unreachable".to_owned())?;
    let transaction = [0x50, 0x57];
    let mut query = vec![transaction[0], transaction[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("DNS diagnostic name is invalid".to_owned());
        }
        query.push(u8::try_from(label.len()).map_err(|_| "DNS label is too long".to_owned())?);
        query.extend_from_slice(label.as_bytes());
    }
    query.extend_from_slice(&[0, 0, 1, 0, 1]);
    socket
        .send(&query)
        .await
        .map_err(|_| "DNS query send failed".to_owned())?;
    let mut response = [0_u8; 1_232];
    let size = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.recv(&mut response),
    )
    .await
    .map_err(|_| "DNS response timed out".to_owned())?
    .map_err(|_| "DNS response failed".to_owned())?;
    if size < 12 || response[..2] != transaction || response[2] & 0x80 == 0 {
        return Err("DNS response is malformed or mismatched".to_owned());
    }
    Ok(())
}

fn command_available(program: &str) -> bool {
    ProcessCommand::new(program)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success() || !output.stderr.is_empty())
}

fn command_status(program: &str, arguments: &[&str]) -> Result<(), String> {
    ProcessCommand::new(program)
        .args(arguments)
        .output()
        .map_err(|_| format!("{program} is unavailable"))
        .and_then(|output| {
            if output.status.success() {
                Ok(())
            } else {
                Err(format!("{program} check failed"))
            }
        })
}

fn push_result(checks: &mut Vec<DiagnosticCheck>, name: &'static str, result: Result<(), String>) {
    match result {
        Ok(()) => checks.push(DiagnosticCheck {
            name,
            ok: true,
            detail: "verified".into(),
        }),
        Err(detail) => checks.push(DiagnosticCheck {
            name,
            ok: false,
            detail,
        }),
    }
}

fn push_bool(checks: &mut Vec<DiagnosticCheck>, name: &'static str, ok: bool, detail: &str) {
    checks.push(DiagnosticCheck {
        name,
        ok,
        detail: detail.into(),
    });
}
