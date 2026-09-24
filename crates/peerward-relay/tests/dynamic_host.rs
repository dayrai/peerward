//! Black-box test of an already running isolated Control/shared Relay installation.
//! Set `PEERWARD_DYNAMIC_TEST_DIR` to a generated /tmp/peerward-dynamic-* directory.
use base64::Engine as _;
use peerward_credentials::{AuthorityCertificate, RootPublicKey, SubjectCredential, TrustSet};
use peerward_peer::{
    NoiseRelayReceiver, NoiseRelaySender, OpaqueRelaySender, PacketReceiver, PeerConfig, PeerError,
    split_noise_relay,
};
use peerward_types::{AttachmentId, MeshId, UnixTime};
use peerward_wire::{
    ControlEnvelope, HandshakePayload, RelayEnvelopeV2, control_envelope::Message,
};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;

struct Lab {
    client: reqwest::Client,
    origin: String,
    bearer: String,
    directory: PathBuf,
}
impl Lab {
    async fn api(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<Value>,
        version: Option<u64>,
    ) -> (u16, Value) {
        let mut request = self
            .client
            .request(method, format!("{}/api/v1{path}", self.origin))
            .bearer_auth(&self.bearer);
        if let Some(body) = body {
            request = request.json(&body);
        }
        if let Some(version) = version {
            request = request.header("if-match", format!("\"{version}\""));
        }
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let bytes = response.bytes().await.unwrap();
        (
            status,
            if bytes.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&bytes).unwrap()
            },
        )
    }
    async fn create(&self, name: &str) -> Value {
        let (status, job) = self
            .api(
                reqwest::Method::POST,
                "/mesh-provisioning",
                Some(json!({"request_id":uuid::Uuid::new_v4(),"name":name})),
                None,
            )
            .await;
        assert_eq!(status, 202, "{job}");
        let end = tokio::time::Instant::now() + Duration::from_mins(2);
        loop {
            let (_, mesh) = self
                .api(
                    reqwest::Method::GET,
                    &format!("/meshes/{}", job["mesh_id"].as_str().unwrap()),
                    None,
                    None,
                )
                .await;
            if mesh["lifecycle"] == "active" {
                return mesh;
            }
            assert!(tokio::time::Instant::now() < end, "creation timed out");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
    async fn join(&self, mesh: &Value, label: &str) -> Profile {
        let id = mesh["id"].as_str().unwrap();
        let (status, ticket) = self
            .api(
                reqwest::Method::POST,
                &format!("/meshes/{id}/join-tickets"),
                Some(json!({"expires_in_seconds":300})),
                None,
            )
            .await;
        assert_eq!(status, 201);
        let encoding = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let bundle = json!({"claim_url":format!("{}/api/v1/join/{}/claim",self.origin,ticket["token"].as_str().unwrap()),
            "mesh_id":id,"root_fingerprint":ticket["root_fingerprint"],"expires_at":ticket["expires_at_unix"],"nonce":encoding.encode(uuid::Uuid::new_v4().as_bytes())});
        let profile = self
            .directory
            .join(format!("{label}-{}", uuid::Uuid::new_v4()));
        let binary = std::env::var_os("PEERWARD_TEST_BINARY").unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../target/debug/peerward")
                .into_os_string()
        });
        let output = std::process::Command::new(binary)
            .args([
                "join",
                "accept",
                &format!(
                    "peerward://join?bundle={}",
                    encoding.encode(serde_json::to_vec(&bundle).unwrap())
                ),
                "--output-dir",
            ])
            .arg(&profile)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "join failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Profile::load(&profile)
    }
    async fn delete(&self, mesh: &Value) -> String {
        let id = mesh["id"].as_str().unwrap();
        let (_, current) = self
            .api(reqwest::Method::GET, &format!("/meshes/{id}"), None, None)
            .await;
        let (status, job) = self
            .api(
                reqwest::Method::DELETE,
                &format!("/meshes/{id}"),
                Some(json!({"confirmation_name":mesh["name"]})),
                current["version"].as_u64(),
            )
            .await;
        assert_eq!(status, 202, "{job}");
        job["job_id"].as_str().unwrap().to_owned()
    }
    async fn wait_deleted(&self, job: &str) {
        let end = tokio::time::Instant::now() + Duration::from_mins(1);
        loop {
            let (_, state) = self
                .api(
                    reqwest::Method::GET,
                    &format!("/mesh-lifecycle/{job}"),
                    None,
                    None,
                )
                .await;
            if state["status"] == "succeeded" {
                return;
            }
            assert_ne!(state["status"], "failed", "{state}");
            assert!(tokio::time::Instant::now() < end, "deletion timed out");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}
struct Profile {
    config: PeerConfig,
    private: [u8; 32],
    credential: Vec<u8>,
    trust: TrustSet,
}
impl Profile {
    fn load(path: &Path) -> Self {
        let file = path.join("peer.toml");
        let mut config =
            PeerConfig::parse(&std::fs::read_to_string(&file).unwrap(), &file).unwrap();
        if let Some(ca) = std::env::var_os("PEERWARD_DYNAMIC_RELAY_CA") {
            config.relay_transport.ca_pem = Some(std::fs::read_to_string(ca).unwrap());
        }
        let read_key = |path: &Path| -> [u8; 32] {
            hex::decode(std::fs::read_to_string(path).unwrap().trim())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let root =
            RootPublicKey::from_bytes(&read_key(config.root_public_key_file.as_ref().unwrap()))
                .unwrap();
        let mut trust = TrustSet::new(root, config.mesh_id);
        for certificate in &config.authority_certificate_files {
            trust
                .add_authority(
                    AuthorityCertificate::decode(&std::fs::read(certificate).unwrap()).unwrap(),
                    now(),
                )
                .unwrap();
        }
        let private = read_key(&config.private_key_file);
        let credential = std::fs::read(&config.credential_file).unwrap();
        Self {
            config,
            private,
            credential,
            trust,
        }
    }
    async fn connect(&self) -> Result<Session, PeerError> {
        let target = &self.config.relays[0];
        let public: [u8; 32] = hex::decode(&target.public_key).unwrap().try_into().unwrap();
        let (socket, transport, _) = peerward_peer::connect_relay_endpoints_with_options(
            &target.endpoints,
            &self.private,
            &public,
            target.relay_id,
            self.config.mesh_id,
            &self.trust,
            now(),
            HandshakePayload {
                major: peerward_wire::PROTOCOL_MAJOR,
                minor: 0,
                capabilities: peerward_wire::SUPPORTED_CAPABILITIES
                    | peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY,
                credential: self.credential.clone(),
                attachment_id: AttachmentId::new().as_bytes().to_vec(),
            },
            &self.config.relay_transport,
        )
        .await?;
        let (sender, receiver) = mpsc::channel(64);
        let (writer, reader) = split_noise_relay(socket, transport, sender);
        Ok(Session(writer, reader, receiver))
    }
    async fn ready(&self) -> Session {
        let end = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            match self.connect().await {
                Ok(session) => return session,
                Err(error) => assert!(tokio::time::Instant::now() < end, "{error:?}"),
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}
struct Session(
    NoiseRelaySender,
    NoiseRelayReceiver,
    mpsc::Receiver<ControlEnvelope>,
);
impl Session {
    async fn matching<T>(&mut self, mut select: impl FnMut(ControlEnvelope) -> Option<T>) -> T {
        loop {
            tokio::select! {
                result=self.1.receive_packet()=>panic!("unexpected packet/end: {result:?}"),
                control=self.2.recv()=>if let Some(value)=select(control.unwrap()){return value;},
            }
        }
    }
    async fn opaque(&mut self) -> RelayEnvelopeV2 {
        tokio::time::timeout(
            Duration::from_secs(5),
            self.matching(|c| match c.message {
                Some(Message::Opaque(v)) => Some(v),
                _ => None,
            }),
        )
        .await
        .unwrap()
    }
}
fn now() -> UnixTime {
    UnixTime(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires an explicitly selected isolated dynamic installation"]
async fn deletion_preserves_other_mesh_socket_and_delivers_permanent_terminal() {
    let directory = PathBuf::from(
        std::env::var_os("PEERWARD_DYNAMIC_TEST_DIR").expect("isolated installation required"),
    );
    assert!(
        directory
            .to_string_lossy()
            .starts_with("/tmp/peerward-dynamic-")
            || directory.starts_with(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../artifacts/dynamic-mesh")
                    .canonicalize()
                    .unwrap()
            )
    );
    let environment = std::fs::read_to_string(directory.join(".env")).unwrap();
    let bearer = environment
        .lines()
        .find_map(|line| line.strip_prefix("PEERWARD_DEV_BEARER="))
        .unwrap()
        .to_owned();
    let lab = Lab {
        client: reqwest::Client::new(),
        origin: std::env::var("PEERWARD_DYNAMIC_CONTROL")
            .unwrap_or_else(|_| "http://127.0.0.1:29080".into()),
        bearer,
        directory,
    };
    let a = lab.create("isolation-a").await;
    let b = lab.create("isolation-b").await;
    if let Ok(host) = std::env::var("PEERWARD_DYNAMIC_SECOND_HOST") {
        for mesh in [&a, &b] {
            let end = tokio::time::Instant::now() + Duration::from_mins(1);
            loop {
                let (status, assignment) = lab
                    .api(
                        reqwest::Method::POST,
                        &format!("/meshes/{}/relay-hosts", mesh["id"].as_str().unwrap()),
                        Some(json!({"host_id":host})),
                        None,
                    )
                    .await;
                assert_eq!(status, 202, "{assignment}");
                if assignment["state"] == "ready" {
                    break;
                }
                assert!(
                    tokio::time::Instant::now() < end,
                    "second host readiness timed out: {assignment}"
                );
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
    let pa = lab.join(&a, "a").await;
    // Connect immediately after the first Join. Admission may already be committed
    // while the signed directory publisher still exposes the empty revision zero.
    let mut sa = pa.ready().await;
    let initial = tokio::time::timeout(
        Duration::from_secs(5),
        sa.matching(|control| match control.message {
            Some(Message::PeerDirectory(chunk)) => Some(chunk),
            _ => None,
        }),
    )
    .await
    .unwrap();
    assert_eq!((initial.index, initial.count), (0, 1));
    let signed = peerward_directory::decode_peer_directory(&initial.body).unwrap();
    assert!(
        signed.directory.entries.iter().any(|entry| {
            entry.entry.peer_id == pa.config.peer_id
                && entry.entry.enabled
                && entry.entry.accepted_credentials.iter().any(|binding| {
                    binding.serial == SubjectCredential::decode(&pa.credential).unwrap().serial
                })
        }),
        "Relay acknowledged a Join before its first signed directory contained the admitted credential"
    );
    let pb = lab.join(&b, "b").await;
    let mut pc = lab.join(&b, "c").await;
    if std::env::var_os("PEERWARD_DYNAMIC_SECOND_HOST").is_some() {
        assert_eq!(pc.config.relays.len(), 2);
        let other = pc
            .config
            .relays
            .iter()
            .position(|relay| relay.relay_id != pb.config.relays[0].relay_id)
            .unwrap();
        pc.config.relays.swap(0, other);
    }
    // A valid Noise exchange addressed to B cannot authorize an A credential.
    let target = &pb.config.relays[0];
    let public: [u8; 32] = hex::decode(&target.public_key).unwrap().try_into().unwrap();
    let cross = peerward_peer::connect_relay_endpoints_with_options(
        &target.endpoints,
        &pa.private,
        &public,
        target.relay_id,
        pb.config.mesh_id,
        &pb.trust,
        now(),
        HandshakePayload {
            major: peerward_wire::PROTOCOL_MAJOR,
            minor: 0,
            capabilities: peerward_wire::SUPPORTED_CAPABILITIES,
            credential: pa.credential.clone(),
            attachment_id: AttachmentId::new().as_bytes().to_vec(),
        },
        &pb.config.relay_transport,
    )
    .await;
    assert!(cross.is_err(), "cross-Mesh credential must be rejected");
    let mut sb = pb.ready().await;
    // C has joined but has no connection. Its absence must neither block B's
    // authenticated keepalive nor force B to replace its original Relay socket.
    sb.0.send_opaque(pb.config.mesh_id, pc.config.peer_id, &[41; 128])
        .await
        .unwrap();
    sb.0.send_control(ControlEnvelope {
        trace_context: None,
        message: Some(Message::Keepalive(peerward_wire::Keepalive {
            monotonic_timestamp: 987_654,
        })),
    })
    .await
    .unwrap();
    tokio::time::timeout(
        Duration::from_secs(2),
        sb.matching(|control| match control.message {
            Some(Message::Keepalive(value)) if value.monotonic_timestamp == 987_654 => Some(()),
            _ => None,
        }),
    )
    .await
    .expect("offline destination blocked or disconnected the source Relay link");
    // Let the bounded pending ciphertext expire while its destination stays
    // offline; the next application frame must never be displaced by this probe.
    tokio::time::sleep(Duration::from_millis(3_200)).await;
    let mut sc = pc.ready().await;
    let mesh_b =
        MeshId::from_uuid(uuid::Uuid::parse_str(b["id"].as_str().unwrap()).unwrap()).unwrap();
    for index in 0..3 {
        sb.0.send_opaque(mesh_b, pc.config.peer_id, &[42, index])
            .await
            .unwrap();
        assert_eq!(sc.opaque().await.opaque, [42, index]);
    }
    // A replacement owns the new fence immediately, before the periodic DB renewal.
    let replacement = pb.ready().await;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::select! {
                ended = sb.1.receive_packet() => { assert!(ended.is_err()); break; }
                _ = sb.2.recv() => {}
            }
        }
    })
    .await
    .expect("old primary remained attached after a newer session became ready");
    let mut sb = replacement;
    let deletion = lab.delete(&a).await;
    let terminal = tokio::time::timeout(
        Duration::from_secs(10),
        sa.matching(|c| match c.message {
            Some(Message::Close(v)) if v.body.starts_with(b"PWM1") => Some(v.body),
            _ => None,
        }),
    )
    .await
    .unwrap();
    pa.trust
        .verify_termination(
            &peerward_credentials::MeshTermination::decode(&terminal).unwrap(),
            0,
            now(),
        )
        .unwrap();
    // The same sender/receiver own the original sockets throughout deletion.
    for index in 0..100 {
        let mut ciphertext = vec![43; 9000];
        ciphertext[1] = index;
        sb.0.send_opaque(mesh_b, pc.config.peer_id, &ciphertext)
            .await
            .unwrap();
        let frame = sc.opaque().await;
        assert_eq!(frame.source_peer, pb.config.peer_id.as_bytes());
        assert_eq!(frame.opaque, ciphertext);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    lab.wait_deleted(&deletion).await;
    assert!(
        matches!(pa.connect().await,Err(PeerError::MeshTerminated(record)) if record==terminal)
    );
    assert!(SubjectCredential::decode(&pa.credential).is_ok());
    drop(sb);
    drop(sc);
    let deletion = lab.delete(&b).await;
    lab.wait_deleted(&deletion).await;
}
