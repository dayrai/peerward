use super::*;

#[tokio::test]
async fn linux_pump_uses_wireguard_for_first_packet_and_rejects_denied_traffic() {
    let now = UnixTime(wall_clock_seconds());
    let mesh = MeshId::new();
    let ids = [PeerId::new(), PeerId::new()];
    let root = RootSigningKey::from_bytes(&[1; 32]);
    let authority = AuthoritySigningKey::from_bytes(&[2; 32]);
    let signer = DirectorySigningKey::from_bytes(&[3; 32]);
    let certificate = root
        .certify(UnsignedAuthority {
            mesh_id: mesh,
            serial: CredentialSerial::new(),
            public_key: authority.public_key(),
            not_before: UnixTime(now.0 - 60),
            not_after: UnixTime(now.0 + 86400),
        })
        .unwrap();
    let mut trust = TrustSet::new(root.public_key(), mesh);
    trust.add_authority(certificate.clone(), now).unwrap();
    let distribution =
        authority.certify_distribution(mesh, signer.public_key().to_bytes(), [4; 32], [5; 32]);
    let policy = signer.sign_policy(
        mesh,
        1,
        encode_policy_document(&Policy::new(1, IdentityAction::Allow, Vec::new())).unwrap(),
    );
    let mut cores = Vec::new();
    let mut entries = Vec::new();
    for (index, id) in ids.iter().enumerate() {
        let seed = u8::try_from(index + 10).unwrap();
        let private = x25519_dalek::StaticSecret::from([seed; 32]);
        let credential = authority
            .issue(UnsignedSubject {
                mesh_id: mesh,
                subject: SubjectId::Peer(*id),
                serial: CredentialSerial::new(),
                identity_public_key: [seed; 32],
                public_noise_key: [seed + 1; 32],
                wireguard_public_key: x25519_dalek::PublicKey::from(&private).to_bytes(),
                not_before: UnixTime(now.0 - 60),
                not_after: UnixTime(now.0 + 3600),
            })
            .unwrap();
        entries.push(signer.sign_peer(PeerEntry {
            secondary_address: None,
            mesh_id: mesh,
            peer_id: *id,
            address: format!("10.20.0.{}", index + 2).parse().unwrap(),
            identity_public_key: credential.identity_public_key,
            noise_public_key: credential.public_noise_key,
            credential_serial: credential.serial,
            accepted_credentials: vec![peerward_directory::PeerCredentialBinding::from_subject(
                &credential,
                None,
            )],
            enabled: true,
            labels: BTreeMap::new(),
            not_after: credential.not_after,
        }));
        cores.push(
            peerward_peer_core::WireguardRuntime::new(
                mesh,
                *id,
                trust.clone(),
                &distribution,
                credential,
                private,
                1280,
                128,
                2,
                now,
            )
            .unwrap(),
        );
    }
    let directory = signer.sign_peers(mesh, 1, entries).unwrap();
    let authorize = |core: &mut peerward_peer_core::WireguardRuntime| {
        use peerward_management::*;
        if !core
            .configuration_dependencies()
            .contains_key(&ConfigurationPart::Authorities)
        {
            core.authorities(
                &authority
                    .sign_authority_bundle(mesh, 1, certificate.clone(), vec![], vec![])
                    .unwrap(),
                now,
            )
            .unwrap();
            core.revoke(&signer.sign_revocations(mesh, 1, vec![]).unwrap(), now)
                .unwrap();
        }
        let resources = ResourceConfiguration::default();
        let dns: Vec<DnsProfile> = vec![];
        let mut parts = core.configuration_dependencies();
        parts.insert(
            ConfigurationPart::Resources,
            ComponentReference {
                version: 1,
                digest: content_digest(&resources).unwrap(),
            },
        );
        parts.insert(
            ConfigurationPart::Dns,
            ComponentReference {
                version: 1,
                digest: content_digest(&dns).unwrap(),
            },
        );
        let manifest = ConfigurationManifest {
            mesh_id: mesh,
            version: core.authorization_floor().configuration_version + 1,
            parts,
        };
        let lease = AuthorizationLease {
            mesh_id: mesh,
            configuration_digest: content_digest(&manifest).unwrap(),
            sequence: core.authorization_floor().lease_sequence + 1,
            issued_at: now.0,
            valid_until: now.0 + 900,
        };
        core.install_configuration(
            ConfigurationDelivery {
                manifest: signer.sign_manifest(manifest).unwrap(),
                lease: signer.sign_lease(lease).unwrap(),
                resources,
                dns,
            },
            now,
            Instant::now(),
        )
        .unwrap();
    };
    let mut paths = Vec::new();
    let mut commands = Vec::new();
    let mut incoming = Vec::new();
    for mut core in cores {
        core.install_directory(&directory, now).unwrap();
        core.install_policy(&policy).unwrap();
        authorize(&mut core);
        let (sender, receiver) = mpsc::channel(64);
        let (plaintext, packets) = mpsc::channel(64);
        let (audit, _) = mpsc::channel(64);
        let relay = RelayPoolSender {
            state: Arc::new(Mutex::new(RelayPoolState {
                primary: 0,
                primary_since: monotonic_seconds(),
                better_streak: vec![0],
                slots: vec![sender],
                flow_assignments: BTreeMap::new(),
            })),
            health: Arc::new(Mutex::new(vec![RelaySlotHealth {
                connected: true,
                ..RelaySlotHealth::default()
            }])),
            observability: None,
        };
        paths.push(WireguardPath {
            core: Arc::new(Mutex::new(core)),
            relay,
            sockets: {
                let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                Arc::new(StdRwLock::new(BTreeMap::from([(
                    socket.local_addr().unwrap(),
                    socket,
                )])))
            },
            incoming: plaintext,
            mesh,
            audit,
            observability: None,
            counters: Arc::new(CounterSet::default()),
        });
        commands.push(receiver);
        incoming.push(packets);
    }
    let observed = peerward_service::PeerObservability::default();
    paths[0].observability = Some(observed.clone());
    paths[0].record_drop(true, 1280, &PeerError::QueueFull);
    paths[0].record_dispatch_drop(false, 1280, &PacketPumpError::NoRoute);
    paths[0].record_drop(true, 20, &PeerError::InvalidPacket);
    let metrics = observed.metrics_json();
    assert_eq!(metrics["peerward_peer_acl_denied_total"], 0);
    assert_eq!(metrics["peerward_peer_queue_full_total"], 1);
    assert_eq!(metrics["peerward_peer_no_route_total"], 1);
    assert_eq!(metrics["peerward_peer_invalid_packets_total"], 1);
    let (shutdown, stop) = watch::channel(false);
    let mut tunnels = Vec::new();
    let mut pumps = Vec::new();
    for (path, packets) in paths.iter().cloned().zip(incoming) {
        let (send, input) = mpsc::channel(8);
        let (output, receive) = mpsc::channel(8);
        pumps.push(tokio::spawn(run_wireguard_pump(
            ChannelReader(input),
            ChannelWriter(output),
            path,
            packets,
            1280,
            stop.clone(),
        )));
        tunnels.push((send, receive));
    }
    let mut forwarding = Vec::new();
    for (index, mut receiver) in commands.into_iter().enumerate() {
        let destination = paths[1 - index].clone();
        let source = ids[index];
        let sender = TestRelay {
            destination,
            source,
        };
        forwarding.push(tokio::spawn(async move {
            while let Some(command) = receiver.recv().await {
                assert!(forward_slot_command(command, &sender).await);
            }
        }));
    }
    let packet = udp_packet();
    tunnels[0].0.send(packet.clone()).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), tunnels[1].1.recv())
            .await
            .unwrap(),
        Some(packet.clone())
    );
    assert_eq!(paths[0].core.lock().await.pending_bytes(), 0);
    let event = paths[0]
        .core
        .lock()
        .await
        .send_tunnel(&packet, now, Instant::now())
        .unwrap()
        .remove(0);
    let peerward_peer_core::WireguardOutput::Network {
        authorization,
        expires,
        ..
    } = event
    else {
        panic!()
    };
    let guard = WireguardSendGuard {
        core: Arc::downgrade(&paths[0].core),
        authorization,
        expires,
    };
    assert!(guard.current().await);
    // A slow TUN consumer is bounded and reports resource pressure, not an ACL denial.
    let (bounded, _consumer) = mpsc::channel(1);
    let mut congested = paths[0].clone();
    congested.incoming = bounded;
    for full in [false, true] {
        let result = congested
            .dispatch(vec![peerward_peer_core::WireguardOutput::Tunnel {
                peer: ids[1],
                packet: packet.clone(),
                ingress: peerward_peer_core::WireguardIngress::Relay(ids[1]),
                authorization,
                expires,
            }])
            .await;
        assert_eq!(matches!(result, Err(PacketPumpError::QueueFull)), full);
    }
    assert_eq!(observed.metrics_json()["peerward_peer_queue_full_total"], 2);
    assert_eq!(observed.metrics_json()["peerward_peer_acl_denied_total"], 0);
    // An unavailable address family must not reroute direct checks through Relay.
    let (send, mut receive) = mpsc::channel(8);
    let mut probe_path = paths[0].clone();
    probe_path.relay.state = Arc::new(Mutex::new(RelayPoolState {
        primary: 0,
        primary_since: monotonic_seconds(),
        better_streak: vec![0],
        slots: vec![send],
        flow_assignments: BTreeMap::new(),
    }));
    for path_probe in [true, false] {
        probe_path
            .dispatch(vec![peerward_peer_core::WireguardOutput::Network {
                local_key: [1; 32],
                peer: Some(ids[1]),
                packet: vec![42; 1312],
                reply_to: Some(peerward_peer_core::WireguardIngress::Direct(
                    "[2001:db8::1]:1234".parse().unwrap(),
                )),
                path_probe,
                authorization,
                expires,
            }])
            .await
            .unwrap();
        if path_probe {
            assert!(receive.try_recv().is_err());
        } else {
            let RelaySlotCommand::Wireguard(envelope, _) = receive.try_recv().unwrap() else {
                panic!()
            };
            let Some(ControlMessage::Opaque(opaque)) = envelope.message else {
                panic!()
            };
            assert_eq!(opaque.opaque, vec![42; 1312]);
        }
    }
    let denied = signer.sign_policy(
        mesh,
        2,
        encode_policy_document(&Policy::new(2, IdentityAction::Deny, Vec::new())).unwrap(),
    );
    paths[0].core.lock().await.install_policy(&denied).unwrap();
    authorize(&mut *paths[0].core.lock().await);
    assert!(!guard.current().await);
    // TestRelay would panic if the stale command reached its writer.
    assert!(
        forward_slot_command(
            RelaySlotCommand::Wireguard(
                ControlEnvelope {
                    trace_context: None,
                    message: None
                },
                guard
            ),
            &TestRelay {
                destination: paths[1].clone(),
                source: ids[0]
            }
        )
        .await
    );
    tunnels[0].0.send(packet).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(50), tunnels[1].1.recv())
            .await
            .is_err()
    );
    shutdown.send(true).unwrap();
    for pump in pumps {
        pump.await.unwrap().unwrap();
    }
    assert!(paths[0].counters.egress_denied.load(Ordering::Relaxed) > 0);
    assert_eq!(observed.metrics_json()["peerward_peer_acl_denied_total"], 1);
    for worker in forwarding {
        worker.abort();
        let _ = worker.await;
    }
}

#[derive(Clone)]
struct TestRelay {
    destination: WireguardPath,
    source: PeerId,
}
#[async_trait]
impl ControlSender for TestRelay {
    async fn send_control(&self, envelope: ControlEnvelope) -> Result<(), PacketPumpError> {
        let Some(ControlMessage::Opaque(opaque)) = envelope.message else {
            panic!()
        };
        assert!(matches!(opaque.opaque[0], 1..=4));
        self.destination
            .receive(
                peerward_peer_core::WireguardIngress::Relay(self.source),
                &opaque.opaque,
            )
            .await
    }
}
