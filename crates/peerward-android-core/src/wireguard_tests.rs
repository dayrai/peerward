use super::*;
use peerward_credentials::{
    AuthoritySigningKey, RootSigningKey, UnsignedAuthority, UnsignedSubject,
};
use peerward_directory::{
    DirectorySigningKey, PeerCredentialBinding, PeerEntry, SignedPeerDirectory,
    encode_peer_directory, encode_policy,
};
use peerward_peer_core::{WireguardIngress, WireguardOutput, WireguardRuntime};
use peerward_service::ServiceSnapshotSigningKey;
use peerward_types::{CredentialSerial, RelayId};
use peerward_wire::{PeerDirectoryChunk, PolicyBundle, RelayEnvelopeV2, ik_responder};
use std::{
    collections::{BTreeMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};

pub(crate) struct Fixture {
    mesh: MeshId,
    now: UnixTime,
    signer: DirectorySigningKey,
    trust: MobileTrust,
    alice: SubjectCredential,
    bob: SubjectCredential,
    relay: SubjectCredential,
    root: [u8; 32],
    authority: peerward_credentials::AuthorityCertificate,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let mesh = MeshId::new();
        let now = UnixTime(wall_clock_seconds());
        let root = RootSigningKey::from_bytes(&[1; 32]);
        let authority = AuthoritySigningKey::from_bytes(&[2; 32]);
        let mut credentials = TrustSet::new(root.public_key(), mesh);
        let certificate = root
            .certify(UnsignedAuthority {
                mesh_id: mesh,
                serial: CredentialSerial::new(),
                public_key: authority.public_key(),
                not_before: UnixTime(now.0 - 60),
                not_after: UnixTime(now.0 + 86_400),
            })
            .unwrap();
        credentials.add_authority(certificate.clone(), now).unwrap();
        let signer = DirectorySigningKey::from_bytes(&[3; 32]);
        let services = ServiceSnapshotSigningKey::from_bytes(&[4; 32]);
        let binding = authority.certify_distribution(
            mesh,
            signer.public_key().to_bytes(),
            services.verifier().to_bytes(),
            [5; 32],
        );
        let issue = |subject, noise_seed, wg_seed| {
            authority
                .issue(UnsignedSubject {
                    subject,
                    mesh_id: mesh,
                    identity_public_key: if wg_seed == 0 {
                        [0; 32]
                    } else {
                        ed25519_dalek::SigningKey::from_bytes(&[noise_seed + 1; 32])
                            .verifying_key()
                            .to_bytes()
                    },
                    public_noise_key: RawStaticDh::new([noise_seed; 32]).public_key(),
                    wireguard_public_key: if wg_seed == 0 {
                        [0; 32]
                    } else {
                        PublicKey::from(&StaticSecret::from([wg_seed; 32])).to_bytes()
                    },
                    serial: CredentialSerial::new(),
                    not_before: UnixTime(now.0 - 30),
                    not_after: UnixTime(now.0 + 3600),
                })
                .unwrap()
        };
        Self {
            mesh,
            now,
            signer,
            trust: MobileTrust::new(
                mesh,
                credentials,
                DirectoryPublicKey::from_bytes(&binding.directory_public_key).unwrap(),
                services.verifier(),
                [5; 32],
                &binding,
                now,
            )
            .unwrap(),
            alice: issue(SubjectId::Peer(PeerId::new()), 10, 11),
            bob: issue(SubjectId::Peer(PeerId::new()), 20, 21),
            relay: issue(SubjectId::Relay(RelayId::new()), 30, 0),
            root: root.public_key().to_bytes(),
            authority: certificate,
        }
    }

    fn trust(&self) -> MobileTrust {
        MobileTrust::new(
            self.mesh,
            self.trust.credentials.clone(),
            self.signer.public_key(),
            self.trust.services,
            [5; 32],
            &self.trust.binding,
            self.now,
        )
        .unwrap()
    }

    fn entry(&self, credential: &SubjectCredential, last: u8) -> PeerEntry {
        PeerEntry {
            secondary_address: None,
            mesh_id: self.mesh,
            peer_id: peer(credential),
            address: format!("10.4.0.{last}").parse().unwrap(),
            identity_public_key: credential.identity_public_key,
            noise_public_key: credential.public_noise_key,
            credential_serial: credential.serial,
            accepted_credentials: vec![PeerCredentialBinding::from_subject(credential, None)],
            enabled: true,
            labels: BTreeMap::new(),
            not_after: credential.not_after,
        }
    }

    fn directory(&self) -> SignedPeerDirectory {
        self.signer
            .sign_peers(
                self.mesh,
                1,
                vec![
                    self.signer.sign_peer(self.entry(&self.alice, 1)),
                    self.signer.sign_peer(self.entry(&self.bob, 2)),
                ],
            )
            .unwrap()
    }

    fn policy(&self, revision: u64, allow: bool) -> peerward_directory::SignedPolicyBundle {
        let policy = peerward_policy::Policy::new(
            revision,
            if allow {
                peerward_policy::Action::Allow
            } else {
                peerward_policy::Action::Deny
            },
            Vec::new(),
        );
        self.signer.sign_policy(
            self.mesh,
            revision,
            peerward_policy::encode_policy_document(&policy).unwrap(),
        )
    }

    pub(crate) fn mobile(&self) -> SharedMobileWireguard {
        Arc::new(Mutex::new(
            MobileWireguard::new(
                &self.trust,
                self.alice.clone(),
                StaticSecret::from([11; 32]),
                1280,
                self.now,
            )
            .unwrap(),
        ))
    }

    fn linux(&self) -> WireguardRuntime {
        let mut runtime = WireguardRuntime::new(
            self.mesh,
            peer(&self.bob),
            self.trust.credentials.clone(),
            &self.trust.binding,
            self.bob.clone(),
            StaticSecret::from([21; 32]),
            1280,
            128,
            2,
            self.now,
        )
        .unwrap();
        runtime
            .install_directory(&self.directory(), self.now)
            .unwrap();
        runtime.install_policy(&self.policy(1, true)).unwrap();
        self.authorize(&mut runtime);
        runtime
    }

    pub(crate) fn carrier(
        &self,
        owner: &SharedMobileWireguard,
    ) -> (NativeSession, StreamTransport) {
        let (mut native, first) = NativeSession::initiate(
            Arc::new(RawStaticDh::new([10; 32])),
            self.relay.public_noise_key,
            &self.alice,
            *AttachmentId::new().as_bytes(),
            0,
            self.now,
            self.trust(),
        )
        .unwrap();
        native.attach_wireguard(Arc::clone(owner)).unwrap();
        let mut relay = ik_responder(&[30; 32]).unwrap();
        let mut buffer = vec![0; 65_535];
        relay.read_message(&first, &mut buffer).unwrap();
        let welcome = HandshakePayload {
            major: PROTOCOL_MAJOR,
            minor: 0,
            capabilities: 0,
            credential: self.relay.encode(),
            attachment_id: AttachmentId::new().as_bytes().to_vec(),
        };
        let length = relay
            .write_message(&welcome.encode_to_vec(), &mut buffer)
            .unwrap();
        native
            .finish_handshake(&buffer[..length], self.now, 100)
            .unwrap();
        let link = StreamTransport::from_handshake(relay, 100).unwrap();
        self.install(&mut native);
        self.authorize_carrier(&mut native);
        (native, link)
    }

    fn configuration(
        &self,
        runtime: &mut WireguardRuntime,
    ) -> peerward_management::ConfigurationDelivery {
        use peerward_management::*;
        let parts = runtime.configuration_dependencies();
        if !parts.contains_key(&ConfigurationPart::Authorities) {
            let bundle = AuthoritySigningKey::from_bytes(&[2; 32])
                .sign_authority_bundle(self.mesh, 1, self.authority.clone(), vec![], vec![])
                .unwrap();
            runtime.authorities(&bundle, self.now).unwrap();
        }
        if !parts.contains_key(&ConfigurationPart::Revocations) {
            runtime
                .revoke(
                    &self.signer.sign_revocations(self.mesh, 1, vec![]).unwrap(),
                    self.now,
                )
                .unwrap();
        }
        let mut parts = runtime.configuration_dependencies();
        let resources = ResourceConfiguration::default();
        let dns: Vec<DnsProfile> = vec![];
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
        let floor = runtime.authorization_floor();
        // Identical relay attachments deliver the same configuration, not a new authorization.
        let manifest = ConfigurationManifest {
            mesh_id: self.mesh,
            version: parts[&ConfigurationPart::Policy]
                .version
                .max(parts[&ConfigurationPart::Authorities].version),
            parts,
        };
        let digest = content_digest(&manifest).unwrap();
        let sequence = if floor.configuration_digest == digest {
            floor.lease_sequence
        } else {
            floor.lease_sequence + 1
        };
        let lease = AuthorizationLease {
            mesh_id: self.mesh,
            configuration_digest: digest,
            sequence,
            issued_at: self.now.0,
            valid_until: self.now.0 + 900,
        };
        ConfigurationDelivery {
            manifest: self.signer.sign_manifest(manifest).unwrap(),
            lease: self.signer.sign_lease(lease).unwrap(),
            resources,
            dns,
        }
    }

    fn authorize(&self, runtime: &mut WireguardRuntime) {
        let delivery = self.configuration(runtime);
        runtime
            .install_configuration(delivery, self.now, Instant::now())
            .unwrap();
    }

    fn authorize_carrier(&self, native: &mut NativeSession) {
        let delivery =
            self.configuration(&mut native.wireguard.as_ref().unwrap().lock().unwrap().core);
        native
            .apply_control(&ControlEnvelope {
                trace_context: None,
                message: Some(ControlMessage::Configuration(PeerDirectoryChunk {
                    mesh_id: self.mesh.as_bytes().to_vec(),
                    revision: delivery.lease.lease.sequence,
                    index: 0,
                    count: 1,
                    body: serde_json::to_vec(&delivery).unwrap(),
                })),
            })
            .unwrap();
    }

    fn install(&self, native: &mut NativeSession) {
        native
            .apply_control(&ControlEnvelope {
                trace_context: None,
                message: Some(ControlMessage::PeerDirectory(PeerDirectoryChunk {
                    mesh_id: self.mesh.as_bytes().to_vec(),
                    revision: 1,
                    index: 0,
                    count: 1,
                    body: encode_peer_directory(&self.directory()).unwrap(),
                })),
            })
            .unwrap();
        native.apply_control(&self.policy_control(1, true)).unwrap();
    }

    fn policy_control(&self, revision: u64, allow: bool) -> ControlEnvelope {
        ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Policy(PolicyBundle {
                mesh_id: self.mesh.as_bytes().to_vec(),
                revision,
                index: 0,
                count: 1,
                body: encode_policy(&self.policy(revision, allow)).unwrap(),
            })),
        }
    }

    fn envelope(&self, source: PeerId, destination: PeerId, packet: Vec<u8>) -> Record {
        Record::Control(ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Opaque(RelayEnvelopeV2 {
                major: PROTOCOL_MAJOR,
                mesh_id: self.mesh.as_bytes().to_vec(),
                source_peer: source.as_bytes().to_vec(),
                destination_peer: destination.as_bytes().to_vec(),
                kind: OpaqueFrameKind::Session as i32,
                opaque: packet,
            })),
        })
    }

    fn exchange(
        &self,
        owner: &SharedMobileWireguard,
        native: &mut NativeSession,
        relay: &mut StreamTransport,
        linux: &mut WireguardRuntime,
        initial: Vec<WireguardOutput>,
    ) -> Vec<Vec<u8>> {
        let mut to_mobile: VecDeque<_> = initial.into();
        let mut delivered = Vec::new();
        for _ in 0..16 {
            while let Some(event) = to_mobile.pop_front() {
                match event {
                    WireguardOutput::Network { packet, .. } => {
                        let frame = relay
                            .encode(&self.envelope(peer(&self.bob), peer(&self.alice), packet))
                            .unwrap();
                        native.decrypt(&frame, 100).unwrap();
                    }
                    WireguardOutput::Tunnel { packet, .. } => delivered.push(packet),
                }
            }
            let tickets = owner.lock().unwrap().poll(self.now, Instant::now());
            if tickets.is_empty() {
                return delivered;
            }
            for ticket in tickets {
                owner
                    .lock()
                    .unwrap()
                    .deliver(ticket.id, self.now, Instant::now(), |event| {
                        match event {
                            WireguardOutput::Network { packet, .. } => {
                                let frame = native.encrypt(
                                    &self.envelope(
                                        peer(&self.alice),
                                        peer(&self.bob),
                                        packet.clone(),
                                    ),
                                    100,
                                )?;
                                let Record::Control(envelope) = relay.decode(&frame)? else {
                                    panic!()
                                };
                                let Some(ControlMessage::Opaque(opaque)) = envelope.message else {
                                    panic!()
                                };
                                assert_ne!(opaque.opaque.get(..4), Some(b"PWD2".as_slice()));
                                to_mobile.extend(linux.receive(
                                    WireguardIngress::Relay(peer(&self.alice)),
                                    &opaque.opaque,
                                    self.now,
                                    Instant::now(),
                                )?);
                            }
                            WireguardOutput::Tunnel { packet, .. } => {
                                delivered.push(packet.clone());
                            }
                        }
                        Ok(())
                    })
                    .unwrap();
            }
        }
        panic!("WireGuard exchange did not settle");
    }
}

fn peer(credential: &SubjectCredential) -> PeerId {
    let SubjectId::Peer(peer) = credential.subject else {
        panic!()
    };
    peer
}

fn packet(first: u8, second: u8) -> Vec<u8> {
    super::tests::udp_packet([10, 4, 0, first], [10, 4, 0, second], 40_000, 1234)
}

#[test]
fn android_formal_relay_entry_interoperates_with_linux_and_preserves_session_on_replacement() {
    let f = Fixture::new();
    let owner = f.mobile();
    let (mut native, mut relay) = f.carrier(&owner);
    let mut linux = f.linux();
    owner
        .lock()
        .unwrap()
        .send(&packet(1, 2), f.now, Instant::now())
        .unwrap();
    assert_eq!(
        f.exchange(&owner, &mut native, &mut relay, &mut linux, Vec::new()),
        vec![packet(1, 2)]
    );
    native.close();
    drop(native);
    owner
        .lock()
        .unwrap()
        .core
        .update_candidates(Vec::new())
        .unwrap();
    // An offline mesh can still seal immediately using its existing WireGuard session.
    owner
        .lock()
        .unwrap()
        .send(&packet(1, 2), f.now, Instant::now())
        .unwrap();
    let tickets = owner.lock().unwrap().poll(f.now, Instant::now());
    assert_eq!(tickets.len(), 1);
    owner
        .lock()
        .unwrap()
        .deliver(tickets[0].id, f.now, Instant::now(), |output| {
            let WireguardOutput::Network { packet, .. } = output else {
                panic!()
            };
            assert_eq!(&packet[..4], &[4, 0, 0, 0]);
            Ok(())
        })
        .unwrap();
    let (mut replacement, mut relay) = f.carrier(&owner);
    let response = linux
        .send_tunnel(&packet(2, 1), f.now, Instant::now())
        .unwrap();
    assert_eq!(
        f.exchange(&owner, &mut replacement, &mut relay, &mut linux, response),
        vec![packet(2, 1)]
    );
    assert_eq!(owner.lock().unwrap().core.credential_count(), 1);
}

#[test]
fn android_output_tickets_expire_and_signed_policy_invalidates_both_writers() {
    let f = Fixture::new();
    let owner = f.mobile();
    let (mut native, mut relay) = f.carrier(&owner);
    let mut linux = f.linux();
    owner
        .lock()
        .unwrap()
        .send(&packet(1, 2), f.now, Instant::now())
        .unwrap();
    f.exchange(&owner, &mut native, &mut relay, &mut linux, Vec::new());
    let incoming = linux
        .send_tunnel(&packet(2, 1), f.now, Instant::now())
        .unwrap();
    for event in incoming {
        if let WireguardOutput::Network { packet, .. } = event {
            let frame = relay
                .encode(&f.envelope(peer(&f.bob), peer(&f.alice), packet))
                .unwrap();
            native.decrypt(&frame, 100).unwrap();
        }
    }
    owner
        .lock()
        .unwrap()
        .send(&packet(1, 2), f.now, Instant::now())
        .unwrap();
    let tickets = owner.lock().unwrap().poll(f.now, Instant::now());
    assert!(tickets.iter().any(|ticket| ticket.tunnel));
    assert!(tickets.iter().any(|ticket| !ticket.tunnel));
    native.apply_control(&f.policy_control(2, false)).unwrap();
    f.authorize_carrier(&mut native);
    for ticket in tickets {
        assert!(
            !owner
                .lock()
                .unwrap()
                .deliver(ticket.id, f.now, Instant::now(), |_| panic!("stale write"))
                .unwrap()
        );
    }
    assert!(
        owner
            .lock()
            .unwrap()
            .send(&packet(1, 2), f.now, Instant::now())
            .is_err()
    );
    native.apply_control(&f.policy_control(3, true)).unwrap();
    f.authorize_carrier(&mut native);
    owner
        .lock()
        .unwrap()
        .send(&packet(1, 2), f.now, Instant::now())
        .unwrap();
    let ticket = owner.lock().unwrap().poll(f.now, Instant::now()).remove(0);
    assert!(
        !owner
            .lock()
            .unwrap()
            .deliver(
                ticket.id,
                f.now,
                Instant::now() + Duration::from_secs(4),
                |_| panic!("expired write")
            )
            .unwrap()
    );
}

#[test]
fn duplicate_relay_snapshots_do_not_clear_pending_handshakes_or_accept_same_revision_substitution()
{
    let f = Fixture::new();
    let owner = f.mobile();
    let (mut first, _) = f.carrier(&owner);
    owner
        .lock()
        .unwrap()
        .send(&packet(1, 2), f.now, Instant::now())
        .unwrap();
    let (mut second, mut relay) = f.carrier(&owner);
    let mut linux = f.linux();
    assert_eq!(
        f.exchange(&owner, &mut second, &mut relay, &mut linux, Vec::new()),
        vec![packet(1, 2)]
    );
    let bytes = encode_policy(&f.policy(1, false)).unwrap();
    assert!(
        first
            .shared_update(3, 1, &bytes, |core| core
                .install_policy(&f.policy(1, false))
                .map(|_| ()))
            .is_err()
    );
    first.close();
    owner
        .lock()
        .unwrap()
        .send(&packet(1, 2), f.now, Instant::now())
        .unwrap();
    owner.lock().unwrap().close();
    assert!(
        owner
            .lock()
            .unwrap()
            .send(&packet(1, 2), f.now, Instant::now())
            .is_err()
    );
    assert!(owner.lock().unwrap().poll(f.now, Instant::now()).is_empty());
}

#[test]
fn android_profile_installs_only_its_independent_root_bound_wireguard_private_key() {
    use base64::Engine;
    let f = Fixture::new();
    let encode = |bytes: &[u8]| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    let document = serde_json::json!({
        "config_version": 4, "profile_id": "test", "device_key_id": "device", "mesh_id": f.mesh.to_string(),
        "peer_id": peer(&f.alice).to_string(), "mesh_name": "Test", "address": "10.4.0.1/32", "dns_suffix": "mesh.test",
        "credential": encode(&f.alice.encode()), "relays": [{"relay_id": match f.relay.subject { SubjectId::Relay(id) => id.to_string(), SubjectId::Peer(_) => panic!() },
            "endpoints": ["tcp://relay.example:443"], "noise_public_key": encode(&f.relay.public_noise_key)}],
        "routes": ["10.4.0.0/24"], "dns_servers": ["10.4.0.3"], "mtu": 1280,
        "local_identity_public": encode(&f.alice.identity_public_key), "local_noise_public": encode(&f.alice.public_noise_key),
        "local_wireguard_public": encode(&f.alice.wireguard_public_key), "root_public_key": encode(&f.root),
        "authority_certificates": [encode(&f.authority.encode())], "distribution_public_key": encode(&f.trust.binding.directory_public_key),
        "service_public_key": encode(&f.trust.binding.service_public_key), "audit_public_key": encode(&f.trust.binding.audit_public_key),
        "distribution_certificate": encode(&f.trust.binding.encode()),
    });
    let blob = encode_mobile_profile(&serde_json::to_vec(&document).unwrap()).unwrap();
    assert!(mobile_wireguard_from_profile(&blob, StaticSecret::from([11; 32]), f.now).is_ok());
    assert!(mobile_wireguard_from_profile(&blob, StaticSecret::from([10; 32]), f.now).is_err());
    assert!(mobile_wireguard_from_profile(&blob, StaticSecret::from([21; 32]), f.now).is_err());
}

#[test]
fn resumed_authority_revision_is_checked_once_then_shared_across_relay_attachments() {
    let mut f = Fixture::new();
    f.trust.credentials.resume_authority_revision(7).unwrap();
    let owner = f.mobile();
    let signed = AuthoritySigningKey::from_bytes(&[2; 32])
        .sign_authority_bundle(f.mesh, 7, f.authority.clone(), Vec::new(), Vec::new())
        .unwrap();
    owner
        .lock()
        .unwrap()
        .accept_update(1, 7, &signed.encode().unwrap(), |owner| {
            owner.core.authorities(&signed, f.now).map_err(Into::into)
        })
        .unwrap();
    // NativeSession's per-link chunk assemblers may replay the identical accepted snapshot.
    owner
        .lock()
        .unwrap()
        .accept_update(1, 7, &signed.encode().unwrap(), |_| {
            panic!("duplicate install")
        })
        .unwrap();
    assert!(
        owner
            .lock()
            .unwrap()
            .core
            .authorities(&signed, f.now)
            .is_err()
    );
    let (mut first, _) = f.carrier(&owner);
    let (mut second, _) = f.carrier(&owner);
    first.close();
    second.close();
    owner
        .lock()
        .unwrap()
        .send(&packet(1, 2), f.now, Instant::now())
        .unwrap();
}

#[test]
fn shared_dns_and_denial_audit_survive_carrier_loss_and_cannot_outlive_mesh_close() {
    let f = Fixture::new();
    let owner = f.mobile();
    let (mut native, _) = f.carrier(&owner);
    native.apply_control(&f.policy_control(2, false)).unwrap();
    f.authorize_carrier(&mut native);
    assert!(
        owner
            .lock()
            .unwrap()
            .send(&packet(1, 2), f.now, Instant::now())
            .is_err()
    );
    assert!(!native.audit_signature_transcript(f.now).unwrap().is_empty());
    native.close();
    assert!(!owner.lock().unwrap().audit_counts.is_empty());
    let query = super::tests::dns_query("absent.mesh.test", 1);
    let response = owner
        .lock()
        .unwrap()
        .resolve_dns(&query, "10.4.0.1".parse().unwrap(), "mesh.test", f.now)
        .unwrap();
    assert_eq!(response[3] & 15, 3);
    assert!(
        owner
            .lock()
            .unwrap()
            .resolve_dns(&query, "10.4.0.2".parse().unwrap(), "mesh.test", f.now)
            .is_err()
    );
    owner.lock().unwrap().close();
    assert!(
        owner
            .lock()
            .unwrap()
            .resolve_dns(&query, "10.4.0.1".parse().unwrap(), "mesh.test", f.now)
            .is_err()
    );
}

#[test]
fn signed_revocation_immediately_removes_only_the_matching_service_metadata() {
    use peerward_service::{RemoteService, RemoteServiceSnapshot, ServiceProtocol};
    let f = Fixture::new();
    let owner = f.mobile();
    let (mut carrier, _) = f.carrier(&owner);
    let services = [&f.alice, &f.bob]
        .into_iter()
        .enumerate()
        .map(|(index, credential)| RemoteService {
            id: peerward_types::ServiceId::new(),
            owner: peer(credential),
            credential_serial: credential.serial,
            virtual_address: format!("10.4.0.{}", index + 1).parse().unwrap(),
            protocols: vec![ServiceProtocol::Tcp],
            listen_port: 443,
            alias: Some(format!("service{index}")),
        })
        .collect::<Vec<_>>();
    let publish = |revision| {
        let signed = ServiceSnapshotSigningKey::from_bytes(&[4; 32])
            .sign(RemoteServiceSnapshot {
                mesh_id: f.mesh,
                revision,
                services: services.clone(),
            })
            .unwrap();
        ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Services(peerward_wire::ServiceSnapshot {
                mesh_id: f.mesh.as_bytes().to_vec(),
                revision,
                index: 0,
                count: 1,
                body: serde_json::to_vec(&signed).unwrap(),
            })),
        }
    };
    carrier.apply_control(&publish(1)).unwrap();
    let visible = |name| {
        owner
            .lock()
            .unwrap()
            .services
            .resolve_visible(name, "10.4.0.1".parse().unwrap(), |_, _| true)
            .is_some()
    };
    assert!(visible("service0"));
    assert!(visible("service1"));
    let revoked = f
        .signer
        .sign_revocations(f.mesh, 2, vec![f.bob.serial])
        .unwrap();
    carrier
        .apply_control(&ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Revocation(
                peerward_wire::CredentialRevocation {
                    mesh_id: f.mesh.as_bytes().to_vec(),
                    revision: 2,
                    index: 0,
                    count: 1,
                    body: peerward_directory::encode_revocations(&revoked).unwrap(),
                },
            )),
        })
        .unwrap();
    assert!(visible("service0"));
    assert!(!visible("service1"));
    assert!(carrier.apply_control(&publish(2)).is_err());
    assert!(visible("service0"));
    assert!(!visible("service1"));
}

#[test]
fn core_receipt_requires_device_signature_and_retries_the_same_claim() {
    use ed25519_dalek::Signer as _;
    let f = Fixture::new();
    let state =
        std::env::temp_dir().join(format!("peerward-mobile-receipt-{}", uuid::Uuid::new_v4()));
    let owner = f.mobile();
    owner
        .lock()
        .unwrap()
        .core
        .enable_checkpoint(&state, f.now)
        .unwrap();
    let (mut carrier, _) = f.carrier(&owner);
    management_tests::acknowledge_evidence(&mut carrier, f.now);
    let transcript = carrier.management_transcript(f.now).unwrap();
    assert!(!transcript.is_empty());
    assert!(carrier.complete_management([0; 64]).is_err());
    assert_eq!(carrier.management_transcript(f.now).unwrap(), transcript);
    let identity = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
    let bytes = carrier
        .complete_management(identity.sign(&transcript).to_bytes())
        .unwrap();
    assert_eq!(
        carrier
            .complete_management(identity.sign(&transcript).to_bytes())
            .unwrap(),
        bytes
    );
    let envelope = ControlEnvelope::decode(bytes.as_slice()).unwrap();
    let Some(ControlMessage::PeerManagement(body)) = envelope.message else {
        panic!()
    };
    let signed: peerward_management::SignedPeerCommand =
        serde_json::from_slice(&body.body).unwrap();
    signed
        .verify(&f.alice.identity_public_key, f.now.0)
        .unwrap();
    assert!(matches!(
        signed.command.operation,
        peerward_management::PeerOperation::Applied {
            category: peerward_management::ApplicationCategory::Core,
            ..
        }
    ));
    carrier.management_result(&peerward_wire::PeerManagementResult {
        request_id: uuid::Uuid::new_v4().as_bytes().to_vec(),
        committed: true,
        error: String::new(),
    });
    assert!(!carrier.management_transcript(f.now).unwrap().is_empty());
    carrier.management_result(&peerward_wire::PeerManagementResult {
        request_id: signed.command.request_id.as_bytes().to_vec(),
        committed: true,
        error: String::new(),
    });
    assert!(carrier.management_transcript(f.now).unwrap().is_empty());
    drop(carrier);
    drop(owner);
    std::fs::remove_dir_all(state).unwrap();
}

#[path = "wireguard_platform_tests.rs"]
mod platform_tests;

#[path = "management_tests.rs"]
mod management_tests;
