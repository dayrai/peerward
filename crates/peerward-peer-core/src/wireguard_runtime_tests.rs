use super::*;
use crate::{WireguardIngress, WireguardOutput, WireguardRuntime};
use peerward_directory::SignedPolicyBundle;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

impl Fixture {
    fn authorize(&self, runtime: &mut WireguardRuntime) {
        self.authorize_resources(
            runtime,
            peerward_management::ResourceConfiguration::default(),
        );
    }
    fn authorize_resources(
        &self,
        runtime: &mut WireguardRuntime,
        resources: peerward_management::ResourceConfiguration,
    ) {
        self.authorize_configuration(runtime, resources, vec![]);
    }
    fn authorize_configuration(
        &self,
        runtime: &mut WireguardRuntime,
        resources: peerward_management::ResourceConfiguration,
        dns: Vec<peerward_management::DnsProfile>,
    ) -> peerward_management::ConfigurationDelivery {
        use peerward_management::*;
        let references = runtime.configuration_dependencies();
        if !references.contains_key(&ConfigurationPart::Authorities) {
            let authorities = self
                .authority
                .sign_authority_bundle(self.mesh, 1, self.certificate.clone(), vec![], vec![])
                .unwrap();
            runtime.authorities(&authorities, UnixTime(10)).unwrap();
        }
        if !references.contains_key(&ConfigurationPart::Revocations) {
            runtime
                .revoke(
                    &self.signer.sign_revocations(self.mesh, 1, vec![]).unwrap(),
                    UnixTime(10),
                )
                .unwrap();
        }
        let mut parts = runtime.configuration_dependencies();
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
            mesh_id: self.mesh,
            version: runtime.authorization_floor().configuration_version + 1,
            parts,
        };
        let lease = AuthorizationLease {
            mesh_id: self.mesh,
            configuration_digest: content_digest(&manifest).unwrap(),
            sequence: runtime.authorization_floor().lease_sequence + 1,
            issued_at: 10,
            valid_until: 910,
        };
        let delivery = ConfigurationDelivery {
            manifest: self.signer.sign_manifest(manifest).unwrap(),
            lease: self.signer.sign_lease(lease).unwrap(),
            resources,
            dns,
        };
        runtime
            .install_configuration(delivery.clone(), UnixTime(10), Instant::now())
            .unwrap();
        delivery
    }
    fn runtime(&self, credential: SubjectCredential, seed: u8) -> WireguardRuntime {
        let SubjectId::Peer(peer) = credential.subject else {
            panic!()
        };
        WireguardRuntime::new(
            self.mesh,
            peer,
            self.trust.clone(),
            &self.distribution,
            credential,
            StaticSecret::from([seed; 32]),
            1280,
            128,
            2,
            UnixTime(10),
        )
        .unwrap()
    }
    fn policy(&self, revision: u64, allow: bool) -> SignedPolicyBundle {
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
}

#[test]
fn encrypted_candidates_establish_direct_and_network_changes_preserve_wireguard_session() {
    let f = Fixture::new();
    let a_id = PeerId::new();
    let b_id = PeerId::new();
    let ca = f.credential(a_id, 10);
    let cb = f.credential(b_id, 20);
    let directory = f.signed(1, vec![f.entry(&ca, "10.0.0.1"), f.entry(&cb, "10.0.0.2")]);
    let mut a = f.runtime(ca, 10);
    let mut b = f.runtime(cb, 20);
    let now = Instant::now();
    let a_endpoint = "192.0.2.1:51820".parse().unwrap();
    let b_endpoint = "192.0.2.2:51820".parse().unwrap();
    for runtime in [&mut a, &mut b] {
        runtime.install_directory(&directory, UnixTime(10)).unwrap();
        runtime.install_policy(&f.policy(1, true)).unwrap();
        f.authorize(runtime);
    }
    a.update_candidates(vec![a_endpoint]).unwrap();
    b.update_candidates(vec![b_endpoint]).unwrap();
    let packet = udp(1, 2, 4242, 20);
    let initial = a.send_tunnel(&packet, UnixTime(10), now).unwrap();
    let mut queue: VecDeque<_> = initial.into_iter().map(|event| (true, event)).collect();
    let mut data = Vec::new();
    let mut direct = 0;
    let mut steps = 0;
    while let Some((from_a, event)) = queue.pop_front() {
        steps += 1;
        assert!(steps < 100);
        match event {
            WireguardOutput::Network {
                packet, reply_to, ..
            } => {
                let source = if from_a { a_endpoint } else { b_endpoint };
                let ingress = if let Some(WireguardIngress::Direct(destination)) = reply_to {
                    assert_eq!(destination, if from_a { b_endpoint } else { a_endpoint });
                    direct += 1;
                    WireguardIngress::Direct(source)
                } else {
                    WireguardIngress::Relay(if from_a { a_id } else { b_id })
                };
                let target = if from_a { &mut b } else { &mut a };
                let events = target.receive(ingress, &packet, UnixTime(10), now).unwrap();
                queue.extend(events.into_iter().map(|event| (!from_a, event)));
            }
            WireguardOutput::Tunnel { packet, .. } => data.push(packet),
        }
    }
    assert_eq!(data, vec![packet.clone()]);
    assert!(direct >= 4);
    assert_eq!(a.direct_peers(UnixTime(10), now), vec![b_id]);
    let output = a.send_tunnel(&packet, UnixTime(10), now).unwrap();
    assert!(output.iter().any(|event| matches!(event, WireguardOutput::Network { reply_to: Some(WireguardIngress::Direct(endpoint)), .. } if *endpoint == b_endpoint)));
    a.update_candidates(Vec::new()).unwrap();
    assert!(a.direct_peers(UnixTime(10), now).is_empty());
    let output = a.send_tunnel(&packet, UnixTime(10), now).unwrap();
    assert!(output.iter().all(|event| matches!(event, WireguardOutput::Network { reply_to: None, packet, .. } if packet[..4] == [4, 0, 0, 0])));
    assert_eq!(a.credential_count(), 1);
    assert!(a.tick(UnixTime(10), now).unwrap().iter().all(|event| !matches!(event, WireguardOutput::Network { packet, .. } if packet[..4] == [1,0,0,0])));
}

#[test]
fn suspend_discards_old_sessions_and_requires_a_new_authorization_lease() {
    let f = Fixture::new();
    let a_id = PeerId::new();
    let b_id = PeerId::new();
    let a_credential = f.credential(a_id, 10);
    let b_credential = f.credential(b_id, 20);
    let directory = f.signed(
        1,
        vec![
            f.entry(&a_credential, "10.0.0.1"),
            f.entry(&b_credential, "10.0.0.2"),
        ],
    );
    let mut a = f.runtime(a_credential, 10);
    let mut b = f.runtime(b_credential, 20);
    let now = Instant::now();
    for runtime in [&mut a, &mut b] {
        runtime.install_directory(&directory, UnixTime(10)).unwrap();
        runtime.install_policy(&f.policy(1, true)).unwrap();
        f.authorize(runtime);
    }
    let packet = udp(1, 2, 4242, 20);
    let initial = a.send_tunnel(&packet, UnixTime(10), now).unwrap();
    assert_eq!(
        relay_exchange(&mut a, &mut b, a_id, b_id, initial, now),
        vec![packet.clone()]
    );
    let old_output = a.send_tunnel(&packet, UnixTime(10), now).unwrap();
    let authorization = old_output
        .iter()
        .find_map(|event| match event {
            WireguardOutput::Network { authorization, .. } => Some(*authorization),
            WireguardOutput::Tunnel { .. } => None,
        })
        .unwrap();
    let old_inbound = b
        .send_tunnel(&udp(2, 1, 4242, 20), UnixTime(10), now)
        .unwrap();
    a.resume_after_suspend();
    assert_eq!(a.credential_count(), 1);
    assert_eq!(a.pending_bytes(), 0);
    assert!(!a.delivery_current(authorization, UnixTime(10)));
    for output in old_inbound {
        if let WireguardOutput::Network { packet, .. } = output {
            assert!(
                a.receive(WireguardIngress::Relay(b_id), &packet, UnixTime(10), now)
                    .is_err()
            );
        }
    }
    assert!(a.send_tunnel(&packet, UnixTime(10), now).is_err());
    f.authorize(&mut a);
    let fresh = a.send_tunnel(&packet, UnixTime(10), now).unwrap();
    assert!(fresh.iter().any(|event| matches!(event, WireguardOutput::Network { packet, .. } if packet[..4] == [1, 0, 0, 0])));
    assert_eq!(
        relay_exchange(&mut a, &mut b, a_id, b_id, fresh, now),
        vec![packet]
    );
}

#[test]
fn recovery_requires_active_directory_and_revocations_in_either_order() {
    let f = Fixture::new();
    let peer = PeerId::new();
    let old = f.credential(peer, 10);
    let new = f.credential(peer, 20);
    let old_directory = f.signed(1, vec![f.entry(&old, "10.0.0.1")]);
    let new_directory = f.signed(2, vec![f.entry(&new, "10.0.0.1")]);
    let revoked_old = f
        .signer
        .sign_revocations(f.mesh, 1, vec![old.serial])
        .unwrap();
    for revocations_first in [false, true] {
        let mut runtime = f.runtime(new.clone(), 20);
        runtime
            .install_directory(&old_directory, UnixTime(10))
            .unwrap();
        assert!(runtime.confirmed_local_credential(UnixTime(10)).is_none());
        if revocations_first {
            runtime.revoke(&revoked_old, UnixTime(10)).unwrap();
        } else {
            runtime
                .install_directory(&new_directory, UnixTime(10))
                .unwrap();
        }
        assert!(runtime.confirmed_local_credential(UnixTime(10)).is_none());
        if revocations_first {
            runtime
                .install_directory(&new_directory, UnixTime(10))
                .unwrap();
        } else {
            runtime.revoke(&revoked_old, UnixTime(10)).unwrap();
        }
        assert_eq!(
            runtime.confirmed_local_credential(UnixTime(10)),
            Some(new.clone())
        );
        runtime
            .revoke(
                &f.signer
                    .sign_revocations(f.mesh, 2, vec![new.serial])
                    .unwrap(),
                UnixTime(10),
            )
            .unwrap();
        assert!(runtime.confirmed_local_credential(UnixTime(10)).is_none());
        assert!(
            runtime
                .install_directory(&old_directory, UnixTime(10))
                .is_err()
        );
    }
    let mut expired = f.runtime(new, 20);
    expired
        .install_directory(&new_directory, UnixTime(10))
        .unwrap();
    expired.revoke(&revoked_old, UnixTime(10)).unwrap();
    assert!(expired.confirmed_local_credential(UnixTime(1001)).is_none());
}

fn udp(source: u8, destination: u8, port: u16, payload: usize) -> Vec<u8> {
    let mut packet = vec![0x5a; 28 + payload];
    packet[..28].fill(0);
    packet[0] = 0x45;
    let length = u16::try_from(packet.len()).unwrap();
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 0, 0, source]);
    packet[16..20].copy_from_slice(&[10, 0, 0, destination]);
    packet[20..22].copy_from_slice(&1234_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&port.to_be_bytes());
    packet[24..26].copy_from_slice(&(length - 20).to_be_bytes());
    checksum(&mut packet);
    packet
}
fn checksum(packet: &mut [u8]) {
    packet[10..12].fill(0);
    let mut sum: u32 = packet[..20]
        .chunks_exact(2)
        .map(|p| u32::from(u16::from_be_bytes([p[0], p[1]])))
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!u16::try_from(sum).unwrap()).to_be_bytes());
}
fn fragments(packet: &[u8]) -> [Vec<u8>; 2] {
    let mut first = packet[..36].to_vec();
    first[2..4].copy_from_slice(&36_u16.to_be_bytes());
    first[6..8].copy_from_slice(&0x2000_u16.to_be_bytes());
    checksum(&mut first);
    let mut last = packet[..20].to_vec();
    last.extend_from_slice(&packet[36..]);
    let length = u16::try_from(last.len()).unwrap();
    last[2..4].copy_from_slice(&length.to_be_bytes());
    last[6..8].copy_from_slice(&2_u16.to_be_bytes());
    checksum(&mut last);
    [first, last]
}
fn relay_exchange(
    a: &mut WireguardRuntime,
    b: &mut WireguardRuntime,
    a_id: PeerId,
    b_id: PeerId,
    initial: Vec<WireguardOutput>,
    now: Instant,
) -> Vec<Vec<u8>> {
    let mut queue: VecDeque<_> = initial.into_iter().map(|event| (true, event)).collect();
    let mut packets = Vec::new();
    let mut steps = 0;
    while let Some((from_a, event)) = queue.pop_front() {
        steps += 1;
        assert!(steps < 100);
        match event {
            WireguardOutput::Network { peer, packet, .. } => {
                if peer != Some(if from_a { b_id } else { a_id }) {
                    assert_ne!(
                        peer,
                        Some(if from_a { a_id } else { b_id }),
                        "must not tunnel to self"
                    );
                    continue; // A third, offline Peer may receive bounded coordination probes.
                }
                let target = if from_a { &mut *b } else { &mut *a };
                let output = target
                    .receive(
                        WireguardIngress::Relay(if from_a { a_id } else { b_id }),
                        &packet,
                        UnixTime(10),
                        now,
                    )
                    .unwrap();
                queue.extend(output.into_iter().map(|event| (!from_a, event)));
            }
            WireguardOutput::Tunnel { packet, .. } => packets.push(packet),
        }
    }
    packets
}

#[test]
fn relay_bootstrap_queues_first_packet_and_direct_ingress_shares_replay_state() {
    let f = Fixture::new();
    let a_id = PeerId::new();
    let b_id = PeerId::new();
    let ca = f.credential(a_id, 10);
    let cb = f.credential(b_id, 20);
    let directory = f.signed(1, vec![f.entry(&ca, "10.0.0.1"), f.entry(&cb, "10.0.0.2")]);
    let mut a = f.runtime(ca, 10);
    let mut b = f.runtime(cb, 20);
    let now = Instant::now();
    assert!(
        a.send_tunnel(&udp(1, 2, 4242, 10), UnixTime(10), now)
            .is_err()
    );
    for runtime in [&mut a, &mut b] {
        runtime.install_directory(&directory, UnixTime(10)).unwrap();
        runtime.install_policy(&f.policy(1, true)).unwrap();
        f.authorize(runtime);
    }
    let packet = udp(1, 2, 4242, 10);
    let first = a.send_tunnel(&packet, UnixTime(10), now).unwrap();
    assert_eq!(a.pending_bytes(), packet.len());
    assert_eq!(
        relay_exchange(&mut a, &mut b, a_id, b_id, first, now),
        vec![packet.clone()]
    );
    assert_eq!(a.pending_bytes(), 0);
    let WireguardOutput::Network {
        packet: encrypted, ..
    } = a.send_tunnel(&packet, UnixTime(10), now).unwrap().remove(0)
    else {
        panic!()
    };
    assert!(
        b.receive(WireguardIngress::Relay(b_id), &encrypted, UnixTime(10), now)
            .is_err()
    );
    let accepted = b
        .receive(
            WireguardIngress::Direct("192.0.2.1:51820".parse().unwrap()),
            &encrypted,
            UnixTime(10),
            now,
        )
        .unwrap();
    assert!(accepted.iter().any(|event| matches!(event,WireguardOutput::Tunnel { packet: received, .. } if received==&packet)));
    let authorization = accepted
        .iter()
        .find_map(|event| match event {
            WireguardOutput::Tunnel { authorization, .. } => Some(*authorization),
            WireguardOutput::Network { .. } => None,
        })
        .unwrap();
    assert!(b.delivery_current(authorization, UnixTime(10)));
    b.install_policy(&f.policy(2, false)).unwrap();
    assert!(!b.delivery_current(authorization, UnixTime(10)));
    assert!(
        b.receive(WireguardIngress::Relay(a_id), &encrypted, UnixTime(10), now)
            .is_err()
    );
    assert!(
        a.send_tunnel(&udp(2, 2, 4242, 10), UnixTime(10), now)
            .is_err()
    );
    assert!(
        a.send_tunnel(&udp(1, 2, 51821, 10), UnixTime(10), now)
            .is_err()
    );
}

#[test]
fn policy_change_discards_waiting_plaintext_and_fragments_keep_complete_flow_authorization() {
    let f = Fixture::new();
    let a_id = PeerId::new();
    let b_id = PeerId::new();
    let ca = f.credential(a_id, 10);
    let cb = f.credential(b_id, 20);
    let directory = f.signed(1, vec![f.entry(&ca, "10.0.0.1"), f.entry(&cb, "10.0.0.2")]);
    let mut a = f.runtime(ca, 10);
    let mut b = f.runtime(cb, 20);
    let now = Instant::now();
    for runtime in [&mut a, &mut b] {
        runtime.install_directory(&directory, UnixTime(10)).unwrap();
        runtime.install_policy(&f.policy(1, true)).unwrap();
        f.authorize(runtime);
    }
    let packet = udp(1, 2, 4242, 20);
    let pieces = fragments(&packet);
    assert!(
        a.send_tunnel(&pieces[1], UnixTime(10), now)
            .unwrap()
            .is_empty()
    );
    let hello = a.send_tunnel(&pieces[0], UnixTime(10), now).unwrap();
    assert_eq!(
        relay_exchange(&mut a, &mut b, a_id, b_id, hello, now),
        pieces.to_vec()
    );
    // A fresh engine waits for a new handshake; a policy replacement removes its queue.
    a.close();
    let ca = f.credential(a_id, 30);
    let directory = f.signed(
        2,
        vec![
            f.entry(&ca, "10.0.0.1"),
            f.entry(&f.credential(b_id, 20), "10.0.0.2"),
        ],
    );
    let mut waiting = f.runtime(ca, 30);
    waiting.install_directory(&directory, UnixTime(10)).unwrap();
    waiting.install_policy(&f.policy(1, true)).unwrap();
    f.authorize(&mut waiting);
    waiting.send_tunnel(&packet, UnixTime(10), now).unwrap();
    assert!(waiting.pending_bytes() > 0);
    waiting.install_policy(&f.policy(2, false)).unwrap();
    assert_eq!(waiting.pending_bytes(), 0);
    assert!(waiting.send_tunnel(&packet, UnixTime(10), now).is_err());
}

#[test]
fn local_overlap_is_bounded_and_old_revocation_preserves_active_data_engine() {
    let f = Fixture::new();
    let id = PeerId::new();
    let remote = PeerId::new();
    let old = f.credential(id, 10);
    let new = f.credential(id, 30);
    let other = f.credential(remote, 20);
    let mut runtime = f.runtime(old.clone(), 10);
    runtime
        .install_directory(
            &f.signed(
                1,
                vec![f.entry(&old, "10.0.0.1"), f.entry(&other, "10.0.0.2")],
            ),
            UnixTime(10),
        )
        .unwrap();
    runtime
        .stage(new.clone(), StaticSecret::from([30; 32]), UnixTime(10))
        .unwrap();
    assert_eq!(runtime.credential_count(), 2);
    assert!(
        runtime
            .stage(
                f.credential(id, 40),
                StaticSecret::from([40; 32]),
                UnixTime(10)
            )
            .is_err()
    );
    let mut entry = f.entry(&new, "10.0.0.1");
    entry
        .accepted_credentials
        .push(PeerCredentialBinding::from_subject(
            &old,
            Some(UnixTime(20)),
        ));
    runtime
        .install_directory(
            &f.signed(2, vec![entry, f.entry(&other, "10.0.0.2")]),
            UnixTime(10),
        )
        .unwrap();
    runtime
        .revoke(
            &f.signer
                .sign_revocations(f.mesh, 1, vec![old.serial])
                .unwrap(),
            UnixTime(10),
        )
        .unwrap();
    assert_eq!(runtime.credential_count(), 1);
    runtime.install_policy(&f.policy(1, true)).unwrap();
    f.authorize(&mut runtime);
    let now = Instant::now();
    assert!(
        !runtime
            .send_tunnel(&udp(1, 2, 4242, 10), UnixTime(10), now)
            .unwrap()
            .is_empty()
    );
    runtime
        .tick(UnixTime(1001), now + Duration::from_secs(1000))
        .unwrap();
    assert_eq!(runtime.credential_count(), 0);
    assert_eq!(runtime.pending_bytes(), 0);
}

#[path = "wireguard_checkpoint_tests.rs"]
mod checkpoint_tests;

#[path = "wireguard_resource_tests.rs"]
mod resource_tests;

#[path = "wireguard_dual_stack_tests.rs"]
mod dual_stack_tests;

#[path = "wireguard_admission_tests.rs"]
mod admission_tests;
