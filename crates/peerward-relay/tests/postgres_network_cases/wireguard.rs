/// Real authenticated Relay ingress and backbone with standard `WireGuard` ciphertext.
/// This complements the privileged TUN/kernel gate; it does not claim a NAT matrix.
async fn assert_wireguard_relay_packets(
    sessions: &mut [RelayTestSession],
    credentials: &[peerward_credentials::SubjectCredential],
    directory: &peerward_directory::SignedPeerDirectory,
    policy: &peerward_directory::SignedPolicyBundle,
    distribution: &peerward_credentials::DistributionCertificate,
    root: &RootSigningKey,
    authority: &peerward_credentials::AuthorityCertificate,
    authorities: &peerward_credentials::SignedAuthorityBundle,
    revocations: &peerward_directory::SignedRevocationBundle,
    configuration: &peerward_management::ConfigurationDelivery,
    now: u64,
) {
    use peerward_peer_core::{WireguardIngress, WireguardOutput, WireguardRuntime};
    let mesh = directory.directory.mesh_id;
    let ids: Vec<_> = credentials.iter().map(|credential| match credential.subject { SubjectId::Peer(peer) => peer, SubjectId::Relay(_) => panic!() }).collect();
    let mut cores: Vec<_> = credentials.iter().enumerate().map(|(index, credential)| {
        let mut trust = TrustSet::new(root.public_key(), mesh);
        trust.add_authority(authority.clone(), UnixTime(now)).unwrap();
        let mut core = WireguardRuntime::new(mesh, ids[index], trust, distribution, credential.clone(),
            x25519_dalek::StaticSecret::from([u8::try_from(index + 0x70).unwrap(); 32]), 1280, 128, 2, UnixTime(now)).unwrap();
        core.authorities(authorities, UnixTime(now)).unwrap();
        core.install_directory(directory, UnixTime(now)).unwrap();
        core.install_policy(policy).unwrap();
        core.revoke(revocations, UnixTime(now)).unwrap();
        assert!(core.install_configuration(configuration.clone(), UnixTime(now), std::time::Instant::now()).unwrap());
        core
    }).collect();
    // Peer 1 shares a Relay; Peer 2 is reached over the authenticated backbone.
    for destination in 1..3 {
        let packet = udp_packet(Ipv4Addr::new(10,97,0,2), Ipv4Addr::new(10,97,0,u8::try_from(destination + 2).unwrap()), 42000, 4242);
        let initial = cores[0].send_tunnel(&packet, UnixTime(now), std::time::Instant::now()).unwrap();
        let mut queue: std::collections::VecDeque<_> = initial.into_iter().map(|event| (0, event)).collect();
        let mut delivered = Vec::new(); let mut steps = 0;
        while let Some((source, event)) = queue.pop_front() {
            steps += 1; assert!(steps < 100);
            match event {
                WireguardOutput::Network { peer, packet: ciphertext, reply_to, .. } => {
                    assert!(!matches!(reply_to, Some(WireguardIngress::Direct(_))));
                    assert!(matches!(ciphertext[0], 1..=4));
                    assert_ne!(ciphertext, packet);
                    let target = ids.iter().position(|id| Some(*id) == peer).unwrap();
                    sessions[source].0.send_opaque(mesh, ids[target], &ciphertext).await.unwrap();
                    let received = tokio::time::timeout(std::time::Duration::from_secs(3), receive_opaque(&mut sessions[target])).await.unwrap();
                    assert_eq!(received.source_peer, ids[source].as_bytes()); assert_eq!(received.opaque, ciphertext);
                    let events = cores[target].receive(WireguardIngress::Relay(ids[source]), &received.opaque, UnixTime(now), std::time::Instant::now()).unwrap();
                    queue.extend(events.into_iter().map(|event| (target, event)));
                }
                WireguardOutput::Tunnel { packet, .. } => delivered.push(packet),
            }
        }
        assert_eq!(delivered, vec![packet]);
    }
}
