use super::*;

struct HaLab {
    peers: [PeerId; 3],
    runtimes: [WireguardRuntime; 3],
    primary_offline: bool,
}
impl HaLab {
    fn new(f: &Fixture) -> Self {
        let peers = [PeerId::new(), PeerId::new(), PeerId::new()];
        let credentials = [
            f.credential(peers[0], 10),
            f.credential(peers[1], 20),
            f.credential(peers[2], 30),
        ];
        let directory = f.signed(
            1,
            credentials
                .iter()
                .enumerate()
                .map(|(index, credential)| f.entry(credential, &format!("10.0.0.{}", index + 1)))
                .collect(),
        );
        let mut config = resource_config(f.mesh, peers[0], peers[1]);
        let mut backup = config.bindings[0].clone();
        backup.id = Uuid::new_v4();
        backup.peer_id = peers[2];
        backup.priority = 200;
        let mut advertisement = config.advertisements[0].clone();
        advertisement.binding_id = backup.id;
        advertisement.peer_id = backup.peer_id;
        config.bindings.push(backup);
        config.advertisements.push(advertisement);
        let runtimes = std::array::from_fn(|index| {
            let mut runtime = f.runtime(
                credentials[index].clone(),
                u8::try_from((index + 1) * 10).unwrap(),
            );
            runtime.install_directory(&directory, UnixTime(10)).unwrap();
            runtime.install_policy(&f.policy(1, false)).unwrap();
            f.authorize_resources(&mut runtime, config.clone());
            runtime.set_resource_platform_ready(true);
            runtime
        });
        Self {
            peers,
            runtimes,
            primary_offline: false,
        }
    }
    fn deliver(&mut self, from: usize, output: Vec<WireguardOutput>, now: Instant) -> Vec<usize> {
        let mut queue: VecDeque<_> = output.into_iter().map(|output| (from, output)).collect();
        let mut recipients = vec![];
        let mut steps = 0;
        while let Some((source, event)) = queue.pop_front() {
            steps += 1;
            assert!(steps < 500);
            if self.primary_offline && source == 1 {
                continue;
            }
            match event {
                WireguardOutput::Network {
                    peer: Some(peer),
                    packet,
                    ..
                } => {
                    let target = self.peers.iter().position(|id| *id == peer).unwrap();
                    if self.primary_offline && target == 1 {
                        continue;
                    }
                    let result = self.runtimes[target]
                        .receive(
                            WireguardIngress::Relay(self.peers[source]),
                            &packet,
                            UnixTime(10),
                            now,
                        )
                        .unwrap();
                    queue.extend(result.into_iter().map(|event| (target, event)));
                }
                WireguardOutput::Tunnel { .. } => recipients.push(source),
                WireguardOutput::Network { peer: None, .. } => {
                    panic!("authenticated peer expected")
                }
            }
        }
        recipients
    }
    fn tick(&mut self, now: Instant) {
        for source in 0..3 {
            if self.primary_offline && source == 1 {
                continue;
            }
            let output = self.runtimes[source].tick(UnixTime(10), now).unwrap();
            assert!(
                self.deliver(source, output, now).is_empty(),
                "probes never escape to host TUN"
            );
        }
    }
    fn send(&mut self, source_port: u16, now: Instant) -> Vec<usize> {
        let mut packet = udp(1, 2, 4242, 10);
        packet[16..20].copy_from_slice(&[192, 168, 45, 50]);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        checksum(&mut packet);
        let output = self.runtimes[0]
            .send_tunnel(&packet, UnixTime(10), now)
            .unwrap();
        self.deliver(0, output, now)
    }
}

#[test]
fn encrypted_gateway_checks_switch_after_three_failures_and_keep_healthy_backup_connections() {
    let f = Fixture::new();
    let mut lab = HaLab::new(&f);
    let now = Instant::now();
    let at = |seconds| now + Duration::from_secs(seconds);
    assert_eq!(lab.send(2000, now), vec![1]);
    lab.tick(now);
    lab.tick(at(5));
    assert!(
        lab.runtimes[0]
            .gateway_path_observations(at(5))
            .iter()
            .all(|item| item.health == PathHealth::Healthy)
    );
    lab.primary_offline = true;
    for seconds in [10, 15, 20, 25] {
        lab.tick(at(seconds));
    }
    let status = lab.runtimes[0].gateway_path_observations(at(25));
    assert!(
        status
            .iter()
            .any(|item| item.peer_id == lab.peers[1] && item.health == PathHealth::Unhealthy)
    );
    assert_eq!(lab.send(2001, at(25)), vec![2]);
    lab.primary_offline = false;
    for seconds in [30, 35, 40, 45, 50, 55] {
        lab.tick(at(seconds));
        assert_eq!(
            lab.send(u16::try_from(3000 + seconds).unwrap(), at(seconds)),
            vec![2]
        );
    }
    lab.tick(at(60));
    assert_eq!(
        lab.send(4000, at(60)),
        vec![1],
        "new flows return only after the stability window"
    );
    assert_eq!(
        lab.send(2001, at(60)),
        vec![2],
        "existing healthy backup flow retains its provider"
    );
    // A publication failure on another provider must not erase this backup connection.
    let mut configuration = lab.runtimes[0]
        .resource_network_configuration(UnixTime(10))
        .unwrap()
        .0;
    configuration.advertisements[0].forwarding_ready = false;
    f.authorize_resources(&mut lab.runtimes[0], configuration);
    assert_eq!(lab.send(2001, at(60)), vec![2]);
}
