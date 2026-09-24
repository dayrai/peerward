use std::{collections::VecDeque, str::FromStr};

use super::*;

#[tokio::test]
async fn underlay_ipv4_and_ipv6_share_a_port_without_mapped_address_aliases() {
    let underlay = LinuxUnderlayNetwork::default();
    let ipv4 = underlay
        .bind_udp("0.0.0.0:0".parse().unwrap())
        .await
        .unwrap();
    let port = ipv4.local_addr().unwrap().port();
    let ipv6 = underlay
        .bind_udp(format!("[::]:{port}").parse().unwrap())
        .await
        .unwrap();
    let sender4 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sender6 = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    sender4
        .send_to(b"v4", format!("127.0.0.1:{port}"))
        .await
        .unwrap();
    sender6
        .send_to(b"v6", format!("[::1]:{port}"))
        .await
        .unwrap();
    let mut buffer = [0; 8];
    let (length, source) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        ipv4.recv_from(&mut buffer),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&buffer[..length], b"v4");
    assert!(source.is_ipv4());
    let (length, source) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        ipv6.recv_from(&mut buffer),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(&buffer[..length], b"v6");
    assert!(source.is_ipv6());
    let addresses = linux_underlay_addresses().await.unwrap();
    assert!(
        addresses
            .iter()
            .all(|address| !address.address.is_loopback()
                && !address.interface.is_empty()
                && address.index != 0
                && address.mtu > 0)
    );
}

#[derive(Default)]
pub(super) struct MockBackend {
    pub(super) calls: Vec<CommandSpec>,
    replies: VecDeque<Result<String, PlatformError>>,
}

struct FakeTunnelDevice {
    mtu: u16,
    stream: tokio::io::DuplexStream,
}

impl TunnelDevice for FakeTunnelDevice {
    type Reader = tokio::io::ReadHalf<tokio::io::DuplexStream>;
    type Writer = tokio::io::WriteHalf<tokio::io::DuplexStream>;

    fn mtu(&self) -> u16 {
        self.mtu
    }

    fn split(self) -> (Self::Reader, Self::Writer) {
        tokio::io::split(self.stream)
    }
}

impl CommandBackend for MockBackend {
    fn run(&mut self, command: &CommandSpec) -> Result<String, PlatformError> {
        self.calls.push(command.clone());
        if self.replies.is_empty()
            && command.program == "resolvectl"
            && command
                .arguments
                .first()
                .is_some_and(|value| value == "snapshot")
        {
            return serde_json::to_string(&ResolvedLinkState {
                dns: vec![(2, vec![192, 0, 2, 53])],
                domains: vec![("old.test".into(), false)],
                default_route: true,
            })
            .map_err(PlatformError::from);
        }
        self.replies
            .pop_front()
            .unwrap_or_else(|| Ok(String::new()))
    }
}

pub(super) fn config() -> LinuxNetworkConfig {
    LinuxNetworkConfig {
        secondary_address: None,
        interface: "pw-test0".into(),
        interface_precreated: false,
        address: IpNet::from_str("10.7.0.2/24").unwrap(),
        mtu: 1380,
        routes: vec![IpNet::from_str("10.7.0.0/24").unwrap()],
        dns_suffix: "mesh.test".into(),
        dns_server: "10.7.0.1".parse().unwrap(),
        dns_backend: DnsBackend::SystemdResolved,
        nft_allow: vec![NftAllow {
            destination: IpNet::from_str("10.7.0.0/24").unwrap(),
            protocol: Some("tcp"),
            destination_port: Some(443),
        }],
    }
}

#[tokio::test]
async fn fake_tunnel_adapter_proves_platform_contract_without_os_ioctls() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let (stream, mut remote) = tokio::io::duplex(64);
    let device = FakeTunnelDevice { mtu: 1_380, stream };
    assert_eq!(device.mtu(), 1_380);
    let (mut reader, mut writer) = device.split();
    remote.write_all(b"packet-in").await.unwrap();
    let mut inbound = [0_u8; 9];
    reader.read_exact(&mut inbound).await.unwrap();
    assert_eq!(&inbound, b"packet-in");
    writer.write_all(b"packet-out").await.unwrap();
    let mut outbound = [0_u8; 10];
    remote.read_exact(&mut outbound).await.unwrap();
    assert_eq!(&outbound, b"packet-out");
}

#[tokio::test]
async fn underlay_change_generation_is_observable_without_replacing_the_receiver() {
    let underlay = LinuxUnderlayNetwork::default();
    let mut changes = underlay.network_changes();
    assert_eq!(*changes.borrow(), 0);
    underlay.notify_network_change();
    changes.changed().await.unwrap();
    assert_eq!(*changes.borrow(), 1);
}

#[tokio::test]
async fn underlay_debounce_waits_for_a_quiet_period_after_the_last_event() {
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    sender.send(()).await.unwrap();
    assert!(receiver.recv().await.is_some());
    let mut debounce =
        tokio::spawn(async move { wait_for_underlay_event_quiet_period(&mut receiver).await });

    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    sender.send(()).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(600)).await;
    sender.send(()).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(600), &mut debounce)
            .await
            .is_err(),
        "debounce completed before the final quiet period"
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(600), debounce)
            .await
            .expect("debounce did not complete after the quiet period")
            .expect("debounce task failed")
    );
}

#[test]
fn network_fingerprint_extracts_only_ipv4_local_addresses_from_fib_trie() {
    let first = r"
Main:
  +-- 10.0.0.0/8 2 0 2
     |-- 10.1.0.0
        /16 link UNICAST
Local:
  +-- 10.0.0.0/8 2 0 2
     |-- 10.1.2.3
        /32 host LOCAL
     |-- 10.1.255.255
        /32 link BROADCAST
";
    let settled = r"
Main:
  +-- 10.0.0.0/8 9 7 12
     |-- 10.1.0.0
        /16 link UNICAST
Local:
  +-- 10.0.0.0/8 2 0 2
     |-- 10.1.2.3
        /32 host LOCAL
";
    assert_eq!(ipv4_local_addresses(first), ipv4_local_addresses(settled));
    assert_eq!(
        ipv4_local_addresses(first),
        ["10.1.2.3".parse().unwrap()].into_iter().collect()
    );
}

#[test]
fn route_fingerprints_ignore_traffic_counters_but_detect_route_changes() {
    for (ipv6, row, busy, changed) in [
        (
            false,
            "eth0 00000000 0100000A 0003 0 0 200 00000000 0 0 0",
            "eth0 00000000 0100000A 0003 8 900 200 00000000 0 0 0",
            "eth0 00000000 0200000A 0003 8 900 200 00000000 0 0 0",
        ),
        (
            true,
            "fd420203000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000001 underlay",
            "fd420203000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 0000001a 00000210 00000001 underlay",
            "fd420203000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000200 0000001a 00000210 00000001 underlay",
        ),
    ] {
        assert_eq!(stable_route_rows(row, ipv6), stable_route_rows(busy, ipv6));
        assert_ne!(
            stable_route_rows(row, ipv6),
            stable_route_rows(changed, ipv6)
        );
        let ordered = format!("{row}\n{changed}");
        let reordered = format!("{changed}\n{busy}");
        assert_eq!(
            stable_route_rows(&ordered, ipv6),
            stable_route_rows(&reordered, ipv6)
        );
    }
}

#[test]
fn default_gateway_parsers_prefer_the_lowest_metric_and_support_ipv6() {
    let ipv4 = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
eth0 00000000 0100000A 0003 0 0 200 00000000 0 0 0\n\
eth1 00000000 FE00000A 0003 0 0 10 00000000 0 0 0\n";
    assert_eq!(
        parse_ipv4_default_gateway(ipv4).unwrap(),
        Some("10.0.0.254".parse().unwrap())
    );

    let ipv6 = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000020 00000000 00000000 00000003 eth0\n\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000002 00000010 00000000 00000000 00000003 eth1\n";
    assert_eq!(
        parse_ipv6_default_gateway(ipv6).unwrap(),
        Some("fe80::2".parse().unwrap())
    );
}

#[test]
fn default_gateway_parsers_reject_down_direct_and_malformed_candidates() {
    let ipv4 = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
eth0 00000000 00000000 0001 0 0 1 00000000 0 0 0\n";
    assert_eq!(parse_ipv4_default_gateway(ipv4).unwrap(), None);
    let malformed = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
eth0 00000000 NOTHEX 0003 0 0 1 00000000 0 0 0\n";
    assert!(parse_ipv4_default_gateway(malformed).is_err());
}

#[test]
fn partial_failure_rolls_back_only_completed_steps_in_reverse() {
    let backend = MockBackend {
        calls: Vec::new(),
        replies: VecDeque::from([
            Ok(String::new()),
            Ok(String::new()),
            Err(PlatformError::Command("injected".into())),
            Ok(String::new()),
            Ok(String::new()),
        ]),
    };
    let mut coordinator = StateCoordinator::new(backend);
    assert!(coordinator.apply(&config()).is_err());
    let backend = coordinator.into_backend().unwrap();
    assert_eq!(backend.calls[3].arguments[1], "del");
    assert_eq!(backend.calls[4].arguments[..2], ["tuntap", "del"]);
}

#[test]
fn network_manager_values_are_snapshotted_and_restored() {
    let mut config = config();
    config.dns_backend = DnsBackend::NetworkManager {
        connection: "Wired profile".into(),
    };
    let mut coordinator = StateCoordinator::new(MockBackend::default());
    coordinator.prepare(&config).unwrap();
    coordinator.backend.replies = VecDeque::from([Ok("192.0.2.53".into()), Ok("old.test".into())]);
    coordinator.activate_dns(&config).unwrap();
    coordinator.commit().unwrap();
    let backend = coordinator.into_backend().unwrap();
    assert!(backend.calls.iter().any(|call| {
        call.program == "peerward-network-manager"
            && call
                .input
                .as_deref()
                .is_some_and(|input| input.contains("192.0.2.53") && input.contains("old.test"))
    }));
}

#[test]
fn managed_dns_backends_journal_owned_compare_and_swap_mutations() {
    let resolved = dns_operations(&mut MockBackend::default(), &config()).unwrap();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].apply.program, "peerward-resolved");
    let resolved_apply: ResolvedLinkMutation =
        serde_json::from_str(resolved[0].apply.input.as_deref().unwrap()).unwrap();
    let resolved_rollback: ResolvedLinkMutation =
        serde_json::from_str(resolved[0].rollback.input.as_deref().unwrap()).unwrap();
    assert_eq!(resolved_apply.expected, resolved_rollback.replacement);
    assert_eq!(resolved_apply.replacement, resolved_rollback.expected);
    assert_eq!(resolved_apply.replacement.dns, vec![(2, vec![10, 7, 0, 1])]);

    let mut intent = config();
    intent.dns_backend = DnsBackend::NetworkManager {
        connection: "Wired profile".into(),
    };
    let mut backend = MockBackend {
        calls: Vec::new(),
        replies: VecDeque::from([Ok("192.0.2.53".into()), Ok("old.test".into())]),
    };
    let network_manager = dns_operations(&mut backend, &intent).unwrap();
    assert_eq!(network_manager.len(), 1);
    assert_eq!(network_manager[0].apply.program, "peerward-network-manager");
    let apply: NetworkManagerDnsMutation =
        serde_json::from_str(network_manager[0].apply.input.as_deref().unwrap()).unwrap();
    let rollback: NetworkManagerDnsMutation =
        serde_json::from_str(network_manager[0].rollback.input.as_deref().unwrap()).unwrap();
    assert_eq!(apply.expected, rollback.replacement);
    assert_eq!(apply.replacement, rollback.expected);
    assert_eq!(apply.expected.dns, "192.0.2.53");
    assert_eq!(apply.replacement.search, "~.,~mesh.test");
}

#[test]
fn atomic_state_round_trip_and_replacement() {
    let directory = std::env::temp_dir().join(format!("peerward-state-{}", Uuid::new_v4()));
    let path = directory.join("peer.json");
    let store = AtomicStateStore::new(&path);
    let mut state = LocalState {
        schema_version: 1,
        peer_id: PeerId::new(),
        directory_revision: 1,
        policy_revision: 2,
        relay_revision: 3,
    };
    store.save(&state).unwrap();
    assert_eq!(store.load::<LocalState>().unwrap(), state);
    state.policy_revision = 4;
    store.save(&state).unwrap();
    assert_eq!(store.load::<LocalState>().unwrap(), state);
    fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn precreated_interface_is_configured_but_never_deleted() {
    let mut intent = config();
    intent.interface_precreated = true;
    let mut coordinator = StateCoordinator::new(MockBackend::default());
    coordinator.apply(&intent).unwrap();
    let backend = coordinator.into_backend().unwrap();
    assert!(backend.calls.iter().all(|call| {
        !(call.program == "ip" && call.arguments.first().is_some_and(|arg| arg == "tuntap"))
    }));
    assert!(
        backend.calls.iter().any(|call| {
            call.program == "ip" && call.arguments.iter().any(|arg| arg == "address")
        })
    );
}

#[test]
fn mesh_dns_gateway_is_installed_as_a_local_host_address() {
    let mut coordinator = StateCoordinator::new(MockBackend::default());
    coordinator.apply(&config()).unwrap();
    let backend = coordinator.into_backend().unwrap();
    assert!(backend.calls.iter().any(|call| {
        call.program == "ip"
            && call.arguments == ["address", "add", "10.7.0.1/32", "dev", "pw-test0"]
    }));
    assert!(backend.calls.iter().any(|call| {
        call.program == "ip"
            && call.arguments == ["address", "del", "10.7.0.1/32", "dev", "pw-test0"]
    }));
    assert!(backend.calls.iter().any(|call| {
        call.program == "ip" && call.arguments == ["route", "add", "10.7.0.0/24", "dev", "pw-test0"]
    }));
}

#[test]
fn nftables_policy_is_one_atomic_apply_and_one_atomic_rollback() {
    let mut coordinator = StateCoordinator::new(MockBackend::default());
    coordinator.apply(&config()).unwrap();
    let backend = coordinator.into_backend().unwrap();
    let nft = backend
        .calls
        .iter()
        .filter(|call| call.program == "nft")
        .collect::<Vec<_>>();
    assert_eq!(nft.len(), 2);
    assert!(nft[0].input.as_deref().is_some_and(|batch| {
        batch.contains("destroy table inet peerward_pw_test0")
            && batch.contains("add rule inet peerward_pw_test0")
    }));
    assert_eq!(
        nft[1].input.as_deref(),
        Some("destroy table inet peerward_pw_test0\n")
    );
}

#[test]
fn staged_transaction_does_not_activate_dns_or_firewall_during_prepare() {
    let mut coordinator = StateCoordinator::new(MockBackend::default());
    let intent = config();
    coordinator.prepare(&intent).unwrap();
    assert!(coordinator.backend.calls.iter().all(|call| {
        !matches!(
            call.program.as_str(),
            "nft"
                | "resolvectl"
                | "nmcli"
                | "resolvconf"
                | "peerward-resolved"
                | "peerward-network-manager"
        )
    }));
    coordinator.activate_dns(&intent).unwrap();
    assert!(
        coordinator
            .backend
            .calls
            .iter()
            .any(|call| call.program == "nft")
    );
    assert!(
        coordinator
            .backend
            .calls
            .iter()
            .any(|call| call.program == "resolvectl")
    );
}

#[test]
fn auto_dns_selects_resolved_after_the_side_effect_free_probe() {
    let mut intent = config();
    intent.dns_backend = DnsBackend::Auto {
        connection: Some("Wired profile".into()),
        resolv_conf: "/etc/resolv.conf".into(),
    };
    let mut coordinator = StateCoordinator::new(MockBackend::default());
    coordinator.prepare(&intent).unwrap();
    coordinator.activate_dns(&intent).unwrap();

    let calls = &coordinator.backend.calls;
    assert!(
        calls.iter().any(|call| {
            call.program == "resolvectl" && call.arguments == ["probe", "pw-test0"]
        })
    );
    assert!(calls.iter().any(|call| {
        call.program == "peerward-resolved"
            && call.arguments == ["replace", "pw-test0"]
            && call
                .input
                .as_deref()
                .is_some_and(|input| input.contains("10,7,0,1") && input.contains("mesh.test"))
    }));
    assert!(calls.iter().all(|call| call.program != "nmcli"));
}

#[test]
fn durable_journal_replays_exact_rollbacks_after_restart() {
    let directory = std::env::temp_dir().join(format!("peerward-journal-{}", Uuid::new_v4()));
    let journal = directory.join("network.json");
    let mut first = StateCoordinator::with_journal(MockBackend::default(), &journal);
    first.prepare(&config()).unwrap();
    let expected = first.applied.iter().rev().cloned().collect::<Vec<_>>();
    assert!(journal.exists());
    std::mem::forget(first);

    let mut recovered = StateCoordinator::with_journal(MockBackend::default(), &journal);
    recovered.recover().unwrap();
    assert_eq!(recovered.backend.calls, expected);
    assert!(!journal.exists());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn recovery_cleans_up_after_non_persistent_tun_disappears() {
    let directory = std::env::temp_dir().join(format!("peerward-gone-tun-{}", Uuid::new_v4()));
    let journal = directory.join("network.json");
    let mut config = config();
    config.interface_precreated = true;
    let mut first = StateCoordinator::with_journal(MockBackend::default(), &journal);
    first.apply(&config).unwrap();
    let commands = first.applied.iter().rev().cloned().collect::<Vec<_>>();
    drop(first);

    let replies = commands
        .iter()
        .map(|command| {
            if command.program == "nft" {
                Ok(String::new())
            } else {
                Err(PlatformError::InterfaceMissing(config.interface.clone()))
            }
        })
        .collect();
    let mut recovered = StateCoordinator::with_journal(
        MockBackend {
            calls: Vec::new(),
            replies,
        },
        &journal,
    );
    recovered.recover().unwrap();
    assert_eq!(recovered.backend.calls, commands);
    assert!(!journal.exists());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn missing_interface_still_fails_network_preparation() {
    let mut config = config();
    config.interface_precreated = true;
    let mut coordinator = StateCoordinator::new(MockBackend {
        calls: Vec::new(),
        replies: VecDeque::from([Err(PlatformError::InterfaceMissing(
            config.interface.clone(),
        ))]),
    });
    assert!(matches!(
        coordinator.prepare(&config),
        Err(PlatformError::InterfaceMissing(_))
    ));
}

#[test]
fn failed_rollback_is_retained_for_retry() {
    let directory =
        std::env::temp_dir().join(format!("peerward-rollback-retry-{}", Uuid::new_v4()));
    let journal = directory.join("network.json");
    let mut coordinator = StateCoordinator::with_journal(MockBackend::default(), &journal);
    coordinator.prepare(&config()).unwrap();
    let failed_command = coordinator.applied.last().unwrap().clone();
    coordinator
        .backend
        .replies
        .push_back(Err(PlatformError::Command("permission denied".into())));
    assert!(matches!(
        coordinator.shutdown(),
        Err(PlatformError::Rollback)
    ));
    let saved: NetworkJournal = AtomicStateStore::new(&journal).load().unwrap();
    assert_eq!(saved.rollback, vec![failed_command.clone()]);
    drop(coordinator);

    let mut recovered = StateCoordinator::with_journal(MockBackend::default(), &journal);
    recovered.recover().unwrap();
    assert_eq!(recovered.backend.calls, vec![failed_command]);
    assert!(!journal.exists());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn resolv_conf_restore_uses_compare_and_swap_ownership() {
    let directory = std::env::temp_dir().join(format!("peerward-resolv-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("resolv.conf");
    fs::write(
        &path,
        "search old.test\nnameserver 192.0.2.53\noptions edns0\n",
    )
    .unwrap();
    let operations = resolv_conf_operations(&path, "10.7.0.1").unwrap();
    let mut backend = LinuxCommandBackend;
    backend.run(&operations[0].apply).unwrap();
    let installed = fs::read_to_string(&path).unwrap();
    assert!(installed.starts_with("# Managed temporarily by Peerward\nnameserver 10.7.0.1\n"));
    assert!(installed.contains("search old.test"));
    backend.run(&operations[0].rollback).unwrap();
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "search old.test\nnameserver 192.0.2.53\noptions edns0\n"
    );

    backend.run(&operations[0].apply).unwrap();
    fs::write(&path, "nameserver 203.0.113.8\n").unwrap();
    assert!(matches!(
        backend.run(&operations[0].rollback),
        Err(PlatformError::OwnershipConflict)
    ));
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        "nameserver 203.0.113.8\n"
    );
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn resolver_input_is_rejected_before_an_oversized_sparse_file_is_read() {
    let directory = std::env::temp_dir().join(format!("peerward-resolv-bound-{}", Uuid::new_v4()));
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join("resolv.conf");
    fs::File::create(&path)
        .unwrap()
        .set_len((MAX_RESOLV_CONF_BYTES + 1) as u64)
        .unwrap();

    assert!(resolv_conf_operations(&path, "10.7.0.1").is_err());
    assert!(read_regular_bounded(&path, MAX_RESOLV_CONF_BYTES as u64).is_err());
    fs::remove_dir_all(directory).unwrap();
}

#[test]
fn dual_stack_tun_installs_and_recovers_both_addresses_and_refuses_missing_family() {
    let mut intent = config();
    intent.secondary_address = Some("fd07::2/128".parse().unwrap());
    intent.routes.push("fd07::/64".parse().unwrap());
    let mut coordinator = StateCoordinator::new(MockBackend::default());
    coordinator.apply(&intent).unwrap();
    let backend = coordinator.into_backend().unwrap();
    for action in ["add", "del"] {
        assert!(backend.calls.iter().any(|call| call.program == "ip"
            && call.arguments == ["address", action, "fd07::2/128", "dev", "pw-test0"]));
        assert!(backend.calls.iter().any(|call| call.program == "ip"
            && call.arguments == ["route", action, "fd07::/64", "dev", "pw-test0"]));
    }
    intent.secondary_address = None;
    assert!(validate_config(&intent).is_err());
    intent.secondary_address = Some("10.7.0.3/32".parse().unwrap());
    assert!(validate_config(&intent).is_err());
}
