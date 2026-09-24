//! Repeatable component measurement, not a network capacity claim.
//!
//! cargo run --release -p peerward-peer-core --example state-table -- identity 16384 100000 5
//! Replace `identity` with `packet` to measure the shared packet firewall.
use std::{collections::BTreeMap, hint::black_box, time::Instant};

use peerward_dataplane::{Action as PacketAction, Firewall, ParsedPacket};
use peerward_policy::{Action, Evaluator, FlowKey, Packet, PeerDescriptor, Policy};
use peerward_types::{IpProtocol, MeshId, PeerId};

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    assert_eq!(
        args.len(),
        4,
        "usage: state-table identity|packet FLOWS PACKETS ROUNDS"
    );
    let flows: u16 = args[1].parse().expect("flows must be 1..65535");
    let packets: u32 = args[2].parse().expect("invalid packet count");
    let rounds: u16 = args[3].parse().expect("invalid round count");
    assert!(flows > 0 && packets > 0 && rounds > 0);
    assert!(matches!(args[0].as_str(), "identity" | "packet"));
    let mesh = MeshId::new();
    let source = PeerDescriptor {
        id: PeerId::new(),
        address: "10.0.0.1".parse().unwrap(),
        labels: BTreeMap::new(),
    };
    let destination = PeerDescriptor {
        id: PeerId::new(),
        address: "10.0.0.2".parse().unwrap(),
        labels: BTreeMap::new(),
    };
    for round in 1..=rounds {
        let mut identity = Evaluator::new(
            mesh,
            Policy::new(1, Action::Allow, vec![]),
            usize::from(flows),
            64,
            10,
        );
        let firewall = Firewall::new(1, PacketAction::Allow, vec![], usize::from(flows), 1);
        let mut packet = ParsedPacket {
            source: source.address,
            destination: destination.address,
            protocol: 17,
            source_port: Some(1),
            destination_port: Some(443),
            tcp_flags: None,
            icmp: None,
            fragment: None,
            packet_len: 28,
            related_flow: None,
        };
        let mut evaluate = |port: u16, now: u64| {
            packet.source_port = Some(port);
            if args[0] == "packet" {
                assert_eq!(
                    black_box(firewall.evaluate(black_box(&packet), now)).action,
                    PacketAction::Allow
                );
            } else {
                let flow = FlowKey {
                    source: source.address,
                    destination: destination.address,
                    protocol: IpProtocol::UDP,
                    source_port: Some(port),
                    destination_port: Some(443),
                };
                assert_eq!(
                    black_box(identity.evaluate(
                        black_box(&Packet {
                            mesh_id: mesh,
                            source: &source,
                            destination: &destination,
                            flow,
                            initiating: true,
                            related_flow: None,
                            fragment_of: None,
                        }),
                        now
                    ))
                    .action,
                    Action::Allow
                );
            }
        };
        for port in 1..=flows {
            evaluate(port, 1);
        }
        let start = Instant::now();
        for index in 0..packets {
            let port = u16::try_from(index % u32::from(flows) + 1).unwrap();
            // Advance every 10k packets; a full sweep remains inside the UDP idle timeout.
            evaluate(port, 2 + u64::from(index / 10_000));
        }
        let elapsed = start.elapsed().as_nanos();
        let retained = if args[0] == "packet" {
            firewall.state_len()
        } else {
            identity.state_len()
        };
        assert_eq!(retained, usize::from(flows));
        println!(
            "{{\"engine\":\"{}\",\"flows\":{flows},\"packets\":{packets},\"round\":{round},\"elapsed_ns\":{elapsed}}}",
            args[0]
        );
    }
}
