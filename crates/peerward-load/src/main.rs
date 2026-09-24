use std::{
    path::PathBuf,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use clap::Parser;
use peerward_wire::{HandshakePayload, PROTOCOL_MAJOR, Record, StreamTransport};
use prost::Message;
use rand::{RngCore, rngs::OsRng};
use serde::Serialize;
use x25519_dalek::{PublicKey, StaticSecret};

const MAX_PEERS: usize = 10_000;
const MAX_TOTAL_RECORDS: usize = 10_000_000;

#[derive(Debug, Parser)]
#[command(name = "peerward-load", version, about)]
struct Arguments {
    /// Number of independent Noise IK session pairs (capacity tiers are 100/1000/10000).
    #[arg(long)]
    peers: usize,
    /// Encrypted IPv4 records sent and authenticated in each session generation.
    #[arg(long, default_value_t = 100)]
    messages_per_peer: usize,
    /// Fresh Noise IK replacements performed after the initial session.
    #[arg(long, default_value_t = 1)]
    reconnect_rounds: usize,
    /// Plaintext packet size.
    #[arg(long, default_value_t = 1_200)]
    payload_bytes: usize,
    /// Worker threads. Defaults to available parallelism.
    #[arg(long)]
    workers: Option<usize>,
    /// Operator-supplied hardware description recorded verbatim.
    #[arg(long, default_value = "unspecified developer host")]
    hardware: String,
    /// Operator-supplied traffic model label recorded verbatim.
    #[arg(long, default_value = "uniform component traffic")]
    traffic_model: String,
    /// JSON report destination. Standard output is used when omitted.
    #[arg(long)]
    output: Option<PathBuf>,
}

#[derive(Debug)]
struct WorkerMeasurements {
    handshakes_micros: Vec<u64>,
    records_micros: Vec<u64>,
    failures: u64,
}

#[derive(Serialize)]
struct Report {
    schema_version: u8,
    status: &'static str,
    scope: &'static str,
    declared_tier: String,
    peerward_version: &'static str,
    protocol_major: u32,
    noise_suite: &'static str,
    hardware: String,
    platform: String,
    traffic_model: String,
    peers: usize,
    workers: usize,
    reconnect_rounds: usize,
    messages_per_peer: usize,
    payload_bytes: usize,
    elapsed_millis: u64,
    successful_handshakes: usize,
    successful_records: usize,
    failures: u64,
    handshakes_per_second: f64,
    records_per_second: f64,
    handshake_latency_micros: Percentiles,
    record_latency_micros: Percentiles,
    scenarios: Scenarios,
    limitations: Vec<&'static str>,
}

#[derive(Serialize)]
struct Percentiles {
    p50: u64,
    p95: u64,
    p99: u64,
}

#[derive(Serialize)]
struct Scenarios {
    noise_ik_and_framing: &'static str,
    credential_verification: &'static str,
    deployed_relay_forwarding: &'static str,
    relay_failure: &'static str,
    postgresql_failure_recovery: &'static str,
    multi_region: &'static str,
}

fn main() {
    let arguments = Arguments::parse();
    match run(&arguments) {
        Ok(report) => {
            let encoded = serde_json::to_string_pretty(&report).expect("report serialization");
            if let Some(path) = arguments.output {
                if let Err(error) = std::fs::write(&path, format!("{encoded}\n")) {
                    eprintln!("cannot write {}: {error}", path.display());
                    std::process::exit(1);
                }
            } else {
                println!("{encoded}");
            }
        }
        Err(error) => {
            eprintln!("load run rejected: {error}");
            std::process::exit(2);
        }
    }
}

fn run(arguments: &Arguments) -> Result<Report, String> {
    if !(1..=MAX_PEERS).contains(&arguments.peers)
        || arguments.messages_per_peer == 0
        || arguments.reconnect_rounds > 100
        || !(20..=60_000).contains(&arguments.payload_bytes)
        || arguments
            .peers
            .checked_mul(arguments.messages_per_peer)
            .and_then(|records| records.checked_mul(arguments.reconnect_rounds + 1))
            .is_none_or(|records| records > MAX_TOTAL_RECORDS)
    {
        return Err("peers, reconnects, payload, or total record count exceeds its bound".into());
    }
    let workers = arguments
        .workers
        .unwrap_or_else(|| thread::available_parallelism().map_or(1, usize::from));
    if !(1..=256).contains(&workers) {
        return Err("workers must be within 1..=256".into());
    }
    let workers = workers.min(arguments.peers);
    let started = Instant::now();
    let (sender, receiver) = mpsc::channel();
    thread::scope(|scope| {
        for worker in 0..workers {
            let sender = sender.clone();
            scope.spawn(move || {
                let mut measurements = WorkerMeasurements {
                    handshakes_micros: Vec::new(),
                    records_micros: Vec::new(),
                    failures: 0,
                };
                for peer in (worker..arguments.peers).step_by(workers) {
                    if run_peer(peer, arguments, &mut measurements).is_err() {
                        measurements.failures = measurements.failures.saturating_add(1);
                    }
                }
                let _ = sender.send(measurements);
            });
        }
    });
    drop(sender);
    let mut handshakes = Vec::new();
    let mut records = Vec::new();
    let mut failures = 0_u64;
    for worker in receiver {
        handshakes.extend(worker.handshakes_micros);
        records.extend(worker.records_micros);
        failures = failures.saturating_add(worker.failures);
    }
    let elapsed = started.elapsed();
    let seconds = elapsed.as_secs_f64().max(f64::EPSILON);
    let successful_handshakes = handshakes.len();
    let successful_records = records.len();
    let handshake_rate = f64::from(u32::try_from(successful_handshakes).unwrap_or(u32::MAX));
    let record_rate = f64::from(u32::try_from(successful_records).unwrap_or(u32::MAX));
    Ok(Report {
        schema_version: 1,
        status: "unverified",
        scope: "noise_component",
        declared_tier: match arguments.peers {
            100 | 1_000 | 10_000 => arguments.peers.to_string(),
            _ => "custom".into(),
        },
        peerward_version: env!("CARGO_PKG_VERSION"),
        protocol_major: PROTOCOL_MAJOR,
        noise_suite: peerward_wire::IK_SUITE,
        hardware: arguments.hardware.clone(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        traffic_model: arguments.traffic_model.clone(),
        peers: arguments.peers,
        workers,
        reconnect_rounds: arguments.reconnect_rounds,
        messages_per_peer: arguments.messages_per_peer,
        payload_bytes: arguments.payload_bytes,
        elapsed_millis: millis(elapsed),
        successful_handshakes,
        successful_records,
        failures,
        handshakes_per_second: handshake_rate / seconds,
        records_per_second: record_rate / seconds,
        handshake_latency_micros: percentiles(&mut handshakes),
        record_latency_micros: percentiles(&mut records),
        scenarios: Scenarios {
            noise_ik_and_framing: "passed",
            credential_verification: "missing",
            deployed_relay_forwarding: "missing",
            relay_failure: "missing",
            postgresql_failure_recovery: "missing",
            multi_region: "missing",
        },
        limitations: vec![
            "This exercises the production Noise IK and encrypted record implementations without a deployed Relay or PostgreSQL.",
            "It cannot satisfy the stable capacity gate; use it to size generators before an end-to-end run.",
            "CPU, RAM, Relay bandwidth, PostgreSQL TPS/WAL, and recovery time require external collectors in the end-to-end harness.",
        ],
    })
}

fn run_peer(
    peer: usize,
    arguments: &Arguments,
    measurements: &mut WorkerMeasurements,
) -> Result<(), peerward_wire::WireError> {
    for generation in 0..=arguments.reconnect_rounds {
        let handshake_started = Instant::now();
        let (mut sender, mut receiver) = open_noise_session(peer, generation)?;
        measurements
            .handshakes_micros
            .push(micros(handshake_started.elapsed()));
        let packet = ipv4_packet(arguments.payload_bytes, peer, generation);
        for _ in 0..arguments.messages_per_peer {
            let record_started = Instant::now();
            let frame = sender.encode(&Record::Ipv4(packet.clone()))?;
            match receiver.decode(&frame)? {
                Record::Ipv4(opened) if opened == packet => {}
                _ => return Err(peerward_wire::WireError::KindMismatch),
            }
            measurements
                .records_micros
                .push(micros(record_started.elapsed()));
        }
    }
    Ok(())
}

fn open_noise_session(
    peer: usize,
    generation: usize,
) -> Result<(StreamTransport, StreamTransport), peerward_wire::WireError> {
    let mut initiator_private = [0_u8; 32];
    let mut responder_private = [0_u8; 32];
    OsRng.fill_bytes(&mut initiator_private);
    OsRng.fill_bytes(&mut responder_private);
    let responder_public = PublicKey::from(&StaticSecret::from(responder_private)).to_bytes();
    let preface = peerward_wire::RelayPreface {
        mesh_id: peerward_types::MeshId::new(),
        target: peerward_types::RelayId::new(),
        source: None,
    };
    let preface = peerward_wire::RelayPreface::decode(&preface.encode())?;
    let mut initiator = preface.handshake(true, &initiator_private, Some(&responder_public))?;
    let mut responder = preface.handshake(false, &responder_private, None)?;
    let hello = HandshakePayload {
        major: PROTOCOL_MAJOR,
        minor: 0,
        capabilities: peerward_wire::SUPPORTED_CAPABILITIES
            | peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY,
        credential: format!("component-peer-{peer}").into_bytes(),
        attachment_id: attachment(peer, generation).to_vec(),
    };
    let welcome = HandshakePayload {
        major: PROTOCOL_MAJOR,
        minor: 0,
        capabilities: peerward_wire::SUPPORTED_CAPABILITIES
            | peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY,
        credential: b"component-relay".to_vec(),
        attachment_id: attachment(generation, peer).to_vec(),
    };
    let mut first = vec![0; 65_535];
    let first_len = initiator.write_message(&hello.encode_to_vec(), &mut first)?;
    let mut opened = vec![0; 65_535];
    let opened_len = responder.read_message(&first[..first_len], &mut opened)?;
    let decoded = HandshakePayload::decode(&opened[..opened_len])
        .map_err(peerward_wire::WireError::MalformedControl)?;
    decoded.negotiate(
        peerward_wire::SUPPORTED_CAPABILITIES | peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY,
    )?;
    let mut second = vec![0; 65_535];
    let second_len = responder.write_message(&welcome.encode_to_vec(), &mut second)?;
    let opened_len = initiator.read_message(&second[..second_len], &mut opened)?;
    let decoded = HandshakePayload::decode(&opened[..opened_len])
        .map_err(peerward_wire::WireError::MalformedControl)?;
    decoded.negotiate(
        peerward_wire::SUPPORTED_CAPABILITIES | peerward_wire::PRIMARY_ATTACHMENT_CAPABILITY,
    )?;
    Ok((
        StreamTransport::from_handshake(initiator, 0)?,
        StreamTransport::from_handshake(responder, 0)?,
    ))
}

fn attachment(first: usize, second: usize) -> [u8; 16] {
    let mut value = [0_u8; 16];
    value[..8].copy_from_slice(&u64::try_from(first).unwrap_or(u64::MAX).to_be_bytes());
    value[8..].copy_from_slice(&u64::try_from(second).unwrap_or(u64::MAX).to_be_bytes());
    value
}

fn ipv4_packet(length: usize, peer: usize, generation: usize) -> Vec<u8> {
    let mut packet = vec![0_u8; length];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(length).unwrap_or(u16::MAX).to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&u32::try_from(peer).unwrap_or(u32::MAX).to_be_bytes());
    packet[16..20].copy_from_slice(&u32::try_from(generation).unwrap_or(u32::MAX).to_be_bytes());
    packet
}

fn percentiles(values: &mut [u64]) -> Percentiles {
    values.sort_unstable();
    Percentiles {
        p50: percentile(values, 50),
        p95: percentile(values, 95),
        p99: percentile(values, 99),
    }
}

fn percentile(values: &[u64], percentile: usize) -> u64 {
    let index = values.len().saturating_mul(percentile).saturating_add(99) / 100;
    values.get(index.saturating_sub(1)).copied().unwrap_or(0)
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_report_cannot_be_mistaken_for_capacity_evidence() {
        let report = run(&Arguments {
            peers: 2,
            messages_per_peer: 3,
            reconnect_rounds: 1,
            payload_bytes: 64,
            workers: Some(2),
            hardware: "test".into(),
            traffic_model: "test".into(),
            output: None,
        })
        .unwrap();
        assert_eq!(report.status, "unverified");
        assert_eq!(report.scope, "noise_component");
        assert_eq!(report.successful_handshakes, 4);
        assert_eq!(report.successful_records, 12);
        assert_eq!(report.failures, 0);
        assert_eq!(report.scenarios.noise_ik_and_framing, "passed");
        assert_eq!(report.scenarios.deployed_relay_forwarding, "missing");
    }

    #[test]
    fn rejects_unbounded_work() {
        let result = run(&Arguments {
            peers: MAX_PEERS,
            messages_per_peer: 10_000,
            reconnect_rounds: 100,
            payload_bytes: 64,
            workers: Some(1),
            hardware: "test".into(),
            traffic_model: "test".into(),
            output: None,
        });
        assert!(result.is_err());
    }
}
