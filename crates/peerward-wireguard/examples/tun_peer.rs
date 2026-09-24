//! Isolated engine qualification harness; no Control/ACL or production enrollment.
#[cfg(target_os = "linux")]
use {
    base64::{Engine as _, engine::general_purpose::STANDARD},
    peerward_wireguard::{Engine, Event, Ingress, Limits},
    std::{
        net::SocketAddr,
        time::{Duration, Instant},
    },
    tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        net::UdpSocket,
    },
    x25519_dalek::StaticSecret,
    zeroize::Zeroizing,
};

#[cfg(target_os = "linux")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 6 {
        return Err(
            "usage: tun_peer INTERFACE PRIVATE_KEY_FILE PEER_PUBLIC_KEY_FILE LISTEN ENDPOINT"
                .into(),
        );
    }
    let encoded = Zeroizing::new(std::fs::read_to_string(&args[2])?);
    let private = Zeroizing::new(STANDARD.decode(encoded.trim())?);
    let private = Zeroizing::new(<[u8; 32]>::try_from(private.as_slice())?);
    let public: [u8; 32] = STANDARD
        .decode(std::fs::read_to_string(&args[3])?.trim())?
        .as_slice()
        .try_into()?;
    let mut engine = Engine::new(StaticSecret::from(*private), Limits::default())?;
    engine.install(public)?;
    let udp = UdpSocket::bind(&args[4]).await?;
    let endpoint: SocketAddr = args[5].parse()?;
    let tun = tokio_tun::TunBuilder::new()
        .name(&args[1])
        .build()?
        .pop()
        .ok_or("TUN not created")?;
    let (mut input, mut output) = tokio::io::split(tun);
    let mut packets = vec![0; 9000];
    let mut datagrams = vec![0; 10_000];
    let mut timer = tokio::time::interval(Duration::from_millis(100));
    let mut transmitted = 0_u64;
    let mut received = 0_u64;
    let mut handshakes = 0_u64;
    let mut data_sessions = std::collections::HashSet::new();
    let mut received_sessions = std::collections::HashSet::new();
    eprintln!("TUN ready: {}", args[1]);
    loop {
        let (events, destination) = tokio::select! {
            result = input.read(&mut packets) => {
                let length = result?;
                (engine.send(&public, &packets[..length], Instant::now(), |_, _| true)?, endpoint)
            }
            result = udp.recv_from(&mut datagrams) => {
                let (length, source) = result?;
                match engine.receive(Ingress::Direct(source), &datagrams[..length]) {
                    Ok(events) => {
                        if datagrams[..length].starts_with(&[4, 0, 0, 0]) {
                            received_sessions.insert(u32::from_le_bytes(datagrams[4..8].try_into()?));
                        }
                        (events, source)
                    }
                    Err(error) => { eprintln!("rejected datagram: {error}"); continue; }
                }
            }
            _ = timer.tick() => (engine.tick(Instant::now(), |_, _| true), endpoint),
            _ = tokio::signal::ctrl_c() => break,
        };
        for event in events {
            match event {
                Event::Network { packet, .. } => {
                    if matches!(packet[0], 1 | 2) {
                        handshakes += 1;
                    }
                    if packet[0] == 4 {
                        data_sessions.insert(u32::from_le_bytes(packet[4..8].try_into()?));
                    }
                    udp.send_to(&packet, destination).await?;
                    transmitted += 1;
                }
                Event::Plaintext { packet, .. } => {
                    output.write_all(&packet).await?;
                    received += 1;
                }
            }
        }
    }
    eprintln!(
        "engine harness: {transmitted} WG datagrams sent, {received} IP packets received, {handshakes} handshake messages sent"
    );
    eprintln!("{} data sessions used", data_sessions.len());
    eprintln!(
        "{} authenticated receiving sessions used",
        received_sessions.len()
    );
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("The TUN qualification harness requires Linux.");
    std::process::exit(1);
}
