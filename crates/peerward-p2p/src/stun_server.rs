use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use tokio::{net::UdpSocket, sync::watch};

use crate::{STUN_MAGIC, stun::XOR_MAPPED_ADDRESS};

const MAX_CLIENTS: usize = 4096;
const MAX_PER_SECOND: u32 = 1000;
const MAX_PER_IP_SECOND: u32 = 10;

/// Minimal public Binding service used for address observation only.
/// Does not authenticate peers or reveal candidates to the control plane.
pub async fn serve_stun(
    socket: UdpSocket,
    mut shutdown: watch::Receiver<bool>,
) -> std::io::Result<()> {
    let mut limits = StunLimits::new(Instant::now());
    let mut request = [0_u8; 1024];
    loop {
        if *shutdown.borrow() {
            return Ok(());
        }
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { return Ok(()); }
            }
            received = socket.recv_from(&mut request) => {
                let (length, source) = received?;
                if !limits.allow(source.ip(), Instant::now()) { continue; }
                if let Some(response) = stun_binding_response(&request[..length], source) {
                    socket.send_to(&response, source).await?;
                }
            }
        }
    }
}

/// Answers an exact 20-byte unauthenticated Binding request. Unsupported
/// attribute-bearing requests are dropped, bounding amplification to 2.2x.
pub fn stun_binding_response(request: &[u8], observed: SocketAddr) -> Option<Vec<u8>> {
    if request.len() != 20
        || request[..4] != [0, 1, 0, 0]
        || request[4..8] != STUN_MAGIC.to_be_bytes()
        || observed.port() == 0
        || observed.ip().is_unspecified()
        || observed.ip().is_multicast()
    {
        return None;
    }
    let address = observed.ip().to_canonical();
    let size: u16 = if address.is_ipv4() { 8 } else { 20 };
    let mut bytes = Vec::with_capacity(44);
    bytes.extend_from_slice(&[1, 1]);
    bytes.extend_from_slice(&(size + 4).to_be_bytes());
    bytes.extend_from_slice(&request[4..20]);
    bytes.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
    bytes.extend_from_slice(&size.to_be_bytes());
    bytes.extend_from_slice(&[0, if address.is_ipv4() { 1 } else { 2 }]);
    bytes.extend_from_slice(&(observed.port() ^ 0x2112).to_be_bytes());
    match address {
        IpAddr::V4(ip) => {
            bytes.extend(ip.octets().iter().zip(&request[4..8]).map(|(a, b)| a ^ b));
        }
        IpAddr::V6(ip) => {
            bytes.extend(ip.octets().iter().zip(&request[4..20]).map(|(a, b)| a ^ b));
        }
    }
    Some(bytes)
}

struct StunLimits {
    period: Instant,
    total: u32,
    clients: HashMap<IpAddr, u32>,
}

impl StunLimits {
    fn new(now: Instant) -> Self {
        Self {
            period: now,
            total: 0,
            clients: HashMap::new(),
        }
    }

    fn allow(&mut self, ip: IpAddr, now: Instant) -> bool {
        if now.duration_since(self.period) >= Duration::from_secs(1) {
            self.period = now;
            self.total = 0;
            self.clients.clear();
        }
        if self.total >= MAX_PER_SECOND {
            return false;
        }
        // IPv6 privacy-address churn must not bypass the per-client limit.
        let ip = match ip.to_canonical() {
            IpAddr::V6(ip) => IpAddr::V6((u128::from(ip) & (u128::MAX << 64)).into()),
            ip @ IpAddr::V4(_) => ip,
        };
        if !self.clients.contains_key(&ip) && self.clients.len() >= MAX_CLIENTS {
            return false;
        }
        let count = self.clients.entry(ip).or_default();
        if *count >= MAX_PER_IP_SECOND {
            return false;
        }
        *count += 1;
        self.total += 1;
        true
    }
}

#[cfg(test)]
#[path = "stun_tests.rs"]
mod tests;
