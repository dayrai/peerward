use std::collections::{BTreeMap, VecDeque};

mod wire;
use wire::{
    build_tcp_reply, build_tcp_reset, build_udp_reply, error_reply, initial_sequence, parse_tcp,
    parse_udp, read_u16, segment_tcp_response,
};

const UDP_PROTOCOL: u8 = 17;
const UDP_HEADER: usize = 8;
const TCP_PROTOCOL: u8 = 6;
const TCP_HEADER: usize = 20;
const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
const MAX_TCP_FLOWS: usize = 128;
const MAX_PENDING_QUERIES: usize = 128;
const MAX_TCP_DNS_FRAME: usize = 65_537;
const MAX_DNS_MESSAGE: usize = 65_535;

/// Upstream transport required for a DNS query extracted from the Android TUN.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TunDnsTransport {
    Udp = 1,
    Tcp = 2,
}

/// One bounded result from the platform-neutral TUN DNS state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunDnsDecision {
    /// Packet is unrelated to the configured virtual DNS gateways.
    Pass,
    /// Packets must be written back to the TUN without using an upstream socket.
    Replies(Vec<Vec<u8>>),
    /// Kotlin must resolve exactly this query and return it with the opaque token.
    Resolve {
        token: u64,
        transport: TunDnsTransport,
        source: Vec<u8>,
        query: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TcpKey {
    source: Vec<u8>,
    destination: Vec<u8>,
    source_port: u16,
}

struct TcpFlow {
    client_next: u32,
    server_next: u32,
    input: Vec<u8>,
    last_response: Option<Vec<u8>>,
    response_start: Option<u32>,
}

#[derive(Clone)]
struct UdpRequest {
    version: u8,
    ip_header_length: usize,
    source: Vec<u8>,
    destination: Vec<u8>,
    source_port: u16,
    destination_port: u16,
    payload: Vec<u8>,
}

#[derive(Clone)]
struct TcpRequest {
    version: u8,
    source: Vec<u8>,
    destination: Vec<u8>,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    flags: u8,
    payload: Vec<u8>,
}

enum PendingQuery {
    Udp(UdpRequest),
    Tcp {
        key: TcpKey,
        request: TcpRequest,
        query: Vec<u8>,
    },
}

/// Rust-owned, bounded UDP/TCP DNS interception state for the Android TUN.
///
/// No endpoint, socket, descriptor, or resolver crosses this boundary. The platform
/// adapter receives only a query plus an opaque token and returns one bounded answer.
pub struct TunDnsProxy {
    servers: Vec<Vec<u8>>,
    mtu: usize,
    tcp_flows: BTreeMap<TcpKey, TcpFlow>,
    flow_order: VecDeque<TcpKey>,
    pending: BTreeMap<u64, PendingQuery>,
    next_token: u64,
}

impl TunDnsProxy {
    /// Creates a proxy for one or more canonical IPv4/IPv6 gateway addresses.
    ///
    /// # Errors
    ///
    /// Returns [`crate::MobileError::InvalidInput`] for an empty, duplicate-only,
    /// oversized, non-IP server list or an invalid TUN MTU.
    pub fn new(servers: Vec<Vec<u8>>, mtu: usize) -> Result<Self, crate::MobileError> {
        if servers.is_empty()
            || servers.len() > 8
            || mtu < 576
            || mtu > u16::MAX.into()
            || servers
                .iter()
                .any(|address| !matches!(address.len(), 4 | 16))
        {
            return Err(crate::MobileError::InvalidInput);
        }
        let mut canonical = servers;
        canonical.sort();
        canonical.dedup();
        Ok(Self {
            servers: canonical,
            mtu,
            tcp_flows: BTreeMap::new(),
            flow_order: VecDeque::new(),
            pending: BTreeMap::new(),
            next_token: 1,
        })
    }

    /// Consumes one complete TUN packet and returns a bounded platform action.
    ///
    /// # Errors
    ///
    /// Returns an error when the packet exceeds the wire bound or the pending
    /// resolver table is full.
    pub fn inspect(&mut self, packet: &[u8]) -> Result<TunDnsDecision, crate::MobileError> {
        if packet.len() > u16::MAX.into() {
            return Err(crate::MobileError::InvalidInput);
        }
        let protocol = match packet.first().map(|byte| byte >> 4) {
            Some(4) => packet.get(9).copied(),
            Some(6) => packet.get(6).copied(),
            _ => None,
        };
        if protocol == Some(TCP_PROTOCOL) {
            return self.inspect_tcp(packet);
        }
        let Some(request) = parse_udp(packet) else {
            return Ok(TunDnsDecision::Pass);
        };
        if !self.is_dns_target(&request.destination, request.destination_port) {
            return Ok(TunDnsDecision::Pass);
        }
        self.issue(
            PendingQuery::Udp(request.clone()),
            TunDnsTransport::Udp,
            request.source,
            request.payload,
        )
    }

    /// Completes one exact query once and returns packets to write to the TUN.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown/duplicate token, an oversized response,
    /// or a TCP flow that was invalidated before completion.
    pub fn complete(
        &mut self,
        token: u64,
        response: &[u8],
    ) -> Result<Vec<Vec<u8>>, crate::MobileError> {
        if token == 0 || response.len() > MAX_DNS_MESSAGE {
            return Err(crate::MobileError::InvalidInput);
        }
        let pending = self
            .pending
            .remove(&token)
            .ok_or(crate::MobileError::InvalidState)?;
        Ok(match pending {
            PendingQuery::Udp(request) => {
                let fallback;
                let dns = if response.is_empty() {
                    fallback = error_reply(&request.payload, 2, false);
                    &fallback
                } else if response.len() + request.ip_header_length + UDP_HEADER > self.mtu {
                    fallback = error_reply(&request.payload, 0, true);
                    &fallback
                } else {
                    response
                };
                vec![build_udp_reply(&request, dns)]
            }
            PendingQuery::Tcp {
                key,
                request,
                query,
            } => {
                let fallback;
                let dns = if response.is_empty() {
                    fallback = error_reply(&query, 2, false);
                    &fallback
                } else {
                    response
                };
                let mut framed = Vec::with_capacity(dns.len() + 2);
                framed
                    .extend_from_slice(&u16::try_from(dns.len()).unwrap_or(u16::MAX).to_be_bytes());
                framed.extend_from_slice(dns);
                let flow = self
                    .tcp_flows
                    .get_mut(&key)
                    .ok_or(crate::MobileError::InvalidState)?;
                flow.last_response = Some(framed.clone());
                flow.response_start = Some(flow.server_next);
                segment_tcp_response(self.mtu, &request, flow, &framed, flow.server_next, true)
            }
        })
    }

    #[allow(clippy::too_many_lines)]
    fn inspect_tcp(&mut self, packet: &[u8]) -> Result<TunDnsDecision, crate::MobileError> {
        let Some(request) = parse_tcp(packet) else {
            return Ok(TunDnsDecision::Pass);
        };
        if !self.is_dns_target(&request.destination, request.destination_port) {
            return Ok(TunDnsDecision::Pass);
        }
        let key = TcpKey {
            source: request.source.clone(),
            destination: request.destination.clone(),
            source_port: request.source_port,
        };
        if request.flags & TCP_RST != 0 {
            self.remove_flow(&key);
            return Ok(TunDnsDecision::Replies(Vec::new()));
        }
        if request.flags & TCP_SYN != 0 && request.flags & TCP_ACK == 0 {
            self.insert_flow(key.clone(), &request);
            let flow = self.tcp_flows.get(&key).expect("flow was just inserted");
            return Ok(TunDnsDecision::Replies(vec![build_tcp_reply(
                &request,
                flow.server_next.wrapping_sub(1),
                flow.client_next,
                TCP_SYN | TCP_ACK,
                &[],
            )]));
        }
        let Some(flow) = self.tcp_flows.get_mut(&key) else {
            return Ok(TunDnsDecision::Replies(vec![build_tcp_reset(&request)]));
        };
        if request.flags & TCP_FIN != 0 {
            flow.client_next = request.sequence.wrapping_add(1);
            let reply = build_tcp_reply(
                &request,
                flow.server_next,
                flow.client_next,
                TCP_FIN | TCP_ACK,
                &[],
            );
            self.remove_flow(&key);
            return Ok(TunDnsDecision::Replies(vec![reply]));
        }
        if request.payload.is_empty() {
            return Ok(TunDnsDecision::Replies(Vec::new()));
        }
        if request.sequence != flow.client_next {
            let replies = if let Some(last) = flow.last_response.clone() {
                segment_tcp_response(
                    self.mtu,
                    &request,
                    flow,
                    &last,
                    flow.response_start.unwrap_or(flow.server_next),
                    false,
                )
            } else {
                vec![build_tcp_reply(
                    &request,
                    flow.server_next,
                    flow.client_next,
                    TCP_ACK,
                    &[],
                )]
            };
            return Ok(TunDnsDecision::Replies(replies));
        }
        if flow.input.len() + request.payload.len() > MAX_TCP_DNS_FRAME {
            self.remove_flow(&key);
            return Ok(TunDnsDecision::Replies(vec![build_tcp_reset(&request)]));
        }
        flow.input.extend_from_slice(&request.payload);
        flow.client_next = flow
            .client_next
            .wrapping_add(u32::try_from(request.payload.len()).unwrap_or(u32::MAX));
        if flow.input.len() < 2 {
            return Ok(TunDnsDecision::Replies(vec![build_tcp_reply(
                &request,
                flow.server_next,
                flow.client_next,
                TCP_ACK,
                &[],
            )]));
        }
        let query_length = usize::from(read_u16(&flow.input, 0));
        if !(12..=MAX_DNS_MESSAGE).contains(&query_length) || flow.input.len() < query_length + 2 {
            return Ok(TunDnsDecision::Replies(vec![build_tcp_reply(
                &request,
                flow.server_next,
                flow.client_next,
                TCP_ACK,
                &[],
            )]));
        }
        if flow.input.len() != query_length + 2 {
            self.remove_flow(&key);
            return Ok(TunDnsDecision::Replies(vec![build_tcp_reset(&request)]));
        }
        let query = flow.input[2..].to_vec();
        let source = request.source.clone();
        self.issue(
            PendingQuery::Tcp {
                key,
                request,
                query: query.clone(),
            },
            TunDnsTransport::Tcp,
            source,
            query,
        )
    }

    fn issue(
        &mut self,
        pending: PendingQuery,
        transport: TunDnsTransport,
        source: Vec<u8>,
        query: Vec<u8>,
    ) -> Result<TunDnsDecision, crate::MobileError> {
        if self.pending.len() >= MAX_PENDING_QUERIES || query.len() > MAX_DNS_MESSAGE {
            return Err(crate::MobileError::InvalidState);
        }
        let token = self.next_token;
        self.next_token = self
            .next_token
            .checked_add(1)
            .filter(|value| *value != 0)
            .unwrap_or(1);
        self.pending.insert(token, pending);
        Ok(TunDnsDecision::Resolve {
            token,
            transport,
            source,
            query,
        })
    }

    fn is_dns_target(&self, destination: &[u8], port: u16) -> bool {
        port == 53 && self.servers.iter().any(|server| server == destination)
    }

    fn insert_flow(&mut self, key: TcpKey, request: &TcpRequest) {
        if !self.tcp_flows.contains_key(&key)
            && self.tcp_flows.len() >= MAX_TCP_FLOWS
            && let Some(oldest) = self.flow_order.pop_front()
        {
            self.tcp_flows.remove(&oldest);
        }
        self.flow_order.retain(|candidate| candidate != &key);
        self.flow_order.push_back(key.clone());
        let initial = initial_sequence(&key);
        self.tcp_flows.insert(
            key,
            TcpFlow {
                client_next: request.sequence.wrapping_add(1),
                server_next: initial.wrapping_add(1),
                input: Vec::new(),
                last_response: None,
                response_start: None,
            },
        );
    }

    fn remove_flow(&mut self, key: &TcpKey) {
        self.tcp_flows.remove(key);
        self.flow_order.retain(|candidate| candidate != key);
    }
}

#[cfg(test)]
mod tests;
