/// Host underlay services needed by NAT discovery and future OS socket protection.
#[async_trait]
pub trait UnderlayNetwork: Send + Sync {
    /// Resolve transport bootstrap names. Protected adapters override this so a
    /// system DNS configuration pointing into the VPN cannot cause recursion.
    async fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, PlatformError> {
        Ok(tokio::net::lookup_host((host, port))
            .await?
            .take(16)
            .collect())
    }
    /// Binds a UDP socket outside the virtual tunnel.
    async fn bind_udp(&self, address: SocketAddr) -> Result<UdpSocket, PlatformError>;
    /// Binds an address to its actual interface. Test adapters may use normal source binding.
    async fn bind_udp_on(
        &self,
        address: SocketAddr,
        _interface: &str,
    ) -> Result<UdpSocket, PlatformError> {
        self.bind_udp(address).await
    }
    /// Connects a TCP stream outside the virtual tunnel.
    async fn connect_tcp(&self, address: SocketAddr) -> Result<TcpStream, PlatformError>;
    /// Returns the current default gateway used for PCP and NAT-PMP.
    async fn default_gateway(&self) -> Result<IpAddr, PlatformError>;
    /// Monotonic generation that changes when the underlay is replaced.
    fn network_changes(&self) -> watch::Receiver<u64>;
}

/// Linux underlay implementation used by direct-path mapping discovery.
#[derive(Debug, Clone)]
pub struct LinuxUnderlayNetwork {
    generation: std::sync::Arc<watch::Sender<u64>>,
    protected: bool,
}

impl Default for LinuxUnderlayNetwork {
    fn default() -> Self {
        let (generation, _) = watch::channel(0);
        let network = Self {
            generation: std::sync::Arc::new(generation),
            protected: false,
        };
        network.start_monitor();
        network
    }
}

impl LinuxUnderlayNetwork {
    /// Use for privileged packet runtimes. Mark before binding/connecting so existing
    /// control and direct sockets also survive subsequently enabling an exit.
    pub fn protected() -> Self {
        Self {
            protected: true,
            ..Self::default()
        }
    }
    /// Notifies lease managers after a route/address monitor observes replacement.
    pub fn notify_network_change(&self) {
        let next = self.generation.borrow().wrapping_add(1);
        self.generation.send_replace(next);
    }

    fn start_monitor(&self) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let generation = std::sync::Arc::downgrade(&self.generation);
        runtime.spawn(monitor_linux_underlay(generation));
    }

    /// Creates the production fingerprint fallback without a netlink listener.
    ///
    /// This is exposed only with the privileged-netns feature so integration
    /// tests can prove that a failed/unavailable listener does not stop change
    /// detection.
    #[cfg(feature = "privileged-netns")]
    pub fn polling_fallback_for_test() -> Self {
        let (generation, _) = watch::channel(0);
        let network = Self {
            generation: std::sync::Arc::new(generation),
            protected: false,
        };
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(monitor_linux_underlay_polling(std::sync::Arc::downgrade(
                &network.generation,
            )));
        }
        network
    }
}

#[async_trait]
impl UnderlayNetwork for LinuxUnderlayNetwork {
    async fn bind_udp(&self, address: SocketAddr) -> Result<UdpSocket, PlatformError> {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(address),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        if address.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        if self.protected {
            socket.set_mark(EXIT_UNDERLAY_MARK)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        Ok(UdpSocket::from_std(socket.into())?)
    }

    async fn bind_udp_on(
        &self,
        address: SocketAddr,
        interface: &str,
    ) -> Result<UdpSocket, PlatformError> {
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(address),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        if address.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        if self.protected {
            socket.set_mark(EXIT_UNDERLAY_MARK)?;
        }
        socket.bind_device(Some(interface.as_bytes()))?;
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        Ok(UdpSocket::from_std(socket.into())?)
    }

    async fn connect_tcp(&self, address: SocketAddr) -> Result<TcpStream, PlatformError> {
        let socket = if address.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        if self.protected {
            socket2::SockRef::from(&socket).set_mark(EXIT_UNDERLAY_MARK)?;
        }
        Ok(socket.connect(address).await?)
    }

    async fn default_gateway(&self) -> Result<IpAddr, PlatformError> {
        linux_default_gateway()
    }

    fn network_changes(&self) -> watch::Receiver<u64> {
        self.generation.subscribe()
    }
}

fn linux_network_fingerprint() -> u64 {
    use std::hash::{Hash as _, Hasher as _};

    let mut fingerprint = std::collections::hash_map::DefaultHasher::new();
    for path in [
        "/proc/net/route",
        "/proc/net/ipv6_route",
        "/proc/net/fib_trie",
        "/proc/net/if_inet6",
    ] {
        path.hash(&mut fingerprint);
        match read_regular_bounded(Path::new(path), MAX_KERNEL_TABLE_BYTES) {
            Ok(contents) => {
                if path == "/proc/net/fib_trie" {
                    // fib_trie also contains forwarding-trie bookkeeping that can
                    // settle after one logical route operation. Hash only the
                    // IPv4 local-address view; routes themselves are covered by
                    // /proc/net/route. This prevents delayed kernel housekeeping
                    // from producing a second underlay generation.
                    ipv4_local_addresses(&String::from_utf8_lossy(&contents))
                        .hash(&mut fingerprint);
                } else if path == "/proc/net/route" || path == "/proc/net/ipv6_route" {
                    stable_route_rows(
                        &String::from_utf8_lossy(&contents),
                        path.ends_with("ipv6_route"),
                    )
                    .hash(&mut fingerprint);
                } else {
                    contents.hash(&mut fingerprint);
                }
            }
            Err(error) => error.kind().hash(&mut fingerprint),
        }
    }
    fingerprint.finish()
}

fn stable_route_rows(routes: &str, ipv6: bool) -> std::collections::BTreeSet<Vec<&str>> {
    // Kernel route reference/use counters change during ordinary packet I/O.
    // Include route identity, gateway, flags, metrics and interface, not counters
    // or dump ordering; neither change invalidates a path or its MTU proof.
    routes
        .lines()
        .filter_map(|line| {
            let columns: Vec<_> = line.split_whitespace().collect();
            let (minimum, counters) = if ipv6 { (10, 6..8) } else { (11, 4..6) };
            if columns.len() < minimum || columns.first() == Some(&"Iface") {
                return None;
            }
            Some(
                columns
                    .into_iter()
                    .enumerate()
                    .filter_map(|(index, value)| (!counters.contains(&index)).then_some(value))
                    .collect(),
            )
        })
        .collect()
}

fn ipv4_local_addresses(fib_trie: &str) -> std::collections::BTreeSet<std::net::Ipv4Addr> {
    let mut addresses = std::collections::BTreeSet::new();
    let mut candidate = None;
    for line in fib_trie.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed
            .strip_prefix("|-- ")
            .or_else(|| trimmed.strip_prefix("+-- "))
            .and_then(|value| value.split_whitespace().next())
        {
            candidate = value.parse().ok();
        }
        if trimmed.contains(" host LOCAL")
            && let Some(address) = candidate
        {
            addresses.insert(address);
        }
    }
    addresses
}

fn linux_default_gateway() -> Result<IpAddr, PlatformError> {
    let ipv4_routes = read_text_bounded(Path::new("/proc/net/route"), MAX_KERNEL_TABLE_BYTES);
    if let Ok(routes) = &ipv4_routes
        && let Some(gateway) = parse_ipv4_default_gateway(routes)?
    {
        return Ok(IpAddr::V4(gateway));
    }
    let ipv6_routes = read_text_bounded(Path::new("/proc/net/ipv6_route"), MAX_KERNEL_TABLE_BYTES);
    if let Ok(routes) = &ipv6_routes
        && let Some(gateway) = parse_ipv6_default_gateway(routes)?
    {
        return Ok(IpAddr::V6(gateway));
    }
    if let (Err(ipv4_error), Err(_)) = (ipv4_routes, ipv6_routes) {
        return Err(PlatformError::Io(ipv4_error));
    }
    Err(PlatformError::Command("no default gateway".into()))
}

fn parse_ipv4_default_gateway(routes: &str) -> Result<Option<std::net::Ipv4Addr>, PlatformError> {
    let mut best = None;
    for line in routes.lines().skip(1) {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        if columns.len() < 7 || columns[1] != "00000000" {
            continue;
        }
        let flags = u16::from_str_radix(columns[3], 16)
            .map_err(|_| PlatformError::Command("invalid kernel route flags".into()))?;
        if flags & 0x0003 != 0x0003 {
            continue;
        }
        let raw = u32::from_str_radix(columns[2], 16)
            .map_err(|_| PlatformError::Command("invalid kernel gateway".into()))?;
        let address = std::net::Ipv4Addr::from(raw.to_le_bytes());
        let metric = columns[6]
            .parse::<u32>()
            .map_err(|_| PlatformError::Command("invalid kernel route metric".into()))?;
        if !address.is_unspecified() && best.is_none_or(|(best_metric, _)| metric < best_metric) {
            best = Some((metric, address));
        }
    }
    Ok(best.map(|(_, address)| address))
}

fn parse_ipv6_default_gateway(routes: &str) -> Result<Option<std::net::Ipv6Addr>, PlatformError> {
    let mut best = None;
    for line in routes.lines() {
        let columns = line.split_whitespace().collect::<Vec<_>>();
        if columns.len() < 10
            || columns[0] != "00000000000000000000000000000000"
            || columns[1] != "00"
        {
            continue;
        }
        let flags = u32::from_str_radix(columns[8], 16)
            .map_err(|_| PlatformError::Command("invalid IPv6 route flags".into()))?;
        if flags & 0x0003 != 0x0003 {
            continue;
        }
        let mut octets = [0_u8; 16];
        if columns[4].len() != 32 {
            return Err(PlatformError::Command("invalid IPv6 gateway".into()));
        }
        for (index, octet) in octets.iter_mut().enumerate() {
            *octet = u8::from_str_radix(&columns[4][index * 2..index * 2 + 2], 16)
                .map_err(|_| PlatformError::Command("invalid IPv6 gateway".into()))?;
        }
        let address = std::net::Ipv6Addr::from(octets);
        let metric = u32::from_str_radix(columns[5], 16)
            .map_err(|_| PlatformError::Command("invalid IPv6 route metric".into()))?;
        if !address.is_unspecified() && best.is_none_or(|(best_metric, _)| metric < best_metric) {
            best = Some((metric, address));
        }
    }
    Ok(best.map(|(_, address)| address))
}

fn advance_generation(generation: &watch::Sender<u64>) {
    let next = generation.borrow().wrapping_add(1);
    generation.send_replace(next);
}

const UNDERLAY_EVENT_QUIET_PERIOD: std::time::Duration = std::time::Duration::from_secs(1);

async fn wait_for_underlay_event_quiet_period(
    events: &mut tokio::sync::mpsc::Receiver<()>,
) -> bool {
    loop {
        match tokio::time::timeout(UNDERLAY_EVENT_QUIET_PERIOD, events.recv()).await {
            Ok(Some(())) => {}
            Ok(None) => return false,
            Err(_) => return true,
        }
    }
}

async fn monitor_linux_underlay(generation: std::sync::Weak<watch::Sender<u64>>) {
    let (events, mut event_receiver) = tokio::sync::mpsc::channel(1);
    let listener = tokio::spawn(netlink_listener_supervisor(events));
    let mut previous = linux_network_fingerprint();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        tokio::select! {
            _ = interval.tick() => {
                let Some(generation) = generation.upgrade() else {
                    listener.abort();
                    return;
                };
                let current = linux_network_fingerprint();
                if current != previous {
                    previous = current;
                    advance_generation(&generation);
                }
            }
            event = event_receiver.recv() => {
                if event.is_none() {
                    listener.abort();
                    return;
                }
                if !wait_for_underlay_event_quiet_period(&mut event_receiver).await {
                    listener.abort();
                    return;
                }
                let Some(generation) = generation.upgrade() else {
                    listener.abort();
                    return;
                };
                let current = linux_network_fingerprint();
                if current != previous {
                    previous = current;
                    advance_generation(&generation);
                }
            }
        }
    }
}

#[cfg(feature = "privileged-netns")]
async fn monitor_linux_underlay_polling(generation: std::sync::Weak<watch::Sender<u64>>) {
    let mut previous = linux_network_fingerprint();
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    interval.tick().await;
    loop {
        interval.tick().await;
        let Some(generation) = generation.upgrade() else {
            return;
        };
        let current = linux_network_fingerprint();
        if current != previous {
            previous = current;
            advance_generation(&generation);
        }
    }
}

async fn netlink_listener_supervisor(events: tokio::sync::mpsc::Sender<()>) {
    loop {
        if let Err(error) = listen_for_netlink_changes(&events).await {
            tracing::warn!(error = %error, "Linux underlay netlink listener failed; /proc polling remains active");
        }
        tokio::select! {
            () = events.closed() => return,
            () = tokio::time::sleep(std::time::Duration::from_secs(30)) => {}
        }
    }
}

async fn listen_for_netlink_changes(
    events: &tokio::sync::mpsc::Sender<()>,
) -> Result<(), PlatformError> {
    use futures_util::StreamExt as _;
    use rtnetlink::sys::AsyncSocket as _;

    let (mut connection, _, mut messages) = rtnetlink::new_connection()?;
    let groups = rtnetlink::constants::RTMGRP_LINK
        | rtnetlink::constants::RTMGRP_IPV4_IFADDR
        | rtnetlink::constants::RTMGRP_IPV4_ROUTE
        | rtnetlink::constants::RTMGRP_IPV6_IFADDR
        | rtnetlink::constants::RTMGRP_IPV6_ROUTE;
    connection
        .socket_mut()
        .socket_mut()
        .bind(&rtnetlink::sys::SocketAddr::new(0, groups))?;
    let worker = tokio::spawn(connection);
    loop {
        tokio::select! {
            () = events.closed() => {
                worker.abort();
                return Ok(());
            }
            message = messages.next() => {
                if message.is_none() {
                    worker.abort();
                    return Err(PlatformError::Command("rtnetlink event stream closed".into()));
                }
                if events.try_send(()).is_err() && events.is_closed() {
                    worker.abort();
                    return Ok(());
                }
            }
        }
    }
}
