#[derive(Default)]
struct EndpointDialer {
    preferred: Option<String>,
    failures: BTreeMap<String, u32>,
}

impl EndpointDialer {
    async fn connect(
        &mut self,
        endpoints: &[NetworkEndpoint],
        options: &peerward_carrier::ClientOptions,
    ) -> Result<BoxStream, std::io::Error> {
        validate_endpoint_list(endpoints).map_err(|_| invalid_endpoint())?;
        self.failures
            .retain(|endpoint, _| endpoints.iter().any(|item| item.as_str() == endpoint));
        let mut ordered = endpoints.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|endpoint| {
            (
                endpoint.carrier_priority(),
                usize::from(self.preferred.as_deref() != Some(endpoint.as_str())),
                self.failures.get(endpoint.as_str()).copied().unwrap_or(0),
            )
        });
        let mut tasks = tokio::task::JoinSet::new();
        for (index, endpoint) in ordered.into_iter().filter(|endpoint| options.http_connect_proxy.is_none() || endpoint.is_wss()).enumerate() {
            let endpoint = endpoint.clone(); let options = options.clone();
            tasks.spawn(async move {
                tokio::time::sleep(Duration::from_millis(u64::try_from(index).unwrap_or(16) * 250)).await;
                let result = tokio::time::timeout(Duration::from_secs(8), connect_happy_eyeballs(&endpoint, &options)).await
                    .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()));
                (endpoint, result)
            });
        }
        let mut last_error = None;
        while let Some(result) = tasks.join_next().await {
            let Ok((endpoint, result)) = result else { continue; };
            match result {
                Ok(stream) => {
                    tasks.abort_all();
                    self.preferred = Some(endpoint.to_string());
                    self.failures.insert(endpoint.to_string(), 0);
                    return Ok(stream);
                }
                Err(error) => {
                    self.failures.entry(endpoint.to_string())
                        .and_modify(|failures| *failures = failures.saturating_add(1)).or_insert(1);
                    last_error = Some(error);
                }
            }
        }
        Err(last_error.unwrap_or_else(invalid_endpoint))
    }
}

async fn connect_happy_eyeballs(endpoint: &NetworkEndpoint, options: &peerward_carrier::ClientOptions) -> Result<BoxStream, std::io::Error> {
    let resolved = tokio::net::lookup_host(options.dial_endpoint(endpoint)?.authority()).await?;
    let mut ipv6 = VecDeque::new();
    let mut ipv4 = VecDeque::new();
    for address in resolved.take(16) {
        let family = if address.is_ipv6() { &mut ipv6 } else { &mut ipv4 };
        if !family.contains(&address) {
            family.push_back(address);
        }
    }
    let mut addresses = Vec::with_capacity(ipv6.len() + ipv4.len());
    while !ipv6.is_empty() || !ipv4.is_empty() {
        if let Some(address) = ipv6.pop_front() {
            addresses.push(address);
        }
        if let Some(address) = ipv4.pop_front() {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        return Err(invalid_endpoint());
    }
    let (sender, mut receiver) = mpsc::channel(addresses.len());
    let mut tasks = tokio::task::JoinSet::new();
    for (index, address) in addresses.into_iter().enumerate() {
        let sender = sender.clone();
        let endpoint = endpoint.clone();
        let options = options.clone();
        tasks.spawn(async move {
            tokio::time::sleep(Duration::from_millis(
                u64::try_from(index).unwrap_or(u64::MAX).saturating_mul(250),
            ))
            .await;
            let result = tokio::time::timeout(Duration::from_secs(5), async {
                if endpoint.is_quic() {
                    let local = if address.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
                    return Ok(peerward_carrier::quic::connect(std::net::UdpSocket::bind(local)?, address, &endpoint.host(), &options).await?.into_stream());
                }
                let socket = TcpStream::connect(address).await?;
                socket.set_nodelay(true)?;
                peerward_carrier::client(Box::new(socket), &endpoint, &options).await
            })
                .await
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))
                .and_then(std::convert::identity);
            let _ = sender.send(result).await;
        });
    }
    drop(sender);
    let mut last_error = None;
    while let Some(result) = receiver.recv().await {
        match result {
            Ok(stream) => {
                tasks.abort_all();
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(invalid_endpoint))
}

fn invalid_endpoint() -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid Relay endpoint")
}
