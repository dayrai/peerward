async fn answer<P: PacketPolicy + ?Sized>(
    message: &[u8],
    source: IpAddr,
    tcp_client: bool,
    suffix: &str,
    network: ipnet::IpNet,
    upstreams: &[SocketAddr],
    directory: &Arc<RwLock<DirectPeerDirectory>>,
    services: &Arc<Mutex<RemoteServiceTable>>,
    firewall: &P,
    management: Option<&ManagedDns>,
) -> io::Result<Vec<u8>> {
    let question = parse_question(message)?;
    let managed = if let Some(management) = management {
        // Local listeners may receive loopback queries from the operating-system resolver.
        if !local_dns_source(
            source,
            management.local_address,
            management.secondary_address,
            management.proxy,
        ) {
            return Ok(response(message, &question, 5, None));
        }
        match management.core.lock().await.effective_dns(
            management.local_address,
            peerward_types::UnixTime(crate::packet::wall_clock_seconds()),
        ) {
            Ok(view) => Some(view),
            Err(_) => return Ok(response(message, &question, 2, None)),
        }
    } else {
        None
    };
    let source = management.map_or(source, |owner| owner.local_address);
    let local_owner = directory
        .read()
        .map_err(|_| invalid_dns())?
        .dns_by_address(source)
        .map(|record| record.peer_id);
    let delegated = managed
        .as_ref()
        .is_some_and(|(_, dns)| dns.delegates_mesh_child(&question.name, suffix));
    if !delegated && (question.name == suffix || question.name.ends_with(&format!(".{suffix}"))) {
        let Some(label) = local_label(&question.name, suffix) else {
            if let Some((_, dns)) = &managed
                && dns.records.contains_key(&question.name)
            {
                return Ok(managed_records(message, &question, dns, tcp_client));
            }
            return Ok(response(message, &question, 3, None));
        };
        let peer = directory
            .read()
            .map_err(|_| invalid_dns())?
            .dns_by_name_family(
                label,
                match question.qtype {
                    1 => Some(false),
                    28 => Some(true),
                    _ => None,
                },
            )
            .filter(|record| {
                (management.is_some() && local_owner == Some(record.peer_id))
                    || firewall_allows_peer_dns(firewall, source, record.address)
            });
        let address = if let Some(peer) = peer {
            Some(peer.address)
        } else {
            services
                .lock()
                .await
                .resolve_visible(label, source, |source, service| {
                    firewall_allows_service(firewall, source, service, 0)
                })
        };
        if address.is_none()
            && let Some((_, dns)) = &managed
            && dns.records.contains_key(&question.name)
        {
            return Ok(managed_records(message, &question, dns, tcp_client));
        }
        let known_peer = address.is_none()
            && directory
                .read()
                .map_err(|_| invalid_dns())?
                .dns_by_name(label)
                .is_some_and(|record| {
                    (management.is_some() && local_owner == Some(record.peer_id))
                        || firewall_allows_peer_dns(firewall, source, record.address)
                });
        return Ok(match (question.qtype, address) {
            (1, Some(IpAddr::V4(address))) => {
                response(message, &question, 0, Some(Answer::A(address)))
            }
            (28, Some(IpAddr::V6(address))) => {
                response(message, &question, 0, Some(Answer::Aaaa(address)))
            }
            (_, Some(_)) => response(message, &question, 0, None),
            (_, None) => response(message, &question, if known_peer { 0 } else { 3 }, None),
        });
    }
    if let Some(address) = reverse_address(&question.name).filter(|address| {
        network.contains(address)
            || directory
                .read()
                .is_ok_and(|directory| directory.dns_by_address(*address).is_some())
    }) {
        if question.qtype != 12 {
            return Ok(response(message, &question, 0, None));
        }
        let peer = directory
            .read()
            .map_err(|_| invalid_dns())?
            .dns_by_address(address)
            .filter(|record| {
                (management.is_some() && local_owner == Some(record.peer_id))
                    || firewall_allows_peer_dns(firewall, source, record.address)
            });
        let name = if let Some(peer) = peer {
            Some(peer.name)
        } else {
            services
                .lock()
                .await
                .resolve_ptr_visible(address, source, |source, service| {
                    firewall_allows_service(firewall, source, service, 0)
                })
        };
        return Ok(match name {
            Some(name) => response(
                message,
                &question,
                0,
                Some(Answer::Ptr(format!("{name}.{suffix}"))),
            ),
            None => response(message, &question, 3, None),
        });
    }
    if let Some((version, dns)) = &managed {
        if dns.records.contains_key(&question.name) {
            return Ok(managed_records(message, &question, dns, tcp_client));
        }
        if let Some(route) = dns.route(&question.name) {
            let owner = management.expect("managed view has owner");
            let servers: Vec<_> = route
                .upstreams
                .iter()
                .copied()
                .filter(|server| {
                    *server != owner.listener
                        && !(server.ip() == owner.proxy && server.port() == 53)
                })
                .collect();
            let reply = forward(message, &question, &servers, tcp_client, management).await?;
            let current = management
                .expect("managed view has owner")
                .core
                .lock()
                .await
                .effective_dns(
                    management.expect("managed view has owner").local_address,
                    peerward_types::UnixTime(crate::packet::wall_clock_seconds()),
                );
            return Ok(if current.is_ok_and(|(current, _)| current == *version) {
                reply
            } else {
                response(message, &question, 2, None)
            });
        }
    }
    forward(message, &question, upstreams, tcp_client, management).await
}

fn managed_records(
    query: &[u8],
    question: &Question,
    dns: &peerward_management::EffectiveDns,
    tcp: bool,
) -> Vec<u8> {
    use peerward_management::DnsRecord;
    let Ok(records) = dns.answer_records(&question.name, question.qtype) else {
        return response(query, question, 2, None);
    };
    let mut output = response(query, question, 0, None);
    output[6..8].copy_from_slice(
        &u16::try_from(records.len())
            .expect("bounded DNS answers")
            .to_be_bytes(),
    );
    for (name, record) in records {
        let (kind, data) = match record {
            DnsRecord::A(address) => (1u16, address.octets().to_vec()),
            DnsRecord::AAAA(address) => (28u16, address.octets().to_vec()),
            DnsRecord::CNAME(target) => (5u16, encode_name(&target)),
        };
        output.extend(encode_name(&name));
        output.extend(kind.to_be_bytes());
        output.extend(1u16.to_be_bytes());
        output.extend(30u32.to_be_bytes());
        output.extend(
            u16::try_from(data.len())
                .expect("bounded RDATA")
                .to_be_bytes(),
        );
        output.extend(data);
    }
    if output.len() > MAX_DNS_MESSAGE || (!tcp && output.len() > question.udp_limit) {
        truncated(query, question)
    } else {
        output
    }
}

enum Answer {
    A(Ipv4Addr),
    Aaaa(std::net::Ipv6Addr),
    Ptr(String),
}

fn response(query: &[u8], question: &Question, rcode: u16, answer: Option<Answer>) -> Vec<u8> {
    let mut output = Vec::with_capacity(128);
    output.extend_from_slice(&question.id.to_be_bytes());
    let flags = 0x8000 | 0x0400 | (question.flags & 0x0100) | rcode;
    output.extend_from_slice(&flags.to_be_bytes());
    output.extend_from_slice(&1_u16.to_be_bytes());
    output.extend_from_slice(&u16::from(answer.is_some()).to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&0_u16.to_be_bytes());
    output.extend_from_slice(&query[DNS_HEADER..question.wire_end]);
    if let Some(answer) = answer {
        output.extend_from_slice(&[0xc0, 0x0c]);
        let (kind, data) = match answer {
            Answer::A(address) => (1_u16, address.octets().to_vec()),
            Answer::Aaaa(address) => (28_u16, address.octets().to_vec()),
            Answer::Ptr(name) => (12_u16, encode_name(&name)),
        };
        output.extend_from_slice(&kind.to_be_bytes());
        output.extend_from_slice(&1_u16.to_be_bytes());
        output.extend_from_slice(&30_u32.to_be_bytes());
        output.extend_from_slice(&u16::try_from(data.len()).unwrap_or(0).to_be_bytes());
        output.extend_from_slice(&data);
    }
    output
}

fn truncated(query: &[u8], question: &Question) -> Vec<u8> {
    let mut output = Vec::new();
    output.extend_from_slice(&question.id.to_be_bytes());
    output.extend_from_slice(&(0x8000 | 0x0200 | (question.flags & 0x0100)).to_be_bytes());
    output.extend_from_slice(&1_u16.to_be_bytes());
    output.extend_from_slice(&[0; 6]);
    output.extend_from_slice(&query[DNS_HEADER..question.wire_end]);
    output
}

async fn forward(
    message: &[u8],
    question: &Question,
    upstreams: &[SocketAddr],
    tcp_client: bool,
    management: Option<&ManagedDns>,
) -> io::Result<Vec<u8>> {
    for upstream in upstreams {
        let binding = if let Some(owner) = management {
            match owner.core.lock().await.dns_requires_tunnel(
                upstream.ip(),
                peerward_types::UnixTime(crate::packet::wall_clock_seconds()),
            ) {
                Ok(true) => {
                    let Some(address) = std::iter::once(owner.local_address)
                        .chain(owner.secondary_address)
                        .find(|address| address.is_ipv4() == upstream.is_ipv4())
                    else {
                        continue;
                    };
                    Some((owner.interface.as_str(), address))
                }
                Ok(false) => None,
                _ => continue,
            }
        } else {
            None
        };
        let result = if tcp_client {
            forward_tcp(message, *upstream, binding).await
        } else {
            forward_udp(message, *upstream, binding).await
        };
        if let Ok(reply) = result {
            if validate_forwarded(&reply, question).is_err()
                || matches!(read_u16(&reply, 2)? & 15, 2 | 5)
            {
                continue;
            }
            if !tcp_client && reply.len() > question.udp_limit {
                return Ok(truncated(message, question));
            }
            return Ok(reply);
        }
    }
    Ok(response(message, question, 2, None))
}

async fn forward_udp(
    message: &[u8],
    upstream: SocketAddr,
    binding: Option<(&str, IpAddr)>,
) -> io::Result<Vec<u8>> {
    let bind = if let Some((_, address)) = binding {
        SocketAddr::new(address, 0)
    } else if upstream.is_ipv4() {
        "0.0.0.0:0".parse().expect("literal address")
    } else {
        "[::]:0".parse().expect("literal address")
    };
    let socket = UdpSocket::bind(bind).await?;
    if let Some((interface, _)) = binding {
        socket.bind_device(Some(interface.as_bytes()))?;
    }
    socket.connect(upstream).await?;
    socket.send(message).await?;
    let mut reply = vec![0; MAX_DNS_MESSAGE];
    let length = timeout(FORWARD_TIMEOUT, socket.recv(&mut reply))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    reply.truncate(length);
    Ok(reply)
}

async fn forward_tcp(
    message: &[u8],
    upstream: SocketAddr,
    binding: Option<(&str, IpAddr)>,
) -> io::Result<Vec<u8>> {
    let socket = if upstream.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    if let Some((interface, address)) = binding {
        socket.bind(SocketAddr::new(address, 0))?;
        socket.bind_device(Some(interface.as_bytes()))?;
    }
    let mut stream = timeout(FORWARD_TIMEOUT, socket.connect(upstream))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    stream
        .write_u16(u16::try_from(message.len()).map_err(|_| invalid_dns())?)
        .await?;
    stream.write_all(message).await?;
    let length = timeout(FORWARD_TIMEOUT, stream.read_u16())
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    if usize::from(length) > MAX_DNS_MESSAGE {
        return Err(invalid_dns());
    }
    let mut reply = vec![0; usize::from(length)];
    timeout(FORWARD_TIMEOUT, stream.read_exact(&mut reply))
        .await
        .map_err(|_| io::ErrorKind::TimedOut)??;
    Ok(reply)
}

fn validate_forwarded(reply: &[u8], question: &Question) -> io::Result<()> {
    if reply.len() < DNS_HEADER
        || reply.len() > MAX_DNS_MESSAGE
        || read_u16(reply, 0)? != question.id
        || read_u16(reply, 2)? & 0x8000 == 0
        || read_u16(reply, 4)? != 1
    {
        return Err(invalid_dns());
    }
    let (name, end) = decode_name(reply, DNS_HEADER)?;
    if name != question.name
        || read_u16(reply, end)? != question.qtype
        || read_u16(reply, end + 2)? != 1
    {
        return Err(invalid_dns());
    }
    Ok(())
}

async fn serve_udp<P: PacketPolicy + 'static>(
    socket: UdpSocket,
    suffix: String,
    network: ipnet::IpNet,
    upstreams: Vec<SocketAddr>,
    management: Option<ManagedDns>,
    directory: Arc<RwLock<DirectPeerDirectory>>,
    services: Arc<Mutex<RemoteServiceTable>>,
    firewall: Arc<P>,
    observability: Option<peerward_service::PeerObservability>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let socket = Arc::new(socket);
    let slots = Arc::new(Semaphore::new(MAX_CONCURRENT_DNS_QUERIES));
    let mut queries = JoinSet::new();
    let mut buffer = vec![0; MAX_DNS_MESSAGE];
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buffer) => {
                let (length, source) = received?;
                if let Some(observability) = &observability {
                    observability.record_dns_query();
                }
                let query = buffer[..length].to_vec();
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    let reply = parse_question(&query).map_or_else(
                        |_| form_error(&query),
                        |question| response(&query, &question, 2, None),
                    );
                    socket.send_to(&reply, source).await?;
                    continue;
                };
                let socket = Arc::clone(&socket);
                let suffix = suffix.clone();
                let upstreams = upstreams.clone();
                let management = management.clone();
                let directory = Arc::clone(&directory);
                let services = Arc::clone(&services);
                let firewall = Arc::clone(&firewall);
                queries.spawn(async move {
                    let _permit = permit;
                    let reply = answer(
                        &query, source.ip(), false, &suffix, network, &upstreams,
                        &directory, &services, firewall.as_ref(), management.as_ref(),
                    ).await.unwrap_or_else(|_| form_error(&query));
                    let _ = socket.send_to(&reply, source).await;
                });
            }
            Some(result) = queries.join_next(), if !queries.is_empty() => {
                if let Err(error) = result {
                    tracing::debug!(?error, "Peer DNS UDP query task failed");
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    queries.abort_all();
                    while queries.join_next().await.is_some() {}
                    return Ok(());
                }
            }
        }
    }
}

async fn serve_tcp<P: PacketPolicy + 'static>(
    listener: TcpListener,
    suffix: String,
    network: ipnet::IpNet,
    upstreams: Vec<SocketAddr>,
    management: Option<ManagedDns>,
    directory: Arc<RwLock<DirectPeerDirectory>>,
    services: Arc<Mutex<RemoteServiceTable>>,
    firewall: Arc<P>,
    observability: Option<peerward_service::PeerObservability>,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_CONCURRENT_DNS_QUERIES));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, source) = accepted?;
                let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let directory = Arc::clone(&directory);
                let services = Arc::clone(&services);
                let firewall = Arc::clone(&firewall);
                let observability = observability.clone();
                let suffix = suffix.clone();
                let upstreams = upstreams.clone();
                let management = management.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = serve_tcp_connection(
                        stream, source.ip(), &suffix, network, &upstreams,
                        directory, services, firewall, observability, management,
                    ).await {
                        tracing::debug!(source = %source.ip(), ?error, "Peer DNS TCP request failed");
                    }
                });
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result {
                    tracing::debug!(?error, "Peer DNS TCP connection task failed");
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { break; }
            }
        }
    }
    connections.shutdown().await;
    Ok(())
}

async fn serve_tcp_connection<P: PacketPolicy + ?Sized>(
    mut stream: TcpStream,
    source: IpAddr,
    suffix: &str,
    network: ipnet::IpNet,
    upstreams: &[SocketAddr],
    directory: Arc<RwLock<DirectPeerDirectory>>,
    services: Arc<Mutex<RemoteServiceTable>>,
    firewall: Arc<P>,
    observability: Option<peerward_service::PeerObservability>,
    management: Option<ManagedDns>,
) -> io::Result<()> {
    loop {
        let length = match stream.read_u16().await {
            Ok(length) => usize::from(length),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        };
        if !(DNS_HEADER..=MAX_DNS_MESSAGE).contains(&length) {
            return Err(invalid_dns());
        }
        let mut query = vec![0; length];
        stream.read_exact(&mut query).await?;
        if let Some(observability) = &observability {
            observability.record_dns_query();
        }
        let reply = answer(
            &query,
            source,
            true,
            suffix,
            network,
            upstreams,
            &directory,
            &services,
            firewall.as_ref(),
            management.as_ref(),
        )
        .await
        .unwrap_or_else(|_| form_error(&query));
        stream
            .write_u16(u16::try_from(reply.len()).map_err(|_| invalid_dns())?)
            .await?;
        stream.write_all(&reply).await?;
    }
}
