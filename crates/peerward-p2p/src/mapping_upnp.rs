async fn upnp_map(
    expected_gateway: IpAddr,
    internal: SocketAddr,
    lifetime_seconds: u32,
    timeout: Duration,
) -> Result<MappingLease, P2pError> {
    let gateway = igd_next::aio::tokio::search_gateway(upnp_options(internal, timeout))
        .await
        .map_err(|_| P2pError::Mapping)?;
    if gateway.addr.ip() != expected_gateway {
        return Err(P2pError::Mapping);
    }
    let external = tokio::time::timeout(
        timeout,
        gateway.get_any_address(
            PortMappingProtocol::UDP,
            internal,
            lifetime_seconds,
            "Peerward direct UDP",
        ),
    )
    .await
    .map_err(|_| P2pError::Timeout)?
    .map_err(|_| P2pError::Mapping)?;
    Ok(MappingLease {
        protocol: MappingProtocol::Upnp,
        external,
        internal,
        lifetime_seconds,
        epoch: None,
        nonce: None,
    })
}

fn upnp_options(internal: SocketAddr, timeout: Duration) -> SearchOptions {
    SearchOptions {
        bind_addr: SocketAddr::new(internal.ip(), 0),
        timeout: Some(timeout),
        single_search_timeout: Some(timeout),
        ..SearchOptions::default()
    }
}
