fn spawn_wireguard_worker(
    data_path: WireguardPath,
    mut datagrams: mpsc::Receiver<(SocketAddr, SocketAddr, Vec<u8>)>,
    mut data_shutdown: watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(250));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            let result = tokio::select! {
                changed = data_shutdown.changed() => { if changed.is_err() || *data_shutdown.borrow() { break; } continue; }
                datagram = datagrams.recv() => {
                    let Some((local, source, bytes)) = datagram else { break; };
                    data_path.receive(peerward_peer_core::WireguardIngress::DirectPath { local, remote: source }, &bytes).await
                }
                _ = tick.tick() => data_path.tick().await,
            };
            if let Err(error) = result {
                tracing::debug!(?error, "WireGuard datagram dropped or deferred");
            }
        }
    })
}
