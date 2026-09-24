/// Platform I/O only. Fragment decisions and stateful ACL evaluation live in the shared core.
async fn run_wireguard_pump<R: PacketReader, W: PacketWriter>(
    mut reader: R,
    mut writer: W,
    path: WireguardPath,
    mut inbound: mpsc::Receiver<peerward_peer_core::WireguardOutput>,
    mtu: usize,
    mut shutdown: watch::Receiver<bool>,
) -> Result<PacketCounters, PacketPumpError> {
    let mut buffer = vec![0; mtu.max(576)];
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { return Ok(path.counters.snapshot()); }
            }
            packet = reader.read_packet(&mut buffer) => {
                let count = packet?;
                if count == 0 { return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()); }
                let result = path.core.lock().await.send_tunnel(&buffer[..count], UnixTime(wall_clock_seconds()), Instant::now());
                match result {
                    Ok(events) => {
                        let has_data = events.iter().any(|event| matches!(event, peerward_peer_core::WireguardOutput::Network { packet, .. } if packet.get(..4) == Some(&[4,0,0,0])));
                        match path.dispatch(events).await {
                            Ok(carrier) => {
                                path.counters.egress_allowed.fetch_add(1, Ordering::Relaxed);
                                if has_data { match carrier { DataPath::Direct => &path.counters.direct_sent, DataPath::Relay => &path.counters.relay_sent }.fetch_add(1, Ordering::Relaxed); }
                                if let Some(observability) = &path.observability { observability.record_egress(count, true, has_data && carrier == DataPath::Direct); }
                            }
                            Err(error) => path.record_dispatch_drop(false, count, &error),
                        }
                    }
                    Err(error) => path.record_drop(false, count, &error),
                }
            }
            packet = inbound.recv() => {
                let Some(peerward_peer_core::WireguardOutput::Tunnel { packet, authorization, expires, .. }) = packet else { return Ok(path.counters.snapshot()); };
                // Revocation cannot overtake this bounded write; a blocked TUN cannot stall control.
                let mut core = path.core.lock().await;
                if Instant::now() >= expires || !core.delivery_current(authorization, UnixTime(wall_clock_seconds())) {
                    drop(core); path.record_drop(true, packet.len(), &PeerError::Revoked); continue;
                }
                let written = tokio::time::timeout(Duration::from_millis(20), writer.write_packet(&packet)).await;
                drop(core);
                match written {
                    Ok(Ok(())) => {
                        path.counters.ingress_allowed.fetch_add(1, Ordering::Relaxed);
                        if let Some(observability) = &path.observability { observability.record_ingress(packet.len(), true); }
                    }
                    Ok(Err(error)) => return Err(error),
                    Err(_) => path.record_drop(true, packet.len(), &PeerError::QueueFull),
                }
            }
        }
    }
}

impl WireguardPath {
    fn record_dispatch_drop(&self, ingress: bool, bytes: usize, error: &PacketPumpError) {
        let reason = match error {
            PacketPumpError::QueueFull => PeerError::QueueFull,
            PacketPumpError::NoRoute | PacketPumpError::SessionPending => PeerError::NoRoute,
            _ => PeerError::InvalidPacket,
        };
        self.record_drop(ingress, bytes, &reason);
    }

    fn record_drop(&self, ingress: bool, bytes: usize, error: &PeerError) {
        let direction = if ingress {
            peerward_wire::AuditDirectionV1::Ingress
        } else {
            peerward_wire::AuditDirectionV1::Egress
        };
        let reason = match error {
            PeerError::PolicyDenied => peerward_wire::AuditReasonV1::PolicyDenied,
            PeerError::Revoked | PeerError::NoRoute => {
                peerward_wire::AuditReasonV1::SessionUnavailable
            }
            PeerError::QueueFull => peerward_wire::AuditReasonV1::ResourceLimited,
            PeerError::PacketRuntime(_) => peerward_wire::AuditReasonV1::SecurityAnomaly,
            _ => peerward_wire::AuditReasonV1::MalformedPacket,
        };
        record_packet_audit(Some(&self.audit), direction, reason, 1);
        if ingress {
            &self.counters.ingress_denied
        } else {
            &self.counters.egress_denied
        }
        .fetch_add(1, Ordering::Relaxed);
        if let Some(observability) = &self.observability {
            match error {
                PeerError::QueueFull => observability.record_queue_full(),
                PeerError::NoRoute | PeerError::Revoked => observability.record_no_route(),
                PeerError::PolicyDenied if ingress => observability.record_ingress(bytes, false),
                PeerError::PolicyDenied => observability.record_egress(bytes, false, false),
                _ => observability.record_invalid_packet(),
            }
        }
    }
}
