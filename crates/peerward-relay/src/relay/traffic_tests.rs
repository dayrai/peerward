#[cfg(test)]
mod traffic_tests {
    use super::*;

    #[tokio::test]
    async fn metered_carrier_counts_completed_io_not_pending_buffers() {
        let counters = Arc::new(TrafficCounters::default());
        let (left, mut right) = tokio::io::duplex(4);
        let mut metered = MeteredStream::wrap(Box::new(left), &counters);
        assert_eq!(metered.carrier(), "tcp");
        assert!(!metered.is_quic());
        assert!(metered.take_quic().is_none());
        assert_eq!(metered.write(b"12345678").await.unwrap(), 4);
        // A cancelled, blocked write must not count bytes it never accepted.
        assert!(
            tokio::time::timeout(Duration::from_millis(10), metered.write_all(b"5678"))
                .await
                .is_err()
        );
        assert_eq!(counters.accepted_bytes.load(Ordering::Relaxed), 4);
        let mut data = [0; 4];
        right.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"1234");
        right.write_all(b"reply".split_at(4).0).await.unwrap();
        metered.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"repl");
        assert_eq!(counters.received_bytes.load(Ordering::Relaxed), 4);
        metered.write_all(b"5678").await.unwrap();
        right.read_exact(&mut data).await.unwrap();
        assert_eq!(counters.accepted_bytes.load(Ordering::Relaxed), 8);
        drop(right);
        assert_eq!(metered.read(&mut data).await.unwrap(), 0);
        assert!(metered.write_all(b"failed").await.is_err());
        assert_eq!(counters.accepted_bytes.load(Ordering::Relaxed), 8);
        assert_eq!(counters.received_bytes.load(Ordering::Relaxed), 4);
    }

    #[tokio::test]
    async fn metrics_survive_carrier_replacement_without_identity_labels() {
        let counters = Arc::new(TrafficCounters::default());
        for _ in 0..2 {
            let (socket, _other) = tokio::io::duplex(8);
            let mut socket = MeteredStream::wrap(Box::new(socket), &counters);
            socket.write_all(b"test").await.unwrap();
        }
        let metrics = traffic_metrics(&counters);
        assert!(metrics.contains("peerward_relay_framed_accepted_bytes_total 8\n"));
        assert!(metrics.contains("peerward_relay_authenticated_peer_sessions 0\n"));
        assert!(!metrics.contains('{'));
    }

    #[tokio::test]
    async fn admitted_backbone_count_is_released_on_cancellation() {
        let counters = Arc::new(TrafficCounters::default());
        let (ready, received) = tokio::sync::oneshot::channel();
        let shared = Arc::clone(&counters);
        let task = tokio::spawn(async move {
            let _guard = AuthenticatedBackboneCounter::acquire(&shared);
            let _ = ready.send(());
            std::future::pending::<()>().await;
        });
        received.await.unwrap();
        assert_eq!(counters.authenticated_backbones.load(Ordering::Relaxed), 1);
        task.abort();
        let _ = task.await;
        assert_eq!(counters.authenticated_backbones.load(Ordering::Relaxed), 0);
    }
}
