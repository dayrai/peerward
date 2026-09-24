/// Drop the other owned futures as soon as one subsystem completes. A suspended
/// pump may hold the core lock while waiting on a bounded TUN write; polling it
/// after another subsystem stops or retaining it during key destruction can
/// strand that lock. Dropping a losing future releases its guards and TUN halves.
async fn race_packet_tasks<P, C, D>(
    pump: P,
    control: C,
    dns: D,
    counters: Arc<CounterSet>,
) -> Result<PacketCounters, PeerError>
where
    P: std::future::Future<Output = Result<PacketCounters, PacketPumpError>>,
    C: std::future::Future<Output = Result<(), PacketPumpError>>,
    D: std::future::Future<Output = Result<(), io::Error>>,
{
    tokio::pin!(pump, control, dns);
    tokio::select! {
        result = &mut pump => result.map_err(packet_error_to_peer),
        result = &mut control => result.map(|()| counters.snapshot()).map_err(packet_error_to_peer),
        result = &mut dns => result.map(|()| counters.snapshot()).map_err(PeerError::Io),
    }
}

#[cfg(test)]
mod packet_task_tests {
    use super::*;

    struct DropSignal(Option<oneshot::Sender<()>>);

    impl Drop for DropSignal {
        fn drop(&mut self) {
            if let Some(signal) = self.0.take() {
                let _ = signal.send(());
            }
        }
    }

    #[tokio::test]
    async fn dropping_relay_worker_owner_cancels_its_children() {
        let (shutdown, _shutdown_rx) = watch::channel(false);
        let (started_tx, started_rx) = oneshot::channel();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let worker = tokio::spawn(async move {
            let _drop_signal = DropSignal(Some(dropped_tx));
            started_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        started_rx.await.unwrap();
        let workers = RelayWorkerSet {
            shutdown,
            workers: vec![worker],
        };

        drop(workers);
        tokio::time::timeout(Duration::from_secs(1), dropped_rx)
            .await
            .expect("dropping the runtime owner must cancel relay children")
            .unwrap();
    }

    #[tokio::test]
    async fn completed_control_drops_a_pump_suspended_with_the_core_lock() {
        let core = Arc::new(Mutex::new(()));
        let pump_core = Arc::clone(&core);
        let (locked, ready) = oneshot::channel();
        let pump = async move {
            let _guard = pump_core.lock().await;
            locked.send(()).unwrap();
            std::future::pending::<Result<PacketCounters, PacketPumpError>>().await
        };
        let control = async {
            ready.await.unwrap();
            Ok(())
        };
        tokio::time::timeout(
            Duration::from_secs(1),
            race_packet_tasks(pump, control, std::future::pending(), Arc::default()),
        )
        .await
        .unwrap()
        .unwrap();
        assert!(
            core.try_lock().is_ok(),
            "shutdown must release the suspended TUN guard"
        );
    }
}
