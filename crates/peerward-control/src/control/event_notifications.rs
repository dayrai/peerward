async fn run_event_notifications(store: Store, database_url: String, sender: watch::Sender<u64>) {
    let mut generation = 0_u64;
    loop {
        let mut dispatcher = match store.dispatcher(&database_url).await {
            Ok(dispatcher) => dispatcher,
            Err(error) => {
                tracing::warn!(?error, "Control event notification listener unavailable");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        loop {
            match dispatcher.next_cursor().await {
                Ok(_) => {
                    generation = generation.wrapping_add(1);
                    let _ = sender.send(generation);
                }
                Err(error) => {
                    tracing::warn!(?error, "Control event notification listener disconnected");
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
