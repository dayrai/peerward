fn validate_neighbor_health(
    local_relay: RelayId,
    health: &[RelayNeighborHealth],
) -> Result<(), StoreError> {
    if health.len() > 64 {
        return Err(StoreError::Invalid("Relay neighbor health"));
    }
    let mut neighbors = HashSet::with_capacity(health.len());
    if health.iter().any(|item| {
        item.relay_id == local_relay
            || !neighbors.insert(item.relay_id)
            || item.rtt_millis > 120_000
            || item.loss_permyriad > 10_000
            || !(1..=32).contains(&item.samples)
    }) {
        return Err(StoreError::Invalid("Relay neighbor health"));
    }
    Ok(())
}
