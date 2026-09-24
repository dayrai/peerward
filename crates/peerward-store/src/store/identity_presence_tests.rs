mod neighbor_health_tests {
    use super::*;

    #[test]
    fn relay_health_validation_rejects_self_duplicates_and_unbounded_values() {
        let local = RelayId::new();
        let remote = RelayId::new();
        let valid = RelayNeighborHealth {
            relay_id: remote,
            rtt_millis: 25,
            loss_permyriad: 125,
            samples: 32,
        };
        assert!(validate_neighbor_health(local, std::slice::from_ref(&valid)).is_ok());
        assert!(validate_neighbor_health(local, &[valid.clone(), valid]).is_err());
        assert!(validate_neighbor_health(
            local,
            &[RelayNeighborHealth {
                relay_id: local,
                rtt_millis: 0,
                loss_permyriad: 10_001,
                samples: 0,
            }],
        )
        .is_err());
    }
}
