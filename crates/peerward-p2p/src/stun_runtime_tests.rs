use super::*;
use crate::stun_binding_response;

fn servers(count: u16) -> Vec<SocketAddr> {
    (0..count)
        .map(|index| SocketAddr::from(([127, 0, 0, 1], 3478 + index)))
        .collect()
}

#[test]
fn lost_responses_retransmit_identical_transactions_and_expire() {
    let mut runtime = StunRuntime::new(servers(1)).unwrap();
    let first = runtime.poll(1000);
    assert_eq!(first.next_poll_millis, 250);
    assert!(runtime.poll(1100).probes.is_empty());
    assert_eq!(runtime.poll(1250).probes, first.probes);
    assert_eq!(runtime.poll(1750).probes, first.probes);
    let probe = &first.probes[0];
    let response =
        stun_binding_response(&probe.request, "203.0.113.1:54321".parse().unwrap()).unwrap();
    assert!(matches!(
        runtime.accept(probe.server, &response, 3000),
        Err(P2pError::Timeout)
    ));
    assert!(runtime.poll(3000).probes.is_empty());
    let next = runtime.next_refresh.unwrap();
    assert!((55_000..=67_000).contains(&next));
    assert_ne!(runtime.poll(next).probes, first.probes);
}

#[test]
fn prediction_issues_requests_in_actual_allocation_order() {
    let mut runtime = StunRuntime::with_prediction(servers(4), true).unwrap();
    let mut predictions = Vec::new();
    for index in 0..4_u16 {
        let now = 60_000 + u64::from(index) * 250;
        let probes = runtime.poll(now).probes;
        assert_eq!(probes.len(), 1);
        let probe = &probes[0];
        assert_eq!(u16::from(probe.server_index), index);
        let mapped = SocketAddr::from(([203, 0, 113, 1], 40_000 + index * 2));
        let response = stun_binding_response(&probe.request, mapped).unwrap();
        predictions = runtime
            .accept(probe.server, &response, now + 10)
            .unwrap()
            .predicted;
    }
    assert_eq!(
        predictions,
        (40_004..=40_008)
            .map(|port| SocketAddr::from(([203, 0, 113, 1], port)))
            .collect::<Vec<_>>()
    );
}

#[test]
fn source_replay_clock_reset_and_network_replacement_are_fenced() {
    let mut runtime = StunRuntime::new(servers(1)).unwrap();
    let probe = runtime.poll(1000).probes.remove(0);
    let response =
        stun_binding_response(&probe.request, "203.0.113.1:54321".parse().unwrap()).unwrap();
    assert!(
        runtime
            .accept("127.0.0.1:3479".parse().unwrap(), &response, 1010)
            .is_err()
    );
    assert!(runtime.accept(probe.server, &response, 999).is_err());
    assert!(runtime.accept(probe.server, &response, 1010).is_ok());
    assert!(runtime.accept(probe.server, &response, 1011).is_err());
    runtime.reset_network();
    assert_ne!(runtime.poll(0).probes[0].request, probe.request);
    assert!(runtime.accept(probe.server, &response, 1).is_err());
}

#[test]
fn ordinary_discovery_has_at_most_four_concurrent_transactions() {
    let mut runtime = StunRuntime::new(servers(8)).unwrap();
    assert_eq!(runtime.poll(0).probes.len(), 4);
    assert_eq!(runtime.pending.len(), 4);
    assert_eq!(runtime.poll(2000).probes.len(), 4);
    assert_eq!(runtime.pending.len(), 4);
    assert!(runtime.poll(4000).probes.is_empty());
    assert!(runtime.pending.is_empty());
}

#[test]
fn failed_prediction_resumes_parallel_discovery_during_cooldown() {
    let mut runtime = StunRuntime::with_prediction(servers(8), true).unwrap();
    assert_eq!(runtime.poll(0).probes.len(), 1);
    // Timeout terminates the ordered experiment. Remaining servers still get
    // ordinary concurrent discovery without producing predictions.
    let fallback = runtime.poll(2000);
    assert_eq!(fallback.probes.len(), 4);
    assert!(!runtime.prediction_active);
    for probe in fallback.probes {
        let response = stun_binding_response(
            &probe.request,
            SocketAddr::from(([203, 0, 113, 1], 40_000 + u16::from(probe.server_index) * 2)),
        )
        .unwrap();
        assert!(
            runtime
                .accept(probe.server, &response, 2010)
                .unwrap()
                .predicted
                .is_empty()
        );
    }
}
