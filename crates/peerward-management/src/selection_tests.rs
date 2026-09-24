use super::*;
use peerward_types::PeerId;
use std::time::{Duration, Instant};
use uuid::Uuid;

#[test]
fn initial_unknown_is_bounded_three_failures_switch_and_recovery_waits_thirty_seconds() {
    let resource = Uuid::new_v4();
    let bindings: Vec<_> = [100, 200]
        .into_iter()
        .map(|priority| GatewayBinding {
            id: Uuid::new_v4(),
            resource_id: resource,
            peer_id: PeerId::new(),
            version: 1,
            approved: true,
            priority,
            forwarding: ForwardingMode::Snat,
            return_route_confirmed: false,
            approval_source: ApprovalSource::Manual,
        })
        .collect();
    let ads: Vec<_> = bindings
        .iter()
        .map(|binding| RouteAdvertisement {
            binding_id: binding.id,
            binding_version: 1,
            peer_id: binding.peer_id,
            sequence: 1,
            published: true,
            forwarding_ready: true,
            valid_until: 1000,
        })
        .collect();
    let now = Instant::now();
    let at = |seconds| now + Duration::from_secs(seconds);
    let mut selector = GatewaySelector::default();
    for binding in &bindings {
        selector.register(binding.id, now);
    }
    assert_eq!(selector.health(bindings[0].id, now), PathHealth::Unknown);
    assert_eq!(
        selector.select(resource, &bindings, &ads, 10, now),
        Some(bindings[0].peer_id)
    );
    for second in [5, 10] {
        selector.observe(bindings[0].id, false, at(second));
        selector.observe(bindings[1].id, true, at(second));
        assert_eq!(
            selector.select(resource, &bindings, &ads, 10, at(second)),
            Some(bindings[0].peer_id)
        );
    }
    selector.observe(bindings[0].id, false, at(15));
    selector.observe(bindings[1].id, true, at(15));
    assert_eq!(
        selector.select(resource, &bindings, &ads, 10, at(15)),
        Some(bindings[1].peer_id)
    );
    for second in [20, 25, 30, 35, 40, 45] {
        for binding in &bindings {
            selector.observe(binding.id, true, at(second));
        }
        assert_eq!(
            selector.select(resource, &bindings, &ads, 10, at(second)),
            Some(bindings[1].peer_id)
        );
    }
    for binding in &bindings {
        selector.observe(binding.id, true, at(50));
    }
    assert_eq!(
        selector.select(resource, &bindings, &ads, 10, at(50)),
        Some(bindings[0].peer_id)
    );
    assert_eq!(
        selector.select(resource, &bindings, &ads, 10, at(66)),
        None,
        "stale observations cannot keep a path alive"
    );
    let mut unknown = GatewaySelector::default();
    unknown.register(bindings[0].id, now);
    assert!(!unknown.eligible(bindings[0].id, at(15)));
    // Revoked advertisements and grants are excluded even when the probe remains healthy.
    let mut withdrawn = bindings.clone();
    withdrawn[0].approved = false;
    assert_eq!(
        selector.select(resource, &withdrawn, &ads, 10, at(50)),
        Some(bindings[1].peer_id)
    );
}
