use std::{thread, time::Duration};

use super::*;
use crate::tests::{direct, engine, network, packet};

#[test]
fn session_api_drives_rekey_timers_during_one_way_flows() {
    let mut a = engine(1);
    let mut b = engine(2);
    a.install(b.public_key()).unwrap();
    b.install(a.public_key()).unwrap();
    let short = Duration::from_millis(100);
    let mut params = a.peers[&b.public_key()].tunnel.timer_params().clone();
    params.rekey_after_time = short..=short;
    a.peers
        .get_mut(&b.public_key())
        .unwrap()
        .tunnel
        .dangerously_set_timer_params(params);
    let init = network(a.initiate(&b.public_key()).unwrap());
    let response = network(b.receive(direct(), &init).unwrap());
    let confirmation = network(a.receive(direct(), &response).unwrap());
    b.receive(direct(), &confirmation).unwrap();
    thread::sleep(Duration::from_millis(120));
    let before = a.tick(Instant::now(), |_, _| true);
    let encrypted = network(
        a.send(&b.public_key(), &packet(64), Instant::now(), |_, _| true)
            .unwrap(),
    );
    b.receive(direct(), &encrypted).unwrap();
    let events = a.tick(Instant::now(), |_, _| true);
    assert!(
        before
            .iter()
            .chain(events.iter())
            .any(|e| matches!(e, Event::Network { packet, .. } if packet[0] == 1)),
        "sending through the session API must arm the standard rekey timer: {before:?} {events:?}"
    );
}

#[test]
fn mac_validation_and_cookie_challenge_precede_unknown_peer_lookup() {
    let mut a = engine(1);
    let limits = Limits {
        handshakes_per_second: 1,
        ..Limits::default()
    };
    let mut b = Engine::new(StaticSecret::from([2; 32]), limits).unwrap();
    a.install(b.public_key()).unwrap();
    let init = network(a.initiate(&b.public_key()).unwrap());
    assert_eq!(b.receive(direct(), &init), Err(Error::UnknownPeer));
    let mut cookie = None;
    for _ in 0..100 {
        if let Ok(events) = b.receive(direct(), &init) {
            cookie = Some(network(events));
            break;
        }
    }
    let cookie = cookie.expect("untrusted initiations must hit the cookie limiter");
    assert_eq!(cookie.len(), 64);
    assert_eq!(&cookie[..4], &[3, 0, 0, 0]);
    a.receive(direct(), &cookie).unwrap();
    let retry = a
        .peers
        .get_mut(&b.public_key())
        .unwrap()
        .tunnel
        .format_handshake_initiation(true)
        .unwrap();
    b.install(a.public_key()).unwrap();
    let retry: Packet = retry.into();
    let reply = b.receive(direct(), &retry).unwrap();
    assert_eq!(network(reply)[0], 2);
}

#[test]
fn dropping_and_revoking_free_session_index_reservations() {
    let mut a = engine(1);
    let b = engine(2);
    a.install(b.public_key()).unwrap();
    let init = network(a.initiate(&b.public_key()).unwrap());
    let index = u32::from_le_bytes(init[4..8].try_into().unwrap());
    let indices = a.indices.clone();
    assert!(indices.in_use(index));
    a.remove(&b.public_key());
    assert!(!indices.in_use(index));
    a.install(b.public_key()).unwrap();
    let init = network(a.initiate(&b.public_key()).unwrap());
    let index = u32::from_le_bytes(init[4..8].try_into().unwrap());
    drop(a);
    assert!(!indices.in_use(index));
}
