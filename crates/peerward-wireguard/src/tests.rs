use std::time::{Duration, Instant};

use x25519_dalek::{PublicKey, StaticSecret};

use super::*;

pub(crate) fn engine(seed: u8) -> Engine {
    Engine::new(StaticSecret::from([seed; 32]), Limits::default()).unwrap()
}

pub(crate) fn packet(length: usize) -> Vec<u8> {
    let mut data = vec![0; length];
    data[0] = 0x45;
    data[2..4].copy_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
    data[8] = 64;
    data[9] = 17;
    data[12..16].copy_from_slice(&[10, 42, 0, 1]);
    data[16..20].copy_from_slice(&[10, 42, 0, 2]);
    data
}

pub(crate) fn network(events: Vec<Event>) -> Vec<u8> {
    assert_eq!(events.len(), 1, "{events:?}");
    match events.into_iter().next().unwrap() {
        Event::Network { packet, .. } => packet,
        event @ Event::Plaintext { .. } => panic!("expected network output: {event:?}"),
    }
}

pub(crate) fn direct() -> Ingress {
    Ingress::Direct("127.0.0.1:12345".parse().unwrap())
}

fn connect() -> (Engine, Engine) {
    let mut a = engine(1);
    let mut b = engine(2);
    a.install(b.public_key()).unwrap();
    b.install(a.public_key()).unwrap();
    let now = Instant::now();
    let init = network(
        a.send(&b.public_key(), &packet(61), now, |_, _| true)
            .unwrap(),
    );
    assert_eq!(init.len(), 148);
    let response = network(b.receive(direct(), &init).unwrap());
    assert_eq!(response.len(), 92);
    let confirmation = network(a.receive(direct(), &response).unwrap());
    assert_eq!(confirmation.len(), 32);
    assert!(b.receive(direct(), &confirmation).unwrap().is_empty());
    let first = network(a.tick(now, |_, _| true));
    assert_eq!(
        b.receive(direct(), &first).unwrap(),
        vec![Event::Plaintext {
            peer: a.public_key(),
            packet: packet(61),
        }]
    );
    (a, b)
}

#[test]
fn standard_handshake_padding_replay_and_bidirectional_data() {
    let (mut a, mut b) = connect();
    for length in [20, 61, 1279, 1280] {
        let plain = packet(length);
        let sealed = network(
            b.send(&a.public_key(), &plain, Instant::now(), |_, _| true)
                .unwrap(),
        );
        assert_eq!(sealed.len(), length.next_multiple_of(16) + 32);
        assert_eq!(&sealed[..4], &[4, 0, 0, 0]);
        assert_eq!(
            a.receive(direct(), &sealed).unwrap(),
            vec![Event::Plaintext {
                peer: b.public_key(),
                packet: plain,
            }]
        );
        assert_eq!(a.receive(direct(), &sealed), Err(Error::Authentication));
    }
}

#[test]
fn a_full_mtu_probe_never_proves_bytes_beyond_the_actual_ciphertext() {
    for mtu in [1280, 1281, 9000] {
        let mut a = Engine::new(
            StaticSecret::from([1; 32]),
            Limits {
                mtu,
                ..Limits::default()
            },
        )
        .unwrap();
        let mut b = Engine::new(
            StaticSecret::from([2; 32]),
            Limits {
                mtu,
                ..Limits::default()
            },
        )
        .unwrap();
        a.install(b.public_key()).unwrap();
        b.install(a.public_key()).unwrap();
        let init = network(a.initiate(&b.public_key()).unwrap());
        let response = network(b.receive(direct(), &init).unwrap());
        let confirmation = network(a.receive(direct(), &response).unwrap());
        b.receive(direct(), &confirmation).unwrap();
        let ciphertext = network(
            a.send(&b.public_key(), &packet(mtu), Instant::now(), |_, _| true)
                .unwrap(),
        );
        assert_eq!(ciphertext.len(), mtu + 32);
        assert_eq!(
            b.receive(direct(), &ciphertext).unwrap(),
            vec![Event::Plaintext {
                peer: a.public_key(),
                packet: packet(mtu)
            }]
        );
    }
}

#[test]
fn relay_and_direct_share_the_same_session_and_replay_window() {
    let (mut a, mut b) = connect();
    let ciphertext = network(
        a.send(&b.public_key(), &packet(64), Instant::now(), |_, _| true)
            .unwrap(),
    );
    let ingress = Ingress::Relay {
        peer: a.public_key(),
    };
    assert!(matches!(
        &b.receive(ingress, &ciphertext).unwrap()[0],
        Event::Plaintext { .. }
    ));
    assert_eq!(b.receive(direct(), &ciphertext), Err(Error::Authentication));
    let stranger = engine(3).public_key();
    b.install(stranger).unwrap();
    let ciphertext = network(
        a.send(&b.public_key(), &packet(64), Instant::now(), |_, _| true)
            .unwrap(),
    );
    assert_eq!(
        b.receive(Ingress::Relay { peer: stranger }, &ciphertext),
        Err(Error::Unauthorized)
    );
    assert!(b.receive(ingress, &ciphertext).is_ok());
}

#[test]
fn exact_removal_frees_indices_and_does_not_remove_other_keys() {
    let (mut a, mut b) = connect();
    let other = engine(3).public_key();
    b.install(other).unwrap();
    let ciphertext = network(
        a.send(&b.public_key(), &packet(64), Instant::now(), |_, _| true)
            .unwrap(),
    );
    b.remove(&a.public_key());
    assert_eq!(b.receive(direct(), &ciphertext), Err(Error::UnknownIndex));
    assert!(
        b.send(&other, &packet(64), Instant::now(), |_, _| true)
            .is_ok()
    );
    assert_eq!(
        b.send(&a.public_key(), &packet(64), Instant::now(), |_, _| true),
        Err(Error::UnknownPeer)
    );
}

#[test]
fn queues_have_count_bytes_expiry_and_policy_revalidation() {
    let limits = Limits {
        queued_packets: 2,
        queued_bytes: 1280,
        total_queued_bytes: 1280,
        ..Limits::default()
    };
    let mut a = Engine::new(StaticSecret::from([1; 32]), limits).unwrap();
    let b = engine(2);
    a.install(b.public_key()).unwrap();
    let now = Instant::now();
    a.send(&b.public_key(), &packet(64), now, |_, _| true)
        .unwrap();
    a.send(&b.public_key(), &packet(64), now, |_, _| true)
        .unwrap();
    assert_eq!(
        a.send(&b.public_key(), &packet(64), now, |_, _| true),
        Err(Error::QueueFull)
    );
    assert_eq!(a.pending_bytes(), 128);
    a.tick(now, |_, _| false);
    assert_eq!(a.pending_bytes(), 0);
    a.send(&b.public_key(), &packet(1280), now, |_, _| true)
        .unwrap();
    assert_eq!(
        a.send(&b.public_key(), &packet(64), now, |_, _| true),
        Err(Error::QueueFull)
    );
    a.tick(now + Duration::from_secs(4), |_, _| true);
    assert_eq!(a.pending_bytes(), 0);
    a.send(&b.public_key(), &packet(64), now, |_, _| true)
        .unwrap();
    a.clear_pending();
    assert_eq!(a.pending_bytes(), 0);
}

#[test]
fn malformed_unknown_and_tampered_packets_fail_closed() {
    let (mut a, mut b) = connect();
    for bad in [vec![], vec![1; 148], vec![4; 31], vec![4; 1313]] {
        assert!(b.receive(direct(), &bad).is_err());
    }
    let mut ciphertext = network(
        a.send(&b.public_key(), &packet(64), Instant::now(), |_, _| true)
            .unwrap(),
    );
    ciphertext[32] ^= 1;
    assert_eq!(b.receive(direct(), &ciphertext), Err(Error::Authentication));
    let mut unknown = engine(3);
    unknown.install(b.public_key()).unwrap();
    let init = network(
        unknown
            .send(&b.public_key(), &packet(64), Instant::now(), |_, _| true)
            .unwrap(),
    );
    assert_eq!(b.receive(direct(), &init), Err(Error::UnknownPeer));
    assert_eq!(b.install([0; 32]), Err(Error::InvalidKey));
    assert_eq!(b.install(b.public_key()), Err(Error::InvalidKey));
}

#[test]
fn repeated_directory_install_does_not_rekey() {
    let (mut a, mut b) = connect();
    a.install(b.public_key()).unwrap();
    let ciphertext = network(
        a.send(&b.public_key(), &packet(64), Instant::now(), |_, _| true)
            .unwrap(),
    );
    assert_eq!(ciphertext[0], 4);
    assert!(b.receive(direct(), &ciphertext).is_ok());
}

#[test]
fn packet_validation_precedes_any_queue_or_crypto_work() {
    let mut a = engine(1);
    let b = PublicKey::from(&StaticSecret::from([2; 32])).to_bytes();
    a.install(b).unwrap();
    assert_eq!(
        a.send(&b, &packet(1281), Instant::now(), |_, _| true),
        Err(Error::PacketTooLarge)
    );
    assert_eq!(
        a.send(&b, &[0x45; 19], Instant::now(), |_, _| true),
        Err(Error::InvalidPacket)
    );
    assert_eq!(
        a.send(&b, &packet(64), Instant::now(), |_, _| false),
        Err(Error::Unauthorized)
    );
    assert_eq!(a.pending_bytes(), 0);
}
