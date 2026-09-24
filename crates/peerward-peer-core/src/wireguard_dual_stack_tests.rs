use super::*;

fn udp6(source: &str, destination: &str) -> Vec<u8> {
    let source = source.parse::<std::net::Ipv6Addr>().unwrap().octets();
    let destination = destination.parse::<std::net::Ipv6Addr>().unwrap().octets();
    let mut bytes = vec![0; 56];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&16u16.to_be_bytes());
    bytes[6] = 17;
    bytes[7] = 64;
    bytes[8..24].copy_from_slice(&source);
    bytes[24..40].copy_from_slice(&destination);
    bytes[40..42].copy_from_slice(&1234u16.to_be_bytes());
    bytes[42..44].copy_from_slice(&4242u16.to_be_bytes());
    bytes[44..46].copy_from_slice(&16u16.to_be_bytes());
    let mut sum = 16u32 + 17;
    for part in [&bytes[8..40], &bytes[40..]] {
        for word in part.chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    bytes[46..48].copy_from_slice(&(!u16::try_from(sum).unwrap()).to_be_bytes());
    bytes
}

#[test]
fn one_credential_owns_both_families_and_never_a_third_address() {
    let f = Fixture::new();
    let aid = PeerId::new();
    let bid = PeerId::new();
    let ca = f.credential(aid, 10);
    let cb = f.credential(bid, 20);
    let mut ea = f.entry(&ca, "10.0.0.1");
    let mut eb = f.entry(&cb, "10.0.0.2");
    ea.secondary_address = Some("fd12::1".parse().unwrap());
    eb.secondary_address = Some("fd12::2".parse().unwrap());
    ea.labels.insert("name".into(), "laptop".into());
    eb.labels.insert("name".into(), "nas".into());
    let directory = f.signed(1, vec![ea.clone(), eb.clone()]);
    let mut a = f.runtime(ca, 10);
    let mut b = f.runtime(cb, 20);
    for runtime in [&mut a, &mut b] {
        runtime.install_directory(&directory, UnixTime(10)).unwrap();
        runtime.install_policy(&f.policy(1, true)).unwrap();
        f.authorize(runtime);
    }
    for (ipv6, expected) in [(false, "10.0.0.2"), (true, "fd12::2")] {
        assert_eq!(
            a.policy()
                .resolve_peer_name_family("nas", "10.0.0.1".parse().unwrap(), Some(ipv6)),
            Some(expected.parse().unwrap())
        );
    }
    let now = Instant::now();
    for packet in [udp(1, 2, 4242, 8), udp6("fd12::1", "fd12::2")] {
        let output = a.send_tunnel(&packet, UnixTime(10), now).unwrap();
        assert_eq!(
            relay_exchange(&mut a, &mut b, aid, bid, output, now),
            vec![packet]
        );
    }
    assert_eq!(a.credential_count(), 1);
    assert!(
        a.send_tunnel(&udp6("fd12::3", "fd12::2"), UnixTime(10), now)
            .is_err()
    );
    eb.secondary_address = ea.secondary_address;
    assert!(
        a.install_directory(&f.signed(2, vec![ea.clone(), eb.clone()]), UnixTime(10))
            .is_err()
    );
    eb.secondary_address = Some("10.0.0.3".parse().unwrap());
    assert!(
        a.install_directory(&f.signed(2, vec![ea, eb]), UnixTime(10))
            .is_err()
    );
}
