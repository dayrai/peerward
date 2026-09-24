use super::*;

#[test]
fn independent_families_share_ports_but_each_must_avoid_stun() {
    let parse = |extra: &str, stun: &[&str]| {
        let mut config = QuicListenerConfig {
            address: "0.0.0.0:8443".parse().unwrap(),
            additional_address: Some(extra.parse().unwrap()),
            certificate_file: "quic.pem".into(),
            private_key_file: "quic.key".into(),
        };
        config.validate(
            Path::new("/etc/peerward/relay.toml"),
            &stun
                .iter()
                .map(|address| address.parse().unwrap())
                .collect::<Vec<_>>(),
        )
    };
    assert!(parse("[::]:8443", &[]).is_ok());
    assert!(parse("[::1]:8443", &["[::1]:3478"]).is_ok());
    assert!(parse("[::1]:8443", &["[::1]:8443"]).is_err());
    assert!(parse("[::1]:8443", &["[::]:8443"]).is_err());
    assert!(parse("[::]:8443", &["127.0.0.1:8443"]).is_err());
    assert!(parse("127.0.0.1:8444", &[]).is_err());
    assert!(parse("[::]:0", &[]).is_err());
    assert!(parse("[ff02::1]:8443", &[]).is_err());
}
