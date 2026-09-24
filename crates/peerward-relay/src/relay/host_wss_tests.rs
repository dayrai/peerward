use super::*;

#[test]
fn plaintext_upgrade_is_confined_to_loopback_and_tls_requires_both_files() {
    let parse = |address: &str, certificate: bool, key: bool| {
        let mut config = WssListenerConfig {
            address: address.parse().unwrap(),
            certificate_file: certificate.then(|| PathBuf::from("wss.pem")),
            private_key_file: key.then(|| PathBuf::from("wss.key")),
        };
        config
            .validate(Path::new("/etc/peerward/relay.toml"), &[])
            .map(|()| config)
    };
    assert!(parse("127.0.0.1:8443", false, false).is_ok());
    assert!(parse("[::1]:8443", false, false).is_ok());
    assert!(parse("0.0.0.0:8443", false, false).is_err());
    assert!(parse("[::]:8443", false, false).is_err());
    assert!(parse("192.0.2.1:8443", false, false).is_err());
    assert!(parse("127.0.0.1:8443", true, false).is_err());
    assert!(parse("127.0.0.1:8443", false, true).is_err());
    let config = parse("0.0.0.0:8443", true, true).unwrap();
    assert_eq!(
        config.private_key_file.unwrap(),
        PathBuf::from("/etc/peerward/wss.key")
    );
}
