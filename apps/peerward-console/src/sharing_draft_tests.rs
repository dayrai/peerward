fn sharing_test_draft(
    kind: &str,
    protocol: &str,
    prefix: &str,
    dns: &str,
    address: &str,
) -> Result<peerward_api::ConsoleSharingDraft, String> {
    build_sharing_draft(
        uuid::Uuid::new_v4(),
        "Shared resource".into(),
        uuid::Uuid::new_v4().to_string(),
        kind.into(),
        protocol.into(),
        "8443".into(),
        prefix.into(),
        uuid::Uuid::new_v4().to_string(),
        false,
        dns.into(),
        address.into(),
        String::new(),
        String::new(),
    )
}

#[test]
fn web_protocol_presets_keep_custom_ports_and_use_tcp() {
    for protocol in ["http", "https"] {
        let draft = sharing_test_draft("service", protocol, "", "Web", "").unwrap();
        assert_eq!(draft.protocol, 6);
        assert!(matches!(draft.target, peerward_api::ConsoleSharingTarget::Service { ref protocols, port: 8443, ref alias }
            if protocols == &[peerward_types::ServiceProtocol::Tcp] && alias.as_deref() == Some("web")));
    }
    assert!(sharing_test_draft("service", "all", "", "", "").is_err());
    assert!(sharing_test_draft("lan", "https", "192.168.1.50/32", "", "").is_err());
}

#[test]
fn service_dns_requires_a_label_instead_of_a_full_domain() {
    for alias in ["nas.home", "-nas", "nas-", "nas_name", "nas/name"] {
        assert!(sharing_test_draft("service", "tcp", "", alias, "").is_err());
    }
    assert!(sharing_test_draft("service", "tcp", "", "nas-files", "").is_ok());
}

#[test]
fn host_dns_uses_the_lan_target_address_for_ipv4_and_ipv6() {
    for (prefix, expected) in [("192.168.1.50/32", "192.168.1.50"), ("fd00::50/128", "fd00::50")] {
        let draft = sharing_test_draft("lan", "tcp", prefix, "printer.home", "").unwrap();
        assert!(matches!(draft.target, peerward_api::ConsoleSharingTarget::Network { dns_address: Some(address), .. }
            if address.to_string() == expected));
    }
    assert!(sharing_test_draft("lan", "tcp", "192.168.1.0/24", "printer.home", "").is_err());
    assert!(sharing_test_draft("lan", "tcp", "192.168.1.0/24", "printer.home", "192.168.1.50").is_ok());
}

#[test]
fn removing_dns_clears_its_address_and_exit_all_protocols_has_no_port() {
    let draft = sharing_test_draft("lan", "tcp", "192.168.1.50/32", "", "192.168.1.50").unwrap();
    assert!(matches!(draft.target, peerward_api::ConsoleSharingTarget::Network { dns_name: None, dns_address: None, .. }));
    let exit = sharing_test_draft("internet", "all", "", "", "").unwrap();
    assert_eq!(exit.protocol, 0);
    assert_eq!(exit.port, None);
    assert!(matches!(exit.source, peerward_api::ConsoleGrantSource::None));
}
