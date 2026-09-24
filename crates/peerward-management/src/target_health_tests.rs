use crate::*;

#[test]
fn target_probes_cannot_escape_scope_or_use_implicit_endpoints() {
    let subnet = ResourceTarget::Subnet {
        prefix: "192.168.2.0/24".parse().unwrap(),
        site_id: uuid::Uuid::new_v4(),
    };
    for (address, port, valid) in [
        ("192.168.2.50", 631, true),
        ("192.168.3.50", 631, false),
        ("192.168.2.50", 0, false),
        ("127.0.0.1", 631, false),
    ] {
        assert_eq!(
            TargetProbe {
                address: address.parse().unwrap(),
                port
            }
            .validate(&subnet)
            .is_ok(),
            valid
        );
    }
    let internet = ResourceTarget::Internet {
        ipv4: true,
        ipv6: false,
    };
    for (address, valid) in [
        ("8.8.8.8", true),
        ("169.254.169.254", false),
        ("192.168.2.50", false),
        ("::1", false),
    ] {
        assert_eq!(
            TargetProbe {
                address: address.parse().unwrap(),
                port: 443
            }
            .validate(&internet)
            .is_ok(),
            valid
        );
    }
    assert!(
        serde_json::from_value::<TargetProbe>(
            serde_json::json!({"address":"8.8.8.8","port":443,"url":"https://example.test"})
        )
        .is_err()
    );
}
