fn default_editor_document(route: ConsoleRoute) -> String {
    let value = match route {
        ConsoleRoute::Meshes => json!({
            "address_cidr": "10.240.0.0/24",
            "gateway": "10.240.0.1",
            "dns_suffix": "mesh.peerward",
            "mtu": "1280",
            "reserved": "",
            "default_policy": "deny",
            "quarantine_seconds": "60",
            "rotation_overlap_seconds": "3600"
        }),
        ConsoleRoute::Authorities => json!({
            "certificate": "", "replaces": "", "certificate_file_name": "",
            "certificate_mesh_id": "", "certificate_serial": "",
            "certificate_not_before": "", "certificate_not_after": "",
            "certificate_import_error": ""
        }),
        ConsoleRoute::Peers => json!({
            "display_name": "",
            "location": "",
            "labels": "",
            "administrative_state": "",
            "public_key": "",
            "serial": "",
            "credential_serials": "[]"
        }),
        ConsoleRoute::Relays => json!({
            "peer_endpoints": "tcp://127.0.0.1:7777",
            "backbone_endpoints": "tcp://127.0.0.1:7778",
            "region": "default",
            "routing_weight": "100",
            "administrative_state": "",
            "public_key": "",
            "serial": "",
            "credential_serials": "[]"
        }),
        ConsoleRoute::JoinTickets => {
            json!({"expires_in_seconds": "300","assigned_name":"","labels":"","join_mode":"bearer","identity_fingerprint":"","device_lifecycle":"long_lived","device_deadline":""})
        }
        ConsoleRoute::Policy => {
            json!({
                "revision": "1", "default_action": "deny", "rules": "[]",
                "source_peer_id": "", "target_service_id": "",
                "simulation_protocol": "tcp", "simulate_draft": "false"
            })
        }
        ConsoleRoute::Services => json!({
            "peer_id": "",
            "protocol": "tcp",
            "listen_port": "443",
            "alias": "",
            "labels": ""
        }),
        ConsoleRoute::Overview
        | ConsoleRoute::Audit
        | ConsoleRoute::Operations
        | ConsoleRoute::Networks
        | ConsoleRoute::Webhooks => json!({}),
    };
    value.to_string()
}
