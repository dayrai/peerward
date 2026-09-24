/// Route-specific editor fields; the serialized backing state is never sent verbatim.
#[component]
fn ResourceEditor(
    route: ConsoleRoute,
    document: Signal<String>,
    lookups: Vec<ResourceSummary>,
    disabled: bool,
    existing: bool,
    locale: Locale,
) -> Element {
    let peers = lookups
        .iter()
        .filter(|item| item.details.get("lookup_kind").and_then(Value::as_str) == Some("peer"))
        .cloned()
        .collect::<Vec<_>>();
    let services = lookups
        .iter()
        .filter(|item| item.details.get("lookup_kind").and_then(Value::as_str) == Some("service"))
        .cloned()
        .collect::<Vec<_>>();
    match route {
        ConsoleRoute::Meshes => rsx! {
            if serde_json::from_str::<Value>(&document()).is_ok_and(|fields| fields.get("lease_seconds").is_some()) {
                EditorChoice { label: console_message(locale,"authorization-limit"), field: "lease_seconds", document, disabled, choices: vec![("300", console_message(locale,"authorization-5")), ("900", console_message(locale,"authorization-15")), ("3600", console_message(locale,"authorization-60"))] }
                p { {console_message(locale,"authorization-limit-impact")} }
            }
            EditorField { label: console_message(locale,"address-cidr"), field: "address_cidr", document, disabled:disabled||existing, multiline: false }
            EditorField { label: console_message(locale,"gateway-address"), field: "gateway", document, disabled:disabled||existing, multiline: false }
            EditorField { label: console_message(locale,"dns-suffix"), field: "dns_suffix", document, disabled, multiline: false }
            EditorField { label: console_message(locale,"mesh-mtu"), field: "mtu", document, disabled:disabled||existing, multiline: false }
            EditorField { label: console_message(locale,"reserved-addresses"), field: "reserved", document, disabled:disabled||existing, multiline: false }
            EditorChoice { label: console_message(locale,"default-policy"), field: "default_policy", document, disabled:disabled||existing, choices: vec![("deny", console_message(locale,"deny")), ("allow", console_message(locale,"allow"))] }
            EditorField { label: console_message(locale,"address-quarantine"), field: "quarantine_seconds", document, disabled:disabled||existing, multiline: false }
            EditorField { label: console_message(locale,"credential-overlap"), field: "rotation_overlap_seconds", document, disabled:disabled||existing, multiline: false }
        },
        ConsoleRoute::Authorities => rsx! {
            AuthorityCertificateImport { document, disabled, locale }
            details { class: "advanced-certificate",
                summary { {console_message(locale, "advanced-certificate-value")} }
                EditorField { label: console_message(locale,"authority-certificate"), field: "certificate", document, disabled, multiline: true }
            }
            EditorField { label: console_message(locale,"replaced-authority"), field: "replaces", document, disabled, multiline: false }
        },
        ConsoleRoute::Peers => rsx! {
            EditorField { label: console_message(locale,"device-display-name"), field: "display_name", document, disabled, multiline: false }
            EditorField { label: console_message(locale,"device-location"), field: "location", document, disabled, multiline: false }
            p { class: "muted", {console_message(locale,"device-description-help")} }
            EditorField { label: console_message(locale,"labels"), field: "labels", document, disabled, multiline: false }
            EditorChoice { label: console_message(locale,"administrative-state"), field: "administrative_state", document, disabled, choices: vec![("", console_message(locale,"unchanged")), ("enabled", console_message(locale,"enabled")), ("disabled", console_message(locale,"disabled"))] }
            CredentialSelector { document, disabled, locale }
        },
        ConsoleRoute::Relays => rsx! {
            EditorField { label: console_message(locale,"peer-endpoints"), field: "peer_endpoints", document, disabled, multiline: false }
            EditorField { label: console_message(locale,"backbone-endpoints"), field: "backbone_endpoints", document, disabled, multiline: false }
            EditorField { label: console_message(locale,"relay-region"), field: "region", document, disabled, multiline: false }
            EditorField { label: console_message(locale,"relay-routing-weight"), field: "routing_weight", document, disabled, multiline: false }
            EditorChoice { label: console_message(locale,"administrative-state"), field: "administrative_state", document, disabled, choices: vec![("", console_message(locale,"unchanged")), ("enabled", console_message(locale,"enabled")), ("disabled", console_message(locale,"disabled"))] }
            EditorField { label: console_message(locale,"new-noise-key"), field: "public_key", document, disabled, multiline: false }
            CredentialSelector { document, disabled, locale }
        },
        ConsoleRoute::JoinTickets => rsx! {
            EditorField { label: console_message(locale,"ticket-lifetime"), field: "expires_in_seconds", document, disabled, multiline: false }
            EditorField { label: console_message(locale,"invitation-assigned-name"), field: "assigned_name", document, disabled, multiline: false }
            EditorField { label: console_message(locale,"invitation-labels"), field: "labels", document, disabled, multiline: false }
            EditorChoice { label:console_message(locale,"invitation-mode"),field:"join_mode",document,disabled,
                choices:vec![("bearer",console_message(locale,"invitation-bearer")),("prebound",console_message(locale,"invitation-prebound")),("approval",console_message(locale,"invitation-approval"))] }
            if editor_value(&document(),"join_mode")=="prebound" {
                EditorField { label:console_message(locale,"invitation-fingerprint"),field:"identity_fingerprint",document,disabled,multiline:false }
            }
            p {class:"muted",{console_message(locale,"invitation-mode-help")}}
            EditorChoice { label:console_message(locale,"device-admission"),field:"device_lifecycle",document,disabled,
                choices:vec![("long_lived",console_message(locale,"device-long-lived")),("ephemeral",console_message(locale,"device-ephemeral")),("expiring",console_message(locale,"device-expiring"))] }
            if editor_value(&document(),"device_lifecycle")=="expiring" {
                EditorField { label:console_message(locale,"device-deadline-utc"),field:"device_deadline",document,disabled,multiline:false }
            }
            p {class:"muted",{console_message(locale,"device-admission-help")}}
        },
        ConsoleRoute::Policy => rsx! {
            EditorField { label: console_message(locale,"policy-revision"), field: "revision", document, disabled, multiline: false }
            EditorChoice { label: console_message(locale,"default-action"), field: "default_action", document, disabled, choices: vec![("deny", console_message(locale,"deny")), ("allow", console_message(locale,"allow"))] }
            PolicyRuleEditor { document, disabled, locale }
            fieldset { class: "policy-simulator",
                legend { {console_message(locale,"policy-simulator")} }
                EditorLookup { label: console_message(locale,"source-peer"), field: "source_peer_id", document, disabled: false, choices: peers }
                EditorLookup { label: console_message(locale,"target-service"), field: "target_service_id", document, disabled: false, choices: services }
                EditorChoice { label: console_message(locale,"service-protocol"), field: "simulation_protocol", document, disabled: false, choices: vec![("tcp", "TCP"), ("udp", "UDP")] }
                if !disabled {
                    EditorChoice { label: console_message(locale,"simulation-policy"), field: "simulate_draft", document, disabled: false, choices: vec![("false", console_message(locale,"current-policy")), ("true", console_message(locale,"draft-policy"))] }
                }
            }
        },
        ConsoleRoute::Services => rsx! {
            EditorLookup { label: console_message(locale,"publishing-peer"), field: "peer_id", document, disabled, choices: peers }
            EditorChoice { label: console_message(locale,"service-protocol"), field: "protocol", document, disabled, choices: vec![("tcp", "TCP"), ("udp", "UDP"), ("both", "TCP + UDP")] }
            EditorField { label: console_message(locale,"listen-port"), field: "listen_port", document, disabled, multiline: false }
            EditorField { label: console_message(locale,"dns-alias"), field: "alias", document, disabled, multiline: false }
            EditorField { label: console_message(locale,"labels"), field: "labels", document, disabled, multiline: false }
        },
        ConsoleRoute::Overview
        | ConsoleRoute::Audit
        | ConsoleRoute::Operations
        | ConsoleRoute::Networks
        | ConsoleRoute::Webhooks => rsx! {},
    }
}
