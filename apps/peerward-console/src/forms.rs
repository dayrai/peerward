include!("form_defaults.rs");

fn editor_value(document: &str, field: &str) -> String {
    serde_json::from_str::<Value>(document)
        .ok()
        .and_then(|value| value.get(field).and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_default()
}

fn set_editor_value(mut document: Signal<String>, field: &'static str, value: String) {
    let mut object = serde_json::from_str::<Value>(&document())
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    object.insert(field.into(), Value::String(value));
    document.set(Value::Object(object).to_string());
}

fn set_editor_values(mut document: Signal<String>, values: &[(&str, String)]) {
    let mut object = serde_json::from_str::<Value>(&document())
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    for (field, value) in values {
        object.insert((*field).into(), Value::String(value.clone()));
    }
    document.set(Value::Object(object).to_string());
}

fn policy_rules(document: &str) -> Vec<Value> {
    serde_json::from_str::<Vec<Value>>(&editor_value(document, "rules")).unwrap_or_default()
}

fn set_policy_rules(document: Signal<String>, rules: Vec<Value>) {
    set_editor_value(document, "rules", Value::Array(rules).to_string());
}

fn set_policy_rule_value(
    document: Signal<String>,
    index: usize,
    section: Option<&str>,
    field: &str,
    value: Value,
) {
    let mut rules = policy_rules(&document());
    let Some(rule) = rules.get_mut(index).and_then(Value::as_object_mut) else {
        return;
    };
    if let Some(section) = section {
        if let Some(target) = rule.get_mut(section).and_then(Value::as_object_mut) {
            target.insert(field.into(), value);
        }
    } else {
        rule.insert(field.into(), value);
    }
    set_policy_rules(document, rules);
}

fn csv_values(value: &str) -> Value {
    Value::Array(
        value
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| Value::String(value.into()))
            .collect(),
    )
}

fn label_values(value: &str) -> Value {
    let object = value
        .split(',')
        .filter_map(|pair| pair.trim().split_once('='))
        .map(|(key, value)| (key.trim().into(), Value::String(value.trim().into())))
        .collect();
    Value::Object(object)
}

fn port_values(value: &str) -> Value {
    Value::Array(value.split(',').filter_map(|span| {
        let span = span.trim();
        if span.is_empty() { return None; }
        let (first, last) = span.split_once('-').unwrap_or((span, span));
        Some(json!({"first": first.trim().parse::<u16>().ok()?, "last": last.trim().parse::<u16>().ok()?}))
    }).collect())
}

fn joined_values(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

fn joined_ports(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(|value| {
                    let first = value.get("first")?.as_u64()?;
                    let last = value.get("last")?.as_u64()?;
                    Some(if first == last {
                        first.to_string()
                    } else {
                        format!("{first}-{last}")
                    })
                })
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

fn editor_document_for_resource(route: ConsoleRoute, resource: &ResourceSummary) -> String {
    let mut document = serde_json::from_str::<Value>(&default_editor_document(route))
        .ok()
        .and_then(|value| value.as_object().cloned())
        .unwrap_or_default();
    let copy = |document: &mut serde_json::Map<String, Value>, field: &str| {
        if let Some(value) = resource.details.get(field) {
            let value = value
                .as_str()
                .map_or_else(|| value.to_string(), str::to_owned);
            document.insert(field.into(), Value::String(value));
        }
    };
    match route {
        ConsoleRoute::Meshes => {
            for field in [
                "address_cidr",
                "gateway",
                "dns_suffix",
                "mtu",
                "default_policy",
                "lease_seconds",
            ] {
                copy(&mut document, field);
            }
        }
        ConsoleRoute::Peers => {
            copy(&mut document, "display_name");
            copy(&mut document, "location");
            copy(&mut document, "administrative_state");
            document.insert(
                "labels".into(),
                Value::String(editor_labels(resource.details.get("labels"))),
            );
            insert_credential_choices(&mut document, resource.details.get("credentials"));
        }
        ConsoleRoute::Relays => {
            copy(&mut document, "administrative_state");
            copy(&mut document, "region");
            copy(&mut document, "routing_weight");
            for field in ["peer_endpoints", "backbone_endpoints"] {
                if let Some(values) = resource.details.get(field).and_then(Value::as_array) {
                    document.insert(
                        field.into(),
                        Value::String(
                            values
                                .iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(", "),
                        ),
                    );
                }
            }
            insert_credential_choices(&mut document, resource.details.get("credentials"));
        }
        ConsoleRoute::Services => {
            for field in ["peer_id", "listen_port", "alias"] {
                copy(&mut document, field);
            }
            if let Some(protocols) = resource.details.get("protocols").and_then(Value::as_array) {
                let values = protocols
                    .iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>();
                document.insert(
                    "protocol".into(),
                    Value::String(
                        if values.len() == 2 {
                            "both"
                        } else {
                            values.first().copied().unwrap_or("tcp")
                        }
                        .into(),
                    ),
                );
            }
            document.insert(
                "labels".into(),
                Value::String(editor_labels(resource.details.get("labels"))),
            );
        }
        ConsoleRoute::JoinTickets => {
            if let Some(settings) = resource.details.get("settings") {
                document.insert(
                    "assigned_name".into(),
                    Value::String(
                        settings
                            .get("name")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .into(),
                    ),
                );
                document.insert(
                    "labels".into(),
                    Value::String(editor_labels(settings.get("labels"))),
                );
                document.insert(
                    "join_mode".into(),
                    Value::String(settings["mode"]["kind"].as_str().unwrap_or("bearer").into()),
                );
                document.insert(
                    "device_lifecycle".into(),
                    Value::String(
                        settings["lifecycle"]["kind"]
                            .as_str()
                            .unwrap_or("long_lived")
                            .into(),
                    ),
                );
                let deadline = settings["lifecycle"]["valid_until"]
                    .as_i64()
                    .and_then(|seconds| time::OffsetDateTime::from_unix_timestamp(seconds).ok())
                    .and_then(|at| {
                        time::format_description::parse_borrowed::<2>(
                            "[year]-[month]-[day]T[hour]:[minute]",
                        )
                        .ok()
                        .and_then(|format| at.format(&format).ok())
                    })
                    .unwrap_or_default();
                document.insert("device_deadline".into(), Value::String(deadline));
                document.insert(
                    "identity_fingerprint".into(),
                    Value::String(
                        settings["mode"]["identity_fingerprint"]
                            .as_str()
                            .unwrap_or("")
                            .into(),
                    ),
                );
            }
        }
        ConsoleRoute::Authorities
        | ConsoleRoute::Policy
        | ConsoleRoute::Overview
        | ConsoleRoute::Audit
        | ConsoleRoute::Operations
        | ConsoleRoute::Networks
        | ConsoleRoute::Webhooks => {}
    }
    Value::Object(document).to_string()
}

fn insert_credential_choices(
    document: &mut serde_json::Map<String, Value>,
    credentials: Option<&Value>,
) {
    let mut choices = Vec::new();
    let mut preferred = None;
    if let Some(credentials) = credentials {
        for lifecycle in ["pending", "active"] {
            if let Some(serial) = credentials
                .get(lifecycle)
                .filter(|value| !value.is_null())
                .and_then(|value| value.get("serial"))
                .and_then(Value::as_str)
            {
                preferred.get_or_insert_with(|| serial.to_owned());
                choices.push(json!({"serial": serial, "lifecycle": lifecycle}));
            }
        }
        if let Some(overlap) = credentials.get("overlap").and_then(Value::as_array) {
            for item in overlap {
                if let Some(serial) = item.get("serial").and_then(Value::as_str) {
                    choices.push(json!({"serial": serial, "lifecycle": "overlap"}));
                }
            }
        }
    }
    choices.sort_by(|left, right| left["serial"].as_str().cmp(&right["serial"].as_str()));
    choices.dedup_by(|left, right| left["serial"] == right["serial"]);
    document.insert(
        "credential_serials".into(),
        Value::String(Value::Array(choices).to_string()),
    );
    if let Some(serial) = preferred {
        document.insert("serial".into(), Value::String(serial));
    }
}

#[component]
fn CredentialSelector(document: Signal<String>, disabled: bool, locale: Locale) -> Element {
    let choices =
        serde_json::from_str::<Vec<Value>>(&editor_value(&document(), "credential_serials"))
            .unwrap_or_default();
    let no_choices = choices.is_empty();
    let selected = editor_value(&document(), "serial");
    rsx! {
        div { class: "form-field",
            label { r#for: "peerward-form-serial", {console_message(locale, "credential-serial")} }
            select {
                id: "peerward-form-serial",
                value: "{selected}",
                disabled: disabled || no_choices,
                onchange: move |event| set_editor_value(document, "serial", event.value()),
                if no_choices {
                    option { value: "", {console_message(locale, "no-credential-lifecycle")} }
                }
                for choice in choices {
                    if let (Some(serial), Some(lifecycle)) = (
                        choice.get("serial").and_then(Value::as_str),
                        choice.get("lifecycle").and_then(Value::as_str),
                    ) {
                        option { value: "{serial}", "{lifecycle} · {serial}" }
                    }
                }
            }
        }
    }
}

fn editor_labels(value: Option<&Value>) -> String {
    value
        .and_then(Value::as_object)
        .map(|labels| {
            labels
                .iter()
                .filter_map(|(key, value)| value.as_str().map(|value| format!("{key}={value}")))
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default()
}

#[component]
fn EditorField(
    label: &'static str,
    field: &'static str,
    document: Signal<String>,
    disabled: bool,
    multiline: bool,
) -> Element {
    let id = format!("peerward-form-{field}");
    let value = editor_value(&document(), field);
    rsx! {
        div { class: if multiline { "form-field form-field--wide" } else { "form-field" },
            label { r#for: "{id}", "{label}" }
            if multiline {
                textarea {
                    id: "{id}",
                    value: "{value}",
                    disabled,
                    oninput: move |event| set_editor_value(document, field, event.value()),
                }
            } else {
                input {
                    id: "{id}",
                    r#type: if field == "device_deadline" { "datetime-local" } else { "text" },
                    value: "{value}",
                    disabled,
                    oninput: move |event| set_editor_value(document, field, event.value()),
                }
            }
        }
    }
}

#[component]
fn EditorChoice(
    label: &'static str,
    field: &'static str,
    document: Signal<String>,
    disabled: bool,
    choices: Vec<(&'static str, &'static str)>,
) -> Element {
    let id = format!("peerward-form-{field}");
    let value = editor_value(&document(), field);
    rsx! {
        div { class: "form-field",
            label { r#for: "{id}", "{label}" }
            select {
                id: "{id}",
                value: "{value}",
                disabled,
                onchange: move |event| set_editor_value(document, field, event.value()),
                for (choice, text) in choices {
                    option { value: "{choice}", "{text}" }
                }
            }
        }
    }
}

#[component]
fn EditorLookup(
    label: &'static str,
    field: &'static str,
    document: Signal<String>,
    disabled: bool,
    choices: Vec<ResourceSummary>,
) -> Element {
    let id = format!("peerward-form-{field}");
    let list_id = format!("{id}-choices");
    let value = editor_value(&document(), field);
    rsx! {
        div { class: "form-field",
            label { r#for: "{id}", "{label}" }
            input {
                id: "{id}", list: "{list_id}", value: "{value}", disabled,
                autocomplete: "off",
                oninput: move |event| set_editor_value(document, field, event.value()),
            }
            datalist { id: "{list_id}",
                for choice in choices {
                    option { value: "{choice.id}", label: "{choice.name}" }
                }
            }
        }
    }
}

#[component]
fn PolicyRuleEditor(document: Signal<String>, disabled: bool, locale: Locale) -> Element {
    let rules = policy_rules(&document());
    rsx! {
        section { class: "policy-rule-editor", aria_label: console_message(locale, "policy-rules"),
            h3 { {console_message(locale, "policy-rules")} }
            if rules.is_empty() { p { class: "empty", {console_message(locale, "no-policy-rules")} } }
            for (index, rule) in rules.into_iter().enumerate() {
                PolicyRuleCard { index, rule, document, disabled, locale }
            }
            button { r#type: "button", disabled, onclick: move |_| {
                let mut rules = policy_rules(&document());
                rules.push(json!({
                    "id": uuid::Uuid::new_v4(), "priority": rules.len() * 10 + 10,
                    "action": "deny", "enabled": true, "log": false,
                    "source": {"peer_ids": [], "labels": {}, "cidrs": []},
                    "destination": {"peer_ids": [], "labels": {}, "cidrs": []},
                    "protocol": "any", "destination_ports": []
                }));
                set_policy_rules(document, rules);
            }, {console_message(locale, "add-rule")} }
            p { class: "muted", {console_message(locale, "policy-priority-help")} }
            details { class: "advanced-policy",
                summary { {console_message(locale, "advanced-policy-json")} }
                EditorField { label: console_message(locale,"advanced-policy-json"), field: "rules", document, disabled, multiline: true }
            }
        }
    }
}

#[component]
fn PolicyRuleCard(
    index: usize,
    rule: Value,
    document: Signal<String>,
    disabled: bool,
    locale: Locale,
) -> Element {
    let id = rule
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let source = rule.get("source");
    let destination = rule.get("destination");
    let source_peers = joined_values(source.and_then(|value| value.get("peer_ids")));
    let source_cidrs = joined_values(source.and_then(|value| value.get("cidrs")));
    let destination_peers = joined_values(destination.and_then(|value| value.get("peer_ids")));
    let destination_cidrs = joined_values(destination.and_then(|value| value.get("cidrs")));
    let labels = |value: Option<&Value>| {
        value
            .and_then(Value::as_object)
            .map(|labels| {
                labels
                    .iter()
                    .filter_map(|(key, value)| value.as_str().map(|value| format!("{key}={value}")))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default()
    };
    let source_labels = labels(source.and_then(|value| value.get("labels")));
    let destination_labels = labels(destination.and_then(|value| value.get("labels")));
    let ports = joined_ports(rule.get("destination_ports"));
    let action = rule
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("deny")
        .to_owned();
    let protocol = rule
        .get("protocol")
        .and_then(Value::as_str)
        .unwrap_or("any")
        .to_owned();
    let enabled = rule.get("enabled").and_then(Value::as_bool).unwrap_or(true);
    let log = rule.get("log").and_then(Value::as_bool).unwrap_or(false);
    rsx! {
        article { class: "policy-rule card", aria_label: "Rule {index}",
            h4 { {format!("{} {}", console_message(locale, "rule"), index + 1)} }
            label { {console_message(locale, "resource-rule-priority")}
                input { r#type: "number", min: "0", max: "4294967295", disabled,
                    value: rule.get("priority").and_then(Value::as_u64).unwrap_or_default().to_string(),
                    oninput: move |event| { if let Ok(priority) = event.value().parse::<u32>() { set_policy_rule_value(document, index, None, "priority", json!(priority)); } }
                }
            }
            p { code { "{id}" } CopyValue { value: id, locale } }
            label { input { r#type: "checkbox", checked: enabled, disabled,
                onchange: move |event| set_policy_rule_value(document, index, None, "enabled", Value::Bool(event.checked())) } {console_message(locale, "enabled")} }
            label { {console_message(locale, "action")} select { disabled, value: "{action}",
                onchange: move |event| set_policy_rule_value(document, index, None, "action", Value::String(event.value())),
                option { value: "allow", {console_message(locale, "allow")} } option { value: "deny", {console_message(locale, "deny")} } } }
            label { {console_message(locale, "source-peers")} input { value: "{source_peers}", disabled, oninput: move |event| set_policy_rule_value(document,index,Some("source"),"peer_ids",csv_values(&event.value())) } }
            label { {console_message(locale, "source-labels")} input { value: "{source_labels}", disabled, oninput: move |event| set_policy_rule_value(document,index,Some("source"),"labels",label_values(&event.value())) } }
            label { {console_message(locale, "source-cidrs")} input { value: "{source_cidrs}", disabled, oninput: move |event| set_policy_rule_value(document,index,Some("source"),"cidrs",csv_values(&event.value())) } }
            label { {console_message(locale, "destination-peers")} input { value: "{destination_peers}", disabled, oninput: move |event| set_policy_rule_value(document,index,Some("destination"),"peer_ids",csv_values(&event.value())) } }
            label { {console_message(locale, "destination-labels")} input { value: "{destination_labels}", disabled, oninput: move |event| set_policy_rule_value(document,index,Some("destination"),"labels",label_values(&event.value())) } }
            label { {console_message(locale, "destination-cidrs")} input { value: "{destination_cidrs}", disabled, oninput: move |event| set_policy_rule_value(document,index,Some("destination"),"cidrs",csv_values(&event.value())) } }
            label { {console_message(locale, "protocol")} select { disabled, value: "{protocol}", onchange: move |event| set_policy_rule_value(document,index,None,"protocol",Value::String(event.value())),
                option { value: "any", "Any" } option { value: "tcp", "TCP" } option { value: "udp", "UDP" } option { value: "icmp", "ICMP" } } }
            label { {console_message(locale, "destination-ports")} input { value: "{ports}", disabled, oninput: move |event| set_policy_rule_value(document,index,None,"destination_ports",port_values(&event.value())) } }
            label { input { r#type: "checkbox", checked: log, disabled, onchange: move |event| set_policy_rule_value(document,index,None,"log",Value::Bool(event.checked())) } {console_message(locale, "log-decisions")} }
            div { class: "actions",
                button { r#type: "button", disabled, onclick: move |_| { let mut rules=policy_rules(&document()); rules.remove(index); set_policy_rules(document,rules); }, {console_message(locale,"remove-rule")} }
            }
        }
    }
}
