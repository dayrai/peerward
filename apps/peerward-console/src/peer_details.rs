fn peer_display_name(resource: &ResourceSummary) -> String {
    resource
        .details
        .get("display_name")
        .and_then(Value::as_str)
        .filter(|name| !name.is_empty())
        .unwrap_or(&resource.name)
        .to_owned()
}

fn peer_addresses(resource: &ResourceSummary) -> Vec<String> {
    resource
        .details
        .get("mesh_addresses")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn peer_location(resource: &ResourceSummary, locale: Locale) -> String {
    resource
        .details
        .get("location")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .unwrap_or(console_message(locale, "not-set"))
        .to_owned()
}

fn peer_platform(resource: &ResourceSummary, locale: Locale) -> String {
    let labels = resource.details.get("labels");
    let values = ["platform", "platform_version", "device_model"]
        .into_iter()
        .filter_map(|key| {
            labels
                .and_then(|labels| labels.get(key))
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
        })
        .collect::<Vec<_>>();
    if values.is_empty() {
        console_message(locale, "not-reported").into()
    } else {
        values.join(" · ")
    }
}

fn peer_state_key(resource: &ResourceSummary) -> &'static str {
    if resource
        .details
        .get("administrative_state")
        .and_then(Value::as_str)
        == Some("disabled")
    {
        "disabled"
    } else {
        match resource.details.get("online").and_then(Value::as_bool) {
            Some(true) => "device-online",
            Some(false) => "device-offline",
            None => "not-reported",
        }
    }
}

fn peer_state(resource: &ResourceSummary, locale: Locale) -> &'static str {
    console_message(locale, peer_state_key(resource))
}

fn peer_state_explanation(resource: &ResourceSummary, locale: Locale) -> &'static str {
    match peer_state_key(resource) {
        "disabled" => console_text(
            locale,
            "这台设备已停用，不能重新连接或使用共享。",
            "This device is disabled and cannot reconnect or use shares.",
        ),
        "device-online" => console_text(
            locale,
            "设备当前已连接。能否访问具体共享仍由访问规则和目标状态决定。",
            "The device is connected. Access to a specific share still depends on access rules and target state.",
        ),
        "device-offline" => console_text(
            locale,
            "设备当前没有有效在线状态。已有访问规则不会因为离线自动删除。",
            "The device has no current online connection. Existing access rules are not removed when it goes offline.",
        ),
        _ => console_text(
            locale,
            "暂时没有足够的运行状态信息。",
            "There is not enough runtime status information yet.",
        ),
    }
}

fn peer_state_class(resource: &ResourceSummary) -> &'static str {
    match peer_state_key(resource) {
        "device-online" => "ready",
        "disabled" => "blocked",
        "device-offline" => "offline",
        _ => "unknown",
    }
}

fn peer_admission_label(resource: &ResourceSummary, locale: Locale) -> &'static str {
    console_message(
        locale,
        match resource.details["admission"]["kind"].as_str() {
            Some("ephemeral") => "device-ephemeral",
            Some("expiring") => "device-expiring",
            _ => "device-long-lived",
        },
    )
}

fn peer_has_lifecycle_notice(resource: &ResourceSummary) -> bool {
    matches!(
        resource.details["admission"]["kind"].as_str(),
        Some("ephemeral" | "expiring")
    ) || resource.details["admission_end_reason"].as_str().is_some()
}

#[component]
fn PeerDetails(resource: ResourceSummary, locale: Locale) -> Element {
    let addresses = peer_addresses(&resource);
    let state_class = peer_state_class(&resource);
    rsx! {
        section { class: "card peer-details device-status-card", aria_label: console_message(locale, "device-details"),
            div { class: "device-status-head",
                div { class: format!("device-state-mark {state_class}"), aria_hidden: "true",
                    if state_class == "ready" { "✓" } else if state_class == "blocked" { "×" } else { "!" }
                }
                div {
                    div { class: "device-status-title",
                        h2 { {peer_display_name(&resource)} }
                        span { class: format!("device-state-pill {state_class}"), {peer_state(&resource, locale)} }
                    }
                    p { class: "muted", {peer_state_explanation(&resource, locale)} }
                }
            }
            div { class: "device-fact-grid",
                div { class: "device-fact",
                    small { {console_message(locale, "mesh-ip")} }
                    if addresses.is_empty() {
                        strong { {console_message(locale, "address-unassigned")} }
                    } else {
                        for address in &addresses {
                            div { class: "device-address-line", code { tabindex: "0", "{address}" } CopyValue { value: address.clone(), locale } }
                        }
                    }
                }
                div { class: "device-fact",
                    small { {console_text(locale, "系统", "System")} }
                    strong { {peer_platform(&resource, locale)} }
                }
                div { class: "device-fact",
                    small { {console_message(locale, "device-location")} }
                    strong { {peer_location(&resource, locale)} }
                }
            }
            if peer_has_lifecycle_notice(&resource) {
                div { class: "device-lifecycle-note",
                    span { aria_hidden: "true", "i" }
                    div {
                        strong { {peer_admission_label(&resource, locale)} }
                        if let Some(until) = resource.details["admission"]["valid_until"].as_u64() {
                            p { {console_text(locale, "自动结束时间：", "Automatic end: ")} LocalDateTime { value: join_deadline(until), locale } }
                        }
                        if let Some(reason) = resource.details["admission_end_reason"].as_str() {
                            p { {console_message(locale, if reason == "expired" { "device-admission-expired" } else { "device-admission-retired" })} }
                        }
                    }
                }
            }
            details { class: "advanced-tools device-technical-details",
                summary { {console_message(locale, "technical-details")} }
                dl { class: "resource-details",
                    div { class: "resource-detail",
                        dt { {console_message(locale, "device-network-name")} }
                        dd { code { "{resource.name}" } }
                    }
                    div { class: "resource-detail",
                        dt { {console_message(locale, "device-admission")} }
                        dd {
                            {peer_admission_label(&resource, locale)}
                            if let Some(until) = resource.details["admission"]["valid_until"].as_u64() { " · " LocalDateTime { value: join_deadline(until), locale } }
                        }
                    }
                    div { class: "resource-detail",
                        dt { {console_message(locale, "identifier")} }
                        dd { code { "{resource.id}" } CopyValue { value: resource.id.clone(), locale } }
                    }
                    for key in ["labels", "presence", "credentials"] {
                        if let Some(value) = resource.details.get(key) {
                            div { class: "resource-detail", dt { {console_message(locale, key)} } dd { {display_detail(value)} } }
                        }
                    }
                }
            }
        }
    }
}
