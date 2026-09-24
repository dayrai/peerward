fn device_platform_name(resource: &ResourceSummary, locale: Locale) -> String {
    match resource.details["labels"]["platform"]
        .as_str()
        .unwrap_or("")
    {
        "linux" => "Linux",
        "android" => "Android",
        "windows" => "Windows",
        "macos" => "macOS",
        "" | "unknown" => console_message(locale, "not-reported"),
        value => value,
    }
    .to_owned()
}

#[component]
fn ConsoleDeviceHero(
    resource: ResourceSummary,
    summary: Option<peerward_api::ConsoleDeviceSummary>,
    locale: Locale,
    checking: bool,
    on_check: EventHandler<()>,
) -> Element {
    let state = peer_state_key(&resource);
    let online = state == "device-online";
    let role = if summary
        .as_ref()
        .is_some_and(|value| value.forwarded_resources > 0)
    {
        console_text(locale, "网关设备", "Gateway")
    } else if summary
        .as_ref()
        .is_some_and(|value| value.provided_services > 0)
    {
        console_text(locale, "服务设备", "Service device")
    } else {
        console_text(locale, "网络设备", "Network device")
    };
    let location = resource.details["location"]
        .as_str()
        .filter(|value| !value.is_empty())
        .unwrap_or(role);
    let platform = device_platform_name(&resource, locale);
    // Reuse the prototype's device symbol, as in the inventory, without inventing device metadata.
    let icon = if platform == "Android" {
        "▯"
    } else if role == console_text(locale, "网关设备", "Gateway") {
        "◇"
    } else {
        "▰"
    };
    rsx! {
        div { class: "device-detail-hero",
            span { class: "device-big-icon", aria_hidden: "true", "{icon}" }
            div { class: "device-hero-copy",
                span { class: if online { "device-status good" } else if state == "disabled" { "device-status warn" } else { "device-status neutral" },
                    span { aria_hidden: "true", "●" } {peer_state(&resource, locale)}
                }
                p {
                    "{platform} · {location} · " {console_text(locale, "最近连接 ", "Last connected ")}
                    if let Some(value) = summary.as_ref().and_then(|value| value.last_connected_at.clone()) {
                        ConsoleDeviceLastConnection { value, locale }
                    } else if online { {console_text(locale, "刚刚", "Just now")} }
                    else { {console_text(locale, "暂无记录", "No record")} }
                }
            }
            button { class: "secondary-button device-check-connection", disabled: checking,
                onclick: move |_| on_check.call(()),
                {if checking { console_text(locale, "正在检查…", "Checking…") } else { console_text(locale, "检查连接", "Check connection") }}
            }
        }
        div { class: format!("device-health {}", if online { "healthy" } else { "offline" }),
            span { aria_hidden: "true", if online { "✓" } else { "!" } }
            div {
                strong { {match state {
                    "device-online" => console_text(locale, "设备已连接", "Device is connected"),
                    "device-offline" => console_text(locale, "设备当前离线", "Device is offline"),
                    "disabled" => console_text(locale, "设备已停用", "Device is disabled"),
                    _ => console_text(locale, "设备状态未知", "Device status unknown"),
                }} }
                p { {if online {
                    console_text(locale, "已观测到中继连接；共享访问还取决于授权、DNS 和目标状态。", "A relay connection was observed. Share access also depends on authorization, DNS and target health.")
                } else { peer_state_explanation(&resource, locale) }} }
            }
        }
        if let Some(summary) = summary {
            section { class: "device-runtime-diagnostics", aria_label: console_text(locale, "运行诊断", "Runtime diagnostics"),
                if let Some(at) = summary.runtime_observed_at {
                    p { {console_text(locale, "运行报告时间：", "Runtime report observed: ")} LocalDateTime { value: join_deadline(at), locale } }
                }
                for observation in summary.diagnostics {
                    ConsoleDiagnostic { observation, locale }
                }
            }
        }
    }
}

#[component]
fn ConsoleDiagnostic(observation: peerward_types::RuntimeDiagnostic, locale: Locale) -> Element {
    rsx! {
        div { class: "diagnostic-evidence", role: "status",
            div {
                strong { {peerward_ui::diagnostic_label(locale, observation.code)} }
                p { {peerward_ui::diagnostic_next_step(locale, observation.retry_hint)} }
                p {
                    {console_text(locale, "证据时间：", "Observed: ")}
                    if let Some(at) = observation.observed_at { LocalDateTime { value: join_deadline(at), locale } }
                    else { {console_text(locale, "暂无记录", "No observation")} }
                }
            }
        }
    }
}

#[component]
fn ConsoleDeviceFacts(resource: ResourceSummary, locale: Locale) -> Element {
    let addresses = peer_addresses(&resource);
    let address = addresses
        .iter()
        .find(|value| !value.contains(':'))
        .or(addresses.first());
    rsx! {
        section { class: "device-primary-facts", aria_label: console_message(locale, "device-details"),
            div {
                small { {console_text(locale, "虚拟地址", "Virtual address")} }
                div { class: "copy-inline-value",
                    strong { tabindex: "0", {address.map_or(console_message(locale, "address-unassigned"), String::as_str)} }
                    if let Some(address) = address { CopyValue { value: address.clone(), locale } }
                }
            }
            div {
                small { {console_text(locale, "系统", "System")} }
                strong { {device_platform_name(&resource, locale)} }
            }
            div {
                small { {console_text(locale, "位置说明", "Location description")} }
                strong { {peer_location(&resource, locale)} }

            }
        }
        if peer_has_lifecycle_notice(&resource) {
            div { class: "device-lifecycle-note",
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
    }
}

#[component]
fn ConsoleDeviceTechnical(resource: ResourceSummary, locale: Locale) -> Element {
    rsx! {
        details { class: "device-detail-technical",
            summary { {console_message(locale, "technical-details")} }
            dl { class: "resource-details",
                div { class: "resource-detail",
                    dt { {console_text(locale, "设备 ID", "Device ID")} }
                    dd { class: "copy-inline-value", code { tabindex: "0", "{resource.id}" } CopyValue { value: resource.id.clone(), locale } }
                }
                div { class: "resource-detail",
                    dt { {console_message(locale, "device-network-name")} }
                    dd { code { "{resource.name}" } }
                }
                div { class: "resource-detail",
                    dt { {console_text(locale, "系统 / 型号", "System / model")} }
                    dd { {peer_platform(&resource, locale)} }
                }
                div { class: "resource-detail",
                    dt { {console_message(locale, "device-admission")} }
                    dd { {peer_admission_label(&resource, locale)} }
                }
                for address in peer_addresses(&resource) {
                    div { class: "resource-detail",
                        dt { {if address.contains(':') { "IPv6" } else { "IPv4" }} }
                        dd { class: "copy-inline-value", code { tabindex: "0", "{address}" } CopyValue { value: address, locale } }
                    }
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
