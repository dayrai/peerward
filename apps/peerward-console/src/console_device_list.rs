#[component]
fn ConsoleDeviceListHead(
    mesh: String,
    mesh_name: String,
    locale: Locale,
    can_write: bool,
    export_query: String,
    on_refresh: EventHandler<()>,
    refreshing: bool,
    on_advanced: EventHandler<()>,
    on_groups: EventHandler<()>,
    #[props(default)] on_add: Option<EventHandler<()>>,
) -> Element {
    rsx! {
        div { class: "page-head device-page-head",
            div {
                div { class: "eyebrow", "{mesh_name}" }
                h1 { {console_text(locale, "设备", "Devices")} }
                p { {console_page_description(locale, ConsoleRoute::Peers)} }
            }
            div { class: "head-actions",
                button { class: "secondary-button", onclick: move |_| on_groups.call(()),
                    {console_text(locale, "设备组", "Device groups")}
                }
                details { class: "device-more",
                    summary { {console_text(locale, "更多", "More")} }
                    div { class: "device-more-menu",
                        button { class: "quiet-button", disabled: refreshing, onclick: move |_| on_refresh.call(()),
                            {if refreshing { console_text(locale, "正在刷新…", "Refreshing…") } else { console_text(locale, "刷新设备", "Refresh devices") }}
                        }
                        a { href: format!("/api/v1/meshes/{mesh}/console/devices/export?{export_query}"),
                            {console_text(locale, "导出当前结果", "Export current results")}
                        }
                        button { class: "quiet-button", onclick: move |_| on_advanced.call(()),
                            {if can_write { console_text(locale, "高级设备工具…", "Advanced device tools…") }
                             else { console_text(locale, "高级设备信息…", "Advanced device information…") }}
                        }
                    }
                }
                if can_write {
                    if let Some(on_add) = on_add {
                        button { onclick:move |_| on_add.call(()), {console_text(locale,"＋ 添加设备","＋ Add device")} }
                    } else { a { class: "primary-link", href: format!("/join-tickets?mesh={mesh}"),
                        {console_text(locale, "＋ 添加设备", "＋ Add device")}
                    } }
                }
            }
        }
    }
}

#[component]
fn ConsoleDeviceJoinGuide(locale: Locale) -> Element {
    rsx! {
        section { class: "device-join-guide",
            div { class: "guide-copy",
                span { class: "guide-icon", aria_hidden: "true", "＋" }
                div {
                    strong { {console_text(locale, "添加设备只需要一次接入", "Enroll a device just once")} }
                    p { {console_text(locale, "控制台生成一次性邀请；在新设备上使用后，设备会建立自己的长期身份。", "Create a one-time invitation; the new device then establishes its own long-term identity.")} }
                }
            }
            ol { class: "guide-flow", aria_label: console_text(locale, "设备加入流程", "Device enrollment steps"),
                for (number, zh, en) in [(1, "创建设备", "Create device"), (2, "扫码或运行命令", "Scan or run command"), (3, "设备上线", "Device online")] {
                    li { b { "{number}" } {console_text(locale, zh, en)} }
                }
            }
        }
    }
}

#[component]
fn ConsoleDeviceList(
    mesh: String,
    resources: Vec<ResourceSummary>,
    summaries: std::collections::BTreeMap<String, peerward_api::ConsoleDeviceSummary>,
    count: Option<u64>,
    filtered: bool,
    locale: Locale,
    on_select: EventHandler<String>,
    empty_message: Option<String>,
) -> Element {
    rsx! {
        section { class: "device-table-panel",
            div { class: "device-table-head",
                h2 {
                    {if filtered { console_text(locale, "筛选结果", "Filtered devices") } else { console_text(locale, "全部设备", "All devices") }}
                    if let Some(total) = count { span { "{total}" } }
                }
                div { class: "device-legend",
                    i { class: "device-dot online", aria_hidden: "true" }
                    {console_message(locale, "device-online")}
                    i { class: "device-dot", aria_hidden: "true" }
                    {console_message(locale, "device-offline")}
                }
            }
            if resources.is_empty() {
                div { class: "empty", role: "status", {empty_message.as_deref().unwrap_or_default()} }
            } else {
                div { class: "device-list-scroll", role: "table", aria_label: console_message(locale, "peers"),
                    div { class: "device-list-row device-list-header", role: "row",
                        for (zh, en) in [("设备", "Device"), ("状态", "Status"), ("地址", "Address"), ("最近连接", "Last connection"), ("访问范围", "Access scope")] {
                            div { role: "columnheader", {console_text(locale, zh, en)} }
                        }
                        div { role: "columnheader", span { class: "sr-only", {console_text(locale, "操作", "Actions")} } }
                    }
                    for resource in resources {
                        ConsoleDeviceListRow {
                            key: "{resource.id}", mesh: mesh.clone(),
                            summary: summaries.get(&resource.id).cloned(), resource, locale, on_select,
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn ConsoleDeviceListRow(
    mesh: String,
    resource: ResourceSummary,
    summary: Option<peerward_api::ConsoleDeviceSummary>,
    locale: Locale,
    on_select: EventHandler<String>,
) -> Element {
    let name = peer_display_name(&resource);
    let state = peer_state_key(&resource);
    let platform = resource
        .details
        .get("labels")
        .and_then(|labels| labels.get("platform"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let platform_name = match platform {
        "linux" => "Linux",
        "android" => "Android",
        "windows" => "Windows",
        "macos" => "macOS",
        "" => console_text(locale, "平台未上报", "Platform not reported"),
        value => value,
    };
    let service_count = summary.as_ref().map_or(0, |value| value.provided_services);
    let gateway_count = summary
        .as_ref()
        .map_or(0, |value| value.forwarded_resources);
    let role = if gateway_count > 0 {
        console_text(locale, "网关设备", "Gateway")
    } else if service_count > 0 {
        console_text(locale, "服务设备", "Service device")
    } else {
        console_text(locale, "网络设备", "Network device")
    };
    let icon = if platform == "android" {
        "▯"
    } else if gateway_count > 0 {
        "◇"
    } else if service_count > 0 {
        "▤"
    } else {
        "▰"
    };
    let location = resource
        .details
        .get("location")
        .and_then(Value::as_str)
        .unwrap_or("");
    let subtitle = format!(
        "{platform_name} · {}",
        if location.is_empty() { role } else { location }
    );
    let addresses = peer_addresses(&resource);
    let address = addresses
        .iter()
        .find(|address| !address.contains(':'))
        .or(addresses.first());
    let access_href = format!("/policy?mesh={mesh}&source=peer%3A{}", resource.id);
    rsx! {
        div { class: "device-list-row", role: "row", "data-peer": "{resource.id}",
            tabindex: "0",
            "data-console-focus-key": format!("device-row:{}", resource.id),
            onclick: { let id = resource.id.clone(); move |_| on_select.call(id.clone()) },
            onkeydown: { let id = resource.id.clone(); move |event: KeyboardEvent| {
                if event.key() == Key::Enter || event.key() == Key::Character(" ".into()) {
                    event.prevent_default();
                    on_select.call(id.clone());
                }
            } },
            div { class: "device-cell", role: "cell",
                span { class: "device-icon", aria_hidden: "true", "{icon}" }
                div { class: "device-copy",
                    button { class: "device-name", r#type: "button", title: "{resource.name}",
                        "data-console-focus-key": format!("device:{}", resource.id),
                        onclick: { let id = resource.id.clone(); move |event| { event.stop_propagation(); on_select.call(id.clone()); } },
                        onkeydown: move |event| event.stop_propagation(),
                        "{name}"
                    }
                    small { title: "{subtitle}", "{subtitle}" }
                }
            }
            div { role: "cell",
                span { class: if state == "device-online" { "device-status good" } else if state == "disabled" { "device-status warn" } else { "device-status neutral" },
                    span { aria_hidden: "true", "●" } {peer_state(&resource, locale)}
                }
            }
            div { role: "cell", class: "device-list-address",
                if let Some(address) = address { code { title: addresses.join(" · "), "{address}" } }
                else { span { class: "muted", {console_message(locale, "address-unassigned")} } }
            }
            div { role: "cell",
                if let Some(value) = summary.as_ref().and_then(|summary| summary.last_connected_at.clone()) {
                    ConsoleDeviceLastConnection { value, locale }
                } else if state == "device-online" {
                    {console_text(locale, "刚刚", "Just now")}
                } else {
                    span { class: "muted", {console_text(locale, "暂无记录", "No record")} }
                }
            }
            div { class: "device-access-scope", role: "cell",
                a { href: access_href, title: console_text(locale, "查看这台设备的实际访问结果", "View this device's evaluated access"),
                    onclick: move |event| event.stop_propagation(),
                    onkeydown: move |event| event.stop_propagation(),
                    {if gateway_count > 0 { match locale { Locale::ZhCn => format!("转发 {gateway_count} 个共享"), Locale::EnUs => format!("Forwards {gateway_count} shares") } }
                     else if service_count > 0 { match locale { Locale::ZhCn => format!("共享 {service_count} 个服务"), Locale::EnUs => format!("Shares {service_count} services") } }
                     else { console_text(locale, "查看访问", "View access").to_owned() }}
                }
            }
            div { role: "cell",
                button { class: "device-row-more", r#type: "button",
                    aria_label: match locale { Locale::ZhCn => format!("查看{name}详情"), Locale::EnUs => format!("View {name} details") },
                    onclick: move |event| { event.stop_propagation(); on_select.call(resource.id.clone()); },
                    onkeydown: move |event| event.stop_propagation(), "•••"
                }
            }
        }
    }
}

#[component]
fn ConsoleDeviceLastConnection(value: String, locale: Locale) -> Element {
    let machine = value.clone();
    let mut displayed = use_signal(|| value.clone());
    use_effect(use_reactive((&value, &locale), move |(value, locale)| {
        #[cfg(target_arch = "wasm32")]
        {
            let timestamp = js_sys::Date::parse(&value);
            if timestamp.is_finite() {
                // Relative labels deliberately discard subsecond precision after clamping.
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let seconds = ((js_sys::Date::now() - timestamp) / 1000.0).max(0.0) as u64;
                let (amount, zh, en) = if seconds < 60 {
                    (0, "刚刚", "Just now")
                } else if seconds < 3600 {
                    (seconds / 60, "分钟前", "min ago")
                } else if seconds < 86400 {
                    (seconds / 3600, "小时前", "h ago")
                } else {
                    (seconds / 86400, "天前", "d ago")
                };
                displayed.set(if amount == 0 {
                    console_text(locale, zh, en).to_owned()
                } else {
                    format!("{amount} {}", console_text(locale, zh, en))
                });
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = (&value, locale, &mut displayed);
    }));
    rsx! { time { datetime: "{machine}", title: "{machine}", "{displayed}" } }
}
