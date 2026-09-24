#[component]
#[allow(unused_mut)]
fn SharingDetailsFields(
    locale: Locale, kind: String, disabled: bool, more_settings: bool,
    mut name: Signal<String>, mut provider: Signal<String>, mut provider_query: Signal<String>,
    mut provider_cursor: Signal<String>, providers: Resource<Result<peerward_api::ConsoleDevicePage, String>>,
    mut protocol: Signal<String>, mut port: Signal<String>, mut port_edited: Signal<bool>, mut prefix: Signal<String>,
    mut site: Signal<String>, mut ipv6: Signal<bool>, mut dns: Signal<String>,
    mut dns_address: Signal<String>, mut reason: Signal<String>,
) -> Element {
    let description = match kind.as_str() {
        "service" => console_text(locale, "服务直接运行在加入 Mesh 的设备上。", "The service runs directly on a device in the mesh."),
        "lan" => console_text(locale, "目标本身不需要安装 Peerward，由网关设备负责转发。", "The target does not need Peerward; a gateway forwards traffic to it."),
        _ => console_text(locale, "出口由网关设备提供，并使用 SNAT 对外访问；不会自动开放公网入站。", "The gateway provides outbound access using SNAT; public inbound access is not enabled."),
    };
    let provider_label = match kind.as_str() {
        "service" => console_text(locale, "提供设备", "Provider device"),
        "lan" => console_text(locale, "网关设备", "Gateway device"),
        _ => console_text(locale, "出口网关", "Exit gateway"),
    };
    let next_provider = providers.read().as_ref().and_then(|r| r.as_ref().ok()).and_then(|p| p.next_cursor.clone());
    let service = kind == "service";
    let loading_providers = providers.state()() == UseResourceState::Pending;
    let host_target = prefix().parse::<ipnet::IpNet>().ok().is_some_and(|net| net.prefix_len() == if net.addr().is_ipv4() { 32 } else { 128 });
    rsx! {
        fieldset { class: "sharing-details-fields", disabled,
            legend { class: "sr-only", {console_text(locale, "共享信息", "Sharing details")} }
            div { class: "workflow-note",
                strong { {resource_kind_label(locale, &kind)} }
                p { "{description}" }
            }
            label { r#for: "share-name", {console_text(locale, "共享名称", "Share name")}
                input { id: "share-name", value: name, required: true, maxlength: 128,
                    placeholder: if service { console_text(locale, "例如：家庭 NAS 文件服务", "For example: Home NAS files") } else if kind == "lan" { console_text(locale, "例如：客厅打印机", "For example: Living room printer") } else { console_text(locale, "例如：家庭互联网出口", "For example: Home internet exit") },
                    oninput: move |e| name.set(e.value()),
                }
            }
            div { class: "sharing-provider-field",
                div { class: "sharing-provider-caption",
                    label { r#for: "share-provider", "{provider_label}" }
                    span { role: "status",
                        if loading_providers { {console_text(locale, "正在读取候选项…", "Loading choices…")} }
                    }
                }
                select { id: "share-provider", value: provider, required: true, onchange: move |e| provider.set(e.value()),
                    option { value: "", selected: provider().is_empty(), {console_text(locale, "请选择设备", "Select a device")} }
                    if let Some(Ok(page)) = providers.read().as_ref() {
                        for peer in page.items.iter().filter(|p| p.administrative_state == peerward_api::AdministrativeState::Enabled) {
                            option { value: peer.id.to_string(), selected: provider() == peer.id.to_string(),
                                if peer.display_name.is_empty() { "{peer.name}" } else { "{peer.display_name}" }
                            }
                        }
                    }
                }
            }
            if !loading_providers {
                {console_picker_feedback(providers, providers.read().as_ref().and_then(|r| r.as_ref().ok()).is_some_and(|p| p.items.iter().all(|p| p.administrative_state != peerward_api::AdministrativeState::Enabled)), locale)}
            }
            if next_provider.is_some() || !provider_query().is_empty() || !provider_cursor().is_empty() {
                label { r#for: "share-provider-query", {console_text(locale, "查找提供设备 / 网关", "Find provider / gateway")}
                    input { id: "share-provider-query", value: provider_query, oninput: move |e| { provider_query.set(e.value()); provider_cursor.set(String::new()); provider.set(String::new()); } }
                }
                if let Some(next) = next_provider { button { r#type: "button", class: "secondary-button", onclick: move |_| { provider_cursor.set(next.clone()); provider.set(String::new()); }, {console_text(locale, "更多提供设备", "More publishers")} } }
                if !provider_cursor().is_empty() { button { r#type: "button", class: "secondary-button", onclick: move |_| { provider_cursor.set(String::new()); provider.set(String::new()); }, {console_text(locale, "提供设备首页", "First publisher page")} } }
            }
            if kind == "lan" {
                label { r#for: "share-prefix", {console_text(locale, "局域网目标", "LAN target")}
                    input { id: "share-prefix", value: prefix, required: true, placeholder: "192.168.1.50/32", oninput: move |e| prefix.set(e.value()) }
                }
            }
            if kind != "internet" {
                div { class: "sharing-form-pair",
                    div { class: "sharing-protocol-field",
                        label { r#for: "share-protocol", {console_text(locale, "协议", "Protocol")} }
                        select { id: "share-protocol", value: protocol, "data-console-click-picker": "true",
                            onchange: move |e| {
                                let value = e.value();
                                if !port_edited() { port.set(sharing_default_port(&value, service).into()); }
                                protocol.set(value);
                            },
                            option { value: "tcp", selected: protocol() == "tcp", "TCP" }
                            option { value: "udp", selected: protocol() == "udp", "UDP" }
                            if service {
                                option { value: "http", selected: protocol() == "http", "HTTP" }
                                option { value: "https", selected: protocol() == "https", "HTTPS" }
                                option { value: "both", selected: protocol() == "both", "TCP + UDP" }
                            } else {
                                option { value: "all", selected: protocol() == "all", {console_text(locale, "全部协议", "All protocols")} }
                            }
                        }
                    }
                    label { r#for: "share-port", {console_text(locale, "端口", "Port")}
                        input { id: "share-port", r#type: "number", min: 1, max: 65535, required: protocol() != "all", disabled: protocol() == "all", value: port, oninput: move |e| { port.set(e.value()); port_edited.set(true); } }
                    }
                }
                label { r#for: "share-dns", {console_text(locale, "DNS 名称（可选）", "DNS name (optional)")}
                    input { id: "share-dns", value: dns, placeholder: if service { console_text(locale, "例如：nas", "For example: nas") } else { "printer.home" }, oninput: move |e| dns.set(e.value()) }
                }
                if !dns().is_empty() && service {
                    p { class: "sharing-field-help", {console_text(locale, "填写服务别名（如 nas），完整域名由网络的 DNS 设置生成。", "Enter a service alias, such as nas; the network DNS settings determine its full name.")} }
                }
                if !dns().is_empty() && kind == "lan" && (!host_target || more_settings) {
                    label { r#for: "share-dns-address", {console_text(locale, "DNS 解析地址", "DNS address")}
                        input { id: "share-dns-address", value: dns_address, required: !host_target, oninput: move |e| dns_address.set(e.value()) }
                    }
                }
                p { class: "sharing-field-help",
                    if service { {console_text(locale, "路径：访问设备 → 提供设备。", "Path: accessing device → provider device.")} }
                    else { {console_text(locale, "路径：访问设备 → 网关设备 → 局域网目标。", "Path: accessing device → gateway → LAN target.")} }
                }
            } else {
                label { r#for: "share-route", {console_text(locale, "路由范围", "Route scope")}
                    input { id: "share-route", value: if ipv6() { "0.0.0.0/0, ::/0" } else { "0.0.0.0/0" }, disabled: true }
                }
                SharingInfoNote {
                    title: console_text(locale, "默认出口只用于出站", "The default exit is outbound only"),
                    body: console_text(locale, "Peerward 会保留设备身份和访问规则；这里不创建公网入站规则。", "Peerward preserves device identity and access rules; this does not create public inbound rules."),
                }
            }
            if more_settings {
                div { class: "sharing-extra-fields",
                    if kind == "lan" {
                        label { r#for: "share-site", {console_text(locale, "站点标识（同一局域网使用相同值）", "Site identity (reuse for the same LAN)")}
                            input { id: "share-site", value: site, oninput: move |e| site.set(e.value()) }
                        }
                    }
                    if kind == "internet" {
                        label { class: "checkbox-row",
                            input { r#type: "checkbox", checked: ipv6, onchange: move |e| ipv6.set(e.checked()) }
                            {console_text(locale, "同时提供 IPv6 出口", "Also provide IPv6 egress")}
                        }
                        div { class: "sharing-protocol-field",
                            label { r#for: "exit-share-protocol", {console_text(locale, "授权协议", "Allowed protocol")} }
                            select { id: "exit-share-protocol", value: protocol, "data-console-click-picker": "true", onchange: move |e| protocol.set(e.value()),
                                option { value: "all", selected: protocol() == "all", {console_text(locale, "全部协议", "All protocols")} }
                                option { value: "tcp", selected: protocol() == "tcp", "TCP" }
                                option { value: "udp", selected: protocol() == "udp", "UDP" }
                            }
                        }
                        if protocol() != "all" {
                            label { r#for: "exit-share-port", {console_text(locale, "授权端口", "Allowed port")}
                                input { id: "exit-share-port", r#type: "number", min: 1, max: 65535, required: true, value: port, oninput: move |e| { port.set(e.value()); port_edited.set(true); } }
                            }
                        }
                    }
                    label { r#for: "share-reason", {console_text(locale, "操作原因（可选）", "Reason (optional)")}
                        input { id: "share-reason", value: reason, maxlength: 512, oninput: move |e| reason.set(e.value()) }
                    }
                }
            }
        }
    }
}

fn sharing_default_port(protocol: &str, service: bool) -> &'static str {
    match protocol { "http" => "80", "https" => "443", _ if service => "445", _ => "631" }
}
