#[component]
#[allow(unused_mut, unused_variables)]
fn ConsoleAccessDetail(
    mesh: String,
    resource: peerward_api::ConsoleSharingResource,
    initial_result: Option<peerward_api::ConsoleMatrixCell>,
    source: Option<peerward_api::ConsoleGrantSource>,
    locale: Locale,
    csrf: Option<String>,
    can_write: bool,
) -> Element {
    let mut address = use_signal(String::new);
    let mut gateway = use_signal(String::new);
    let mut protocol = use_signal(|| "6".to_owned());
    let mut service_protocol = use_signal(String::new);
    let mut port = use_signal(|| "443".to_owned());
    let mut submitted = use_signal(|| None::<peerward_api::ConsoleMatrixQuery>);
    let mut message = use_signal(String::new);
    let bindings = use_console_query::<Value>(if resource.kind == "service" {
        String::new()
    } else {
        format!(
            "/api/v1/meshes/{mesh}/network-resources/{}/health",
            resource.id
        )
    });
    let mut result = use_console_post::<peerward_api::ConsoleMatrix>(
        if submitted().is_some() {
            format!("/api/v1/meshes/{mesh}/console/matrix")
        } else {
            String::new()
        },
        json!(submitted()),
    );
    let form_resource = resource.clone();
    let form_source = source.clone();
    rsx! {
        h2 { "{resource.name}" }
        p { class: "muted", "{resource.target}" }
        if source.is_none() {
            p { class: "info-note",
                {
                    console_text(
                        locale,
                        "请先关闭此窗口，在访问页面选择来源设备或组。",
                        "Close this drawer and select a source device or group first.",
                    )
                }
            }
        }
        if let Some(cell) = initial_result.as_ref() {
            section { class: "card access-explanation",
                small { {console_text(locale, "当前结果", "Current result")} }
                h3 { {matrix_outcome(locale, &cell.outcome)} }
                if cell.sources > 1 {
                    p { class: "muted",
                        {format!(
                            "{} / {} {}",
                            cell.allowed_sources,
                            cell.sources,
                            console_text(locale, "来源允许", "sources allowed"),
                        )}
                    }
                }
                if cell.reasons.is_empty() {
                    p { {console_text(locale, "当前结果没有额外说明。", "No additional explanation is available for this result.")} }
                } else {
                    ul { class: "access-reasons",
                        for reason in &cell.reasons {
                            li { {matrix_reason(locale, reason)} }
                        }
                    }
                }
                if !cell.matched_rules.is_empty() {
                    details { class: "advanced-tools",
                        summary { {console_text(locale, "命中的规则标识", "Matched rule identities")} }
                        for id in &cell.matched_rules {
                            p { code { "{id}" } }
                        }
                    }
                }
            }
        }
        ConsoleManagedGrants {
            mesh: mesh.clone(),
            service: resource.id,
            network: resource.kind != "service",
            locale,
            csrf: csrf.clone(),
            can_write,
            on_change: move |()| result.restart(),
        }
        if can_write {
            if let Some(source) = source.clone() {
                ConsoleGrantForm {
                    mesh: mesh.clone(),
                    resource: resource.clone(),
                    source,
                    locale,
                    csrf: csrf.clone(),
                    on_change: move |()| result.restart(),
                }
            }
        }
        details { class: "advanced-tools access-simulation",
            summary { {console_text(locale, "高级：模拟具体条件", "Advanced: simulate specific conditions")} }
            p { class: "muted",
                {console_text(locale, "只有需要核对具体地址、协议、端口或网关时才使用。它解释访问规则判断，不代表真实连通性。", "Use this only when you need to evaluate a specific address, protocol, port, or gateway. It explains access-rule evaluation and does not prove connectivity.")}
            }
            form {
                class: "console-form",
                onsubmit: move |event| {
                    event.prevent_default();
                    message.set(String::new());
                    let Some(source) = form_source.clone() else { return };
                    let target = if form_resource.kind == "service" {
                        let address = if address().trim().is_empty() {
                            None
                        } else if let Ok(value) = address().trim().parse() {
                            Some(value)
                        } else {
                            message.set(console_text(locale, "请输入提供设备的有效网络地址，或留空检查全部地址族。", "Enter a valid address of the publishing device, or leave blank to evaluate all address families.").into());
                            return;
                        };
                        peerward_api::ConsoleMatrixTarget::Service {
                            id: form_resource.id,
                            address,
                            protocol: service_protocol().parse().ok(),
                        }
                    } else {
                        let (Ok(address), Ok(provider), Ok(protocol)) = (
                            address().parse(),
                            gateway().parse(),
                            protocol().parse::<u8>(),
                        ) else {
                            message.set(console_text(locale, "请填写有效地址并选择网关。", "Enter a valid address and select a gateway.").into());
                            return;
                        };
                        let port = if [6, 17].contains(&protocol) {
                            match port().parse::<u16>() {
                                Ok(p) if p > 0 => Some(p),
                                _ => {
                                    message.set(console_text(locale, "请填写有效端口。", "Enter a valid port.").into());
                                    return;
                                }
                            }
                        } else {
                            None
                        };
                        peerward_api::ConsoleMatrixTarget::Network {
                            id: form_resource.id,
                            address: Some(address),
                            provider: Some(provider),
                            protocol: Some(protocol),
                            port,
                        }
                    };
                    submitted.set(Some(peerward_api::ConsoleMatrixQuery {
                        source,
                        targets: vec![target],
                    }));
                    result.restart();
                },
                if resource.kind == "service" {
                    label { r#for: "simulate-service-address", {console_text(locale, "提供设备地址（留空检查全部）", "Publisher address (blank evaluates all)")} }
                    input { id: "simulate-service-address", value: address, oninput: move |e| address.set(e.value()) }
                    label { r#for: "simulate-service-protocol", {console_text(locale, "服务协议", "Service transport")} }
                    select { id: "simulate-service-protocol", value: service_protocol, onchange: move |e| service_protocol.set(e.value()),
                        option { value: "", {console_text(locale, "全部已配置协议", "All configured transports")} }
                        if let Some(service) = &resource.service {
                            for transport in &service.protocols {
                                option { value: if *transport == peerward_types::ServiceProtocol::Tcp { "6" } else { "17" }, {if *transport == peerward_types::ServiceProtocol::Tcp { "TCP" } else { "UDP" }} }
                            }
                        }
                    }
                    p { class: "muted", {console_text(locale, "端口使用此服务的已保存端口。未指定地址和协议时汇总全部情况。", "Uses this service's saved port. Blank selections evaluate every configured transport and address family.")} }
                } else {
                    label { r#for: "simulate-address", {console_text(locale, "实际目标地址", "Actual target address")} }
                    input { id: "simulate-address", value: address, required: true, oninput: move |e| address.set(e.value()) }
                    label { r#for: "simulate-gateway", {console_text(locale, "网关", "Gateway")} }
                    select {
                        id: "simulate-gateway",
                        value: gateway,
                        required: true,
                        onchange: move |e| gateway.set(e.value()),
                        option { value: "", {console_text(locale, "请选择", "Select")} }
                        if let Some(Ok(view)) = bindings.read().as_ref() {
                            if let Some(items) = view["bindings"].as_array() {
                                for b in items {
                                    option { value: b["peer_id"].as_str().unwrap_or_default(),
                                        {b["peer_name"].as_str().unwrap_or_default()}
                                    }
                                }
                            }
                        }
                    }
                    label { r#for: "simulate-protocol", {console_text(locale, "协议", "Protocol")} }
                    select {
                        id: "simulate-protocol",
                        value: protocol,
                        onchange: move |e| protocol.set(e.value()),
                        option { value: "6", "TCP" }
                        option { value: "17", "UDP" }
                        option { value: "1", "ICMPv4" }
                        option { value: "58", "ICMPv6" }
                    }
                    if ["6", "17"].contains(&protocol().as_str()) {
                        label { r#for: "simulate-port", {console_text(locale, "端口", "Port")} }
                        input { id: "simulate-port", r#type: "number", min: 1, max: 65535, value: port, oninput: move |e| port.set(e.value()) }
                    }
                }
                button { r#type: "submit", disabled: source.is_none(),
                    {console_text(locale, "模拟访问", "Simulate access")}
                }
            }
            if let Some(Ok(matrix)) = result.read().as_ref() {
                for cell in &matrix.cells {
                    section { class: "card",
                        h3 { {matrix_outcome(locale, &cell.outcome)} }
                        if cell.sources > 1 {
                            p { {format!("{} / {} {}", cell.allowed_sources, cell.sources, console_text(locale, "来源允许", "sources allowed"))} }
                        }
                        ul {
                            for reason in &cell.reasons {
                                li { {matrix_reason(locale, reason)} }
                            }
                        }
                        p { class: "muted", {format_timestamp(matrix.observed_at)} }
                    }
                }
            }
            if let Some(Err(e)) = result.read().as_ref() {
                if !e.is_empty() {
                    p { role: "alert", "{e}" }
                }
            }
            if !message().is_empty() {
                p { role: "alert", "{message}" }
            }
        }
    }
}
