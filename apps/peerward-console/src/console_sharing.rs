fn evidence_label(locale: Locale, value: &peerward_api::ConsoleEvidence) -> &'static str {
    match value.state.as_str() {
        "ready" => console_text(locale, "已确认", "Confirmed"),
        "blocked" => console_text(locale, "需处理", "Needs attention"),
        "paused" => console_text(locale, "已暂停", "Paused"),
        "pending" => console_text(locale, "等待应用", "Pending"),
        _ => console_text(locale, "未知 / 未检查", "Unknown / not checked"),
    }
}
fn evidence_reason(locale: Locale, reason: &str) -> &'static str {
    match reason {
        "resource_paused" => console_text(
            locale,
            "管理员已暂停共享；原共享设置和授权保留",
            "Sharing is paused; definitions and grants are retained",
        ),
        "saved" => console_text(locale, "定义已保存", "Definition saved"),
        "select_source" => console_text(
            locale,
            "请在访问页面选择来源设备检查权限",
            "Select a source in Access to evaluate permission",
        ),
        "provider_online" => console_text(
            locale,
            "提供设备当前在线",
            "Provider is currently online",
        ),
        "provider_offline" => console_text(locale, "提供设备当前离线", "Provider is offline"),
        "gateway_advertised" => console_text(
            locale,
            "负责转发的设备已提供当前连接路径",
            "The forwarding device is providing a current connection path",
        ),
        "gateway_tcp_connect" => console_text(
            locale,
            "已连接目标地址和端口；未检查应用登录",
            "The target address and port are reachable; application login was not tested",
        ),
        "gateway_probe_failed" => console_text(
            locale,
            "负责转发的设备无法连接目标地址或端口",
            "The forwarding device could not connect to the target address or port",
        ),
        "service_disabled" => console_text(locale, "服务已停用", "Service is disabled"),
        "no_current_path" => console_text(
            locale,
            "当前没有可用的网关路径",
            "There is no usable gateway path right now",
        ),
        _ => console_text(
            locale,
            "缺少有效观测，不能确认目标可达",
            "No current observation confirms target reachability",
        ),
    }
}
#[component]
fn ConsoleSharingPanel(
    mesh: String,
    locale: Locale,
    csrf: Option<String>,
    can_write: bool,
    requested_resource: String,
) -> Element {
    #[cfg(target_arch = "wasm32")]
    let navigator = use_navigator();
    let mut query = use_signal(String::new);
    let mut kind = use_signal(String::new);
    let mut cursor = use_signal(String::new);
    let mut selected = use_signal(|| None::<peerward_api::ConsoleSharingResource>);
    let mut opened_from_list = use_signal(|| false);
    let mut create = use_signal(|| false);
    let mut deep_link = use_signal(String::new);
    use_effect(use_reactive((&requested_resource,), move |(resource,)| {
        if resource.is_empty() {
            opened_from_list.set(false);
            selected.set(None);
            deep_link.set(String::new());
        } else {
            deep_link.set(resource);
        }
    }));
    let deep = use_console_query::<Page<peerward_api::ConsoleSharingResource>>(
        if deep_link().is_empty() {
            String::new()
        } else {
            format!(
                "/api/v1/meshes/{mesh}/console/sharing?resource={}",
                deep_link()
            )
        },
    );
    use_effect(move || {
        if !deep_link().is_empty()
            && let Some(Ok(page)) = deep.read().as_ref()
            && let Some(item) = page.items.first()
        {
            selected.set(Some(item.clone()));
            deep_link.set(String::new());
        }
    });
    use_effect(use_reactive((&mesh,), move |(_,)| {
        selected.set(None);
        cursor.set(String::new());
        create.set(false);
    }));
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params.append_pair("limit", "50").append_pair("q", &query());
    if !kind().is_empty() {
        params.append_pair("kind", &kind());
    }
    if !cursor().is_empty() {
        params.append_pair("cursor", &cursor());
    }
    let mut data =
        use_console_query::<Page<peerward_api::ConsoleSharingResource>>(if mesh.is_empty() {
            String::new()
        } else {
            format!("/api/v1/meshes/{mesh}/console/sharing?{}", params.finish())
        });
    let has_filters = !query().is_empty() || !kind().is_empty();
    #[cfg(target_arch = "wasm32")]
    let open_mesh = mesh.clone();
    let open_detail = use_callback(move |resource: peerward_api::ConsoleSharingResource| {
        #[cfg(target_arch = "wasm32")]
        let id = resource.id;
        opened_from_list.set(true);
        selected.set(Some(resource));
        #[cfg(target_arch = "wasm32")]
        navigator.push(
            ConsoleClientRoute::Services {
                mesh: Some(open_mesh.clone()),
                resource: Some(id.to_string()),
            }
            .href(),
        );
    });
    #[cfg(target_arch = "wasm32")]
    let close_mesh = mesh.clone();
    let close_detail = use_callback(move |()| {
        selected.set(None);
        #[cfg(target_arch = "wasm32")]
        {
            let returned = opened_from_list()
                && web_sys::window()
                    .and_then(|window| window.history().ok())
                    .is_some_and(|history| history.back().is_ok());
            opened_from_list.set(false);
            if !returned {
                navigator.replace(
                    ConsoleClientRoute::Services {
                        mesh: Some(close_mesh.clone()),
                        resource: None,
                    }
                    .href(),
                );
            }
        }
    });
    rsx! {
        section { class: "card",
            div { class: "panel-head",
                h2 { {console_text(locale, "共享", "Sharing")} }
                div { class: "actions",
                    button {
                        class: "secondary-button",
                        onclick: move | _ | data
                                .restart(),
                        {console_text(locale, "刷新状态", "Refresh status")}
                    }
                    if can_write {
                        button {
                            disabled: mesh.is_empty(),
                            onclick: move | _ | create
                                    .set(true),
                            {console_text(locale, "＋ 添加共享", "＋ Add share")}
                        }
                    }
                }
            }
            div { class: "filter-bar",
                label { class: "sr-only", r#for: "sharing-search",
                    {console_text(locale, "搜索共享", "Search shares")}
                }
                input {
                    id: "sharing-search",
                    value: query,
                    placeholder: console_text(locale, "搜索共享名称", "Search share names"),
                    oninput: move |e| {
                        query.set(e.value());
                        cursor.set(String::new());
                    },
                }
                div { class: "segmented",
                    for (key, zh, en) in [
                        ("", "全部", "All"),
                        ("service", "设备服务", "Device services"),
                        ("lan", "局域网资源", "LAN resources"),
                        ("internet", "互联网出口", "Internet exits"),
                    ]
                    {
                        button {
                            class: if kind() == key { "active" } else { "" },
                            onclick: move |_| {
                                kind.set(key.into());
                                cursor.set(String::new());
                            },
                            {console_text(locale, zh, en)}
                        }
                    }
                }
            }
            if mesh.is_empty() {
                p { class: "empty",
                    {
                        console_text(
                            locale,
                            "选择网络后管理共享。",
                            "Select a network to manage sharing.",
                        )
                    }
                }
            } else if let Some(Ok(page)) = data.read().as_ref() {
                if page.items.is_empty() {
                    div { class: "feedback-state feedback-empty embedded-feedback", role: "status",
                        span { class: "feedback-icon", aria_hidden: "true", if has_filters { "⌕" } else { "⇄" } }
                        div { class: "feedback-copy",
                            strong {
                                if has_filters {
                                    {console_text(locale, "没有匹配的共享", "No shares match these filters")}
                                } else {
                                    {console_text(locale, "这个网络还没有共享", "This network has no shares yet")}
                                }
                            }
                            p {
                                if has_filters {
                                    {console_text(locale, "调整关键词或类型筛选后再试。", "Adjust the search or type filter and try again.")}
                                } else if can_write {
                                    {console_text(locale, "添加一个设备服务、局域网资源或互联网出口。", "Add a device service, LAN resource, or internet exit.")}
                                } else {
                                    {console_text(locale, "当前没有已配置的共享。只读账号会在共享创建后看到它们。", "No shares are configured yet. A read-only account will see them here after they are created.")}
                                }
                            }
                        }
                        if can_write && !has_filters {
                            button { onclick: move |_| create.set(true),
                                {console_text(locale, "添加第一个共享", "Add the first share")}
                            }
                        }
                    }
                }
                for resource in &page.items {
                    article { class: "sharing-row",
                        span {
                            class: format!("resource-kind {}", resource.kind),
                            aria_hidden: "true",
                            if resource.kind == "service" {
                                "▤"
                            } else if resource.kind == "lan" {
                                "⌂"
                            } else {
                                "↗"
                            }
                        }
                        div { class: "sharing-copy",
                            strong { "{resource.name}" }
                            span { class: "type-chip", {resource_kind_label(locale, &resource.kind)} }
                            p { "{resource.provider} · {resource.target}" }
                        }
                        div { class: "sharing-path",
                            small { {console_text(locale, "连接", "Connection")} }
                            strong { {evidence_label(locale, &resource.path)} }
                        }
                        button {
                            class: "secondary-button",
                            "data-console-focus-key": format!("sharing:{}", resource.id),
                            onclick: {
                                let resource = resource.clone();
                                move |_| open_detail.call(resource.clone())
                            },
                            {console_text(locale, "查看详情", "View details")}
                        }
                    }
                }
                div { class: "actions",
                    if !cursor().is_empty() {
                        button {
                            class: "secondary-button",
                            onclick: move | _ | cursor
                                    .set(String::new()),
                            {console_text(locale, "返回第一页", "First page")}
                        }
                    }
                    if let Some(next) = page.next_cursor.clone() {
                        button {
                            class: "secondary-button",
                            onclick: move |_| cursor.set(next.clone()),
                            {console_message(locale, "next-page")}
                        }
                    }
                }
            } else if let Some(Err(error)) = data.read().as_ref() {
                if !error.is_empty() {
                    div { class: "feedback-state feedback-error embedded-feedback", role: "alert",
                        span { class: "feedback-icon", aria_hidden: "true", "!" }
                        div { class: "feedback-copy",
                            strong { {console_text(locale, "暂时无法读取共享", "Shares are temporarily unavailable")} }
                            p { "{error}" }
                        }
                        button { class: "secondary-button", onclick: move |_| data.restart(),
                            {console_text(locale, "重试", "Retry")}
                        }
                    }
                }
            } else {
                div { class: "feedback-state feedback-loading embedded-feedback", role: "status", aria_busy: "true",
                    span { class: "feedback-icon", aria_hidden: "true", "…" }
                    div { class: "feedback-copy",
                        strong { {console_text(locale, "正在读取共享", "Loading shares")} }
                        p { {console_text(locale, "正在检查当前定义和连接状态。", "Checking current definitions and connection state.")} }
                    }
                }
            }
        }
        if let Some(resource) = selected() {
            ConsoleOverlay {
                title: console_text(locale, "共享详情", "Sharing details"),
                on_close: move |()| close_detail.call(()),
                ConsoleSharingDetail {
                    key: "{mesh}:{resource.id}",
                    mesh: mesh.clone(),
                    initial: resource,
                    locale,
                    csrf: csrf.clone(),
                    can_write,
                    on_change: move | () | data
                            .restart(),
                }
            }
        }
        if create() && can_write {
            ConsoleOverlay {
                wizard: true,
                wizard_label: console_text(locale, "引导操作", "Guided setup").to_owned(),
                title: console_text(locale, "添加共享", "Add share"),
                on_close: move |()| {
                    create.set(false);
                    data.restart();
                },
                ConsoleSharingWizard {
                    can_write,
                    on_cancel: move |()| { create.set(false); data.restart(); },
                    key: "{mesh}",
                    mesh: mesh.clone(),
                    locale,
                    csrf: csrf.clone(),
                    on_change: move |()| data.restart(),
                }
            }
        }
    }
}
fn resource_kind_label(locale: Locale, kind: &str) -> &'static str {
    match kind {
        "service" => console_text(locale, "设备服务", "Device service"),
        "lan" | "subnet" => console_text(locale, "局域网资源", "LAN resource"),
        _ => console_text(locale, "互联网出口", "Internet exit"),
    }
}
#[component]
fn ConsoleSharingDetail(
    mesh: String,
    initial: peerward_api::ConsoleSharingResource,
    locale: Locale,
    csrf: Option<String>,
    can_write: bool,
    on_change: EventHandler<()>,
) -> Element {
    let mut tab = use_signal(|| "status".to_owned());
    let mut data = use_console_query::<Page<peerward_api::ConsoleSharingResource>>(format!(
        "/api/v1/meshes/{mesh}/console/sharing?resource={}",
        initial.id
    ));
    let resource = data
        .read()
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .and_then(|p| p.items.first())
        .cloned()
        .unwrap_or(initial);
    let has_gateway_path = resource.network.is_some();
    rsx! {
        div { class: "resource-detail-head",
            div {
                div { class: "resource-title-row",
                    h2 { "{resource.name}" }
                    span { class: "type-chip", {resource_kind_label(locale, &resource.kind)} }
                }
                p { class: "muted",
                    {format!("{}：{} · {}", console_text(locale, "提供设备", "Provider"), resource.provider, resource.target)}
                }
            }
            div { class: "resource-detail-head-actions",
                button { class: "secondary-button", onclick: move |_| data.restart(),
                    {console_text(locale, "重新检查", "Recheck")}
                }
                a { class: "primary-link", href: format!("/policy?mesh={mesh}&resource={}", resource.id),
                    {console_text(locale, "检查访问", "Check access")}
                }
            }
        }
        if let Some(Err(e)) = data.read().as_ref() {
            if !e.is_empty() {
                div { class: "feedback-state feedback-error embedded-feedback", role: "alert",
                    span { class: "feedback-icon", aria_hidden: "true", "!" }
                    div { class: "feedback-copy",
                        strong { {console_text(locale, "暂时无法更新共享详情", "Unable to refresh sharing details right now")} }
                        p { {console_text(locale, "下面显示的是上次已加载的信息。重新检查成功前，不要把它当作当前状态。", "The information below is the last loaded state. Do not treat it as current until recheck succeeds.")} }
                        small { "{e}" }
                    }
                    button { class: "secondary-button", onclick: move |_| data.restart(),
                        {console_text(locale, "重试", "Retry")}
                    }
                }
            }
        }
        div {
            class: "segmented detail-tabs resource-detail-tabs",
            role: "tablist",
            aria_label: console_text(locale, "共享详情", "Sharing details"),
            button {
                role: "tab", id: "sharing-detail-tab-status", aria_controls: "sharing-detail-panel-status",
                aria_selected: (tab() == "status").to_string(), tabindex: if tab() == "status" { "0" } else { "-1" },
                class: if tab() == "status" { "active" } else { "" }, onclick: move |_| tab.set("status".into()),
                {console_text(locale, "状态", "Status")}
            }
            if can_write {
                button {
                    role: "tab", id: "sharing-detail-tab-settings", aria_controls: "sharing-detail-panel-settings",
                    aria_selected: (tab() == "settings").to_string(), tabindex: if tab() == "settings" { "0" } else { "-1" },
                    class: if tab() == "settings" { "active" } else { "" }, onclick: move |_| tab.set("settings".into()),
                    {console_text(locale, "共享信息", "Sharing details")}
                }
            }
            button {
                role: "tab", id: "sharing-detail-tab-access", aria_controls: "sharing-detail-panel-access",
                aria_selected: (tab() == "access").to_string(), tabindex: if tab() == "access" { "0" } else { "-1" },
                class: if tab() == "access" { "active" } else { "" }, onclick: move |_| tab.set("access".into()),
                {console_text(locale, "谁可以访问", "Who can access")}
            }
            if has_gateway_path {
                button {
                    role: "tab", id: "sharing-detail-tab-path", aria_controls: "sharing-detail-panel-path",
                    aria_selected: (tab() == "path").to_string(), tabindex: if tab() == "path" { "0" } else { "-1" },
                    class: if tab() == "path" { "active" } else { "" }, onclick: move |_| tab.set("path".into()),
                    {console_text(locale, "网关路径", "Gateway path")}
                }
            }
        }
        if tab() == "status" {
            div { id: "sharing-detail-panel-status", role: "tabpanel", aria_labelledby: "sharing-detail-tab-status",
                section { class: "resource-status-overview",
                    div { class: "resource-health-steps",
                        for (zh, en, evidence) in [
                            ("配置", "Configuration", resource.configuration.clone()),
                            ("授权", "Authorization", resource.authorization.clone()),
                            ("连接路径", "Connection path", resource.path.clone()),
                            ("可达性", "Reachability", resource.reachability.clone()),
                        ] {
                            article { class: format!("health-step {}", evidence.state),
                                small { {console_text(locale, zh, en)} }
                                strong { {evidence_label(locale, &evidence)} }
                                p { {evidence_reason(locale, &evidence.reason)} }
                                if let Some(observation) = evidence.diagnostic {
                                    p { {peerward_ui::diagnostic_next_step(locale, observation.retry_hint)} }
                                }
                                if let Some(at) = evidence.observed_at { LocalDateTime { value: at, locale } }
                            }
                        }
                    }
                    p { class: "info-note",
                        {console_text(locale, "“已配置”只代表定义已经保存。是否能用，还要同时看访问授权、当前网络路径和目标可达性。", "Configured only means the definition is saved. Usability also depends on access permission, the current network path, and target reachability.")}
                    }
                    details { class: "advanced-tools raw-resource-details",
                        summary { {console_text(locale, "技术详情", "Technical details")} }
                        dl { class: "resource-details",
                            div { class: "resource-detail", dt { {console_text(locale, "资源 ID", "Resource ID")} } dd { code { "{resource.id}" } CopyValue { value: resource.id.to_string(), locale } } }
                            div { class: "resource-detail", dt { {console_text(locale, "版本", "Version")} } dd { "{resource.version}" } }
                            div { class: "resource-detail", dt { {console_text(locale, "底层类型", "Underlying type")} } dd { "{resource.kind}" } }
                        }
                        details { class: "advanced-tools raw-resource-details",
                            summary { {console_text(locale, "查看原始资源数据", "View raw resource data")} }
                            pre { {serde_json::to_string_pretty(&json!({ "service": resource.service, "network": resource.network })).unwrap_or_default()} }
                        }
                    }
                }
            }
        } else if tab() == "settings" && can_write {
            div { id: "sharing-detail-panel-settings", role: "tabpanel", aria_labelledby: "sharing-detail-tab-settings",
                ConsoleSharingActions {
                    key: "{resource.id}", mesh: mesh.clone(), resource: resource.clone(), locale, csrf: csrf.clone(),
                    on_change: move |()| { data.restart(); on_change.call(()); },
                    on_show_status: move |()| tab.set("status".into()),
                }
            }
        } else if tab() == "access" {
            div { id: "sharing-detail-panel-access", role: "tabpanel", aria_labelledby: "sharing-detail-tab-access",
                ConsoleSharingAccess {
                    key: "{resource.id}", mesh: mesh.clone(), resource: resource.clone(), locale, csrf: csrf.clone(), can_write,
                    on_change: move |()| { data.restart(); on_change.call(()); },
                }
            }
        } else if tab() == "path" && has_gateway_path {
            div { id: "sharing-detail-panel-path", role: "tabpanel", aria_labelledby: "sharing-detail-tab-path",
                if let Some(network) = resource.network.clone() {
                    section { class: "detail-section-intro",
                        h3 { {console_text(locale, "网关路径", "Gateway path")} }
                        p { class: "muted", {console_text(locale, "只有局域网资源和互联网出口需要网关。日常情况下无需调整优先级或批准状态。", "Only LAN resources and internet exits need gateways. Priority and approval normally require no routine changes.")} }
                    }
                    ConsoleGatewayManager {
                        mesh: mesh.clone(), resource: network, locale, csrf: csrf.clone(), can_write,
                        on_change: move |()| { data.restart(); on_change.call(()); }
                    }
                }
            }
        }
    }
}
