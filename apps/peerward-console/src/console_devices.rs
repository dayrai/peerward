#[component]
fn ConsoleDevicesPanel(
    mesh: String,
    mesh_name: String,
    on_advanced: EventHandler<()>,
    on_groups: EventHandler<()>,
    #[props(default)] on_add: Option<EventHandler<()>>,
    locale: Locale,
    csrf: Option<String>,
    can_write: bool,
    can_renew: bool,
    initial: Vec<ResourceSummary>,
    requested_resource: String,
    relay_filter: Option<String>,
) -> Element {
    #[cfg(target_arch = "wasm32")]
    let navigator = use_navigator();
    let mut search = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut platform = use_signal(String::new);
    let mut cursor = use_signal(String::new);
    let mut selected = use_signal(String::new);
    let mut opened_from_list = use_signal(|| false);
    use_effect(use_reactive((&mesh,), move |_| {
        cursor.set(String::new());
    }));
    use_effect(use_reactive((&requested_resource,), move |(resource,)| {
        if resource.is_empty() {
            opened_from_list.set(false);
        }
        selected.set(resource);
    }));
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params
        .append_pair("limit", "50")
        .append_pair("q", &search());
    for (key, value) in [
        ("status", status()),
        ("platform", platform()),
        ("cursor", cursor()),
        ("relay_id", relay_filter.clone().unwrap_or_default()),
    ] {
        if !value.is_empty() {
            params.append_pair(key, &value);
        }
    }
    let export_query = params.finish();
    let mut data = use_console_query::<peerward_api::ConsoleDevicePage>(if mesh.is_empty() {
        String::new()
    } else {
        format!("/api/v1/meshes/{mesh}/console/devices?{export_query}")
    });
    let value = data.read().as_ref().and_then(|r| r.as_ref().ok()).cloned();
    let resources = value.as_ref().map_or_else(
        || {
            if search().is_empty()
                && status().is_empty()
                && platform().is_empty()
                && cursor().is_empty()
            {
                initial.into_iter().take(50).collect()
            } else {
                vec![]
            }
        },
        |p| p.items.iter().cloned().map(ResourceSummary::from).collect(),
    );
    let count = value.as_ref().map(|p| p.total);
    let has_filters = !search().is_empty()
        || !status().is_empty()
        || !platform().is_empty()
        || !cursor().is_empty();
    let loading_results = data.state()() == UseResourceState::Pending;
    let load_error = data
        .read()
        .as_ref()
        .and_then(|result| result.as_ref().err())
        .cloned()
        .unwrap_or_default();
    #[cfg(target_arch = "wasm32")]
    let open_mesh = mesh.clone();
    #[cfg(target_arch = "wasm32")]
    let open_relay = relay_filter.clone();
    let open_detail = use_callback(move |id: String| {
        opened_from_list.set(true);
        selected.set(id.clone());
        #[cfg(target_arch = "wasm32")]
        navigator.push(
            ConsoleClientRoute::Peers {
                mesh: Some(open_mesh.clone()),
                relay_id: open_relay.clone(),
                resource: Some(id),
            }
            .href(),
        );
    });
    #[cfg(target_arch = "wasm32")]
    let close_mesh = mesh.clone();
    #[cfg(target_arch = "wasm32")]
    let close_relay = relay_filter.clone();
    let close_detail = use_callback(move |()| {
        selected.set(String::new());
        #[cfg(target_arch = "wasm32")]
        {
            let returned = opened_from_list()
                && web_sys::window()
                    .and_then(|window| window.history().ok())
                    .is_some_and(|history| history.back().is_ok());
            opened_from_list.set(false);
            if !returned {
                navigator.replace(
                    ConsoleClientRoute::Peers {
                        mesh: Some(close_mesh.clone()),
                        relay_id: close_relay.clone(),
                        resource: None,
                    }
                    .href(),
                );
            }
        }
    });
    rsx! {
        ConsoleDeviceListHead {
            mesh: mesh.clone(), mesh_name, locale, can_write, export_query,
            on_refresh: move |()| data.restart(), on_advanced, on_groups, on_add, refreshing: loading_results,
        }
        ConsoleDeviceJoinGuide { locale }
        section { class: "device-toolbar",
            div { class: "device-search-box",
                span { aria_hidden: "true", "⌕" }
                label { class: "sr-only", r#for: "device-search", {console_text(locale, "搜索设备", "Search devices")} }
                input {
                    id: "device-search", value: search,
                    placeholder: console_text(locale, "按名称、IP 或标签搜索设备", "Search by name, IP or label"),
                    oninput: move |e| { search.set(e.value()); cursor.set(String::new()); },
                }
            }
            label { class: "sr-only", r#for: "device-state-filter", {console_message(locale, "state")} }
            select {
                id: "device-state-filter", value: status,
                onchange: move |e| { status.set(e.value()); cursor.set(String::new()); },
                option { value: "", {console_text(locale, "状态：全部", "Status: all")} }
                option { value: "online", {console_message(locale, "device-online")} }
                option { value: "offline", {console_message(locale, "device-offline")} }
                option { value: "disabled", {console_message(locale, "disabled")} }
            }
            label { class: "sr-only", r#for: "device-platform-filter", {console_text(locale, "平台", "Platform")} }
            select {
                id: "device-platform-filter", value: platform,
                onchange: move |e| { platform.set(e.value()); cursor.set(String::new()); },
                option { value: "", {console_text(locale, "平台：全部", "Platform: all")} }
                option { value: "linux", "Linux" }
                option { value: "android", "Android" }
            }
        }
        if !load_error.is_empty() {
            section { class: "card feedback-state feedback-error", role: "alert",
                span { class: "feedback-icon", aria_hidden: "true", "!" }
                div { class: "feedback-copy",
                    strong { {console_text(locale, "暂时无法读取设备列表", "Device list is temporarily unavailable")} }
                    p { "{load_error}" }
                }
                button { class: "secondary-button", onclick: move |_| data.restart(),
                    {console_text(locale, "重试", "Retry")}
                }
            }
        } else if loading_results && (has_filters || resources.is_empty()) {
            section { class: "card feedback-state feedback-loading", role: "status", aria_busy: "true",
                span { class: "feedback-icon", aria_hidden: "true", "…" }
                div { class: "feedback-copy",
                    strong { {console_text(locale, "正在读取设备", "Loading devices")} }
                    p { {console_text(locale, "搜索或筛选后会在这里更新结果。", "Search and filter results will appear here.")} }
                }
            }
        } else {
            ConsoleDeviceList {
                mesh: mesh.clone(), resources, locale, count,
                summaries: value.as_ref().map(|page| page.summaries.clone()).unwrap_or_default(),
                filtered: has_filters,
                on_select: move |id: String| open_detail.call(id),
                empty_message: Some(
                    if has_filters {
                        console_text(locale, "没有匹配的设备。调整搜索或筛选条件。", "No devices match these filters. Adjust the search or filters.")
                    } else if can_write {
                        console_text(locale, "这个网络还没有设备。使用“添加设备”开始。", "This network has no devices yet. Use Add device to begin.")
                    } else {
                        console_text(locale, "这个网络还没有设备。当前账号为只读，设备加入后会在这里显示。", "This network has no devices yet. This account is read-only; enrolled devices will appear here.")
                    }
                    .to_owned(),
                ),
            }
            if !cursor().is_empty() || value.as_ref().and_then(|p| p.next_cursor.as_ref()).is_some() {
            div { class: "actions",
                if !cursor().is_empty() {
                    button {
                        class: "secondary-button",
                        onclick: move |_| cursor.set(String::new()),
                        {console_text(locale, "返回第一页", "First page")}
                    }
                }
                if let Some(next) = value.as_ref().and_then(|p| p.next_cursor.clone()) {
                    button {
                        class: "secondary-button",
                        onclick: move |_| cursor.set(next.clone()),
                        {console_message(locale, "next-page")}
                    }
                }
            }
        }
        }
        if !selected().is_empty() {
            ConsoleDeviceDetail {
                    key: "{mesh}:{selected}",
                    mesh: mesh.clone(),
                    peer: selected(),
                    locale,
                    csrf,
                    can_write,
                    can_renew,
                    on_change: move |()| data.restart(),
                    on_close: move |()| close_detail.call(()),
                    summary: value.as_ref().and_then(|page| page.summaries.get(&selected()).cloned()),
            }
        }
    }
}
#[component]
#[allow(unused_variables, unused_mut)]
fn DeviceEditForm(
    mesh: String,
    resource: PeerResource,
    csrf: Option<String>,
    locale: Locale,
    can_write: bool,
    on_change: EventHandler<()>,
    on_done: EventHandler<()>,
) -> Element {
    let mut display = use_signal(|| resource.display_name.clone());
    let mut location = use_signal(|| resource.location.clone());
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut saved = use_signal(|| false);
    let dirty = !saved() && (display() != resource.display_name || location() != resource.location);
    rsx! {
        form {
            class: "card device-basic-info",
            "data-console-dirty": dirty.to_string(),
            aria_busy: busy().to_string(), "data-console-submitting": busy().to_string(),
            onsubmit: move |event| {
                event.prevent_default();
                #[cfg(target_arch = "wasm32")]
                {
                    if busy() || !can_write || !dirty {
                        return;
                    }
                    busy.set(true);
                    error.set(String::new());
                    let mesh = mesh.clone();
                    let csrf = csrf.clone();
                    let id = resource.id;
                    let version = resource.version;
                    spawn(async move {
                        let result: Result<PeerResource, ConsoleApiError> = browser_api_client()
                            .with_csrf(csrf.unwrap_or_default())
                            .conditional_request(
                                Method::PATCH,
                                &format!("/api/v1/meshes/{mesh}/peers/{id}"),
                                Some(json!({ "display_name": display(), "location": location() })),
                                version,
                            )
                            .await;
                        match result {
                            Ok(_) => {
                                saved.set(true);
                                on_change.call(());
                            }
                            Err(e) => error.set(console_api_error(locale, e)),
                        }
                        busy.set(false);
                    });
                }
            },
            h3 { {console_text(locale, "基本信息", "Basic information")} }
            p { class: "muted", {console_text(locale, "这里只修改你在控制台里看到的名称和位置说明，不会改变设备身份、设备网络地址或现有访问权限。", "These fields only change how the device is described in the console. They do not change identity, device network addresses, or existing access permissions.")} }
            label { r#for: "drawer-device-name", {console_text(locale, "显示名称", "Display name")} }
            input {
                id: "drawer-device-name",
                value: display,
                disabled: !can_write || busy(),
                oninput: move |e| {
                    saved.set(false);
                    error.set(String::new());
                    display.set(e.value());
                },
            }
            label { r#for: "drawer-device-location",
                {console_text(locale, "位置说明", "Location description")}
            }
            input {
                id: "drawer-device-location",
                value: location,
                disabled: !can_write || busy(),
                oninput: move |e| {
                    saved.set(false);
                    error.set(String::new());
                    location.set(e.value());
                },
            }
            p { class: "muted",
                {console_text(locale, "显示名称不会改变设备的网络名称或访问标签。", "The display name does not change the device network name or access labels.")}
            }
            button {
                r#type: "submit",
                disabled: !can_write || busy() || !dirty,
                if busy() {
                    {console_text(locale, "正在保存…", "Saving…")}
                } else {
                    {console_text(locale, "保存更改", "Save changes")}
                }
            }
            if !error().is_empty() {
                p { role: "alert", "{error}" }
            }
            if saved() {
                div { class: "save-followup",
                    p { role: "status", aria_live: "polite", {console_text(locale, "已保存", "Saved")} }
                    button { r#type: "button", class: "secondary-button", onclick: move |_| on_done.call(()),
                        {console_text(locale, "返回状态", "Back to status")}
                    }
                }
            }
        }
    }
}
#[component]
fn ConfigurationReceipts(mesh: String, peer: String, locale: Locale) -> Element {
    let mut data = use_console_query::<Value>(format!(
        "/api/v1/meshes/{mesh}/peers/{peer}/configuration-receipts"
    ));
    rsx! {
        details { class: "advanced-tools",
            summary { {console_text(locale, "配置应用回执", "Configuration application receipts")} }
            p { class: "muted",
                {
                    console_text(
                        locale,
                        "没有回执代表未知，不代表配置已应用。",
                        "Missing receipts mean unknown, not applied.",
                    )
                }
            }
            if let Some(Ok(value)) = data.read().as_ref() {
                pre { { serde_json::to_string_pretty(value)
                        .unwrap_or_default() } }
            } else if let Some(Err(error)) = data.read().as_ref() {
                if !error.is_empty() {
                    p { role: "alert", "{error}" }
                    button { class: "secondary-button", onclick: move |_| data.restart(),
                        {console_text(locale, "重试", "Retry")}
                    }
                }
            }
        }
    }
}

#[component]
fn ConsoleDeviceShares(mesh: String, peer: String, locale: Locale) -> Element {
    let mut cursor = use_signal(String::new);
    let mut data = use_console_query::<Page<peerward_api::ConsoleSharingResource>>(format!(
        "/api/v1/meshes/{mesh}/console/sharing?provider={peer}&limit=20&cursor={}",
        cursor()
    ));
    rsx! {section{class:"device-provided-shares",h3{{console_text(locale,"这台设备对外共享","Sharing provided by this device")}}
        p { class: "muted", {console_text(locale, "别人能否使用这些共享，仍由访问规则决定。", "Access to these shares is still controlled by access rules.")} }
        if let Some(Ok(page))=data.read().as_ref(){
            if page.items.is_empty(){p{class:"empty",{console_text(locale,"没有匹配的共享资源","No matching shared resources")}}}
            for resource in &page.items{article{class:"renewal-item",a{href:format!("/services?mesh={mesh}&resource={}",resource.id),"{resource.name}"}p{class:"muted","{resource.target} · ",{evidence_label(locale,&resource.path)}}}}
            if let Some(next)=&page.next_cursor{button{onclick:{let next=next.clone();move |_|cursor.set(next.clone())},{console_message(locale,"next-page")}}}
            if !cursor().is_empty(){button{onclick:move |_|cursor.set(String::new()),{console_text(locale,"第一页","First page")}}}
        }else if let Some(Err(error))=data.read().as_ref(){if !error.is_empty(){p{role:"alert","{error}"}button{class:"secondary-button",onclick:move |_|data.restart(),{console_text(locale,"重试","Retry")}}}}
        else{p{role:"status",{console_message(locale,"loading")}}}
        if data.read().as_ref().is_some_and(Result::is_ok){button{class:"secondary-button",onclick:move |_|data.restart(),{console_text(locale,"刷新","Refresh")}}}
    }}
}
#[component]
fn ConsoleDeviceActivity(mesh: String, peer: String, locale: Locale) -> Element {
    let mut cursor = use_signal(String::new);
    let mut data = use_console_query::<Page<AuditResource>>(format!(
        "/api/v1/meshes/{mesh}/console/devices/{peer}/activity?limit=20{}",
        if cursor().is_empty() {
            String::new()
        } else {
            format!("&cursor={}", cursor())
        }
    ));
    rsx! {section{class:"card",h3{{console_text(locale,"设备操作记录","Device activity")}}
        if let Some(Ok(page))=data.read().as_ref(){
            if page.items.is_empty(){p{class:"empty",{console_text(locale,"暂无匹配的操作记录","No matching activity")}}}
            for item in &page.items{article{class:"renewal-item",strong{{activity_action(locale,&item.action)}}p{"{item.actor} · " {activity_result(locale,&item.result)}}LocalDateTime{value:item.timestamp.clone(),locale}}}
            if let Some(next)=&page.next_cursor{button{onclick:{let next=next.clone();move |_|cursor.set(next.clone())},{console_message(locale,"next-page")}}}
            if !cursor().is_empty(){button{onclick:move |_|cursor.set(String::new()),{console_text(locale,"第一页","First page")}}}
        }else if let Some(Err(error))=data.read().as_ref(){if !error.is_empty(){p{role:"alert","{error}"}button{class:"secondary-button",onclick:move |_|data.restart(),{console_text(locale,"重试","Retry")}}}}
        else{p{role:"status",{console_message(locale,"loading")}}}
        if data.read().as_ref().is_some_and(Result::is_ok){button{class:"secondary-button",onclick:move |_|data.restart(),{console_text(locale,"刷新","Refresh")}}}
    }}
}
