#[component]
#[allow(unused_mut, unused_variables)]
fn ConsoleDeviceDetail(
    mesh: String,
    peer: String,
    locale: Locale,
    csrf: Option<String>,
    can_write: bool,
    can_renew: bool,
    on_change: EventHandler<()>,
    on_close: EventHandler<()>,
    summary: Option<peerward_api::ConsoleDeviceSummary>,
) -> Element {
    let mut tab = use_signal(|| "overview".to_owned());
    let mut data = use_console_query::<PeerResource>(format!("/api/v1/meshes/{mesh}/peers/{peer}"));
    let selected_tab = if tab() == "edit" {
        "overview".to_owned()
    } else {
        tab()
    };
    let current = data.read().as_ref().and_then(|result| result.as_ref().ok()).cloned();
    let heading = current.as_ref().map_or_else(
        || console_text(locale, "正在读取设备…", "Loading device…").into(),
        |peer| peer_display_name(&ResourceSummary::from(peer.clone())),
    );
    let mut checking = use_signal(|| false);
    let mut check_message = use_signal(String::new);
    let mut check_error = use_signal(|| false);
    let check_mesh = mesh.clone();
    let check_peer = peer.clone();
    let check = use_callback(move |()| {
        #[cfg(target_arch = "wasm32")]
        {
            if checking() { return; }
            checking.set(true);
            check_message.set(String::new());
            check_error.set(false);
            let path = format!("/api/v1/meshes/{check_mesh}/peers/{check_peer}");
            spawn(async move {
                let result: Result<PeerResource, ConsoleApiError> = browser_api_client().request(Method::GET, &path, None).await;
                match result {
                    Ok(peer) => {
                        check_message.set(console_text(locale,
                            if peer.online { "设备在线；已核对服务器连接记录。共享端口和端到端延迟未测试。" }
                            else { "设备当前没有有效连接，请检查设备上的 Peerward 客户端。" },
                            if peer.online { "Device online; server connection records checked. Shared ports and end-to-end latency were not tested." }
                            else { "No current device connection. Check the Peerward client on the device." }).into());
                        data.restart();
                        on_change.call(());
                    }
                    Err(error) => {
                        check_error.set(true);
                        check_message.set(console_api_error(locale, error));
                    }
                }
                checking.set(false);
            });
        }
    });
    rsx! {
        ConsoleOverlay {
            title: console_text(locale, "设备详情", "Device details"), heading, device: true, on_close,
            if let Some(resource) = &current {
                ConsoleDeviceHero { resource: resource.clone().into(), summary: summary.clone(), locale,
                    checking: checking(), on_check: move |()| check.call(()) }
            }
            if !check_message().is_empty() {
                p { class: "device-connection-result", role: if check_error() { "alert" } else { "status" }, "{check_message}" }
            }
        div {
            class: "segmented detail-tabs",
            role: "tablist",
            aria_label: console_text(locale, "设备详情", "Device details"),
            for (key, zh, en) in [
                ("overview", "状态", "Status"),
                ("network", "共享与访问", "Sharing & access"),
                ("maintenance", "维护", "Maintenance"),
            ] {
                button {
                    role: "tab",
                    id: format!("device-detail-tab-{key}"),
                    aria_selected: (selected_tab == key).to_string(),
                    aria_controls: format!("device-detail-panel-{key}"),
                    tabindex: if selected_tab == key { "0" } else { "-1" },
                    class: if selected_tab == key { "active" } else { "" },
                    onclick: move |_| tab.set(key.into()),
                    {console_text(locale, zh, en)}
                }
            }
        }
        if let Some(Ok(resource)) = data.read().as_ref() {
            if selected_tab == "overview" {
                div {
                    id: "device-detail-panel-overview",
                    role: "tabpanel",
                    aria_labelledby: "device-detail-tab-overview",
                    if tab() == "edit" {
                        DeviceEditForm {
                            mesh: mesh.clone(),
                            resource: resource.clone(),
                            csrf: csrf.clone(),
                            locale,
                            can_write,
                            on_change: move |()| {
                                data.restart();
                                on_change.call(());
                            },
                            on_done: move |()| tab.set("overview".into()),
                        }
                    } else {
                        ConsoleDeviceFacts { resource: resource.clone().into(), locale }
                        if can_write {
                            div { class: "detail-inline-actions",
                                button { class: "secondary-button", onclick: move |_| tab.set("edit".into()),
                                    {console_text(locale, "修改基本信息", "Edit basic information")}
                                }
                            }
                        }
                        ConsoleDeviceTechnical { resource: resource.clone().into(), locale }
                    }
                }
            } else if selected_tab == "network" {
                div {
                    id: "device-detail-panel-network",
                    role: "tabpanel",
                    aria_labelledby: "device-detail-tab-network",
                    ConsoleDeviceAccessSummary { mesh: mesh.clone(), peer: resource.id, locale, can_write }
                    ConsoleDeviceShares { mesh: mesh.clone(), peer: peer.clone(), locale }
                    p { class: "device-access-note",
                        strong { {console_text(locale, "默认拒绝仍然生效。", "Default deny still applies. ")} }
                        {console_text(locale, "设备加入网络不代表自动获得全部共享的访问权限。", "Joining the network does not grant access to every share.")}
                    }
                    ConfigurationReceipts { mesh: mesh.clone(), peer: peer.clone(), locale }
                }
            } else {
                div {
                    id: "device-detail-panel-maintenance",
                    role: "tabpanel",
                    aria_labelledby: "device-detail-tab-maintenance",
                    section { class: "card maintenance-intro",
                        h3 { {console_text(locale, "设备维护", "Device maintenance")} }
                        p { class: "muted", {console_text(locale, "正常设备不需要定期操作。只有设备身份异常、更换设备或永久停用时才使用下面的工具。", "Healthy devices need no routine maintenance. Use these tools only for device-identity problems, device replacement, or permanent retirement.")} }
                        if let Some(credential) = &resource.credentials.active {
                            dl { class: "resource-details credential-summary",
                                div { class: "resource-detail",
                                    dt { {console_text(locale, "设备身份状态", "Device identity status")} }
                                    dd { {console_text(locale, "有效", "Valid")} }
                                }
                                if let Some(expiry) = &credential.not_after {
                                    div { class: "resource-detail",
                                        dt { {console_text(locale, "有效期至", "Expires")} }
                                        dd { LocalDateTime { value: expiry.clone(), locale } }
                                    }
                                }
                            }
                            details { class: "advanced-tools",
                                summary { {console_text(locale, "凭据技术信息", "Credential technical details")} }
                                p { code { "{credential.serial}" } }
                            }
                        } else {
                            p { class: "info-note", {console_text(locale, "当前没有有效的设备身份。设备无法正常重新连接。", "There is no active device identity. The device cannot reconnect normally.")} }
                        }
                    }
                    ConsoleRenewalPanel {
                        mesh: mesh.clone(),
                        peer: resource.clone(),
                        locale,
                        csrf: csrf.clone(),
                        can_renew,
                        on_change: move |()| {
                            data.restart();
                            on_change.call(());
                        },
                    }
                    details { class: "advanced-tools device-activity-details",
                        summary { {console_text(locale, "查看设备操作记录", "View device activity")} }
                        ConsoleDeviceActivity { mesh: mesh.clone(), peer: peer.clone(), locale }
                    }
                    if can_write
                        && resource.administrative_state == peerward_api::AdministrativeState::Enabled
                    {
                        ConsoleRetireDevice {
                            mesh: mesh.clone(),
                            peer: resource.clone(),
                            locale,
                            csrf: csrf.clone(),
                            on_change: move |()| {
                                data.restart();
                                on_change.call(());
                            },
                        }
                    }
                }
            }
        } else if let Some(Err(error)) = data.read().as_ref() {
            if !error.is_empty() {
                section { class: "card feedback-state feedback-error", role: "alert",
                    span { class: "feedback-icon", aria_hidden: "true", "!" }
                    div { class: "feedback-copy",
                        strong { {console_text(locale, "暂时无法读取设备详情", "Device details are temporarily unavailable")} }
                        p { "{error}" }
                    }
                    button { class: "secondary-button", onclick: move |_| data.restart(),
                        {console_text(locale, "重试", "Retry")}
                    }
                }
            }
        } else {
            section { class: "card feedback-state feedback-loading", role: "status", aria_busy: "true",
                span { class: "feedback-icon", aria_hidden: "true", "…" }
                div { class: "feedback-copy",
                    strong { {console_text(locale, "正在读取设备详情", "Loading device details")} }
                }
            }
        }
        }
    }
}
