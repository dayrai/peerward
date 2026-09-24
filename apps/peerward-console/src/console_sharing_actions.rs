#[component]
#[allow(unused_mut, unused_variables)]
fn ConsoleSharingActions(
    mesh: String,
    resource: peerward_api::ConsoleSharingResource,
    locale: Locale,
    csrf: Option<String>,
    on_change: EventHandler<()>,
    on_show_status: EventHandler<()>,
) -> Element {
    let latest = resource.clone();
    let current_version = resource.version;
    let mut baseline = use_signal(|| resource.clone());
    let resource = baseline();
    let mut editing = use_signal(|| resource.service.is_some());
    let mut confirming = use_signal(|| false);
    let mut name = use_signal(|| resource.name.clone());
    let mut alias = use_signal(|| {
        resource
            .service
            .as_ref()
            .and_then(|s| s.alias.clone())
            .unwrap_or_default()
    });
    let original_protocol = resource.service.as_ref().map_or("tcp", |s| {
        if s.protocols.len() > 1 {
            "both"
        } else if s.protocols.first() == Some(&peerward_types::ServiceProtocol::Udp) {
            "udp"
        } else {
            "tcp"
        }
    });
    let mut protocol = use_signal(|| original_protocol.to_owned());
    let mut port = use_signal(|| {
        resource
            .service
            .as_ref()
            .map(|s| s.listen_port.to_string())
            .unwrap_or_default()
    });
    let mut confirmation = use_signal(String::new);
    let mut edit_reason = use_signal(String::new);
    let mut state_reason = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut message = use_signal(String::new);
    let mut submitted = use_signal(|| false);
    use_effect(use_reactive((&latest,), move |(latest,)| {
        if submitted() && latest.version != baseline.read().version {
            name.set(latest.name.clone());
            alias.set(
                latest
                    .service
                    .as_ref()
                    .and_then(|s| s.alias.clone())
                    .unwrap_or_default(),
            );
            port.set(
                latest
                    .service
                    .as_ref()
                    .map(|s| s.listen_port.to_string())
                    .unwrap_or_default(),
            );
            protocol.set(
                latest
                    .service
                    .as_ref()
                    .map_or("tcp", |s| {
                        if s.protocols.len() > 1 {
                            "both"
                        } else if s.protocols.first() == Some(&peerward_types::ServiceProtocol::Udp)
                        {
                            "udp"
                        } else {
                            "tcp"
                        }
                    })
                    .to_owned(),
            );
            baseline.set(latest);
            editing.set(false);
            confirming.set(false);
            edit_reason.set(String::new());
            state_reason.set(String::new());
            confirmation.set(String::new());
        }
    }));
    let impact = use_console_query::<peerward_api::ConsoleSharingImpact>(format!(
        "/api/v1/meshes/{mesh}/console/sharing/{}/{}/impact",
        resource.kind, resource.id,
    ));
    let paused = resource.configuration.state == "paused";
    let save_resource = resource.clone();
    let save_mesh = mesh.clone();
    let save_csrf = csrf.clone();
    let dirty = !submitted()
        && (name() != resource.name
            || alias()
                != resource
                    .service
                    .as_ref()
                    .and_then(|s| s.alias.clone())
                    .unwrap_or_default()
            || protocol() != original_protocol
            || port()
                != resource
                    .service
                    .as_ref()
                    .map(|s| s.listen_port.to_string())
                    .unwrap_or_default()
            || !edit_reason().is_empty()
            || !state_reason().is_empty()
            || !confirmation().is_empty());
    rsx! {
        div { class: "sharing-settings-stack", "data-console-dirty": dirty.to_string(), aria_busy: busy().to_string(), "data-console-submitting": busy().to_string(),
            if current_version != resource.version && !submitted() {
                p { class: "info-note", {console_text(locale, "资源已在别处更新。草稿已保留；关闭并重新打开详情可载入新版本。旧版本提交会被拒绝。", "This resource changed elsewhere. Your draft is preserved. Reopen details to load the current version; stale writes are rejected.")} }
            }
            if submitted() {
                div { class: "success-note save-followup", role: "status",
                    p { {console_text(locale, "已提交。配置已经保存，设备应用情况仍需在“状态”确认。", "Submitted. The configuration is saved; confirm device application in Status.")} }
                    button { class: "secondary-button", onclick: move |_| on_show_status.call(()),
                        {console_text(locale, "查看状态", "View status")}
                    }
                }
            } else {
                section { class: "card sharing-common-settings",
                    div { class: "panel-head",
                        div {
                            h3 { {console_text(locale, "修改共享信息", "Edit sharing details")} }
                            p { class: "muted", {console_text(locale, "在这里保存共享参数；添加或撤销授权，请切换到“谁可以访问”。", "Save sharing parameters here. To add or revoke grants, switch to Who can access.")} }
                        }
                        if resource.network.is_some() { button {
                            class: "secondary-button",
                            disabled: busy(),
                            onclick: move |_| editing.toggle(),
                            if editing() {
                                {console_text(locale, "收起", "Hide")}
                            } else {
                                {console_text(locale, "修改目标", "Edit target")}
                            }
                        } }
                    }
                    if editing() && resource.network.is_some() {
                        ConsoleNetworkEditor {
                            mesh: mesh.clone(),
                            resource: resource.network.clone().unwrap(),
                            locale,
                            csrf: csrf.clone(),
                            on_change: move |()| {
                                submitted.set(true);
                                on_change.call(());
                            }
                        }
                    }
                    if editing() && resource.service.is_some() {
                        form {
                            class: "console-form compact-resource-edit",
                            onsubmit: move |event| {
                                event.prevent_default();
                                if busy() { return; }
                                message.set(String::new());
                                #[cfg(target_arch = "wasm32")]
                                {
                                    let Some(service) = save_resource.service.clone() else { return };
                                    let mesh = save_mesh.clone();
                                    let csrf = save_csrf.clone();
                                    let id = save_resource.id;
                                    let Ok(listen_port) = port().parse::<u16>() else {
                                        message.set(console_text(locale, "请输入有效端口", "Enter a valid port").into());
                                        return;
                                    };
                                    let protocols = match protocol().as_str() {
                                        "both" => vec![peerward_types::ServiceProtocol::Tcp, peerward_types::ServiceProtocol::Udp],
                                        "udp" => vec![peerward_types::ServiceProtocol::Udp],
                                        _ => vec![peerward_types::ServiceProtocol::Tcp],
                                    };
                                    let body = peerward_api::ConsoleServiceEdit {
                                        display_name: name(),
                                        alias: (!alias().trim().is_empty()).then(|| alias().trim().to_owned()),
                                        protocols,
                                        listen_port,
                                        paused,
                                        reason: edit_reason(),
                                    };
                                    busy.set(true);
                                    spawn(async move {
                                        let result: Result<Value, ConsoleApiError> = browser_api_client()
                                            .with_csrf(csrf.unwrap_or_default())
                                            .conditional_request(
                                                Method::PATCH,
                                                &format!("/api/v1/meshes/{mesh}/console/services/{id}"),
                                                Some(json!(body)),
                                                service.version,
                                            )
                                            .await;
                                        match result {
                                            Ok(_) => {
                                                submitted.set(true);
                                                on_change.call(());
                                            }
                                            Err(e) => message.set(console_api_error(locale, e)),
                                        }
                                        busy.set(false);
                                    });
                                }
                            },
                            label { r#for: "edit-share-name", {console_text(locale, "共享名称", "Share name")} }
                            input {
                                id: "edit-share-name",
                                value: name,
                                required: true,
                                maxlength: 128,
                                disabled: busy(),
                                oninput: move |e| { message.set(String::new()); name.set(e.value()); },
                            }
                            label { r#for: "edit-share-provider", {console_text(locale, "提供设备", "Provider device")} }
                            input { id: "edit-share-provider", value: resource.provider.clone(), readonly: true, aria_describedby: "edit-share-provider-help" }
                            p { id: "edit-share-provider-help", class: "muted",
                                {console_text(locale, "提供设备和共享类型在创建后固定；更换设备或类型需新建共享。", "Provider and share type are fixed after creation. Create another share to use a different device or type.")}
                            }
                            div { class: "field-pair",
                                div { class: "sharing-protocol-field",
                                    label { r#for: "edit-share-protocol", {console_text(locale, "协议", "Protocol")} }
                                    select {
                                        id: "edit-share-protocol",
                                        value: protocol,
                                        "data-console-click-picker": "true",
                                        disabled: busy(),
                                        onchange: move |e| { message.set(String::new()); protocol.set(e.value()); },
                                        option { value: "tcp", "TCP" }
                                        option { value: "udp", "UDP" }
                                        option { value: "both", "TCP + UDP" }
                                    }
                                }
                                label { r#for: "edit-share-port", {console_text(locale, "服务端口", "Service port")}
                                    input {
                                        id: "edit-share-port",
                                        r#type: "number",
                                        min: 1,
                                        max: 65535,
                                        required: true,
                                        value: port,
                                        disabled: busy(),
                                        oninput: move |e| { message.set(String::new()); port.set(e.value()); },
                                    }
                                }
                            }
                            label { r#for: "edit-share-alias", {console_text(locale, "DNS 名称（可选）", "DNS name (optional)")} }
                                input {
                                    id: "edit-share-alias",
                                    value: alias,
                                    placeholder: console_text(locale, "例如：nas", "For example: nas"),
                                    maxlength: 63,
                                    pattern: "[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?",
                                    disabled: busy(),
                                    oninput: move |e| { message.set(String::new()); alias.set(e.value()); },
                                }
                            details { class: "inline-advanced",
                                summary { {console_text(locale, "操作原因（可选）", "Reason (optional)")} }
                                label { r#for: "edit-share-reason", {console_text(locale, "操作原因（可选）", "Reason (optional)")} }
                                input {
                                    id: "edit-share-reason",
                                    value: edit_reason,
                                    maxlength: 512,
                                    disabled: busy(),
                                    oninput: move |e| { message.set(String::new()); edit_reason.set(e.value()); },
                                }
                            }
                            div { class: "actions",
                                button { disabled: busy(), r#type: "submit",
                                    if busy() { {console_text(locale, "正在保存…", "Saving…")} } else { {console_text(locale, "保存设置", "Save settings")} }
                                }
                            }
                        }
                    }
                }
                section { class: if paused { "card sharing-state-card" } else { "card sharing-state-card danger-zone" },
                    div { class: "panel-head",
                        div {
                            h3 {
                                if paused {
                                    {console_text(locale, "恢复这个共享", "Resume this share")}
                                } else {
                                    {console_text(locale, "暂停这个共享", "Pause this share")}
                                }
                            }
                            p { class: "muted",
                                if paused {
                                    {console_text(locale, "恢复后仍需等待配置应用、路径和授权都满足，才代表实际可以访问。", "After resuming, configuration, path, and authorization still need to be ready before access actually works.")}
                                } else {
                                    {console_text(locale, "暂停会保留定义和访问授权，但会中断这个共享的使用。以后可以恢复。", "Pausing keeps the definition and access grants but interrupts use of this share. It can be resumed later.")}
                                }
                            }
                        }
                        button {
                            class: if paused { "" } else { "danger-button" },
                            disabled: busy(),
                            onclick: move |_| {
                                if confirming() {
                                    confirmation.set(String::new());
                                    state_reason.set(String::new());
                                    confirming.set(false);
                                } else {
                                    confirming.set(true);
                                }
                            },
                            if confirming() {
                                {console_text(locale, "取消", "Cancel")}
                            } else if paused {
                                {console_text(locale, "恢复共享", "Resume sharing")}
                            } else {
                                {console_text(locale, "暂停共享", "Pause sharing")}
                            }
                        }
                    }
                    if confirming() {
                        div { class: "state-change-confirmation",
                            p { class: "info-note",
                                if paused {
                                    {console_text(locale, "恢复使用当前定义和已有授权。只有设备应用新配置后，路径状态才会重新变为可用。", "Resume uses the current definition and existing grants. The path becomes usable only after devices apply the configuration.")}
                                } else {
                                    {console_text(locale, "暂停会阻断这个端点的访问；与它重叠的共享也可能受影响。", "Pausing blocks this endpoint and may also affect overlapping shares.")}
                                }
                            }
                            if let Some(Ok(impact)) = impact.read().as_ref() {
                                if !impact.overlapping_resources.is_empty() {
                                    p {
                                        strong { {console_text(locale, "可能受影响：", "May also affect: ")} }
                                        {impact.overlapping_resources.join(", ")}
                                    }
                                }
                                label { r#for: "state-share-confirm",
                                    {format!("{} {}", console_text(locale, "请输入共享名称确认：", "Type the share name:"), resource.name)}
                                }
                                input {
                                    id: "state-share-confirm",
                                    value: confirmation,
                                    disabled: busy(),
                                    oninput: move |e| { message.set(String::new()); confirmation.set(e.value()); },
                                }
                                label { r#for: "state-share-reason", {console_text(locale, "操作原因", "Reason")} }
                                input {
                                    id: "state-share-reason",
                                    value: state_reason,
                                    maxlength: 512,
                                    disabled: busy(),
                                    oninput: move |e| { message.set(String::new()); state_reason.set(e.value()); },
                                }
                                button {
                                    class: if paused { "" } else { "danger-button" },
                                    disabled: busy() || confirmation() != resource.name || state_reason().trim().is_empty() || impact.version != resource.version,
                                    onclick: move |_| {
                                        #[cfg(target_arch = "wasm32")]
                                        {
                                            let resource = resource.clone();
                                            let mesh = mesh.clone();
                                            let csrf = csrf.clone();
                                            busy.set(true);
                                            let reason = state_reason();
                                            spawn(async move {
                                                let (method, path, body) = if let Some(service) = resource.service {
                                                    (
                                                        Method::PATCH,
                                                        format!("/api/v1/meshes/{mesh}/console/services/{}", resource.id),
                                                        json!(peerward_api::ConsoleServiceEdit {
                                                            display_name: resource.name,
                                                            alias: service.alias,
                                                            protocols: service.protocols,
                                                            listen_port: service.listen_port,
                                                            paused: !paused,
                                                            reason
                                                        }),
                                                    )
                                                } else {
                                                    (
                                                        Method::PUT,
                                                        format!("/api/v1/meshes/{mesh}/console/resources/{}/state", resource.id),
                                                        json!(peerward_api::ConsoleResourceState { paused: !paused, reason }),
                                                    )
                                                };
                                                let result: Result<Value, ConsoleApiError> = browser_api_client()
                                                    .with_csrf(csrf.unwrap_or_default())
                                                    .conditional_request(method, &path, Some(body), resource.version)
                                                    .await;
                                                match result {
                                                    Ok(_) => {
                                                        submitted.set(true);
                                                        on_change.call(());
                                                    }
                                                    Err(e) => message.set(console_api_error(locale, e)),
                                                }
                                                busy.set(false);
                                            });
                                        }
                                    },
                                    if busy() {
                                        {console_text(locale, "正在提交…", "Submitting…")}
                                    } else if paused {
                                        {console_text(locale, "确认恢复共享", "Confirm resume")}
                                    } else {
                                        {console_text(locale, "确认暂停共享", "Confirm pause")}
                                    }
                                }
                            } else if let Some(Err(e)) = impact.read().as_ref() {
                                p { role: "alert", "{e}" }
                            } else {
                                p { role: "status", {console_message(locale, "loading")} }
                            }
                        }
                    }
                }
            }
            if !message().is_empty() {
                p { role: "alert", "{message}" }
            }
        }
    }
}
