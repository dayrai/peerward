#[component]
fn ConsoleGatewayManager(
    mesh: String,
    resource: peerward_management::NetworkResource,
    locale: Locale,
    csrf: Option<String>,
    can_write: bool,
    on_change: EventHandler<()>,
) -> Element {
    let mut cursor = use_signal(String::new);
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("limit", "20");
    if !cursor().is_empty() {
        query.append_pair("cursor", &cursor());
    }
    let mut data = use_console_query::<Page<peerward_api::ConsoleGateway>>(format!(
        "/api/v1/meshes/{mesh}/console/network-resources/{}/gateways?{}",
        resource.id,
        query.finish()
    ));
    rsx! {
        section { class: "card",
            h3 { {console_text(locale, "提供网关", "Providing gateways")} }
            p { class: "muted", {console_text(locale, "批准只允许该设备提供此目标；设备仍需在线并报告转发就绪。数字越小越优先。", "Approval permits this device to provide the target. It must still be online and report forwarding readiness. Lower priorities are preferred.")} }
            if let Some(Ok(page)) = data.read().as_ref() {
                if page.items.is_empty() { p { class: "empty", {console_text(locale, "暂无网关绑定。", "No gateway bindings.")} } }
                for gateway in &page.items {
                    ConsoleGatewayEditor { key: "{gateway.binding.id}", mesh: mesh.clone(), resource: resource.clone(), gateway: gateway.clone(), locale, csrf: csrf.clone(), can_write,
                        on_change: move |()| { data.restart(); on_change.call(()); }
                    }
                }
                div { class: "actions",
                    if !cursor().is_empty() { button { onclick: move |_| cursor.set(String::new()), {console_text(locale, "第一页", "First page")} } }
                    if let Some(next) = page.next_cursor.clone() { button { onclick: move |_| cursor.set(next.clone()), {console_message(locale, "next-page")} } }
                }
            } else if let Some(Err(error)) = data.read().as_ref() {
                p { role: "alert", "{error}" }
                button { onclick: move |_| data.restart(), {console_text(locale, "重试", "Retry")} }
            } else { p { role: "status", {console_text(locale, "正在读取网关…", "Loading gateways…")} } }
        }
    }
}

#[component]
#[allow(unused_mut, unused_variables)]
fn ConsoleGatewayEditor(
    mesh: String,
    resource: peerward_management::NetworkResource,
    gateway: peerward_api::ConsoleGateway,
    locale: Locale,
    csrf: Option<String>,
    can_write: bool,
    on_change: EventHandler<()>,
) -> Element {
    let mut editing = use_signal(|| false);
    let mut priority = use_signal(|| gateway.binding.priority.to_string());
    let mut approved = use_signal(|| gateway.binding.approved);
    let mut reason = use_signal(String::new);
    let mut confirmation = use_signal(String::new);
    let mut preview = use_signal(|| None::<peerward_api::ConsoleNetworkEditPreview>);
    let mut staged = use_signal(|| None::<peerward_api::ConsoleNetworkEdit>);
    let mut busy = use_signal(|| false);
    let mut message = use_signal(String::new);
    let mut editing_base = use_signal(|| (resource.clone(), gateway.clone()));
    let target = resource.definition.name.clone();
    let edit_gateway = gateway.clone();
    let run = use_callback(move |apply: bool| {
        #[cfg(target_arch = "wasm32")]
        {
            if busy() {
                return;
            }
            let (resource, current) = editing_base();
            let draft = if apply {
                let Some(draft) = staged() else {
                    return;
                };
                draft
            } else {
                let Ok(priority) = priority().parse::<u32>() else {
                    return;
                };
                peerward_api::ConsoleNetworkEdit {
                    request_id: uuid::Uuid::new_v4(),
                    resource_version: resource.version,
                    definition: resource.definition.clone(),
                    reason: reason(),
                    gateways: vec![peerward_api::ConsoleGatewayChange {
                        id: current.binding.id,
                        version: current.binding.version,
                        priority,
                        approved: approved(),
                    }],
                }
            };
            let path = format!(
                "/api/v1/meshes/{mesh}/console/network-resources/{}",
                resource.id
            );
            let csrf = csrf.clone();
            busy.set(true);
            message.set(String::new());
            spawn(async move {
                let api = browser_api_client().with_csrf(csrf.unwrap_or_default());
                let result: Result<peerward_api::ConsoleNetworkEditPreview, ConsoleApiError> =
                    if apply {
                        let Some(review) = preview() else {
                            busy.set(false);
                            return;
                        };
                        api.conditional_request(
                            Method::POST,
                            &format!("{path}/apply"),
                            Some(json!(peerward_api::ConsoleNetworkEditApply {
                                draft: draft.clone(),
                                preview_digest: review.digest
                            })),
                            review.version,
                        )
                        .await
                    } else {
                        api.request(Method::POST, &format!("{path}/preview"), Some(json!(draft)))
                            .await
                    };
                match result {
                    Ok(review) => {
                        staged.set(Some(draft));
                        preview.set(Some(review));
                        if apply {
                            editing.set(false);
                            reason.set(String::new());
                            confirmation.set(String::new());
                            preview.set(None);
                            message.set(
                                console_text(
                                    locale,
                                    "网关变更已提交，等待当前路径上报。",
                                    "Gateway change submitted; awaiting current path evidence.",
                                )
                                .into(),
                            );
                            on_change.call(());
                        }
                    }
                    Err(error) => message.set(console_api_error(locale, error)),
                }
                busy.set(false);
            });
        }
    });
    rsx! {
        article { class: "card", "data-console-dirty": (editing() && (!reason().is_empty() || !confirmation().is_empty() || priority() != editing_base.read().1.binding.priority.to_string() || approved() != editing_base.read().1.binding.approved)).to_string(),
            strong { "{gateway.peer_name}" }
            p { {format!("{} · {} · {} {}", if gateway.online { console_text(locale, "在线", "Online") } else { console_text(locale, "离线", "Offline") }, if gateway.binding.approved { console_text(locale, "已批准", "Approved") } else { console_text(locale, "未批准", "Not approved") }, console_text(locale, "优先级", "Priority"), gateway.binding.priority)} }
            if can_write && !editing() {
                button { class: "secondary-button", onclick: move |_| { editing_base.set((resource.clone(), edit_gateway.clone())); priority.set(edit_gateway.binding.priority.to_string()); approved.set(edit_gateway.binding.approved); editing.set(true); }, {console_text(locale, "管理此网关", "Manage gateway")} }
            }
            if editing() {
                if let Some(review) = preview() {
                    p { class: "risk-preview", {format!("{} → {} · {}", gateway.peer_name, target, if approved() { console_text(locale, "批准提供该目标，采用手动批准。", "Allow this gateway to provide this target with manual approval.") } else { console_text(locale, "撤回该网关路径，现有连接可能中断。", "Withdraw this gateway path; existing connections may be interrupted.") })} }
                    p { {format!("{}：{} → {}", console_text(locale, "优先级", "Priority"), editing_base.read().1.binding.priority, priority())} }
                    p { {format!("{}：{}", console_text(locale, "变更原因", "Change reason"), reason())} }
                    if !review.overlapping_resources.is_empty() { p { {format!("{} {}", console_text(locale, "重叠资源：", "Overlapping resources:"), review.overlapping_resources.join(", "))} } }
                    label { {console_text(locale, "输入网关名称确认", "Type the gateway name")}
                        input { value: confirmation, disabled: busy(), oninput: move |e| confirmation.set(e.value()) }
                    }
                    button { disabled: busy() || confirmation() != gateway.peer_name, onclick: move |_| run.call(true), {console_text(locale, "确认网关变更", "Apply gateway change")} }
                    button { class: "secondary-button", disabled: busy(), onclick: move |_| preview.set(None), {console_text(locale, "返回修改", "Back")} }
                } else {
                    label { {console_text(locale, "网关优先级", "Gateway priority")}
                        input { r#type: "number", min: 0, max: "4294967295", value: priority, disabled: busy(), oninput: move |e| priority.set(e.value()) }
                    }
                    label { input { r#type: "checkbox", checked: approved, disabled: busy(), onchange: move |e| approved.set(e.checked()) } {console_text(locale, "批准此网关提供当前目标", "Approve this gateway for the current target")} }
                    label { {console_text(locale, "网关变更原因", "Gateway change reason")}
                        input { value: reason, disabled: busy(), maxlength: 512, oninput: move |e| reason.set(e.value()) }
                    }
                    button { disabled: busy() || reason().trim().is_empty() || priority().parse::<u32>().is_err(), onclick: move |_| run.call(false), {console_text(locale, "预览网关变更", "Preview gateway change")} }
                }
            }
            if !message().is_empty() { p { role: "status", "{message}" } }
        }
    }
}
