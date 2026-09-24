#[component]
#[allow(unused_mut, unused_variables)]
fn ConsoleGrantForm(
    mesh: String,
    resource: peerward_api::ConsoleSharingResource,
    source: peerward_api::ConsoleGrantSource,
    locale: Locale,
    csrf: Option<String>,
    on_change: EventHandler<()>,
    #[props(default)] expanded: bool,
) -> Element {
    let request = use_signal(uuid::Uuid::new_v4);
    let mut protocol = use_signal(|| "6".to_owned());
    let mut port = use_signal(|| "443".to_owned());
    let mut reason = use_signal(String::new);
    let mut staged = use_signal(|| None::<peerward_api::ConsoleGrantDraft>);
    let mut preview = use_signal(|| None::<peerward_api::ConsoleSharingPreview>);
    let mut busy = use_signal(|| false);
    let mut complete = use_signal(|| false);
    let mut message = use_signal(String::new);
    let preview_mesh = mesh.clone();
    let preview_csrf = csrf.clone();
    rsx! {
        details {
            class: "card advanced-tools",
            open: expanded,
            "data-console-dirty": (!complete() && (!reason().is_empty() || protocol() != "6" || port() != "443")).to_string(),
            aria_busy: busy().to_string(), "data-console-submitting": busy().to_string(),
            summary { {console_text(locale, "为此来源添加授权", "Add a grant for this source")} }
            if complete() {
                p { class: "success-note", role: "status",
                    {
                        console_text(
                            locale,
                            "授权已提交，等待设备应用。可重新模拟检查当前有效策略。",
                            "Grant submitted; waiting for devices. Evaluate again to check current policy.",
                        )
                    }
                }
            } else if let Some(review) = preview() {
                p {
                    {
                        format!(
                            "{} {}",
                            review.affected_sources,
                            console_text(
                                locale,
                                "台来源设备；已有规则顺序和拒绝规则保留。",
                                "source devices; existing order and denies are preserved.",
                            ),
                        )
                    }
                }
                if !review.overlapping_resources.is_empty() {
                    p {
                        {
                            format!(
                                "{} {}",
                                console_text(locale, "重叠目标：", "Overlapping targets: "),
                                review.overlapping_resources.join(", "),
                            )
                        }
                    }
                }
                div { class: "actions",
                    button {
                        class: "secondary-button",
                        disabled: busy(),
                        onclick: move |_| preview.set(None),
                        {console_text(locale, "返回修改", "Back")}
                    }
                    button {
                        disabled: busy(),
                        onclick: move |_| {
                            #[cfg(target_arch = "wasm32")]
                            {
                                if busy() { return; }
                                let Some(draft) = staged() else { return };
                                let mesh = mesh.clone();
                                let csrf = csrf.clone();
                                let review = review.clone();
                                busy.set(true);
                                spawn(async move {
                                    let result: Result<
                                        peerward_api::ConsoleSharingPreview,
                                        ConsoleApiError,
                                    > = browser_api_client()
                                        .with_csrf(csrf.unwrap_or_default())
                                        .conditional_request(
                                            Method::POST,
                                            &format!("/api/v1/meshes/{mesh}/console/grants/apply"),
                                            Some(
                                                json!(
                                                    peerward_api::ConsoleGrantApply { draft, preview_digest :
                                                    review.digest }
                                                ),
                                            ),
                                            review.version,
                                        )
                                        .await;
                                    match result {
                                        Ok(_) => {
                                            complete.set(true);
                                            on_change.call(());
                                        }
                                        Err(e) => message.set(console_api_error(locale, e)),
                                    }
                                    busy.set(false);
                                });
                            }
                        },
                        if busy() { {console_text(locale, "正在授权…", "Granting…")} } else { {console_text(locale, "确认授权", "Confirm grant")} }
                    }
                }
            } else {
                form {
                    class: "console-form",
                    onsubmit: move |event| {
                        event.prevent_default();
                        if busy() { return; }
                        message.set(String::new());
                        let protocol = protocol().parse::<u8>().unwrap_or(6);
                        let port = if [6, 17].contains(&protocol) {
                            match port().parse::<u16>() {
                                Ok(p) if p > 0 => Some(p),
                                _ => {
                                    message
                                        .set(
                                            console_text(
                                                    locale,
                                                    "请输入有效端口。",
                                                    "Enter a valid port.",
                                                )
                                                .into(),
                                        );
                                    return;
                                }
                            }
                        } else {
                            None
                        };
                        let draft = peerward_api::ConsoleGrantDraft {
                            request_id: request(),
                            resource_id: resource.id,
                            service: resource.kind == "service",
                            source: source.clone(),
                            protocol,
                            port,
                            reason: reason(),
                        };
                        #[cfg(target_arch = "wasm32")]
                        {
                            let mesh = preview_mesh.clone();
                            let csrf = preview_csrf.clone();
                            staged.set(Some(draft.clone()));
                            busy.set(true);
                            spawn(async move {
                                let result: Result<
                                    peerward_api::ConsoleSharingPreview,
                                    ConsoleApiError,
                                > = browser_api_client()
                                    .with_csrf(csrf.unwrap_or_default())
                                    .request(
                                        Method::POST,
                                        &format!("/api/v1/meshes/{mesh}/console/grants/preview"),
                                        Some(json!(draft)),
                                    )
                                    .await;
                                match result {
                                    Ok(p) => preview.set(Some(p)),
                                    Err(e) => message.set(console_api_error(locale, e)),
                                }
                                busy.set(false);
                            });
                        }
                    },
                    if resource.kind != "service" {
                        label { r#for: "grant-protocol",
                            {console_text(locale, "授权协议", "Allowed protocol")}
                        }
                        select {
                            id: "grant-protocol",
                            value: protocol,
                            disabled: busy(),
                            onchange: move |e| { message.set(String::new()); protocol.set(e.value()); },
                            option { value: "6", "TCP" }
                            option { value: "17", "UDP" }
                            option { value: "0", {console_text(locale, "全部协议", "All protocols")} }
                        }
                        if protocol() != "0" {
                            label { r#for: "grant-port",
                                {console_text(locale, "授权端口", "Allowed port")}
                            }
                            input {
                                id: "grant-port",
                                r#type: "number",
                                min: 1,
                                max: 65535,
                                value: port,
                                disabled: busy(),
                                oninput: move |e| { message.set(String::new()); port.set(e.value()); },
                            }
                        }
                    } else {
                        p { class: "muted",
                            {
                                console_text(
                                    locale,
                                    "授权限于此服务定义中的协议和端口。",
                                    "Grant is limited to this service's configured protocols and port.",
                                )
                            }
                        }
                    }
                    label { r#for: "grant-reason", {console_text(locale, "操作原因", "Reason")} }
                    input {
                        id: "grant-reason",
                        value: reason,
                        required: true,
                        maxlength: 512,
                        disabled: busy(),
                        oninput: move |e| { message.set(String::new()); reason.set(e.value()); },
                    }
                    button { r#type: "submit", disabled: busy(),
                        if busy() { {console_text(locale, "正在检查…", "Checking…")} } else { {console_text(locale, "预览授权影响", "Preview grant impact")} }
                    }
                }
            }
            if !message().is_empty() {
                p { role: "alert", "{message}" }
            }
        }
    }
}
