fn renewal_state(locale: Locale, state: &str) -> &'static str {
    match state {
        "completed" => console_text(
            locale,
            "已完成，新身份已重新认证",
            "Completed; new identity authenticated",
        ),
        "awaiting_reconnect" => console_text(
            locale,
            "已激活，等待本地提交和重新连接",
            "Activated; awaiting local commit and reconnect",
        ),
        "updating" => console_text(locale, "设备正在更新", "Device is updating"),
        "waiting_offline" => {
            console_text(locale, "等待离线设备恢复连接", "Waiting for offline device")
        }
        "upgrade_required" => console_text(
            locale,
            "客户端需升级后才能接收此请求",
            "Client upgrade required",
        ),
        "expired" => console_text(
            locale,
            "请求已过期，可重新发起",
            "Request expired; submit a new request",
        ),
        "superseded" => console_text(
            locale,
            "设备身份已改变，请刷新设备",
            "Device identity changed; refresh device",
        ),
        "delivered" => console_text(
            locale,
            "已投递，等待设备执行",
            "Delivered; awaiting device execution",
        ),
        _ => console_text(locale, "已提交，等待投递", "Submitted; awaiting delivery"),
    }
}
#[component]
#[allow(unused_mut, unused_variables)]
fn ConsoleRenewalPanel(
    mesh: String,
    peer: PeerResource,
    locale: Locale,
    csrf: Option<String>,
    can_renew: bool,
    on_change: EventHandler<()>,
) -> Element {
    let mut history = use_console_query::<Page<peerward_api::ConsoleRenewal>>(format!(
        "/api/v1/meshes/{mesh}/console/devices/{}/renewals?limit=100",
        peer.id
    ));
    let mut reason = use_signal(String::new);
    let mut deadline = use_signal(|| "86400".to_owned());
    let mut confirmed = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let mut message = use_signal(String::new);
    let mut message_error = use_signal(|| false);
    let mut request = use_signal(uuid::Uuid::new_v4);
    rsx! {
        section { class: "card",
            div { class: "panel-head",
                h3 {
                    {
                        console_text(
                            locale,
                            "请求设备更新身份",
                            "Request device identity renewal",
                        )
                    }
                }
                button {
                    class: "secondary-button",
                    onclick: move |_| {
                        history.restart();
                        on_change.call(());
                    },
                    {console_text(locale, "刷新进度", "Refresh progress")}
                }
            }
            p { class: "muted",
                {
                    console_text(
                        locale,
                        "设备收到请求后，会在本机生成新密钥并更新身份。离线设备会等待重连；只有新身份重新认证后才显示已完成。",
                        "The device generates new keys locally and renews its identity after receiving the request. Offline devices wait for connection. Completion requires authentication with the replacement identity.",
                    )
                }
            }
            if let Some(Ok(page)) = history.read().as_ref() {
                for item in page.items.iter() {
                    article { class: "renewal-item",
                        strong { { renewal_state(locale,&
                                item.state) } }
                        p {
                            small { {console_text(locale, "提交时间：", "Submitted: ")} }
                            LocalDateTime { value: item.created_at.clone(), locale }
                        }
                        p {
                            small { {console_text(locale, "请求期限：", "Deadline: ")} }
                            LocalDateTime { value: item.expires_at.clone(), locale }
                        }
                        details {
                            summary { {console_text(locale, "请求标识", "Request identity")} }
                            code { "{item.id}" }
                        }
                    }
                }
            }
            if let Some(Err(e)) = history.read().as_ref() {
                if !e.is_empty() {
                    div { class: "feedback-state feedback-error embedded-feedback", role: "alert",
                        span { class: "feedback-icon", aria_hidden: "true", "!" }
                        div { class: "feedback-copy",
                            strong { {console_text(locale, "暂时无法读取更新进度", "Unable to load renewal progress right now")} }
                            p { "{e}" }
                        }
                        button { class: "secondary-button", onclick: move |_| history.restart(),
                            {console_text(locale, "重试", "Retry")}
                        }
                    }
                }
            }
            if can_renew && peer.credentials.active.is_some() {
                details { class: "advanced-tools",
                    summary { {console_text(locale, "发起更新请求", "Create renewal request")} }
                    form {
                        class: "console-form",
                        "data-console-dirty": (!reason().is_empty() || confirmed() || deadline() != "86400").to_string(),
                        aria_busy: busy().to_string(), "data-console-submitting": busy().to_string(),
                        onsubmit: move |e| {
                            e.prevent_default();
                            #[cfg(target_arch = "wasm32")]
                            {
                                if busy() { return; }
                                if !confirmed() {
                                    return;
                                }
                                let Some(active) = peer.credentials.active.clone() else { return };
                                let current_serial = active.serial;
                                let mesh = mesh.clone();
                                let csrf = csrf.clone();
                                let id = peer.id;
                                let version = peer.version;
                                let body = peerward_api::ConsoleRenewalRequest {
                                    request_id: request(),
                                    current_serial,
                                    valid_for_seconds: deadline().parse().unwrap_or(86400),
                                    reason: reason(),
                                };
                                busy.set(true);
                                message.set(String::new());
                                message_error.set(false);
                                spawn(async move {
                                    let result: Result<peerward_api::ConsoleRenewal, ConsoleApiError> = browser_api_client()
                                        .with_csrf(csrf.unwrap_or_default())
                                        .conditional_request(
                                            Method::POST,
                                            &format!("/api/v1/meshes/{mesh}/console/devices/{id}/renewals"),
                                            Some(json!(body)),
                                            version,
                                        )
                                        .await;
                                    match result {
                                        Ok(_) => {
                                            message_error.set(false);
                                            message.set(console_text(locale,
                                                "请求已提交，请查看上方进度。",
                                                "Request submitted. See the progress above.").into());
                                            history.restart();
                                            confirmed.set(false);
                                            reason.set(String::new());
                                            deadline.set("86400".into());
                                            request.set(uuid::Uuid::new_v4());
                                        }
                                        Err(e) => { message_error.set(true); message.set(console_api_error(locale, e)); }
                                    }
                                    busy.set(false);
                                });
                            }
                        },
                        label { r#for: "renewal-deadline",
                            {console_text(locale, "等待期限", "Waiting deadline")}
                        }
                        select {
                            id: "renewal-deadline",
                            value: deadline,
                            disabled: busy(),
                            onchange: move |e| { message.set(String::new()); message_error.set(false); deadline.set(e.value()); },
                            option { value: "3600", {console_text(locale, "1 小时", "1 hour")} }
                            option { value: "86400", {console_text(locale, "24 小时", "24 hours")} }
                            option { value: "604800", {console_text(locale, "7 天", "7 days")} }
                        }
                        label { r#for: "renewal-reason",
                            {console_text(locale, "操作原因", "Reason")}
                        }
                        input {
                            id: "renewal-reason",
                            value: reason,
                            required: true,
                            maxlength: 512,
                            disabled: busy(),
                            oninput: move |e| { message.set(String::new()); message_error.set(false); reason.set(e.value()); },
                        }
                        label { class: "checkbox-row",
                            input {
                                r#type: "checkbox",
                                checked: confirmed,
                                disabled: busy(),
                                onchange: move |e| { message.set(String::new()); message_error.set(false); confirmed.set(e.checked()); },
                            }
                            {
                                console_text(
                                    locale,
                                    "确认更新此设备的身份，期间可能短暂重连。",
                                    "Renew this device's identity; it may briefly reconnect.",
                                )
                            }
                        }
                        button {
                            disabled: busy() || !confirmed(),
                            r#type: "submit",
                            if busy() { {console_text(locale, "正在提交…", "Submitting…")} } else { {console_text(locale, "提交更新请求", "Submit renewal request")} }
                        }
                    }
                }
            }
            if !message().is_empty() {
                if message_error() { p { role: "alert", "{message}" } }
                else { p { role: "status", aria_live: "polite", "{message}" } }
            }
        }
    }
}
