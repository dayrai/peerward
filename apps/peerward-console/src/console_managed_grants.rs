#[component]
#[allow(unused_mut, unused_variables)]
fn ConsoleManagedGrants(
    mesh: String,
    service: uuid::Uuid,
    #[props(default)] network: bool,
    locale: Locale,
    csrf: Option<String>,
    can_write: bool,
    on_change: EventHandler<()>,
    #[props(default)] refresh: u64,
) -> Element {
    let family = if network {
        "network-resources"
    } else {
        "services"
    };
    let mut cursor = use_signal(String::new);
    let mut data = use_console_query::<Page<peerward_api::ConsoleServiceGrant>>(format!(
        "/api/v1/meshes/{mesh}/console/{family}/{service}/grants?limit=50&cursor={}",
        cursor(),
    ));
    let mut selected = use_signal(|| None::<peerward_api::ConsoleServiceGrant>);
    let mut seen_refresh = use_signal(|| refresh);
    use_effect(use_reactive((&refresh,), move |(refresh,)| {
        if refresh != seen_refresh() {
            seen_refresh.set(refresh);
            data.restart();
        }
    }));
    let mut reason = use_signal(String::new);
    let mut confirmed = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let mut message = use_signal(String::new);
    let mut message_error = use_signal(|| false);
    let mut impact =
        use_console_query::<peerward_api::ConsoleSharingImpact>(if selected().is_some() {
            format!(
                "/api/v1/meshes/{mesh}/console/sharing/{}/{service}/impact",
                if network { "lan" } else { "service" }
            )
        } else {
            String::new()
        });
    rsx! {
        section { class: "card",
            h3 { {console_text(locale, "此资源的授权", "Resource grants")} }
            p { class: "muted",
                {
                    console_text(
                        locale,
                        "每次只变更选中的授权。其他授权和高级规则仍会影响最终权限；变更后请重新模拟。",
                        "Only the selected grant changes. Other grants and advanced rules still affect access; simulate again after changes.",
                    )
                }
            }
            if let Some(Ok(page)) = data.read().as_ref() {
                if page.items.is_empty() {
                    p {
                        {
                            console_text(
                                locale,
                                "尚无简易授权；高级规则仍可能允许访问。",
                                "No managed grants. Advanced rules may still allow access.",
                            )
                        }
                    }
                }
                for grant in &page.items {
                    article { class: "managed-grant",
                        div {
                            strong {
                                if grant.source_names.is_empty() && grant.advanced {
                                    {console_text(locale, "按高级规则匹配来源", "Source matched by advanced rule")}
                                } else if grant.source_names.is_empty() {
                                    {console_text(locale, "来源已移除", "Source removed")}
                                } else {
                                    {grant.source_names.join("、")}
                                }
                            }
                            if network { p { class: "muted", {console_grant_conditions(locale, grant)} } }
                            p { class: "muted",
                                if grant.advanced { {console_text(locale, "高级规则", "Advanced rule")} } else if grant.enabled {
                                    {console_text(locale, "授权启用", "Grant enabled")}
                                } else {
                                    {console_text(locale, "授权已撤销", "Grant revoked")}
                                }
                            }
                        }
                        if grant.advanced {
                            p { class: "muted", {console_text(locale, "此规则包含高级条件或多个对象，请在高级规则中检查。", "This rule has advanced conditions or multiple targets. Review it in the advanced editor.")} }
                            a { href: format!("/policy?mesh={mesh}#advanced-access"), {console_text(locale, "查看高级规则", "Review advanced rules")} }
                        } else if can_write {
                            button {
                                class: "secondary-button",
                                disabled: busy(),
                                onclick: {
                                    let grant = grant.clone();
                                    move |_| {
                                        selected.set(Some(grant.clone()));
                                        reason.set(String::new());
                                        confirmed.set(false);
                                        message.set(String::new());
                                        message_error.set(false);
                                    }
                                },
                                if grant.enabled {
                                    {console_text(locale, "撤销此授权", "Revoke grant")}
                                } else {
                                    {console_text(locale, "恢复此授权", "Restore grant")}
                                }
                            }
                        }
                    }
                }
                div { class: "actions",
                    if !cursor().is_empty() {
                        button { onclick: move |_| cursor.set(String::new()),
                            {console_text(locale, "第一页", "First page")}
                        }
                    }
                    if let Some(next) = page.next_cursor.clone() {
                        button { onclick: move |_| cursor.set(next.clone()),
                            {console_message(locale, "next-page")}
                        }
                    }
                }
            }
            if let Some(Err(e)) = data.read().as_ref() {
                if !e.is_empty() {
                    p { role: "alert", "{e}" }
                    button { onclick:move |_| data.restart(), {console_text(locale,"重试","Retry")} }
                }
            }
            if data.read().is_none() { p { role:"status", {console_text(locale,"正在读取授权…","Loading grants…")} } }
            if let Some(grant) = selected() {
                form {
                    class: "console-form",
                    "data-console-dirty": (!reason().is_empty() || confirmed()).to_string(),
                    aria_busy: busy().to_string(), "data-console-submitting": busy().to_string(),
                    onsubmit: move |e| {
                        e.prevent_default();
                        #[cfg(target_arch = "wasm32")]
                        {
                            if busy() || !confirmed() {
                                return;
                            }
                            let mesh = mesh.clone();
                            let csrf = csrf.clone();
                            let grant = grant.clone();
                            busy.set(true);
                            spawn(async move {
                                let response = browser_api_client()
                                    .with_csrf(csrf.unwrap_or_default())
                                    .conditional_request::<
                                        Value,
                                    >(
                                        Method::PUT,
                                        &format!(
                                            "/api/v1/meshes/{mesh}/console/{family}/{service}/grants/{}",
                                            grant.id,
                                        ),
                                        Some(
                                            json!(
                                                peerward_api::ConsoleServiceGrantState { enabled:! grant
                                                .enabled, reason : reason() }
                                            ),
                                        ),
                                        grant.version,
                                    )
                                    .await;
                                match response {
                                    Ok(_) => {
                                        message_error.set(false);
                                        message
                                            .set(
                                                console_text(
                                                        locale,
                                                        "已提交，等待设备应用策略。请重新模拟并核对连接状态。",
                                                        "Submitted; awaiting device policy application. Simulate again and check connection status.",
                                                    )
                                                    .into(),
                                            );
                                        selected.set(None);
                                        data.restart();
                                        on_change.call(());
                                    }
                                    Err(e) => {
                                        message_error.set(true);
                                        message.set(console_api_error(locale, e));
                                    }
                                }
                                busy.set(false);
                            });
                        }
                    },
                    p {
                        {console_text(locale, "变更对象：", "Grant source: ")}
                        { grant.source_names
                                .join("、") }
                    }
                    if let Some(Ok(impact)) = impact.read().as_ref() {
                        p { {format!("{}：{}", console_text(locale, "变更资源", "Resource"), impact.resource_name)} }
                        if !impact.overlapping_resources.is_empty() { p { class: "risk-preview", {format!("{}：{}", console_text(locale, "重叠目标", "Overlapping targets"), impact.overlapping_resources.join("、"))} } }
                    } else if let Some(Err(error)) = impact.read().as_ref() { p { role: "alert", "{error}" } button { r#type:"button",onclick:move |_|impact.restart(),{console_text(locale,"重试影响检查","Retry impact check")} } }
                    label { r#for: "grant-state-reason",
                        {console_text(locale, "操作原因", "Reason")}
                    }
                    input {
                        id: "grant-state-reason",
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
                                "确认仅变更此授权；其他授权和拒绝规则保持不变。重叠目标可能受影响，提交后需重新模拟。",
                                "Confirm only this grant changes. Other grants and deny rules are preserved. Overlapping targets may be affected; simulate again after submitting.",
                            )
                        }
                    }
                    div { class: "actions",
                        button {
                            r#type: "submit",
                            disabled: busy() || !confirmed() || impact.read().as_ref().is_none_or(Result::is_err),
                            if busy() { {console_text(locale, "正在提交…", "Submitting…")} } else { {console_text(locale, "确认提交", "Confirm")} }
                        }
                        button {
                            r#type: "button",
                            disabled: busy(),
                            class: "secondary-button",
                            "data-console-dismiss": "true",
                            onclick: move |_| {
                                message.set(String::new());
                                message_error.set(false);
                                selected.set(None);
                            },
                            {console_text(locale, "取消", "Cancel")}
                        }
                    }
                }
            }
            if !message().is_empty() {
                if message_error() {
                    p { role: "alert", "{message}" }
                } else {
                    p { role: "status", aria_live: "polite", "{message}" }
                }
            }
        }
    }
}

fn console_grant_conditions(locale: Locale, grant: &peerward_api::ConsoleServiceGrant) -> String {
    let protocol = match grant.protocol {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMPv4",
        58 => "ICMPv6",
        _ => console_text(locale, "全部协议", "All protocols"),
    };
    let ports = grant
        .destination_ports
        .iter()
        .map(|(first, last)| {
            if first == last {
                first.to_string()
            } else {
                format!("{first}–{last}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    if ports.is_empty() {
        protocol.into()
    } else {
        format!("{protocol} · {ports}")
    }
}
