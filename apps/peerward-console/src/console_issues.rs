fn issue_title(locale: Locale, kind: &str, severity: &str) -> &'static str {
    match kind {
        "gateway_path_missing" => {
            console_text(locale, "共享当前没有可用连接路径", "Sharing currently has no usable connection path")
        }
        "target_probe_failed" => {
            console_text(locale, "共享目标当前不可达", "Sharing target is currently unreachable")
        }
        value if value.starts_with("configuration_rejected_") => {
            console_text(locale, "设备没有应用最新配置", "Device did not apply the latest configuration")
        }
        "device_offline" => console_text(locale, "设备当前离线", "Device is offline"),
        "credential_expiring" if severity == "critical" => console_text(
            locale,
            "设备身份已经过期",
            "Device identity has expired",
        ),
        "credential_expiring" => console_text(
            locale,
            "设备身份即将到期",
            "Device identity is nearing expiry",
        ),
        "join_pending" => console_text(locale, "有新设备等待确认", "A new device is waiting for approval"),
        _ => console_text(locale, "需要检查", "Needs investigation"),
    }
}
fn issue_summary(locale: Locale, kind: &str, severity: &str) -> &'static str {
    match kind {
        "gateway_path_missing" => console_text(
            locale,
            "负责转发这个共享的设备当前没有提供可用连接路径。",
            "The device responsible for forwarding this share is not currently providing a usable connection path.",
        ),
        "target_probe_failed" => console_text(
            locale,
            "负责转发的设备最近无法连接这个共享的目标地址或端口。",
            "The forwarding device was recently unable to connect to this share's target address or port.",
        ),
        value if value.starts_with("configuration_rejected_") => console_text(
            locale,
            "设备已经收到最新设置，但没有成功应用；这不是普通的访问拒绝。",
            "The device received the latest settings but did not apply them successfully. This is not a normal access denial.",
        ),
        "device_offline" => console_text(
            locale,
            "控制服务当前没有看到这台设备的有效在线状态。已有访问规则不会因此被自动删除。",
            "The control service currently sees no valid online state for this device. Existing access rules are not removed automatically.",
        ),
        "credential_expiring" if severity == "critical" => console_text(
            locale,
            "当前设备身份已经超过有效期，新的身份连接可能无法建立。",
            "The current device identity is past its validity period, so new authenticated connections may fail.",
        ),
        "credential_expiring" => console_text(
            locale,
            "当前设备身份将在 30 天内到期；设备目前仍可使用，但需要在到期前完成更新。",
            "The current device identity expires within 30 days. The device can still operate, but should renew before expiry.",
        ),
        "join_pending" => console_text(
            locale,
            "一台新设备请求加入。批准前，它不会获得设备身份，也不会自动获得现有共享权限。",
            "A new device is requesting enrollment. Until approved, it receives no device identity and no existing sharing access automatically.",
        ),
        _ => console_text(
            locale,
            "系统发现了需要人工核对的证据。",
            "The system found evidence that needs human review.",
        ),
    }
}
fn issue_guidance(locale: Locale, kind: &str, severity: &str) -> &'static str {
    match kind {
        "gateway_path_missing" => console_text(
            locale,
            "先打开共享详情，检查负责转发的设备是否在线，以及网关路径是否已启用；通常不要先修改访问权限。",
            "Open the sharing details first, check whether the forwarding device is online and whether the gateway path is enabled. Usually, do not change access permissions first.",
        ),
        "target_probe_failed" => console_text(
            locale,
            "先核对共享的目标地址和端口，再确认目标服务正在运行。这里只检查网络连接，不检查应用登录。",
            "Check the share target address and port first, then confirm the target service is running. This only checks network connectivity, not application login.",
        ),
        value if value.starts_with("configuration_rejected_") => console_text(
            locale,
            "打开设备详情查看失败原因，再修复相关设置或设备本机运行条件。",
            "Open the device details, review the failure reason, then correct the relevant settings or the device runtime.",
        ),
        "device_offline" => console_text(
            locale,
            "先确认这台设备是否本来就应该在线；如果应该在线，再检查电源、网络和 Peerward 客户端。",
            "First decide whether this device is expected to be online. If it is, check power, network connectivity, and the Peerward client.",
        ),
        "credential_expiring" if severity == "critical" => console_text(
            locale,
            "打开设备维护检查当前身份和更新状态；离线设备需要先恢复连接，无法更新时再考虑重新加入。",
            "Open device maintenance and review the current identity and renewal state. Offline devices must reconnect first; only re-enroll if renewal cannot complete.",
        ),
        "credential_expiring" => console_text(
            locale,
            "在到期前请求设备自行更新身份；离线设备恢复连接后再完成更新。控制台不会替设备生成私钥。",
            "Ask the device to renew its identity before expiry. Offline devices can complete renewal after reconnecting. The console does not generate the device private key.",
        ),
        "join_pending" => console_text(
            locale,
            "在新设备本机独立核对身份指纹，再批准加入；不认识的申请直接保留未批准。",
            "Independently verify the identity fingerprint on the new device before approving it. Leave unrecognized requests unapproved.",
        ),
        _ => console_text(
            locale,
            "打开相关对象查看当前证据，再决定是否需要修改配置。",
            "Open the related object, review current evidence, and only then decide whether configuration needs to change.",
        ),
    }
}
fn issue_impact(locale: Locale, kind: &str, severity: &str) -> &'static str {
    if severity == "critical" && kind == "credential_expiring" {
        return console_text(locale, "可能阻止新连接", "May block new connections");
    }
    if severity == "critical" {
        return console_text(locale, "需要立即检查", "Needs immediate review");
    }
    match kind {
        "gateway_path_missing" => console_text(locale, "影响这个共享", "Affects this share"),
        "target_probe_failed" => {
            console_text(locale, "可能影响这个共享", "May affect this share")
        }
        value if value.starts_with("configuration_rejected_") => {
            console_text(locale, "可能影响这台设备", "May affect this device")
        }
        "device_offline" => console_text(locale, "影响这台设备", "Affects this device"),
        "credential_expiring" => {
            console_text(locale, "暂不影响使用", "Not affecting use yet")
        }
        "join_pending" => console_text(locale, "不影响现有设备", "Does not affect existing devices"),
        _ => console_text(locale, "需要核对", "Needs review"),
    }
}
fn issue_action_label(locale: Locale, kind: &str) -> &'static str {
    match kind {
        "gateway_path_missing" => console_text(locale, "检查网关路径", "Check gateway path"),
        "target_probe_failed" => console_text(locale, "检查共享", "Check sharing"),
        value if value.starts_with("configuration_rejected_") => {
            console_text(locale, "查看设备回执", "Review device receipt")
        }
        "device_offline" => console_text(locale, "检查设备", "Check device"),
        "credential_expiring" => console_text(locale, "更新设备身份", "Update device identity"),
        "join_pending" => console_text(locale, "核对入网申请", "Review enrollment request"),
        _ => console_text(locale, "查看详情", "View details"),
    }
}
fn issue_action_href(issue: &peerward_api::ConsoleIssue) -> String {
    issue.href.clone()
}

#[component]
fn ConsoleIssuesPanel(
    mesh: String,
    locale: Locale,
    csrf: Option<String>,
    #[props(default)] notifications: bool,
) -> Element {
    let mut filter = use_signal(|| "open".to_owned());
    let mut cursor = use_signal(String::new);
    let mut recheck_marker = use_signal(String::new);
    let mut recheck_previous_all = use_signal(|| 0_u64);
    let mut recheck_previous_open = use_signal(|| 0_u64);
    let mut recheck_requested = use_signal(|| false);
    let path = if mesh.is_empty() {
        String::new()
    } else {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        query.append_pair("limit", "50");
        let status = if notifications {
            match filter().as_str() {
                "open" => "unread",
                "known" => "read",
                _ => "all",
            }
        } else {
            match filter().as_str() {
                "open" => "open",
                "known" => "known",
                _ => "all",
            }
        };
        query.append_pair("status", status);
        if !cursor().is_empty() {
            query.append_pair("cursor", &cursor());
        }
        format!("/api/v1/meshes/{mesh}/console/issues?{}", query.finish())
    };
    let mut data = use_console_query::<peerward_api::ConsoleIssuePage>(path);
    let current_page = data.read().as_ref().and_then(|result| result.as_ref().ok()).cloned();
    let recheck_complete = current_page.as_ref().is_some_and(|page| {
        recheck_requested() && !recheck_marker().is_empty() && page.checked_at != recheck_marker()
    });
    rsx! {
        section { class: "card issues-panel",
            div { class: "panel-head",
                div {
                    h2 {
                        {
                            if notifications {
                                console_text(locale, "最近需要关注", "Needs attention")
                            } else {
                                console_text(locale, "待处理事项", "Items to handle")
                            }
                        }
                    }
                    p { class: "muted",
                        {
                            if notifications {
                                console_text(locale, "这里是提醒，不是另一套故障列表。处理动作仍从问题与维护进入。", "These are reminders, not a second fault list. Use Issues and maintenance for corrective actions.")
                            } else {
                                console_text(locale, "每项都说明发生了什么、影响范围和建议下一步；正常的访问拒绝不会列为故障。", "Each item explains what happened, its impact, and the next step. Expected access denials are not treated as faults.")
                            }
                        }
                    }
                }
                button {
                    class: "secondary-button",
                    disabled: !notifications && recheck_requested() && !recheck_complete,
                    onclick: move |_| {
                        if !notifications
                            && let Some(page) = current_page.as_ref() {
                            recheck_marker.set(page.checked_at.clone());
                            recheck_previous_all.set(page.all_count);
                            recheck_previous_open.set(page.open_count);
                            recheck_requested.set(true);
                        }
                        data.restart();
                    },
                    {
                        if notifications {
                            console_text(locale, "刷新", "Refresh")
                        } else if recheck_requested() && !recheck_complete {
                            console_text(locale, "正在重新检查…", "Checking…")
                        } else {
                            console_text(locale, "重新检查", "Check again")
                        }
                    }
                }
            }
            if mesh.is_empty() {
                p { class: "empty",
                    {console_text(locale, "请先选择一个网络。", "Select a network first.")}
                }
            } else {
                if let Some(Ok(page)) = data.read().as_ref() {
                    if recheck_complete && !notifications {
                        div { class: if page.open_count == 0 { "recheck-result recovered" } else { "recheck-result" }, role: "status",
                            span { class: "recheck-result-icon", if page.open_count == 0 { "✓" } else { "↻" } }
                            div {
                                strong {
                                    {
                                        if page.open_count == 0 {
                                            console_text(locale, "重新检查完成：当前证据已恢复", "Check complete: current evidence is healthy")
                                        } else if page.all_count < recheck_previous_all() {
                                            console_text(locale, "重新检查完成：先前有事项已不再出现", "Check complete: previous items no longer appear")
                                        } else if page.all_count > recheck_previous_all() {
                                            console_text(locale, "重新检查完成：发现了新的事项", "Check complete: new items were found")
                                        } else {
                                            console_text(locale, "重新检查完成：仍有事项需要处理", "Check complete: items still need attention")
                                        }
                                    }
                                }
                                p {
                                    {
                                        if page.open_count == 0 {
                                            console_text(locale, "当前没有待处理事项。Peerward 依据重新读取的真实证据确认状态，而不是依据你是否点击过某个修复按钮。", "There are no open items now. Peerward confirms this from freshly read evidence, not from whether a repair button was clicked.")
                                        } else if page.all_count < recheck_previous_all() {
                                            console_text(locale, "至少有先前事项已不再满足提醒条件；仍存在的事项会继续保留，直到当前证据真正变化。", "At least one previous item no longer meets the alert condition. Remaining items stay visible until their current evidence actually changes.")
                                        } else if page.open_count < recheck_previous_open() {
                                            console_text(locale, "待处理数量已经减少，但仍有事项需要继续确认。", "The open count decreased, but some items still need confirmation.")
                                        } else {
                                            console_text(locale, "当前证据仍满足这些提醒条件。打开仍存在的事项，继续按建议下一步处理。", "Current evidence still meets these alert conditions. Open the remaining items and continue with the recommended next step.")
                                        }
                                    }
                                }
                                small { {console_text(locale, "检查完成于", "Checked at")} " · " LocalDateTime { value: page.checked_at.clone(), locale } }
                            }
                        }
                    }
                }
                div { class: "segmented",
                    for (key, zh, en) in [
                        ("open", "待处理", "Open"),
                        ("known", "已知", "Known"),
                        ("all", "全部", "All"),
                    ]
                    {
                        button {
                            class: if filter() == key { "active" } else { "" },
                            onclick: move |_| {
                                cursor.set(String::new());
                                recheck_requested.set(false);
                                recheck_marker.set(String::new());
                                filter.set(key.into());
                            },
                            {
                                let count = if let Some(page) = current_page.as_ref() {
                                    match key {
                                        "open" => if notifications { page.unread_count } else { page.open_count },
                                        "known" => page.all_count.saturating_sub(if notifications { page.unread_count } else { page.open_count }),
                                        _ => page.all_count,
                                    }
                                } else { 0 };
                                let label = if notifications && key == "open" {
                                    console_text(locale, "未读", "Unread")
                                } else if notifications && key == "known" {
                                    console_text(locale, "已读", "Read")
                                } else {
                                    console_text(locale, zh, en)
                                };
                                format!("{label} {count}")
                            }
                        }
                    }
                }
                if let Some(Ok(page)) = data.read().as_ref() {
                    if page.items.is_empty() {
                        div { class: "ops-empty-state",
                            span { "✓" }
                            div {
                                strong {
                                    {
                                        if filter() == "known" {
                                            console_text(locale, "没有已知事项", "No acknowledged items")
                                        } else if filter() == "open" {
                                            console_text(locale, "当前没有待处理事项", "Nothing needs attention right now")
                                        } else {
                                            console_text(locale, "当前没有事项", "No current items")
                                        }
                                    }
                                }
                                p {
                                    {
                                        console_text(locale, "默认拒绝、正常拦截和一般活动仍会记录，但不会混进故障待办。", "Default-deny decisions, expected blocks, and routine activity are still recorded without becoming fault tasks.")
                                    }
                                }
                            }
                        }
                    }
                    for issue in &page.items
                    {
                        ConsoleIssueCard {
                            issue: issue
                                    .clone(),
                            locale,
                            csrf: csrf.clone(),
                            notifications,
                            on_change: move | () |
                                    data.restart(),
                        }
                    }
                    if !notifications {
                        div { class: "recovery-guidance",
                            strong { {console_text(locale, "修复后如何确认", "How to confirm recovery")} }
                            p { {console_text(locale, "完成设备、共享或设备身份处理后，回到这里点“重新检查”。事项消失表示当前证据已经恢复；仍然存在就继续处理。提交配置、重启客户端或发出更新请求本身都不等于恢复成功。", "After working on a device, share, or device identity, return here and choose Check again. If the item disappears, current evidence has recovered; if it remains, continue troubleshooting. Saving configuration, restarting a client, or requesting identity renewal alone does not prove recovery.")} }
                        }
                    }
                    div { class: "actions",
                        if !cursor().is_empty() {
                            button { onclick: move |_| {
                                    recheck_requested.set(false);
                                    recheck_marker.set(String::new());
                                    cursor.set(String::new());
                                },
                                {console_text(locale, "返回第一页", "First page")}
                            }
                        }
                        if let Some(next) = page.next_cursor.clone() {
                            button { onclick: move |_| {
                                    recheck_requested.set(false);
                                    recheck_marker.set(String::new());
                                    cursor.set(next.clone());
                                },
                                {console_message(locale, "next-page")}
                            }
                        }
                    }
                } else if let Some(Err(error)) = data.read().as_ref() {
                    if !error.is_empty() {
                        p { role: "alert", "{error}" }
                    }
                }
            }
        }
    }
}
#[component]
fn ConsoleIssueCard(
    issue: peerward_api::ConsoleIssue,
    locale: Locale,
    csrf: Option<String>,
    #[props(default)] notifications: bool,
    on_change: EventHandler<()>,
) -> Element {
    #[allow(unused_mut)]
    let mut error = use_signal(String::new);
    #[allow(unused_mut)]
    let mut busy = use_signal(|| false);
    let severity = issue.severity.clone();
    let action_href = issue_action_href(&issue);
    rsx! {
        article { class: format!("issue-card issue-card-actionable {}", issue.severity),
            span { class: "issue-icon", if issue.severity == "critical" { "!" } else { "i" } }
            div { class: "issue-copy",
                div { class: "issue-heading-row",
                    div { class: "issue-heading",
                        strong { "{issue.name}" }
                        span { {issue_title(locale, &issue.kind, &severity)} }
                    }
                    div { class: "issue-tags",
                        span {
                            class: if issue.severity == "critical" { "issue-impact critical" } else { "issue-impact" },
                            {issue_impact(locale, &issue.kind, &severity)}
                        }
                        if notifications {
                            span { class: "status-pill compact-pill",
                                {
                                    if issue.read {
                                        console_text(locale, "已读", "Read")
                                    } else {
                                        console_text(locale, "未读", "Unread")
                                    }
                                }
                            }
                        }
                        if issue.known {
                            span { class: "status-pill compact-pill",
                                {console_text(locale, "已知", "Acknowledged")}
                            }
                        }
                    }
                }
                div { class: "issue-summary-block",
                    small { {console_text(locale, "发生了什么", "What happened")} }
                    p { class: "issue-summary", {issue_summary(locale, &issue.kind, &severity)} }
                }
                div { class: "issue-next-step",
                    span { "→" }
                    div {
                        strong { {console_text(locale, "建议下一步", "Recommended next step")} }
                        p { {issue_guidance(locale, &issue.kind, &severity)} }
                    }
                }
                if let Some(at) = issue.observed_at.as_ref() {
                    div { class: "issue-observed",
                        small { {console_text(locale, "观测时间", "Observed")} " · " }
                        LocalDateTime { value: at.clone(), locale }
                    }
                }
                div { class: "issue-actions",
                    a { class: "secondary-link issue-primary-action", href: action_href,
                        {issue_action_label(locale, &issue.kind)}
                    }
                    button {
                        class: "quiet-button",
                        disabled: busy() || (notifications && issue.read),
                        onclick: move |_| {
                            #[cfg(target_arch = "wasm32")]
                            {
                                busy.set(true);
                                let issue = issue.clone();
                                let csrf = csrf.clone();
                                spawn(async move {
                                    let body = peerward_api::ConsoleNoticeUpdate {
                                        id: issue.id,
                                        fingerprint: issue.fingerprint,
                                        known: if notifications { None } else { Some(!issue.known) },
                                        read: if notifications { Some(true) } else { None },
                                    };
                                    let result: Result<Value, ConsoleApiError> = browser_api_client()
                                        .with_csrf(csrf.unwrap_or_default())
                                        .request(
                                            Method::PATCH,
                                            &format!("/api/v1/meshes/{}/console/notices", issue.mesh_id),
                                            Some(serde_json::to_value(body).unwrap()),
                                        )
                                        .await;
                                    match result {
                                        Ok(_) => on_change.call(()),
                                        Err(e) => error.set(console_api_error(locale, e)),
                                    }
                                    busy.set(false);
                                });
                            }
                        },
                        {
                            if notifications {
                                console_text(locale, "标记已读", "Mark read")
                            } else if issue.known {
                                console_text(locale, "重新列为待处理", "Reopen")
                            } else {
                                console_text(locale, "标记已知", "Acknowledge")
                            }
                        }
                    }
                }
                if !error().is_empty() {
                    p { role: "alert", "{error}" }
                }
            }
        }
    }
}
