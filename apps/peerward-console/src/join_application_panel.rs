#[derive(Clone, PartialEq)]
enum JoinReviewOperation {
    Load(Option<String>),
    Approve,
    Reject,
}

#[component]
#[allow(unused_mut, unused_variables)]
fn JoinApplicationPanel(
    mesh: String,
    csrf: Option<String>,
    can_write: bool,
    locale: Locale,
    #[props(default)] ready: bool,
    #[props(default)] ticket_id: Option<uuid::Uuid>,
    #[props(default)] requested_application: Option<uuid::Uuid>,
    #[props(default)] on_submitting: EventHandler<bool>,
    #[props(default)] on_progress: EventHandler<u8>,
    #[props(default)] guided: bool,
    #[props(default)] on_back: EventHandler<()>,
    #[props(default)] on_restart: EventHandler<()>,
    #[props(default)] on_cancel: EventHandler<()>,
) -> Element {
    let mut active = use_signal(|| mesh.clone());
    let mut mesh_generation = use_signal(|| 0_u64);
    let mut applications = use_signal(Vec::<peerward_management::JoinApplication>::new);
    let mut selected = use_signal(|| None::<peerward_management::JoinApplication>);
    let mut fingerprint = use_signal(String::new);
    let mut active_selection = use_signal(|| (ticket_id, requested_application));
    let mut next = use_signal(|| None::<String>);
    let mut busy = use_signal(|| false);
    let mut submitting = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut query = use_signal(String::new);
    let mut ticket = use_signal(|| None::<JoinTicketResource>);
    let mut current_read = use_signal(|| false);
    let operate = use_callback(move |operation: JoinReviewOperation| {
        #[cfg(target_arch = "wasm32")]
        {
            if *busy.peek()
                || active.peek().is_empty()
                || (!can_write && !matches!(operation, JoinReviewOperation::Load(_)))
            {
                return;
            }
            if !matches!(operation, JoinReviewOperation::Load(_)) {
                let selection = selected.peek();
                let Some(entry) = selection.as_ref() else {
                    return;
                };
                if !*current_read.peek()
                    || ticket_id.is_some_and(|id| entry.ticket_id != id)
                    || requested_application.is_some_and(|id| entry.id != id)
                    || entry.status != peerward_management::JoinApplicationStatus::Pending
                    || (operation == JoinReviewOperation::Approve
                        && *fingerprint.peek() != entry.identity_fingerprint)
                {
                    return;
                }
            }
            let scope = active.peek().clone();
            let generation = *mesh_generation.peek();
            let captured = selected.peek().clone();
            let confirmed = fingerprint.peek().clone();
            let mut api = browser_api_client();
            if let Some(csrf) = &csrf {
                api = api.with_csrf(csrf.clone());
            }
            busy.set(true);
            submitting.set(!matches!(operation, JoinReviewOperation::Load(_)));
            error.set(String::new());
            spawn(async move {
                let base = format!("/api/v1/meshes/{scope}/join-applications");
                // Commit feedback is independent from the following metadata refresh.
                // A failed GET must never turn an accepted approval into a failed write.
                if !matches!(operation, JoinReviewOperation::Load(_)) {
                    let Some(entry) = captured else {
                        busy.set(false);
                        submitting.set(false);
                        return;
                    };
                    let approving = operation == JoinReviewOperation::Approve;
                    let result: Result<peerward_management::JoinApplication, ConsoleApiError> = api
                        .conditional_request(
                            Method::POST,
                            &format!(
                                "{base}/{}/{}",
                                entry.id,
                                if approving { "approve" } else { "reject" }
                            ),
                            if approving {
                                Some(json!({"identity_fingerprint":confirmed}))
                            } else {
                                None
                            },
                            entry.version,
                        )
                        .await;
                    if *active.peek() != scope || *mesh_generation.peek() != generation {
                        return;
                    }
                    match result {
                        Ok(updated) => {
                            selected.set(Some(updated));
                            fingerprint.set(String::new());
                        }
                        Err(failure) => {
                            error.set(console_api_error(locale, failure));
                            current_read.set(false);
                            busy.set(false);
                            submitting.set(false);
                            return;
                        }
                    }
                }
                let result: Result<
                    (
                        Option<JoinTicketResource>,
                        Page<peerward_management::JoinApplication>,
                    ),
                    ConsoleApiError,
                > = async {
                    let ticket = if let Some(id) = ticket_id {
                        Some(
                            api.request(
                                Method::GET,
                                &format!("/api/v1/meshes/{scope}/join-tickets/{id}"),
                                None,
                            )
                            .await?,
                        )
                    } else {
                        None
                    };
                    let mut params = url::form_urlencoded::Serializer::new(String::new());
                    params.append_pair("limit", "50");
                    if let Some(id) = ticket_id {
                        params.append_pair("ticket", &id.to_string());
                    }
                    if let JoinReviewOperation::Load(Some(cursor)) = &operation {
                        params.append_pair("cursor", cursor);
                    }
                    let page = api
                        .request(Method::GET, &format!("{base}?{}", params.finish()), None)
                        .await?;
                    Ok((ticket, page))
                }
                .await;
                if *active.peek() != scope || *mesh_generation.peek() != generation {
                    return;
                }
                match result {
                    Ok((fresh_ticket, page)) => {
                        ticket.set(fresh_ticket);
                        let items = page.items;
                        let selected_id = selected
                            .peek()
                            .as_ref()
                            .map(|entry| entry.id)
                            .or(requested_application);
                        if let Some(selected_id) = selected_id {
                            // Selection may be on another history page. Re-read it before enabling decisions.
                            match api
                                .request::<peerward_management::JoinApplication>(
                                    Method::GET,
                                    &format!("{base}/{selected_id}"),
                                    None,
                                )
                                .await
                            {
                                Ok(fresh) => {
                                    if *active.peek() != scope
                                        || *mesh_generation.peek() != generation
                                    {
                                        return;
                                    }
                                    selected.set(Some(fresh));
                                    current_read.set(true);
                                }
                                Err(failure) => {
                                    if *active.peek() != scope
                                        || *mesh_generation.peek() != generation
                                    {
                                        return;
                                    }
                                    current_read.set(false);
                                    error.set(console_api_error(locale, failure));
                                }
                            }
                        } else {
                            selected.set(
                                items
                                    .iter()
                                    .find(|entry| {
                                        entry.status
                                            == peerward_management::JoinApplicationStatus::Pending
                                    })
                                    .or_else(|| items.first())
                                    .cloned(),
                            );
                            current_read.set(true);
                        }
                        applications.set(items);
                        next.set(page.next_cursor);
                    }
                    Err(failure) => {
                        current_read.set(false);
                        error.set(console_api_error(locale, failure));
                    }
                }
                busy.set(false);
                submitting.set(false);
            });
        }
    });
    use_effect(use_reactive(
        (&mesh, &ready, &ticket_id, &requested_application),
        move |(mesh, ready, ticket_id, requested_application)| {
            if *active.peek() != mesh
                || *active_selection.peek() != (ticket_id, requested_application)
            {
                let next_generation = mesh_generation.peek().wrapping_add(1);
                mesh_generation.set(next_generation);
                active.set(mesh.clone());
                active_selection.set((ticket_id, requested_application));
                selected.set(None);
                fingerprint.set(String::new());
                applications.set(Vec::new());
                next.set(None);
                busy.set(false);
                submitting.set(false);
                error.set(String::new());
                query.set(String::new());
                ticket.set(None);
                current_read.set(false);
            }
            if ready {
                operate.call(JoinReviewOperation::Load(None));
            }
        },
    ));
    use_effect(move || on_submitting.call(submitting()));
    let current = selected();
    let can_decide = current_read()
        && active_selection() == (ticket_id, requested_application)
        && ready
        && can_write
        && !busy()
        && current.as_ref().is_some_and(|entry| {
            entry.status == peerward_management::JoinApplicationStatus::Pending
                && ticket_id.is_none_or(|id| entry.ticket_id == id)
                && requested_application.is_none_or(|id| entry.id == id)
        });
    let entered = fingerprint();
    let can_approve = can_decide
        && peerward_management::valid_identity_fingerprint(&entered)
        && current
            .as_ref()
            .is_some_and(|entry| entry.identity_fingerprint == entered);
    let search = query().to_lowercase();
    let completed_peer = current
        .as_ref()
        .filter(|entry| entry.status == peerward_management::JoinApplicationStatus::Approved)
        .and_then(|entry| entry.peer_id)
        .or_else(|| ticket().and_then(|value| value.claimed_peer_id));
    let ended = ticket()
        .is_some_and(|value| matches!(value.status.as_str(), "expired" | "cancelled" | "rejected"))
        || current.as_ref().is_some_and(|entry| {
            !matches!(
                entry.status,
                peerward_management::JoinApplicationStatus::Pending
                    | peerward_management::JoinApplicationStatus::Approved
            )
        });
    let progress = if ticket_id.is_none() && requested_application.is_none() {
        1
    } else if completed_peer.is_some() {
        4
    } else if current
        .as_ref()
        .is_some_and(|e| e.status == peerward_management::JoinApplicationStatus::Pending)
    {
        3
    } else if ticket_id.is_some() {
        2
    } else {
        1
    };
    use_effect(use_reactive((&progress,), move |(step,)| {
        on_progress.call(step);
    }));
    let dirty = !fingerprint().is_empty()
        && current.as_ref().is_some_and(|entry| {
            entry.status == peerward_management::JoinApplicationStatus::Pending
        });
    rsx! {
        section { id: "join-review", class: if guided {"enrollment-review enrollment-review-guided"} else {"card enrollment-review"},
            "data-console-dirty": dirty.to_string(),
            "data-console-submitting": submitting().to_string(),
            aria_busy: busy().to_string(), aria_label: console_message(locale, "join-applications"),
            if !guided {
            div { class: "panel-head",
                div {
                    h2 { {console_text(locale, "确认设备", "Confirm device")} }
                    p { class: "muted",
                        {
                            console_text(
                                locale,
                                "在新设备使用邀请后，它会出现在这里。推荐方式需要核对身份并批准一次。",
                                "After the invitation is used on the new device, it appears here. The recommended mode requires one identity check and approval.",
                            )
                        }
                    }
                }
                button {
                    r#type: "button",
                    class: "secondary-button",
                    disabled: !ready || busy(),
                    onclick: move |_| operate.call(JoinReviewOperation::Load(None)),
                    {
                        if busy() {
                            console_text(locale, "正在检查…", "Checking…")
                        } else {
                            console_text(locale, "检查连接", "Check connection")
                        }
                    }
                }
            }
            }
            if !error().is_empty() {
                p { role: "alert", class: "error", "{error}" }
            }
            if busy() && current.is_none() {
                p { role: "status", {console_text(locale, "正在读取设备加入状态…", "Reading enrollment status…")} }
            }
            if !error().is_empty() && current.is_some() {
                p { class: "warning-note", {console_text(locale, "下方保留上次结果。请检查连接以获取最新状态后再操作。", "The last result is retained below. Check connection for current status before acting.")} }
            }
            if let Some(peer_id) = completed_peer {
                EnrollmentComplete { mesh: mesh.clone(), peer_id, locale, can_write }
            } else if let Some(_value) = ticket().filter(|value| matches!(value.status.as_str(), "expired" | "cancelled" | "rejected")) {
                p { role: "status", class: "info-note",
                    {console_text(locale, "此邀请已结束。请生成新邀请，再在设备上加入。", "This invitation has ended. Create another invitation and join again on the device.")}
                }
            } else if !busy() && error().is_empty() && applications().is_empty() && current.is_none() {
                div { class: "waiting-state",
                    span { class: "waiting-state-icon", "↻" }
                    div {
                        strong { {console_text(locale, "正在等待新设备", "Waiting for the new device")} }
                        p {
                            {
                                console_text(
                                    locale,
                                    "先在新设备完成扫码或命令，然后点击“检查连接”。邀请过期时重新生成即可，不会影响其他设备。",
                                    "Finish the QR or command step on the new device, then choose Check connection. If the invitation expires, create a new one; other devices are unaffected.",
                                )
                            }
                        }
                    }
                }
            }
            if guided && completed_peer.is_none() && current_read() && !ended && error().is_empty() {
                ol { class:"enrollment-checklist", aria_label:console_text(locale,"设备接入进度","Enrollment progress"),
                    li { span { class:"done", "✓" } div { strong { {console_text(locale,"一次性加入凭据已创建","One-time invitation created")} } small { {console_text(locale,"邀请只用于首次接入","For initial enrollment only")} } } }
                    li { span { class:if current.is_some() {"done"} else {"current"}, if current.is_some() {"✓"} else {"2"} } div { strong { {console_text(locale,"新设备提交自己的设备密钥","Device submits its own public key")} } small { {if current.is_some() {console_text(locale,"已收到设备身份，请核对下方申请","Identity received; review the application below")} else {console_text(locale,"等待设备连接","Waiting for the device")}} } } }
                    li { span {"3"} div { strong { {console_text(locale,"签发设备身份","Issue the device identity")} } small { {console_text(locale,"通过真实身份核对后完成","Completes after identity verification")} } } }
                }
            }
            if completed_peer.is_none() {
            if let Some(entry) = current.clone() {
                if entry.status == peerward_management::JoinApplicationStatus::Pending {
                    div { class: "workflow-state current",
                        span { "3" }
                        div {
                            strong { {console_text(locale, "设备已提交申请，等待你确认", "Device submitted a request; confirmation is required")} }
                            p {
                                {
                                    console_text(
                                        locale,
                                        "请在新设备上查看身份指纹，与下方值逐字核对。只有一致时才批准。",
                                        "Read the identity fingerprint on the new device and compare it character by character with the value below. Approve only when they match.",
                                    )
                                }
                            }
                        }
                    }
                    dl { class: "resource-details enrollment-identity",
                        div { class: "resource-detail",
                            dt { {console_text(locale, "设备名称", "Device name")} }
                            dd { "{entry.name}" }
                        }
                        div { class: "resource-detail identity-fingerprint",
                            dt { {console_message(locale, "invitation-fingerprint")} }
                            dd { code { "{entry.identity_fingerprint}" } }
                        }
                        div { class: "resource-detail",
                            dt { {console_text(locale, "最晚确认时间", "Approval deadline")} }
                            dd { LocalDateTime { value: join_deadline(entry.expires_at), locale } }
                        }
                    }
                    if can_write {
                        label { r#for: "join-confirm-fingerprint",
                            {console_text(locale, "输入你在设备上核对到的完整指纹", "Enter the full fingerprint verified on the device")}
                        }
                        input {
                            id: "join-confirm-fingerprint",
                            value: fingerprint,
                            disabled: busy() || !current_read(),
                            oninput: move |event| fingerprint.set(event.value()),
                            spellcheck: "false",
                            autocomplete: "off",
                            placeholder: console_text(locale, "粘贴或输入完整指纹", "Paste or enter the full fingerprint"),
                        }
                        p { class: "muted",
                            {
                                console_text(
                                    locale,
                                    "这个确认防止误批准另一台设备。不要只根据控制台里显示的值直接复制后批准。",
                                    "This check prevents approving the wrong device. Do not approve by merely copying the value shown by the console.",
                                )
                            }
                        }
                        div { class: "actions",
                            button {
                                r#type: "button",
                                disabled: !can_approve,
                                onclick: move |_| operate.call(JoinReviewOperation::Approve),
                                {console_text(locale, "身份一致，批准设备", "Identity matches — approve device")}
                            }
                            button {
                                r#type: "button",
                                class: "danger-button",
                                disabled: !can_decide,
                                onclick: move |_| operate.call(JoinReviewOperation::Reject),
                                {console_text(locale, "不是这台设备", "This is not the device")}
                            }
                        }
                    } else {
                        p { class: "info-note",
                            {console_text(locale, "当前账号只能查看申请，需要设备管理权限才能批准。", "This account can review the application but device management permission is required to approve it.")}
                        }
                    }
                } else {
                    div { class: "info-note",
                        strong { {join_review_status(locale, entry.status)} }
                        p {
                            {
                                console_text(
                                    locale,
                                    "这个申请已经结束。如果仍要加入这台设备，请重新生成一次性邀请。",
                                    "This application has ended. Create a new one-time invitation if this device still needs to join.",
                                )
                            }
                        }
                    }
                }
            }
            }
            if guided {
                div { class:"actions sharing-wizard-footer",
                    SharingWizardCancel { locale, busy:submitting(), on_cancel }
                    if completed_peer.is_none() || !error().is_empty() {
                        if completed_peer.is_none() && ticket_id.is_some() {
                            button { r#type:"button", class:"secondary-button", disabled:submitting(), onclick:move |_| on_back.call(()), {console_text(locale,"上一步","Back")} }
                        }
                        button { r#type:"button", disabled:!ready || busy(), onclick:move |_| operate.call(JoinReviewOperation::Load(None)),
                            {if busy() {console_text(locale,"正在检查…","Checking…")} else {console_text(locale,"检查连接","Check connection")}}
                        }
                    }
                    if can_write && (completed_peer.is_some() || ended) {
                        button { r#type:"button", class:"secondary-button", "data-console-dismiss":"true", disabled:submitting(), onclick:move |_| on_restart.call(()), {console_text(locale,"邀请下一台设备","Invite another device")} }
                    }
                }
            }
            if ticket_id.is_none() && requested_application.is_none() && !applications().is_empty() {
                details { class: "advanced-tools enrollment-history",
                    summary {
                        strong { {console_text(locale, "其他加入申请与历史", "Other join applications and history")} }
                        small { {format!("{}", applications().len())} }
                    }
                    label { r#for: "join-review-search",
                        {console_text(locale, "查找申请", "Find an application")}
                    }
                    input {
                        id: "join-review-search",
                        value: query,
                        oninput: move |event| query.set(event.value()),
                        placeholder: console_text(locale, "按设备名称搜索", "Search by device name"),
                    }
                    ul { class: "plain-list enrollment-history-list",
                        for entry in applications()
                            .into_iter()
                            .filter(|entry| entry.name.to_lowercase().contains(&search))
                        {
                            li { key: "{entry.id}",
                                button {
                                    r#type: "button",
                                    class: "quiet-button",
                                    "data-console-dismiss": "true",
                                    disabled: !ready || busy(),
                                    onclick: move |_| {
                                        selected.set(Some(entry.clone()));
                                        fingerprint.set(String::new());
                                    },
                                    strong { "{entry.name}" }
                                    span { {join_review_status(locale, entry.status)} }
                                }
                            }
                        }
                    }
                    if let Some(cursor) = next() {
                        button {
                            r#type: "button",
                            class: "secondary-button",
                            disabled: !ready || busy(),
                            onclick: move |_| operate.call(JoinReviewOperation::Load(Some(cursor.clone()))),
                            {console_message(locale, "join-review-next")}
                        }
                    }
                }
            }
        }
    }
}

fn join_review_status(
    locale: Locale,
    status: peerward_management::JoinApplicationStatus,
) -> &'static str {
    use peerward_management::JoinApplicationStatus as S;
    console_message(
        locale,
        match status {
            S::Pending => "join-review-pending",
            S::Approved => "join-review-approved",
            S::Rejected => "join-review-rejected",
            S::Cancelled => "join-review-cancelled",
            S::Expired => "join-review-expired",
        },
    )
}

fn join_deadline(value: u64) -> String {
    i64::try_from(value)
        .ok()
        .and_then(|value| time::OffsetDateTime::from_unix_timestamp(value).ok())
        .and_then(|value| {
            value
                .format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "unknown".into())
}
