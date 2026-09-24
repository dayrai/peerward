#[component]
#[allow(unused_mut, unused_variables)]
fn ConsoleInvitation(
    mesh: String,
    locale: Locale,
    csrf: Option<String>,
    can_write: bool,
    requested_resource: String,
    on_cancel: EventHandler<()>,
) -> Element {
    let mut name = use_signal(String::new);
    let mut review_busy = use_signal(|| false);
    let mut progress = use_signal(|| 1_u8);
    // Keep the first browser render identical to SSR, which has no detail query.
    let mut requested = use_signal(|| None::<uuid::Uuid>);
    use_effect(use_reactive((&requested_resource,), move |(resource,)| {
        requested.set(resource.parse().ok());
        if !resource.is_empty() {
            progress.set(3);
        }
    }));
    let requested_application = requested();
    let mut groups = use_signal(std::collections::BTreeSet::<uuid::Uuid>::new);
    let mut platform = use_signal(|| peerward_management::EnrollmentPlatform::Linux);
    let mut link = use_signal(String::new);
    let mut ticket_id = use_signal(|| None::<uuid::Uuid>);
    let mut ready = use_signal(|| false);
    use_effect(move || ready.set(true));
    let mut expiry = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut active_mesh = use_signal(|| mesh.clone());
    let mut generation = use_signal(|| 0_u64);
    use_effect(use_reactive((&mesh,), move |(mesh,)| {
        if *active_mesh.peek() != mesh {
            active_mesh.set(mesh);
            let next = generation.peek().wrapping_add(1);
            generation.set(next);
            name.set(String::new());
            groups.set(std::collections::BTreeSet::new());
            platform.set(peerward_management::EnrollmentPlatform::Linux);
            link.set(String::new());
            ticket_id.set(None);
            expiry.set(String::new());
            busy.set(false);
            error.set(String::new());
            progress.set(1);
            review_busy.set(false);
        }
    }));
    let restart = use_callback(move |()| {
        link.set(String::new());
        ticket_id.set(None);
        requested.set(None);
        name.set(String::new());
        groups.set(std::collections::BTreeSet::new());
        platform.set(peerward_management::EnrollmentPlatform::Linux);
        error.set(String::new());
        progress.set(1);
    });
    let create_mesh = mesh.clone();
    let create_csrf = csrf.clone();
    let dirty = link().is_empty()
        && (!name().is_empty()
            || !groups().is_empty()
            || platform() != peerward_management::EnrollmentPlatform::Linux);
    let name_valid = peerward_management::JoinSettings {
        display_name: name().trim().to_owned(),
        ..Default::default()
    }
    .validate()
    .is_ok();
    rsx! {
        div { class: "sharing-wizard enrollment-workflow",
            EnrollmentProgress { locale, step: progress() }
            if !can_write {
                p { class: "info-note",
                    {
                        console_text(
                            locale,
                            "当前账号可以查看加入申请，但没有创建设备邀请的权限。",
                            "This account can review join applications but cannot create device invitations.",
                        )
                    }
                }
            } else if mesh.is_empty() {
                p {
                    {
                        console_text(
                            locale,
                            "请先创建或选择网络。",
                            "Create or select a network first.",
                        )
                    }
                }
            } else if progress() == 1 && requested_application.is_none() {
                form {
                    class: "console-form enrollment-create-form",
                    id: "enrollment-create",
                    "data-console-dirty": dirty.to_string(),
                    aria_busy: busy().to_string(), "data-console-submitting": busy().to_string(),
                    onsubmit: move |e| {
                        e.prevent_default();
                        if ticket_id().is_some() { progress.set(2); } else {
                        #[cfg(target_arch = "wasm32")]
                        {
                            if busy() || !can_write || create_mesh.is_empty() {
                                return;
                            }
                            let display_name = name.peek().trim().to_owned();
                            let display_name = if display_name.is_empty() { console_text(locale, "新设备", "New device").to_owned() } else { display_name };
                            let mesh = create_mesh.clone();
                            let request_generation = generation();
                            let csrf = create_csrf.clone();
                            let body = peerward_api::JoinTicketCreateRequest {
                                expires_in_seconds: 15 * 60,
                                settings: peerward_management::JoinSettings {
                                    display_name: display_name.clone(),
                                    device_groups: groups(),
                                    platform_hint: Some(platform()),
                                    mode: peerward_management::JoinMode::Approval,
                                    ..Default::default()
                                },
                            };
                            if body.settings.validate().is_err() {
                                return;
                            }
                            name.set(display_name);
                            busy.set(true);
                            error.set(String::new());
                            spawn(async move {
                                let api = browser_api_client().with_csrf(csrf.unwrap_or_default());
                                let result = api.create_join_ticket(&mesh, &body).await;
                                if *active_mesh.peek() != mesh || generation() != request_generation { return; }
                                match result {
                                    Ok(ticket) => {
                                        expiry.set(ticket.expires_at.clone());
                                        ticket_id.set(Some(ticket.id));
                                        match api.join_link(&ticket) {
                                            Ok(value) => { link.set(value); progress.set(2); },
                                            Err(e) => error.set(console_api_error(locale, e)),
                                        }
                                    }
                                    Err(e) => error.set(console_api_error(locale, e)),
                                }
                                busy.set(false);
                            });
                        }
                        }
                    },
                    if ticket_id().is_some() {
                        p { class: "info-note", {console_text(locale, "这份邀请已签发，设置已固定。下一步可继续使用原邀请。", "This invitation has been issued with fixed settings. Continue to use the same invitation.")} }
                    }
                    div { class: "workflow-note",
                        strong { {console_text(locale, "先告诉 Peerward 这是什么设备", "Tell Peerward about this device")} }
                        p { {console_text(locale, "这里只创建管理记录，不会立即改变新设备上的任何设置。", "This only creates an enrollment record; it does not change any settings on the new device.")} }
                    }
                    label { r#for: "invite-device-name", {console_text(locale, "设备名称", "Device name")} }
                    input {
                        id: "invite-device-name", value: name,
                        disabled: busy() || ticket_id().is_some(), autocomplete: "off",
                        aria_invalid: (!name_valid).to_string(),
                        aria_describedby: if name_valid {None} else {Some("invite-name-error")},
                        maxlength: 128,
                        placeholder: console_text(locale, "例如：小明的笔记本", "For example: Alex's laptop"),
                        oninput: move |e| { name.set(e.value()); error.set(String::new()); },
                    }
                    if !name_valid {
                        p { id: "invite-name-error", class: "error", role: "alert",
                            {console_text(locale, "设备名称最多 128 个字符，不能包含控制字符。", "Use at most 128 characters without control characters for the device name.")}
                        }
                    }
                    div { class: "enrollment-platform-field",
                        div {
                            label { r#for: "invite-device-platform", {console_text(locale, "设备平台", "Device platform")} }
                            select { id: "invite-device-platform",
                                value: if platform() == peerward_management::EnrollmentPlatform::Android {"android"} else {"linux"},
                                disabled: busy() || ticket_id().is_some(),
                                onchange: move |e| {
                                    if let Ok(value) = serde_json::from_value(Value::String(e.value())) { platform.set(value); }
                                    error.set(String::new());
                                },
                                option { value: "linux", "Linux" }
                                option { value: "android", "Android" }
                            }
                        }
                    }
                    EnrollmentGroups { key: "{mesh}", mesh: mesh.clone(), locale, selected: groups, disabled: busy() || ticket_id().is_some() }
                    div { class: "actions sharing-wizard-footer",
                        SharingWizardCancel { locale, busy: busy(), on_cancel }
                        button { r#type: "submit", disabled: busy() || !name_valid,
                            {if busy() { console_text(locale, "正在生成…", "Creating…") }
                             else { console_text(locale, "下一步", "Next") }}
                        }
                    }
                }
            }
            if ticket_id().is_some() && progress() == 2 {
                EnrollmentConnect { link: link(), expiry: expiry(), name: name(), platform: platform(), locale }
                details { class:"enrollment-restart",
                    summary { {console_text(locale,"需要修改邀请设置？","Need different invitation settings?")} }
                    p { class:"muted", {console_text(locale,"重新邀请不会自动取消原邀请；不用的邀请可在邀请记录中取消。","Starting over does not cancel the old invitation; cancel unused invitations in invitation history.")} }
                    button { r#type:"button", class:"secondary-button", "data-console-dismiss":"true", disabled:review_busy(), onclick:move |_| restart.call(()), {console_text(locale,"邀请下一台设备","Invite another device")} }
                }
            }
            if ticket_id().is_some() || requested_application.is_some() || !can_write {
                div { hidden: progress() < 3 && can_write,
                    JoinApplicationPanel {
                        key: "{mesh}:{ticket_id():?}:{requested_application:?}", requested_application,
                        mesh: mesh.clone(), csrf: csrf.clone(), can_write, locale, ready: ready(), ticket_id: ticket_id(),
                        on_progress: move |value| { if value == 4 { progress.set(4); } },
                        on_submitting: move |value| review_busy.set(value), guided:true,
                        on_back:move |()| progress.set(2), on_restart:restart, on_cancel,
                    }
                }
                if progress() == 2 {
                div { class: "actions sharing-wizard-footer",
                    SharingWizardCancel { locale, busy: review_busy(), on_cancel }
                    if progress() == 2 {
                        button { class: "secondary-button", r#type: "button", disabled: review_busy(),
                            onclick: move |_| progress.set(1),
                            {console_text(locale, "上一步", "Back")}
                        }
                        button { r#type: "button", disabled: review_busy(), onclick: move |_| progress.set(3),
                            {console_text(locale, "我已在设备上操作", "I've used the invitation")}
                        }
                    }
                }
            }
            }
            if requested_application.is_some() {
                a { class: "secondary-link", href: format!("/join-tickets?mesh={mesh}"),
                    {console_text(locale, "返回添加设备", "Back to adding devices")}
                }
            }
            if !error().is_empty() {
                p { role: "alert", "{error}" }
            }
        }
    }
}
