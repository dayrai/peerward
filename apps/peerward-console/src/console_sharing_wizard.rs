#[component]
#[allow(unused_mut, unused_variables)]
fn ConsoleSharingWizard(
    mesh: String,
    locale: Locale,
    csrf: Option<String>,
    can_write: bool,
    on_change: EventHandler<()>,
    on_cancel: EventHandler<()>,
) -> Element {
    let request = use_signal(uuid::Uuid::new_v4);
    let mut kind = use_signal(|| "service".to_owned());
    let mut name = use_signal(String::new);
    let mut provider = use_signal(String::new);
    let mut provider_query = use_signal(String::new);
    let mut source = use_signal(String::new);
    let mut source_query = use_signal(String::new);
    let mut prefix = use_signal(String::new);
    let mut site = use_signal(|| uuid::Uuid::new_v4().to_string());
    let mut protocol = use_signal(|| "tcp".to_owned());
    let mut port = use_signal(|| "445".to_owned());
    let mut port_edited = use_signal(|| false);
    let mut more_settings = use_signal(|| false);
    let mut ipv6 = use_signal(|| false);
    let mut dns = use_signal(String::new);
    let mut dns_address = use_signal(String::new);
    let mut reason = use_signal(String::new);
    let mut preview = use_signal(|| None::<peerward_api::ConsoleSharingPreview>);
    let mut staged = use_signal(|| None::<peerward_api::ConsoleSharingDraft>);
    let mut busy = use_signal(|| false);
    let mut message = use_signal(String::new);
    let mut complete = use_signal(|| false);
    let mut created_resource = use_signal(uuid::Uuid::nil);
    let mut gateway_confirmed = use_signal(|| false);
    let initial_site = use_signal(|| site.peek().clone());
    let mut step = use_signal(|| 1_u8);
    let mut provider_cursor = use_signal(String::new);
    let mut source_cursor = use_signal(String::new);
    let mut providers_params = url::form_urlencoded::Serializer::new(String::new());
    providers_params
        .append_pair("limit", "50")
        .append_pair("q", &provider_query());
    if !provider_cursor().is_empty() {
        providers_params.append_pair("cursor", &provider_cursor());
    }
    let providers = use_console_query::<peerward_api::ConsoleDevicePage>(format!(
        "/api/v1/meshes/{mesh}/console/devices?{}",
        providers_params.finish()
    ));
    let mut sources_params = url::form_urlencoded::Serializer::new(String::new());
    sources_params
        .append_pair("limit", "50")
        .append_pair("q", &source_query());
    if !source_cursor().is_empty() {
        sources_params.append_pair("cursor", &source_cursor());
    }
    let sources = use_console_query::<peerward_api::ConsoleDevicePage>(format!(
        "/api/v1/meshes/{mesh}/console/devices?{}",
        sources_params.finish()
    ));
    let mut group_cursor = use_signal(String::new);
    let mut group_query = url::form_urlencoded::Serializer::new(String::new());
    group_query
        .append_pair("mesh", &mesh)
        .append_pair("kind", "group")
        .append_pair("limit", "50")
        .append_pair("q", &source_query());
    if !group_cursor().is_empty() {
        group_query.append_pair("cursor", &group_cursor());
    }
    let groups = use_console_query::<Page<peerward_api::ConsoleSearchItem>>(format!(
        "/api/v1/console/search?{}",
        group_query.finish()
    ));
    let create_mesh = mesh.clone();
    let commit_mesh = mesh.clone();
    let create_csrf = csrf.clone();
    let dirty = !complete() && (
        !name().is_empty() || !provider().is_empty() || !provider_query().is_empty()
        || !source().is_empty() || !source_query().is_empty() || kind() != "service"
        || !prefix().is_empty() || site() != initial_site() || protocol() != "tcp" || port() != "445" || ipv6()
        || !dns().is_empty() || !dns_address().is_empty() || !reason().is_empty()
    );
    rsx! {
        div { class: "sharing-wizard", "data-console-dirty": dirty.to_string(), aria_busy: busy().to_string(), "data-console-submitting": busy().to_string(),
            SharingWizardProgress { locale, step: if preview().is_some() || complete() { 4 } else { step() }, complete: complete() }
            if complete() {
                div { class: "success-note sharing-created", role: "status",
                    h3 { {console_text(locale, "共享已创建", "Sharing created")} }
                    p {
                        {
                            console_text(
                                locale,
                                "共享设置已经保存。连接路径和可达性仍以设备实际观测为准；如果刚创建，短时间显示“等待应用”是正常的。",
                                "The sharing settings are saved. Path and reachability still depend on device observations; a brief Pending state is normal immediately after creation.",
                            )
                        }
                    }
                }
                div { class: "next-actions",
                    a {
                        class: "primary-link",
                        href: format!("/services?mesh={mesh}&resource={}", created_resource()),
                        {console_text(locale, "查看共享状态", "View sharing status")}
                    }
                    a {
                        class: "secondary-link",
                        href: sharing_access_href(&mesh, created_resource(), &source()),
                        {console_text(locale, "继续检查访问", "Continue to access review")}
                    }
                }
            } else if let Some(review) = preview() {
                if let Some(draft) = staged() {
                    ConsoleSharingReview {
                        draft, review: review.clone(), locale,
                        protocol_label: if protocol() == "both" { "TCP + UDP".into() } else { protocol().to_ascii_uppercase() },
                        provider_name: providers.read().as_ref().and_then(|r| r.as_ref().ok()).and_then(|p| p.items.iter().find(|p| p.id.to_string() == provider())).map_or_else(|| provider.peek().clone(), |p| if p.display_name.is_empty() { p.name.clone() } else { p.display_name.clone() }),
                        source_name: sources.read().as_ref().and_then(|r| r.as_ref().ok()).and_then(|p| p.items.iter().find(|p| format!("peer:{}", p.id) == source())).map(|p| if p.display_name.is_empty() { p.name.clone() } else { p.display_name.clone() })
                            .or_else(|| groups.read().as_ref().and_then(|r| r.as_ref().ok()).and_then(|p| p.items.iter().find(|p| format!("group:{}", p.id) == source())).map(|p| p.name.clone())).unwrap_or_else(|| source.peek().clone()),
                    }
                }
                if kind() != "service" {
                    label { class: "checkbox-row",
                        input { id: "share-gateway-approval", r#type: "checkbox", checked: gateway_confirmed(), disabled: busy(), onchange: move |e| gateway_confirmed.set(e.checked()) }
                        {console_text(locale, "我确认批准所选网关提供此目标的转发路径", "I approve the selected gateway to forward traffic to this target")}
                    }
                }
                div { class: "actions sharing-wizard-footer",
                    SharingWizardCancel { locale, busy: busy(), on_cancel }
                    button {
                        class: "secondary-button",
                        disabled: busy(),
                        onclick: move |_| { preview.set(None); gateway_confirmed.set(false); message.set(String::new()); step.set(3); },
                        {console_text(locale, "上一步", "Back")}
                    }
                    button {
                        disabled: busy() || !can_write || (kind() != "service" && !gateway_confirmed()),
                        onclick: move |_| {
                            #[cfg(target_arch = "wasm32")]
                            {
                                if busy() || !can_write || (kind() != "service" && !gateway_confirmed()) { return; }
                                let Some(draft) = staged() else { return };
                                let mesh = commit_mesh.clone();
                                let csrf = csrf.clone();
                                let review = review.clone();
                                busy.set(true);
                                message.set(String::new());
                                spawn(async move {
                                    let result: Result<
                                        peerward_api::ConsoleSharingPreview,
                                        ConsoleApiError,
                                    > = browser_api_client()
                                        .with_csrf(csrf.unwrap_or_default())
                                        .conditional_request(
                                            Method::POST,
                                            &format!("/api/v1/meshes/{mesh}/console/sharing/apply"),
                                            Some(
                                                json!(
                                                    peerward_api::ConsoleSharingApply { draft, preview_digest :
                                                    review.digest }
                                                ),
                                            ),
                                            review.version,
                                        )
                                        .await;
                                    match result {
                                        Ok(applied) => {
                                            created_resource.set(applied.resource_id);
                                            complete.set(true);
                                            on_change.call(());
                                        }
                                        Err(e) => message.set(console_api_error(locale, e)),
                                    }
                                    busy.set(false);
                                });
                            }
                        },
                        if busy() {
                            {console_text(locale, "正在创建…", "Creating…")}
                        } else {
                            {console_text(locale, "创建共享", "Create share")}
                        }
                    }
                }
            } else {
                form {
                    class: "console-form",
                    onsubmit: move |event| {
                        event.prevent_default();
                        if busy() || !can_write { return; }
                        message.set(String::new());
                        if step() == 1 { step.set(2); return; }
                        let draft = build_sharing_draft(
                            request(),
                            name(),
                            provider(),
                            kind(),
                            protocol(),
                            port(),
                            prefix(),
                            site(),
                            ipv6(),
                            dns(),
                            dns_address(),
                            source(),
                            reason(),
                        );
                        match draft {
                            Err(e) => message.set(e),
                            Ok(draft) => {
                                if step() == 2 { step.set(3); return; }
                                #[cfg(target_arch = "wasm32")] {
                                let mesh = create_mesh.clone();
                                let csrf = create_csrf.clone();
                                busy.set(true);
                                staged.set(Some(draft.clone()));
                                spawn(async move {
                                    let result: Result<
                                        peerward_api::ConsoleSharingPreview,
                                        ConsoleApiError,
                                    > = browser_api_client()
                                        .with_csrf(csrf.unwrap_or_default())
                                        .request(
                                            Method::POST,
                                            &format!("/api/v1/meshes/{mesh}/console/sharing/preview"),
                                            Some(json!(draft)),
                                        )
                                        .await;
                                    match result {
                                        Ok(p) => { gateway_confirmed.set(false); preview.set(Some(p)); },
                                        Err(e) => message.set(console_api_error(locale, e)),
                                    }
                                    busy.set(false);
                                });
                                }
                                #[cfg(not(target_arch = "wasm32"))] let _ = draft;
                            }
                        }
                    },
                    if step() == 1 {
                        SharingKindChoices {
                            locale, kind: kind(), disabled: busy() || !can_write,
                            on_select: move |value: String| {
                                if kind() != value {
                                    kind.set(value.clone());
                                    protocol.set(if value == "internet" { "all" } else { "tcp" }.into());
                                    port.set(if value == "lan" { "631" } else { "445" }.into());
                                    port_edited.set(false);
                                    dns.set(String::new());
                                    dns_address.set(String::new());
                                }
                            },
                        }
                        div { class: "actions sharing-wizard-footer",
                            SharingWizardCancel { locale, busy: busy(), on_cancel }
                            button { r#type: "submit", disabled: busy() || !can_write,
                                {console_text(locale, "下一步", "Next")}
                            }
                        }
                    } else if step() == 2 {
                        SharingDetailsFields {
                            locale, kind: kind(), name, provider, provider_query, provider_cursor,
                            providers, protocol, port, port_edited, prefix, site, ipv6, dns, dns_address, reason,
                            disabled: busy() || !can_write, more_settings: kind() != "service" && more_settings(),
                        }
                        div { class: "actions sharing-wizard-footer",
                            SharingWizardCancel { locale, busy: busy(), on_cancel }
                            if kind() != "service" {
                                button { r#type: "button", class: "quiet-button sharing-more-settings", aria_expanded: more_settings().to_string(), disabled: busy(), onclick: move |_| more_settings.toggle(),
                                    if more_settings() { {console_text(locale, "收起设置", "Hide settings")} }
                                    else { {console_text(locale, "更多设置", "More settings")} }
                                }
                            }
                            button { r#type: "button", class: "secondary-button", disabled: busy(), onclick: move |_| { message.set(String::new()); step.set(1); },
                                {console_text(locale, "上一步", "Back")}
                            }
                            button { r#type: "submit", disabled: busy(),
                                {console_text(locale, "下一步", "Next")}
                            }
                        }
                    } else {
                        SharingAccessChoices {
                            locale, source, source_query, source_cursor, group_cursor,
                            sources, groups, disabled: busy() || !can_write,
                        }
                        div { class: "actions sharing-wizard-footer",
                            SharingWizardCancel { locale, busy: busy(), on_cancel }
                            button { r#type: "button", class: "secondary-button", disabled: busy(), onclick: move |_| { message.set(String::new()); step.set(2); },
                                {console_text(locale, "上一步", "Back")}
                            }
                            button { r#type: "submit", disabled: busy(),
                                if busy() { {console_text(locale, "正在检查…", "Checking…")} } else { {console_text(locale, "下一步", "Next")} }
                            }
                        }
                    }
                }
            }
            if busy() {
                p { role: "status", {console_message(locale, "loading")} }
            }
            if !message().is_empty() {
                p { role: "alert", "{message}" }
            }
        }
    }
}
