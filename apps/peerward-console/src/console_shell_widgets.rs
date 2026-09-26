fn console_page_description(locale: Locale, route: ConsoleRoute) -> &'static str {
    match route {
        ConsoleRoute::Overview => console_text(
            locale,
            "先看今天需要你处理的事；没有异常时，其余状态保持安静。",
            "Start with what needs your attention today; otherwise, keep routine status quiet.",
        ),
        ConsoleRoute::Peers => console_text(
            locale,
            "查看设备是否在线、谁在使用，以及它可以访问哪些共享。",
            "See device connection status, recent activity and share access.",
        ),
        ConsoleRoute::Services => console_text(
            locale,
            "统一管理设备服务、局域网资源和互联网出口。",
            "Manage device services, LAN resources and internet exits together.",
        ),
        ConsoleRoute::Policy => console_text(
            locale,
            "查看设备或设备组可以使用哪些共享，并按需调整授权。没有明确允许的访问默认阻止。",
            "Review which shares a device or group can use and adjust grants. Access without an explicit allow is blocked by default.",
        ),
        ConsoleRoute::Operations => console_text(
            locale,
            "先处理当前网络的问题；部署、备份和中继服务维护放在系统工具中。",
            "Resolve this network first; deployment, backups and relay-service maintenance live under System tools.",
        ),
        ConsoleRoute::Audit => console_text(
            locale,
            "按真实记录回溯配置变更和操作结果。",
            "Review recorded configuration changes and operation results.",
        ),
        ConsoleRoute::Networks => console_text(
            locale,
            "查看并切换你管理的网络。每个网络的设备、共享和访问设置彼此独立。",
            "View and switch networks. Devices, sharing and access settings are isolated in each network.",
        ),
        ConsoleRoute::Meshes => console_text(
            locale,
            "管理网络名称、设备要求和基础功能。高级配置默认折叠。",
            "Manage network identity, device requirements and features. Advanced settings are collapsed by default.",
        ),
        ConsoleRoute::JoinTickets => console_text(
            locale,
            "生成一次性邀请，核对加入申请，再确认设备上线。",
            "Create a one-time invitation, review enrollment requests and confirm the device comes online.",
        ),
        ConsoleRoute::Relays => console_text(
            locale,
            "管理安装级中继服务、容量、维护、备份和升级；这些能力可被多个网络共用。",
            "Manage installation-level relay services, capacity, maintenance, backups and upgrades shared across networks.",
        ),
        ConsoleRoute::Authorities => console_text(
            locale,
            "管理网络信任、签发机构和自动化凭证。",
            "Manage network trust, signing authorities and automation credentials.",
        ),
        ConsoleRoute::Webhooks => console_text(
            locale,
            "配置事件通知，检查投递结果，并管理配置归属。",
            "Configure event notifications, review delivery results and manage configuration ownership.",
        ),
    }
}

fn console_search_kind_label(locale: Locale, kind: &str) -> &'static str {
    match kind {
        "device" => console_text(locale, "设备", "Device"),
        "group" => console_text(locale, "设备组", "Device group"),
        "mesh" => console_text(locale, "网络", "Network"),
        "service" | "subnet" | "internet" | "lan" => console_text(locale, "共享", "Share"),
        _ => console_text(locale, "项目", "Item"),
    }
}

#[component]
fn ConsoleOverlay(
    title: &'static str,
    on_close: EventHandler<()>,
    children: Element,
    #[props(default)] wide: bool,
    #[props(default)] device: bool,
    #[props(default)] wizard: bool,
    #[props(default)] wizard_label: String,
    #[props(default)] heading: String,
) -> Element {
    rsx! {
        div { class: if wizard { "overlay-backdrop sharing-wizard-backdrop" } else if device { "overlay-backdrop device-detail-backdrop" } else { "overlay-backdrop" }, onclick: move |_| on_close.call(()),
            section {
                class: if wizard { "console-drawer sharing-wizard-modal" } else if device { "console-drawer device-detail-drawer" } else if wide { "console-drawer console-drawer--wide" } else { "console-drawer" },
                role: "dialog",
                aria_modal: "true",
                aria_label: title,
                "data-console-overlay-root": "true",
                tabindex: "-1",
                onclick: move |e| e.stop_propagation(),
                onkeydown: move |e| {
                    if e.key() == Key::Escape {
                        on_close.call(());
                    }
                },
                header { class: "drawer-head",
                    if wizard {
                        div {
                            div { class: "eyebrow", "{wizard_label}" }
                            h2 { "{title}" }
                        }
                    } else if heading.is_empty() {
                        h2 { "{title}" }
                    } else {
                        div {
                            div { class: "eyebrow", "{title}" }
                            h2 { "{heading}" }
                        }
                    }
                    button {
                        class: "icon-button",
                        aria_label: "Close / 关闭",
                        onclick: move |_| on_close.call(()),
                        "×"
                    }
                }
                div { class: "drawer-body", {children} }
            }
        }
    }
}
#[component]
fn SessionLockButton(csrf: Option<String>, locale: Locale) -> Element {
    #[allow(unused_mut)]
    let mut error = use_signal(String::new);
    #[allow(unused_mut)]
    let mut busy = use_signal(|| false);
    rsx! {
        button {
            class: "secondary-button",
            disabled: busy(),
            onclick: move |_| {
                #[cfg(target_arch = "wasm32")]
                {
                    let csrf = csrf.clone();
                    busy.set(true);
                    spawn(async move {
                        let api = browser_api_client().with_csrf(csrf.unwrap_or_default());
                        match api.logout().await {
                            Ok(_) => {
                                if let Some(w) = web_sys::window() {
                                    let return_to = format!(
                                        "{}{}",
                                        w.location().pathname().unwrap_or_else(|_| "/".into()),
                                        w.location().search().unwrap_or_default(),
                                    );
                                    let mut query = url::form_urlencoded::Serializer::new(
                                        String::new(),
                                    );
                                    query.append_pair("return_to", &return_to);
                                    let _ = w
                                        .location()
                                        .replace(&format!("/locked?{}", query.finish()));
                                }
                            }
                            Err(e) => {
                                error.set(console_api_error(locale, e));
                                busy.set(false);
                            }
                        }
                    });
                }
            },
            {console_text(locale, "锁定控制台", "Lock console")}
        }
        if !error().is_empty() {
            p { role: "alert", "{error}" }
        }
    }
}
#[component]
fn ConsoleSearchDialog(mesh: String, locale: Locale, on_close: EventHandler<()>) -> Element {
    let mut query = use_signal(String::new);
    let mut all = use_signal(|| false);
    let path = if query().trim().is_empty() {
        String::new()
    } else {
        let mut params = url::form_urlencoded::Serializer::new(String::new());
        params
            .append_pair("q", query().trim())
            .append_pair("limit", "30");
        if !all() && !mesh.is_empty() {
            params.append_pair("mesh", &mesh);
        }
        format!("/api/v1/console/search?{}", params.finish())
    };
    let results = use_console_query::<Page<peerward_api::ConsoleSearchItem>>(path);
    rsx! {
        ConsoleOverlay {
            title: console_text(locale, "全局搜索", "Global search"),
            on_close,
            label { r#for: "console-search-query",
                {
                    console_text(
                        locale,
                        "设备、共享或网络名称",
                        "Device, share or network name",
                    )
                }
            }
            input {
                id: "console-search-query",
                autofocus: true,
                value: query,
                oninput: move | e
                        | query.set(e.value()),
            }
            label { class: "inline-check",
                input {
                    r#type: "checkbox",
                    checked: all(),
                    onchange: move |e| all.set(e.checked()),
                }
                {console_text(locale, "搜索所有网络", "Search all networks")}
            }
            if let Some(Ok(page)) = results.read().as_ref() {
                if page.items.is_empty() {
                    p { class: "empty",
                        {console_text(locale, "没有找到匹配项", "No matches found")}
                    }
                }
                for item in &page.items {
                    a { class: "search-result", href: item.href
                                .clone(),
                        strong { "{item.name}" }
                        small { "{item.mesh_name} · " {console_search_kind_label(locale, &item.kind)} }
                    }
                }
                if page.next_cursor.is_some() {
                    p { class: "muted",
                        {
                            console_text(
                                locale,
                                "结果较多，请输入更具体的关键词。",
                                "Refine your search to see more specific results.",
                            )
                        }
                    }
                }
            } else if let Some(Err(error)) = results.read().as_ref() {
                if !error.is_empty() {
                    p { role: "alert", "{error}" }
                }
            }
        }
    }
}

fn console_session_role(locale: Locale, role: &str) -> &str {
    match role {
        "admin" => console_text(locale, "管理员", "Administrator"),
        "operator" => console_text(locale, "操作员", "Operator"),
        "viewer" => console_text(locale, "只读用户", "Viewer"),
        "auditor" => console_text(locale, "审计员", "Auditor"),
        "" => console_message(locale, "sign-in"),
        value => value,
    }
}
