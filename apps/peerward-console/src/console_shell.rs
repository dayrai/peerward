fn console_text(locale: Locale, zh: &'static str, en: &'static str) -> &'static str {
    match locale {
        Locale::ZhCn => zh,
        Locale::EnUs => en,
    }
}
#[component]
fn ConsoleShell(
    route: ConsoleRoute,
    snapshot: ConsoleSnapshot,
    locale: Signal<Locale>,
    theme: Signal<Theme>,
    client_routing: bool,
    children: Element,
) -> Element {
    #[allow(unused_mut)]
    let mut hydrated = use_signal(|| false);
    use_effect(move || hydrated.set(true));
    // SSR omits inert=""; in the browser inert="false" still blocks input.
    // Use Some("true") before hydration and None to remove the attribute.
    let mut search_open = use_signal(|| false);
    let mut notices_open = use_signal(|| false);
    let mut mobile_open = use_signal(|| false);
    let mut mesh_query = use_signal(String::new);
    let mut mesh_cursor = use_signal(String::new);
    let mesh = snapshot.mesh_id.clone();
    use_effect(use_reactive((&mesh,), move |(_,)| {
        search_open.set(false);
        notices_open.set(false);
        mobile_open.set(false);
        mesh_query.set(String::new());
        mesh_cursor.set(String::new());
    }));
    let authenticated = !snapshot.role.is_empty();
    let can_read = snapshot.has_capability("resource_read");
    let can_write = snapshot.has_capability("resource_write");
    let can_trust = snapshot.has_capability("trust_manage");
    let show_read_only_notice = can_read
        && !can_write
        && matches!(
            route,
            ConsoleRoute::Overview
                | ConsoleRoute::Peers
                | ConsoleRoute::Services
                | ConsoleRoute::Policy
                | ConsoleRoute::Operations
                | ConsoleRoute::JoinTickets
                | ConsoleRoute::Webhooks
        );
    let mut network_query = url::form_urlencoded::Serializer::new(String::new());
    network_query
        .append_pair("kind", "mesh")
        .append_pair("limit", "20")
        .append_pair("q", &mesh_query());
    if !mesh_cursor().is_empty() {
        network_query.append_pair("cursor", &mesh_cursor());
    }
    let mut networks = use_console_query::<Page<peerward_api::ConsoleSearchItem>>(if can_read {
        format!("/api/v1/console/search?{}", network_query.finish())
    } else {
        String::new()
    });

    let overview =
        use_console_query::<peerward_api::ConsoleOverview>(if can_read && !mesh.is_empty() {
            format!("/api/v1/meshes/{mesh}/console/overview")
        } else {
            String::new()
        });
    let counts = overview
        .read()
        .as_ref()
        .and_then(|v| v.as_ref().ok())
        .cloned();
    let nav = [
        (ConsoleRoute::Overview, "⌂"),
        (ConsoleRoute::Peers, "▣"),
        (ConsoleRoute::Services, "⇄"),
        (ConsoleRoute::Policy, "✓"),
        (ConsoleRoute::Operations, "!"),
    ];
    rsx! {
        div {
            class: "shell console-v14",
            "data-theme": theme().attribute(),
            lang: locale().tag(),
            onkeydown: move |event| {
                if event.key() == Key::Escape {
                    search_open.set(false);
                    notices_open.set(false);
                    mobile_open.set(false);
                }
                if event.key() == Key::Character("k".into())
                    && (event.modifiers().ctrl() || event.modifiers().meta())
                {
                    event.prevent_default();
                    search_open.set(true);
                }
            },
            a { class: "pw-skip", href: "#main-content",
                "{locale().message(Message::SkipToContent)}"
            }
            if mobile_open() {button {class:"mobile-nav-backdrop",aria_label:console_text(locale(), "关闭导航", "Close navigation"),onclick:move |_| mobile_open.set(false)}}
            aside { id: "console-sidebar", class: if mobile_open() { "sidebar mobile-open" } else { "sidebar" },
                div { class: "brand-row",
                    span { class: "logo-mark", "P" }
                    div {
                        strong { "Peerward" }
                        small { {console_text(locale(), "网络管理", "Network management")} }
                    }
                }
                section { class: "network-card",
                    small { class: "eyebrow",
                        {console_text(locale(), "当前网络", "CURRENT NETWORK")}
                    }
                    details { class: "network-switcher",
                        summary {
                            span { class: "network-avatar", "⌂" }
                            span {
                                strong {
                                    if mesh.is_empty() {
                                        {console_text(locale(), "选择网络", "Select a network")}
                                    } else {
                                        {
                                            if snapshot.mesh_id.is_empty() {
                                                console_text(locale(), "未选择网络", "No network selected").to_owned()
                                            } else {
                                                snapshot.mesh_name.clone()
                                            }
                                        }
                                    }
                                }
                            }
                            span { class: "chevron", "⌄" }
                        }
                        div { class: "network-menu",
                            label { class: "sr-only", r#for: "network-search",
                                {console_text(locale(), "搜索网络", "Search networks")}
                            }
                            input {
                                id: "network-search",
                                value: mesh_query,
                                placeholder: console_text(locale(), "搜索网络", "Search networks"),
                                oninput: move |e| { mesh_query.set(e.value()); mesh_cursor.set(String::new()); },
                            }
                            if let Some(Ok(page)) = networks.read().as_ref() {
                                for item in &page.items {
                                    a { href: ConsoleClientRoute::from_console_route(route, Some(item.id.to_string()), None).href(), aria_current: if item.id.to_string() == mesh { Some("true") } else { None }, "{item.name}" }
                                }
                                if page.items.is_empty() { p { class: "empty", {console_text(locale(), "没有匹配的网络", "No matching networks")} } }
                                if let Some(next) = page.next_cursor.clone() { button { class: "quiet-button", onclick: move |_| mesh_cursor.set(next.clone()), {console_text(locale(), "更多网络", "More networks")} } }
                                if !mesh_cursor().is_empty() { button { class: "quiet-button", onclick: move |_| mesh_cursor.set(String::new()), {console_text(locale(), "返回第一页", "First page")} } }
                            } else {
                                for item in snapshot.meshes.iter().filter(|m| m.name.to_lowercase().contains(&mesh_query().to_lowercase())) {
                                    a { href: ConsoleClientRoute::from_console_route(route, Some(item.id.clone()), None).href(), aria_current: if item.id == mesh { Some("true") } else { None }, "{item.name}" }
                                }
                                if let Some(Err(error)) = networks.read().as_ref() { if !error.is_empty() { p { role: "alert", "{error}" } button { onclick: move |_| networks.restart(), {console_text(locale(), "重试", "Retry")} } } }
                            }
                            a { href: format!("/networks?mesh={mesh}"),
                                {console_text(locale(), "管理所有网络", "Manage all networks")}
                            }
                        }
                    }
                    div { class: "network-links",
                        a { href: format!("/meshes?mesh={mesh}"),
                            {console_text(locale(), "网络设置", "Network settings")}
                        }
                    }
                }
                nav {
                    class: "nav main-nav",
                    aria_label: console_message(locale(), "primary-navigation"),
                    for (item, icon) in nav.into_iter()
                        .filter(|(r, _)| {
                            can_read || matches!(r, ConsoleRoute::Overview | ConsoleRoute::Operations)
                        })
                    {
                        div { class: if primary_route(route) == item { "nav-row selected" } else { "nav-row" },
                            span { class: "nav-icon", aria_hidden: "true", "{icon}" }
                            ConsoleSectionLink {
                                item,
                                mesh: mesh.clone(),
                                selected: primary_route(route) == item,
                                client_routing,
                                label: primary_route_label(locale(), item),
                            }
                            if item == ConsoleRoute::Operations {
                                if let Some(count) = counts
                                    .as_ref()
                                    .map(|v| v.open_issue_count)
                                    .filter(|count| *count > 0)
                                {
                                    span { class: "nav-count", "{count}" }
                                }
                            }
                        }
                    }
                }
                details { class: "advanced-navigation", open: matches!(route, ConsoleRoute::Audit | ConsoleRoute::Relays | ConsoleRoute::Authorities | ConsoleRoute::Webhooks),
                    summary { {console_text(locale(), "系统工具", "System tools")} }
                    ConsoleSectionLink {
                        item: ConsoleRoute::Audit,
                        mesh: mesh
                                .clone(),
                        selected: route == ConsoleRoute::Audit,
                        client_routing,
                        label: primary_route_label(locale(), ConsoleRoute::Audit),
                    }
                    if can_read {
                        ConsoleSectionLink {
                            item: ConsoleRoute::Relays,
                            mesh: mesh.clone(),
                            selected: route ==
                                    ConsoleRoute::Relays,
                            client_routing,
                            label: console_text(locale(), "系统维护", "System maintenance"),
                        }
                        ConsoleSectionLink {
                            item: ConsoleRoute::Webhooks,
                            mesh: mesh.clone(),
                            selected: route ==
                                    ConsoleRoute::Webhooks,
                            client_routing,
                            label: console_text(locale(), "Webhook 与配置", "Webhooks and configuration"),
                        }
                    }
                    if can_trust {
                        ConsoleSectionLink {
                            item: ConsoleRoute::Authorities,
                            mesh: mesh.clone(),
                            selected: route == ConsoleRoute::Authorities,
                            client_routing,
                            label: console_text(locale(), "凭据与签发机构", "Credentials and authorities"),
                        }
                    }
                }
                if !snapshot.healthy {
                    div { class: "sidebar-bottom",
                        p { class: "connection-state unavailable",
                            span { class: "state-dot" }
                            {console_message(locale(), "control-unreachable")}
                        }
                    }
                }
            }
            div { class: "main",
                header { class: "topbar",
                    inert: if hydrated() { None } else { Some("true") },
                    aria_busy: (!hydrated()).to_string(),
                    button {
                        class: "icon-button mobile-menu",
                        disabled: !hydrated(),
                        r#type: "button",
                        aria_label: console_text(locale(), "打开导航", "Open navigation"),
                        aria_expanded: mobile_open().to_string(),
                        aria_controls: "console-sidebar",
                        onclick: move |_| mobile_open.toggle(),
                        "☰"
                    }
                    div { class: "top-actions",
                        if can_read {
                            button {
                                class: "icon-button",
                                r#type: "button",
                                aria_label: console_text(locale(), "全局搜索", "Global search"),
                                aria_haspopup: "dialog",
                                "data-console-focus-key": "global-search",
                                title: "Ctrl / ⌘ K",
                                disabled: !hydrated(),
                                onclick: move |_| search_open.set(true),
                                "⌕"
                            }
                            button {
                                class: "icon-button",
                                r#type: "button",
                                aria_label: console_text(locale(), "通知中心", "Notifications"),
                                aria_haspopup: "dialog",
                                "data-console-focus-key": "notifications",
                                disabled: !hydrated(),
                                onclick: move |_| notices_open.set(true),
                                "♢"
                                if let Some(count)=counts.as_ref().map(|v|v.unread_notice_count).filter(|v|*v>0){span{class:"notice-count","{count}"}}
                            }
                        }
                        details { class: "account-menu",
                            summary {
                                span { class: "avatar small-avatar",
                                    {console_text(locale(), "管", "A")}
                                }
                                span { class: "session-copy",
                                    strong { {console_session_role(locale(), &snapshot.role)} }
                                    small {
                                        if authenticated { span { class: "state-dot" } }
                                        {if !authenticated { console_message(locale(), "sign-in") }
                                         else if snapshot.csrf_token.is_some() { console_text(locale(), "OIDC 已登录", "OIDC signed in") }
                                         else { console_text(locale(), "开发会话", "Development session") }}
                                    }
                                }
                                span { class: "session-chevron", aria_hidden: "true", "⌄" }
                            }
                            div { class: "account-popover",
                                strong { {console_text(locale(), "管理会话", "Management session")} }
                                p { class: "muted",
                                    {
                                        console_text(
                                            locale(),
                                            "权限由身份提供方和控制服务决定。",
                                            "Permissions are provided by your identity provider and the control service.",
                                        )
                                    }
                                }
                                div { class: "account-preferences",
                                    small { {console_text(locale(), "显示与语言", "Display and language")} }
                                    PreferenceControls { locale, theme }
                                }
                                a { href: "/api/v1/auth/login",
                                    {console_text(locale(), "重新验证身份", "Authenticate again")}
                                }
                                if authenticated && snapshot.csrf_token.is_some() {
                                    SessionLockButton {
                                        csrf: snapshot.csrf_token.clone(),
                                        locale: locale(),
                                    }
                                }
                            }
                        }
                    }
                }
                main {
                    class: "content",
                    id: "main-content",
                    inert: if hydrated() { None } else { Some("true") },
                    "data-console-ready": hydrated().to_string(),
                    aria_busy: (!
                            hydrated()).to_string(),
                    if !matches!(route, ConsoleRoute::Peers | ConsoleRoute::JoinTickets) || mesh.is_empty() {
                    div { class: "page-head",
                        div {
                            div { class: "eyebrow",
                                {
                                    if snapshot.mesh_id.is_empty() {
                                        console_text(locale(), "未选择网络", "No network selected").to_owned()
                                    } else {
                                        snapshot.mesh_name.clone()
                                    }
                                }
                            }
                            h1 { {if route == ConsoleRoute::Meshes && mesh.is_empty() { primary_route_label(locale(),ConsoleRoute::Networks) } else { primary_route_label(locale(), route) }} }
                            p { {console_page_description(locale(), if route == ConsoleRoute::Meshes && mesh.is_empty() { ConsoleRoute::Networks } else { route })} }
                        }
                    }
                    }
                    if show_read_only_notice {
                        section { class: "permission-banner", role: "status",
                            span { class: "permission-banner-mark", aria_hidden: "true", "◌" }
                            div {
                                strong { {console_text(locale(), "只读模式", "Read-only mode")} }
                                p {
                                    {console_text(
                                        locale(),
                                        "可以查看状态、访问结果和问题，但不能添加设备或修改共享、访问设置。问题仍可标记为已知。",
                                        "You can review status, access results, and issues, but cannot add devices or change sharing or access settings. Issues can still be acknowledged.",
                                    )}
                                }
                            }
                        }
                    }
                    if let Some(error) = snapshot.error.as_ref() {
                        ErrorNotice {
                            error: UiError {
                                code: error.code.clone(),
                                message: error.message.clone(),
                                request_id: Some(error.request_id.clone()),
                                field_errors: error.field_errors.clone(),
                                retryable: error.retryable,
                            },
                        }
                    }
                    {children}
                }
            }
            if search_open() {
                ConsoleSearchDialog {
                    mesh: mesh.clone(),
                    locale: locale(),
                    on_close: move |()| search_open.set(false),
                }
            }
            if notices_open() {
                ConsoleOverlay {
                    title: console_text(locale(), "最近需要关注", "Needs attention"),
                    on_close: move |()| notices_open.set(false),
                    ConsoleIssuesPanel {
                        mesh: mesh.clone(),
                        locale: locale(),
                        csrf: snapshot
                                .csrf_token,
                        notifications: true,
                    }
                }
            }
        }
    }
}

include!("console_shell_widgets.rs");
