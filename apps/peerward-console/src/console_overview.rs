static CONSOLE_QUERY_EPOCH: GlobalSignal<u64> = Signal::global(|| 0);
#[allow(unused_mut)]
fn use_console_query<T>(path: String) -> Resource<Result<T, String>>
where
    T: DeserializeOwned + 'static,
{
    #[cfg(target_arch = "wasm32")]
    let locale = use_context::<Signal<Locale>>();
    use_resource(use_reactive((&path,), move |(path,)| {
        let _epoch = CONSOLE_QUERY_EPOCH();
        #[cfg(target_arch = "wasm32")]
        let language = locale();
        async move {
            #[cfg(target_arch = "wasm32")]
            {
                if path.is_empty() {
                    return Err(String::new());
                }
                browser_api_client()
                    .request::<T>(Method::GET, &path, None)
                    .await
                    .map_err(|e| console_api_error(language, e))
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = path;
                Err(String::new())
            }
        }
    }))
}
#[component]
fn ConsoleOverviewPanel(
    mesh: String,
    locale: Locale,
    csrf: Option<String>,
    can_write: bool,
) -> Element {
    let path = if mesh.is_empty() {
        String::new()
    } else {
        format!("/api/v1/meshes/{mesh}/console/overview")
    };
    let mut data = use_console_query::<peerward_api::ConsoleOverview>(path);
    if mesh.is_empty() {
        return rsx! {
            section { class: "card first-run",
                span { class: "eyebrow", {console_text(locale, "开始使用", "GET STARTED")} }
                h2 {
                    {
                        console_text(
                            locale,
                            "先选择一个网络",
                            "Select a network first",
                        )
                    }
                }
                p {
                    {
                        console_text(
                            locale,
                            "设备、共享和访问权限都按网络分开管理。先选择已有网络；需要新建时可在网络列表中操作。",
                            "Devices, sharing, and access permissions are managed per network. Choose an existing network first; create one from the network list when needed.",
                        )
                    }
                }
                a { class: "primary-link", href: "/meshes",
                    {console_text(locale, "查看所有网络", "View all networks")}
                }
            }
        };
    }
    let observed = data.read().as_ref().and_then(|r| r.as_ref().ok()).cloned();
    rsx! {
        if let Some(view) = observed {
            section { class: if view.open_issue_count > 0 { "health-banner attention" } else { "health-banner healthy" },
                span { class: "health-icon",
                    if view.open_issue_count > 0 { "!" } else { "✓" }
                }
                div { class: "health-copy",
                    strong {
                        if view.open_issue_count > 0 {
                            {format!("{} {}", view.open_issue_count, console_text(locale, "项需要处理", "items need attention"))}
                        } else if view.devices == 0 {
                            if can_write {
                                {console_text(locale, "网络已创建，先加入第一台设备", "Network created; add your first device")}
                            } else {
                                {console_text(locale, "网络已创建，目前还没有设备", "Network created; there are no devices yet")}
                            }
                        } else {
                            {console_text(locale, "当前没有需要处理的事项", "Nothing needs your attention right now")}
                        }
                    }
                    p {
                        if view.open_issue_count > 0 {
                            {console_text(locale, "只显示需要人工决定或操作的事项；正常的安全阻止不会算作故障。", "Only items requiring a decision or action appear here; expected security denials are not faults.")}
                        } else if view.devices == 0 && !can_write {
                            {console_text(locale, "当前账号为只读；设备加入后会在这里显示状态。", "This account is read-only; device status will appear here after devices are enrolled.")}
                        } else {
                            {console_text(locale, "例行状态保持安静，需要介入时再提醒你。", "Routine status stays quiet and only surfaces when you need to act.")}
                        }
                    }
                }
                button {
                    class: "secondary-button",
                    onclick: move |_| data.restart(),
                    {console_text(locale, "重新检查", "Check again")}
                }
                div { class: "health-meta",
                    small { {console_text(locale, "上次检查", "Last checked")} }
                    time { datetime: format_timestamp(view.observed_at),
                        { format_timestamp(view.observed_at) }
                    }
                }
            }
            section { class: "dashboard-stats overview-stats overview-stats--compact",
                ConsoleStat {
                    title: console_text(locale, "设备", "Devices"),
                    value: format!("{} / {}", view.online_devices, view.devices),
                    note: console_text(locale, "在线 / 全部", "Online / total"),
                }
                ConsoleStat {
                    title: console_text(locale, "共享", "Sharing"),
                    value: (view.services + view.networks + view.exits).to_string(),
                    note: console_text(locale, "设备服务、局域网和出口", "Services, LAN and internet exits"),
                }
            }
            if view.pending_applications > 0 || view.credential_warnings > 0 {
                div { class: "overview-signals",
                    if view.pending_applications > 0 {
                        a { href: format!("/join-tickets?mesh={mesh}"),
                            strong { "{view.pending_applications}" }
                            span { {console_text(locale, "台设备等待确认", "devices waiting for approval")} }
                        }
                    }
                    if view.credential_warnings > 0 {
                        a { href: format!("/peers?mesh={mesh}"),
                            strong { "{view.credential_warnings}" }
                            span { {console_text(locale, "台设备身份需要关注", "device identities need attention")} }
                        }
                    }
                }
            }
            if can_write && (view.devices == 0 || view.services + view.networks + view.exits == 0) {
                section { class: "card setup-steps",
                    h2 { {console_text(locale, "完成首次设置", "Finish initial setup")} }
                    a { href: format!("/join-tickets?mesh={mesh}"),
                        if view.devices > 0 { "✓ · " } else { "1 · " }
                        {console_text(locale, "加入设备", "Add devices")}
                    }
                    a { href: format!("/services?mesh={mesh}"),
                        if view.services + view.networks + view.exits > 0 { "✓ · " } else { "2 · " }
                        {console_text(locale, "添加共享", "Add share")}
                    }
                    a { href: format!("/policy?mesh={mesh}"),
                        "3 · "
                        {console_text(locale, "检查访问权限", "Review access")}
                    }
                }
            }
            if view.open_issue_count > 0 {
                section { class: "card overview-attention",
                    div { class: "panel-head",
                        div {
                            h2 { {console_text(locale, "需要处理", "Needs attention")} }
                            p { class: "muted",
                                {console_text(locale, "这里只保留最需要你介入的事项；完整列表在“问题与维护”。", "Only the most actionable items stay here; the full list is in Issues and maintenance.")}
                            }
                        }
                        a { class: "text-link", href: format!("/operations?mesh={mesh}"),
                            {console_text(locale, "查看全部", "View all")}
                        }
                    }
                    for issue in view.issues.iter().take(3) {
                        ConsoleIssueCard {
                            issue: issue.clone(),
                            locale,
                            csrf: csrf.clone(),
                            on_change: move | () | data.restart(),
                        }
                    }
                }
            }
            nav { class: "overview-shortcuts", aria_label: if can_write { console_text(locale, "常用操作", "Common actions") } else { console_text(locale, "快速查看", "Quick links") },
                if can_write {
                    a { href: format!("/join-tickets?mesh={mesh}"), "＋ ", {console_text(locale, "添加设备", "Add device")} }
                    a { href: format!("/services?mesh={mesh}"), "⇄ ", {console_text(locale, "添加共享", "Add share")} }
                    a { href: format!("/policy?mesh={mesh}"), "✓ ", {console_text(locale, "调整访问", "Adjust access")} }
                } else {
                    a { href: format!("/peers?mesh={mesh}"), "▣ ", {console_text(locale, "查看设备", "View devices")} }
                    a { href: format!("/services?mesh={mesh}"), "⇄ ", {console_text(locale, "查看共享", "View sharing")} }
                    a { href: format!("/policy?mesh={mesh}"), "✓ ", {console_text(locale, "检查访问", "Review access")} }
                }
            }
        } else if let Some(Err(error)) = data.read().as_ref() {
            if !error.is_empty() {
                section { class: "card feedback-state feedback-error", role: "alert",
                    span { class: "feedback-icon", aria_hidden: "true", "!" }
                    div { class: "feedback-copy",
                        strong { {console_text(locale, "暂时无法读取网络状态", "Network status is temporarily unavailable")} }
                        p { "{error}" }
                    }
                    button { class: "secondary-button", onclick: move |_| data.restart(),
                        {console_text(locale, "重试", "Retry")}
                    }
                }
            }
        } else {
            section { class: "card feedback-state feedback-loading", role: "status", aria_busy: "true",
                span { class: "feedback-icon", aria_hidden: "true", "…" }
                div { class: "feedback-copy",
                    strong { {console_text(locale, "正在读取网络状态", "Loading network status")} }
                    p { {console_text(locale, "通常只需要几秒钟。", "This usually takes only a few seconds.")} }
                }
            }
        }
    }
}
fn format_timestamp(seconds: u64) -> String {
    i64::try_from(seconds)
        .ok()
        .and_then(|s| time::OffsetDateTime::from_unix_timestamp(s).ok())
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "—".into())
}
#[component]
fn ConsoleStat(title: &'static str, value: String, note: &'static str) -> Element {
    rsx! {
        article { class: "card stat-card",
            small { "{title}" }
            strong { "{value}" }
            p { "{note}" }
        }
    }
}
