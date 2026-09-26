#[component]
fn ConsoleAccessPanel(
    mesh: String,
    #[props(default)] mesh_name: String,
    locale: Locale,
    csrf: Option<String>,
    can_write: bool,
    #[props(default)] requested_resource: String,
    #[props(default)] requested_source: String,
    #[props(default)] fixed_source: Option<peerward_types::PeerId>,
) -> Element {
    #[cfg(target_arch = "wasm32")]
    let navigator = use_navigator();
    // SSR bootstraps the route and mesh, without URL source filters. Apply those
    // in the effect below so the initial browser DOM matches the hydrated tree.
    let initial_source = fixed_source.map(|id| format!("peer:{id}")).unwrap_or_default();
    let mut source = use_signal(|| initial_source);
    let mut source_search = use_signal(String::new);
    let mut resource_search = use_signal(String::new);
    let mut cursor = use_signal(String::new);
    let mut selected = use_signal(|| None::<peerward_api::ConsoleSharingResource>);
    let mut grant_open = use_signal(|| false);
    let mut locally_selected = use_signal(|| false);
    let policy = use_console_query::<PolicyPutRequest>(format!("/api/v1/meshes/{mesh}/policy"));
    let mut focused_resource = use_signal(String::new);
    let requested_share = use_console_query::<Page<peerward_api::ConsoleSharingResource>>(
        if requested_resource.is_empty() {
            String::new()
        } else {
            format!("/api/v1/meshes/{mesh}/console/sharing?resource={requested_resource}")
        },
    );
    let requested_group_id = requested_source
        .strip_prefix("group:")
        .and_then(|id| uuid::Uuid::parse_str(id).ok())
        .map(|id| id.to_string());
    let requested_group_path = if let Some(id) = requested_group_id.as_deref() {
        format!("/api/v1/meshes/{mesh}/collections/{id}")
    } else {
        match requested_share.read().as_ref() {
            Some(Ok(page)) if page.items.is_empty() && !requested_resource.is_empty() => {
                format!("/api/v1/meshes/{mesh}/collections/{requested_resource}")
            }
            _ => String::new(),
        }
    };
    let requested_group =
        use_console_query::<peerward_management::Collection>(requested_group_path);
    let requested_peer_id = requested_source
        .strip_prefix("peer:")
        .and_then(|id| id.parse::<peerward_types::PeerId>().ok());
    let requested_peer = use_console_query::<PeerResource>(requested_peer_id.as_ref().map_or_else(
        String::new,
        |id| format!("/api/v1/meshes/{mesh}/peers/{id}"),
    ));
    #[cfg(target_arch = "wasm32")]
    let source_mesh = mesh.clone();
    #[cfg(target_arch = "wasm32")]
    let source_resource = requested_resource.clone();
    let select_source = use_callback(move |value: String| {
        selected.set(None);
        locally_selected.set(true);
        source.set(value.clone());
        #[cfg(target_arch = "wasm32")]
        navigator.replace(
            ConsoleClientRoute::Policy {
                mesh: Some(source_mesh.clone()),
                resource: (!source_resource.is_empty()).then(|| source_resource.clone()),
                source: (!value.is_empty()).then_some(value),
            }
            .href(),
        );
    });
    use_effect(use_reactive((&requested_resource,), move |_| {
        focused_resource.set(String::new());
        resource_search.set(String::new());
        cursor.set(String::new());
    }));
    use_effect(use_reactive((&requested_source,), move |(requested,)| {
        if fixed_source.is_none()
            && (requested.is_empty() || parse_console_source(&requested).is_some())
        {
            if *source.peek() != requested { locally_selected.set(false); }
            source.set(requested);
        }
    }));
    use_effect(move || {
        if let Some(Ok(page)) = requested_share.read().as_ref()
            && let Some(resource) = page.items.first()
        {
            focused_resource.set(resource.id.to_string());
            resource_search.set(resource.name.clone());
            cursor.set(String::new());
        }
    });
    let requested_source_for_legacy = requested_source.clone();
    use_effect(move || {
        if fixed_source.is_none()
            && requested_source_for_legacy.is_empty()
            && let Some(Ok(group)) = requested_group.read().as_ref()
        {
            source.set(format!("group:{}", group.id));
        }
    });
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params
        .append_pair("limit", "50")
        .append_pair("q", &source_search());
    let mut devices = use_console_query::<peerward_api::ConsoleDevicePage>(if fixed_source.is_some() {
        String::new()
    } else {
        format!(
            "/api/v1/meshes/{mesh}/console/devices?{}",
            params.finish()
        )
    });
    let mut group_query = url::form_urlencoded::Serializer::new(String::new());
    group_query
        .append_pair("mesh", &mesh)
        .append_pair("kind", "group")
        .append_pair("limit", "50")
        .append_pair("q", &source_search());
    let mut groups = use_console_query::<Page<peerward_api::ConsoleSearchItem>>(if fixed_source.is_some() {
        String::new()
    } else {
        format!("/api/v1/console/search?{}", group_query.finish())
    });
    let source_load_error = if fixed_source.is_none() {
        devices
            .read()
            .as_ref()
            .and_then(|value| value.as_ref().err())
            .filter(|error| !error.is_empty())
            .cloned()
            .or_else(|| {
                groups
                    .read()
                    .as_ref()
                    .and_then(|value| value.as_ref().err())
                    .filter(|error| !error.is_empty())
                    .cloned()
            })
    } else {
        None
    };
    let no_source_candidates = fixed_source.is_none()
        && devices
            .read()
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .is_some_and(|page| {
                page.items.iter().all(|item| {
                    item.administrative_state != peerward_api::AdministrativeState::Enabled
                })
            })
        && groups
            .read()
            .as_ref()
            .and_then(|value| value.as_ref().ok())
            .is_some_and(|page| page.items.is_empty());
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params
        .append_pair("limit", "8")
        .append_pair("q", &resource_search());
    if !cursor().is_empty() {
        params.append_pair("cursor", &cursor());
    }
    let mut resources = use_console_query::<Page<peerward_api::ConsoleSharingResource>>(format!(
        "/api/v1/meshes/{mesh}/console/sharing?{}",
        params.finish()
    ));
    let targets = resources
        .read()
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .map(|p| {
            p.items
                .iter()
                .map(|r| {
                    if r.kind == "service" {
                        peerward_api::ConsoleMatrixTarget::Service {
                            id: r.id,
                            address: None,
                            protocol: None,
                        }
                    } else {
                        peerward_api::ConsoleMatrixTarget::Network {
                            id: r.id,
                            address: None,
                            provider: None,
                            protocol: None,
                            port: None,
                        }
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut result = use_console_post::<peerward_api::ConsoleMatrix>(
        if source().is_empty() {
            String::new()
        } else {
            format!("/api/v1/meshes/{mesh}/console/matrix")
        },
        json!(peerward_api::ConsoleMatrixQuery {
            source: parse_console_source(&source())
                .unwrap_or(peerward_api::ConsoleGrantSource::None),
            targets
        }),
    );
    let active_source = source();
    use_effect(use_reactive((&active_source,), move |_| selected.set(None)));
    // Recompute the explanation from the latest matrix, including after grant changes.
    let current_result = selected().and_then(|resource| result.read().as_ref()
        .and_then(|r| r.as_ref().ok())
        .and_then(|matrix| matrix.cells.iter().find(|cell| cell.id == resource.id).cloned()));
    let source_label = devices.read().as_ref().and_then(|r| r.as_ref().ok())
        .and_then(|page| page.items.iter().find(|peer| source() == format!("peer:{}", peer.id)))
        .map(|peer| if peer.display_name.is_empty() { peer.name.clone() } else { peer.display_name.clone() })
        .or_else(|| requested_peer.read().as_ref().and_then(|r| r.as_ref().ok())
            .filter(|peer| source() == format!("peer:{}", peer.id))
            .map(|peer| if peer.display_name.is_empty() { peer.name.clone() } else { peer.display_name.clone() }))
        .or_else(|| groups.read().as_ref().and_then(|r| r.as_ref().ok())
            .and_then(|page| page.items.iter().find(|group| source() == format!("group:{}", group.id)))
            .map(|group| group.name.clone()))
        .or_else(|| requested_group.read().as_ref().and_then(|r| r.as_ref().ok())
            .filter(|group| source() == format!("group:{}", group.id)).map(|group| group.definition.name.clone()))
        .unwrap_or_else(|| console_text(locale, "当前来源", "Current source").into());
    rsx! {
        div { class: "access-page",
        if fixed_source.is_none() {
            div { class: "page-head access-page-head",
                div {
                    div { class: "eyebrow", "{mesh_name}" }
                    h1 { {console_text(locale, "访问", "Access")} }
                    p { {console_page_description(locale, ConsoleRoute::Policy)} }
                }
                if can_write {
                    button { class: "primary-button", onclick: move |_| grant_open.set(true),
                        {console_text(locale, "＋ 添加授权", "＋ Add grant")}
                    }
                }
            }
            section { class: "card access-default",
                span { class: "access-default-icon", aria_hidden: "true", dangerous_inner_html: include_str!("../assets/icons/check-lg.svg") }
                div {
                    if let Some(Ok(current)) = policy.read().as_ref() {
                        if current.default_action == "deny" {
                            strong { {console_text(locale, "默认拒绝已开启", "Default deny is enabled")} }
                            small { {console_text(locale, "没有明确授权，就不能访问共享。先选来源，再看它对每个共享的最终结果。", "Select a source to see its final access result for each share. Access requires an explicit grant.")} }
                        } else {
                            strong { {console_text(locale, "设备通信的默认策略为允许", "Device communication is allowed by default")} }
                            small { {console_text(locale, "当前网络使用自定义策略，请以各共享的最终访问结果为准。", "This network uses a custom policy. Review each share’s effective access result.")} }
                        }
                    } else {
                        strong { {console_text(locale, "访问由当前规则决定", "Access is determined by current rules")} }
                        small { {console_text(locale, "选择来源，查看它对每个共享的最终结果。", "Select a source to see the final result for each share.")} }
                    }
                }
            }
        }
        section { class: "card access-source-card",
            div { class: "access-source-section",
                if let Some(id) = fixed_source {
                    h2 { {console_text(locale, "这台设备可以访问什么", "What this device can access")} }
                    p { class: "muted",
                        {console_text(locale, "下面直接显示这台设备对各个共享的当前访问结果。需要比较其他设备时，再打开完整访问页。", "This view shows the device's current access result for each share. Open the full Access page only when you need to compare another device or group.")}
                    }
                    div { class: "access-focus-banner access-context-banner",
                        div {
                            small { {console_text(locale, "当前设备", "Current device")} }
                            strong { {console_text(locale, "设备详情中的访问结果", "Access from device details")} }
                            p { {console_text(locale, "设备上下文已经固定，不需要再次选择来源。", "The device context is fixed here, so there is no source selector to manage.")} }
                        }
                        a { class: "text-link", href: format!("/policy?mesh={mesh}&source=peer:{id}"),
                            {console_text(locale, "打开完整访问页", "Open full access view")}
                        }
                    }
                } else {
                    h2 { {console_text(locale, "先选择访问来源", "Select an access source first")} }
                    p { class: "muted",
                        {
                            console_text(
                                locale,
                                "可以选择单台设备或设备组；搜索只用来缩小候选范围。",
                                "Select a device or group; search only narrows the available choices.",
                            )
                        }
                    }
                    div { class: "filter-bar access-source-toolbar",
                        label { class: "sr-only", r#for: "access-source-search",
                            {console_text(locale, "查找设备或组", "Find device or group")}
                        }
                        input {
                            id: "access-source-search",
                            value: source_search,
                            placeholder: console_text(locale, "搜索设备或设备组", "Search devices or groups"),
                            oninput: move |e| source_search.set(e.value()),
                        }
                        label { r#for: "access-source",
                            {console_text(locale, "设备或设备组", "Device or group")}
                        }
                        select {
                            id: "access-source",
                            "data-console-selection": "true",
                            value: source,
                            onchange: move | e | select_source.call(e.value()),
                            option { value: "",
                                {console_text(locale, "请选择访问来源", "Select an access source")}
                            }
                            if let Some(Ok(peer)) = requested_peer.read().as_ref() {
                                if source() == format!("peer:{}", peer.id)
                                    && devices
                                        .read()
                                        .as_ref()
                                        .and_then(|value| value.as_ref().ok())
                                        .is_none_or(|page| !page.items.iter().any(|item| item.id == peer.id))
                                {
                                    option { value: format!("peer:{}", peer.id),
                                        {format!("{} · {}", if peer.display_name.is_empty() { peer.name.as_str() } else { peer.display_name.as_str() }, console_text(locale, "设备", "Device"))}
                                    }
                                }
                            }
                            if let Some(Ok(page)) = devices.read().as_ref() {
                                for p in page.items
                                    .iter()
                                    .filter(|p| p.administrative_state == peerward_api::AdministrativeState::Enabled)
                                {
                                    option { value: format!("peer:{}", p.id),
                                        {if p.display_name.is_empty() || p.display_name == p.name { format!("{} · {}", p.name, console_text(locale, "设备", "Device")) } else { format!("{} · {}", p.display_name, p.name) }}
                                    }
                                }
                            }
                            if let Some(Ok(group)) = requested_group.read().as_ref() {
                                if source() == format!("group:{}", group.id)
                                    && groups
                                        .read()
                                        .as_ref()
                                        .and_then(|value| value.as_ref().ok())
                                        .is_none_or(|page| !page.items.iter().any(|item| item.id == group.id))
                                {
                                    option { value: format!("group:{}", group.id),
                                        "{group.definition.name} · " {console_text(locale, "设备组", "Device group")}
                                    }
                                }
                            }
                            if let Some(Ok(page)) = groups.read().as_ref() {
                                for g in page.items.iter()
                                {
                                    option { value: format!("group:{}", g.id),
                                        "{g.name} · " {console_text(locale, "设备组", "Device group")}
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if let Some(error) = source_load_error.as_ref() {
                div { class: "feedback-state feedback-error embedded-feedback", role: "alert",
                    span { class: "feedback-icon", aria_hidden: "true", "!" }
                    div { class: "feedback-copy",
                        strong { {console_text(locale, "暂时无法读取设备或设备组", "Unable to load devices or groups right now")} }
                        p { "{error}" }
                    }
                    button { class: "secondary-button", onclick: move |_| { devices.restart(); groups.restart(); },
                        {console_text(locale, "重试", "Retry")}
                    }
                }
            }
            if fixed_source.is_none() && !locally_selected() && !requested_source.is_empty() && source() == requested_source {
                if let Some(id) = requested_peer_id {
                    div { class: "access-focus-banner access-context-banner",
                        div {
                            small { {console_text(locale, "当前访问来源", "Current access source")} }
                            strong {
                                if let Some(Ok(peer)) = requested_peer.read().as_ref() {
                                    {if peer.display_name.is_empty() { peer.name.clone() } else { peer.display_name.clone() }}
                                } else {
                                    {console_text(locale, "指定设备", "Selected device")}
                                }
                            }
                            p { {console_text(locale, "这台设备已保留在当前链接中，刷新后仍会作为访问来源。", "This device is preserved in the current link and remains the access source after refresh.")} }
                        }
                        a { class: "text-link", href: format!("/peers?mesh={mesh}&resource={id}"),
                            {console_text(locale, "查看设备详情", "View device details")}
                        }
                    }
                } else if requested_group_id.is_some() {
                    div { class: "access-focus-banner access-context-banner",
                        div {
                            small { {console_text(locale, "已定位设备组", "Device group selected")} }
                            strong {
                                if let Some(Ok(group)) = requested_group.read().as_ref() {
                                    "{group.definition.name}"
                                } else {
                                    {console_text(locale, "指定设备组", "Selected device group")}
                                }
                            }
                            p { {console_text(locale, "访问结果已自动使用这个设备组作为来源。", "Access results are using this group as the source.")} }
                        }
                        a { class: "text-link", href: format!("/policy?mesh={mesh}"),
                            {console_text(locale, "清除上下文", "Clear context")}
                        }
                    }
                }
            }
            if let Some(Ok(page)) = requested_share.read().as_ref() {
                if let Some(resource) = page.items.first() {
                    div { class: "access-focus-banner",
                        div {
                            small { {console_text(locale, "正在检查这个共享", "Reviewing this share")} }
                            strong { "{resource.name}" }
                            p { "{resource.target}" }
                        }
                        a { class: "text-link", href: format!("/services?mesh={mesh}&resource={}", resource.id),
                            {console_text(locale, "返回共享详情", "Back to sharing details")}
                        }
                    }
                }
            }
        }
        section { class: "card access-workspace",
            div { class: "panel-head access-matrix-head",
                div {
                    h2 { {console_text(locale, "访问结果", "Access results")} }
                    p { class: "muted", {console_text(locale, "只显示当前来源对各共享的最终结果。点击结果查看原因或修改授权。", "The current source’s final result for each share. Select a result to review or change grants.")} }
                }
                div { class: "actions",
                    label { class: "sr-only", r#for: "access-resource-search",
                        {console_text(locale, "搜索共享", "Search shares")}
                    }
                    input {
                        id: "access-resource-search",
                        value: resource_search,
                        placeholder: console_text(locale, "搜索共享", "Search shares"),
                        oninput: move |e| {
                            resource_search.set(e.value());
                            cursor.set(String::new());
                        },
                    }
                    button { class: "secondary-button", onclick: move |_| { *CONSOLE_QUERY_EPOCH.write() += 1; },
                        {console_text(locale, "重新检查", "Check again")}
                    }
                }
            }
            if source().is_empty() && fixed_source.is_none(){
                if let Some(Err(error))=devices.read().as_ref(){if !error.is_empty(){p{role:"alert", class:"inline-error","{error}"}}}
                if let Some(Err(error))=groups.read().as_ref(){if !error.is_empty(){p{role:"alert", class:"inline-error","{error}"}}}
                if no_source_candidates {
                    div { class: "feedback-state feedback-empty embedded-feedback", role: "status",
                        span { class: "feedback-icon", aria_hidden: "true", if source_search().is_empty() { "▣" } else { "⌕" } }
                        div { class: "feedback-copy",
                            strong {
                                if source_search().is_empty() {
                                    {console_text(locale, "还没有可检查的设备或设备组", "There are no devices or groups to review yet")}
                                } else {
                                    {console_text(locale, "没有匹配的设备或设备组", "No devices or groups match this search")}
                                }
                            }
                            p {
                                if !source_search().is_empty() {
                                    {console_text(locale, "调整搜索关键词后再试。", "Adjust the search and try again.")}
                                } else if can_write {
                                    {console_text(locale, "先加入一台设备；需要时再把多台设备整理成设备组。", "Enroll a device first; create device groups later when they are useful.")}
                                } else {
                                    {console_text(locale, "当前账号为只读。设备或设备组出现后，就可以在这里检查它们的访问结果。", "This account is read-only. When devices or groups are available, you can review their access results here.")}
                                }
                            }
                        }
                        if source_search().is_empty() && can_write {
                            a { class: "secondary-button", href: format!("/join-tickets?mesh={mesh}"),
                                {console_text(locale, "添加设备", "Add device")}
                            }
                        }
                    }
                } else {
                    div { class: "access-empty-selection",
                        span { class: "access-empty-icon", aria_hidden: "true", dangerous_inner_html: include_str!("../assets/icons/arrow-up-left.svg") }
                        div {
                            strong { {console_text(locale, "先选择一台设备或设备组", "Choose a device or group first")} }
                            p { class: "muted", {console_text(locale, "上面的搜索只用来缩小候选范围；选中来源后，这里只显示它对共享的最终访问结果。", "Use the search above to narrow the choices. After selecting a source, this area shows only its final access results for shares.")} }
                        }
                    }
                }
            } else if let Some(Err(error)) = resources.read().as_ref() {
                if !error.is_empty() {
                    div { class: "feedback-state feedback-error embedded-feedback", role: "alert",
                        span { class: "feedback-icon", aria_hidden: "true", "!" }
                        div { class: "feedback-copy",
                            strong { {console_text(locale, "暂时无法读取共享", "Unable to load shares right now")} }
                            p { "{error}" }
                        }
                        button { class: "secondary-button", onclick: move |_| resources.restart(),
                            {console_text(locale, "重试", "Retry")}
                        }
                    }
                }
            } else if let Some(Ok(page)) = resources.read().as_ref() {
                if page.items.is_empty() {
                    div { class: "feedback-state feedback-empty embedded-feedback",
                        span { class: "feedback-icon", aria_hidden: "true", "—" }
                        div { class: "feedback-copy",
                            if resource_search().is_empty() {
                                strong { {console_text(locale, "还没有共享可以检查", "There are no shares to review yet")} }
                                if can_write {
                                    p { {console_text(locale, "先添加一个共享，再检查设备是否可以访问它。", "Add a share first, then check whether this device can access it.")} }
                                } else {
                                    p { {console_text(locale, "当前没有已配置的共享。共享创建后，这里会显示所选来源的访问结果。", "No shares are configured yet. Access results for the selected source will appear here after sharing is created.")} }
                                }
                            } else {
                                strong { {console_text(locale, "没有匹配的共享", "No matching shares")} }
                                p { {console_text(locale, "调整搜索关键词后再试。", "Adjust the search and try again.")} }
                            }
                        }
                        if resource_search().is_empty() && can_write {
                            a { class: "secondary-button", href: format!("/services?mesh={mesh}"),
                                {console_text(locale, "添加共享", "Add share")}
                            }
                        }
                    }
                } else {
                    div { class: "matrix-scroll",
                        table { class: "access-permission-matrix",
                            caption { class: "sr-only", {console_text(locale, "所选来源的有效访问权限", "Effective access for selected source")} }
                            thead {
                                tr {
                                    th { scope: "col", class: "access-matrix-corner",
                                        strong { {console_text(locale, "当前来源", "Current source")} }
                                        small { {console_text(locale, "点击结果查看原因", "Select a result to review")} }
                                    }
                                    for resource in &page.items {
                                        th { scope: "col",
                                            span { class: "access-kind", {resource_kind_label(locale, &resource.kind)} }
                                            strong { "{resource.name}" }
                                            small { "{resource.target}" }
                                        }
                                    }
                                }
                            }
                            tbody {
                                tr {
                                    th { scope: "row", class: "access-matrix-source",
                                        span { class: "access-kind", {if source().starts_with("group:") { console_text(locale,"设备组","Group") } else { console_text(locale,"设备","Device") }} }
                                        strong { "{source_label}" }
                                    }
                                    for resource in &page.items {
                                        td { class: if focused_resource() == resource.id.to_string() { "focused-cell" } else { "" },
                                            if let Some(cell) = result.read().as_ref().and_then(|r| r.as_ref().ok())
                                                .and_then(|m| m.cells.iter().find(|c| c.id == resource.id)) {
                                                button {
                                                    class: format!("access-matrix-cell {}", cell.outcome),
                                                    "data-console-dismiss": "true",
                                                    aria_label: format!("{} · {} · {}", resource.name, matrix_outcome(locale, &cell.outcome), console_text(locale,"查看原因","Review reason")),
                                                    aria_pressed: selected().is_some_and(|item| item.id == resource.id).to_string(),
                                                    onclick: {
                                                        let resource = resource.clone();
                                                        move |_| selected.set(Some(resource.clone()))
                                                    },
                                                    span { class: "access-decision-icon", aria_hidden: "true",
                                                        dangerous_inner_html: match cell.outcome.as_str() {
                                                            "allowed" => include_str!("../assets/icons/check-lg.svg"),
                                                            "denied" => include_str!("../assets/icons/dash.svg"),
                                                            _ => include_str!("../assets/icons/exclamation.svg"),
                                                        }
                                                    }
                                                    span {
                                                        strong { {matrix_outcome(locale,&cell.outcome)} }
                                                        if cell.sources > 1 {
                                                            small { "{cell.allowed_sources} / {cell.sources}" }
                                                        }
                                                    }
                                                }
                                            } else {
                                                span { class: "access-matrix-pending", {console_text(locale,"正在计算…","Evaluating…")} }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    div { class: "actions",
                        if !cursor().is_empty() {
                            button {
                                class: "secondary-button",
                                onclick: move |_| cursor.set(String::new()),
                                {console_text(locale, "第一页", "First page")}
                            }
                        }
                        if let Some(next) = page.next_cursor.clone() {
                            button {
                                class: "secondary-button",
                                onclick: move |_| cursor.set(next.clone()),
                                {console_message(locale, "next-page")}
                            }
                        }
                    }
                }
            } else {
                div { class: "feedback-state feedback-loading embedded-feedback", role: "status", aria_busy: "true",
                    span { class: "feedback-icon", aria_hidden: "true", "…" }
                    div { class: "feedback-copy",
                        strong { {console_text(locale, "正在读取访问结果", "Loading access results")} }
                        p { {console_text(locale, "正在读取共享并计算当前访问结果。", "Loading shares and evaluating current access.")} }
                    }
                }
            }
            if let Some(Err(e)) = result.read().as_ref() {
                if !e.is_empty() {
                    div { class: "feedback-state feedback-error embedded-feedback", role: "alert",
                        span { class: "feedback-icon", aria_hidden: "true", "!" }
                        div { class: "feedback-copy",
                            strong { {console_text(locale, "暂时无法计算访问结果", "Unable to evaluate access right now")} }
                            p { "{e}" }
                        }
                        button { class: "secondary-button", onclick: move |_| result.restart(),
                            {console_text(locale, "重试", "Retry")}
                        }
                    }
                }
            }
            div { class: "access-matrix-legend",
                for (kind, zh, en, icon) in [
                    ("allowed", "可以访问", "Allowed", include_str!("../assets/icons/check-lg.svg")),
                    ("denied", "默认阻止", "Blocked by default", include_str!("../assets/icons/dash.svg")),
                    ("conditions", "有需要关注的情况", "Needs attention", include_str!("../assets/icons/exclamation.svg")),
                ] {
                    span { class: "{kind}", i { class:"access-decision-icon", aria_hidden:"true", dangerous_inner_html:icon } {console_text(locale,zh,en)} }
                }
            }
        }
        div { class: "access-workbench",
            section { class: "card access-detail-panel", aria_label: console_text(locale,"访问详情","Access details"),
                div { class: "panel-head",
                    div {
                        h2 { {console_text(locale,"访问详情","Access details")} }
                        p { class: "muted", {console_text(locale,"选择上方一个结果，这里会用自然语言解释为什么允许或阻止。","Select a result above for an explanation of why access is allowed or blocked.")} }
                    }
                    span { class: "access-detail-context", {selected().map(|r| r.name).unwrap_or_else(|| console_text(locale,"尚未选择","Not selected").into())} }
                }
                if let Some(resource) = selected() {
                    ConsoleAccessDetail {
                        key: "{mesh}:{source}:{resource.id}", mesh: mesh.clone(), resource,
                        initial_result: current_result, source: parse_console_source(&source()), locale,
                        csrf: csrf.clone(), can_write,
                        on_change: move |()| result.restart(),
                    }
                } else {
                    div { class: "access-detail-empty",
                        span { class: "access-empty-icon", aria_hidden: "true", dangerous_inner_html: include_str!("../assets/icons/arrow-up-left.svg") }
                        strong { {console_text(locale,"选择一个访问结果","Select an access result")} }
                        p { {console_text(locale,"这里会显示最终决定、命中的授权和当前路径状态。","Review the final decision, matching grants and path status here.")} }
                    }
                }
            }
            if let Some(resource) = selected() {
                ConsoleAccessSimulation { key: "{mesh}:{source}:{resource.id}", mesh:mesh.clone(), resource, source:parse_console_source(&source()), locale }
            } else {
                details { class: "card access-simulator-panel",
                    summary {
                        strong { {console_text(locale,"高级：模拟具体条件","Advanced: simulate specific conditions")} }
                        small { {console_text(locale,"需要排查协议、端口或具体条件时再展开。","Expand to inspect protocols, ports or specific conditions.")} }
                    }
                    p { class:"muted", {console_text(locale,"先选择访问来源，再点击一个共享的访问结果。","Select an access source and a share’s result first.")} }
                }
            }
        }
        if grant_open() && can_write {
            ConsoleOverlay { title: console_text(locale,"添加授权","Add grant"), on_close: move |()| grant_open.set(false),
                ConsoleAccessGrant { mesh:mesh.clone(), locale, csrf:csrf.clone(), initial_source:source(), initial_resource:selected(), on_change:move |()| { *CONSOLE_QUERY_EPOCH.write() += 1; } }
            }
        }
        }
    }
}
