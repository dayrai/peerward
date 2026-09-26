#[component]
#[allow(unused_mut)]
fn ConsoleSharingAccess(
    mesh: String,
    #[props(default)] initial_source: String,
    resource: peerward_api::ConsoleSharingResource,
    locale: Locale,
    csrf: Option<String>,
    can_write: bool,
    on_change: EventHandler<()>,
) -> Element {
    let mut source = use_signal(|| initial_source);
    let mut source_name = use_signal(String::new);
    let mut query = use_signal(String::new);
    let mut device_cursor = use_signal(String::new);
    let mut group_cursor = use_signal(String::new);
    let mut grants_refresh = use_signal(|| 0_u64);
    let mut device_params = url::form_urlencoded::Serializer::new(String::new());
    device_params
        .append_pair("limit", "50")
        .append_pair("q", &query());
    if !device_cursor().is_empty() {
        device_params.append_pair("cursor", &device_cursor());
    }
    let devices = use_console_query::<peerward_api::ConsoleDevicePage>(if can_write {
        format!(
            "/api/v1/meshes/{mesh}/console/devices?{}",
            device_params.finish()
        )
    } else {
        String::new()
    });
    let mut group_params = url::form_urlencoded::Serializer::new(String::new());
    group_params
        .append_pair("mesh", &mesh)
        .append_pair("kind", "group")
        .append_pair("limit", "50")
        .append_pair("q", &query());
    if !group_cursor().is_empty() {
        group_params.append_pair("cursor", &group_cursor());
    }
    let groups = use_console_query::<Page<peerward_api::ConsoleSearchItem>>(if can_write {
        format!("/api/v1/console/search?{}", group_params.finish())
    } else {
        String::new()
    });
    let peers = devices
        .read()
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .map(|p| p.items.clone())
        .unwrap_or_default();
    let collections = groups
        .read()
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .map(|p| p.items.clone())
        .unwrap_or_default();
    let mut candidates: Vec<(String, String)> = collections
        .iter()
        .map(|g| (format!("group:{}", g.id), g.name.clone()))
        .collect();
    candidates.extend(
        peers
            .iter()
            .filter(|p| p.administrative_state == peerward_api::AdministrativeState::Enabled)
            .map(|p| {
                (
                    format!("peer:{}", p.id),
                    if p.display_name.is_empty() {
                        p.name.clone()
                    } else {
                        p.display_name.clone()
                    },
                )
            }),
    );
    let selected_visible = candidates.iter().any(|(id, _)| *id == source());
    let next_device = devices
        .read()
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .and_then(|p| p.next_cursor.clone());
    let next_group = groups
        .read()
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .and_then(|p| p.next_cursor.clone());
    rsx! {
        div { class: "sharing-access-settings",
            p { class: "info-note",
                {console_text(locale, "这里管理这个共享的访问授权。多条授权和高级规则可能共同生效；修改后可用“检查访问”核对最终结果。", "Manage grants for this share here. Multiple grants and advanced rules may apply; use Check access to verify the final result.")}
            }
            ConsoleManagedGrants {
                mesh: mesh.clone(), service: resource.id, network: resource.kind != "service", locale,
                csrf: csrf.clone(), can_write, refresh: grants_refresh(),
                on_change: move |()| on_change.call(()),
            }
            if can_write {
                section { class: "card sharing-grant-source",
                    h3 { {console_text(locale, "添加访问授权", "Add access grant")} }
                    p { class: "muted", {console_text(locale, "选择一台设备或一个设备组，再预览并确认授权。已有授权在上方逐条管理。", "Select a device or group, then preview and confirm the grant. Manage existing grants individually above.")} }
                    div { class: "console-form",
                        label { r#for: "sharing-access-search", {console_text(locale, "查找设备或设备组", "Find devices or groups")} }
                        input { id: "sharing-access-search", value: query, oninput: move |e| {
                            query.set(e.value()); device_cursor.set(String::new()); group_cursor.set(String::new());
                        } }
                        label { r#for: "sharing-access-source", {console_text(locale, "授权给谁", "Grant access to")} }
                        select { id: "sharing-access-source", value: source, "data-console-selection": "true",
                            onchange: move |e| {
                                let value = e.value();
                                source_name.set(candidates.iter().find(|(id, _)| *id == value).map(|(_, name)| name.clone()).unwrap_or_default());
                                source.set(value);
                            },
                            option { value: "", {console_text(locale, "请选择设备或设备组", "Select a device or group")} }
                            if !source().is_empty() && !selected_visible {
                                option { value: source, selected: true, "{source_name}" }
                            }
                            optgroup { label: console_text(locale, "设备组", "Device groups"),
                                for group in &collections { option { value: "group:{group.id}", selected: source() == format!("group:{}", group.id), "{group.name}" } }
                            }
                            optgroup { label: console_text(locale, "设备", "Devices"),
                                for peer in peers.iter().filter(|p| p.administrative_state == peerward_api::AdministrativeState::Enabled) {
                                    option { value: "peer:{peer.id}", selected: source() == format!("peer:{}", peer.id),
                                        if peer.display_name.is_empty() { "{peer.name}" } else { "{peer.display_name}" }
                                    }
                                }
                            }
                        }
                        {console_picker_feedback(devices, false, locale)}
                        {console_picker_feedback(groups, false, locale)}
                        div { class: "actions",
                            if let Some(next) = next_device { button { class: "secondary-button", onclick: move |_| device_cursor.set(next.clone()), {console_text(locale, "更多设备", "More devices")} } }
                            if let Some(next) = next_group { button { class: "secondary-button", onclick: move |_| group_cursor.set(next.clone()), {console_text(locale, "更多设备组", "More groups")} } }
                            if !device_cursor().is_empty() || !group_cursor().is_empty() {
                                button { class: "secondary-button", onclick: move |_| { device_cursor.set(String::new()); group_cursor.set(String::new()); }, {console_text(locale, "返回首页", "First page")} }
                            }
                        }
                    }
                }
                if let Some(selected) = parse_console_source(&source()) {
                    ConsoleGrantForm {
                        key: "{source}", mesh: mesh.clone(), resource: resource.clone(), source: selected,
                        locale, csrf: csrf.clone(), expanded: true,
                        on_change: move |()| { grants_refresh += 1; on_change.call(()); },
                    }
                }
            }
        }
    }
}
