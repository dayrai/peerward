#[component]
fn EnrollmentGroups(
    mesh: String,
    locale: Locale,
    mut selected: Signal<std::collections::BTreeSet<uuid::Uuid>>,
    disabled: bool,
) -> Element {
    let mut data = use_console_query::<Vec<peerward_api::ConsoleEnrollmentGroup>>(format!(
        "/api/v1/meshes/{mesh}/console/enrollment-groups"
    ));
    let observed = data
        .read()
        .as_ref()
        .and_then(|value| value.as_ref().ok())
        .cloned();
    rsx! {
        fieldset { class: "enrollment-groups", disabled,
            legend { {console_text(locale, "设备组（可选，可多选）", "Device groups (optional, multiple)")} }
            if let Some(groups) = observed {
                if groups.is_empty() {
                    p { class: "field-help", {console_text(locale, "暂无设备组。可先不分组，加入后从“设备 → 设备组”创建和分配。", "No device groups yet. Continue without a group, then create and assign groups from Devices → Device groups.")} }
                } else {
                    div { class: "enrollment-group-options",
                        for group in groups.iter() {
                            {let id = group.id; rsx! {
                                label { class: "enrollment-group-option",
                                    input { r#type: "checkbox", name: "device_groups", value: "{id}",
                                        checked: selected().contains(&id),
                                        onchange: move |event| {
                                            if event.checked() { selected.write().insert(id); }
                                            else { selected.write().remove(&id); }
                                        },
                                    }
                                    span { "{group.name}" }
                                }
                            }}
                        }
                    }
                    if selected().is_empty() {
                        p { class: "field-help", {console_text(locale, "默认不分组，加入后仍可修改。", "No groups selected by default; you can change membership after enrollment.")} }
                    } else {
                        div { class: "enrollment-group-access", aria_live: "polite",
                            strong { {console_text(locale, "所选组的当前授权", "Current grants for selected groups")} }
                            for group in groups.iter().filter(|group| selected().contains(&group.id)) {
                                div { class: "enrollment-group-grants",
                                    b { "{group.name}" }
                                    if group.grants.is_empty() {
                                        p { {console_text(locale, "该组暂无已启用的共享授权。", "This group has no enabled sharing grants.")} }
                                    } else {
                                        ul {
                                            for grant in &group.grants {
                                                li {
                                                    "{grant.name} · "
                                                    {enrollment_grant_scope(grant, locale)}
                                                    if grant.conditional {
                                                        " · " {console_text(locale, "附加条件", "Additional conditions")}
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            p { class: "field-help", {console_text(locale, "入网成功后自动加入所选组，并适用届时的访问规则。这里展示现有允许规则，实际访问仍受附加条件、拒绝规则和共享状态限制。", "Successful enrollment adds the device to these groups and applies the rules current at that time. These are existing allow rules; actual access also depends on conditions, deny rules and sharing status.")} }
                        }
                    }
                }
            } else if let Some(Err(error)) = data.read().as_ref() {
                if !error.is_empty() {
                    p { role: "alert", "{error}" }
                    button { r#type: "button", class: "secondary-button", onclick: move |_| data.restart(),
                        {console_text(locale, "重新加载设备组", "Reload device groups")}
                    }
                }
            } else {
                p { role: "status", {console_text(locale, "正在加载设备组…", "Loading device groups…")} }
            }
        }
    }
}

fn enrollment_grant_scope(grant: &peerward_api::ConsoleEnrollmentGrant, locale: Locale) -> String {
    let protocol = match grant.protocol {
        6 => "TCP",
        17 => "UDP",
        1 => "ICMP",
        58 => "ICMPv6",
        _ => console_text(locale, "全部协议", "All protocols"),
    };
    let ports = grant
        .destination_ports
        .iter()
        .map(|(start, end)| {
            if start == end {
                start.to_string()
            } else {
                format!("{start}–{end}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    if ports.is_empty() {
        protocol.to_owned()
    } else {
        format!("{protocol} {ports}")
    }
}
