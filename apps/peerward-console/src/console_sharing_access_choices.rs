#[component]
#[allow(unused_mut)]
fn SharingAccessChoices(
    locale: Locale, disabled: bool, mut source: Signal<String>, mut source_query: Signal<String>,
    mut source_cursor: Signal<String>, mut group_cursor: Signal<String>,
    sources: Resource<Result<peerward_api::ConsoleDevicePage, String>>,
    groups: Resource<Result<Page<peerward_api::ConsoleSearchItem>, String>>,
) -> Element {
    let next_source = sources.read().as_ref().and_then(|r| r.as_ref().ok()).and_then(|p| p.next_cursor.clone());
    let next_group = groups.read().as_ref().and_then(|r| r.as_ref().ok()).and_then(|p| p.next_cursor.clone());
    let count = sources.read().as_ref().and_then(|r| r.as_ref().ok()).map_or(0, |p| p.items.len())
        + groups.read().as_ref().and_then(|r| r.as_ref().ok()).map_or(0, |p| p.items.len());
    rsx! {
        div { class: "workflow-note",
            strong { {console_text(locale, "再决定“谁可以访问”", "Then decide who can access")} }
            p { {console_text(locale, "访问授权和共享类型是两件事；没有明确授权时默认阻止。", "Access permission is separate from share type; access without an explicit grant is blocked.")} }
        }
        fieldset { class: "sharing-access-choices", disabled,
            legend { class: "sr-only", {console_text(locale, "谁可以访问", "Who can access")} }
            if count > 8 || next_source.is_some() || next_group.is_some() || !source_query().is_empty() || !source_cursor().is_empty() || !group_cursor().is_empty() {
                label { r#for: "share-source-search", {console_text(locale, "查找设备或设备组", "Find devices or groups")}
                    input { id: "share-source-search", value: source_query, oninput: move |e| { source_query.set(e.value()); source_cursor.set(String::new()); group_cursor.set(String::new()); source.set(String::new()); } }
                }
            }
            div { class: "sharing-access-cards",
                if let Some(Ok(page)) = groups.read().as_ref() {
                    for group in page.items.iter() {
                        label { class: "sharing-access-card", key: "group-{group.id}",
                            input { r#type: "radio", name: "share-source", value: "group:{group.id}", checked: source() == format!("group:{}", group.id),
                                aria_label: group.name.clone(), onchange: { let id = group.id; move |_| source.set(format!("group:{id}")) },
                            }
                            span { strong { "{group.name}" } small { {console_text(locale, "授权给此设备组，成员变化会更新授权", "Grant this device group; membership changes update access")} } }
                        }
                    }
                }
                if let Some(Ok(page)) = sources.read().as_ref() {
                    for peer in page.items.iter().filter(|p| p.administrative_state == peerward_api::AdministrativeState::Enabled) {
                        label { class: "sharing-access-card", key: "peer-{peer.id}",
                            input { r#type: "radio", name: "share-source", value: "peer:{peer.id}", checked: source() == format!("peer:{}", peer.id),
                                aria_label: if peer.display_name.is_empty() { peer.name.clone() } else { peer.display_name.clone() },
                                onchange: { let id = peer.id; move |_| source.set(format!("peer:{id}")) },
                            }
                            span {
                                strong { if peer.display_name.is_empty() { "{peer.name}" } else { "{peer.display_name}" } }
                                small { {console_text(locale, "直接授权给这一台设备", "Grant access directly to this device")} }
                            }
                        }
                    }
                }
                label { class: "sharing-access-card",
                    input { r#type: "radio", name: "share-source", value: "", checked: source().is_empty(), aria_label: console_text(locale, "暂不新增授权", "No new grant"), onchange: move |_| source.set(String::new()) }
                    span {
                        strong { {console_text(locale, "暂不新增授权", "No new grant")} }
                        small { {console_text(locale, "先保存共享，稍后再授权；现有规则仍生效", "Save now and grant access later; existing rules still apply")} }
                    }
                }
            }
            {console_picker_feedback(sources, false, locale)}
            {console_picker_feedback(groups, false, locale)}
            if let Some(next) = next_group { button { r#type: "button", class: "secondary-button", onclick: move |_| { group_cursor.set(next.clone()); source.set(String::new()); }, {console_text(locale, "更多设备组", "More groups")} } }
            if let Some(next) = next_source { button { r#type: "button", class: "secondary-button", onclick: move |_| { source_cursor.set(next.clone()); source.set(String::new()); }, {console_text(locale, "更多来源设备", "More devices")} } }
            if !source_cursor().is_empty() || !group_cursor().is_empty() {
                button { r#type: "button", class: "secondary-button", onclick: move |_| { source_cursor.set(String::new()); group_cursor.set(String::new()); source.set(String::new()); }, {console_text(locale, "返回首页", "First page")} }
            }
        }
        div { class: "security-note compact-security-note",
            span { aria_hidden: "true", "✓" }
            p { strong { {console_text(locale, "默认拒绝仍然生效。", "Default deny remains in effect. ")} }
                {console_text(locale, "共享创建成功不代表所有设备自动获得访问权。", "Creating a share does not automatically grant access to every device.")}
            }
        }
    }
}
