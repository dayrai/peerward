#[component]
fn ConsoleAccessGrant(
    mesh: String,
    locale: Locale,
    csrf: Option<String>,
    initial_source: String,
    initial_resource: Option<peerward_api::ConsoleSharingResource>,
    on_change: EventHandler<()>,
) -> Element {
    let mut query = use_signal(String::new);
    let mut cursor = use_signal(String::new);
    let mut selected = use_signal(|| initial_resource);
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params.append_pair("q", &query()).append_pair("limit", "50");
    if !cursor().is_empty() { params.append_pair("cursor", &cursor()); }
    let resources = use_console_query::<Page<peerward_api::ConsoleSharingResource>>(
        format!("/api/v1/meshes/{mesh}/console/sharing?{}", params.finish()),
    );
    rsx! {
        div { class:"console-form access-grant-picker",
            label { r#for:"grant-share-search", {console_text(locale,"搜索共享","Search shares")} }
            input { id:"grant-share-search", value:query, oninput:move |e| { query.set(e.value()); cursor.set(String::new()); } }
            label { r#for:"grant-share", {console_text(locale,"允许访问哪个共享","Allow access to which share")} }
            select { id:"grant-share", value:selected().map(|r|r.id.to_string()).unwrap_or_default(), "data-console-selection":"true",
                onchange:move |e| {
                    let value=e.value();
                    selected.set(resources.read().as_ref().and_then(|r|r.as_ref().ok())
                        .and_then(|page|page.items.iter().find(|r|r.id.to_string()==value).cloned()));
                },
                option { value:"", {console_text(locale,"请选择共享","Select a share")} }
                if let Some(current) = selected() {
                    if !resources.read().as_ref().and_then(|r|r.as_ref().ok()).is_some_and(|page| page.items.iter().any(|r|r.id==current.id)) {
                        option { value:"{current.id}", selected:true, "{current.name}" }
                    }
                }
                if let Some(Ok(page)) = resources.read().as_ref() {
                    for resource in &page.items { option { value:"{resource.id}", selected:selected().is_some_and(|r|r.id==resource.id), "{resource.name}" } }
                }
            }
            {console_picker_feedback(resources, false, locale)}
            if let Some(Ok(page)) = resources.read().as_ref() {
                if let Some(next) = page.next_cursor.clone() {
                    button { class:"secondary-button", onclick:move |_| cursor.set(next.clone()), {console_text(locale,"更多共享","More shares")} }
                }
            }
            if !cursor().is_empty() { button { class:"secondary-button", onclick:move |_| cursor.set(String::new()), {console_text(locale,"第一页","First page")} } }
        }
        if let Some(resource) = selected() {
            ConsoleSharingAccess { key:"{resource.id}", mesh, resource, locale, csrf, can_write:true, initial_source,
                on_change:move |()| on_change.call(()) }
        }
    }
}

#[component]
fn ConsoleAccessRules(mesh: String, locale: Locale) -> Element {
    let data = use_console_query::<PolicyPutRequest>(format!("/api/v1/meshes/{mesh}/policy"));
    let mut document = use_signal(String::new);
    use_effect(move || {
        if let Some(Ok(policy)) = data.read().as_ref() { document.set(policy_editor_document(policy)); }
    });
    rsx! {
        div { class:"access-rule-summary",
            if let Some(Ok(policy)) = data.read().as_ref() {
                if policy.rules.is_empty() {
                    p { class:"muted", {console_text(locale,"尚无设备通信规则。需要设备互通时，可在下方配置。","No device communication rules. Configure device access below when needed.")} }
                } else {
                    PolicyRuleSummary { document, locale, disabled:true, mesh }
                }
            }
            {console_picker_feedback(data, false, locale)}
        }
    }
}
