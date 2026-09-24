#[component]
fn InteractiveConsole(
    route: ConsoleRoute,
    initial: ConsoleSnapshot,
    client_location: ConsoleClientRoute,
) -> Element {
    #[cfg(target_arch = "wasm32")]
    let route_navigator = use_navigator();
    use_future(move || async move {
        #[cfg(target_arch = "wasm32")]
        loop {
            gloo_timers::future::TimeoutFuture::new(30_000).await;
            *CONSOLE_QUERY_EPOCH.write() += 1;
        }
    });
    let initial_mesh = initial.mesh_id.clone();
    let (initial_route, initial_mesh_filter, initial_relay_filter) = client_location.parts();
    let initial_location =
        ConsoleLocation::new(initial_route, initial_mesh_filter, initial_relay_filter);
    #[allow(unused_mut)]
    let mut snapshot = use_signal(|| initial);
    let active_route = use_signal(|| route);
    let mut loaded_location = use_signal(|| initial_location);
    let generation = use_signal(|| 0_u64);
    #[allow(unused_mut)]
    let mut loading = use_signal(|| false);
    #[allow(unused_mut)]
    let mut status = use_signal(String::new);
    let mut name = use_signal(String::new);
    let mut document = use_signal(|| default_editor_document(route));
    let mut selected_mesh = use_signal(|| initial_mesh);
    let mut selected_resource = use_signal(String::new);
    let mut manual_mesh = use_signal(|| false);
    let mut confirmation = use_signal(String::new);
    #[allow(unused_mut)]
    let mut join_link = use_signal(String::new);
    #[allow(unused_mut)]
    let mut browser_ready = use_signal(|| false);
    #[allow(unused_mut)]
    let mut locale = use_signal(|| Locale::ZhCn);
    use_context_provider(|| locale);
    #[allow(unused_mut)]
    let mut theme = use_signal(Theme::default);
    #[allow(unused_mut)]
    let mut preferences_loaded = use_signal(|| false);
    use_effect(move || {
        #[cfg(target_arch = "wasm32")]
        {
            if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten())
            {
                locale.set(
                    if storage
                        .get_item("peerward.console.locale")
                        .ok()
                        .flatten()
                        .as_deref()
                        == Some("en-US")
                    {
                        Locale::EnUs
                    } else {
                        Locale::ZhCn
                    },
                );
                theme.set(
                    match storage
                        .get_item("peerward.console.theme")
                        .ok()
                        .flatten()
                        .as_deref()
                    {
                        Some("dark") => Theme::Dark,
                        Some("light") => Theme::Light,
                        _ => Theme::System,
                    },
                );
            }
            preferences_loaded.set(true);
        }
    });
    use_effect(move || {
        if preferences_loaded() {
            sync_document_preferences(locale(), theme());
        }
    });
    let can_write = snapshot.read().has_capability("resource_write");
    let mesh_active = snapshot
        .read()
        .meshes
        .iter()
        .find(|mesh| mesh.id == snapshot.read().mesh_id)
        .is_some_and(|mesh| {
            mesh.details
                .get("lifecycle")
                .and_then(Value::as_str)
                .unwrap_or("active")
                == "active"
        });
    let can_manage_trust = snapshot.read().has_capability("trust_manage");

    let requested_resource = match &client_location {
        ConsoleClientRoute::Peers { resource, .. }
        | ConsoleClientRoute::JoinTickets { resource, .. }
        | ConsoleClientRoute::Services { resource, .. }
        | ConsoleClientRoute::Policy { resource, .. } => resource
            .as_deref()
            .and_then(|id| uuid::Uuid::parse_str(id).ok())
            .map(|id| id.to_string())
            .unwrap_or_default(),
        _ => String::new(),
    };
    let requested_source = match &client_location {
        ConsoleClientRoute::Policy { source, .. } => source
            .as_deref()
            .filter(|value| parse_console_source(value).is_some())
            .unwrap_or_default()
            .to_owned(),
        _ => String::new(),
    };
    use_interactive_navigation(
        client_location,
        &InteractiveNavigation {
            snapshot,
            active_route,
            loaded_location,
            generation,
            selected_mesh,
            selected_resource,
            name,
            document,
            confirmation,
            join_link,
            status,
            locale,
            loading,
        },
    );

    use_interactive_events(
        &InteractiveNavigation {
            snapshot,
            active_route,
            loaded_location,
            generation,
            selected_mesh,
            selected_resource,
            name,
            document,
            confirmation,
            join_link,
            status,
            locale,
            loading,
        },
        browser_ready,
    );

    let mutate = use_interactive_mutation(
        route,
        &InteractiveNavigation {
            snapshot,
            active_route,
            loaded_location,
            generation,
            selected_mesh,
            selected_resource,
            name,
            document,
            confirmation,
            join_link,
            status,
            locale,
            loading,
        },
    );
    let required_confirmation = snapshot
        .read()
        .resources
        .iter()
        .find(|resource| resource.id == selected_resource.read().as_str())
        .map(|resource| resource.name.clone())
        .unwrap_or_default();
    let authority_certificate_ready = !editor_value(&document(), "certificate").is_empty();
    let selected_peer_disabled = route == ConsoleRoute::Peers
        && snapshot
            .read()
            .resources
            .iter()
            .find(|resource| resource.id == selected_resource.read().as_str())
            .and_then(|resource| resource.details.get("administrative_state"))
            .and_then(Value::as_str)
            == Some("disabled");
    let relay_rotation_ready = !editor_value(&document(), "public_key").is_empty();
    let credential_selected = !editor_value(&document(), "serial").is_empty();
    let resource_selected = !selected_resource.read().is_empty();
    let load_next_page = use_callback(move |cursor: String| {
        status.set(console_message(locale(), "loading-page").into());
        #[cfg(target_arch = "wasm32")]
        {
            let api = browser_api_client();
            let current = snapshot.read().clone();
            let mesh = current.mesh_id.clone();
            let location = loaded_location.peek().clone();
            let page_generation = *generation.peek();
            loading.set(true);
            spawn(async move {
                match api
                    .route_resource_snapshot(route, &current, Some(&mesh), Some(&cursor))
                    .await
                {
                    Ok(value)
                        if snapshot.peek().mesh_id == mesh
                            && *loaded_location.peek() == location
                            && *generation.peek() == page_generation =>
                    {
                        let value = if route == ConsoleRoute::Peers {
                            append_resource_page(&current, value)
                        } else {
                            value
                        };
                        snapshot.set(value);
                        status.set(console_message(locale(), "page-loaded").into());
                    }
                    Err(error)
                        if *loaded_location.peek() == location
                            && *generation.peek() == page_generation =>
                    {
                        snapshot.write().error = Some(api_error_body(error));
                    }
                    Ok(_) | Err(_) => {}
                }
                if *loaded_location.peek() == location && *generation.peek() == page_generation {
                    loading.set(false);
                }
            });
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = cursor;
    });

    let select_resource = use_callback(move |selected: String| {
        selected_resource.set(selected.clone());
        confirmation.set(String::new());
        if let Some(resource) = snapshot
            .read()
            .resources
            .iter()
            .find(|resource| resource.id == selected)
            .cloned()
        {
            name.set(resource.name.clone());
            document.set(editor_document_for_resource(route, &resource));
        } else {
            name.set(String::new());
            document.set(default_editor_document(route));
        }
    });
    let mut initialized_settings = use_signal(String::new);
    use_effect(use_reactive((&route,), move |(route,)| {
        if route != ConsoleRoute::Meshes {
            if !initialized_settings.peek().is_empty() {
                initialized_settings.set(String::new());
            }
            return;
        }
        let mesh = selected_mesh();
        let current = snapshot.read();
        if route == ConsoleRoute::Meshes
            && !mesh.is_empty()
            && *initialized_settings.peek() != mesh
            && current.resources.iter().any(|resource| resource.id == mesh)
        {
            drop(current);
            initialized_settings.set(mesh.clone());
            select_resource.call(mesh);
        }
    }));

    let show_action_panel = matches!(
        route,
        ConsoleRoute::Meshes
            | ConsoleRoute::Authorities
            | ConsoleRoute::Peers
            | ConsoleRoute::Relays
            | ConsoleRoute::JoinTickets
            | ConsoleRoute::Policy
            | ConsoleRoute::Services
    ) && (can_write
        || can_manage_trust
        || (route == ConsoleRoute::Policy && snapshot.read().has_capability("resource_read")));
    let baseline = snapshot
        .read()
        .resources
        .iter()
        .find(|r| r.id == selected_resource())
        .cloned();
    let editor_dirty = if let Some(resource) = baseline {
        name() != resource.name || document() != editor_document_for_resource(route, &resource)
    } else {
        !name().is_empty() || document() != default_editor_document(route)
    };
    let maintenance_path = if selected_mesh().is_empty() {
        "/relays".to_owned()
    } else {
        format!("/relays?mesh={}", selected_mesh())
    };
    let resource_extras = rsx! {
        if route == ConsoleRoute::Operations && can_manage_trust {
            OperationsStatusPanel {locale:locale(),maintenance_path:maintenance_path.clone(),compact:true,ready:browser_ready()}
        }
        if route == ConsoleRoute::Relays && can_manage_trust {
            OperationsStatusPanel {locale:locale(),maintenance_path:maintenance_path.clone(),ready:browser_ready()}
            div{class:"tool-sections system-maintenance-tools",
                details{class:"card advanced-tools",id:"capacity-tools",summary{strong{{console_text(locale(),"Relay 容量与观测","Relay capacity and observations")}}small{{console_text(locale(),"负载、通道与采样时间","Load, carriers and sample times")}}}CapacityPanel{locale:locale(),ready:browser_ready()}}
                details{class:"card advanced-tools",id:"maintenance-tools",summary{strong{{console_text(locale(),"维护与替换","Maintenance and replacement")}}small{{console_text(locale(),"预览影响后执行","Preview impact before execution")}}}MaintenancePanel{csrf:snapshot.read().csrf_token.clone(),locale:locale(),ready:browser_ready()}}
                details{class:"card advanced-tools",id:"deployment-tools",summary{strong{{console_text(locale(),"备份与升级","Backups and upgrades")}}small{{console_text(locale(),"任务、结果与恢复指引","Tasks, results and recovery guidance")}}}DeploymentPanel{csrf:snapshot.read().csrf_token.clone(),locale:locale(),ready:browser_ready()}}
            }
        }
        if route == ConsoleRoute::Authorities && can_manage_trust {
            details{class:"card advanced-tools",summary{{console_text(locale(),"自动化凭证","Automation credentials")}}MachineCredentialsPanel { mesh:selected_mesh(),csrf:snapshot.read().csrf_token.clone(),locale:locale(),ready:browser_ready() }}
            details{class:"card advanced-tools",summary{{console_text(locale(),"配置管理权","Configuration ownership")}}ConfigurationOwnershipPanel { mesh:selected_mesh(),csrf:snapshot.read().csrf_token.clone(),locale:locale(),ready:browser_ready() }}
        }
        if route == ConsoleRoute::Webhooks && snapshot.read().has_capability("resource_read") {
            WebhooksPanel { mesh:selected_mesh(),csrf:snapshot.read().csrf_token.clone(),locale:locale(),can_manage:can_manage_trust,ready:browser_ready() }
            details{class:"card advanced-tools",id:"configuration-tools",summary{{console_text(locale(),"配置管理：导入、导出与变更预览","Configuration: import, export and preview")}}ConfigurationPanel { mesh:selected_mesh(),csrf:snapshot.read().csrf_token.clone(),locale:locale(),can_write,ready:browser_ready() }}
        }
        if route == ConsoleRoute::Peers && snapshot.read().has_capability("resource_read") {
            JoinApplicationPanel{mesh:selected_mesh(),csrf:snapshot.read().csrf_token.clone(),can_write,locale:locale(),ready:browser_ready()}
        }
        if matches!(route,ConsoleRoute::Meshes | ConsoleRoute::Networks) && snapshot.read().has_capability("resource_read") {
            if route == ConsoleRoute::Networks || selected_mesh().is_empty() {
                ConsoleNetworksPanel { snapshot, locale:locale(), ready:browser_ready() }
            } else {
                ConsoleNetworkSettings { key:"{selected_mesh}", mesh:selected_mesh(), snapshot, locale:locale(), ready:browser_ready(), on_saved:move |saved:MeshResource|{name.set(saved.name.clone());document.set(editor_document_for_resource(ConsoleRoute::Meshes,&saved.into()));} }
            }
        }
        if route == ConsoleRoute::Policy && snapshot.read().has_capability("resource_read") {
            ResourcePolicyPanel { mesh:selected_mesh(),csrf:snapshot.read().csrf_token.clone(),can_write,locale:locale(),ready:browser_ready() }
            CollectionPanel { mesh:selected_mesh(),csrf:snapshot.read().csrf_token.clone(),can_write,locale:locale(),ready:browser_ready() }
        }
        if route == ConsoleRoute::Services && snapshot.read().has_capability("resource_read") {
            NetworkPanel { mesh:selected_mesh(), csrf:snapshot.read().csrf_token.clone(), can_write, locale:locale(),ready:browser_ready() }
            AutoApprovalPanel { mesh:selected_mesh(),csrf:snapshot.read().csrf_token.clone(),can_write,locale:locale(),ready:browser_ready() }
        }
        if route == ConsoleRoute::Peers {
            if let Some(resource) = snapshot.read().resources.iter().find(|peer| peer.id == selected_resource()).cloned() {
                PeerDetails { resource, locale: locale() }
            }
        }
        if route == ConsoleRoute::Peers {
            if let Some(cursor) = snapshot.read().next_cursor.clone() {
                section { class: "card pagination-actions",
                    button {
                        r#type: "button",
                        disabled: !browser_ready() || loading(),
                        onclick: move |_| load_next_page.call(cursor.clone()),
                        {console_message(locale(), "next-page")}
                    }
                }
            }
        }
        if can_write && bulk_family(route).is_some() && route != ConsoleRoute::JoinTickets && !snapshot.read().mesh_id.is_empty() && !snapshot.read().resources.is_empty() {
            BulkActions { route, snapshot, loading, status, locale: locale() }
        }
    };
    let action_panel = rsx! {
        if !join_link().is_empty() {
            JoinSecretCard { link: join_link(), locale: locale() }
        }
        if show_action_panel {
        section {
            class: "card action-panel",
            "data-console-dirty":editor_dirty.to_string(),
            aria_label: console_message(locale(), "resource-actions"),
            "data-browser-ready": if browser_ready() { "true" } else { "false" },
            h2 { {format!("{} {}", console_message(locale(), "manage"), localized_route(locale(), route))} }
            if loading() { p { role: "status", aria_live: "polite", {console_message(locale(), "loading")} } }
            if !status().is_empty() { p { role: "status", aria_live: "polite", "{status}" } }
            div { class: "action-panel-primary-grid",
                div { class: "form-field", hidden: snapshot.read().meshes.len() == 1,
                    label { r#for: "live-mesh-selection", {console_message(locale(), "mesh")} }
                    select {
                        id: "live-mesh-selection",
                        value: "{selected_mesh}",
                        disabled: !browser_ready() || loading(),
                        onchange: move |event| {
                            let mesh = event.value();
                            selected_mesh.set(mesh.clone());
                            selected_resource.set(String::new());
                            confirmation.set(String::new());
                            #[cfg(target_arch = "wasm32")]
                            {
                                route_navigator.replace(
                                    ConsoleClientRoute::from_console_route(
                                        route,
                                        (!mesh.is_empty()).then_some(mesh),
                                        None,
                                    )
                                    .href(),
                                );
                            }
                        },
                        option { value: "", selected: selected_mesh.read().is_empty(), {console_message(locale(), "select-mesh")} }
                        for mesh in snapshot.read().meshes.clone() {
                            option { value: "{mesh.id}", selected: selected_mesh.read().as_str() == mesh.id, "{mesh.name}" }
                        }
                    }
                }
                div { class: "form-field",
                    label { r#for: "live-resource-selection", {console_message(locale(), "resource")} }
                    select {
                        id: "live-resource-selection",
                        value: "{selected_resource}",
                        disabled: !browser_ready() || loading() || snapshot.read().resources.is_empty(),
                        onchange: move |event| select_resource.call(event.value()),
                        option {
                            value: "",
                            selected: selected_resource.read().is_empty(),
                            {console_message(locale(), if route == ConsoleRoute::JoinTickets { "new-join-ticket" } else { "select-resource" })}
                        }
                        for resource in snapshot.read().resources.clone() {
                            option { value: "{resource.id}", selected: selected_resource.read().as_str() == resource.id, "{resource.name}" }
                        }
                    }
                }
                if matches!(route, ConsoleRoute::Meshes | ConsoleRoute::Peers | ConsoleRoute::Relays) {
                    div { class: "form-field",
                        label { r#for: "live-resource-name", {console_message(locale(), "name")} }
                        input {
                            id: "live-resource-name",
                            value: "{name}",
                            oninput: move |event| name.set(event.value()),
                            disabled: !browser_ready() || loading(),
                        }
                    }
                }
            }
            if route == ConsoleRoute::Meshes {
                label {
                    input { r#type: "checkbox", checked: manual_mesh(),
                        onchange: move |event| manual_mesh.set(event.checked()) }
                    {console_message(locale(), "mesh-manual-mode")}
                }
                if can_manage_trust {
                    MeshProvisioningPanel {
                        snapshot, name, selected: selected_resource(), automatic: !manual_mesh(), locale: locale(),
                        on_complete: move |mesh: String| {
                            selected_mesh.set(mesh.clone());
                            selected_resource.set(mesh.clone());
                            if let Some(resource) = snapshot.read().resources.iter().find(|resource| resource.id == mesh) {
                                name.set(resource.name.clone());
                                document.set(editor_document_for_resource(ConsoleRoute::Meshes, resource));
                            }
                            loaded_location.set(ConsoleLocation::new(ConsoleRoute::Meshes, Some(mesh.clone()), None));
                            #[cfg(target_arch = "wasm32")]
                            route_navigator.replace(ConsoleClientRoute::Meshes { mesh: Some(mesh) }.href());
                        },
                    }
                }
            }
            if !selected_resource.read().is_empty() &&
                (matches!(route, ConsoleRoute::Peers | ConsoleRoute::Relays | ConsoleRoute::Authorities | ConsoleRoute::Services | ConsoleRoute::JoinTickets) || (route == ConsoleRoute::Meshes && can_manage_trust)) {
                p { class: "risk-preview", role: "note", {console_message(locale(), if route == ConsoleRoute::Meshes { "delete-mesh-help" } else { "high-risk-impact" })} }
                label { r#for: "high-risk-confirmation", {console_message(locale(), if route == ConsoleRoute::Authorities { "confirm-certificate-serial" } else { "confirm-resource-name" })} }
                input {
                    id: "high-risk-confirmation",
                    value: "{confirmation}",
                    placeholder: "{required_confirmation}",
                    autocomplete: "off",
                    disabled: !browser_ready() || loading(),
                    oninput: move |event| confirmation.set(event.value()),
                }
                if route == ConsoleRoute::Peers {
                    p { id: "peer-delete-help", role: "note", {console_message(locale(), "delete-peer-help")} }
                }
            }
            if (route != ConsoleRoute::Peers || resource_selected) && (route != ConsoleRoute::Meshes || manual_mesh()) && (can_write || can_manage_trust ||
                (route == ConsoleRoute::Policy && snapshot.read().has_capability("resource_read"))) {
                div { class: if route == ConsoleRoute::Policy { "resource-editor" } else { "resource-editor resource-editor--compact" },
                    ResourceEditor {
                        route,
                        document,
                        existing:resource_selected,
                        lookups: snapshot.read().lookups.clone(),
                        disabled: !browser_ready() || loading() || (route == ConsoleRoute::JoinTickets && resource_selected) || (route == ConsoleRoute::Policy && !can_write),
                        locale: locale(),
                    }
                }
            }
            div { class: "actions",
                if route == ConsoleRoute::Authorities && can_manage_trust {
                    button { r#type: "button", disabled: create_action_disabled(!browser_ready() || loading(), resource_selected) || !authority_certificate_ready, onclick: move |_| mutate.call(BrowserOperation::Create), {console_message(locale(), "stage-authority")} }
                } else if (route == ConsoleRoute::Meshes && can_manage_trust && manual_mesh()) ||
                    (matches!(route, ConsoleRoute::Relays | ConsoleRoute::JoinTickets | ConsoleRoute::Services) && can_write) {
                    button { r#type: "button", disabled: create_action_disabled(!browser_ready() || loading(), resource_selected) || (route != ConsoleRoute::Meshes && !mesh_active), onclick: move |_| mutate.call(BrowserOperation::Create), {console_message(locale(), "create")} }
                }
                if can_write && (matches!(route, ConsoleRoute::Peers | ConsoleRoute::Relays) || (route == ConsoleRoute::Meshes && manual_mesh())) {
                    button { r#type: "button", disabled: !browser_ready() || loading() || selected_resource.read().is_empty(), onclick: move |_| mutate.call(BrowserOperation::Edit), {console_message(locale(), "edit-selected")} }
                }
                if (can_manage_trust && route == ConsoleRoute::Authorities) || (can_write && matches!(route, ConsoleRoute::Peers | ConsoleRoute::Relays | ConsoleRoute::JoinTickets | ConsoleRoute::Services)) {
                    button {
                        r#type: "button",
                        disabled: !browser_ready() || loading() || selected_resource.read().is_empty() ||
                            (route == ConsoleRoute::Peers && selected_peer_disabled) ||
                            (route==ConsoleRoute::JoinTickets && snapshot.read().resources.iter().find(|r|r.id==selected_resource()).is_none_or(|r|!matches!(r.details.get("status").and_then(Value::as_str),Some("unused"|"pending")))) ||
                            (matches!(route, ConsoleRoute::Peers | ConsoleRoute::Relays | ConsoleRoute::Authorities | ConsoleRoute::Services | ConsoleRoute::JoinTickets) && confirmation.read().as_str() != required_confirmation.as_str()),
                        onclick: move |_| mutate.call(BrowserOperation::Delete),
                        {console_message(locale(), "disable-revoke")}
                    }
                }
                if route == ConsoleRoute::Meshes && can_manage_trust {
                    button {
                        r#type: "button",
                        disabled: !browser_ready() || loading() || !resource_selected || confirmation.read().as_str() != required_confirmation.as_str(),
                        onclick: move |_| mutate.call(BrowserOperation::DeleteMesh),
                        {console_message(locale(), "delete-mesh")}
                    }
                }
                if route == ConsoleRoute::Peers && can_write {
                    button {
                        r#type: "button",
                        aria_describedby: resource_selected.then_some("peer-delete-help"),
                        disabled: !browser_ready() || loading() || !selected_peer_disabled || confirmation.read().as_str() != required_confirmation.as_str(),
                        onclick: move |_| mutate.call(BrowserOperation::DeletePeer),
                        {console_message(locale(), "delete-peer")}
                    }
                }
                if route == ConsoleRoute::Authorities && can_manage_trust {
                    button { r#type: "button", disabled: !browser_ready() || loading() || selected_resource.read().is_empty() || confirmation.read().as_str() != required_confirmation.as_str(), onclick: move |_| mutate.call(BrowserOperation::ActivateAuthority), {console_message(locale(), "activate-authority")} }
                }
                if can_write && matches!(route, ConsoleRoute::Peers | ConsoleRoute::Relays) {
                    if route == ConsoleRoute::Relays {
                        button { r#type: "button", disabled: !browser_ready() || loading() || selected_resource.read().is_empty() || !relay_rotation_ready, onclick: move |_| mutate.call(BrowserOperation::Rotate), {console_message(locale(), "rotate-credential")} }
                    }
                    if route != ConsoleRoute::Relays || can_manage_trust {
                    button { r#type: "button", disabled: !browser_ready() || loading() || selected_resource.read().is_empty() || !credential_selected || confirmation.read().as_str() != required_confirmation.as_str(), onclick: move |_| mutate.call(BrowserOperation::ActivateCredential), {console_message(locale(), "activate-credential")} }
                    button { r#type: "button", disabled: !browser_ready() || loading() || selected_resource.read().is_empty() || !credential_selected || confirmation.read().as_str() != required_confirmation.as_str(), onclick: move |_| mutate.call(BrowserOperation::RevokeCredential), {console_message(locale(), "revoke-credential")} }
                    }
                }
                if route == ConsoleRoute::Policy && can_write {
                    button { r#type: "button", disabled: !browser_ready() || loading(), onclick: move |_| mutate.call(BrowserOperation::ValidatePolicy), {console_message(locale(), "validate-policy")} }
                    button { r#type: "button", disabled: !browser_ready() || loading(), onclick: move |_| mutate.call(BrowserOperation::ReplacePolicy), {console_message(locale(), "replace-policy")} }
                }
                if route == ConsoleRoute::Policy && snapshot.read().has_capability("resource_read") {
                    button { r#type: "button", disabled: !browser_ready() || loading() || snapshot.read().mesh_id.is_empty(), onclick: move |_| mutate.call(BrowserOperation::SimulatePolicy), {console_message(locale(), "simulate-policy")} }
                }
                if route != ConsoleRoute::Peers {
                if let Some(cursor) = snapshot.read().next_cursor.clone() {
                    button {
                        r#type: "button",
                        disabled: !browser_ready() || loading(),
                        onclick: move |_| load_next_page.call(cursor.clone()),
                        {console_message(locale(), "next-page")}
                    }
                }
                }
            }
            if resource_selected {
                p {
                    class: "muted",
                    role: "note",
                    {console_message(locale(), if route == ConsoleRoute::JoinTickets { "select-new-join-ticket-to-create" } else { "clear-selection-to-create" })}
                }
            }
        }
        }
        if route == ConsoleRoute::JoinTickets && can_write && !snapshot.read().mesh_id.is_empty() && !snapshot.read().resources.is_empty() {
            BulkActions { route, snapshot, loading, status, locale: locale() }
        }
    };

    rsx! {
        ConsoleApp {
            route,
            snapshot: snapshot.read().clone(),
            locale,
            theme,
            show_action_panel,
            action_panel,
            resource_extras,
            client_routing: true,
            requested_resource,
            requested_source,
        }
    }
}
