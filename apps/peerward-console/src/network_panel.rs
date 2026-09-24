#[component]
#[allow(unused_mut, unused_variables)]
fn NetworkPanel(
    mesh: String,
    csrf: Option<String>,
    can_write: bool,
    locale: Locale,
    #[props(default)] ready: bool,
) -> Element {
    let mut active_mesh = use_signal(|| mesh.clone());
    let mut mesh_generation = use_signal(|| 0_u64);
    let mut data = use_signal(|| None::<NetworkPanelData>);
    let mut draft = use_signal(NetworkDraft::default);
    let mut drafts = use_signal(BTreeMap::<String, NetworkDraft>::new);
    let mut busy = use_signal(|| false);
    let mut message = use_signal(String::new);
    let mut error = use_signal(|| None::<ApiErrorBody>);
    let mut search = use_signal(String::new);
    let mut provider = use_signal(String::new);
    let mut binding_id = use_signal(uuid::Uuid::new_v4);
    let mut preserve = use_signal(|| false);
    let mut priority = use_signal(|| "100".to_owned());
    let mut return_confirmed = use_signal(|| false);
    let mut confirmation = use_signal(String::new);
    let mut observation = use_signal(|| None::<Value>);
    let reload = use_callback(move |cursor: Option<String>| {
        #[cfg(target_arch = "wasm32")]
        {
            if *busy.peek() {
                return;
            }
            let mesh = active_mesh.peek().clone();
            let generation = *mesh_generation.peek();
            if mesh.is_empty() {
                return;
            }
            busy.set(true);
            error.set(None);
            spawn(async move {
                let result = browser_api_client()
                    .network_panel(&mesh, cursor.as_deref())
                    .await;
                if *active_mesh.peek() != mesh || *mesh_generation.peek() != generation {
                    return;
                }
                match result {
                    Ok(mut value) => {
                        if cursor.is_some()
                            && let Some(previous) = data.peek().as_ref()
                        {
                            let known: HashSet<_> = previous
                                .resources
                                .iter()
                                .map(|resource| resource.id)
                                .collect();
                            value
                                .resources
                                .retain(|resource| !known.contains(&resource.id));
                            value.resources.splice(0..0, previous.resources.clone());
                        }
                        data.set(Some(value));
                    }
                    Err(failure) => error.set(Some(api_error_body(failure))),
                }
                busy.set(false);
            });
        }
    });
    use_effect(use_reactive((&mesh,), move |(mesh,)| {
        if *active_mesh.peek() != mesh {
            let next_generation = mesh_generation.peek().wrapping_add(1);
            mesh_generation.set(next_generation);
            drafts
                .write()
                .insert(active_mesh.peek().clone(), draft.peek().clone());
            draft.set(drafts.peek().get(&mesh).cloned().unwrap_or_default());
            active_mesh.set(mesh);
            data.set(None);
            busy.set(false);
            provider.set(String::new());
            confirmation.set(String::new());
            observation.set(None);
            message.set(String::new());
        }
        reload.call(None);
    }));
    let operate = use_callback(move |operation: NetworkOperation| {
        #[cfg(target_arch = "wasm32")]
        {
            if *busy.peek()
                || (!can_write
                    && !matches!(
                        operation,
                        NetworkOperation::Observe { .. } | NetworkOperation::TargetHealth { .. }
                    ))
            {
                return;
            }
            let mesh = active_mesh.peek().clone();
            let generation = *mesh_generation.peek();
            let mut api = browser_api_client();
            if let Some(csrf) = &csrf {
                api = api.with_csrf(csrf.clone());
            }
            let deleting = matches!(operation, NetworkOperation::Delete { .. });
            let saved = matches!(operation, NetworkOperation::Save(_));
            let observing = matches!(
                operation,
                NetworkOperation::Observe { .. } | NetworkOperation::TargetHealth { .. }
            );
            busy.set(true);
            error.set(None);
            message.set(String::new());
            spawn(async move {
                let result = api.network_operation(&mesh, operation).await;
                if *active_mesh.peek() != mesh || *mesh_generation.peek() != generation {
                    return;
                }
                match result {
                    Ok(value) => {
                        if observing {
                            observation.set(Some(value));
                        } else {
                            if saved
                                && let Ok(resource) = serde_json::from_value::<
                                    peerward_management::NetworkResource,
                                >(value)
                            {
                                draft.write().version = Some(resource.version);
                            }
                            if deleting {
                                draft.set(NetworkDraft::default());
                                confirmation.set(String::new());
                            }
                            message.set(console_message(locale, "network-saved").into());
                            match api.network_panel(&mesh, None).await {
                                Ok(value)
                                    if *active_mesh.peek() == mesh
                                        && *mesh_generation.peek() == generation =>
                                {
                                    data.set(Some(value));
                                }
                                Err(failure)
                                    if *active_mesh.peek() == mesh
                                        && *mesh_generation.peek() == generation =>
                                {
                                    error.set(Some(api_error_body(failure)));
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(failure) => error.set(Some(api_error_body(failure))),
                }
                if *active_mesh.peek() == mesh && *mesh_generation.peek() == generation {
                    busy.set(false);
                }
            });
        }
    });
    let peers = data
        .read()
        .as_ref()
        .map(|value| value.peers.clone())
        .unwrap_or_default();
    let bindings = data
        .read()
        .as_ref()
        .map(|value| {
            value
                .bindings
                .iter()
                .filter(|binding| binding.resource_id == draft.read().id)
                .cloned()
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    rsx! {
        section { class:"card network-management", aria_label:console_message(locale,"network-resources"),
            h2 { {console_message(locale,"network-resources")} }
            p { {console_message(locale,"network-resource-flow")} }
            if mesh.is_empty() { p { {console_message(locale,"mesh")} } }
            else {
                div { class:"action-panel-primary-grid",
                    label { {console_message(locale,"network-search")}
                        input { value:"{search}", oninput:move|event|search.set(event.value()) }
                    }
                    button { disabled:busy() || !ready,onclick:move|_|reload.call(None),{console_message(locale,"network-refresh")} }
                    if can_write {
                        button { disabled:busy() || !ready,onclick:move|_|{ draft.set(NetworkDraft::default()); provider.set(String::new()); confirmation.set(String::new()); binding_id.set(uuid::Uuid::new_v4()); },{console_message(locale,"network-new")} }
                    }
                }
                if busy() || !ready { p { role:"status",{console_message(locale,"loading")} } }
                if let Some(failure)=error() {
                    ErrorNotice { error:UiError { code:failure.code, message:failure.message,request_id:Some(failure.request_id),field_errors:failure.field_errors.clone(),retryable:failure.retryable } }
                    for (field,reason) in failure.field_errors { p { role:"alert","{field}: {reason}" } }
                }
                if !message().is_empty() { p { role:"status", aria_live:"polite","{message}" } }
                if let Some(value)=data() {
                    if value.resources.is_empty() { p { {console_message(locale,"network-empty")} } }
                    ul {
                        for resource in value.resources.iter().filter(|resource|resource.definition.name.to_lowercase().contains(&search().to_lowercase())) {
                            li { key:"{resource.id}",
                                button { disabled:busy() || !ready, onclick:{let resource=resource.clone(); move |_| {
                                        draft.set(NetworkDraft::from_resource(&resource));preserve.set(false);return_confirmed.set(false);
                                        provider.set(String::new()); confirmation.set(String::new()); observation.set(None);binding_id.set(uuid::Uuid::new_v4());
                                }},"{resource.definition.name}" }
                            }
                        }
                    }
                    if let Some(cursor)=value.next_cursor { button { disabled:busy() || !ready, onclick:move|_|reload.call(Some(cursor.clone())),{console_message(locale,"next-page")} } }
                }
                fieldset { disabled:busy() || !ready || !can_write,
                    legend { {console_message(locale,"network-target")} }
                    label { {console_message(locale,"name")} input { value:"{draft.read().name}",oninput:move|event|draft.write().name=event.value() } }
                    label {r#for:"network-target-kind",{console_message(locale,"network-target-kind")} }
                    select {id:"network-target-kind",value:"{draft.read().kind}",onchange:move|event|{draft.write().kind=event.value();preserve.set(false);return_confirmed.set(false);},
                        option {value:"subnet",{console_message(locale,"network-kind-subnet")} }
                        option {value:"internet_dual",{console_message(locale,"network-kind-exit-dual")} }
                        option {value:"internet_v4",{console_message(locale,"network-kind-exit-v4")} }
                        option {value:"internet_v6",{console_message(locale,"network-kind-exit-v6")} }
                    }
                    if draft.read().kind=="subnet" {
                    label { {console_message(locale,"network-address")} input { placeholder:"192.168.1.50",value:"{draft.read().prefix}",oninput:move|event|draft.write().prefix=event.value() } }
                    label { {console_message(locale,"network-site")} select { value:"{draft.read().site}", onchange:move|event|{ if let Ok(site)=uuid::Uuid::parse_str(&event.value()) { draft.write().site=site; } },
                        option { value:"{draft.read().site}",{console_message(locale,"network-current-site")} }
                        for resource in data.read().as_ref().map(|value|value.resources.clone()).unwrap_or_default() {
                            if let peerward_management::ResourceTarget::Subnet {site_id,..}=resource.definition.target { option { value:"{site_id}","{resource.definition.name}" } }
                        }
                    } }
                    } else {p { {console_message(locale,"network-exit-help")} } }
                    details { summary { {console_message(locale,"target-health-title")} }
                        p { {console_message(locale,"target-health-help")} }
                        label { {console_message(locale,"target-health-address")} input {value:"{draft.read().probe_address}",oninput:move|event|draft.write().probe_address=event.value()} }
                        label { {console_message(locale,"target-health-port")} input {value:"{draft.read().probe_port}",oninput:move|event|draft.write().probe_port=event.value()} }
                    }
                    if draft.read().version.is_some() { p { {console_message(locale,"network-change-impact")} } }
                    button { disabled:draft.read().definition().is_err(),onclick:move|_|operate.call(NetworkOperation::Save(draft.peek().clone())),{console_message(locale,"network-save-target")} }
                }
                if draft.read().version.is_some() {
                    fieldset { disabled:busy() || !ready || !can_write,
                        legend { {console_message(locale,"network-provider")} }
                        label { {console_message(locale,"network-provider")} select { value:"{provider}",onchange:move|event|{provider.set(event.value());binding_id.set(uuid::Uuid::new_v4());},
                            option { value:"",{console_message(locale,"network-select-device")} }
                            for peer in &peers { option {value:"{peer.id}","{peer.name}"} }
                        } }
                        label { {console_message(locale,"network-priority")} input { r#type:"number",min:"0",max:"4294967295",value:"{priority}",oninput:move|event|{priority.set(event.value());binding_id.set(uuid::Uuid::new_v4());} } }
                        p { {console_message(locale,"network-ha-help")} }
                        if draft.read().kind=="subnet" { label { input { r#type:"checkbox",checked:preserve(),onchange:move|event|{preserve.set(event.checked());return_confirmed.set(false);binding_id.set(uuid::Uuid::new_v4());} } {console_message(locale,"network-preserve-source")} } }
                        if preserve() { label { input {r#type:"checkbox",checked:return_confirmed(),onchange:move|event|{return_confirmed.set(event.checked());binding_id.set(uuid::Uuid::new_v4());}} {console_message(locale,"network-return-confirmed")} } }
                        button {disabled:provider().is_empty() || priority().parse::<u32>().is_err() || (preserve() && !return_confirmed()),onclick:move|_|{if let Ok(peer)=uuid::Uuid::parse_str(&provider()) {operate.call(NetworkOperation::Bind{id:binding_id(),resource:draft.read().id,peer,preserve:preserve(),confirmed:return_confirmed(),priority:priority().parse().unwrap_or(100)});}},{console_message(locale,"network-bind")} }
                    }
                    for binding in bindings {
                        div { class:"card",key:"{binding.id}",
                            p { {peers.iter().find(|peer|peer.id==binding.peer_id).map_or_else(||console_message(locale,"network-device-unavailable").into(),|peer|peer.name.clone())} }
                            BindingPriority { binding:binding.clone(), locale, disabled:busy() || !ready || !can_write,
                                on_save:move|priority|operate.call(NetworkOperation::Priority{id:binding.id,version:binding.version,priority}) }

                            p { {console_message(locale,if binding.approved {"network-approved"}else{"network-awaiting-approval"})} }
                            p { {console_message(locale,if matches!(binding.approval_source,peerward_management::ApprovalSource::Automatic{..}) {"auto-approval-source"}else{"auto-approval-manual"})} }
                            if let peerward_management::ApprovalSource::Automatic{rule_id,rule_version}=binding.approval_source {
                                details{summary{{console_message(locale,"auto-approval-evidence")}}p{"{rule_id} · {rule_version}"}}
                            }
                            p { {console_message(locale,"network-approval-impact")} }
                            if can_write { button {disabled:busy() || !ready,onclick:move|_|operate.call(NetworkOperation::Approve{id:binding.id,version:binding.version,approved:!binding.approved}),{console_message(locale,if binding.approved {"network-withdraw"}else{"network-approve"})} } }
                            if can_write && !binding.approved && binding.forwarding==peerward_management::ForwardingMode::Snat && draft.read().kind=="subnet" {
                                p{{console_message(locale,"auto-approval-request-impact")}}
                                button{disabled:busy()||!ready,onclick:move|_|operate.call(NetworkOperation::Automatic{id:binding.id,version:binding.version}),{console_message(locale,"auto-approval-request")}}
                            }
                            button {disabled:busy() || !ready,onclick:move|_|operate.call(NetworkOperation::Observe{peer:binding.peer_id.into_uuid()}),{console_message(locale,"network-check-applied")} }
                        }
                    }
                p { a { href:ConsoleClientRoute::Policy{mesh:Some(mesh.clone()),resource:None,source:None}.href(),{console_message(locale,"network-set-access")} } }
                    p { {console_message(locale,"network-verify-help")} }
                    button { disabled:busy() || !ready,onclick:move|_|operate.call(NetworkOperation::TargetHealth {resource:draft.read().id}),{console_message(locale,"target-health-refresh")} }
                    if let Some(value)=observation() {
                        if value.get("bindings").is_some() { TargetHealthObservation {value,locale} }
                        else {NetworkObservation { value,locale }}
                    }
                    if can_write { details {
                        summary { {console_message(locale,"network-delete")} }
                        p { {console_message(locale,"network-delete-impact")} }
                        label { {console_message(locale,"name")} input { value:"{confirmation}",oninput:move|event|confirmation.set(event.value()) } }
                        button { disabled:busy() || !ready || confirmation()!=draft.read().name,onclick:move|_|{if let Some(version)=draft.read().version {operate.call(NetworkOperation::Delete{id:draft.read().id,version});}},{console_message(locale,"network-delete")} }
                    } }
                }
            }
        }
    }
}

#[component]
fn NetworkObservation(value: Value, locale: Locale) -> Element {
    rsx! { section { aria_label:console_message(locale,"network-check-applied"),
        p { {console_message(locale,"network-connectivity-unknown")} }
        dl { for category in ["core","routes","dns","firewall"] {
            dt { "{category}" }
            dd { {value["categories"][category]["status"].as_str().unwrap_or("unknown")} }
            if let Some(reason)=value["categories"][category]["reason"].as_str() { dd { "{reason}" } }
        } }
        details { summary { {console_message(locale,"network-details")} } pre { {serde_json::to_string_pretty(&value).unwrap_or_default()} } }
    } }
}

#[component]
fn BindingPriority(
    binding: peerward_management::GatewayBinding,
    locale: Locale,
    disabled: bool,
    on_save: EventHandler<u32>,
) -> Element {
    let mut draft = use_signal(|| binding.priority.to_string());
    let mut applied = use_signal(|| binding.version);
    use_effect(use_reactive((&binding,), move |(binding,)| {
        if *applied.peek() != binding.version {
            draft.set(binding.priority.to_string());
            applied.set(binding.version);
        }
    }));
    rsx! {
        label { {console_message(locale,"network-priority")}
            input {r#type:"number",min:"0",max:"4294967295",value:"{draft}",disabled,oninput:move|event|draft.set(event.value())}
        }
        if !disabled {button {disabled:draft().parse::<u32>().is_err() || draft().parse::<u32>().ok()==Some(binding.priority),
            onclick:move|_|{if let Ok(priority)=draft().parse(){on_save.call(priority);}},
            {console_message(locale,"network-save-priority")}}
        }
    }
}

#[component]
fn TargetHealthObservation(value: Value, locale: Locale) -> Element {
    let bindings = value["bindings"].as_array().cloned().unwrap_or_default();
    rsx! { section {aria_label:console_message(locale,"target-health-title"),
        p{{console_message(locale,"target-health-boundary")}}
        if value["probe"].is_null() {p{{console_message(locale,"target-health-disabled")}}}
        for binding in bindings {
            p { {binding["peer_name"].as_str().unwrap_or("unknown")} ": "
                {console_message(locale,match binding["status"].as_str().unwrap_or("unknown") {
                    "reachable"=>"target-health-reachable","refused"=>"target-health-refused",
                    "timeout"=>"target-health-timeout","unavailable"=>"target-health-unavailable",_=>"target-health-unknown"})}
            }
        }
        details{summary{{console_message(locale,"network-details")}}pre{{serde_json::to_string_pretty(&value).unwrap_or_default()}}}
    }}
}
