#[derive(Clone, PartialEq)]
struct AutoApprovalDraft {
    id: uuid::Uuid,
    version: Option<u64>,
    name: String,
    collection: String,
    site: String,
    prefixes: String,
    enabled: bool,
}
impl Default for AutoApprovalDraft {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            version: None,
            name: String::new(),
            collection: String::new(),
            site: String::new(),
            prefixes: String::new(),
            enabled: false,
        }
    }
}
impl AutoApprovalDraft {
    fn from_rule(rule: peerward_management::AutoApprovalRule) -> Self {
        Self {
            id: rule.id,
            version: Some(rule.version),
            name: rule.definition.name,
            collection: rule.definition.device_collection.to_string(),
            site: rule.definition.site_id.to_string(),
            prefixes: rule
                .definition
                .prefixes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
            enabled: rule.definition.enabled,
        }
    }
    fn definition(&self) -> Option<peerward_management::AutoApprovalDefinition> {
        let definition = peerward_management::AutoApprovalDefinition {
            name: self.name.trim().into(),
            enabled: self.enabled,
            device_collection: self.collection.parse().ok()?,
            site_id: self.site.parse().ok()?,
            prefixes: self
                .prefixes
                .split_whitespace()
                .map(str::parse)
                .collect::<Result<_, _>>()
                .ok()?,
        };
        definition.validate().ok()?;
        Some(definition)
    }
}

#[component]
#[allow(unused_mut, unused_variables)]
fn AutoApprovalPanel(
    mesh: String,
    csrf: Option<String>,
    can_write: bool,
    locale: Locale,
    #[props(default)] ready: bool,
) -> Element {
    let mut active_mesh = use_signal(|| mesh.clone());
    let mut mesh_generation = use_signal(|| 0_u64);
    let mut draft = use_signal(AutoApprovalDraft::default);
    let mut drafts = use_signal(BTreeMap::<String, AutoApprovalDraft>::new);
    let mut rules = use_signal(Vec::<peerward_management::AutoApprovalRule>::new);
    let mut groups = use_signal(Vec::<peerward_management::Collection>::new);
    let mut targets = use_signal(Vec::<peerward_management::NetworkResource>::new);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut query = use_signal(String::new);
    let mut confirmed = use_signal(|| false);
    let operate = use_callback(move |operation: CollectionOperation| {
        #[cfg(target_arch = "wasm32")]
        {
            if *busy.peek()
                || active_mesh.peek().is_empty()
                || (!can_write && operation != CollectionOperation::Load)
            {
                return;
            }
            let mesh = active_mesh.peek().clone();
            let generation = *mesh_generation.peek();
            let captured = draft.peek().clone();
            let mut api = browser_api_client();
            if let Some(csrf) = &csrf {
                api = api.with_csrf(csrf.clone());
            }
            busy.set(true);
            error.set(String::new());
            status.set(String::new());
            spawn(async move {
                let base = format!("/api/v1/meshes/{mesh}");
                let path = format!("{base}/auto-approval-rules");
                let result: Result<Value, ConsoleApiError> = match operation {
                    CollectionOperation::Load => Ok(Value::Null),
                    CollectionOperation::Save => {
                        if let Some(definition) = captured.definition() {
                            match captured.version {
                                Some(version) => {
                                    api.conditional_request(
                                        Method::PUT,
                                        &format!("{path}/{}", captured.id),
                                        Some(json!(definition)),
                                        version,
                                    )
                                    .await
                                }
                                None => {
                                    api.request(
                                        Method::POST,
                                        &path,
                                        Some(json!({"id":captured.id,"definition":definition})),
                                    )
                                    .await
                                }
                            }
                        } else {
                            Err(ConsoleApiError::InvalidResponse)
                        }
                    }
                    CollectionOperation::Delete => match captured.version {
                        Some(version) => {
                            api.conditional_request(
                                Method::DELETE,
                                &format!("{path}/{}", captured.id),
                                None,
                                version,
                            )
                            .await
                        }
                        None => Err(ConsoleApiError::InvalidResponse),
                    },
                };
                if *active_mesh.peek() != mesh || *mesh_generation.peek() != generation {
                    return;
                }
                match result {
                    Ok(value) => {
                        if operation == CollectionOperation::Save {
                            match serde_json::from_value(value) {
                                Ok(rule) => draft.set(AutoApprovalDraft::from_rule(rule)),
                                Err(_) => error.set(
                                    console_message(locale, "resource-rule-invalid-document")
                                        .into(),
                                ),
                            }
                        }
                        if operation == CollectionOperation::Delete {
                            draft.set(AutoApprovalDraft::default());
                            confirmed.set(false);
                        }
                        if operation != CollectionOperation::Load {
                            status.set(console_message(locale, "network-saved").into());
                        }
                        let loaded_rules = api.bounded_network_list(&path, 64).await;
                        let loaded_groups = api
                            .bounded_network_list(&format!("{base}/collections"), 64)
                            .await;
                        let loaded_targets = api
                            .bounded_network_list(&format!("{base}/network-resources"), 4096)
                            .await;
                        if *active_mesh.peek() != mesh || *mesh_generation.peek() != generation {
                            return;
                        }
                        match (loaded_rules, loaded_groups, loaded_targets) {
                            (Ok(a), Ok(b), Ok(c)) => {
                                rules.set(a);
                                groups.set(b);
                                targets.set(c);
                            }
                            _ => error
                                .set(console_message(locale, "resource-policy-load-failed").into()),
                        }
                    }
                    Err(failure) => {
                        let failure = api_error_body(failure);
                        error.set(format!(
                            "{}: {} ({})",
                            failure.code, failure.message, failure.request_id
                        ));
                    }
                }
                if *active_mesh.peek() == mesh && *mesh_generation.peek() == generation {
                    busy.set(false);
                }
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
            rules.set(vec![]);
            groups.set(vec![]);
            targets.set(vec![]);
            busy.set(false);
            confirmed.set(false);
            status.set(String::new());
            error.set(String::new());
        }
        operate.call(CollectionOperation::Load);
    }));
    let mut sites = BTreeMap::new();
    for target in targets() {
        if let peerward_management::ResourceTarget::Subnet { site_id, .. } =
            target.definition.target
        {
            sites.entry(site_id).or_insert(target.definition.name);
        }
    }
    rsx! {
        section{class:"card network-management",aria_label:console_message(locale,"auto-approval"),
            h2{{console_message(locale,"auto-approval")}}
            p{{console_message(locale,"auto-approval-help")}}
            if busy()||!ready{p{role:"status",{console_message(locale,"loading")}}}
            if !error().is_empty(){p{role:"alert","{error}"}}
            if !status().is_empty(){p{role:"status","{status}"}}
            button{disabled:busy()||!ready,onclick:move|_|operate.call(CollectionOperation::Load),{console_message(locale,"network-refresh")}}
            if can_write{button{disabled:busy()||!ready,onclick:move|_|{draft.set(AutoApprovalDraft::default());confirmed.set(false);},{console_message(locale,"auto-approval-new")}}}
            label{{console_message(locale,"network-search")}input{value:"{query}",oninput:move|event|query.set(event.value())}}
            if rules.read().is_empty(){p{{console_message(locale,"auto-approval-empty")}}}
            ul{for rule in rules().into_iter().filter(|rule|rule.definition.name.to_lowercase().contains(&query().to_lowercase())){li{key:"{rule.id}",button{disabled:busy()||!ready,onclick:{let rule=rule.clone();move|_|{draft.set(AutoApprovalDraft::from_rule(rule.clone()));confirmed.set(false);}},"{rule.definition.name}"}}}}
            fieldset{disabled:busy()||!ready||!can_write,
                legend{{console_message(locale,"auto-approval-definition")}}
                label{{console_message(locale,"name")}input{value:"{draft.read().name}",oninput:move|event|draft.write().name=event.value()}}
                label{{console_message(locale,"auto-approval-devices")}select{value:"{draft.read().collection}",onchange:move|event|draft.write().collection=event.value(),
                    option{value:"",{console_message(locale,"auto-approval-select")}}
                    for group in groups().into_iter().filter(|group|group.definition.kind==peerward_management::CollectionKind::Devices){option{value:"{group.id}","{group.definition.name}"}}
                }}
                label{{console_message(locale,"network-site")}select{value:"{draft.read().site}",onchange:move|event|draft.write().site=event.value(),
                    option{value:"",{console_message(locale,"auto-approval-select")}}
                    for (id,name) in sites{option{value:"{id}","{name}"}}
                }}
                label{{console_message(locale,"auto-approval-prefixes")}textarea{rows:"3",placeholder:"192.168.1.0/24",value:"{draft.read().prefixes}",oninput:move|event|draft.write().prefixes=event.value()}}
                label{input{r#type:"checkbox",checked:draft.read().enabled,onchange:move|event|draft.write().enabled=event.checked()}{console_message(locale,"auto-approval-enabled")}}
                p{{console_message(locale,"auto-approval-impact")}}
                button{disabled:draft.read().definition().is_none(),onclick:move|_|operate.call(CollectionOperation::Save),{console_message(locale,"auto-approval-save")}}
            }
            if can_write&&draft.read().version.is_some(){details{summary{{console_message(locale,"auto-approval-delete")}}
                label{input{r#type:"checkbox",checked:confirmed(),onchange:move|event|confirmed.set(event.checked())}{console_message(locale,"auto-approval-delete-impact")}}
                button{disabled:busy()||!ready||!confirmed(),onclick:move|_|operate.call(CollectionOperation::Delete),{console_message(locale,"auto-approval-delete")}}
            }}
        }
    }
}
