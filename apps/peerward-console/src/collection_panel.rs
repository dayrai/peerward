#[derive(Clone, Copy, PartialEq)]
enum CollectionOperation {
    Load,
    Save,
    Delete,
}
#[derive(Clone, PartialEq)]
struct CollectionDraft {
    id: uuid::Uuid,
    version: Option<u64>,
    definition: peerward_management::CollectionDefinition,
}
impl Default for CollectionDraft {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            version: None,
            definition: peerward_management::CollectionDefinition {
                name: String::new(),
                kind: peerward_management::CollectionKind::Devices,
                members: std::collections::BTreeSet::new(),
                labels: BTreeMap::new(),
            },
        }
    }
}

#[component]
#[allow(unused_mut, unused_variables)]
fn CollectionPanel(
    mesh: String,
    csrf: Option<String>,
    can_write: bool,
    locale: Locale,
    #[props(default)] ready: bool,
    #[props(default)] devices_only: bool,
) -> Element {
    let mut active_mesh = use_signal(|| mesh.clone());
    let mut mesh_generation = use_signal(|| 0_u64);
    let mut draft = use_signal(CollectionDraft::default);
    let mut baseline = use_signal(|| draft.peek().definition.clone());
    let mut drafts = use_signal(BTreeMap::<String, CollectionDraft>::new);
    let mut baselines =
        use_signal(BTreeMap::<String, peerward_management::CollectionDefinition>::new);
    let mut collections = use_signal(Vec::<peerward_management::Collection>::new);
    let mut peers = use_signal(Vec::<PeerResource>::new);
    let mut resources = use_signal(Vec::<peerward_management::NetworkResource>::new);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut query = use_signal(String::new);
    let mut label_key = use_signal(String::new);
    let mut label_value = use_signal(String::new);
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
                let path = format!("/api/v1/meshes/{mesh}/collections");
                let result: Result<Value, ConsoleApiError> = match operation {
                    CollectionOperation::Load => Ok(Value::Null),
                    CollectionOperation::Save => match captured.version {
                        Some(version) => {
                            api.conditional_request(
                                Method::PUT,
                                &format!("{path}/{}", captured.id),
                                Some(json!(captured.definition)),
                                version,
                            )
                            .await
                        }
                        None => {
                            api.request(
                                Method::POST,
                                &path,
                                Some(json!({"id":captured.id,"definition":captured.definition})),
                            )
                            .await
                        }
                    },
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
                            match serde_json::from_value::<peerward_management::Collection>(value) {
                                Ok(value) => draft.set(CollectionDraft {
                                    id: value.id,
                                    version: Some(value.version),
                                    definition: value.definition,
                                }),
                                Err(_) => error.set(
                                    console_message(locale, "resource-rule-invalid-document")
                                        .into(),
                                ),
                            }
                        }
                        if operation == CollectionOperation::Delete {
                            draft.set(CollectionDraft::default());
                            confirmed.set(false);
                        }
                        if operation != CollectionOperation::Load {
                            status.set(console_message(locale, "network-saved").into());
                        }
                        if operation != CollectionOperation::Load {
                            baseline.set(draft.peek().definition.clone());
                        }
                        let groups = api.bounded_network_list(&path, 64).await;
                        let devices = api
                            .bounded_network_list(&format!("/api/v1/meshes/{mesh}/peers"), 4096)
                            .await;
                        let targets = api
                            .bounded_network_list(
                                &format!("/api/v1/meshes/{mesh}/network-resources"),
                                4096,
                            )
                            .await;
                        if *active_mesh.peek() != mesh || *mesh_generation.peek() != generation {
                            return;
                        }
                        match (groups, devices, targets) {
                            (Ok(groups), Ok(devices), Ok(targets)) => {
                                collections.set(groups);
                                peers.set(devices);
                                resources.set(targets);
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
    use_effect(use_reactive((&mesh, &ready), move |(mesh, ready)| {
        if *active_mesh.peek() != mesh {
            let next_generation = mesh_generation.peek().wrapping_add(1);
            mesh_generation.set(next_generation);
            drafts
                .write()
                .insert(active_mesh.peek().clone(), draft.peek().clone());
            baselines
                .write()
                .insert(active_mesh.peek().clone(), baseline.peek().clone());
            draft.set(drafts.peek().get(&mesh).cloned().unwrap_or_default());
            baseline.set(
                baselines
                    .peek()
                    .get(&mesh)
                    .cloned()
                    .unwrap_or_else(|| CollectionDraft::default().definition),
            );
            active_mesh.set(mesh);
            collections.set(vec![]);
            peers.set(vec![]);
            resources.set(vec![]);
            busy.set(false);
            confirmed.set(false);
            status.set(String::new());
        }
        if ready {
            operate.call(CollectionOperation::Load);
        }
    }));
    let candidates = match draft.read().definition.kind {
        peerward_management::CollectionKind::Devices => peers()
            .into_iter()
            .map(|peer| {
                let name = if devices_only {
                    peer_display_name(&ResourceSummary::from(peer.clone()))
                } else {
                    peer.name.clone()
                };
                (peer.id.into_uuid(), name, peer.labels)
            })
            .collect::<Vec<_>>(),
        peerward_management::CollectionKind::Resources => resources()
            .into_iter()
            .map(|resource| {
                (
                    resource.id,
                    resource.definition.name,
                    resource.definition.labels,
                )
            })
            .collect(),
    };
    let enabled = peers
        .read()
        .iter()
        .filter(|peer| peer.administrative_state == peerward_api::AdministrativeState::Enabled)
        .map(|peer| peer.id.into_uuid())
        .collect::<HashSet<_>>();
    let resolved = draft.read().definition.resolve(
        draft.read().id,
        candidates
            .iter()
            .filter(|(id, _, _)| {
                draft.read().definition.kind == peerward_management::CollectionKind::Resources
                    || enabled.contains(id)
            })
            .map(|(id, _, labels)| (*id, labels)),
    );
    rsx! {
        section{class:"card network-management collection-manager",aria_label:if devices_only {console_text(locale,"设备组管理","Device groups")} else {console_message(locale,"collections")},
            "data-console-dirty": (can_write && *baseline.read() != draft.read().definition).to_string(),
            "data-console-submitting":busy().to_string(),
            if devices_only {
                p { class:"muted", {console_text(locale,"把需要相同访问权限的设备放在一组。保存后，在共享详情的“谁可以访问”中选择该组；创建组本身不会新增授权。","Group devices that need the same access. After saving, select the group under Who can access in sharing details. Creating a group alone grants no access.")} }
            } else { h2{{console_message(locale,"collections")}} p{{console_message(locale,"collections-help")}} }
            if busy() || !ready{p{role:"status",{console_message(locale,"loading")}}}
            if !error().is_empty(){p{role:"alert","{error}"}}
            if !status().is_empty(){p{role:"status","{status}"}}
            button{class:"secondary-button",disabled:busy()||!ready,onclick:move|_|operate.call(CollectionOperation::Load),{console_message(locale,"network-refresh")}}
            if can_write{button{class:"secondary-button", "data-console-dismiss":"true", disabled:busy()||!ready,onclick:move|_|{draft.set(CollectionDraft::default());baseline.set(draft.peek().definition.clone());confirmed.set(false);},{if devices_only {console_text(locale,"新建设备组","New device group")} else {console_message(locale,"collection-new")}}}}
            ul{class:"collection-list",for collection in collections().into_iter().filter(|item| !devices_only || item.definition.kind == peerward_management::CollectionKind::Devices){li{button{class:"secondary-button", "data-console-dismiss":"true",disabled:busy()||!ready,onclick:move|_|{draft.set(CollectionDraft{id:collection.id,version:Some(collection.version),definition:collection.definition.clone()});baseline.set(draft.peek().definition.clone());confirmed.set(false);},"{collection.definition.name}"}}}}
            fieldset{disabled:busy()||!ready||!can_write,
                legend{{if devices_only {console_text(locale,"设备组信息","Device group details")} else {console_message(locale,"collection-definition")}}}
                label{{if devices_only {console_text(locale,"设备组名称","Device group name")} else {console_message(locale,"name")}}input{value:"{draft.read().definition.name}",oninput:move|event|draft.write().definition.name=event.value()}}
                if !devices_only { label{{console_message(locale,"collection-kind")}select{disabled:draft.read().version.is_some(),value:if draft.read().definition.kind==peerward_management::CollectionKind::Devices{"devices"}else{"resources"},onchange:move|event|{
                    draft.write().definition.kind=if event.value()=="devices"{peerward_management::CollectionKind::Devices}else{peerward_management::CollectionKind::Resources};draft.write().definition.members.clear();draft.write().definition.labels.clear();
                },option{value:"devices",{console_message(locale,"collection-devices")}}option{value:"resources",{console_message(locale,"collection-resources")}}}} }
                label{{if devices_only {console_text(locale,"搜索设备","Search devices")} else {console_message(locale,"network-search")}}input{value:"{query}",oninput:move|event|query.set(event.value())}}
                if devices_only && candidates.is_empty() && !busy() && ready {p{class:"info-note",{console_text(locale,"暂无设备，先添加设备后再选择成员。","No devices yet. Add devices before selecting members.")}}}
                div{class:"collection-members",for (id,name,_) in candidates.iter().filter(|(_,name,_)|name.to_lowercase().contains(&query().to_lowercase())){label{key:"{id}",input{r#type:"checkbox",checked:draft.read().definition.members.contains(id),onchange:{let id=*id;move|event|{if event.checked(){draft.write().definition.members.insert(id);}else{draft.write().definition.members.remove(&id);}}}}"{name}"}}}
                button{class:"secondary-button",onclick:move|_|draft.write().definition.members.clear(),{console_message(locale,"collection-clear-members")}}
                details{summary{{console_message(locale,"collection-labels")}}
                    label{{console_message(locale,"collection-label-key")}input{value:"{label_key}",oninput:move|event|label_key.set(event.value())}}
                    label{{console_message(locale,"collection-label-value")}input{value:"{label_value}",oninput:move|event|label_value.set(event.value())}}
                    button{disabled:label_key().trim().is_empty()||label_value().is_empty(),onclick:move|_|{draft.write().definition.labels.insert(label_key().trim().into(),label_value());},{console_message(locale,"collection-add-label")}}
                    for (key,value) in draft.read().definition.labels.clone(){p{"{key} = {value}" button{onclick:move|_|{draft.write().definition.labels.remove(&key);},{console_message(locale,"resource-rule-remove")}}}}
                }
                p{{format!("{}: {}",console_message(locale,"collection-preview-count"),resolved.members.len())}}
                p{{console_message(locale,"collection-impact")}}
                button{disabled:draft.read().definition.validate().is_err(),onclick:move|_|operate.call(CollectionOperation::Save),{if devices_only {console_text(locale,"保存设备组","Save device group")} else {console_message(locale,"collection-save")}}}
            }
            if can_write && draft.read().version.is_some(){details{summary{{console_message(locale,"collection-delete")}}
                label{input{r#type:"checkbox",checked:confirmed(),onchange:move|event|confirmed.set(event.checked())}{console_message(locale,"collection-delete-impact")}}
                button{disabled:busy()||!ready||!confirmed(),onclick:move|_|operate.call(CollectionOperation::Delete),{console_message(locale,"collection-delete")}}
            }}
        }
    }
}
