#[component]
#[allow(unused_variables, unused_mut)]
fn ResourcePolicyPanel(
    mesh: String,
    csrf: Option<String>,
    can_write: bool,
    locale: Locale,
    #[props(default)] ready: bool,
) -> Element {
    let mut active_mesh = use_signal(|| mesh.clone());
    let mut mesh_generation = use_signal(|| 0_u64);
    let mut base = use_signal(|| None::<peerward_api::ResourcePolicyResponse>);
    let mut document = use_signal(|| "{\"rules\":[],\"tests\":[]}".to_owned());
    let mut drafts = use_signal(BTreeMap::<String, String>::new);
    let mut resources = use_signal(Vec::<peerward_management::NetworkResource>::new);
    let mut peers = use_signal(Vec::<PeerResource>::new);
    let mut bindings = use_signal(Vec::<peerward_management::GatewayBinding>::new);
    let mut collections = use_signal(Vec::<peerward_management::Collection>::new);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut rule = use_signal(ResourceRuleForm::default);
    let mut preview = use_signal(|| None::<(String, Value)>);
    let mut simulation = use_signal(|| None::<Value>);
    let mut address = use_signal(String::new);
    let mut provider = use_signal(String::new);
    let mut history = use_signal(String::new);
    let mut expect_allow = use_signal(|| true);
    let operate = use_callback(move |operation: ResourcePolicyOperation| {
        #[cfg(target_arch = "wasm32")]
        {
            if *busy.peek() || active_mesh.peek().is_empty() {
                return;
            }
            if !can_write
                && matches!(
                    operation,
                    ResourcePolicyOperation::Publish | ResourcePolicyOperation::Preview
                )
            {
                return;
            }
            let mesh = active_mesh.peek().clone();
            let generation = *mesh_generation.peek();
            let captured = document.peek().clone();
            let version = base.peek().as_ref().map_or(0, |value| value.version);
            let Ok(mut body) = (if matches!(
                operation,
                ResourcePolicyOperation::Load | ResourcePolicyOperation::History(_)
            ) {
                Ok(Value::Null)
            } else {
                serde_json::from_str::<Value>(&captured)
            }) else {
                error.set(console_message(locale, "resource-rule-invalid-document").into());
                return;
            };
            if matches!(operation, ResourcePolicyOperation::Simulate) {
                let Ok(request) = rule.peek().rule() else {
                    error.set(console_message(locale, "resource-rule-invalid").into());
                    return;
                };
                if rule
                    .peek()
                    .source
                    .parse::<peerward_types::PeerId>()
                    .is_err()
                    || rule.peek().target.parse::<uuid::Uuid>().is_err()
                    || address.peek().parse::<std::net::IpAddr>().is_err()
                    || provider.peek().parse::<uuid::Uuid>().is_err()
                {
                    error.set(console_message(locale, "resource-test-target").into());
                    return;
                }
                body = json!({"source_peer_id":rule.peek().source,"target":{"kind":"resource","resource_id":rule.peek().target,"address":address.peek().clone(),"provider_peer_id":provider.peek().clone()},"protocol":request.protocol,"destination_port":request.destination_ports.first().map(|value|value.0),"draft_resource_rules":body["rules"]});
                if !can_write {
                    body.as_object_mut()
                        .expect("simulation object")
                        .remove("draft_resource_rules");
                }
            }
            let mut api = browser_api_client();
            if let Some(csrf) = &csrf {
                api = api.with_csrf(csrf.clone());
            }
            busy.set(true);
            error.set(String::new());
            status.set(String::new());
            spawn(async move {
                let result = api
                    .resource_policy_operation(&mesh, operation, version, body)
                    .await;
                if *active_mesh.peek() != mesh || *mesh_generation.peek() != generation {
                    return;
                }
                match result {
                    Ok(value) => match operation {
                        ResourcePolicyOperation::Preview => preview.set(Some((captured, value))),
                        ResourcePolicyOperation::Simulate => simulation.set(Some(value)),
                        ResourcePolicyOperation::Load
                        | ResourcePolicyOperation::History(_)
                        | ResourcePolicyOperation::Publish => {
                            if let Ok(value) = serde_json::from_value::<
                                peerward_api::ResourcePolicyResponse,
                            >(value)
                            {
                                if matches!(
                                    operation,
                                    ResourcePolicyOperation::History(_)
                                        | ResourcePolicyOperation::Publish
                                ) || base.peek().is_none() && !drafts.peek().contains_key(&mesh)
                                {
                                    document.set(
                                        serde_json::to_string_pretty(&value.document)
                                            .unwrap_or_default(),
                                    );
                                }
                                if !matches!(operation, ResourcePolicyOperation::History(_)) {
                                    base.set(Some(value));
                                }
                                preview.set(None);
                                status.set(
                                    console_message(
                                        locale,
                                        if matches!(operation, ResourcePolicyOperation::Publish) {
                                            "network-saved"
                                        } else if matches!(
                                            operation,
                                            ResourcePolicyOperation::History(_)
                                        ) {
                                            "resource-policy-restored-draft"
                                        } else {
                                            "resource-policy-rebased"
                                        },
                                    )
                                    .into(),
                                );
                                if matches!(operation, ResourcePolicyOperation::Load) {
                                    let targets = api
                                        .bounded_network_list(
                                            &format!("/api/v1/meshes/{mesh}/network-resources"),
                                            4096,
                                        )
                                        .await;
                                    let devices = api
                                        .bounded_network_list(
                                            &format!("/api/v1/meshes/{mesh}/peers"),
                                            4096,
                                        )
                                        .await;
                                    let providers = api
                                        .bounded_network_list(
                                            &format!("/api/v1/meshes/{mesh}/gateway-bindings"),
                                            8192,
                                        )
                                        .await;
                                    if *active_mesh.peek() != mesh
                                        || *mesh_generation.peek() != generation
                                    {
                                        return;
                                    }
                                    let groups = api
                                        .bounded_network_list(
                                            &format!("/api/v1/meshes/{mesh}/collections"),
                                            64,
                                        )
                                        .await;
                                    if *active_mesh.peek() != mesh
                                        || *mesh_generation.peek() != generation
                                    {
                                        return;
                                    }
                                    match (targets, devices, providers, groups) {
                                        (Ok(a), Ok(b), Ok(c), Ok(d)) => {
                                            resources.set(a);
                                            peers.set(b);
                                            bindings.set(c);
                                            collections.set(d);
                                        }
                                        _ => error.set(
                                            console_message(locale, "resource-policy-load-failed")
                                                .into(),
                                        ),
                                    }
                                }
                            } else {
                                error.set(
                                    console_message(locale, "resource-rule-invalid-document")
                                        .into(),
                                );
                            }
                        }
                    },
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
                .insert(active_mesh.peek().clone(), document.peek().clone());
            document.set(
                drafts
                    .peek()
                    .get(&mesh)
                    .cloned()
                    .unwrap_or_else(|| "{\"rules\":[],\"tests\":[]}".into()),
            );
            active_mesh.set(mesh);
            base.set(None);
            preview.set(None);
            simulation.set(None);
            resources.set(vec![]);
            collections.set(vec![]);
            peers.set(vec![]);
            bindings.set(vec![]);
            busy.set(false);
            rule.set(ResourceRuleForm::default());
            provider.set(String::new());
            address.set(String::new());
        }
        operate.call(ResourcePolicyOperation::Load);
    }));
    use_effect(use_reactive(
        (&document(), &rule(), &address(), &provider()),
        move |_| {
            simulation.set(None);
        },
    ));
    let editable = resource_policy_draft(&document()).ok();
    let publish_ready = preview.read().as_ref().is_some_and(|(captured, value)| {
        captured == &document()
            && base
                .read()
                .as_ref()
                .is_some_and(|base| value["version"].as_u64() == Some(base.version))
            && (value["failed_tests"].as_array().is_some_and(Vec::is_empty)
                || value["only_removes_grants"] == true)
    });
    rsx! {
        section{class:"card network-management",aria_label:console_message(locale,"resource-policy"),
            h2{{console_message(locale,"resource-policy")}}
            p{{console_message(locale,"resource-policy-help")}}
            if busy() || !ready{p{role:"status",{console_message(locale,"loading")}}}
            if !error().is_empty(){p{role:"alert","{error}"}}
            if !status().is_empty(){p{role:"status",aria_live:"polite","{status}"}}
            button{disabled:busy() || !ready,onclick:move|_|operate.call(ResourcePolicyOperation::Load),{console_message(locale,"resource-policy-reload")}}
            fieldset{disabled:busy() || !ready||base.read().is_none(),
                legend{{console_message(locale,"resource-rule-build")}}
                label{{console_message(locale,"collection-source")}select{value:"{rule.read().source_collection}",onchange:move|event|rule.write().source_collection=event.value(),option{value:"",{console_message(locale,"collection-none")}}for collection in collections().into_iter().filter(|collection|collection.definition.kind==peerward_management::CollectionKind::Devices){option{value:"{collection.id}","{collection.definition.name}"}}}}
                label{{console_message(locale,"collection-target")}select{value:"{rule.read().target_collection}",onchange:move|event|rule.write().target_collection=event.value(),option{value:"",{console_message(locale,"collection-none")}}for collection in collections().into_iter().filter(|collection|collection.definition.kind==peerward_management::CollectionKind::Resources){option{value:"{collection.id}","{collection.definition.name}"}}}}
                if !rule.read().source_collection.is_empty() || !rule.read().target_collection.is_empty(){p{{console_message(locale,"collection-simulation-help")}}}
                label{{console_message(locale,"resource-rule-source")}
                    select{value:"{rule.read().source}",onchange:move|event|rule.write().source=event.value(),option{value:"",{console_message(locale,"network-select-device")}}for peer in peers(){option{value:"{peer.id}","{peer.name}"}}}
                }
                label{{console_message(locale,"resource-rule-target")}
                    select{value:"{rule.read().target}",onchange:move|event|{rule.write().target=event.value();provider.set(String::new());address.set(String::new());},option{value:"",{console_message(locale,"resource-rule-select-target")}}for resource in resources(){option{value:"{resource.id}","{resource.definition.name}"}}}
                }
                label{{console_message(locale,"resource-rule-protocol")}
                    select{value:"{rule.read().protocol}",onchange:move|event|{if let Ok(value)=event.value().parse(){rule.write().protocol=value;}},option{value:"6","TCP"}option{value:"17","UDP"}option{value:"1","ICMPv4"}option{value:"58","ICMPv6"}}
                }
                if [6,17].contains(&rule.read().protocol){label{{console_message(locale,"resource-rule-port")}input{value:"{rule.read().port}",oninput:move|event|rule.write().port=event.value()}}}
                label{{console_message(locale,"resource-rule-priority")}input{r#type:"number",min:"0",value:"{rule.read().priority}",oninput:move|event|rule.write().priority=event.value()}}
                label{{console_message(locale,"resource-rule-action")}select{value:if rule.read().allow{"allow"}else{"deny"},onchange:move|event|rule.write().allow=event.value()=="allow",option{value:"allow",{console_message(locale,"resource-rule-allow")}}option{value:"deny",{console_message(locale,"resource-rule-deny")}}}}
                button{disabled:!can_write||rule.read().rule().is_err()||editable.is_none(),onclick:move|_|{
                    if let (Ok(value),Ok(mut body))=(rule.peek().rule(),resource_policy_draft(&document())){body.rules.push(value);document.set(serde_json::to_string_pretty(&body).unwrap_or_default());preview.set(None);}
                },{console_message(locale,"resource-rule-add")}}
            }
            if let Some(body)=editable.clone(){
                ol{for item in body.rules{li{key:"{item.id}",
                    {resource_rule_summary(&item,&peers(),&resources(),&collections(),locale)}
                    if can_write{button{disabled:busy() || !ready,onclick:move|_|{if let Ok(mut body)=resource_policy_draft(&document()){body.rules.retain(|value|value.id!=item.id);document.set(serde_json::to_string_pretty(&body).unwrap_or_default());preview.set(None);}}, {console_message(locale,"resource-rule-remove")}}}
                }}}
            }
            details{summary{{console_message(locale,"resource-policy-advanced")}}textarea{aria_label:console_message(locale,"resource-policy-advanced"),rows:"14",disabled:busy() || !ready||!can_write,value:"{document}",oninput:move|event|{document.set(event.value());preview.set(None);}}}
            fieldset{disabled:busy() || !ready||base.read().is_none(),legend{{console_message(locale,"resource-test")}}
                label{{console_message(locale,"network-address")}input{value:"{address}",oninput:move|event|address.set(event.value())}}
                label{{console_message(locale,"network-provider")}select{value:"{provider}",onchange:move|event|provider.set(event.value()),option{value:"",{console_message(locale,"network-select-device")}}
                    for binding in bindings().into_iter().filter(|binding|binding.approved&&binding.resource_id.to_string()==rule.read().target){option{value:"{binding.peer_id}",{peers.read().iter().find(|peer|peer.id==binding.peer_id).map_or_else(||console_message(locale,"network-device-unavailable").into(),|peer|peer.name.clone())}}}}}
                button{onclick:move|_|operate.call(ResourcePolicyOperation::Simulate),{console_message(locale,"resource-test-run")}}
                if can_write{label{input{r#type:"checkbox",checked:expect_allow(),onchange:move|event|expect_allow.set(event.checked())}{console_message(locale,"resource-test-expect-allow")}}
                button{disabled:!can_write,onclick:move|_|{
                    let (Ok(source_id),Ok(resource_id))=(rule.peek().source.parse::<peerward_types::PeerId>(),rule.peek().target.parse::<uuid::Uuid>())else{error.set(console_message(locale,"resource-test-target").into());return;};
                    let (Ok(value),Ok(mut body),Ok(target),Ok(gateway))=(rule.peek().rule(),resource_policy_draft(&document()),address.peek().parse::<std::net::IpAddr>(),provider.peek().parse::<peerward_types::PeerId>())else{error.set(console_message(locale,"resource-test-target").into());return;};
                    body.tests.push(peerward_api::ResourcePolicyTest{id:uuid::Uuid::new_v4(),name:format!("{} {}",target,rule.peek().port),source_peer_id:source_id,resource_id,provider_peer_id:gateway,address:target,protocol:value.protocol,destination_port:value.destination_ports.first().map(|ports|ports.0),expected:if expect_allow(){peerward_management::ResourceAction::Allow}else{peerward_management::ResourceAction::Deny}});
                    document.set(serde_json::to_string_pretty(&body).unwrap_or_default());preview.set(None);
                },{console_message(locale,"resource-test-save")}}}
                if let Some(result)=simulation(){p{role:"status",{console_message(locale,if result["allowed"]==true{"resource-test-allowed"}else{"resource-test-denied"})}}details{summary{{console_message(locale,"network-details")}}pre{{serde_json::to_string_pretty(&result).unwrap_or_default()}}}}
            }
            if can_write{
                button{disabled:busy() || !ready||base.read().is_none()||resource_policy_draft(&document()).is_err(),onclick:move|_|operate.call(ResourcePolicyOperation::Preview),{console_message(locale,"resource-policy-preview")}}
                if let Some((_,value))=preview(){p{role:"status",{format!("{}: {} / {}: {}",console_message(locale,"resource-policy-changes"),value["added_or_changed_rules"].as_array().map_or(0,Vec::len),console_message(locale,"resource-policy-failed-tests"),value["failed_tests"].as_array().map_or(0,Vec::len))}}details{summary{{console_message(locale,"network-details")}}pre{{serde_json::to_string_pretty(&value).unwrap_or_default()}}}}
                button{disabled:busy() || !ready||!publish_ready,onclick:move|_|operate.call(ResourcePolicyOperation::Publish),{console_message(locale,"resource-policy-publish")}}
                details{summary{{console_message(locale,"resource-policy-history")}}p{{console_message(locale,"resource-policy-history-help")}}label{{console_message(locale,"resource-policy-version")}}input{aria_label:console_message(locale,"resource-policy-version"),r#type:"number",min:"1",value:"{history}",oninput:move|event|history.set(event.value())}button{disabled:busy() || !ready||history().parse::<u64>().is_err(),onclick:move|_|{if let Ok(version)=history().parse(){operate.call(ResourcePolicyOperation::History(version));}},{console_message(locale,"resource-policy-restore")}}}
            }
        }
    }
}
