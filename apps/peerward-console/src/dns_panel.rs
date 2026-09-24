#[component]
#[allow(unused_mut, unused_variables)]
fn DnsPanel(
    mesh: String,
    csrf: Option<String>,
    can_write: bool,
    locale: Locale,
    #[props(default)] ready: bool,
) -> Element {
    let mut active_mesh = use_signal(|| mesh.clone());
    let mut mesh_generation = use_signal(|| 0_u64);
    let mut profiles = use_signal(Vec::<peerward_api::DnsProfileResponse>::new);
    let mut peers = use_signal(Vec::<PeerResource>::new);
    let mut selected = use_signal(|| None::<(uuid::Uuid, u64)>);
    let mut document = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut preview_peer = use_signal(String::new);
    let mut effective = use_signal(|| None::<Value>);
    let mut suffix = use_signal(String::new);
    let mut upstreams = use_signal(String::new);
    let mut record_name = use_signal(String::new);
    let mut record_value = use_signal(String::new);
    let mut confirmation = use_signal(|| false);
    let mut cached_drafts =
        use_signal(BTreeMap::<String, (String, Option<(uuid::Uuid, u64)>)>::new);
    let operate = use_callback(move |operation: u8| {
        #[cfg(target_arch = "wasm32")]
        {
            if *busy.peek()
                || active_mesh.peek().is_empty()
                || (!can_write && [1, 3].contains(&operation))
            {
                return;
            }
            let mesh = active_mesh.peek().clone();
            let generation = *mesh_generation.peek();
            let captured = *selected.peek();
            let body = if operation == 0 {
                None
            } else if let Ok(value) =
                serde_json::from_str::<peerward_management::DnsProfile>(&document.peek())
            {
                Some(value)
            } else {
                error.set(console_message(locale, "dns-invalid").into());
                return;
            };
            let peer = preview_peer.peek().clone();
            let mut candidates = profiles
                .peek()
                .clone()
                .into_iter()
                .map(|value| value.profile)
                .collect::<Vec<_>>();
            if let Some(body) = &body {
                candidates.retain(|value| value.id != body.id);
                candidates.push(body.clone());
            }
            let mut api = browser_api_client();
            if let Some(csrf) = &csrf {
                api = api.with_csrf(csrf.clone());
            }
            busy.set(true);
            error.set(String::new());
            status.set(String::new());
            spawn(async move {
                let base = format!("/api/v1/meshes/{mesh}");
                let result: Result<Value, ConsoleApiError> = match operation {
                    0 => Ok(Value::Null),
                    1 => match captured {
                        Some((id, version)) => {
                            api.conditional_request(
                                Method::PUT,
                                &format!("{base}/dns-profiles/{id}"),
                                Some(json!(body)),
                                version,
                            )
                            .await
                        }
                        None => {
                            api.request(
                                Method::POST,
                                &format!("{base}/dns-profiles"),
                                Some(json!(body)),
                            )
                            .await
                        }
                    },
                    2 => {
                        api.request(
                            Method::POST,
                            &format!("{base}/dns/preview"),
                            Some(json!({"peer_id":peer,"draft_profiles":candidates})),
                        )
                        .await
                    }
                    3 => match captured {
                        Some((id, version)) => {
                            api.conditional_request(
                                Method::DELETE,
                                &format!("{base}/dns-profiles/{id}"),
                                None,
                                version,
                            )
                            .await
                        }
                        None => Err(ConsoleApiError::InvalidResponse),
                    },
                    _ => Err(ConsoleApiError::InvalidResponse),
                };
                if *active_mesh.peek() != mesh || *mesh_generation.peek() != generation {
                    return;
                }
                match result {
                    Ok(value) => {
                        if operation == 2 {
                            effective.set(Some(value));
                        } else {
                            if operation == 1 {
                                if let Ok(saved) = serde_json::from_value::<
                                    peerward_api::DnsProfileResponse,
                                >(value)
                                {
                                    selected.set(Some((saved.profile.id, saved.version)));
                                    document.set(
                                        serde_json::to_string_pretty(&saved.profile)
                                            .unwrap_or_default(),
                                    );
                                }
                                status.set(console_message(locale, "network-saved").into());
                            }
                            if operation == 3 {
                                document.set(String::new());
                                selected.set(None);
                                effective.set(None);
                            }
                            let list = api
                                .bounded_network_list::<peerward_api::DnsProfileResponse>(
                                    &format!("{base}/dns-profiles"),
                                    64,
                                )
                                .await;
                            let devices = api
                                .bounded_network_list::<PeerResource>(
                                    &format!("{base}/peers"),
                                    4096,
                                )
                                .await;
                            if *active_mesh.peek() != mesh || *mesh_generation.peek() != generation
                            {
                                return;
                            }
                            match (list, devices) {
                                (Ok(list), Ok(devices)) => {
                                    if document.peek().is_empty()
                                        && let Some(default) = list
                                            .iter()
                                            .find(|item| item.profile.id.to_string() == mesh)
                                    {
                                        selected.set(Some((default.profile.id, default.version)));
                                        document.set(
                                            serde_json::to_string_pretty(&default.profile)
                                                .unwrap_or_default(),
                                        );
                                    }
                                    profiles.set(list);
                                    peers.set(devices);
                                }
                                _ => error.set(
                                    console_message(locale, "resource-policy-load-failed").into(),
                                ),
                            }
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
            cached_drafts.write().insert(
                active_mesh.peek().clone(),
                (document.peek().clone(), *selected.peek()),
            );
            let (draft, version) = cached_drafts.peek().get(&mesh).cloned().unwrap_or_default();
            document.set(draft);
            selected.set(version);
            active_mesh.set(mesh);
            profiles.set(vec![]);
            peers.set(vec![]);
            busy.set(false);
            effective.set(None);
            preview_peer.set(String::new());
            confirmation.set(false);
        }
        operate.call(0);
    }));
    let parsed = serde_json::from_str::<peerward_management::DnsProfile>(&document()).ok();
    let valid = parsed
        .as_ref()
        .is_some_and(|value| value.validate().is_ok());
    rsx! {
        section{class:"card network-management",aria_label:console_message(locale,"dns-settings"),
            h2{{console_message(locale,"dns-settings")}}
            p{{console_message(locale,"dns-help")}}
            if busy() || !ready{p{role:"status",{console_message(locale,"loading")}}}
            if !error().is_empty(){p{role:"alert","{error}"}}
            if !status().is_empty(){p{role:"status",aria_live:"polite","{status}"}}
            button{disabled:busy() || !ready,onclick:move|_|operate.call(0),{console_message(locale,"network-refresh")}}
            label{{console_message(locale,"dns-profile")}
                select{disabled:busy() || !ready,value:selected().map(|(id,_)|id.to_string()).unwrap_or_default(),onchange:move|event|{
                    if let Some(profile)=profiles().into_iter().find(|value|value.profile.id.to_string()==event.value()){selected.set(Some((profile.profile.id,profile.version)));document.set(serde_json::to_string_pretty(&profile.profile).unwrap_or_default());effective.set(None);confirmation.set(false);}
                },option{value:"",{console_message(locale,"dns-new")}}
                    for profile in profiles(){option{value:"{profile.profile.id}",{if profile.profile.id.to_string()==mesh{console_message(locale,"dns-default").to_owned()}else{let names=profile.profile.scope.peers.iter().map(|id|peers.read().iter().find(|peer|peer.id==*id).map_or_else(||console_message(locale,"network-device-unavailable").into(),|peer|peer.name.clone())).collect::<Vec<_>>();if names.is_empty(){console_message(locale,"dns-scoped").into()}else{names.join(", ")}}}}}
                }
            }
            if can_write{button{disabled:busy() || !ready,onclick:move|_|{let profile=peerward_management::DnsProfile{id:uuid::Uuid::new_v4(),..Default::default()};selected.set(None);document.set(serde_json::to_string_pretty(&profile).unwrap_or_default());effective.set(None);confirmation.set(false);},{console_message(locale,"dns-new")}}}
            if let Some(profile)=parsed.clone(){
                fieldset{disabled:busy() || !ready||!can_write,
                    legend{{console_message(locale,"dns-basics")}}
                    if profile.id.to_string()!=mesh{label{{console_message(locale,"dns-device-scope")}
                        select{value:profile.scope.peers.first().map(ToString::to_string).unwrap_or_default(),onchange:move|event|{if let Ok(mut value)=serde_json::from_str::<peerward_management::DnsProfile>(&document()){value.scope=peerward_management::DeviceSelector::default();if let Ok(peer)=event.value().parse::<peerward_types::PeerId>(){value.scope.peers.insert(peer);}document.set(serde_json::to_string_pretty(&value).unwrap_or_default());effective.set(None);}},option{value:"",{console_message(locale,"dns-all-devices")}}for peer in peers(){option{value:"{peer.id}","{peer.name}"}}}
                    }}
                    label{{console_message(locale,"dns-search-domains")}input{value:profile.search_domains.join(", "),oninput:move|event|{if let Ok(mut value)=serde_json::from_str::<peerward_management::DnsProfile>(&document()){value.search_domains=event.value().split(',').map(str::trim).filter(|part|!part.is_empty()).map(str::to_owned).collect();document.set(serde_json::to_string_pretty(&value).unwrap_or_default());effective.set(None);}}}}
                    label{{console_message(locale,"dns-split-domain")}input{value:"{suffix}",oninput:move|event|suffix.set(event.value())}}
                    label{{console_message(locale,"dns-upstreams")}input{placeholder:"10.0.0.53:53, [fd00::53]:53",value:"{upstreams}",oninput:move|event|upstreams.set(event.value())}}
                    button{onclick:move|_|{
                        let Ok(mut value)=serde_json::from_str::<peerward_management::DnsProfile>(&document())else{return;};
                        let servers=upstreams().split(',').map(str::trim).map(str::parse::<std::net::SocketAddr>).collect::<Result<Vec<_>,_>>();
                        let Ok(servers)=servers else{error.set(console_message(locale,"dns-invalid").into());return;};
                        value.routes.retain(|route|route.suffix!=suffix().trim());value.routes.push(peerward_management::DnsRoute{suffix:suffix().trim().to_lowercase(),upstreams:servers});
                        if value.validate().is_err(){error.set(console_message(locale,"dns-invalid").into());return;}
                        document.set(serde_json::to_string_pretty(&value).unwrap_or_default());effective.set(None);
                    },{console_message(locale,"dns-add-split")}}
                    label{{console_message(locale,"dns-record-name")}input{value:"{record_name}",oninput:move|event|record_name.set(event.value())}}
                    label{{console_message(locale,"dns-record-value")}input{value:"{record_value}",oninput:move|event|record_value.set(event.value())}}
                    button{onclick:move|_|{
                        let Ok(mut value)=serde_json::from_str::<peerward_management::DnsProfile>(&document())else{return;};
                        let entry=match record_value().trim().parse::<std::net::IpAddr>(){Ok(std::net::IpAddr::V4(ip))=>peerward_management::DnsRecord::A(ip),Ok(std::net::IpAddr::V6(ip))=>peerward_management::DnsRecord::AAAA(ip),Err(_)=>peerward_management::DnsRecord::CNAME(record_value().trim().to_lowercase())};
                        value.records.insert(record_name().trim().to_lowercase(),vec![entry]);
                        if value.validate().is_err(){error.set(console_message(locale,"dns-invalid").into());return;}
                        document.set(serde_json::to_string_pretty(&value).unwrap_or_default());effective.set(None);
                    },{console_message(locale,"dns-add-record")}}
                }
                ul{for route in profile.routes{li{"{route.suffix} → {route.upstreams:?}"}}for (name,values) in profile.records{li{"{name} → {values:?}"}}}
            }
            details{summary{{console_message(locale,"dns-advanced")}}textarea{aria_label:console_message(locale,"dns-advanced"),rows:"12",disabled:busy() || !ready||!can_write,value:"{document}",oninput:move|event|{document.set(event.value());effective.set(None);}}}
            if !valid&&!document().is_empty(){p{role:"alert",{console_message(locale,"dns-invalid")}}}
            label{{console_message(locale,"dns-preview-device")}select{disabled:busy() || !ready,value:"{preview_peer}",onchange:move|event|{preview_peer.set(event.value());effective.set(None);},option{value:"",{console_message(locale,"network-select-device")}}for peer in peers(){option{value:"{peer.id}","{peer.name}"}}}}
            button{disabled:busy() || !ready||!valid||preview_peer().is_empty(),onclick:move|_|operate.call(2),{console_message(locale,"dns-preview")}}
            if let Some(value)=effective(){details{open:true,summary{{console_message(locale,"dns-effective")}}pre{{serde_json::to_string_pretty(&value).unwrap_or_default()}}}}
            if can_write{
                p{{console_message(locale,"dns-save-impact")}}
                button{disabled:busy() || !ready||!valid,onclick:move|_|operate.call(1),{console_message(locale,"dns-save")}}
                if selected.read().is_some_and(|(id,_)|id.to_string()!=mesh){details{summary{{console_message(locale,"dns-delete")}}label{input{r#type:"checkbox",checked:confirmation(),onchange:move|event|confirmation.set(event.checked())}{console_message(locale,"dns-delete-impact")}}button{disabled:busy() || !ready||!confirmation(),onclick:move|_|operate.call(3),{console_message(locale,"dns-delete")}}}}
            }
        }
    }
}
