#[component]
#[allow(unused_mut, unused_variables)]
fn ConfigurationOwnershipPanel(
    mesh: String,
    csrf: Option<String>,
    locale: Locale,
    #[props(default)] ready: bool,
) -> Element {
    let mut active = use_signal(|| mesh.clone());
    let mut epoch = use_signal(|| 0_u64);
    let mut view = use_signal(|| None::<peerward_api::ConfigurationOwnershipView>);
    let mut credentials = use_signal(Vec::<peerward_api::MachineCredentialResource>::new);
    let mut choice = use_signal(String::new);
    let mut confirmed = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut status = use_signal(String::new);
    let operate = use_callback(move |save: bool| {
        #[cfg(target_arch = "wasm32")]
        {
            if *busy.peek() || active.peek().is_empty() {
                return;
            }
            let mesh = active.peek().clone();
            let generation = *epoch.peek();
            let expected = view.peek().as_ref().map(|value| value.version);
            let owner = if choice.peek().is_empty() {
                None
            } else {
                match choice.peek().parse::<uuid::Uuid>() {
                    Ok(id) => Some(id),
                    Err(_) => return,
                }
            };
            let mut api = browser_api_client();
            if let Some(csrf) = &csrf {
                api = api.with_csrf(csrf.clone());
            }
            busy.set(true);
            error.set(String::new());
            status.set(String::new());
            spawn(async move {
                let base = format!("/api/v1/meshes/{mesh}");
                let path = format!("{base}/configuration/ownership");
                let result: Result<Value, ConsoleApiError> = if save {
                    match expected {
                        Some(version) => {
                            api.conditional_request(
                                Method::PUT,
                                &path,
                                Some(json!({"owner_machine_id":owner})),
                                version,
                            )
                            .await
                        }
                        None => Err(ConsoleApiError::InvalidResponse),
                    }
                } else {
                    api.request(Method::GET, &path, None).await
                };
                if *active.peek() != mesh || *epoch.peek() != generation {
                    return;
                }
                match result {
                    Ok(value) => match serde_json::from_value::<
                        peerward_api::ConfigurationOwnershipView,
                    >(value)
                    {
                        Ok(value) => {
                            if save || view.peek().is_none() {
                                choice.set(
                                    value
                                        .owner_machine_id
                                        .map_or_else(String::new, |id| id.to_string()),
                                );
                            }
                            view.set(Some(value));
                            if save {
                                confirmed.set(false);
                                status.set(
                                    console_message(locale, "configuration-owner-saved").into(),
                                );
                            }
                            let loaded = api
                                .bounded_network_list(&format!("{base}/machine-credentials"), 1000)
                                .await;
                            if *active.peek() != mesh || *epoch.peek() != generation {
                                return;
                            }
                            match loaded {
                                Ok(value) => credentials.set(value),
                                Err(failure) => error.set(api_error_body(failure).message),
                            }
                        }
                        Err(_) => error
                            .set(console_message(locale, "resource-rule-invalid-document").into()),
                    },
                    Err(failure) => {
                        let failure = api_error_body(failure);
                        error.set(format!(
                            "{}: {} ({})",
                            failure.code, failure.message, failure.request_id
                        ));
                    }
                }
                if *active.peek() == mesh && *epoch.peek() == generation {
                    busy.set(false);
                }
            });
        }
    });
    use_effect(use_reactive((&mesh,), move |(mesh,)| {
        if *active.peek() != mesh {
            let generation = epoch.peek().wrapping_add(1);
            epoch.set(generation);
            active.set(mesh);
            view.set(None);
            credentials.set(vec![]);
            choice.set(String::new());
            confirmed.set(false);
            busy.set(false);
            error.set(String::new());
            status.set(String::new());
        }
        operate.call(false);
    }));
    rsx! {
        section{class:"card network-management",aria_label:console_message(locale,"configuration-owner"),
            h2{{console_message(locale,"configuration-owner")}}
            p{{console_message(locale,"configuration-owner-help")}}
            if !error().is_empty(){p{role:"alert","{error}"}}
            if !status().is_empty(){p{role:"status","{status}"}}
            if let Some(value)=view(){
                p{{format!("{}: {}",console_message(locale,"configuration-owner-current"),value.owner_name.unwrap_or_else(||console_message(locale,"configuration-owner-manual").into()))}}
                if value.owner_machine_id.is_some()&&!value.owner_active{p{role:"status",{console_message(locale,"configuration-owner-inactive")}}}
            }
            button{disabled:busy()||!ready,onclick:move|_|operate.call(false),{console_message(locale,"resource-policy-reload")}}
            fieldset{disabled:busy()||!ready||view.read().is_none(),
                legend{{console_message(locale,"configuration-owner-transfer")}}
                label{{console_message(locale,"configuration-owner-select")}
                    select{value:"{choice}",onchange:move|event|{choice.set(event.value());confirmed.set(false);},
                        option{value:"",{console_message(locale,"configuration-owner-manual")}}
                        for credential in credentials().into_iter().filter(|value|value.revoked_at.is_none()&&value.capabilities.iter().any(|cap|cap=="resource_write")&&value.capabilities.iter().any(|cap|cap=="resource_read")){
                            option{value:"{credential.id}","{credential.name}"}
                        }
                    }
                }
                label{input{r#type:"checkbox",checked:confirmed(),onchange:move|event|confirmed.set(event.checked())}{console_message(locale,"configuration-owner-impact")}}
                button{disabled:!confirmed(),onclick:move|_|operate.call(true),{console_message(locale,"configuration-owner-save")}}
            }
        }
    }
}
