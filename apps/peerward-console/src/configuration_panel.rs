#[derive(Clone, Copy, PartialEq)]
enum ConfigurationOperation {
    Load,
    Validate,
    Preview,
    Apply,
}

#[component]
#[allow(unused_mut, unused_variables)]
fn ConfigurationPanel(
    mesh: String,
    csrf: Option<String>,
    locale: Locale,
    can_write: bool,
    #[props(default)] ready: bool,
) -> Element {
    let mut active = use_signal(|| mesh.clone());
    let mut generation = use_signal(|| 0u64);
    let mut version = use_signal(|| None::<u64>);
    let mut current = use_signal(String::new);
    let mut draft = use_signal(String::new);
    let mut drafts = use_signal(BTreeMap::<String, String>::new);
    let mut result = use_signal(|| None::<peerward_api::ConfigurationPreview>);
    let mut pending = use_signal(|| None::<(u64, Value)>);
    let mut confirmed = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut status = use_signal(String::new);
    let operate = use_callback(move |operation: ConfigurationOperation| {
        #[cfg(target_arch = "wasm32")]
        {
            if *busy.peek() || active.peek().is_empty() {
                return;
            }
            let mesh = active.peek().clone();
            let epoch = *generation.peek();
            let base = format!("/api/v1/meshes/{mesh}/configuration");
            let mut api = browser_api_client();
            if let Some(csrf) = &csrf {
                api = api.with_csrf(csrf.clone());
            }
            let selected = *version.peek();
            let request = if operation == ConfigurationOperation::Load {
                None
            } else if let Ok(value) =
                serde_json::from_str::<peerward_api::ConfigurationDocument>(&draft.peek())
            {
                Some(serde_json::to_value(value).unwrap_or(Value::Null))
            } else {
                error.set(console_message(locale, "configuration-invalid").into());
                return;
            };
            let application = if operation == ConfigurationOperation::Apply {
                if let Some(prior) = pending.peek().clone() {
                    Some(prior)
                } else {
                    let Some(preview) = result
                        .peek()
                        .clone()
                        .filter(|value| value.can_apply && !value.applied)
                    else {
                        return;
                    };
                    if !*confirmed.peek() || Some(preview.version) != selected {
                        return;
                    }
                    let body = json!({"request_id":uuid::Uuid::new_v4(),"document":request,"preview_digest":preview.preview_digest});
                    let request = (preview.version, body);
                    pending.set(Some(request.clone()));
                    Some(request)
                }
            } else {
                None
            };
            busy.set(true);
            if matches!(
                operation,
                ConfigurationOperation::Validate | ConfigurationOperation::Preview
            ) {
                // A previous preview does not describe the in-flight snapshot. Hide
                // it immediately so its confirmation cannot race the new result.
                result.set(None);
                confirmed.set(false);
            }
            error.set(String::new());
            status.set(String::new());
            spawn(async move {
                let response: Result<Value, ConsoleApiError> = match operation {
                    ConfigurationOperation::Load => {
                        api.request(Method::GET, &format!("{base}/export"), None)
                            .await
                    }
                    ConfigurationOperation::Validate => {
                        api.request(Method::POST, &format!("{base}/validate"), request)
                            .await
                    }
                    ConfigurationOperation::Preview => match selected {
                        Some(version) => {
                            api.conditional_request(
                                Method::POST,
                                &format!("{base}/preview"),
                                request,
                                version,
                            )
                            .await
                        }
                        None => Err(ConsoleApiError::InvalidResponse),
                    },
                    ConfigurationOperation::Apply => match application {
                        Some((version, body)) => {
                            api.conditional_request(
                                Method::POST,
                                &format!("{base}/apply"),
                                Some(body),
                                version,
                            )
                            .await
                        }
                        None => Err(ConsoleApiError::InvalidResponse),
                    },
                };
                if *active.peek() != mesh || *generation.peek() != epoch {
                    return;
                }
                match response {
                    Ok(value) => {
                        if operation == ConfigurationOperation::Load {
                            match serde_json::from_value::<peerward_api::ConfigurationSnapshot>(
                                value,
                            ) {
                                Ok(snapshot) => {
                                    let encoded = serde_json::to_string_pretty(&snapshot.document)
                                        .unwrap_or_default();
                                    if draft.peek().is_empty() {
                                        draft.set(encoded.clone());
                                    }
                                    current.set(encoded);
                                    version.set(Some(snapshot.version));
                                    if pending.peek().is_none() {
                                        result.set(None);
                                        confirmed.set(false);
                                    }
                                    status.set(
                                        console_message(locale, "configuration-loaded").into(),
                                    );
                                }
                                Err(_) => error
                                    .set(console_message(locale, "configuration-invalid").into()),
                            }
                        } else {
                            match serde_json::from_value::<peerward_api::ConfigurationPreview>(
                                value,
                            ) {
                                Ok(preview) => {
                                    if preview.applied {
                                        pending.set(None);
                                        version.set(Some(preview.version));
                                        current.set(draft.peek().clone());
                                        confirmed.set(false);
                                        status.set(
                                            console_message(locale, "configuration-saved").into(),
                                        );
                                    }
                                    // Validation can be run without an export; its version is
                                    // still bound to the actual locked dependency snapshot.
                                    if matches!(
                                        operation,
                                        ConfigurationOperation::Validate
                                            | ConfigurationOperation::Preview
                                    ) {
                                        version.set(Some(preview.version));
                                        pending.set(None);
                                        confirmed.set(false);
                                    }
                                    result.set(Some(preview));
                                }
                                Err(_) => error
                                    .set(console_message(locale, "configuration-invalid").into()),
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
                busy.set(false);
            });
        }
    });
    use_effect(use_reactive((&mesh,), move |(mesh,)| {
        if *active.peek() != mesh {
            let epoch = generation.peek().wrapping_add(1);
            generation.set(epoch);
            let previous = active.peek().clone();
            drafts.write().insert(previous, draft.peek().clone());
            let retained = drafts.peek().get(&mesh).cloned().unwrap_or_default();
            active.set(mesh);
            draft.set(retained);
            version.set(None);
            current.set(String::new());
            result.set(None);
            pending.set(None);
            confirmed.set(false);
            busy.set(false);
            error.set(String::new());
            status.set(String::new());
        }
    }));
    use_effect(use_reactive((&mesh, &ready), move |(mesh, ready)| {
        if ready && !mesh.is_empty() {
            operate.call(ConfigurationOperation::Load);
        }
    }));
    let set_draft = use_callback(move |value: String| {
        draft.set(value);
        result.set(None);
        pending.set(None);
        confirmed.set(false);
        status.set(String::new());
    });
    let export = {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        format!(
            "data:application/json;charset=utf-8;base64,{}",
            STANDARD.encode(current().as_bytes())
        )
    };
    let apply_enabled = can_write
        && !busy()
        && confirmed()
        && (pending().is_some()
            || result().is_some_and(|p| p.can_apply && !p.applied && Some(p.version) == version()));
    rsx! {
        section{class:"management-card",aria_label:console_message(locale,"configuration-title"),
            h2{ {console_message(locale,"configuration-title")} }
            p{class:"muted",{console_message(locale,"configuration-help")}}
            div{class:"actions",
                button{r#type:"button",disabled:busy(),onclick:move |_|operate.call(ConfigurationOperation::Load),{console_message(locale,"configuration-load")}}
                if !current().is_empty(){a{href:export,download:"peerward-configuration.json",{console_message(locale,"configuration-export")}}}
            }
            if let Some(version)=version(){p{class:"muted","Version {version}"}}
            if !error().is_empty(){p{class:"form-error",role:"alert","{error}"}}
            if !status().is_empty(){p{role:"status","{status}"}}
            if can_write {
                label{r#for:"configuration-file",{console_message(locale,"configuration-import")}}
                input{id:"configuration-file",r#type:"file",accept:".json,application/json",disabled:busy(),onchange:move |event|{
                    let Some(file)=event.files().into_iter().next()else{return;};
                    if file.size()>peerward_api::MAX_REQUEST_BYTES as u64{error.set(console_message(locale,"configuration-invalid").into());return;}
                    let mesh=active.peek().clone();let epoch=*generation.peek();
                    spawn(async move {
                        let contents=file.read_bytes().await.ok().and_then(|bytes|String::from_utf8(bytes.to_vec()).ok());
                        if *active.peek()!=mesh||*generation.peek()!=epoch{return;}
                        match contents{Some(value)=>set_draft.call(value),None=>error.set(console_message(locale,"configuration-invalid").into())}
                    });
                }}
                label{r#for:"configuration-document",{console_message(locale,"configuration-document")}}
                textarea{id:"configuration-document",rows:14,value:draft,disabled:busy(),oninput:move |e|set_draft.call(e.value())}
                div{class:"actions",
                    button{r#type:"button",disabled:busy()||draft().is_empty(),onclick:move |_|operate.call(ConfigurationOperation::Validate),{console_message(locale,"configuration-validate")}}
                    button{r#type:"button",disabled:busy()||version().is_none()||draft().is_empty(),onclick:move |_|operate.call(ConfigurationOperation::Preview),{console_message(locale,"configuration-preview")}}
                }
                if let Some(preview)=result(){
                    p{role:"status",{if preview.can_apply{console_message(locale,"configuration-ready")}else{console_message(locale,"configuration-tests-failed")}}}
                    ul{for change in preview.changes {li{key:"{change.kind}-{change.id}-{change.change}","{change.kind}: {change.change} ",code{"{change.id}"}}}}
                    if !preview.failed_tests.is_empty(){p{class:"form-error",{console_message(locale,"configuration-test-results")}}ul{for id in preview.failed_tests{li{code{"{id}"}}}}}
                }
                if pending().is_some(){p{class:"muted",{console_message(locale,"configuration-retry")}}}
                label{input{r#type:"checkbox",checked:confirmed,disabled:busy(),onchange:move |e|confirmed.set(e.checked())}{console_message(locale,"configuration-confirm")}}
                button{r#type:"button",disabled:!apply_enabled,onclick:move |_|operate.call(ConfigurationOperation::Apply),{console_message(locale,"configuration-apply")}}
            }
        }
    }
}
