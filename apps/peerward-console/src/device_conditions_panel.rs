#[derive(Clone, PartialEq, Default)]
struct DeviceConditionDraft {
    definition: peerward_management::DeviceConditions,
    version: Option<u64>,
    minimum_version: String,
    scope: String,
}
impl DeviceConditionDraft {
    fn value(&self) -> Option<peerward_management::DeviceConditions> {
        let mut value = self.definition.clone();
        value.minimum_version = (!self.minimum_version.trim().is_empty())
            .then(|| self.minimum_version.trim().to_owned());
        value.scope = serde_json::from_str(if self.scope.is_empty() {
            "{}"
        } else {
            &self.scope
        })
        .ok()?;
        value.validate().ok()?;
        Some(value)
    }
    #[cfg(any(target_arch = "wasm32", test))]
    fn from_response(value: &Value) -> Option<Self> {
        let definition: peerward_management::DeviceConditions =
            serde_json::from_value(value["definition"].clone()).ok()?;
        Some(Self {
            version: value["version"].as_u64(),
            minimum_version: definition.minimum_version.clone().unwrap_or_default(),
            scope: serde_json::to_string_pretty(&definition.scope).ok()?,
            definition,
        })
    }
}

#[component]
#[allow(unused_mut, unused_variables)]
fn DeviceConditionsPanel(
    mesh: String,
    csrf: Option<String>,
    can_write: bool,
    locale: Locale,
    #[props(default)] ready: bool,
) -> Element {
    let mut active_mesh = use_signal(|| mesh.clone());
    let mut generation = use_signal(|| 0_u64);
    let mut draft = use_signal(DeviceConditionDraft::default);
    let mut drafts = use_signal(BTreeMap::<String, DeviceConditionDraft>::new);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut status = use_signal(String::new);
    let mut confirmed = use_signal(|| false);
    let mut changed = use_signal(|| false);
    let mut peers = use_signal(Vec::<PeerResource>::new);
    let mut selected = use_signal(String::new);
    let mut observation = use_signal(|| None::<Value>);
    let mut restricted = use_signal(|| None::<u64>);
    let operate = use_callback(move |operation: u8| {
        #[cfg(target_arch = "wasm32")]
        {
            if *busy.peek()
                || active_mesh.peek().is_empty()
                || (operation == 1 && (!can_write || !*confirmed.peek()))
            {
                return;
            }
            let mesh = active_mesh.peek().clone();
            let captured_generation = *generation.peek();
            let captured = draft.peek().clone();
            let target = selected.peek().clone();
            if operation == 1 && (captured.value().is_none() || captured.version.is_none()) {
                return;
            }
            if operation == 2 && target.is_empty() {
                return;
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
                let path = format!("{base}/device-conditions");
                let result: Result<Value, ConsoleApiError> = match operation {
                    0 => api.request(Method::GET, &path, None).await,
                    1 => {
                        api.conditional_request(
                            Method::PUT,
                            &path,
                            Some(json!(captured.value())),
                            captured.version.unwrap_or(0),
                        )
                        .await
                    }
                    2 => {
                        api.request(
                            Method::GET,
                            &format!("{base}/peers/{target}/device-condition"),
                            None,
                        )
                        .await
                    }
                    _ => Err(ConsoleApiError::InvalidResponse),
                };
                if *active_mesh.peek() != mesh || *generation.peek() != captured_generation {
                    return;
                }
                match result {
                    Ok(value) => {
                        if operation == 2 {
                            observation.set(Some(value));
                        } else {
                            restricted.set(value["restricted_devices"].as_u64());
                            if (operation == 1 || captured.version.is_none())
                                && let Some(next) = DeviceConditionDraft::from_response(&value)
                            {
                                draft.set(next);
                                changed.set(false);
                            }
                            if operation == 1 {
                                confirmed.set(false);
                                status.set(console_message(locale, "network-saved").into());
                                observation.set(None);
                            }
                            let loaded = api
                                .bounded_network_list::<PeerResource>(
                                    &format!("{base}/peers"),
                                    4096,
                                )
                                .await;
                            if *active_mesh.peek() != mesh
                                || *generation.peek() != captured_generation
                            {
                                return;
                            }
                            match loaded {
                                Ok(values) => peers.set(values),
                                Err(e) => error.set(e.to_string()),
                            }
                        }
                    }
                    Err(e) => error.set(e.to_string()),
                }
                busy.set(false);
            });
        }
    });
    use_effect(use_reactive((&mesh, &ready), move |(mesh, ready)| {
        if *active_mesh.peek() != mesh {
            let old = active_mesh.peek().clone();
            drafts.write().insert(old, draft.peek().clone());
            let next = drafts.peek().get(&mesh).cloned().unwrap_or_default();
            active_mesh.set(mesh);
            generation += 1;
            draft.set(next);
            changed.set(false);
            busy.set(false);
            confirmed.set(false);
            error.set(String::new());
            status.set(String::new());
            selected.set(String::new());
            peers.set(vec![]);
            observation.set(None);
            restricted.set(None);
        }
        if ready {
            operate.call(0);
        }
    }));
    let valid = draft.read().value().is_some();
    rsx! {
        section { class:"card device-conditions console-form", aria_label:console_message(locale,"conditions-title"), "data-console-dirty":changed.to_string(),
            h2 { {console_message(locale,"conditions-title")} }
            if !error().is_empty() { p { role:"alert", "{error}" } }
            if !status().is_empty() && !busy() { p { role:"status", "{status}" } }
            if !ready || busy() {p {role:"status",{console_message(locale,"loading")}}}
            fieldset { class:"plain-fieldset", disabled:!ready || busy() || !can_write || draft.read().version.is_none(),
                label {class:"setting-toggle",
                    span {strong{{console_message(locale,"conditions-enabled")}}small{id:"conditions-enable-help",{console_text(locale,"不满足要求的设备将被限制业务通信。","Devices that do not meet the requirements have restricted traffic.")}}}
                    input { class:"switch-input", aria_label:console_message(locale,"conditions-enabled"), aria_describedby:"conditions-enable-help", r#type:"checkbox", checked:draft.read().definition.enabled, onchange:move |e|{draft.write().definition.enabled=e.checked();confirmed.set(false);changed.set(true);} }
                }
                label { {console_message(locale,"conditions-version")} input { id:"condition-minimum-version",value:draft.read().minimum_version.clone(),oninput:move |e|{draft.write().minimum_version=e.value();confirmed.set(false);changed.set(true);} } }
                p{class:"field-label",{console_text(locale,"允许的平台","Allowed platforms")}}
                div {class:"check-row",for (platform,label) in [(peerward_management::DevicePlatform::Linux,"Linux"),(peerward_management::DevicePlatform::Android,"Android")] {
                    label { input {r#type:"checkbox",checked:draft.read().definition.platforms.contains(&platform),onchange:move |e|{if e.checked(){draft.write().definition.platforms.insert(platform);}else{draft.write().definition.platforms.remove(&platform);}confirmed.set(false);changed.set(true);}} "{label}" }
                }}
                p {class:"field-help",{console_message(locale,"conditions-platform-help")} }
                details {class:"condition-advanced",summary{{console_text(locale,"高级条件与证据范围","Advanced conditions and evidence scope")}}
                    p {class:"field-help",{console_message(locale,"conditions-boundary")}}
                    label { {console_message(locale,"conditions-credential")} select { value:draft.read().definition.minimum_credential_seconds.to_string(),onchange:move |e|{if let Ok(value)=e.value().parse(){draft.write().definition.minimum_credential_seconds=value;confirmed.set(false);changed.set(true);}},
                        for seconds in [0,60,300,900,3600,86400] {option {value:"{seconds}","{seconds}"}}
                    } }
                    for (cap,key) in [
                        (peerward_management::DeviceCapability::ManagedDns,"conditions-cap-dns"),
                        (peerward_management::DeviceCapability::ResourceConsumer,"conditions-cap-resource"),
                        (peerward_management::DeviceCapability::ExitConsumer,"conditions-cap-exit"),
                        (peerward_management::DeviceCapability::SubnetGateway,"conditions-cap-gateway"),
                        (peerward_management::DeviceCapability::ExitGateway,"conditions-cap-exit-gateway"),
                    ] { label { input {r#type:"checkbox",checked:draft.read().definition.required_capabilities.contains(&cap),onchange:move |e|{if e.checked(){draft.write().definition.required_capabilities.insert(cap);}else{draft.write().definition.required_capabilities.remove(&cap);}confirmed.set(false);changed.set(true);}} {console_message(locale,key)} } }
                    details {summary { {console_message(locale,"conditions-scope")} } p {{console_message(locale,"conditions-scope-help")}} textarea {aria_label:console_message(locale,"conditions-scope"),value:draft.read().scope.clone(),oninput:move |e|{draft.write().scope=e.value();confirmed.set(false);changed.set(true);}} }
                }
                if !valid { p {role:"alert",{console_message(locale,"conditions-invalid")}} }
                label {class:"condition-confirm",input {r#type:"checkbox",checked:confirmed(),onchange:move |e|confirmed.set(e.checked())} {console_message(locale,"conditions-confirm")}}
                button { disabled:!valid || !confirmed() || draft.read().version.is_none(),onclick:move |_|operate.call(1),{console_message(locale,"conditions-save")} }
            }
            details {class:"condition-inspection",summary{{console_text(locale,"生效情况与重新读取","Effective state and reload")}}
                if let Some(count)=restricted() { p { {console_message(locale,"conditions-restricted")} " {count}" } }
                button {class:"secondary-button",disabled:!ready || busy(),onclick:move |_|{draft.write().version=None;confirmed.set(false);operate.call(0);},{console_message(locale,"conditions-reload")}}
                label { {console_message(locale,"conditions-inspect")} select {disabled:busy(),value:selected(),onchange:move |e|{selected.set(e.value());observation.set(None);},option {value:"",{console_message(locale,"conditions-select")}} for peer in peers.read().iter() {option {value:peer.id.to_string(),"{peer.name}"}} } }
                button {disabled:busy() || selected().is_empty(),onclick:move |_|operate.call(2),{console_message(locale,"conditions-inspect")}}
                if let Some(value)=observation() {
                    p {role:"status",{console_message(locale,if value["decision"]["allowed"]==true {"conditions-allowed"} else {"conditions-blocked"})}}
                    if let Some(reasons)=value["decision"]["reasons"].as_array(){for reason in reasons {p {{console_message(locale,match reason.as_str(){Some("version")=>"conditions-reason-version",Some("platform")=>"conditions-reason-platform",Some("capabilities")=>"conditions-reason-capabilities",Some("credential")=>"conditions-reason-credential",_=>"conditions-reason-evidence"})}}}}
                    details {summary {{console_message(locale,"technical-details")}} pre { {serde_json::to_string_pretty(&value).unwrap_or_default()} } }
                }
            }
        }
    }
}
