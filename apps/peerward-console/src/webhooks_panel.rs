#[derive(Clone, PartialEq)]
struct WebhookDraft {
    id: uuid::Uuid,
    version: Option<u64>,
    name: String,
    endpoint: String,
    enabled: bool,
    events: std::collections::BTreeSet<String>,
}
impl Default for WebhookDraft {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            version: None,
            name: String::new(),
            endpoint: String::new(),
            enabled: false,
            events: std::collections::BTreeSet::from(["peer.disabled".into()]),
        }
    }
}
#[derive(Clone, Copy)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
enum WebhookOperation {
    Load,
    Save,
    Delete(uuid::Uuid, u64),
    Deliveries(uuid::Uuid, bool),
    Retry(uuid::Uuid, uuid::Uuid, u64),
}

#[component]
#[allow(unused_mut, unused_variables)]
fn WebhooksPanel(
    mesh: String,
    csrf: Option<String>,
    locale: Locale,
    can_manage: bool,
    #[props(default)] ready: bool,
) -> Element {
    let mut active = use_signal(|| mesh.clone());
    let mut epoch = use_signal(|| 0_u64);
    let mut draft = use_signal(WebhookDraft::default);
    let mut drafts = use_signal(BTreeMap::<String, WebhookDraft>::new);
    let mut hooks = use_signal(Vec::<peerward_api::WebhookResource>::new);
    let mut topics = use_signal(Vec::<String>::new);
    let mut deliveries = use_signal(Vec::<peerward_api::WebhookDeliveryResource>::new);
    let mut selected = use_signal(|| None::<uuid::Uuid>);
    let mut cursor = use_signal(|| None::<String>);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut confirm = use_signal(|| false);
    let mut deleting = use_signal(|| None::<uuid::Uuid>);
    let operate = use_callback(move |operation: WebhookOperation| {
        #[cfg(target_arch = "wasm32")]
        {
            if *busy.peek() || active.peek().is_empty() {
                return;
            }
            let mesh = active.peek().clone();
            let generation = *epoch.peek();
            let data = draft.peek().clone();
            let after = cursor.peek().clone();
            let mut api = browser_api_client();
            if let Some(csrf) = &csrf {
                api = api.with_csrf(csrf.clone());
            }
            busy.set(true);
            error.set(String::new());
            spawn(async move {
                let path = format!("/api/v1/meshes/{mesh}/webhooks");
                let result: Result<Value, ConsoleApiError> = match operation {
                    WebhookOperation::Load | WebhookOperation::Deliveries(..) => Ok(Value::Null),
                    WebhookOperation::Save => {
                        let mut body = json!({"name":data.name,"endpoint":data.endpoint,"enabled":data.enabled,"event_types":data.events});
                        if let Some(version) = data.version {
                            api.conditional_request(
                                Method::PUT,
                                &format!("{path}/{}", data.id),
                                Some(body),
                                version,
                            )
                            .await
                        } else {
                            body["id"] = json!(data.id);
                            api.request(Method::POST, &path, Some(body)).await
                        }
                    }
                    WebhookOperation::Delete(id, version) => {
                        api.conditional_request(
                            Method::DELETE,
                            &format!("{path}/{id}"),
                            None,
                            version,
                        )
                        .await
                    }
                    WebhookOperation::Retry(hook, id, version) => {
                        api.conditional_request(
                            Method::POST,
                            &format!("{path}/{hook}/deliveries/{id}/retry"),
                            None,
                            version,
                        )
                        .await
                    }
                };
                if *active.peek() != mesh || *epoch.peek() != generation {
                    return;
                }
                match result {
                    Ok(_) => {
                        if matches!(
                            operation,
                            WebhookOperation::Save | WebhookOperation::Delete(..)
                        ) {
                            draft.set(WebhookDraft::default());
                            confirm.set(false);
                            deleting.set(None);
                            deliveries.set(vec![]);
                            selected.set(None);
                            cursor.set(None);
                        }
                        match operation {
                            WebhookOperation::Deliveries(id, _)
                            | WebhookOperation::Retry(id, _, _) => {
                                let more =
                                    matches!(operation, WebhookOperation::Deliveries(_, true));
                                let mut url = format!("{path}/{id}/deliveries?limit=50");
                                if more && let Some(after) = after {
                                    url.push_str("&cursor=");
                                    url.push_str(&after);
                                }
                                let result = api
                                    .request::<Page<peerward_api::WebhookDeliveryResource>>(
                                        Method::GET,
                                        &url,
                                        None,
                                    )
                                    .await;
                                if *active.peek() != mesh || *epoch.peek() != generation {
                                    return;
                                }
                                match result {
                                    Ok(page) => {
                                        if more {
                                            deliveries.write().extend(page.items);
                                        } else {
                                            deliveries.set(page.items);
                                        }
                                        cursor.set(page.next_cursor);
                                        selected.set(Some(id));
                                    }
                                    Err(failure) => error.set(api_error_body(failure).message),
                                }
                            }
                            _ => {
                                let result = api.bounded_network_list(&path, 16).await;
                                if *active.peek() != mesh || *epoch.peek() != generation {
                                    return;
                                }
                                match result {
                                    Ok(items) => hooks.set(items),
                                    Err(failure) => error.set(api_error_body(failure).message),
                                }
                                let result = api
                                    .request::<Vec<String>>(
                                        Method::GET,
                                        &format!("/api/v1/meshes/{mesh}/webhook-event-types"),
                                        None,
                                    )
                                    .await;
                                if *active.peek() != mesh || *epoch.peek() != generation {
                                    return;
                                }
                                match result {
                                    Ok(items) => topics.set(items),
                                    Err(failure) => error.set(api_error_body(failure).message),
                                }
                            }
                        }
                    }
                    Err(failure) => {
                        let body = api_error_body(failure);
                        error.set(format!(
                            "{}: {} ({})",
                            body.code, body.message, body.request_id
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
            let next_epoch = epoch.peek().wrapping_add(1);
            epoch.set(next_epoch);
            drafts
                .write()
                .insert(active.peek().clone(), draft.peek().clone());
            draft.set(drafts.peek().get(&mesh).cloned().unwrap_or_default());
            active.set(mesh);
            hooks.set(vec![]);
            topics.set(vec![]);
            deliveries.set(vec![]);
            selected.set(None);
            cursor.set(None);
            busy.set(false);
            confirm.set(false);
            deleting.set(None);
        }
        operate.call(WebhookOperation::Load);
    }));
    let disabled = busy() || !ready || active().is_empty();
    rsx! {
        section { class:"card",id:"webhooks-panel",
            h2 {{console_message(locale,"webhooks-title")}}
            p {{console_message(locale,"webhooks-help")}}
            if !error().is_empty() {p {role:"alert","{error}"}}
            button {disabled,onclick:move |_|operate.call(WebhookOperation::Load),{console_message(locale,"webhooks-refresh")}}
            if hooks().is_empty() {p {{console_message(locale,"webhooks-empty")}}}
            for hook in hooks() {
                article {key:"{hook.id}",class:"card",
                    h3 {"{hook.name}"}
                    p {"{hook.endpoint}"}
                    p {if hook.enabled {{console_message(locale,"webhooks-enabled")}}else{{console_message(locale,"webhooks-disabled")}}}
                    p {"{hook.pending_deliveries} / {hook.dead_deliveries} / {hook.dropped_events} " {console_message(locale,"webhooks-counts")}}
                    details {summary {{console_message(locale,"webhooks-verifier")}}
                        p {"Mesh: {active()}"} p {"Webhook: {hook.id}"}
                        code {{hook.signing_public_key.clone().unwrap_or_else(||console_message(locale,"webhooks-unknown").into())}}
                        p {{console_message(locale,"webhooks-verifier-help")}}
                    }
                    button {disabled,onclick:move |_|operate.call(WebhookOperation::Deliveries(hook.id,false)),{console_message(locale,"webhooks-deliveries")}}
                    if can_manage {
                        button {disabled,onclick:{let hook=hook.clone();move |_|{draft.set(WebhookDraft{id:hook.id,version:Some(hook.version),name:hook.name.clone(),endpoint:hook.endpoint.clone(),enabled:hook.enabled,events:hook.event_types.iter().cloned().collect()});confirm.set(false);}}, {console_message(locale,"webhooks-edit")}}
                        if deleting()==Some(hook.id) {
                            p {{console_message(locale,"webhooks-delete-impact")}}
                            button {disabled,onclick:move |_|operate.call(WebhookOperation::Delete(hook.id,hook.version)),{console_message(locale,"webhooks-confirm")}}
                            button {disabled,onclick:move |_|deleting.set(None),{console_message(locale,"webhooks-cancel")}}
                        } else {button {disabled,onclick:move |_|deleting.set(Some(hook.id)),{console_message(locale,"webhooks-delete")}}}
                    }
                }
            }
            if can_manage {
                form {class:"console-form",onsubmit:move |event|{event.prevent_default();if !draft.peek().enabled || *confirm.peek() {operate.call(WebhookOperation::Save);}},
                    label {r#for:"webhook-name",{console_message(locale,"name")}}
                    input {id:"webhook-name",required:true,maxlength:128,disabled,value:draft().name,oninput:move |event|draft.write().name=event.value()}
                    label {r#for:"webhook-endpoint",{console_message(locale,"webhooks-endpoint")}}
                    input {id:"webhook-endpoint",required:true,r#type:"url",maxlength:2048,disabled,value:draft().endpoint,oninput:move |event|{draft.write().endpoint=event.value();confirm.set(false);}}
                    fieldset {class:"webhook-events",disabled,legend {{console_message(locale,"webhooks-events")}}
                        for topic in topics() {label {key:"{topic}",input {r#type:"checkbox",checked:draft().events.contains(&topic),onchange:move |event|{if event.checked(){draft.write().events.insert(topic.clone());}else{draft.write().events.remove(&topic);}}},"{topic}"}}
                    }
                    label {input {r#type:"checkbox",id:"webhook-enabled",disabled,checked:draft().enabled,onchange:move |event|{draft.write().enabled=event.checked();confirm.set(false);}}, {console_message(locale,"webhooks-enable")}}
                    if draft().enabled {
                        label {input {r#type:"checkbox",id:"webhook-confirm",disabled,checked:confirm(),onchange:move |event|confirm.set(event.checked())},{console_message(locale,"webhooks-enable-impact")}}
                    }
                    button {r#type:"submit",disabled:disabled || draft().events.is_empty() || (draft().enabled && !confirm()),{console_message(locale,"webhooks-save")}}
                    button {r#type:"button",disabled,onclick:move |_|{draft.set(WebhookDraft::default());confirm.set(false);},{console_message(locale,"webhooks-cancel")}}
                }
            }
            if let Some(hook)=selected() {
                h3 {{console_message(locale,"webhooks-deliveries")}}
                p {{console_message(locale,"webhooks-retention")}}
                if deliveries().is_empty() {p {{console_message(locale,"webhooks-no-deliveries")}}}
                for delivery in deliveries() {
                    div {key:"{delivery.id}",class:"card",
                        strong {"{delivery.event.kind}"}
                        p {"{delivery.status} · {delivery.attempts} · {delivery.result_code.clone().unwrap_or_default()}"}
                        time {"{delivery.created_at}"}
                        details {summary {{console_message(locale,"webhooks-details")}}code {"{delivery.id}"}p {"{delivery.next_attempt_at}"}}
                        if can_manage && delivery.status=="failed" {button {disabled,onclick:move |_|operate.call(WebhookOperation::Retry(hook,delivery.id,delivery.version)),{console_message(locale,"webhooks-retry")}}}
                    }
                }
                if cursor().is_some() {button {disabled,onclick:move |_|operate.call(WebhookOperation::Deliveries(hook,true)),{console_message(locale,"webhooks-load-more")}}}
                button {disabled,onclick:move |_|operate.call(WebhookOperation::Deliveries(hook,false)),{console_message(locale,"webhooks-refresh")}}
            }
        }
    }
}
