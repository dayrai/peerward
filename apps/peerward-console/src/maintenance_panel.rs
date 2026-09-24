#[component]
#[allow(unused_mut, unused_variables)]
fn MaintenancePanel(
    csrf: Option<String>,
    locale: Locale,
    #[props(default)] ready: bool,
) -> Element {
    let mut hosts = use_signal(Vec::<Value>::new);
    let mut tasks = use_signal(Vec::<Value>::new);
    let mut host = use_signal(String::new);
    let mut replacement = use_signal(String::new);
    let mut operation = use_signal(|| "relay_drain".to_string());
    let mut grace = use_signal(|| "60".to_string());
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut preview = use_signal(|| None::<Value>);
    let mut confirmation = use_signal(|| false);
    let mut request_id = use_signal(uuid::Uuid::new_v4);
    let mut cursor = use_signal(|| None::<String>);
    let mut generation = use_signal(|| 0u64);
    let mut retry = use_signal(|| None::<(String, u64)>);
    let operate = use_callback(move |action: u8| {
        #[cfg(target_arch = "wasm32")]
        {
            if !ready || *busy.peek() {
                return;
            }
            let Some(seconds) = grace
                .peek()
                .parse::<u32>()
                .ok()
                .filter(|v| (15..=900).contains(v))
            else {
                return;
            };
            let plan = json!({"operation":operation.peek().clone(),"host_id":host.peek().clone(),
                "replacement_host_id":if operation.peek().as_str()=="relay_drain" {Some(replacement.peek().clone())}else{None},"grace_seconds":seconds});
            let selected = preview.peek().clone();
            let retrying = retry.peek().clone();
            if matches!(action, 1 | 2) && host.peek().is_empty() {
                return;
            }
            if action == 2
                && (!*confirmation.peek()
                    || selected.as_ref().is_none_or(|v| v["blockers"] != json!([])))
            {
                return;
            }
            if action == 4 && (!*confirmation.peek() || retrying.is_none()) {
                return;
            }
            let id = *request_id.peek();
            let epoch = *generation.peek();
            let after = cursor.peek().clone();
            let mut api = browser_api_client();
            if let Some(csrf) = &csrf {
                api = api.with_csrf(csrf.clone());
            }
            busy.set(true);
            error.set(String::new());
            spawn(async move {
                let path = "/api/v1/maintenance-tasks";
                let result:Result<Value,ConsoleApiError>=match action {
                    1=>api.request(Method::POST,&format!("{path}/preview"),Some(plan.clone())).await,
                    2=>api.request(Method::POST,path,Some(json!({"id":id,"plan":plan,"preview_digest":selected.as_ref().map(|v|v["digest"].clone())}))).await,
                    4=>{let (id,version)=retrying.unwrap_or_default();api.conditional_request(Method::POST,&format!("{path}/{id}/retry"),None,version).await},
                    _=>Ok(Value::Null),
                };
                if *generation.peek() != epoch {
                    return;
                }
                match result {
                    Ok(value) => {
                        if action == 1 {
                            preview.set(Some(value));
                            confirmation.set(false);
                            request_id.set(uuid::Uuid::new_v4());
                        } else {
                            if matches!(action, 2 | 4) {
                                preview.set(None);
                                confirmation.set(false);
                                retry.set(None);
                            }
                            let loaded: Result<Value, ConsoleApiError> =
                                api.request(Method::GET, "/api/v1/relay-hosts", None).await;
                            let task_path = if action == 3 {
                                after.map_or_else(|| path.into(), |c| format!("{path}?cursor={c}"))
                            } else {
                                path.into()
                            };
                            let history: Result<Value, ConsoleApiError> =
                                api.request(Method::GET, &task_path, None).await;
                            if *generation.peek() != epoch {
                                return;
                            }
                            match (loaded, history) {
                                (Ok(loaded), Ok(history)) => {
                                    hosts.set(
                                        loaded["items"].as_array().cloned().unwrap_or_default(),
                                    );
                                    let values =
                                        history["items"].as_array().cloned().unwrap_or_default();
                                    if action == 3 {
                                        tasks.write().extend(values);
                                    } else {
                                        tasks.set(values);
                                    }
                                    cursor.set(history["next_cursor"].as_str().map(str::to_owned));
                                }
                                (Err(e), _) | (_, Err(e)) => error.set(e.to_string()),
                            }
                        }
                    }
                    Err(e) => error.set(e.to_string()),
                }
                busy.set(false);
            });
        }
    });
    use_effect(use_reactive(&ready, move |ready| {
        if ready {
            operate.call(0);
        }
    }));
    let reset = use_callback(move |()| {
        generation += 1;
        preview.set(None);
        confirmation.set(false);
        retry.set(None);
        request_id.set(uuid::Uuid::new_v4());
    });
    rsx! {
        section {id:"relay-maintenance",class:"card",aria_label:console_message(locale,"maintenance-title"),
            h2 {{console_message(locale,"maintenance-title")}}
            p {{console_message(locale,"maintenance-scope")}}
            if !error().is_empty(){p{role:"alert","{error}"}}
            button {disabled:!ready || busy(),onclick:move |_|operate.call(0),{console_message(locale,"maintenance-refresh")}}
            if hosts.read().is_empty(){p{{console_message(locale,"maintenance-empty")}}}
            fieldset {disabled:!ready || busy(),
                label {{console_message(locale,"maintenance-host")}
                    select {aria_label:console_message(locale,"maintenance-host"),value:host(),onchange:move|e|{host.set(e.value());reset.call(());},
                        option{value:"",{console_message(locale,"maintenance-select")}}
                        for row in hosts.read().iter(){option{value:row["id"].as_str().unwrap_or_default(),{row["name"].as_str().unwrap_or_default()}}}
                    }
                }
                label {{console_message(locale,"maintenance-operation")}
                    select {value:operation(),onchange:move|e|{operation.set(e.value());reset.call(());},
                        option{value:"relay_drain",{console_message(locale,"maintenance-drain")}}
                        option{value:"relay_resume",{console_message(locale,"maintenance-resume")}}
                    }
                }
                if operation()=="relay_drain"{
                    label {{console_message(locale,"maintenance-replacement")}
                        select {aria_label:console_message(locale,"maintenance-replacement"),value:replacement(),onchange:move|e|{replacement.set(e.value());reset.call(());},
                            option{value:"",{console_message(locale,"maintenance-select")}}
                            for row in hosts.read().iter().filter(|r|r["id"]!=host()){option{value:row["id"].as_str().unwrap_or_default(),{row["name"].as_str().unwrap_or_default()}}}
                        }
                    }
                    label {{console_message(locale,"maintenance-grace")} input{r#type:"number",min:"15",max:"900",value:grace(),oninput:move|e|{grace.set(e.value());reset.call(());}}}
                }
                button {disabled:host().is_empty() || (operation()=="relay_drain" && replacement().is_empty()) || grace().parse::<u32>().ok().is_none_or(|v|!(15..=900).contains(&v)),onclick:move |_|operate.call(1),{console_message(locale,"maintenance-preview")}}
                if let Some(value)=preview(){
                    p {{console_message(locale,"maintenance-impact")}}
                    if value["will_change_default_host"]==true {p{{console_message(locale,"maintenance-default")}}}
                    if let Some(rows)=value["definition"]["affected"].as_array(){ul{for row in rows{li{{row["name"].as_str().unwrap_or_default()}}}}}
                    if let Some(reasons)=value["blockers"].as_array(){for reason in reasons{p{role:"alert",{maintenance_reason(locale,reason.as_str().unwrap_or_default())}}}}
                    label {input{r#type:"checkbox",checked:confirmation(),onchange:move|e|confirmation.set(e.checked())}{console_message(locale,"maintenance-confirm")}}
                    button {disabled:!confirmation() || value["blockers"]!=json!([]),onclick:move |_|operate.call(2),{console_message(locale,"maintenance-start")}}
                }
            }
            if tasks.read().is_empty(){p{{console_message(locale,"maintenance-no-tasks")}}}
            for task in tasks.read().iter(){
                article {class:"card",aria_label:console_message(locale,"maintenance-task"),
                    h3 {{hosts.read().iter().find(|h|h["id"]==task["host_id"]).and_then(|h|h["name"].as_str()).unwrap_or("Relay").to_owned()} " · " {console_message(locale,if task["operation"]=="relay_drain"{"maintenance-drain"}else{"maintenance-resume"})}}
                    p {role:"status",{console_message(locale,match task["status"].as_str(){Some("succeeded")=>"maintenance-succeeded",Some("failed")=>"maintenance-failed",_=>"maintenance-waiting"})}}
                    if let Some(reason)=task["error_code"].as_str(){p{{maintenance_reason(locale,reason)}}}
                    if task["status"]=="failed"{
                        button {disabled:busy(),onclick:{let id=task["id"].as_str().unwrap_or_default().to_string();let version=task["version"].as_u64().unwrap_or(0);move |_|{retry.set(Some((id.clone(),version)));confirmation.set(false);}}, {console_message(locale,"maintenance-review-retry")}}
                    }
                    details {summary{{console_message(locale,"technical-details")}}pre{{serde_json::to_string_pretty(task).unwrap_or_default()}}}
                }
            }
            if retry().is_some(){
                p{{console_message(locale,"maintenance-impact")}}
                label {input{r#type:"checkbox",checked:confirmation(),onchange:move|e|confirmation.set(e.checked())}{console_message(locale,"maintenance-confirm")}}
                button{disabled:busy() || !confirmation(),onclick:move |_|operate.call(4),{console_message(locale,"maintenance-retry")}}
            }
            if cursor().is_some(){button{disabled:busy(),onclick:move |_|operate.call(3),{console_message(locale,"maintenance-more")}}}
        }
    }
}
fn maintenance_reason(locale: Locale, reason: &str) -> String {
    let key = match reason {
        "host_unavailable" => "maintenance-host-unavailable",
        "host_state_changed" => "maintenance-state-changed",
        "replacement_unavailable" | "replacement_not_ready_for_every_mesh" => {
            "maintenance-replacement-unavailable"
        }
        "mesh_lifecycle_in_progress" => "maintenance-mesh-busy",
        "maintenance_timeout" => "maintenance-timeout",
        "awaiting_host_acknowledgement" | "runtime_lease_still_active" | "awaiting_ready_host" => {
            "maintenance-awaiting-ack"
        }
        _ => return reason.to_owned(),
    };
    console_message(locale, key).into()
}
