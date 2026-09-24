#[component]
#[allow(unused_mut, unused_variables)]
fn DeploymentPanel(csrf: Option<String>, locale: Locale, #[props(default)] ready: bool) -> Element {
    let mut runners = use_signal(Vec::<Value>::new);
    let mut tasks = use_signal(Vec::<Value>::new);
    let mut selected = use_signal(String::new);
    let mut name = use_signal(String::new);
    let mut profile = use_signal(String::new);
    let mut secret = use_signal(|| None::<Value>);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut confirmed = use_signal(|| false);
    let mut request_id = use_signal(uuid::Uuid::new_v4);
    let mut pending = use_signal(|| None::<(String, String, u64)>);
    let mut cursor = use_signal(|| None::<String>);
    let operate = use_callback(move |action: u8| {
        #[cfg(target_arch = "wasm32")]
        {
            if !ready || *busy.peek() {
                return;
            }
            let chosen = runners
                .peek()
                .iter()
                .find(|r| r["id"] == selected.peek().as_str())
                .cloned();
            if action == 2
                && (!*confirmed.peek() || chosen.as_ref().is_none_or(|r| r["preview"].is_null()))
            {
                return;
            }
            if action == 3 && (!*confirmed.peek() || pending.peek().is_none()) {
                return;
            }
            let registration = json!({"id":*request_id.peek(),"name":name.peek().clone(),"profile_digest":profile.peek().clone(),"ttl_seconds":2_592_000});
            let mut task = json!({"id":*request_id.peek(),"runner_id":selected.peek().clone(),"preview_digest":chosen.as_ref().map(|r|r["preview"]["digest"].clone())});
            if chosen
                .as_ref()
                .is_some_and(|r| !r["preview"]["upgrade"].is_null())
            {
                task["operation"] = json!("native_upgrade");
            }
            let revision = pending.peek().clone();
            let after = cursor.peek().clone();
            let mut api = browser_api_client();
            if let Some(csrf) = &csrf {
                api = api.with_csrf(csrf.clone());
            }
            busy.set(true);
            error.set(String::new());
            spawn(async move {
                let result: Result<Value, ConsoleApiError> = match action {
                    1 => {
                        api.request(
                            Method::POST,
                            "/api/v1/deployment-runners",
                            Some(registration),
                        )
                        .await
                    }
                    2 => {
                        api.request(Method::POST, "/api/v1/deployment-tasks", Some(task))
                            .await
                    }
                    3 => {
                        let (kind, id, version) = revision.unwrap_or_default();
                        if kind == "recover" {
                            api.conditional_request(
                                Method::POST,
                                &format!("/api/v1/deployment-tasks/{id}/recover"),
                                Some(json!({"request_id":registration["id"]})),
                                version,
                            )
                            .await
                        } else if kind == "runner" {
                            api.conditional_request(
                                Method::DELETE,
                                &format!("/api/v1/deployment-runners/{id}"),
                                None,
                                version,
                            )
                            .await
                        } else {
                            api.conditional_request(
                                Method::POST,
                                &format!("/api/v1/deployment-tasks/{id}/cancel"),
                                None,
                                version,
                            )
                            .await
                        }
                    }
                    _ => Ok(Value::Null),
                };
                match result {
                    Ok(value) => {
                        if action == 1 {
                            secret.set(Some(value));
                            name.set(String::new());
                            profile.set(String::new());
                        }
                        if action != 4 {
                            confirmed.set(false);
                            pending.set(None);
                            request_id.set(uuid::Uuid::new_v4());
                        }
                        let loaded: Result<Value, ConsoleApiError> = api
                            .request(Method::GET, "/api/v1/deployment-runners?limit=100", None)
                            .await;
                        if let Ok(value) = loaded {
                            runners.set(value["items"].as_array().cloned().unwrap_or_default());
                        }
                        let path = if action == 4 {
                            after.map_or_else(
                                || "/api/v1/deployment-tasks".into(),
                                |c| format!("/api/v1/deployment-tasks?cursor={c}"),
                            )
                        } else {
                            "/api/v1/deployment-tasks".into()
                        };
                        match api.request::<Value>(Method::GET, &path, None).await {
                            Ok(value) => {
                                let rows = value["items"].as_array().cloned().unwrap_or_default();
                                if action == 4 {
                                    tasks.write().extend(rows);
                                } else {
                                    tasks.set(rows);
                                }
                                cursor.set(value["next_cursor"].as_str().map(str::to_owned));
                            }
                            Err(problem) => error.set(problem.to_string()),
                        }
                    }
                    Err(problem) => {
                        error.set(problem.to_string());
                        confirmed.set(false);
                    }
                }
                busy.set(false);
            });
        }
    });
    let current = runners
        .read()
        .iter()
        .find(|r| r["id"] == selected())
        .cloned();
    rsx! {
        section {id:"installation-backups",class:"card",aria_label:console_message(locale,"deployment-title"),
            h2 {{console_message(locale,"deployment-title")}}
            p {{console_message(locale,"deployment-scope")}}
            if !error().is_empty(){p{role:"alert","{error}"}}
            button {disabled:!ready || busy(),onclick:move |_|operate.call(0),{console_message(locale,"deployment-refresh")}}
            details {summary{{console_message(locale,"deployment-register")}}
                fieldset {disabled:!ready || busy(),
                    label {{console_message(locale,"deployment-name")}
                        input{value:name(),maxlength:128,oninput:move|e|{name.set(e.value());request_id.set(uuid::Uuid::new_v4());}}}
                    label {{console_message(locale,"deployment-profile")}
                        input{value:profile(),maxlength:64,oninput:move|e|{profile.set(e.value());request_id.set(uuid::Uuid::new_v4());}}}
                    p {{console_message(locale,"deployment-register-help")}}
                    button {disabled:name().trim().is_empty() || profile().len()!=64,onclick:move |_|operate.call(1),{console_message(locale,"deployment-register")}}
                }
            }
            if let Some(value)=secret(){
                p{role:"status",{console_message(locale,"deployment-secret-help")}}
                textarea{readonly:true,aria_label:console_message(locale,"deployment-secret"),value:serde_json::to_string_pretty(&json!({"runner_id":value["runner"]["id"],"profile_digest":value["runner"]["profile_digest"],"token":value["token"]})).unwrap_or_default()}
                button{onclick:move |_|secret.set(None),{console_message(locale,"deployment-dismiss-secret")}}
            }
            fieldset {disabled:!ready || busy(),
                label {{console_message(locale,"deployment-select")}
                    select {aria_label:console_message(locale,"deployment-select"),value:selected(),onchange:move|e|{selected.set(e.value());confirmed.set(false);pending.set(None);request_id.set(uuid::Uuid::new_v4());},
                        option{value:"",{console_message(locale,"maintenance-select")}}
                        for row in runners.read().iter(){option{value:row["id"].as_str().unwrap_or_default(),{row["name"].as_str().unwrap_or_default()}}}
                    }
                }
                if let Some(value)=current {
                    if value["revoked_at"].is_null(){
                        button{onclick:{let id=value["id"].as_str().unwrap_or_default().to_string();let version=value["version"].as_u64().unwrap_or(0);move |_|{pending.set(Some(("runner".into(),id.clone(),version)));confirmed.set(false);request_id.set(uuid::Uuid::new_v4());}}, {console_message(locale,"deployment-revoke")}}
                    }
                    if value["preview"].is_null() || value["ready"]!=true {p{{console_message(locale,"deployment-no-preview")}}}
                    else if pending().is_none(){
                        if !value["preview"]["upgrade"].is_null() {
                            p{{console_message(locale,"deployment-upgrade-impact")}}
                            p{ {value["preview"]["upgrade"]["role"].as_str().unwrap_or_default()}" · "
                                {value["preview"]["upgrade"]["current_version"].as_str().unwrap_or_default()}" → "
                                {value["preview"]["upgrade"]["version"].as_str().unwrap_or_default()} }
                            if value["preview"]["upgrade"]["repair"]==true {p{{console_message(locale,"deployment-upgrade-repair")}}}
                        } else {p{{console_message(locale,"deployment-impact")}}}
                        ul{for service in value["preview"]["services_to_pause"].as_array().into_iter().flatten(){li{{service.as_str().unwrap_or_default()}}}}
                        p{{console_message(locale,"deployment-observation")}" "{value["preview_at"].as_str().unwrap_or_default()}}
                        label{input{r#type:"checkbox",checked:confirmed(),onchange:move|e|confirmed.set(e.checked())}{console_message(locale,"deployment-confirm")}}
                        button{disabled:!confirmed(),onclick:move |_|operate.call(2),{console_message(locale,if value["preview"]["upgrade"].is_null(){"deployment-start"}else{"deployment-upgrade-start"})}}
                    }
                }
                if let Some((kind,_,_))=pending(){
                    p{{runners.read().iter().find(|r|r["id"]==selected()).and_then(|r|r["name"].as_str()).unwrap_or("Linux").to_owned()}}
                    p{{console_message(locale,if kind=="runner"{"deployment-revoke-impact"}else if kind=="recover"{"deployment-recover-impact"}else{"deployment-cancel-impact"})}}
                    label{input{r#type:"checkbox",checked:confirmed(),onchange:move|e|confirmed.set(e.checked())}{console_message(locale,"deployment-confirm")}}
                    button{disabled:!confirmed(),onclick:move |_|operate.call(3),{console_message(locale,"deployment-confirm-action")}}
                    button{onclick:move |_|{pending.set(None);confirmed.set(false);},{console_message(locale,"deployment-back")}}
                }
            }
            if tasks.read().is_empty(){p{{console_message(locale,"maintenance-no-tasks")}}}
            for task in tasks.read().iter(){
                article{class:"card",aria_label:console_message(locale,"deployment-task"),
                    h3{{runners.read().iter().find(|r|r["id"]==task["runner_id"]).and_then(|r|r["name"].as_str()).unwrap_or("Linux").to_owned()}}
                    p{{console_message(locale,if task["operation"]=="native_upgrade"{"deployment-upgrade-task"}else{"deployment-backup-task"})}}
                    p{role:"status",{console_message(locale,match task["status"].as_str(){Some("succeeded")=>if task["operation"]=="native_upgrade"{"deployment-upgrade-succeeded"}else{"deployment-succeeded"},Some("failed")=>if task["stage"]=="superseded"{"deployment-superseded"}else{"maintenance-failed"},Some("recovery_required")=>"deployment-recovery",Some("cancelled")=>"deployment-cancelled",_=>"deployment-waiting"})}}
                    p{{console_message(locale,"deployment-observation")}" "{task["reported_at"].as_str().unwrap_or_else(||console_message(locale,"deployment-unknown"))}}
                    if task["status"]=="queued"{
                        button{disabled:!ready || busy(),onclick:{let id=task["id"].as_str().unwrap_or_default().to_string();let runner=task["runner_id"].as_str().unwrap_or_default().to_string();let version=task["version"].as_u64().unwrap_or(0);move |_|{selected.set(runner.clone());pending.set(Some(("task".into(),id.clone(),version)));confirmed.set(false);request_id.set(uuid::Uuid::new_v4());}}, {console_message(locale,"deployment-cancel")}}
                    }
                    if task["operation"]=="native_upgrade" && task["status"]=="recovery_required" {
                        button{disabled:!ready || busy() || !runners.read().iter().any(|r|r["id"]==task["runner_id"] && r["connected"]==true),
                            onclick:{let id=task["id"].as_str().unwrap_or_default().to_string();let runner=task["runner_id"].as_str().unwrap_or_default().to_string();let version=task["version"].as_u64().unwrap_or(0);move |_|{selected.set(runner.clone());pending.set(Some(("recover".into(),id.clone(),version)));confirmed.set(false);request_id.set(uuid::Uuid::new_v4());}},
                            {console_message(locale,"deployment-recover")}}
                    }
                    details{summary{{console_message(locale,"technical-details")}}pre{{serde_json::to_string_pretty(task).unwrap_or_default()}}}
                }
            }
            if cursor().is_some(){button{disabled:busy(),onclick:move |_|operate.call(4),{console_message(locale,"deployment-more")}}}
        }
    }
}
