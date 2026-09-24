#[component]
#[allow(unused_mut, unused_variables)]
fn CapacityPanel(locale: Locale, #[props(default)] ready: bool) -> Element {
    let mut hosts = use_signal(Vec::<Value>::new);
    let mut selected = use_signal(String::new);
    let mut sample = use_signal(|| None::<Value>);
    let mut error = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut generation = use_signal(|| 0u64);
    let mut last_success = use_signal(|| 0f64);
    let mut tick = use_signal(|| 0f64);
    let refresh = use_callback(move |()| {
        #[cfg(target_arch = "wasm32")]
        {
            if !ready || *busy.peek() {
                return;
            }
            busy.set(true);
            let epoch = *generation.peek();
            let chosen = selected.peek().clone();
            spawn(async move {
                let api = browser_api_client();
                let result: Result<Value, ConsoleApiError> = async {
                    let list: Value = api
                        .request(Method::GET, "/api/v1/relay-hosts", None)
                        .await?;
                    if *generation.peek() != epoch {
                        return Ok(Value::Null);
                    }
                    let rows = list["items"].as_array().cloned().unwrap_or_default();
                    let id = if chosen.is_empty() {
                        rows.first()
                            .and_then(|r| r["id"].as_str())
                            .unwrap_or_default()
                            .to_owned()
                    } else {
                        chosen
                    };
                    hosts.set(rows);
                    if id.is_empty() {
                        return Ok(Value::Null);
                    }
                    selected.set(id.clone());
                    api.request(
                        Method::GET,
                        &format!("/api/v1/relay-hosts/{id}/capacity"),
                        None,
                    )
                    .await
                }
                .await;
                if *generation.peek() != epoch {
                    return;
                }
                match result {
                    Ok(value) => {
                        sample.set((!value.is_null()).then_some(value));
                        error.set(String::new());
                        last_success.set(js_sys::Date::now());
                    }
                    Err(e) => error.set(e.to_string()),
                }
                busy.set(false);
            });
        }
    });
    use_effect(use_reactive(&ready, move |ready| {
        if ready {
            refresh.call(());
        }
    }));
    use_future(move || async move {
        #[cfg(target_arch = "wasm32")]
        loop {
            gloo_timers::future::TimeoutFuture::new(5000).await;
            tick.set(js_sys::Date::now());
            refresh.call(());
        }
    });
    let current = sample();
    let fresh = error().is_empty()
        && current.as_ref().is_some_and(|v| v["fresh"] == true)
        && tick() - last_success() < 30_000.;
    rsx! {
        section{id:"relay-capacity",class:"card",aria_label:console_message(locale,"capacity-title"),
            h2{{console_message(locale,"capacity-title")}}
            p{{console_message(locale,"capacity-boundary")}}
            label{{console_message(locale,"maintenance-host")}
                select{aria_label:console_message(locale,"capacity-select"),disabled:busy() || !ready,value:selected(),onchange:move|event|{
                    generation+=1;selected.set(event.value());sample.set(None);error.set(String::new());refresh.call(());
                },
                    option{value:"",{console_message(locale,"maintenance-select")}}
                    for host in hosts.read().iter(){option{value:host["id"].as_str().unwrap_or_default(),{host["name"].as_str().unwrap_or_default()}}}
                }
            }
            button{disabled:busy() || !ready,onclick:move|_|refresh.call(()),{console_message(locale,"capacity-refresh")}}
            p{role:"status",{console_message(locale,if fresh{"capacity-fresh"}else{"capacity-unknown"})}}
            if !error().is_empty(){p{role:"alert","{error}"}}
            if let Some(value)=current {
                if let Some(observed)=value["observed_at"].as_u64(){p{{console_message(locale,"capacity-observed")} " " {join_deadline(observed)}}}
                if !value["report"].is_null(){
                    dl{
                        for (key,label) in [("authenticated_peer_sessions","capacity-sessions"),("received_bytes","capacity-read"),("accepted_bytes","capacity-write"),
                            ("router_queued_messages","capacity-queue"),("router_queued_encoded_bytes","capacity-queue-bytes"),("backbone_pending_slots","capacity-backbone"),("audit_pending_slots","capacity-audit")]{
                            dt{{console_message(locale,label)}}dd{{value["report"][key].to_string()}}
                        }
                    }
                    if fresh && value["last_interval"]["queue_full"].as_u64().unwrap_or(0)>0{p{role:"alert",{console_message(locale,"capacity-backpressure")}}}
                    if fresh && value["last_interval"]["audit_dropped"].as_u64().unwrap_or(0)>0{p{role:"alert",{console_message(locale,"capacity-audit-dropped")}}}
                    if fresh && value["last_interval"]["invalid_frames"].as_u64().unwrap_or(0)>0{p{role:"alert",{console_message(locale,"capacity-invalid")}}}
                    details{summary{{console_message(locale,"technical-details")}}pre{{serde_json::to_string_pretty(&value).unwrap_or_default()}}}
                }
            }
        }
    }
}
