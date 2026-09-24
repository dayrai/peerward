#[derive(Clone, PartialEq)]
struct MachineDraft {
    id: uuid::Uuid,
    name: String,
    write: bool,
    ttl: u32,
}
impl Default for MachineDraft {
    fn default() -> Self {
        Self {
            id: uuid::Uuid::new_v4(),
            name: String::new(),
            write: false,
            ttl: 2_592_000,
        }
    }
}
#[derive(Clone, Copy)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))] // Operation payloads are used by the browser adapter.
enum MachineOperation {
    Load(bool),
    Create,
    Revoke(uuid::Uuid, u64),
}

#[component]
#[allow(unused_mut, unused_variables)]
fn MachineCredentialsPanel(
    mesh: String,
    csrf: Option<String>,
    locale: Locale,
    #[props(default)] ready: bool,
) -> Element {
    let mut active_mesh = use_signal(|| mesh.clone());
    let mut mesh_generation = use_signal(|| 0_u64);
    let mut draft = use_signal(MachineDraft::default);
    let mut drafts = use_signal(BTreeMap::<String, MachineDraft>::new);
    let mut records = use_signal(Vec::<peerward_api::MachineCredentialResource>::new);
    let mut cursor = use_signal(|| None::<String>);
    let mut secret = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut confirm = use_signal(|| None::<uuid::Uuid>);
    let operate = use_callback(move |operation: MachineOperation| {
        #[cfg(target_arch = "wasm32")]
        {
            if *busy.peek() || active_mesh.peek().is_empty() {
                return;
            }
            let captured = active_mesh.peek().clone();
            let generation = *mesh_generation.peek();
            let data = draft.peek().clone();
            let next = cursor.peek().clone();
            let mut api = browser_api_client();
            if let Some(csrf) = &csrf {
                api = api.with_csrf(csrf.clone());
            }
            busy.set(true);
            error.set(String::new());
            spawn(async move {
                let path = format!("/api/v1/meshes/{captured}/machine-credentials");
                let result:Result<Value,ConsoleApiError>=match operation {
                    MachineOperation::Load(_)=>Ok(Value::Null),
                    MachineOperation::Create=>api.request(Method::POST,&path,Some(json!({"id":data.id,"name":data.name,
                        "capabilities":if data.write {vec!["resource_read","resource_write"]} else {vec!["resource_read"]},"ttl_seconds":data.ttl}))).await,
                    MachineOperation::Revoke(id,version)=>api.conditional_request(Method::DELETE,&format!("{path}/{id}"),None,version).await,
                };
                if *active_mesh.peek() != captured || *mesh_generation.peek() != generation {
                    return;
                }
                match result {
                    Ok(value) => {
                        if matches!(operation, MachineOperation::Create) {
                            secret.set(
                                value
                                    .get("token")
                                    .and_then(Value::as_str)
                                    .unwrap_or_default()
                                    .into(),
                            );
                            draft.set(MachineDraft::default());
                        }
                        if let MachineOperation::Revoke(id, _) = operation
                            && data.id == id
                        {
                            draft.write().id = uuid::Uuid::new_v4();
                        }
                        confirm.set(None);
                        let more = matches!(operation, MachineOperation::Load(true));
                        let mut query = format!("{path}?limit=50");
                        if more && let Some(cursor) = next {
                            query.push_str("&cursor=");
                            query.push_str(&cursor);
                        }
                        let page = api
                            .request::<Page<peerward_api::MachineCredentialResource>>(
                                Method::GET,
                                &query,
                                None,
                            )
                            .await;
                        if *active_mesh.peek() != captured || *mesh_generation.peek() != generation
                        {
                            return;
                        }
                        match page {
                            Ok(page) => {
                                if more {
                                    records.write().extend(page.items);
                                } else {
                                    records.set(page.items);
                                }
                                cursor.set(page.next_cursor);
                            }
                            Err(failure) => {
                                let failure = api_error_body(failure);
                                error.set(format!("{}: {}", failure.code, failure.message));
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
                if *active_mesh.peek() == captured && *mesh_generation.peek() == generation {
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
                .insert(active_mesh.peek().clone(), draft.peek().clone());
            draft.set(drafts.peek().get(&mesh).cloned().unwrap_or_default());
            active_mesh.set(mesh);
            records.set(vec![]);
            cursor.set(None);
            secret.set(String::new());
            busy.set(false);
            confirm.set(None);
        }
        operate.call(MachineOperation::Load(false));
    }));
    let unavailable = busy() || !ready || active_mesh().is_empty();
    rsx! {
        section { class:"card", aria_label:console_message(locale,"machine-credentials"),
            h2 {{console_message(locale,"machine-credentials")}}
            p {{console_message(locale,"machine-help")}}
            if !error().is_empty() { p {role:"alert","{error}"} }
            div { class:"form-grid",
                label { r#for:"machine-name", {console_message(locale,"name")} }
                input {id:"machine-name",value:"{draft().name}",maxlength:64,disabled:unavailable,oninput:move |event|draft.write().name=event.value()}
                label {r#for:"machine-scope",{console_message(locale,"machine-scope")}}
                select {id:"machine-scope",disabled:unavailable,value:if draft().write {"write"} else {"read"},
                    onchange:move |event|draft.write().write=event.value()=="write",
                    option {value:"read",{console_message(locale,"machine-read")}}
                    option {value:"write",{console_message(locale,"machine-write")}}
                }
                label {r#for:"machine-ttl",{console_message(locale,"machine-expiry")}}
                select {id:"machine-ttl",disabled:unavailable,value:"{draft().ttl}",onchange:move |event|if let Ok(ttl)=event.value().parse() {draft.write().ttl=ttl;},
                    for days in [1u32,7,30,90] { option {value:"{days*86400}","{days}"} }
                }
            }
            button {disabled:unavailable||draft().name.is_empty(),onclick:move |_|operate.call(MachineOperation::Create),{console_message(locale,"machine-create")}}
            button {class:"secondary",disabled:unavailable,onclick:move |_|operate.call(MachineOperation::Load(false)),{console_message(locale,"network-refresh")}}
            if !secret().is_empty() {
                p {role:"status",{console_message(locale,"machine-secret-once")}}
                label {r#for:"machine-secret",{console_message(locale,"machine-secret")}}
                input {id:"machine-secret",r#type:"password",readonly:true,autocomplete:"off",value:"{secret}"}
                button {class:"secondary",onclick:move |_|secret.set(String::new()),{console_message(locale,"machine-secret-dismiss")}}
            }
            if records().is_empty() && !busy() { p {{console_message(locale,"machine-empty")}} }
            for record in records() {
                article {key:"{record.id}",
                    h3 {"{record.name}"}
                    p {{record.capabilities.join(" · ")}}
                    p {{format!("{}: {}",console_message(locale,"machine-expires-at"),record.expires_at)}}
                    if record.revoked_at.is_some() {p {{console_message(locale,"machine-revoked")}}}
                    else if confirm()==Some(record.id) {
                        p {{console_message(locale,"machine-revoke-impact")}}
                        button {class:"danger",disabled:unavailable,onclick:move |_|operate.call(MachineOperation::Revoke(record.id,record.version)),{console_message(locale,"machine-revoke")}}
                        button {class:"secondary",onclick:move |_|confirm.set(None),{console_message(locale,"machine-cancel")}}
                    } else {
                        button {class:"danger",disabled:unavailable,onclick:move |_|confirm.set(Some(record.id)),{console_message(locale,"machine-revoke")}}
                    }
                }
            }
            if cursor().is_some() {button {disabled:unavailable,onclick:move |_|operate.call(MachineOperation::Load(true)),{console_message(locale,"next-page")}}}
        }
    }
}
