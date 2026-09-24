#[component]
#[allow(unused_mut, unused_variables)]
fn ConsoleNetworkCreate(
    snapshot: Signal<ConsoleSnapshot>,
    locale: Locale,
    on_close: EventHandler<()>,
    on_complete: EventHandler<String>,
) -> Element {
    let mut name = use_signal(String::new);
    let mut identifier = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut error = use_signal(String::new);
    let mut reconnecting = use_signal(|| false);
    let mut job = use_signal(|| None::<MeshProvisioningResource>);
    let mut captured = use_signal(|| None::<MeshProvisioningCreateRequest>);
    // Poll only this dialog's durable task. Other networks' jobs cannot switch scope.
    use_future(move || async move {
        #[cfg(target_arch = "wasm32")]
        loop {
            let current = job.peek().clone();
            if let Some(current) = current {
                let api = browser_api_client();
                match api
                    .request::<MeshProvisioningResource>(
                        Method::GET,
                        &format!("/api/v1/mesh-provisioning/{}", current.id),
                        None,
                    )
                    .await
                {
                    Ok(updated) => {
                        reconnecting.set(false);
                        if updated.status == "succeeded" {
                            // Navigation loads the new scope; do not mutate the old page's snapshot.
                            on_complete.call(updated.mesh_id.to_string());
                            break;
                        }
                        job.set(Some(updated));
                    }
                    Err(_) => reconnecting.set(true),
                }
            }
            gloo_timers::future::TimeoutFuture::new(1500).await;
        }
    });
    let submit = use_callback(move |()| {
        #[cfg(target_arch = "wasm32")]
        {
            if busy() || !snapshot.peek().has_capability("trust_manage") {
                return;
            }
            let normalized_identifier = identifier.peek().to_ascii_lowercase();
            if (name.peek().trim().is_empty() || name.peek().trim().len() > 128)
                || !peerward_api::valid_network_identifier(&normalized_identifier)
            {
                return;
            }
            let current = job.peek().clone();
            if current.as_ref().is_some_and(|j| j.status != "failed") {
                return;
            }
            identifier.set(normalized_identifier.clone());
            let body = captured
                .peek()
                .as_ref()
                .filter(|body| {
                    body.name == name.peek().trim()
                        && body.network_identifier.as_deref()
                            == Some(normalized_identifier.as_str())
                })
                .cloned()
                .unwrap_or_else(|| MeshProvisioningCreateRequest {
                    request_id: uuid::Uuid::new_v4(),
                    name: name.peek().trim().into(),
                    network_identifier: Some(normalized_identifier),
                    existing_mesh_id: None,
                });
            captured.set(Some(body.clone()));
            busy.set(true);
            error.set(String::new());
            let api = browser_api_client()
                .with_csrf(snapshot.peek().csrf_token.clone().unwrap_or_default());
            spawn(async move {
                let result = if let Some(current) = current {
                    api.retry_mesh_provisioning(current.id).await
                } else {
                    api.provision_mesh(&body).await
                };
                match result {
                    Ok(value) => {
                        job.set(Some(value));
                    }
                    Err(e) => error.set(console_api_error(locale, e)),
                }
                busy.set(false);
            });
        }
    });
    let started = job.read().is_some();
    let failed = job.read().as_ref().is_some_and(|j| j.status == "failed");
    let normalized_identifier = identifier().to_ascii_lowercase();
    let valid_identifier = peerward_api::valid_network_identifier(&normalized_identifier);
    let identifier_error = !identifier().is_empty() && !valid_identifier;
    let valid_name = !name().trim().is_empty() && name().trim().len() <= 128;
    let dirty = !started && (!name().is_empty() || !identifier().is_empty());
    rsx! {
        div {class:"overlay-backdrop network-create-backdrop",onclick:move |_|{if !busy(){on_close.call(());}},
            section {class:"network-create-modal",role:"dialog",aria_modal:"true",aria_labelledby:"network-create-title",tabindex:"-1","data-console-overlay-root":"true",
                onclick:move |e|e.stop_propagation(),onkeydown:move |e|{if e.key()==Key::Escape && !busy(){on_close.call(());}},
                "data-console-dirty":dirty.to_string(),
                header {class:"network-create-head",
                    div {div {class:"eyebrow",{console_text(locale,"新建网络","New network")}}
                        h2 {id:"network-create-title",{console_text(locale,"创建一个独立网络","Create an independent network")}}
                    }
                    button {class:"icon-button",r#type:"button",aria_label:"Close / 关闭",disabled:busy(),onclick:move |_|on_close.call(()),"×"}
                }
                form {onsubmit:move |e|{e.prevent_default();submit.call(());},
                    div {class:"network-create-body console-form",
                        div {class:"network-create-note",span {aria_hidden:"true","i"}p {{console_text(locale,"新网络不会自动继承当前网络的设备、共享或访问权限。这样可以避免家庭、公司和测试环境互相影响。","The new network does not inherit devices, shares or access permissions. Keep home, work and test environments independent.")}}}
                        label {r#for:"new-network-name",{console_text(locale,"网络名称","Network name")}}
                        input {id:"new-network-name",autofocus:true,required:true,maxlength:"128",disabled:busy()||started,value:name,
                            placeholder:console_text(locale,"例如：办公室网络","For example: Office network"),oninput:move |e|name.set(e.value())}
                        if name().trim().len()>128 {p {role:"alert",{console_text(locale,"网络名称过长，请使用更短的名称。","The network name is too long. Choose a shorter name.")}}}
                        label {r#for:"new-network-identifier",{console_text(locale,"网络标识","Network identifier")}}
                        input {id:"new-network-identifier",required:true,minlength:"1",maxlength:"63",pattern:"[A-Za-z0-9](([A-Za-z0-9]|-)*[A-Za-z0-9])?",
                            autocomplete:"off",autocapitalize:"none",spellcheck:"false",disabled:busy()||started,value:identifier,
                            placeholder:"office-mesh",aria_describedby:if identifier_error{"network-identifier-help network-identifier-error"}else{"network-identifier-help"},aria_invalid:identifier_error.to_string(),
                            oninput:move |e|identifier.set(e.value())}
                        p {id:"network-identifier-help",class:"field-help",{console_text(locale,"使用 1–63 位字母、数字或连字符，大写自动转为小写，首尾不能为连字符；标识不可重复，创建后保持不变。","Use 1–63 letters, digits or hyphens. Uppercase letters are converted to lowercase. No leading or trailing hyphen; the identifier must be unique and cannot change after creation.")}}
                        if identifier_error {p {id:"network-identifier-error",class:"error",role:"alert",{console_text(locale,"网络标识格式不正确：只能使用英文字母、数字和连字符，且首尾不能为连字符。","Invalid identifier: use only English letters, digits and hyphens, with no leading or trailing hyphen.")}}}
                        if valid_identifier && identifier()!=normalized_identifier {p {class:"field-help",role:"status",{console_text(locale,"创建时使用的标识：","Identifier used for creation: ")}"{normalized_identifier}"}}
                        if let Some(value)=job(){
                            div {class:"network-create-progress",role:"status",aria_live:"polite",
                                strong {{console_message(locale,provisioning_stage_key(&value))}}
                                p {{console_text(locale,"创建任务已保存，完成后将自动切换。也可以关闭弹窗，在网络设置中查看进度。","The task is saved. You will switch when it completes, or close this dialog and track progress in network settings.")}}
                                if let Some(code)=value.error_code{p {"{code}"}}
                            }
                        }
                        if reconnecting(){p {role:"status",{console_message(locale,"initialization-reconnecting")}}}
                        if !error().is_empty(){p {role:"alert","{error}"}}
                    }
                    footer {class:"network-create-foot",
                        button {class:"secondary-button",r#type:"button","data-console-dismiss":"true",disabled:busy(),onclick:move |_|on_close.call(()),
                            {if started{console_text(locale,"关闭","Close")}else{console_text(locale,"取消","Cancel")}}}
                        button {r#type:"submit",disabled:busy()||!valid_name||!valid_identifier||(started&&!failed),
                            {if busy(){console_text(locale,"正在提交…","Submitting…")}else if failed{console_text(locale,"重试初始化","Retry initialization")}else if started{console_text(locale,"正在创建…","Creating…")}else{console_text(locale,"创建并切换","Create and switch")}}}
                    }
                }
            }
        }
    }
}
