fn policy_editor_document(policy: &PolicyPutRequest) -> String {
    json!({
        "revision": policy.revision.to_string(),
        "default_action": policy.default_action,
        "rules": serde_json::to_string(&policy.rules).unwrap_or_default()
    })
    .to_string()
}

fn policy_editor_request(document: &str, revision: u64) -> Result<PolicyPutRequest, &'static str> {
    let rules = serde_json::from_str(&editor_value(document, "rules"))
        .map_err(|_| "invalid-policy-draft")?;
    Ok(PolicyPutRequest {
        revision,
        default_action: editor_value(document, "default_action"),
        rules,
    })
}

fn policy_editor_dirty(document: &str, original: &PolicyPutRequest) -> bool {
    policy_editor_request(document, original.revision).as_ref() != Ok(original)
}

fn policy_device_label(peer: &PeerResource) -> String {
    let name = if peer.display_name.is_empty() {
        &peer.name
    } else {
        &peer.display_name
    };
    peer.mesh_addresses
        .first()
        .map_or_else(|| name.clone(), |address| format!("{name} · {address}"))
}

/// Append only the requested device pair; preserve every existing selector and rule.
fn append_device_rules(
    document: &str,
    first: &str,
    second: &str,
    preset: &str,
    mutual: bool,
) -> Result<String, &'static str> {
    let first = first
        .parse::<peerward_types::PeerId>()
        .map_err(|_| "invalid-policy-devices")?;
    let second = second
        .parse::<peerward_types::PeerId>()
        .map_err(|_| "invalid-policy-devices")?;
    if first == second {
        return Err("invalid-policy-devices");
    }
    let (protocol, ports) = match preset {
        "ping" => ("icmp", json!([])),
        "ssh" => ("tcp", json!([{"first":22,"last":22}])),
        "http" => ("tcp", json!([{"first":80,"last":80}])),
        "https" => ("tcp", json!([{"first":443,"last":443}])),
        _ => return Err("invalid-policy-draft"),
    };
    // Do not interpret a malformed JSON draft as an empty policy.
    let mut rules: Vec<Value> = serde_json::from_str(&editor_value(document, "rules"))
        .map_err(|_| "invalid-policy-draft")?;
    let pairs = if mutual {
        vec![(first, second), (second, first)]
    } else {
        vec![(first, second)]
    };
    for (source, destination) in pairs {
        let source = json!({"peer_ids":[source],"labels":{},"cidrs":[]});
        let destination = json!({"peer_ids":[destination],"labels":{},"cidrs":[]});
        if rules.iter().any(|r| {
            r["enabled"] == true
                && r["action"] == "allow"
                && r["source"] == source
                && r["destination"] == destination
                && r["protocol"] == protocol
                && r["destination_ports"] == ports
        }) {
            continue;
        }
        let priority = rules
            .iter()
            .filter_map(|r| r["priority"].as_u64())
            .max()
            .unwrap_or(0)
            .checked_add(10)
            .filter(|v| u32::try_from(*v).is_ok())
            .ok_or("invalid-policy-draft")?;
        rules.push(
            json!({"id":uuid::Uuid::new_v4(),"priority":priority,"action":"allow",
            "enabled":true,"log":false,"source":source,"destination":destination,
            "protocol":protocol,"destination_ports":ports}),
        );
    }
    let mut value: Value = serde_json::from_str(document).map_err(|_| "invalid-policy-draft")?;
    value["rules"] = Value::String(Value::Array(rules).to_string());
    Ok(value.to_string())
}

#[component]
#[allow(unused_mut, unused_variables)]
fn ConsolePolicyEditor(
    mesh: String,
    csrf: Option<String>,
    locale: Locale,
    can_write: bool,
    lookups: Vec<ResourceSummary>,
    extras: Element,
) -> Element {
    let mut data = use_console_query::<PolicyPutRequest>(format!("/api/v1/meshes/{mesh}/policy"));
    let mut original = use_signal(|| None::<PolicyPutRequest>);
    let mut document = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut saving = use_signal(|| false);
    let mut message = use_signal(String::new);
    let mut message_document = use_signal(String::new);
    let mut error = use_signal(String::new);
    let mut conflict = use_signal(|| false);
    let mut first = use_signal(|| None::<PeerResource>);
    let mut second = use_signal(|| None::<PeerResource>);
    let mut preset = use_signal(|| "ping".to_owned());
    let mut mutual = use_signal(|| true);
    let mut reset_requested = use_signal(|| false);
    use_effect(move || {
        let incoming = data.read().as_ref().and_then(|r| r.as_ref().ok()).cloned();
        if *busy.peek() {
            return;
        }
        if let Some(incoming) = incoming {
            let current = original.peek().clone();
            if let Some(current) = current.as_ref() {
                if incoming.revision <= current.revision {
                    return;
                }
                if policy_editor_dirty(&document.peek(), current) {
                    conflict.set(true);
                    return;
                }
            }
            document.set(policy_editor_document(&incoming));
            original.set(Some(incoming));
        }
    });
    let dirty = original
        .read()
        .as_ref()
        .is_some_and(|p| policy_editor_dirty(&document(), p));
    let ready = original.read().is_some();
    let pending_selection = first.read().is_some() || second.read().is_some();
    let valid_selection = first
        .read()
        .as_ref()
        .zip(second.read().as_ref())
        .is_some_and(|(a, b)| a.id != b.id);
    let read_error = data
        .read()
        .as_ref()
        .and_then(|r| r.as_ref().err())
        .cloned()
        .unwrap_or_default();
    let locked = !can_write || !ready || busy();
    let add = use_callback(move |()| {
        let (Some(a), Some(b)) = (first(), second()) else {
            return;
        };
        match append_device_rules(
            &document(),
            &a.id.to_string(),
            &b.id.to_string(),
            &preset(),
            mutual(),
        ) {
            Ok(next) => {
                document.set(next);
                first.set(None);
                second.set(None);
                error.set(String::new());
                message.set(
                    console_text(
                        locale,
                        "已加入待保存规则，请点击下方「保存规则」。",
                        "Added to the draft. Choose Save rules below to apply.",
                    )
                    .into(),
                );
                message_document.set(document());
            }
            Err(key) => error.set(console_message(locale, key).into()),
        }
    });
    let save_mesh = mesh.clone();
    let run = use_callback(move |save: bool| {
        #[cfg(target_arch = "wasm32")]
        {
            if busy() || !can_write || conflict() {
                return;
            }
            let Some(current) = original() else {
                return;
            };
            let Some(revision) = current
                .revision
                .checked_add(1)
                .filter(|r| i64::try_from(*r).is_ok())
            else {
                return;
            };
            let candidate_document = match (first(), second()) {
                (Some(a), Some(b)) => match append_device_rules(
                    &document(),
                    &a.id.to_string(),
                    &b.id.to_string(),
                    &preset(),
                    mutual(),
                ) {
                    Ok(value) => value,
                    Err(key) => {
                        error.set(console_message(locale, key).into());
                        return;
                    }
                },
                (None, None) => document(),
                _ => {
                    error.set(console_message(locale, "invalid-policy-devices").into());
                    return;
                }
            };
            let candidate = match policy_editor_request(&candidate_document, revision) {
                Ok(value) => value,
                Err(key) => {
                    error.set(console_message(locale, key).into());
                    return;
                }
            };
            let api = browser_api_client().with_csrf(csrf.clone().unwrap_or_default());
            let mesh = save_mesh.clone();
            saving.set(save);
            busy.set(true);
            message.set(String::new());
            error.set(String::new());
            spawn(async move {
                let result = async {
                    let validation = api.validate_policy(&mesh, &candidate).await?;
                    if !validation.valid {
                        error.set(format!("{} {}", console_text(locale,"规则未通过校验，尚未保存。请检查：","Validation failed; nothing was saved. Check:"),
                            validation.field_errors.keys().cloned().collect::<Vec<_>>().join(", ")));
                        return Ok(());
                    }
                    if save {
                        let saved = api.replace_policy(&mesh, validation.normalized.as_ref().unwrap_or(&candidate)).await?;
                        document.set(policy_editor_document(&saved));
                        original.set(Some(saved));
                        first.set(None); second.set(None);
                        conflict.set(false);
                        message.set(console_text(locale,"规则已保存。请在设备上测试连接；保存成功不代表设备已经连通。","Rules saved. Test the connection on your devices; saving does not verify connectivity.").into());
                        *CONSOLE_QUERY_EPOCH.write() += 1;
                    } else {
                        document.set(candidate_document);
                        first.set(None); second.set(None);
                        message.set(console_text(locale,"校验通过，尚未保存。点击「保存规则」应用更改。","Validation passed. Choose Save rules to apply your changes.").into());
                    }
                    message_document.set(document());
                    Ok::<(), ConsoleApiError>(())
                }.await;
                if let Err(e) = result {
                    let is_conflict = matches!(&e, ConsoleApiError::Server(body) if body.code == "revision_rollback");
                    if is_conflict {
                        conflict.set(true);
                    }
                    error.set(console_api_error(locale, e));
                }
                busy.set(false);
            });
        }
    });
    rsx! {
        section { class:"policy-workspace", aria_label:console_text(locale,"编辑访问规则","Edit access rules"),
            "data-console-dirty":(dirty || pending_selection).to_string(),
            "data-console-submitting":busy().to_string(),
            div { class:"policy-scroll",
                div { class:"policy-editor-intro",
                    h3 { {console_text(locale,"选择设备，设置通信","Choose devices and connections")} }
                    p { class:"muted", {console_text(locale,"已有规则会自动保留。保存时自动校验并更新版本。","Existing rules are loaded and preserved. Saving validates the changes and updates the version automatically.")} }
                }
                if !read_error.is_empty() {
                    p { role:"alert", class:"error", "{read_error}" }
                    button { disabled:busy(), onclick:move |_| data.restart(), {console_text(locale,"重新加载规则","Retry loading rules")} }
                }
                if !ready && read_error.is_empty() { p { role:"status", {console_message(locale,"loading")} } }
                if ready {
                    if can_write {
                        section { class:"card policy-quick", aria_label:console_text(locale,"添加设备通信","Add device connection"),
                            div { class:"policy-section-heading", h3 { {console_text(locale,"添加设备通信","Add device connection")} } span { class:"status-pill", {console_text(locale,"选择即可配置","Choose to configure")} } }
                            div { class:"policy-device-pair",
                                PolicyDevicePicker { mesh:mesh.clone(), id:"policy-device-first", label:console_text(locale,"发起设备","Source device"), selected:first, disabled:locked, locale }
                                PolicyDevicePicker { mesh:mesh.clone(), id:"policy-device-second", label:console_text(locale,"目标设备","Destination device"), selected:second, disabled:locked, locale }
                            }
                            div { class:"policy-device-pair",
                                label { {console_text(locale,"允许的通信","Connection type")}
                                    select { value:preset, disabled:locked, onchange:move |e| { preset.set(e.value()); mutual.set(e.value()=="ping"); },
                                        option { value:"ping", "Ping (ICMP)" } option { value:"ssh", "SSH · TCP 22" }
                                        option { value:"http", "HTTP · TCP 80" } option { value:"https", "HTTPS · TCP 443" }
                                    }
                                }
                                label { {console_text(locale,"通信方向","Direction")}
                                    select { value:if mutual() {"both"} else {"one"}, disabled:locked, onchange:move |e| mutual.set(e.value()=="both"),
                                        option { value:"both", {console_text(locale,"双向：两台设备互相访问","Both directions")} }
                                        option { value:"one", {console_text(locale,"单向：发起设备访问目标设备","Source to destination")} }
                                    }
                                }
                            }
                            p { class:"muted", {if preset()=="ping" {console_text(locale,"Ping 不需要创建共享或填写端口。双向会添加两条 ICMP 允许规则。","Ping needs no share or port. Both directions adds two ICMP allow rules.")} else {console_text(locale,"允许访问所选服务端口，目标设备上的服务仍需运行。","Allows the selected service port. The service must also be running on the destination.")}} }
                            if first.read().as_ref().zip(second.read().as_ref()).is_some_and(|(a,b)|a.id==b.id) {
                                p { role:"alert", {console_text(locale,"请选择两台不同的设备。","Choose two different devices.")} }
                            }
                            if valid_selection {
                                p { class:"workflow-note", {console_text(locale,"已选好这组通信，点击底部「保存规则」即可生效。需要配置多组设备时，可先加入待保存规则再继续选择。","Ready to save this connection using Save rules below. To configure more pairs, add this one to the draft first.")} }
                            }
                            div { class:"actions", button { disabled:locked || !valid_selection, onclick:move |_| add.call(()), {console_text(locale,"加入待保存规则","Add to draft")} } }
                        }
                    }
                    section { class:"card policy-draft-summary",
                        div { class:"policy-section-heading",
                            h3 { {format!("{} · {}",console_text(locale,"通信规则","Connection rules"),policy_rules(&document()).len())} }
                            span { class:if dirty {"status-pill warning"} else {"status-pill"}, {if dirty {console_text(locale,"有未保存更改","Unsaved changes")} else {console_text(locale,"已与服务器同步","Saved on server")}} }
                        }
                        PolicyRuleSummary { document, locale, disabled:locked, mesh:mesh.clone() }
                        p { class:if editor_value(&document(),"default_action")=="allow" {"risk-preview"} else {"muted"}, {if editor_value(&document(),"default_action")=="allow" {console_text(locale,"未匹配规则的连接：默认允许。","Unmatched connections are allowed by default.")} else {console_text(locale,"未匹配规则的连接：默认拒绝。","Unmatched connections are denied by default.")}} }
                        p { class:"muted", {console_text(locale,"规则按优先级生效。已有更高优先级的拒绝规则仍可能阻止连接。","Rules follow priority order. An existing higher-priority deny rule may still block the connection.")} }
                    }
                    details { class:"card advanced-tools policy-advanced",
                        summary { {console_text(locale,"高级规则编辑","Advanced rule editing")} }
                        p { class:"muted", {console_text(locale,"自定义协议、端口、地址范围和优先级。版本号由保存流程自动管理。","Customize protocols, ports, address ranges and priority. Saving manages the revision automatically.")} }
                        EditorChoice { label:console_message(locale,"default-action"), field:"default_action", document, disabled:locked,
                            choices:vec![("deny",console_text(locale,"未匹配的连接：拒绝（推荐）","Unmatched connections: deny (recommended)")),("allow",console_text(locale,"未匹配的连接：允许","Unmatched connections: allow"))] }
                        if editor_value(&document(),"default_action")=="allow" { p { class:"risk-preview", {console_text(locale,"默认允许会放行所有未匹配规则的连接。","Default allow permits every connection that does not match a rule.")} } }
                        PolicyRuleEditor { document, disabled:locked, locale }
                        p { class:"muted", {format!("{} {}",console_text(locale,"当前已保存版本","Current saved revision"),original.read().as_ref().map_or(0,|p|p.revision))} }
                    }
                    details { class:"card advanced-tools", summary { {console_text(locale,"模拟服务访问","Simulate service access")} }
                        PolicyServiceSimulator { mesh:mesh.clone(), locale, can_write, document, lookups, disabled:busy() }
                    }
                    details { class:"card advanced-tools", summary { {console_text(locale,"资源规则与设备组","Resource rules and device groups")} } {extras} }
                }
            }
            footer { class:"policy-savebar",
                if conflict() { p { role:"alert", class:"error", {console_text(locale,"服务器上的规则已变化，草稿已保留。请重新加载最新规则后再修改。","Rules changed on the server. Your draft is retained. Reload the latest rules before editing again.")} } }
                if !error().is_empty() { p { role:"alert", class:"error", "{error}" } }
                if !message().is_empty() && message_document()==document() && !pending_selection { p { role:"status", "{message}" } }
                if pending_selection && !valid_selection { p { class:"muted", {console_text(locale,"请选择两台不同的设备后保存。","Choose two different devices before saving.")} } }
                if reset_requested() {
                    p { {console_text(locale,"放弃当前草稿并重新加载已保存规则？","Discard this draft and reload saved rules?")} }
                    div { class:"actions",
                        button { onclick:move |_| reset_requested.set(false), {console_text(locale,"继续编辑","Keep editing")} }
                        button { onclick:move |_| { original.set(None); document.set(String::new()); conflict.set(false); error.set(String::new()); message.set(String::new()); first.set(None); second.set(None); reset_requested.set(false); data.restart(); }, {console_text(locale,"放弃并重新加载","Discard and reload")} }
                    }
                } else {
                    div { class:"policy-save-actions",
                        span { class:"muted", {if !ready {console_text(locale,"正在读取规则…","Loading rules…")} else if busy() && saving() {console_text(locale,"正在校验并提交…","Validating and submitting…")} else if busy() {console_text(locale,"正在校验…","Validating…")} else if dirty || pending_selection {console_text(locale,"更改尚未保存","Changes not saved yet")} else {console_text(locale,"所有规则已保存","All rules saved")}} }
                        div { class:"actions",
                            button { disabled:busy() || !ready, onclick:move |_| reset_requested.set(true), {console_text(locale,"重新加载","Reload")} }
                            if can_write {
                                button { disabled:locked || conflict() || !(dirty || valid_selection) || (pending_selection && !valid_selection), onclick:move |_| run.call(false), {console_text(locale,"仅校验","Validate only")} }
                                button { class:"primary-button", disabled:locked || conflict() || !(dirty || valid_selection) || (pending_selection && !valid_selection), onclick:move |_| run.call(true), {if busy() && saving() {console_text(locale,"保存中…","Saving…")} else {console_text(locale,"保存规则","Save rules")}} }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn PolicyDevicePicker(
    mesh: String,
    id: &'static str,
    label: &'static str,
    mut selected: Signal<Option<PeerResource>>,
    disabled: bool,
    locale: Locale,
) -> Element {
    let mut query = use_signal(String::new);
    let mut cursor = use_signal(String::new);
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params.append_pair("limit", "50").append_pair("q", &query());
    if !cursor().is_empty() {
        params.append_pair("cursor", &cursor());
    }
    let mut devices = use_console_query::<peerward_api::ConsoleDevicePage>(format!(
        "/api/v1/meshes/{mesh}/console/devices?{}",
        params.finish()
    ));
    let page = devices
        .read()
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .cloned();
    let options = page
        .as_ref()
        .map(|p| p.items.clone())
        .unwrap_or_default()
        .into_iter()
        .filter(|p| p.administrative_state == peerward_api::AdministrativeState::Enabled)
        .collect::<Vec<_>>();
    let selectable = options.clone();
    let chosen = selected();
    let next = page.as_ref().and_then(|p| p.next_cursor.clone());
    rsx! {
        div { class:"policy-device-picker",
            label { r#for:id, "{label}" }
            select { id, value:chosen.as_ref().map(|p|p.id.to_string()).unwrap_or_default(), disabled,
                onchange:move |e| selected.set(selectable.iter().find(|p|p.id.to_string()==e.value()).cloned()),
                option { value:"", {console_text(locale,"请选择设备","Choose a device")} }
                if let Some(peer)=chosen.as_ref() && !options.iter().any(|p|p.id==peer.id) { option { value:"{peer.id}", {policy_device_label(peer)} } }
                for peer in options { option { value:"{peer.id}", {policy_device_label(&peer)} } }
            }
            if let Some(Err(error))=devices.read().as_ref() {
                p { role:"alert", "{error}" }
                button { disabled, onclick:move |_| devices.restart(), {console_text(locale,"重试","Retry")} }
            }
            if page.as_ref().is_some_and(|p|p.total>50) || !query().is_empty() || !cursor().is_empty() {
                input { aria_label:format!("{} · {}",label,console_text(locale,"搜索设备","Search devices")), placeholder:console_text(locale,"搜索设备名称","Search by device name"), value:query, disabled, oninput:move |e| {query.set(e.value());cursor.set(String::new());} }
                div { class:"actions",
                    if !cursor().is_empty() { button { disabled, onclick:move |_| cursor.set(String::new()), {console_text(locale,"首页","First page")} } }
                    if let Some(next)=next { button { disabled, onclick:move |_| cursor.set(next.clone()), {console_text(locale,"下一页","Next page")} } }
                }
            }
        }
    }
}

#[component]
fn PolicyRuleSummary(
    document: Signal<String>,
    locale: Locale,
    disabled: bool,
    mesh: String,
) -> Element {
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params.append_pair("limit", "100");
    let peers = use_console_query::<peerward_api::ConsoleDevicePage>(format!(
        "/api/v1/meshes/{mesh}/console/devices?{}",
        params.finish()
    ));
    let names = peers
        .read()
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .map(|p| {
            p.items
                .iter()
                .map(|p| (p.id.to_string(), p.display_name.clone()))
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();
    let selector = |s: &Value| {
        let ids = s["peer_ids"].as_array().cloned().unwrap_or_default();
        let mut labels =
            ids.iter()
                .filter_map(Value::as_str)
                .map(|id| {
                    names.get(id).cloned().unwrap_or_else(|| {
                        console_text(locale, "已选设备", "Selected device").into()
                    })
                })
                .collect::<Vec<_>>();
        if let Some(cidrs) = s["cidrs"].as_array() {
            labels.extend(cidrs.iter().filter_map(Value::as_str).map(str::to_owned));
        }
        if s["labels"].as_object().is_some_and(|v| !v.is_empty()) {
            labels.push(console_text(locale, "标签条件", "Label conditions").into());
        }
        if labels.is_empty() {
            console_text(locale, "所有设备", "All devices").to_owned()
        } else {
            labels.join(" · ")
        }
    };
    let rules = policy_rules(&document());
    rsx! {
        if rules.is_empty() { p { class:"empty", {console_text(locale,"还没有通信规则。从上方选择两台设备开始。","No connection rules yet. Choose two devices above to get started.")} } }
        for (index,rule) in rules.iter().enumerate() {
            div { class:"policy-summary-row",
                div {
                    strong { {format!("{} → {}",selector(&rule["source"]),selector(&rule["destination"]))} }
                    small { {format!("{} · {}{}{}",if rule["action"]=="allow" {console_text(locale,"允许","Allow")} else {console_text(locale,"拒绝","Deny")},rule["protocol"].as_str().unwrap_or("any").to_uppercase(),if rule["destination_ports"].as_array().is_some_and(|p|!p.is_empty()) {" · "} else {""},joined_ports(rule.get("destination_ports")))} }
                }
                label { class:"policy-rule-toggle", input { r#type:"checkbox", disabled, checked:rule["enabled"].as_bool().unwrap_or(false), onchange:move |e|set_policy_rule_value(document,index,None,"enabled",json!(e.checked())) } {console_text(locale,"启用","Enabled")} }
            }
        }
    }
}

#[component]
#[allow(unused_mut, unused_variables)]
fn PolicyServiceSimulator(
    mesh: String,
    locale: Locale,
    can_write: bool,
    document: Signal<String>,
    lookups: Vec<ResourceSummary>,
    disabled: bool,
) -> Element {
    let mut source = use_signal(String::new);
    let mut target = use_signal(String::new);
    let mut protocol = use_signal(|| "tcp".to_owned());
    let mut draft = use_signal(|| false);
    let mut busy = use_signal(|| false);
    let mut result = use_signal(String::new);
    let peers = lookups
        .iter()
        .filter(|p| p.details.get("lookup_kind").and_then(Value::as_str) == Some("peer"))
        .cloned()
        .collect::<Vec<_>>();
    let services = lookups
        .iter()
        .filter(|p| p.details.get("lookup_kind").and_then(Value::as_str) == Some("service"))
        .cloned()
        .collect::<Vec<_>>();
    let simulate = use_callback(move |()| {
        #[cfg(target_arch = "wasm32")]
        {
            if busy() || disabled {
                return;
            }
            let policy = if draft() && can_write {
                match policy_editor_request(&document(), 1) {
                    Ok(value) => Some(value),
                    Err(key) => {
                        result.set(console_message(locale, key).into());
                        return;
                    }
                }
            } else {
                None
            };
            let body = json!({"source_peer_id":source(),"target_service_id":target(),"protocol":protocol(),"draft_policy":policy});
            let mesh = mesh.clone();
            busy.set(true);
            spawn(async move {
                match browser_api_client().request::<PolicySimulationResponse>(Method::POST,&format!("/api/v1/meshes/{mesh}/policy/simulate"),Some(body)).await {
                    Ok(value) => result.set(if value.allowed {console_text(locale,"策略允许；仍需在设备上验证连通性。","Policy allows this connection; verify connectivity on the devices.")} else {console_text(locale,"策略拒绝此连接。","Policy denies this connection.")}.into()),
                    Err(e) => result.set(console_api_error(locale,e)),
                }
                busy.set(false);
            });
        }
    });
    rsx! {
        div { class:"policy-service-simulator",
            p { class:"muted", {console_text(locale,"仅检查规则判断，不保存规则，也不建立真实网络连接。","Checks policy decisions only. Does not save rules or make network connections.")} }
            label { {console_message(locale,"source-peer")}
                select { value:source, disabled:disabled||busy(), onchange:move |e|source.set(e.value()),
                    option { value:"", {console_text(locale,"请选择设备","Choose a device")} }
                    for peer in peers { option { value:"{peer.id}", "{peer.name}" } }
                }
            }
            label { {console_message(locale,"target-service")}
                select { value:target, disabled:disabled||busy(), onchange:move |e|target.set(e.value()),
                    option { value:"", {console_text(locale,"请选择服务","Choose a service")} }
                    for service in services { option { value:"{service.id}", "{service.name}" } }
                }
            }
            label { {console_message(locale,"protocol")}
                select { value:protocol, disabled:disabled||busy(), onchange:move |e|protocol.set(e.value()), option { value:"tcp", "TCP" } option { value:"udp", "UDP" } }
            }
            if can_write {
                label { {console_message(locale,"simulation-policy")}
                    select { value:if draft() {"draft"} else {"saved"}, disabled:disabled||busy(), onchange:move |e|draft.set(e.value()=="draft"),
                        option { value:"saved", {console_message(locale,"current-policy")} } option { value:"draft", {console_message(locale,"draft-policy")} }
                    }
                }
            }
            button { disabled:disabled||busy()||source().is_empty()||target().is_empty(), onclick:move |_|simulate.call(()), {console_message(locale,"simulate-policy")} }
            if !result().is_empty() { p { role:"status", "{result}" } }
        }
    }
}
