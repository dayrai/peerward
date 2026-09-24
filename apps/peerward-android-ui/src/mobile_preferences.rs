#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[allow(clippy::struct_excessive_bools)] // Mirrors independent local switches shared with both execution platforms.
struct MobilePreferences {
    accept_private_routes: bool,
    accept_dns: bool,
    allow_inbound: bool,
    exit_resource: Option<String>,
    allow_local_lan: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MobileExitChoice {
    resource_id: String,
    name: String,
    ipv4: bool,
    ipv6: bool,
    providers: usize,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MobilePreferenceView {
    version: u64,
    preferences: MobilePreferences,
    application: String,
    reason: Option<String>,
    exits: Vec<MobileExitChoice>,
    local_lan: Vec<String>,
    #[serde(default)]
    gateway_paths: Vec<MobileGatewayPath>,
}
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct MobileGatewayPath {
    binding_id: String,
    peer_id: String,
    health: String,
}

#[cfg(feature = "web")]
fn preference_request_id() -> Option<String> {
    use wasm_bindgen::JsCast;
    let window = web_sys::window()?;
    let crypto = js_sys::Reflect::get(window.as_ref(), &"crypto".into()).ok()?;
    let random = js_sys::Reflect::get(&crypto, &"getRandomValues".into())
        .ok()?
        .dyn_into::<js_sys::Function>()
        .ok()?;
    let bytes = js_sys::Uint8Array::new_with_length(16);
    random.call1(&crypto, bytes.as_ref()).ok()?;
    let mut bytes = bytes.to_vec();
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    let mut id = String::with_capacity(36);
    for (index, byte) in bytes.into_iter().enumerate() {
        use std::fmt::Write as _;
        if matches!(index, 4 | 6 | 8 | 10) {
            id.push('-');
        }
        write!(id, "{byte:02x}").ok()?;
    }
    Some(id)
}
#[cfg(not(feature = "web"))]
fn preference_request_id() -> Option<String> {
    None
}

#[component]
fn ClientPreferenceSettings() -> Element {
    let locale = consume_context::<Signal<Locale>>();
    let snapshot = consume_context::<Signal<MobileRuntimeSnapshot>>();
    let chinese = locale() == Locale::ZhCn;
    let mut draft = use_signal(|| None::<MobilePreferenceView>);
    let mut submitted = use_signal(|| None::<(String, u64)>);
    let mut error = use_signal(|| None::<String>);
    // Preserve edits during observations and conflicts; switching Peer resets their ownership.
    let mut owner = use_signal(|| None::<String>);
    use_effect(move || {
        let current = snapshot();
        let peer = current
            .profile
            .as_ref()
            .map(|profile| profile.peer_id.clone());
        if owner() != peer {
            owner.set(peer);
            draft.set(None);
            submitted.set(None);
        }
        if draft().is_none() {
            draft.set(current.client_preferences.clone());
        }
        if let Some((_, version)) = submitted()
            && current
                .client_preferences
                .as_ref()
                .is_some_and(|view| view.version > version)
        {
            submitted.set(None);
            draft.set(current.client_preferences);
        }
    });
    let current = snapshot().client_preferences;
    let title = if chinese {
        "连接偏好与互联网出口"
    } else {
        "Connection preferences and Internet exit"
    };
    let refresh = if chinese {
        "重新读取（放弃草稿）"
    } else {
        "Reload (discard draft)"
    };
    let save = if chinese {
        "保存并应用"
    } else {
        "Save and apply"
    };
    rsx! {
        article { class: "mobile-card",
            h2 { "{title}" }
            if let Some(current) = &current {
                p { role: "status", "{current.application} · v{current.version}" }
                if let Some(reason) = &current.reason { p { role: "alert", "{reason}" } }
                if !current.local_lan.is_empty() { p { {format!("LAN: {}", current.local_lan.join(", "))} } }
                if !current.gateway_paths.is_empty() {
                    details {
                        summary { if chinese { "网关路径详情" } else { "Gateway path details" } }
                        p { if chinese { "这是本设备到网关的路径观测，目标应用仍需单独验证。" } else { "These observations cover paths from this device to its gateways. Verify target applications separately." } }
                        for path in &current.gateway_paths {
                            p { "{path.health} · {path.peer_id} · {path.binding_id}" }
                        }
                    }
                }
            } else {
                p { if chinese { "连接设备后读取获准出口。离线期间的应用状态未知。" } else { "Connect to load approved exits. Application status is unknown while offline." } }
            }
            if let Some(view) = draft() {
                label { input { r#type: "checkbox", checked: view.preferences.accept_private_routes,
                    onchange: move |event| { if let Some(view) = draft.write().as_mut() { view.preferences.accept_private_routes = event.checked(); } } }
                    if chinese { "接受获准的私网路由" } else { "Accept approved private routes" }
                }
                label { input { r#type: "checkbox", checked: view.preferences.accept_dns, disabled: view.preferences.exit_resource.is_some(),
                    onchange: move |event| { if let Some(view) = draft.write().as_mut() { view.preferences.accept_dns = event.checked(); } } }
                    if chinese { "使用网络 DNS（出口模式必须启用）" } else { "Use network DNS (required for an exit)" }
                }
                label { input { r#type: "checkbox", checked: view.preferences.allow_inbound,
                    onchange: move |event| { if let Some(view) = draft.write().as_mut() { view.preferences.allow_inbound = event.checked(); } } }
                    if chinese { "接受规则允许的入站连接" } else { "Accept policy-authorized inbound connections" }
                }
                label {
                    if chinese { "互联网出口" } else { "Internet exit" }
                    select { value: view.preferences.exit_resource.clone().unwrap_or_default(),
                        onchange: move |event| { if let Some(view) = draft.write().as_mut() {
                            view.preferences.exit_resource = (!event.value().is_empty()).then(||event.value());
                            view.preferences.allow_local_lan = false;
                            if view.preferences.exit_resource.is_some() { view.preferences.accept_dns = true; }
                        } },
                        option { value: "", if chinese { "不使用出口" } else { "No exit" } }
                        for choice in current.as_ref().map(|view|view.exits.clone()).unwrap_or_default() {
                            option { value: "{choice.resource_id}", disabled: choice.providers == 0,
                                "{choice.name} · IPv4={choice.ipv4} IPv6={choice.ipv6}"
                            }
                        }
                    }
                }
                if view.preferences.exit_resource.is_some() {
                    p { if chinese { "未覆盖的地址族将阻断。DNS 依照网络配置经获准路径解析；请在应用后验证实际访问。" } else { "Uncovered address families are blocked. DNS follows approved network paths; verify actual access after application." } }
                    label { input { r#type: "checkbox", checked: view.preferences.allow_local_lan,
                        onchange: move |event| { if let Some(view) = draft.write().as_mut() { view.preferences.allow_local_lan = event.checked(); } } }
                        if chinese { "允许直接访问当前本地局域网" } else { "Allow direct access to the current local LAN" }
                    }
                }
                if current.as_ref().is_some_and(|current|current.version != view.version) {
                    p { role: "alert", if chinese { "设置已改变，草稿已保留。重新读取后再保存。" } else { "Settings changed. Your draft is retained; reload before saving." } }
                }
                button { disabled: current.is_none() || submitted().is_some(), onclick: move |_| {
                    let Some(view) = draft() else { return; };
                    let Some(id) = preference_request_id() else { error.set(Some("secure_request_id_unavailable".into())); return; };
                    if send_command("client_preferences",json!({"operation":"set","change":{"request_id":id,"expected_version":view.version,"preferences":view.preferences}})) {
                        submitted.set(Some((id,view.version))); error.set(None);
                    }
                }, "{save}" }
            }
            button { class: "secondary", onclick: move |_| {
                draft.set(snapshot().client_preferences); submitted.set(None); error.set(None);
                send_command("client_preferences", json!({"operation":"get"}));
            }, "{refresh}" }
            if let Some(message) = error() { p { role: "alert", "{message}" } }
        }
    }
}
