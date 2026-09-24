#[component]
#[allow(unused_mut, unused_variables)]
fn ConsoleRetireDevice(
    mesh: String,
    peer: PeerResource,
    locale: Locale,
    csrf: Option<String>,
    on_change: EventHandler<()>,
) -> Element {
    let mut confirmation = use_signal(String::new);
    let mut reason = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let mut submitted = use_signal(|| false);
    let mut message = use_signal(String::new);
    let mut message_error = use_signal(|| false);
    let dirty = (!confirmation().is_empty() || !reason().is_empty()) && !submitted();
    let target = peer.name.clone();
    rsx! {
        details { class: "card danger-zone",
            summary { {console_text(locale, "退役这台设备", "Retire this device")} }
            p {
                {
                    console_text(
                        locale,
                        "设备将被停用，凭据撤销，连接中断；它提供的共享和网关路径也会停止。再次使用需要重新加入。",
                        "Disables this device, revokes its credentials and disconnects it. Its services and gateway paths stop. Re-enrollment is required to use it again.",
                    )
                }
            }
            p {
                strong { "{peer.display_name} · {peer.name}" }
            }
            if !submitted() {
                form {
                    class: "console-form",
                    "data-console-dirty": dirty.to_string(),
                    aria_busy: busy().to_string(), "data-console-submitting": busy().to_string(),
                    onsubmit: move |e| {
                        e.prevent_default();
                        if busy() { return; }
                        message.set(String::new());
                        message_error.set(false);
                        #[cfg(target_arch = "wasm32")]
                        {
                            let mesh = mesh.clone();
                            let csrf = csrf.clone();
                            let peer = peer.clone();
                            busy.set(true);
                            spawn(async move {
                                let result = browser_api_client()
                                    .with_csrf(csrf.unwrap_or_default())
                                    .conditional_request::<
                                        Value,
                                    >(
                                        Method::POST,
                                        &format!(
                                            "/api/v1/meshes/{mesh}/console/devices/{}/retire",
                                            peer.id,
                                        ),
                                        Some(
                                            json!(
                                                peerward_api::ConsoleDeviceRetire { name : confirmation(),
                                                reason : reason() }
                                            ),
                                        ),
                                        peer.version,
                                    )
                                    .await;
                                match result {
                                    Ok(_) => {
                                        message_error.set(false);
                                        submitted.set(true);
                                        message
                                            .set(
                                                console_text(
                                                        locale,
                                                        "已退役并撤销访问。在线连接正在断开；离线设备不能凭原凭据重新加入。",
                                                        "Retired and access revoked. Live connections are disconnecting; offline devices cannot reconnect with their old credential.",
                                                    )
                                                    .into(),
                                            );
                                        on_change.call(());
                                    }
                                    Err(e) => { message_error.set(true); message.set(console_api_error(locale, e)); }
                                }
                                busy.set(false);
                            });
                        }
                    },
                    label { r#for: "retire-confirm",
                        {
                            console_text(
                                locale,
                                "输入设备网络名称确认",
                                "Enter the device network name",
                            )
                        }
                    }
                    input {
                        id: "retire-confirm",
                        value: confirmation,
                        autocomplete: "off",
                        required: true,
                        disabled: busy(),
                        oninput: move |e| { message.set(String::new()); message_error.set(false); confirmation.set(e.value()); },
                    }
                    label { r#for: "retire-reason", {console_text(locale, "退役原因", "Reason")} }
                    input {
                        id: "retire-reason",
                        value: reason,
                        required: true,
                        maxlength: 512,
                        disabled: busy(),
                        oninput: move |e| { message.set(String::new()); message_error.set(false); reason.set(e.value()); },
                    }
                    button {
                        r#type: "submit",
                        class: "danger",
                        disabled: busy() || confirmation() != target || reason().trim().is_empty(),
                        if busy() { {console_text(locale, "正在退役…", "Retiring…")} } else { {console_text(locale, "确认退役", "Retire device")} }
                    }
                }
            }
            if !message().is_empty() {
                if message_error() { p { role: "alert", "{message}" } }
                else { p { role: "status", aria_live: "polite", "{message}" } }
            }
        }
    }
}
