#[cfg(feature = "web")]
fn install_native_bridge(
    mut snapshot: Signal<MobileRuntimeSnapshot>,
    mut invitation: Signal<String>,
    mut invitation_preview: Signal<Option<InvitationPreview>>,
    mut command_error: Signal<Option<String>>,
    mut enrollment: Signal<EnrollmentDisplay>,
    mut profiles: Signal<Vec<SavedProfile>>,
) {
    use wasm_bindgen::closure::Closure;

    let Some(window) = web_sys::window() else {
        return;
    };
    let bridge = js_sys::Reflect::get(window.as_ref(), &"peerwardNative".into()).ok();
    let Some(bridge) = bridge.filter(|value| !value.is_undefined() && !value.is_null()) else {
        command_error.set(Some("native_bridge_unavailable".to_owned()));
        return;
    };
    let handler =
        Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |event: web_sys::MessageEvent| {
            let Some(raw) = event.data().as_string() else {
                return;
            };
            let Ok(envelope) = serde_json::from_str::<BridgeEnvelope>(&raw) else {
                return;
            };
            if envelope.version != CONTRACT_VERSION {
                command_error.set(Some("bridge_version_mismatch".to_owned()));
                return;
            }
            match envelope.kind.as_str() {
                "snapshot" if envelope.sequence > snapshot().sequence => {
                    if let Ok(mut next) =
                        serde_json::from_value::<MobileRuntimeSnapshot>(envelope.payload)
                    {
                        next.sequence = envelope.sequence;
                        snapshot.set(next);
                        command_error.set(None);
                    }
                }
                "saved_profiles" => {
                    if let Ok(next) = serde_json::from_value(envelope.payload) {
                        profiles.set(next);
                    }
                }
                "join_pending" => {
                    if let Some(next) = EnrollmentDisplay::from_payload(&envelope.payload) {
                        enrollment.set(next);
                    }
                }
                "invitation" => {
                    if let Some(value) = envelope.payload.get("invitation").and_then(Value::as_str)
                    {
                        invitation.set(value.to_owned());
                        invitation_preview.set(Some(InvitationPreview {
                            control_origin: envelope
                                .payload
                                .get("control_origin")
                                .and_then(Value::as_str)
                                .unwrap_or("unknown")
                                .to_owned(),
                            mesh_summary: envelope
                                .payload
                                .get("mesh_summary")
                                .and_then(Value::as_str)
                                .unwrap_or("confirmed during claim")
                                .to_owned(),
                            ticket_summary: envelope
                                .payload
                                .get("ticket_summary")
                                .and_then(Value::as_str)
                                .unwrap_or("validated Join ticket")
                                .to_owned(),
                        }));
                    }
                }
                "command_result"
                    if envelope.payload.get("success").and_then(Value::as_bool) == Some(false) =>
                {
                    command_error.set(Some(
                        envelope
                            .payload
                            .get("error_code")
                            .and_then(Value::as_str)
                            .unwrap_or("native_command_failed")
                            .to_owned(),
                    ));
                }
                _ => {}
            }
        });
    let _ = js_sys::Reflect::set(&bridge, &"onmessage".into(), handler.as_ref());
    handler.forget();
    send_command("subscribe", json!({}));
}

#[cfg(not(feature = "web"))]
fn install_native_bridge(
    _snapshot: Signal<MobileRuntimeSnapshot>,
    _invitation: Signal<String>,
    _invitation_preview: Signal<Option<InvitationPreview>>,
    _command_error: Signal<Option<String>>,
    _enrollment: Signal<EnrollmentDisplay>,
    _profiles: Signal<Vec<SavedProfile>>,
) {
}

#[cfg(feature = "web")]
fn send_command(kind: &str, payload: Value) -> bool {
    let Some(window) = web_sys::window() else {
        return false;
    };
    let Ok(bridge) = js_sys::Reflect::get(window.as_ref(), &"peerwardNative".into()) else {
        return false;
    };
    let Ok(post) = js_sys::Reflect::get(&bridge, &"postMessage".into())
        .and_then(wasm_bindgen::JsCast::dyn_into::<js_sys::Function>)
    else {
        return false;
    };
    let command = NativeCommand {
        version: CONTRACT_VERSION,
        request_id: next_request_id(),
        kind,
        payload,
    };
    let Ok(encoded) = serde_json::to_string(&command) else {
        return false;
    };
    post.call1(&bridge, &encoded.into()).is_ok()
}

#[cfg(not(feature = "web"))]
fn send_command(_kind: &str, _payload: Value) -> bool {
    false
}

fn next_request_id() -> String {
    thread_local! { static REQUEST_ID: Cell<u64> = const { Cell::new(0) }; }
    REQUEST_ID.with(|value| {
        let next = value.get().saturating_add(1);
        value.set(next);
        format!("web-{next}")
    })
}
