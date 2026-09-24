#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct SavedProfile {
    peer_id: String,
    mesh_name: String,
    address: String,
    active: bool,
    available: bool,
}

#[component]
fn SavedProfileSettings() -> Element {
    let locale = consume_context::<Signal<Locale>>();
    let chinese = locale() == Locale::ZhCn;
    let snapshot = consume_context::<Signal<MobileRuntimeSnapshot>>();
    let profiles = consume_context::<Signal<Vec<SavedProfile>>>();
    let error = consume_context::<Signal<Option<String>>>();
    let stopped = matches!(
        snapshot().connection,
        ConnectionPhase::Stopped | ConnectionPhase::Failed
    );
    let mut confirm = use_signal(|| false);
    let mut forgetting = use_signal(|| None::<String>);
    use_effect(move || {
        send_command("saved_profiles", json!({}));
    });
    rsx! {
        article { class: "mobile-card", id: "saved-networks",
            h2 { if chinese { "保存的网络" } else { "Saved networks" } }
            p { class: "mobile-help",
                if chinese { "先断开当前连接，再选择网络。每次只运行一个配置；切换保留密钥与信任记录，连接时重新验证授权。" }
                else { "Disconnect before choosing a network. One profile runs at a time; keys and trust history remain, and authorization is checked when connecting." }
            }
            if let Some(code) = error() {
                if code.starts_with("saved_profile") || code == "profile_change_requires_stopped_runtime" {
                    p { role: "alert",
                        if chinese { "未切换。请等待 VPN 完全停止并完成或取消待决入网，再重试；配置或密钥损坏时需重新接入。" }
                        else { "No switch was completed. Wait for VPN cleanup and finish or discard pending enrollment, then retry. Damaged profiles or missing keys require enrollment again." }
                    }
                }
            }
            for profile in profiles() {
                div { key: "{profile.peer_id}", class: "mobile-actions",
                    span { if profile.mesh_name.is_empty() {
                            if chinese { "不可读取的配置" } else { "Unreadable profile" }
                        } else { "{profile.mesh_name} · {profile.address}" }
                    }
                    if profile.active {
                        span { if chinese { "当前选择" } else { "Selected" } }
                    } else {
                        button { class: "secondary", disabled: !stopped || !profile.available,
                            onclick: { let id=profile.peer_id.clone(); move |_| { send_command("select_profile", json!({"peer_id":id})); } },
                            if chinese { "选择" } else { "Select" }
                        }
                    }
                    if !profile.active {
                        button { class: "secondary", disabled: !stopped,
                            onclick: { let id=profile.peer_id.clone(); move |_| forgetting.set(Some(id.clone())) },
                            if chinese { "移除保存项" } else { "Forget saved entry" }
                        }
                    }
                    if !profile.available { span { if chinese { "不可用" } else { "Unavailable" } } }
                }
            }
            if let Some(id)=forgetting() {
                p { role: "status", if chinese { "仅移除该保存项，包括无法读取的归档。密钥与信任记录保留；此操作不会停用远端设备。需要撤权请在控制台停用设备。" }
                    else { "Remove this saved entry, including an unreadable archive. Keys and trust history remain; remote access is not revoked. Disable the device in the console to revoke access." } }
                button { disabled: !stopped, onclick: move |_| { send_command("forget_saved_profile", json!({"peer_id":id,"confirm_forget":true}));forgetting.set(None); },
                    if chinese { "确认移除保存项" } else { "Confirm forgetting entry" }
                }
                button { class:"secondary", onclick: move |_| forgetting.set(None), if chinese { "取消" } else { "Cancel" } }
            }
            if snapshot().profile.is_some() {
                if confirm() {
                    p { if chinese { "保存当前网络并打开添加设备入口；当前网络保持断开。" }
                        else { "Save this network and open enrollment; it remains disconnected." } }
                    button { id: "confirm-save-network", disabled: !stopped,
                        onclick: move |_| { send_command("save_and_add_network", json!({"confirm_disconnect":true})); confirm.set(false); },
                        if chinese { "保存并添加网络" } else { "Save and add network" }
                    }
                    button { class: "secondary", onclick: move |_| confirm.set(false),
                        if chinese { "取消" } else { "Cancel" }
                    }
                } else {
                    button { id: "save-network", disabled: !stopped || profiles().len() >= 32, onclick: move |_| confirm.set(true),
                        if chinese { "添加另一个网络" } else { "Add another network" }
                    }
                }
            } else {
                Link { to: Route::Home {}, if chinese { "添加设备" } else { "Add device" } }
            }
        }
    }
}
