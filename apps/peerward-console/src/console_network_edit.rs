#[component]
#[allow(unused_mut, unused_variables)]
fn ConsoleNetworkEditor(
    mesh: String,
    resource: peerward_management::NetworkResource,
    locale: Locale,
    csrf: Option<String>,
    on_change: EventHandler<()>,
) -> Element {
    let original = use_signal(|| NetworkDraft::from_resource(&resource));
    let mut draft = use_signal(|| original.read().clone());
    let mut reason = use_signal(String::new);
    let mut confirmation = use_signal(String::new);
    let request_id = use_signal(uuid::Uuid::new_v4);
    let mut staged = use_signal(|| None::<peerward_api::ConsoleNetworkEdit>);
    let mut preview = use_signal(|| None::<peerward_api::ConsoleNetworkEditPreview>);
    let mut busy = use_signal(|| false);
    let mut complete = use_signal(|| false);
    let mut message = use_signal(String::new);
    let run = use_callback(move |apply: bool| {
        #[cfg(target_arch = "wasm32")]
        {
            if busy() {
                return;
            }
            let candidate = if apply {
                let Some(value) = staged() else {
                    return;
                };
                value
            } else {
                let definition = match draft.read().definition() {
                    Ok(definition) => definition,
                    Err(key) => {
                        message.set(console_message(locale, key).into());
                        return;
                    }
                };
                peerward_api::ConsoleNetworkEdit {
                    request_id: request_id(),
                    resource_version: original.read().version.unwrap_or_default(),
                    definition,
                    reason: reason(),
                    gateways: vec![],
                }
            };
            let base = format!(
                "/api/v1/meshes/{mesh}/console/network-resources/{}",
                original.read().id
            );
            let csrf = csrf.clone();
            busy.set(true);
            message.set(String::new());
            spawn(async move {
                let api = browser_api_client().with_csrf(csrf.unwrap_or_default());
                let result: Result<peerward_api::ConsoleNetworkEditPreview, ConsoleApiError> =
                    if apply {
                        let Some(review) = preview() else {
                            busy.set(false);
                            return;
                        };
                        api.conditional_request(
                            Method::POST,
                            &format!("{base}/apply"),
                            Some(json!(peerward_api::ConsoleNetworkEditApply {
                                draft: candidate.clone(),
                                preview_digest: review.digest
                            })),
                            review.version,
                        )
                        .await
                    } else {
                        api.request(
                            Method::POST,
                            &format!("{base}/preview"),
                            Some(json!(candidate)),
                        )
                        .await
                    };
                match result {
                    Ok(review) => {
                        staged.set(Some(candidate));
                        preview.set(Some(review));
                        if apply {
                            complete.set(true);
                            on_change.call(());
                        }
                    }
                    Err(error) => message.set(console_api_error(locale, error)),
                }
                busy.set(false);
            });
        }
    });
    rsx! {
        section { class: "console-form", "data-console-dirty": (!complete() && (draft() != original() || !reason().is_empty())).to_string(),
            h3 { {console_text(locale, "编辑共享目标", "Edit shared target")} }
            if complete() {
                p { class: "success-note", role: "status", {console_text(locale, "变更已提交。继续查看下方配置、路径和设备回执，确认实际应用进度。", "Change submitted. Check configuration, paths and device receipts below for actual application progress.")} }
            } else if let Some(review) = preview() {
                p { "{draft.read().name}" }
                p { {format!("{}：{} → {}", console_text(locale, "目标", "Target"), console_network_target(&original.read()), console_network_target(&draft.read()))} }
                p { {format!("TCP {}：{} → {}", console_text(locale, "探测", "probe"), console_network_probe(locale, &original.read()), console_network_probe(locale, &draft.read()))} }
                p { {format!("{}：{}", console_text(locale, "变更原因", "Change reason"), reason())} }
                p { {console_text(locale, "已有授权规则、标签和 DNS 记录保持不变。", "Existing grants, labels and DNS records are preserved.")} }
                if review.target_changed {
                    p { class: "risk-preview", {format!("{} {}", review.gateways_requiring_approval, console_text(locale, "个网关需要重新批准；原有路径会撤回。请核对指向旧地址的 DNS 记录。", "gateways require reapproval; previous paths will be withdrawn. Review DNS records pointing to the old target."))} }
                }
                if !review.overlapping_resources.is_empty() {
                    p { {format!("{} {}", console_text(locale, "重叠共享：", "Overlapping shares:"), review.overlapping_resources.join(", "))} }
                }
                label { {console_text(locale, "输入原共享名称确认", "Type the original share name")}
                    input { value: confirmation, disabled: busy(), oninput: move |e| confirmation.set(e.value()) }
                }
                div { class: "actions",
                    button { class: "secondary-button", disabled: busy(), onclick: move |_| { preview.set(None); confirmation.set(String::new()); }, {console_text(locale, "返回修改", "Back")} }
                    button { disabled: busy() || confirmation() != original.read().name, onclick: move |_| run.call(true), {console_text(locale, "确认提交变更", "Apply change")} }
                }
            } else {
                fieldset { disabled: busy(),
                    label { {console_text(locale, "共享名称", "Share name")}
                        input { value: "{draft.read().name}", maxlength: 128, oninput: move |e| draft.write().name = e.value() }
                    }
                    if draft.read().kind == "subnet" {
                        label { {console_text(locale, "目标地址或网段", "Target address or subnet")}
                            input { value: "{draft.read().prefix}", placeholder: "192.168.10.0/24", oninput: move |e| draft.write().prefix = e.value() }
                        }
                    } else {
                        label { {console_text(locale, "出口地址族", "Exit address families")}
                            select { value: "{draft.read().kind}", onchange: move |e| draft.write().kind = e.value(),
                                option { value: "internet_v4", "IPv4" }
                                option { value: "internet_v6", "IPv6" }
                                option { value: "internet_dual", "IPv4 + IPv6" }
                            }
                        }
                    }
                    details {
                        summary { {console_text(locale, "可选 TCP 探测", "Optional TCP probe")} }
                        p { class: "muted", {console_text(locale, "只检查指定地址的 TCP 端口；不验证应用登录、UDP 或完整互联网连接。清空两个字段可关闭探测。", "Checks only this TCP endpoint, not application authentication, UDP or full internet connectivity. Clear both fields to disable probing.")} }
                        label { {console_text(locale, "探测地址", "Probe address")}
                            input { value: "{draft.read().probe_address}", oninput: move |e| draft.write().probe_address = e.value() }
                        }
                        label { {console_text(locale, "探测端口", "Probe port")}
                            input { r#type: "number", min: 1, max: 65535, value: "{draft.read().probe_port}", oninput: move |e| draft.write().probe_port = e.value() }
                        }
                    }
                    label { {console_text(locale, "变更原因", "Change reason")}
                        input { value: reason, maxlength: 512, oninput: move |e| reason.set(e.value()) }
                    }
                    button { disabled: reason().trim().is_empty() || draft.read().definition().is_err(), onclick: move |_| run.call(false), {console_text(locale, "预览变更影响", "Preview change impact")} }
                }
            }
            if !message().is_empty() { p { role: "alert", "{message}" } }
        }
    }
}

fn console_network_target(draft: &NetworkDraft) -> String {
    match draft.kind.as_str() {
        "subnet" => draft.prefix.clone(),
        "internet_v6" => "IPv6".into(),
        "internet_dual" => "IPv4 + IPv6".into(),
        _ => "IPv4".into(),
    }
}

fn console_network_probe(locale: Locale, draft: &NetworkDraft) -> String {
    if draft.probe_address.is_empty() {
        console_text(locale, "未配置", "Not configured").into()
    } else {
        format!("[{}]:{}", draft.probe_address, draft.probe_port)
    }
}
