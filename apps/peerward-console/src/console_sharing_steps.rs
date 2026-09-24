fn sharing_kind_description(locale: Locale, kind: &str) -> &'static str {
    match kind {
        "service" => console_text(locale, "共享某台设备上的 TCP / UDP / HTTP 服务", "Share a device's TCP / UDP / HTTP service"),
        "lan" => console_text(locale, "通过一台网关设备访问打印机、摄像头或网段", "Reach printers, cameras or subnets through a gateway"),
        _ => console_text(locale, "通过网关设备提供受控的互联网出口", "Provide controlled internet access through a gateway"),
    }
}

#[component]
fn SharingWizardProgress(locale: Locale, step: u8, complete: bool) -> Element {
    rsx! {
        ol { class: "sharing-wizard-progress", aria_label: console_text(locale, "添加共享步骤", "Add share steps"),
            for (index, label) in [
                console_text(locale, "共享类型", "Share type"),
                console_text(locale, "共享信息", "Sharing details"),
                console_text(locale, "谁可以访问", "Who can access"),
                console_text(locale, "确认创建", "Confirm"),
            ].into_iter().enumerate() {
                li {
                    class: if complete || index + 1 < usize::from(step) { "done" } else if index + 1 == usize::from(step) { "active" } else { "" },
                    aria_current: if !complete && index + 1 == usize::from(step) { Some("step") } else { None },
                    span { aria_hidden: "true", if complete || index + 1 < usize::from(step) { "✓" } else { "{index + 1}" } }
                    "{label}"
                }
            }
        }
    }
}

#[component]
fn SharingKindChoices(locale: Locale, kind: String, disabled: bool, on_select: EventHandler<String>) -> Element {
    rsx! {
        div { class: "workflow-note",
            strong { {console_text(locale, "先选择共享类型", "Choose a share type first")} }
            p { {console_text(locale, "不同共享会使用不同连接路径；普通操作不需要先理解底层资源模型。", "Different share types use different paths; no knowledge of the underlying resource model is needed.")} }
        }
        fieldset { class: "sharing-kind-choices", disabled,
            legend { class: "sr-only", {console_text(locale, "共享类型", "Share type")} }
            for (value, icon) in [("service", "▤"), ("lan", "⌂"), ("internet", "↗")] {
                label { class: "sharing-kind-card", key: "{value}",
                    input {
                        r#type: "radio", name: "share-kind", value,
                        checked: kind == value,
                        aria_label: resource_kind_label(locale, value),
                        onchange: move |_| on_select.call(value.to_owned()),
                    }
                    span { class: "sharing-kind-icon {value}", aria_hidden: "true", "{icon}" }
                    span {
                        strong { {resource_kind_label(locale, value)} }
                        small { {sharing_kind_description(locale, value)} }
                    }
                }
            }
        }
        div { class: "security-note sharing-kind-security",
            span { aria_hidden: "true", "✓" }
            p { {console_text(locale, "无论哪种类型，都不会生成“共享凭据”；设备身份和访问策略仍然分离。", "No share type creates sharing credentials; device identity and access policy remain separate.")} }
        }
    }
}

#[component]
fn SharingWizardCancel(locale: Locale, busy: bool, on_cancel: EventHandler<()>) -> Element {
    rsx! {
        button {
            r#type: "button", class: "secondary-button sharing-wizard-cancel",
            "data-console-dismiss": "true", disabled: busy,
            onclick: move |_| on_cancel.call(()),
            {console_text(locale, "取消", "Cancel")}
        }
    }
}

#[component]
fn SharingInfoNote(title: String, body: String) -> Element {
    rsx! {
        div { class: "sharing-info-note",
            span { aria_hidden: "true", "i" }
            div { strong { "{title}" } p { "{body}" } }
        }
    }
}
