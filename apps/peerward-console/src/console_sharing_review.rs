fn sharing_access_href(mesh: &str, resource: uuid::Uuid, source: &str) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query
        .append_pair("mesh", mesh)
        .append_pair("resource", &resource.to_string());
    if parse_console_source(source).is_some() {
        query.append_pair("source", source);
    }
    format!("/policy?{}", query.finish())
}

fn console_picker_feedback<T: 'static>(
    mut data: Resource<Result<T, String>>,
    empty: bool,
    locale: Locale,
) -> Element {
    if data.state()() == UseResourceState::Pending {
        return rsx! { p { role: "status", {console_text(locale, "正在读取候选项…", "Loading choices…")} } };
    }
    match data.read().as_ref() {
        Some(Err(error)) if !error.is_empty() => rsx! {
            div { class: "error", role: "alert",
                p { "{error}" }
                button { r#type: "button", class: "secondary-button", onclick: move |_| data.restart(),
                    {console_text(locale, "重试读取候选项", "Retry loading choices")}
                }
            }
        },
        Some(Ok(_)) if empty => rsx! { p { class: "empty",
            {console_text(locale, "没有可选设备，请调整搜索或先添加设备。", "No eligible devices. Adjust the search or add a device first.")}
        } },
        Some(Ok(_)) => rsx! {},
        _ => {
            rsx! { p { role: "status", {console_text(locale, "正在读取候选项…", "Loading choices…")} } }
        }
    }
}

#[component]
fn ConsoleSharingReview(
    draft: peerward_api::ConsoleSharingDraft,
    review: peerward_api::ConsoleSharingPreview,
    provider_name: String,
    source_name: String,
    locale: Locale,
    protocol_label: String,
) -> Element {
    use peerward_api::ConsoleSharingTarget as Target;
    let (kind, endpoint) = match &draft.target {
        Target::Service {
            protocols, port, ..
        } => (
            "service",
            format!(
                "{} · {port}",
                protocols
                    .iter()
                    .map(|p| match p {
                        peerward_types::ServiceProtocol::Tcp => "TCP",
                        peerward_types::ServiceProtocol::Udp => "UDP",
                    })
                    .collect::<Vec<_>>()
                    .join(" + ")
            ),
        ),
        Target::Network { definition, .. } => match &definition.target {
            peerward_management::ResourceTarget::Subnet { prefix, .. } => {
                ("lan", prefix.to_string())
            }
            peerward_management::ResourceTarget::Internet { ipv4, ipv6 } => (
                "internet",
                [ipv4.then_some("0.0.0.0/0"), ipv6.then_some("::/0")]
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join(" + "),
            ),
        },
    };
    let dns_name = match &draft.target {
        Target::Service { alias, .. } => alias.clone(),
        Target::Network { dns_name, .. } => dns_name.clone(),
    };
    let adds_grant = !matches!(&draft.source, peerward_api::ConsoleGrantSource::None);
    let path = if kind == "service" {
        let port = match &draft.target { Target::Service { port, .. } => *port, Target::Network { .. } => 0 };
        format!("{provider_name} · {protocol_label} {port}")
    } else {
        format!("{endpoint} · {} {provider_name}", console_text(locale, "经", "via"))
    };
    let needs_attention = !review.overlapping_resources.is_empty() || (adds_grant && review.affected_sources == 0);
    rsx! {
        dl { class: "sharing-review",
            div { dt { {console_text(locale, "共享类型", "Share type")} } dd { {resource_kind_label(locale, kind)} } }
            div { dt { {console_text(locale, "共享名称", "Share name")} } dd { "{draft.name}" } }
            div { dt { {console_text(locale, "路径", "Path")} } dd { "{path}" } }
            if let Some(dns_name) = dns_name {
                div { dt { {console_text(locale, "DNS 名称", "DNS name")} } dd { "{dns_name}" } }
            }
            div { dt { {console_text(locale, "访问范围", "Access scope")} } dd {
                if source_name.is_empty() { {console_text(locale, "暂不新增授权", "No new grant")} } else { "{source_name}" }
            } }
            if kind != "service" && adds_grant && draft.protocol != 0 {
                div { dt { {console_text(locale, "授权协议与端口", "Allowed protocol and port")} } dd {
                    {match draft.protocol { 6 => "TCP", 17 => "UDP", _ => "IP" }}
                    if let Some(port) = draft.port { " · {port}" }
                } }
            }
        }
        SharingInfoNote {
            title: if adds_grant { console_text(locale, "将同时创建允许规则", "An allow rule will also be created") } else { console_text(locale, "不会创建允许规则", "No allow rule will be created") },
            body: if adds_grant { console_text(locale, "系统会把授权和共享设置分别保存；已有规则仍生效。", "Access grants and share settings are saved separately; existing rules still apply.") } else { console_text(locale, "先保存共享，现有规则仍生效；未被明确允许的访问会被拒绝。", "The share is saved and existing rules still apply; access without an explicit allow rule is denied.") },
        }
        div { class: "workflow-note",
            strong { {console_text(locale, "安全边界保持分离", "Security boundaries stay separate")} }
            p { {console_text(locale, "共享设置、设备身份、访问规则和当前路径状态分别管理，任何一项都不会被另一项静默替代。", "Share settings, device identity, access rules and current path state are managed separately.")} }
        }
        details { class: "sharing-review-impact", open: needs_attention,
            summary { {console_text(locale, "查看预览影响", "Review the impact")} }
            dl { class: "resource-details",
                div { class: "resource-detail", dt { {console_text(locale, "当前授权设备数", "Current source devices")} } dd { "{review.affected_sources}" } }
                div { class: "resource-detail", dt { {console_text(locale, "已有重叠目标", "Existing overlapping targets")} } dd {
                    if review.overlapping_resources.is_empty() { "—" } else { {review.overlapping_resources.join(", ")} }
                } }
            }
            ul { class: "sharing-preview-warnings",
                for warning in &review.warnings { li { {sharing_preview_warning(locale, warning)} } }
            }
        }
    }

}

fn sharing_preview_warning(locale: Locale, warning: &str) -> String {
    match warning {
        "submitted_is_not_applied" => console_text(locale, "保存后仍需等待设备应用配置。", "Devices must still apply the saved configuration."),
        "policy_simulation_is_not_connectivity_evidence" => console_text(locale, "权限检查不代表目标当前可达。", "A permission check does not prove current connectivity."),
        "empty_collection_grants_nobody" => console_text(locale, "所选设备组没有有效成员，此次授权目前不会允许任何设备。", "The selected group has no eligible members; this grant currently permits no devices."),
        "existing_rule_order_and_denies_preserved" => console_text(locale, "已有规则顺序和拒绝规则保留，新授权不保证最终允许。", "Existing rule order and denies are retained; a new grant does not guarantee access."),
        "gateway_requires_current_forwarding_advertisement" => console_text(locale, "批准网关后，还需该设备实际启用转发并报告当前路径。", "After approval, the gateway must enable forwarding and advertise a current path."),
        "overlapping_targets_share_packet_policy" => console_text(locale, "重叠目标可能共用访问规则，请同时检查上述共享的访问结果。", "Overlapping targets may share packet rules. Check access to the shares listed above as well."),
        _ => return format!("{} {warning}", console_text(locale, "服务器提示：", "Server notice:")),
    }.to_owned()
}
