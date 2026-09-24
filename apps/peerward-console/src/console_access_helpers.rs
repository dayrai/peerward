fn use_console_post<T: DeserializeOwned + 'static>(
    path: String,
    body: Value,
) -> Resource<Result<T, String>> {
    #[cfg(target_arch = "wasm32")]
    let locale = use_context::<Signal<Locale>>();
    use_resource(use_reactive((&path, &body), move |(path, body)| {
        let _epoch = CONSOLE_QUERY_EPOCH();
        #[cfg(target_arch = "wasm32")]
        let language = locale();
        async move {
            #[cfg(target_arch = "wasm32")]
            {
                if path.is_empty() {
                    return Err(String::new());
                }
                browser_api_client()
                    .request(Method::POST, &path, Some(body))
                    .await
                    .map_err(|e| console_api_error(language, e))
            }
            #[cfg(not(target_arch = "wasm32"))]
            {
                let _ = (path, body);
                Err(String::new())
            }
        }
    }))
}
fn parse_console_source(value: &str) -> Option<peerward_api::ConsoleGrantSource> {
    if let Some(id) = value.strip_prefix("peer:") {
        Some(peerward_api::ConsoleGrantSource::Peer {
            id: id.parse().ok()?,
        })
    } else if let Some(id) = value.strip_prefix("group:") {
        Some(peerward_api::ConsoleGrantSource::Collection {
            id: id.parse().ok()?,
        })
    } else {
        None
    }
}
fn matrix_outcome(locale: Locale, outcome: &str) -> &'static str {
    match outcome {
        "allowed" => console_text(locale, "允许", "Allowed"),
        "denied" => console_text(locale, "拒绝", "Denied"),
        "partial" => console_text(locale, "部分允许", "Partially allowed"),
        "conditions" => console_text(locale, "需指定条件", "Specify conditions"),
        _ => console_text(locale, "未知 / 尚无结果", "Unknown / no result"),
    }
}
fn matrix_reason(locale: Locale, reason: &str) -> &'static str {
    match reason {
        "policy_simulation_is_not_connectivity_evidence" => console_text(
            locale,
            "访问规则判断不代表连通性",
            "Access-rule evaluation is not connectivity evidence",
        ),
        "device_conditions_restricted" => console_text(
            locale,
            "设备条件限制了访问",
            "Device conditions restrict access",
        ),
        "provider_not_approved" => console_text(
            locale,
            "该网关尚未获得当前批准",
            "Gateway has no current approval",
        ),
        "resource_path_withdrawn" => {
            console_text(locale, "资源路径已撤回", "Resource path is withdrawn")
        }
        "more_specific_resource_selected" => console_text(
            locale,
            "更精确的目标决定了资源选择",
            "A more specific target selects the resource",
        ),
        "equal_prefix_aliases_share_policy_order" => console_text(
            locale,
            "相同前缀资源共用访问规则顺序",
            "Equal prefixes share access-rule ordering",
        ),
        "empty_source" => console_text(
            locale,
            "来源组当前没有有效成员",
            "Source group has no eligible members",
        ),
        "specify_address_protocol_port_and_gateway" => console_text(
            locale,
            "需要目标地址、协议、端口和网关",
            "Address, protocol, port and gateway are needed",
        ),
        _ => evidence_reason(locale, reason),
    }
}
