#[cfg(target_arch = "wasm32")]
fn console_api_error(locale: Locale, error: ConsoleApiError) -> String {
    let body = api_error_body(error);
    let (message, expose_code) = match body.code.as_str() {
        "invalid_input"
            if body.message.starts_with("invitation device group")
                || body.message == "invitation groups must contain devices" =>
        {
            (
                console_text(
                    locale,
                    "所选设备组已被删除、不可用或成员已满。请重新选择设备组；已签发的邀请需要重新创建。",
                    "A selected device group was removed, is unavailable or is full. Select groups again; an issued invitation must be recreated.",
                ),
                false,
            )
        }
        "invalid_network_configuration" if body.message == "invitation.device_groups" => (
            console_text(
                locale,
                "请选择当前网络中的有效设备组，最多 64 个。",
                "Select valid device groups in this network, up to 64.",
            ),
            false,
        ),
        "invalid_network_configuration" if body.message == "invitation.display_name" => (
            console_text(
                locale,
                "设备名称最多 128 个字符，不能包含控制字符。",
                "Use at most 128 characters without control characters for the device name.",
            ),
            false,
        ),
        "invalid_network_configuration" if body.message == "invitation.name" => (
            console_text(
                locale,
                "设备网络名称格式不正确。请使用 1–63 位小写英文字母、数字或短横线，首尾不能为短横线；不需要指定名称时可留空。",
                "Invalid device network name. Use 1–63 lowercase English letters, digits or hyphens, with no leading or trailing hyphen, or leave it empty.",
            ),
            false,
        ),
        "configuration_owned" => (
            console_text(
                locale,
                "此网络的配置由自动化管理，当前账号不能直接修改。请在配置来源更新，或由管理员移交配置管理权后重试。",
                "Automation owns this network configuration. Update its configuration source, or ask an administrator to transfer ownership before retrying.",
            ),
            false,
        ),
        "invalid_fingerprint" => (
            console_text(
                locale,
                "身份指纹格式不正确，请输入在设备上独立核对的完整小写 SHA-256 指纹。",
                "Enter the complete lowercase SHA-256 identity fingerprint independently verified on the device.",
            ),
            false,
        ),
        "network_identifier_exists" => (
            console_text(
                locale,
                "这个网络标识已经存在，请使用其他标识。",
                "This network identifier is already in use. Choose another identifier.",
            ),
            false,
        ),
        "revision_conflict"
        | "version_conflict"
        | "configuration_revision_conflict"
        | "preview_stale"
        | "preview_changed" => (
            console_text(
                locale,
                "版本已变化，本次修改未提交，草稿已保留。请核对最新内容后重新编辑并预览。",
                "The version changed. Your changes were not submitted and your draft is retained. Review the latest content before editing and previewing again.",
            ),
            false,
        ),
        "advanced_grant_required" => (
            console_text(
                locale,
                "此授权包含高级条件，请到高级规则中核对后修改。",
                "This grant has advanced conditions. Review it in the advanced policy editor.",
            ),
            false,
        ),
        "service_address" => (
            console_text(
                locale,
                "该地址不属于提供此服务的设备，请核对设备网络地址。",
                "This address does not belong to the publishing device. Check its network addresses.",
            ),
            false,
        ),
        "service_protocol" => (
            console_text(
                locale,
                "请选择此服务已配置的 TCP 或 UDP 协议。",
                "Select a TCP or UDP transport configured for this service.",
            ),
            false,
        ),
        "network_conflict" if body.message == "exit.provider_resource" => (
            console_text(
                locale,
                "同一设备只能提供一个互联网出口。请编辑该设备已有的出口，或选择其他提供设备。",
                "A device can provide one internet exit. Edit its existing exit or select another publisher.",
            ),
            false,
        ),
        "network_conflict" if body.message == "site_address_ambiguity" => (
            console_text(
                locale,
                "目标地址与其他站点的资源重叠。请核对地址和站点，属于同一局域网时使用相同站点标识。",
                "The target overlaps another site's resource. Review the address and site; resources on the same LAN must share a site identity.",
            ),
            false,
        ),
        "missing_credentials" | "session_expired" | "invalid_session" => (
            console_text(
                locale,
                "登录已失效，请重新登录后重试。",
                "Your session expired. Sign in again and retry.",
            ),
            false,
        ),
        "forbidden" | "insufficient_capability" | "permission_denied" => (
            console_text(
                locale,
                "当前账号没有执行此操作的权限。请检查账号角色。",
                "Your account cannot perform this action. Check its assigned role.",
            ),
            false,
        ),
        "csrf_failed" | "csrf_mismatch" | "invalid_csrf_token" => (
            console_text(
                locale,
                "会话校验失败，本次修改未提交。请刷新页面后重试。",
                "Session verification failed. Changes were not submitted. Refresh the page and retry.",
            ),
            false,
        ),
        "control_unavailable" => (
            console_text(
                locale,
                "暂时无法连接控制服务。请检查连接后重试；提交结果不确定时先刷新状态。",
                "The control service is unavailable. Check the connection and retry; refresh the status first if a submission result is uncertain.",
            ),
            false,
        ),
        _ => (body.message.as_str(), true),
    };
    let fields = body
        .field_errors
        .values()
        .cloned()
        .collect::<Vec<_>>()
        .join("; ");
    let mut rendered = if fields.is_empty() {
        message.to_owned()
    } else {
        format!("{message} {fields}")
    };
    if expose_code && !body.code.is_empty() {
        rendered.push_str(" (");
        rendered.push_str(&body.code);
        rendered.push(')');
    }
    rendered
}
