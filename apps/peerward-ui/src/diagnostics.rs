use crate::{DiagnosticCode, Locale, RetryHint};

/// Localized explanation for a structured observation; raw error prose is never parsed.
#[must_use]
pub const fn diagnostic_label(locale: Locale, code: DiagnosticCode) -> &'static str {
    let (zh, en) = match code {
        DiagnosticCode::DeviceOffline => ("设备离线", "Device offline"),
        DiagnosticCode::AuthenticationFailed => ("身份验证失败", "Authentication failed"),
        DiagnosticCode::PolicyDenied => ("访问规则拒绝了请求", "Access policy denied the request"),
        DiagnosticCode::DnsDegraded => ("DNS 解析不可用", "DNS resolution unavailable"),
        DiagnosticCode::TargetUnreachable => ("目标服务不可达", "Target service unreachable"),
        DiagnosticCode::RelayUnavailable => ("中继连接不可用", "Relay connection unavailable"),
        DiagnosticCode::DirectPathUnavailable => ("直连路径不可用", "Direct path unavailable"),
        DiagnosticCode::SignedStateIncomplete => (
            "正在等待已验证的网络配置",
            "Waiting for verified network configuration",
        ),
        DiagnosticCode::UnderlayUnavailable => (
            "设备的互联网连接不可用",
            "Device internet connection unavailable",
        ),
        DiagnosticCode::PacketPumpUnavailable => {
            ("VPN 数据处理未运行", "VPN packet processing is not running")
        }
        DiagnosticCode::CredentialRotation => {
            ("设备身份正在更新", "Device identity is being renewed")
        }
        DiagnosticCode::VpnPermissionRequired => ("需要 VPN 权限", "VPN permission required"),
        DiagnosticCode::RuntimeFailed => ("客户端运行失败", "Client runtime failed"),
        DiagnosticCode::ObservationUnavailable => {
            ("暂无有效的诊断证据", "No current diagnostic observation")
        }
        DiagnosticCode::Unknown => ("无法识别的诊断原因", "Unrecognized diagnostic reason"),
    };
    match locale {
        Locale::ZhCn => zh,
        Locale::EnUs => en,
    }
}

/// Localized, actionable next step corresponding to the producer's stable hint.
#[must_use]
pub const fn diagnostic_next_step(locale: Locale, hint: RetryHint) -> &'static str {
    let (zh, en) = match hint {
        RetryHint::CheckNetwork => (
            "检查设备网络和中继地址是否可达，连接恢复后重试。",
            "Check the device network and relay reachability, then retry after connectivity returns.",
        ),
        RetryHint::CheckIdentity => (
            "核对设备时间、身份有效期和撤销状态；在管理端更新身份后重连。",
            "Check the device clock, identity expiry and revocation status; renew the identity in Console before reconnecting.",
        ),
        RetryHint::CheckPolicy => (
            "在访问页面核对来源设备、目标、协议和端口，授权后重试。",
            "Check source device, target, protocol and port on Access; retry after authorization.",
        ),
        RetryHint::CheckDnsConfiguration => (
            "检查网络的 DNS 配置和上游解析器；Linux 还需检查本机 DNS 服务权限。",
            "Check network DNS configuration and upstream resolvers; on Linux also inspect local DNS service permissions.",
        ),
        RetryHint::CheckTarget => (
            "在提供设备上检查目标地址、服务监听端口和防火墙，然后重新探测。",
            "Check the target address, listening port and firewall from the provider device, then probe again.",
        ),
        RetryHint::CheckUdpOrUseRelay => (
            "中继在线时可继续通过中继访问；如需直连，请检查两端 UDP 和 NAT 条件。",
            "Use an available relay, or inspect UDP and NAT conditions at both ends to restore direct access.",
        ),
        RetryHint::WaitForSignedState => (
            "保持连接，等待配置同步；持续未恢复时检查 Control 和中继状态。",
            "Keep the connection open for configuration sync; if it persists, check Control and relay health.",
        ),
        RetryHint::RestartPeer => (
            "重新启动客户端；若仍失败，导出诊断信息检查运行日志。",
            "Restart the client; if it still fails, export diagnostics and inspect runtime logs.",
        ),
        RetryHint::WaitForCredentialRotation => (
            "保持连接直到身份更新完成，避免删除本地身份。",
            "Keep connected until identity renewal completes; retain the local identity.",
        ),
        RetryHint::GrantVpnPermission => (
            "点击连接并在系统弹窗中允许 VPN；如被撤回，请重新授权。",
            "Tap Connect and allow VPN in the system prompt; grant permission again if it was revoked.",
        ),
        RetryHint::RefreshObservation => (
            "刷新状态并检查设备是否在线；没有新证据时不要推断连接正常。",
            "Refresh status and check whether the device is online; missing evidence does not establish a healthy connection.",
        ),
        RetryHint::ExportDiagnostics | RetryHint::Unknown => (
            "导出诊断信息并核对客户端与服务端版本。",
            "Export diagnostics and check client and server versions.",
        ),
    };
    match locale {
        Locale::ZhCn => zh,
        Locale::EnUs => en,
    }
}
