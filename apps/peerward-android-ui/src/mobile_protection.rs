#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default)]
struct VpnProtectionStatus {
    always_on: Option<bool>,
    lockdown: Option<bool>,
}

impl VpnProtectionStatus {
    fn label(&self, locale: Locale) -> &'static str {
        match (self.always_on, self.lockdown, locale) {
            (Some(true), Some(true), Locale::ZhCn) => "系统防泄露锁已核验开启",
            (Some(true), Some(true), _) => "System VPN lock verified",
            (Some(_), Some(false), Locale::ZhCn) => "系统防泄露锁未开启",
            (Some(_), Some(false), _) => "System VPN lock is off",
            (_, _, Locale::ZhCn) => "系统防泄露锁状态未知",
            _ => "System VPN lock could not be verified",
        }
    }
}

#[component]
fn VpnProtectionSettings() -> Element {
    let locale = consume_context::<Signal<Locale>>();
    let snapshot = consume_context::<Signal<MobileRuntimeSnapshot>>();
    let chinese = locale() == Locale::ZhCn;
    let title = if chinese {
        "网络保护"
    } else {
        "Network protection"
    };
    let boundary = if chinese {
        "默认保护只在 VPN 有效运行时生效。进程终止或系统撤销 VPN 后，流量可能直接连接互联网。"
    } else {
        "Default protection applies while the VPN is running. Traffic may connect directly if the process stops or the system revokes the VPN."
    };
    let guidance = if chinese {
        "需要系统级保护时，请在系统设置中选择 Peerward，开启“始终开启 VPN”和“阻止未使用 VPN 的连接”，然后返回此页核验。开启后由系统管理连接；未连接 VPN 时可能无法上网。"
    } else {
        "For system protection, select Peerward in VPN settings and enable Always-on VPN and Block connections without VPN. Return here to verify. The system then controls the connection; internet access may be blocked until the VPN connects."
    };
    let settings = if chinese {
        "打开系统 VPN 设置"
    } else {
        "Open system VPN settings"
    };
    let refresh = if chinese {
        "重新核验"
    } else {
        "Verify again"
    };
    rsx! {
        article { class: "mobile-card",
            h2 { "{title}" }
            p { "{boundary}" }
            p { role: "status", aria_live: "polite", "{snapshot().vpn_protection.label(locale())}" }
            p { "{guidance}" }
            button { class: "secondary", onclick: move |_| { send_command("open_vpn_settings", json!({})); }, "{settings}" }
            button { class: "secondary", onclick: move |_| { send_command("refresh_vpn_protection", json!({})); }, "{refresh}" }
        }
    }
}
