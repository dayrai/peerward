#[component]
fn EnrollmentProgress(locale: Locale, step: u8) -> Element {
    rsx! {
        ol { class: "sharing-wizard-progress enrollment-progress", aria_label: console_text(locale,"添加设备步骤","Add device steps"),
            for (index, label) in [
                console_text(locale,"设备信息","Device information"),
                console_text(locale,"接入方式","Connection method"),
                console_text(locale,"等待上线","Waiting for device"),
                console_text(locale,"完成","Complete"),
            ].into_iter().enumerate() {
                li { class: if index + 1 < usize::from(step) {"done"} else if index + 1 == usize::from(step) {"active"} else {""},
                    aria_current: if index + 1 == usize::from(step) {Some("step")} else {None},
                    span { aria_hidden:"true", if index + 1 < usize::from(step) {"✓"} else {"{index + 1}"} }
                    "{label}"
                }
            }
        }
    }
}

#[component]
fn EnrollmentConnect(
    link: String,
    expiry: String,
    name: String,
    platform: peerward_management::EnrollmentPlatform,
    locale: Locale,
) -> Element {
    let mut method = use_signal(|| {
        if platform == peerward_management::EnrollmentPlatform::Android {
            "qr"
        } else {
            "command"
        }
    });
    let command = "peerward join accept --bundle-file - --output-dir ./peerward-device";
    let install = "sudo peerward peer install --profile ./peerward-device\nsudo systemctl enable --now peerward-peer.service";
    let svg = join_qr_svg(&link, locale).unwrap_or_default();
    let download = format!(
        "data:text/plain;charset=utf-8,{}",
        url::form_urlencoded::byte_serialize(link.as_bytes()).collect::<String>()
    );
    rsx! {
        div { class: "success-note enrollment-ticket-ready", role:"status",
            span { class:"enrollment-success-mark", aria_hidden:"true", "✓" }
            div {
                strong { {console_text(locale,"一次性加入凭据已准备好","One-time invitation is ready")} }
                p { {console_text(locale,"只把它用于 ","Use this only to enroll ")} b { "{name}" } {console_text(locale," 的首次接入；加入后设备使用自己的长期身份。","; the device then uses its own long-term identity.")} }
            }
        }
        p { class:"enrollment-expiry",
            strong { {console_text(locale,"加入凭据有效至：","Invitation valid until: ")} }
            LocalDateTime { value:expiry, locale }
        }
        div { class:"segmented enrollment-method-tabs", role:"tablist", aria_label:console_text(locale,"接入方式","Connection method"),
            for (value, zh, en) in [("command","复制命令","Copy command"),("qr","扫码加入","Scan QR code"),("manual","手动输入","Manual entry")] {
                button { id:"enrollment-tab-{value}", r#type:"button", role:"tab",
                    class: if method() == value {"active"} else {""}, aria_selected:(method() == value).to_string(),
                    aria_controls:"enrollment-method", tabindex:if method() == value {"0"} else {"-1"},
                    "data-console-tab-group":"enrollment-methods",
                    onclick:move |_| method.set(value),
                    {console_text(locale,zh,en)}
                }
            }
        }
        div { id:"enrollment-method", class:"enrollment-method-panel", role:"tabpanel", aria_labelledby:"enrollment-tab-{method}",
            if method() == "command" {
                strong { {console_text(locale,"在新设备的终端运行","Run in the new device's terminal")} }
                p { class:"muted", {console_text(locale,"安装 Peerward 后运行命令，再粘贴下方邀请链接，按回车、Ctrl+D。","After installing Peerward, run the command, paste the invitation below, then press Enter and Ctrl+D.")} }
                pre { class:"command-box", code { "{command}" } }
                div { class:"actions",
                    button { r#type:"button", class:"copy-value", "data-copy-value":command,
                        "data-copy-ready":console_text(locale,"复制命令","Copy command"),
                        "data-copy-done":console_text(locale,"已复制","Copied"),
                        "data-copy-error":console_text(locale,"复制失败，请手动复制","Copy failed; copy manually"),
                        span { class:"sr-only copy-feedback", role:"status", aria_live:"polite" }
                         {console_text(locale,"复制命令","Copy command")} }
                    a { class:"secondary-link", href:download, download:"peerward-join.txt", {console_text(locale,"下载加入文件","Download invitation")} }
                }
                details { class:"enrollment-file-help",
                    summary { {console_text(locale,"使用下载的文件加入","Join with the downloaded file")} }
                    pre { class:"command-box", code { "chmod 600 ./peerward-join.txt\npeerward join accept --bundle-file ./peerward-join.txt --output-dir ./peerward-device" } }
                }
                details { class:"enrollment-file-help",
                    summary { {console_text(locale,"加入成功后，在 Linux 后台运行","After joining, run in the background on Linux")} }
                    p { class:"muted", {console_text(locale,"原生安装包提供 systemd 服务。等待加入命令成功后执行；安装前停止此设备已有的前台进程或服务。","The native package provides a systemd service. Run these after the join command succeeds; stop any existing foreground process or service for this device before installation.")} }
                    pre { class:"command-box", code { "{install}" } }
                }
            } else if method() == "qr" {
                div { class:"enrollment-qr-panel",
                    div { class:"join-qr", dangerous_inner_html:"{svg}" }
                    div { strong { {console_text(locale,"在 Peerward 客户端中扫码","Scan in the Peerward client")} }
                        p { class:"muted", {console_text(locale,"打开 Android 客户端，选择加入网络。审批模式下保持客户端等待。","Open the Android client and choose Join network. Keep it waiting when approval is required.")} }
                    }
                }
            } else {
                strong { {console_text(locale,"手动输入邀请链接","Enter the invitation manually")} }
                p { class:"muted", {console_text(locale,"在新设备的 Peerward 客户端选择加入网络，粘贴完整邀请链接。","Choose Join network in the new device's Peerward client and paste the complete invitation link.")} }
            }
            if method() != "qr" {
                label { r#for:"enrollment-link", {console_text(locale,"一次性邀请链接","One-time invitation link")} }
                textarea { id:"enrollment-link", class:"join-link", readonly:true, rows:2, value:link.clone() }
                button { r#type:"button", class:"secondary-button copy-value", "data-copy-value":link,
                    "data-copy-ready":console_text(locale,"复制邀请链接","Copy invitation link"),
                    "data-copy-done":console_text(locale,"已复制","Copied"),
                    "data-copy-error":console_text(locale,"复制失败，请手动复制","Copy failed; copy manually"),
                    span { class:"sr-only copy-feedback", role:"status", aria_live:"polite" }
                    {console_text(locale,"复制邀请链接","Copy invitation link")}
                }
            }
        }
        p { class:"info-note enrollment-secret-note", {console_text(locale,"加入凭据不是共享密码。关闭或刷新页面后不能重新读取，请先保存到目标设备。","This invitation is not a sharing password. It cannot be retrieved after closing or refreshing; transfer it to the target device first.")} }
    }
}
