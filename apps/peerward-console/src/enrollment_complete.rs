#[component]
fn EnrollmentComplete(
    mesh: String,
    peer_id: peerward_types::PeerId,
    locale: Locale,
    can_write: bool,
) -> Element {
    rsx! {
        div { class: "success-note enrollment-complete", role: "status",
            strong { {console_text(locale, "设备已加入网络", "Device joined the network")} }
            p { {console_text(locale,
                "控制服务已批准加入并签发设备身份。请保持客户端运行以领取并应用；是否在线以设备详情中的当前状态为准。",
                "Control approved enrollment and issued the device identity. Keep the client running to retrieve and apply it; check device details for current connectivity.")}
            }
        }
        div { class: "next-actions",
            a { class: "primary-link", href: format!("/peers?mesh={mesh}&resource={peer_id}"),
                {console_text(locale, "查看这台设备", "View this device")}
            }
            a { class: "secondary-link", href: format!("/policy?mesh={mesh}&source=peer:{peer_id}"),
                if can_write { {console_text(locale, "设置访问权限", "Set access permissions")} }
                else { {console_text(locale, "查看访问权限", "View access permissions")} }
            }
        }
    }
}
