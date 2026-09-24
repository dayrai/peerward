#[component]
fn ConsoleInfrastructureInventory(
    route: ConsoleRoute,
    resources: Vec<ResourceSummary>,
    locale: Locale,
) -> Element {
    let relay = route == ConsoleRoute::Relays;
    rsx! {
        section {class:"scope-banner",span{class:"network-avatar",aria_hidden:"true","◇"}
            div {strong{{if relay{console_text(locale,"系统维护作用于安装级主机","System maintenance targets installation hosts")}else{console_text(locale,"网络信任与凭据","Network trust and credentials")}}}
                p{{if relay{console_text(locale,"Relay 主机可同时服务多个网络。下面只展示当前网络关联的 Relay；维护动作作用于共享主机。","A Relay host can serve several networks. Only Relays linked to this network are shown; maintenance acts on the shared host.")}else{console_text(locale,"设备私钥始终留在设备上。签发机构和自动化凭证按各自的生命周期管理。","Device private keys remain on devices. Authorities and automation credentials have separate lifecycles.")}}}
            }
        }
        section {class:"card inventory-panel",h2{{if relay{console_text(locale,"当前网络使用的 Relay","Relays used by this network")}else{console_text(locale,"签发机构","Signing authorities")}}}
            if resources.is_empty(){p{class:"empty",{console_text(locale,"当前范围内暂无记录。选择网络后可查看其配置。","No records in this scope. Select a network to inspect its configuration.")}}}
            for item in resources {
                article{class:"inventory-row",div{class:"panel-head",strong{"{item.name}"}
                    if relay{span{class:"result-pill",{if item.details.get("online")==Some(&Value::Bool(true)){console_text(locale,"在线","Online")}else{console_text(locale,"离线 / 未观测","Offline / not observed")}}}}
                    else{span{class:"result-pill",{item.details.get("lifecycle").map(display_detail).unwrap_or_default()}}}
                }
                    dl{class:"inventory-facts",for (key,zh,en) in if relay{vec![("region","区域","Region"),("presence_count","设备连接","Attached devices"),("peer_endpoints","设备端点","Peer endpoints")]}else{vec![("not_before","生效时间","Valid from"),("not_after","有效期至","Expires"),("overlap_deadline","重叠期限","Overlap deadline")]} {
                        if let Some(value)=item.details.get(key){dt{{console_text(locale,zh,en)}}dd{if key.starts_with("not_")||key=="overlap_deadline"{LocalDateTime{value:display_detail(value),locale}}else{{display_detail(value)}}}}
                    }}
                    details{summary{{console_message(locale,"technical-details")}}code{"{item.id}"}pre{{serde_json::to_string_pretty(&item.details).unwrap_or_default()}}}
                }
            }
        }
    }
}

#[component]
fn ConsoleResourceSummary(mesh: String, locale: Locale) -> Element {
    let data = use_console_query::<peerward_api::ConsoleOverview>(format!(
        "/api/v1/meshes/{mesh}/console/overview"
    ));
    rsx! {
        if let Some(Ok(value)) = data.read().as_ref() {
            div { class: "resource-summary-strip",
                for (zh, en, count, attention) in [
                    ("设备服务", "Device services", value.services, false),
                    ("局域网资源", "LAN resources", value.networks, false),
                    ("互联网出口", "Internet exits", value.exits, false),
                    ("待处理", "Needs attention", value.open_issue_count, true),
                ] {
                    span { class: if attention && count > 0 { "resource-summary-item attention" } else { "resource-summary-item" },
                        strong { "{count}" }
                        {console_text(locale, zh, en)}
                    }
                }
            }
        }
    }
}
