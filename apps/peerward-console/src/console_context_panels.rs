#[component]
fn ConsoleContextPanels(mesh: String, locale: Locale, healthy: bool) -> Element {
    let _ = healthy;
    let data = use_console_query::<Page<peerward_api::AuditResource>>(if mesh.is_empty() {
        String::new()
    } else {
        format!("/api/v1/meshes/{mesh}/audit?limit=3")
    });
    rsx! {
        section{class:"card overview-activity",
            div{class:"panel-head",
                div{
                    h2{{console_text(locale,"最近活动","Recent activity")}}
                    p{class:"muted",{console_text(locale,"只保留最近几条变化；完整记录用于需要回溯时查看。","Only the latest changes are shown here; use the full log when you need to trace history.")}}
                }
                a{class:"text-link",href:format!("/audit?mesh={mesh}"),{console_text(locale,"查看操作记录","View activity log")}}
            }
            match data.read().as_ref(){
                Some(Ok(page))=>rsx!{
                    if page.items.is_empty(){p{class:"empty",{console_text(locale,"此网络暂无操作记录。","No recorded activity in this network.")}}}
                    for row in &page.items{div{class:"recent-activity",span{class:format!("result-pill {}",row.result),{activity_result(locale,&row.result)}}div{strong{{activity_action(locale,&row.action)}}small{"{row.actor} · " LocalDateTime{value:row.timestamp.clone(),locale}}}}}
                },
                Some(Err(error)) if !error.is_empty()=>rsx!{p{role:"alert","{error}"}},
                _=>rsx!{p{class:"muted",{console_message(locale,"loading")}}},
            }
        }
    }
}
#[component]
fn ConsoleNetworkHealthSummary(mesh: String, locale: Locale) -> Element {
    let data = use_console_query::<peerward_api::ConsoleOverview>(if mesh.is_empty() {
        String::new()
    } else {
        format!("/api/v1/meshes/{mesh}/console/overview")
    });
    rsx! {section{class:"card network-path-summary",h2{{console_text(locale,"当前网络路径","Current network paths")}}p{class:"muted",{console_text(locale,"在线状态不代表目标服务或互联网一定可达。","Online status does not establish service or internet reachability.")}}
        if let Some(Ok(view))=data.read().as_ref(){div{class:"path-summary-stats",
            div{small{{console_text(locale,"在线设备","Online devices")}}strong{"{view.online_devices} / {view.devices}"}}
            div{small{{console_text(locale,"局域网资源","LAN resources")}}strong{"{view.networks}"}}
            div{small{{console_text(locale,"互联网出口","Internet exits")}}strong{"{view.exits}"}}
            div{small{{console_text(locale,"身份待检查","Identity warnings")}}strong{"{view.credential_warnings}"}}
        }p{class:"field-help",{console_text(locale,"统计时间","Observed at")} " " LocalDateTime{value:format_timestamp(view.observed_at),locale}}}
        else if let Some(Err(error))=data.read().as_ref(){if !error.is_empty(){p{role:"alert","{error}"}}}
        a{class:"secondary-link",href:format!("/services?mesh={mesh}"),{console_text(locale,"检查共享路径与可达性","Inspect resource paths and reachability")}}
    }}
}
