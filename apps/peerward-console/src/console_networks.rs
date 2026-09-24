#[component]
fn ConsoleNetworksPanel(snapshot: Signal<ConsoleSnapshot>, locale: Locale, ready: bool) -> Element {
    #[cfg(target_arch = "wasm32")]
    let navigator = use_navigator();
    let mut cursor = use_signal(String::new);
    let mut creating = use_signal(|| false);
    let mut data =
        use_console_query::<Page<MeshResource>>(console_page_path("/api/v1/meshes", 12, &cursor()));
    let active = snapshot.read().mesh_id.clone();
    let can_create = snapshot.read().has_capability("trust_manage");
    rsx! {
        div { class:"section-actions page-primary-action",
            if can_create { button { disabled:!ready, onclick:move |_| {creating.set(true);}, {console_text(locale,"＋ 新建网络","＋ New network")} } }
        }
        section {class:"scope-banner",span {class:"network-avatar",aria_hidden:"true","↔"}
            div {strong {{console_text(locale,"每个网络都是独立的安全边界","Each network is an independent security boundary")}}
                p {{console_text(locale,"设备、共享、访问权限和运维事件按网络隔离。切换只改变你正在查看和操作的范围。","Devices, sharing, access and events belong to their network. Switching changes the scope you are viewing and managing.")}}
            }
        }
        match data.read().as_ref() {
            Some(Ok(page)) => rsx! {
                if page.items.is_empty() {
                    section {class:"card empty-workspace",
                        if can_create {
                            h2 {{console_text(locale,"还没有网络","No networks yet")}}
                            p {{console_text(locale,"使用上方“新建网络”创建第一个网络，然后再添加 Linux 或 Android 设备。","Use New network above to create the first network, then add Linux or Android devices.")}}
                        } else {
                            h2 {{console_text(locale,"目前没有可查看的网络","No networks are available to view")}}
                            p {{console_text(locale,"当前账号不能新建网络。网络可用并授权给你后，会在这里显示。","This account cannot create networks. Networks will appear here after they are available and visible to you.")}}
                        }
                    }
                }
                div {class:"network-portfolio", for item in page.items.iter().filter(|m|m.lifecycle!="deleted") {
                    ConsoleNetworkCard {key:"{item.id}",item:item.clone(),active:active.clone(),locale}
                }}
                div {class:"actions pagination-actions",
                    if !cursor().is_empty() {button {class:"secondary-button",onclick:move |_|cursor.set(String::new()),{console_text(locale,"返回第一页","First page")}}}
                    if let Some(next)=page.next_cursor.clone(){button {class:"secondary-button",onclick:move |_|cursor.set(next.clone()),{console_message(locale,"next-page")}}}
                }
            },
            Some(Err(error)) if !error.is_empty()=>rsx!{section {class:"card",p{role:"alert","{error}"}button{onclick:move |_|data.restart(),{console_text(locale,"重试","Retry")}}}},
            _=>rsx!{section{class:"card",p{role:"status",{console_message(locale,"loading")}}}},
        }
        if creating() {
            ConsoleNetworkCreate {snapshot,locale,on_close:move |()|{creating.set(false);data.restart();},
                on_complete:move |id:String| {
                    creating.set(false);
                    data.restart();
                    #[cfg(target_arch="wasm32")]
                    navigator.push(format!("/?mesh={id}"));
                    #[cfg(not(target_arch="wasm32"))] let _=id;
                }
            }
        }
    }
}

#[component]
fn ConsoleNetworkCard(item: MeshResource, active: String, locale: Locale) -> Element {
    let mut data = use_console_query::<peerward_api::ConsoleOverview>(format!(
        "/api/v1/meshes/{}/console/overview",
        item.id
    ));
    let selected = active == item.id.to_string();
    rsx! {
        article {class:if selected{"card portfolio-card current"}else{"card portfolio-card"},
            div {class:"portfolio-title",span{class:"network-avatar",aria_hidden:"true","⌂"}
                div{h2{"{item.name}"}small{class:"muted",{item.network_identifier.as_deref().unwrap_or(&item.dns_suffix)}}}
                if selected {span{class:"type-chip",{console_text(locale,"当前网络","Current")}}}
            }
            p{class:"muted",{console_message(locale,match item.lifecycle.as_str(){"active"=>"mesh-state-active","creating"=>"mesh-state-creating","deleting"=>"mesh-state-deleting",_=>"mesh-state-unknown"})}}
            match data.read().as_ref(){
                Some(Ok(value))=>rsx!{
                    div{class:"portfolio-stats",
                        div{small{{console_text(locale,"在线设备","Devices online")}}strong{"{value.online_devices} / {value.devices}"}}
                        div{small{{console_text(locale,"已配置共享","Configured shares")}}strong{"{value.services + value.networks + value.exits}"}}
                        div{small{{console_text(locale,"待处理","Needs attention")}}strong{"{value.open_issue_count}"}}
                    }
                    a {class:if value.open_issue_count>0{"portfolio-notice attention"}else{"portfolio-notice"},href:format!("/operations?mesh={}",item.id),
                        {if value.open_issue_count>0{console_text(locale,"查看此网络需要处理的事项","Review items that need attention")}else{console_text(locale,"当前没有需要人工处理的事项","No pending items requiring attention")}}
                    }
                },
                Some(Err(error)) if !error.is_empty()=>rsx!{p{role:"alert","{error}"}button{class:"quiet-button",onclick:move |_|data.restart(),{console_text(locale,"重试统计","Retry statistics")}}},
                _=>rsx!{p{class:"muted",role:"status",{console_text(locale,"正在读取网络状态…","Loading network status…")}}},
            }
            div{class:"portfolio-actions",
                a {class:if selected{"secondary-link"}else{"primary-link"},href:format!("/?mesh={}",item.id),{if selected{console_text(locale,"进入当前网络","Open current network")}else{console_text(locale,"切换到此网络","Switch to this network")}}}
                a {class:"secondary-link",href:format!("/meshes?mesh={}",item.id),{console_text(locale,"网络设置","Network settings")}}
            }
        }
    }
}

fn console_page_path(base: &str, limit: u16, cursor: &str) -> String {
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params.append_pair("limit", &limit.to_string());
    if !cursor.is_empty() {
        params.append_pair("cursor", cursor);
    }
    format!("{base}?{}", params.finish())
}
