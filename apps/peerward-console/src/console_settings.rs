#[component]
#[allow(unused_mut, unused_variables)]
fn ConsoleNetworkSettings(
    mesh: String,
    snapshot: Signal<ConsoleSnapshot>,
    locale: Locale,
    ready: bool,
    on_saved: EventHandler<MeshResource>,
) -> Element {
    #[cfg(target_arch = "wasm32")]
    let navigator = use_navigator();
    let mut data = use_console_query::<MeshResource>(format!("/api/v1/meshes/{mesh}"));
    let mut baseline = use_signal(|| None::<MeshResource>);
    let mut name = use_signal(String::new);
    let mut suffix = use_signal(String::new);
    let mut lease = use_signal(|| 900_u32);
    let mut busy = use_signal(|| false);
    let mut status = use_signal(String::new);
    let mut error = use_signal(String::new);
    let mut deleting = use_signal(|| false);
    let mut confirmation = use_signal(String::new);
    let mut delete_job = use_signal(|| None::<uuid::Uuid>);
    let can_write = snapshot.read().has_capability("resource_write");
    let can_trust = snapshot.read().has_capability("trust_manage");
    use_effect(move || {
        let response = data.read();
        if baseline.read().is_none()
            && let Some(Ok(value)) = response.as_ref()
        {
            name.set(value.name.clone());
            suffix.set(value.dns_suffix.clone());
            lease.set(value.lease_seconds);
            baseline.set(Some(value.clone()));
        }
    });
    let save = use_callback(move |()| {
        #[cfg(target_arch = "wasm32")]
        {
            let Some(current) = baseline.peek().clone() else {
                return;
            };
            if busy() || !can_write || name.peek().trim().is_empty() {
                return;
            }
            let request = MeshPatchRequest {
                name: Some(name.peek().trim().into()),
                dns_suffix: Some(suffix.peek().trim().into()),
                lease_seconds: can_trust.then_some(lease()),
            };
            busy.set(true);
            error.set(String::new());
            status.set(String::new());
            let api = browser_api_client()
                .with_csrf(snapshot.peek().csrf_token.clone().unwrap_or_default());
            spawn(async move {
                match api
                    .update_mesh(&current.id.to_string(), &request, current.version)
                    .await
                {
                    Ok(saved) => {
                        name.set(saved.name.clone());
                        suffix.set(saved.dns_suffix.clone());
                        lease.set(saved.lease_seconds);
                        baseline.set(Some(saved.clone()));
                        let mut value = snapshot.write();
                        value.mesh_name.clone_from(&saved.name);
                        for item in &mut value.meshes {
                            if item.id == saved.id.to_string() {
                                *item = saved.clone().into();
                            }
                        }
                        drop(value);
                        on_saved.call(saved);
                        status.set(
                            console_text(locale, "网络设置已保存", "Network settings saved").into(),
                        );
                    }
                    Err(e) => error.set(console_api_error(locale, e)),
                }
                busy.set(false);
            });
        }
    });
    let remove = use_callback(move |()| {
        #[cfg(target_arch = "wasm32")]
        {
            let Some(current) = baseline.peek().clone() else {
                return;
            };
            if busy() || !can_trust || confirmation() != current.name {
                return;
            }
            busy.set(true);
            error.set(String::new());
            let api = browser_api_client()
                .with_csrf(snapshot.peek().csrf_token.clone().unwrap_or_default());
            spawn(async move {
                match api
                    .delete_mesh(
                        &current.id.to_string(),
                        &MeshDeleteRequest {
                            confirmation_name: current.name,
                        },
                        current.version,
                    )
                    .await
                {
                    Ok(job) => {
                        delete_job.set(
                            job.get("job_id")
                                .and_then(Value::as_str)
                                .and_then(|id| id.parse().ok()),
                        );
                        deleting.set(false);
                    }
                    Err(e) => error.set(console_api_error(locale, e)),
                }
                busy.set(false);
            });
        }
    });
    let dirty = baseline.read().as_ref().is_some_and(|v| {
        name() != v.name || suffix() != v.dns_suffix || lease() != v.lease_seconds
    });
    let editable = ready
        && can_write
        && !busy()
        && baseline
            .read()
            .as_ref()
            .is_some_and(|v| v.lifecycle == "active");
    rsx! {
        if let Some(value)=baseline(){
                    div{class:"section-actions page-primary-action",button{disabled:!editable||!dirty||name().trim().is_empty()||suffix().trim().is_empty(),onclick:move |_|save.call(()),{console_text(locale,"保存网络设置","Save network settings")}}}
            div {class:"settings-layout","data-console-dirty":dirty.to_string(),
                section {class:"card settings-basics console-form",
                    h2{{console_text(locale,"基本信息","Basic information")}}
                    label{r#for:"network-name",{console_text(locale,"网络名称","Network name")}}
                    input{id:"network-name",disabled:!editable,value:name,oninput:move |e|name.set(e.value())}
                    label{r#for:"network-identity",{console_text(locale,"网络标识","Network identity")}}
                    input{id:"network-identity",readonly:true,value:value.network_identifier.clone().unwrap_or_else(||value.id.to_string())}
                    p{class:"field-help",{console_text(locale,"网络标识创建后保持稳定，设备和授权始终属于该网络。","Network identity is stable. Devices and grants remain bound to this network.")}}
                    div{class:"settings-hint",strong{{console_text(locale,"一个工作区，清晰管理","One workspace, clear control")}}p{{console_text(locale,"日常管理无需配置成员。当前账户权限仍由 OIDC 和控制服务校验，设备访问在“访问”中单独管理。","Daily operations need no member setup. OIDC and Control still enforce your account permissions; device access is managed separately.")}}}

                    if !status().is_empty(){p{role:"status","{status}"}}
                    if !error().is_empty(){p{role:"alert","{error}"}button{class:"secondary-button",disabled:busy(),onclick:move |_|{baseline.set(None);error.set(String::new());status.set(String::new());data.clear();data.restart();},{console_text(locale,"重新读取最新设置","Reload current settings")}}}
                    if !can_write{p{class:"muted",{console_text(locale,"当前账户可查看设置，无修改权限。","Your account can view these settings but cannot edit them.")}}}
                }
                div {class:"settings-conditions",
                    DeviceConditionsPanel{key:"{mesh}",mesh:mesh.clone(),csrf:snapshot.read().csrf_token.clone(),can_write,locale,ready}
                }
                section {class:"card settings-features",h2{{console_text(locale,"网络功能","Network features")}}
                    div{class:"feature-row",div{strong{{console_text(locale,"托管 DNS","Managed DNS")}}p{{console_text(locale,"按域名访问服务，配置搜索域、上游和记录。","Access services by name; configure domains, upstreams and records.")}}}a{class:"secondary-link",href:"#network-dns",{console_text(locale,"配置 DNS","Configure DNS")}}}
                    div{class:"feature-row",div{strong{{console_text(locale,"资源访问","Resource access")}}p{{console_text(locale,"创建共享并明确授权给设备或设备组。","Share resources and grant access to devices or groups.")}}}a{class:"secondary-link",href:format!("/services?mesh={mesh}"),{console_text(locale,"管理共享","Manage sharing")}}}
                    div{class:"feature-row",div{strong{{console_text(locale,"访问规则","Access rules")}}p{{console_text(locale,"查看实际策略结果并模拟访问条件。","Review policy decisions and simulate access conditions.")}}}a{class:"secondary-link",href:format!("/policy?mesh={mesh}"),{console_text(locale,"管理授权","Manage access")}}}
                }
                details {class:"card settings-advanced",id:"network-advanced",
                    summary{strong{{console_text(locale,"高级设置","Advanced settings")}}small{{console_text(locale,"DNS 后缀、离线授权和只读网络参数","DNS suffix, offline authorization and read-only network parameters")}}}
                    div {class:"settings-fields console-form",
                        label{{console_text(locale,"DNS 后缀","DNS suffix")}
                            input{disabled:!editable,value:suffix,oninput:move |e|suffix.set(e.value())}}
                        label{{console_text(locale,"离线授权时长","Offline authorization duration")}
                            select{disabled:!editable||!can_trust,value:lease().to_string(),onchange:move |e|{if let Ok(v)=e.value().parse(){lease.set(v);}},for seconds in [300,900,3600]{option{value:"{seconds}","{seconds} s"}}}}
                        for (label,text) in [
                            (console_text(locale,"内部网络 UUID","Internal network UUID"),value.id.to_string()),
                            (console_text(locale,"内部 IPv4 / IPv6 地址范围","Internal address ranges"),format!("{} · {}",value.address_cidr,value.secondary_cidr)),
                            (console_text(locale,"网关地址","Gateway addresses"),format!("{} · {}",value.gateway,value.secondary_gateway)),
                            ("MTU",value.mtu.to_string()),
                            (console_text(locale,"未匹配流量","Unmatched traffic"),value.default_policy.clone()),
                        ]{label{"{label}"}div{class:"readonly-value","{text}"}}
                    }
                    p{class:"field-help",{console_text(locale,"地址范围、网关和 MTU 创建后只读；修改访问行为请进入访问规则。","Address ranges, gateways and MTU are immutable. Use access rules to change access behavior.")}}
                }
                details{class:"card settings-advanced",id:"network-dns",summary{strong{{console_text(locale,"托管 DNS 配置","Managed DNS configuration")}}small{{console_text(locale,"按需展开配置与生效检查","Expand to configure and inspect effective settings")}}}
                    DnsPanel{key:"{mesh}",mesh:mesh.clone(),csrf:snapshot.read().csrf_token.clone(),can_write,locale,ready}
                }
                section{class:"card danger-zone settings-danger",h2{{console_text(locale,"危险操作","Danger zone")}}
                    div{class:"feature-row",div{strong{{console_text(locale,"删除网络","Delete network")}}p{{console_message(locale,"delete-mesh-help")}}}
                        if can_trust{button{class:"danger-button",disabled:busy()||delete_job().is_some()||value.lifecycle!="active",onclick:move |_|{confirmation.set(String::new());deleting.set(true);},{console_text(locale,"删除网络","Delete network")}}}
                    }
                    if delete_job().is_some(){p{role:"status",{console_text(locale,"删除请求已提交，等待下方任务报告实际进度。","Deletion submitted. Follow the task below for actual progress.")}}}
                    if can_trust{MeshProvisioningPanel{snapshot,name,selected:mesh.clone(),automatic:false,locale,current_network:true,watch_job:delete_job(),on_complete:move |id:String|{
                        #[cfg(target_arch="wasm32")]if id.is_empty(){navigator.replace("/networks");}
                        #[cfg(not(target_arch="wasm32"))]let _=id;
                    }}}
                }
            }
            if deleting(){ConsoleOverlay{title:console_text(locale,"确认删除网络","Confirm network deletion"),on_close:move |()|deleting.set(false),
                div{class:"console-form",p{strong{"{value.name}"}}p{{console_message(locale,"delete-mesh-help")}}
                    label{r#for:"delete-network-confirm",{console_text(locale,"输入网络名称以确认","Type the network name to confirm")}}
                    input{id:"delete-network-confirm",autocomplete:"off",value:confirmation,oninput:move |e|confirmation.set(e.value())}
                    if !error().is_empty(){p{role:"alert","{error}"}}
                    button{class:"danger-button",disabled:busy()||confirmation()!=value.name,onclick:move |_|remove.call(()),{console_text(locale,"确认删除","Confirm deletion")}}
                }
            }}
        }else if let Some(Err(message))=data.read().as_ref(){
            section{class:"card",p{role:"alert","{message}"}button{onclick:move |_|data.restart(),{console_text(locale,"重试","Retry")}}}
        }else{section{class:"card",p{role:"status",{console_message(locale,"loading")}}}}
    }
}
