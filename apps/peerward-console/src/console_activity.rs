fn activity_result(locale: Locale, result: &str) -> &'static str {
    match result {
        "success" => console_text(locale, "成功", "Success"),
        "denied" => console_text(locale, "拒绝", "Denied"),
        "failure" => console_text(locale, "失败", "Failed"),
        _ => console_text(locale, "未知", "Unknown"),
    }
}
fn activity_target(locale: Locale, target: &str) -> String {
    match target {
        "mesh" => console_text(locale, "网络", "Network"),
        "peer" => console_text(locale, "设备", "Device"),
        "service" => console_text(locale, "设备服务", "Device service"),
        "network_resource" => console_text(locale, "共享", "Share"),
        "policy" | "resource_policy" => console_text(locale, "访问策略", "Access policy"),
        "authority" => console_text(locale, "签发机构", "Authority"),
        "relay" => "Relay",
        "sharing" => console_text(locale, "共享", "Sharing"),
        "device_conditions" => console_text(locale, "设备条件", "Device conditions"),
        "dns_profile" => console_text(locale, "DNS 配置", "DNS profile"),
        "webhook" => console_text(locale, "事件通知", "Webhook"),
        "collection" => console_text(locale, "设备组", "Device group"),
        "join_ticket" => console_text(locale, "加入邀请", "Invitation"),
        "credential" => console_text(locale, "凭据", "Credential"),
        _ => target,
    }
    .to_owned()
}
fn activity_action(locale: Locale, action: &str) -> String {
    let Some((target, operation)) = action.split_once('.') else {
        return action.into();
    };
    let verb = match operation {
        "create" | "created" => console_text(locale, "创建", "Create"),
        "update" | "updated" => console_text(locale, "修改", "Update"),
        "save" | "saved" => console_text(locale, "保存", "Save"),
        "delete" | "deleted" => console_text(locale, "删除", "Delete"),
        "disable" | "disabled" => console_text(locale, "停用", "Disable"),
        "revoke" | "revoked" => console_text(locale, "撤销", "Revoke"),
        "restore" => console_text(locale, "恢复", "Restore"),
        "publish" | "published" => console_text(locale, "发布", "Publish"),
        "approve" | "approved" => console_text(locale, "批准", "Approve"),
        _ => return action.into(),
    };
    format!("{} · {verb}", activity_target(locale, target))
}
#[component]
fn ConsoleActivityPanel(mesh: String, locale: Locale) -> Element {
    let mut cursor = use_signal(String::new);
    let mut query = use_signal(String::new);
    let mut result = use_signal(String::new);
    let mut global = use_signal(|| false);
    let path = if mesh.is_empty() || global() {
        "/api/v1/audit".to_string()
    } else {
        format!("/api/v1/meshes/{mesh}/audit")
    };
    let mut data = use_console_query::<Page<peerward_api::AuditResource>>(console_page_path(
        &path,
        50,
        &cursor(),
    ));
    let rows = data
        .read()
        .as_ref()
        .and_then(|r| r.as_ref().ok())
        .map(|p| p.items.clone())
        .unwrap_or_default();
    let filtered = rows
        .iter()
        .filter(|r| {
            (result().is_empty() || r.result == result())
                && format!(
                    "{} {} {} {:?} {}",
                    r.action,
                    r.actor,
                    r.target_type,
                    r.target_id,
                    activity_action(locale, &r.action)
                )
                .to_lowercase()
                .contains(&query().to_lowercase())
        })
        .cloned()
        .collect::<Vec<_>>();
    let export = {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        format!(
            "data:application/json;charset=utf-8;base64,{}",
            STANDARD.encode(serde_json::to_string_pretty(&filtered).unwrap_or_default())
        )
    };
    rsx! {
        section{class:"scope-banner",span{class:"network-avatar",aria_hidden:"true","✓"}div{strong{{console_text(locale,"操作记录保留可追溯的变更信息","Traceable records of configuration changes")}}p{{console_text(locale,"只展示服务端脱敏记录；加入令牌、私钥和密码不会进入此页面或导出。","Only sanitized server records are shown. Enrollment tokens, private keys and passwords are excluded from this page and its export.")}}}}
        section{class:"card activity-panel",
            div{class:"panel-head",div{h2{{console_text(locale,"操作记录","Activity log")}}p{class:"muted",{console_text(locale,"每页最多 50 条；搜索、结果筛选和导出仅作用于当前页。","Up to 50 records per page. Search, result filters and export apply to this page.")}}}
                a{class:"secondary-link",href:export,download:"peerward-activity-page.json",{console_text(locale,"导出当前页","Export current page")}}
            }
            div{class:"filter-bar",
                label{class:"sr-only",r#for:"activity-search",{console_text(locale,"筛选本页记录","Filter this page")}}
                input{id:"activity-search",placeholder:console_text(locale,"搜索本页操作、操作者或对象","Search this page by action, actor or target"),value:query,oninput:move |e|query.set(e.value())}
                label{class:"sr-only",r#for:"activity-scope",{console_text(locale,"记录范围","Record scope")}}
                select{id:"activity-scope",value:if global(){"all"}else{"current"},onchange:move |e|{global.set(e.value()=="all");cursor.set(String::new());},option{value:"current",{if mesh.is_empty(){console_text(locale,"安装记录","Installation records")}else{console_text(locale,"当前网络","Current network")}}}option{value:"all",{console_text(locale,"所有可见记录","All visible records")}}}
                label{class:"sr-only",r#for:"activity-result",{console_text(locale,"操作结果","Operation result")}}
                select{id:"activity-result",value:result,onchange:move |e|result.set(e.value()),option{value:"",{console_text(locale,"全部结果","All results")}}for key in ["success","failure","denied"]{option{value:key,{activity_result(locale,key)}}}}
                button{class:"secondary-button",onclick:move |_|data.restart(),{console_text(locale,"刷新","Refresh")}}
            }
            match data.read().as_ref(){
                Some(Ok(_))=>rsx!{
                    if filtered.is_empty(){p{class:"empty",{console_text(locale,"本页没有匹配记录。","No matching records on this page.")}}}
                    div{class:"activity-list",for row in filtered {
                        article{class:"activity-row",key:"{row.id}",
                            div{class:"activity-time",LocalDateTime{value:row.timestamp.clone(),locale}}
                            span{class:format!("result-pill {}",row.result),{activity_result(locale,&row.result)}}
                            div{class:"activity-description",strong{{activity_action(locale, &row.action)}}p{{activity_target(locale,&row.target_type)}}
                                details{summary{{console_text(locale,"详情与原因","Details and reason")}}
                                    code{"{row.action}"}
                                    dl{dt{{console_text(locale,"对象标识","Target identity")}}dd{code{{row.target_id.map_or_else(||"—".into(), |id|id.to_string())}}}}
                                    pre{{serde_json::to_string_pretty(&row.metadata).unwrap_or_default()}}
                                }
                            }
                            div{class:"activity-actor",strong{"{row.actor}"}small{{console_text(locale,"操作者","Actor")}}}
                        }
                    }}
                },
                Some(Err(error)) if !error.is_empty()=>rsx!{p{role:"alert","{error}"}},
                _=>rsx!{p{role:"status",{console_message(locale,"loading")}}},
            }
            div{class:"actions",if !cursor().is_empty(){button{class:"secondary-button",onclick:move |_|cursor.set(String::new()),{console_text(locale,"返回第一页","First page")}}}
                if let Some(Ok(page))=data.read().as_ref(){if let Some(next)=page.next_cursor.clone(){button{class:"secondary-button",onclick:move |_|cursor.set(next.clone()),{console_message(locale,"next-page")}}}}
            }
        }
    }
}
