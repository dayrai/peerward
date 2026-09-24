#[component]
#[allow(unused_mut, unused_variables)]
fn OperationsStatusPanel(locale: Locale, maintenance_path: String, #[props(default)] compact: bool, #[props(default)] ready: bool) -> Element {
    let mut value = use_signal(|| None::<Value>);
    let mut error = use_signal(String::new);
    let mut busy = use_signal(|| false);
    let refresh = use_callback(move |()| {
        #[cfg(target_arch = "wasm32")]
        {
            if !ready || *busy.peek() {
                return;
            }
            busy.set(true);
            spawn(async move {
                let result: Result<Value, ConsoleApiError> = browser_api_client()
                    .request(Method::GET, "/api/v1/operations/status", None)
                    .await;
                match result {
                    Ok(observed) => {
                        value.set(Some(observed));
                        error.set(String::new());
                    }
                    Err(e) => {
                        error.set(e.to_string());
                        value.set(None);
                    }
                }
                busy.set(false);
            });
        }
    });
    use_effect(use_reactive(&ready, move |ready| {
        if ready {
            refresh.call(());
        }
    }));
    use_future(move || async move {
        #[cfg(target_arch = "wasm32")]
        loop {
            gloo_timers::future::TimeoutFuture::new(15_000).await;
            refresh.call(());
        }
    });
    rsx! {
        section{class:"card operations-status",aria_label:console_message(locale,"operations-status-title"),
            div{class:"panel-head",div{h2{{console_text(locale,"安装状态","Installation status")}}p{class:"muted",{console_text(locale,"多个网络共享这些基础设施；当前网络的问题优先在上方处理。","These services are shared across networks. Resolve current-network issues above first.")}}}
                button{class:"secondary-button",disabled:busy() || !ready,onclick:move |_|refresh.call(()),{console_message(locale,"operations-status-refresh")}}
            }
            if !error().is_empty(){
                div{class:"feedback-state feedback-error embedded-feedback",role:"alert",
                    span{class:"feedback-icon",aria_hidden:"true","!"}
                    div{class:"feedback-copy",strong{{console_text(locale,"暂时无法读取安装状态","Unable to load installation status right now")}}p{"{error}"}}
                    button{class:"secondary-button",disabled:busy() || !ready,onclick:move |_|refresh.call(()),{console_text(locale,"重试","Retry")}}
                }
            }
            if let Some(observed)=value(){
                if compact {
                    if let Some(alerts)=observed["alerts"].as_array(){
                        if alerts.is_empty(){
                            div{class:"installation-quiet-row",
                                span{class:"installation-quiet-icon","✓"}
                                div{strong{{console_text(locale,"共享基础设施当前无待处理事项","Shared infrastructure has no pending items")}}p{class:"muted",{console_text(locale,"控制服务、中继主机、审计观测和备份回报没有要求你在这里介入。","The control service, relay hosts, audit observations, and backup reports do not currently require action here.")}}}
                                a{class:"secondary-link",href:maintenance_path.clone(),{console_text(locale,"打开系统维护","Open system maintenance")}}
                            }
                        } else {
                            div{class:"installation-attention-row",
                                span{class:"installation-attention-icon","!"}
                                div{strong{{format!("{} {}",alerts.len(),console_text(locale,"项安装级问题需要处理","installation-level items need attention"))}}p{class:"muted",{console_text(locale,"这些问题可能影响多个网络。进入系统维护后再处理，不要在当前网络的访问规则里绕过它们。","These items may affect multiple networks. Handle them in System maintenance rather than working around them in this network's access rules.")}}}
                                a{class:"primary-link",href:maintenance_path.clone(),{console_text(locale,"进入系统维护","Open system maintenance")}}
                            }
                            div{class:"installation-alert-list",
                                for alert in alerts{p{class:"installation-alert",role:"alert",{console_message(locale,match alert.as_str(){
                                    Some("audit_observation_unknown")=>"operations-audit-unknown",Some("relay_observation_unknown")=>"operations-relay-unknown",
                                    Some("relay_maintenance_failed")=>"operations-relay-failed",Some("installation_recovery_required")=>"operations-recovery-required",
                                    Some("latest_backup_failed")=>"operations-backup-failed",_=>"operations-status-unknown",
                                })}}}
                            }
                        }
                    } else {
                        p{role:"status",{console_message(locale,"operations-status-unknown")}}
                        a{class:"secondary-link installation-maintenance-link",href:maintenance_path.clone(),{console_text(locale,"打开系统维护","Open system maintenance")}}
                    }
                    details{class:"condition-advanced compact-installation-evidence",summary{{console_text(locale,"查看安装观测摘要","View installation observation summary")}}
                        div{class:"installation-summary",
                            div{small{{console_text(locale,"控制服务","Control service")}}strong{{console_text(locale,"可访问","Reachable")}}}
                            div{small{{console_text(locale,"审计观测","Audit observations")}}strong{{if observed["audit"]["fresh"]==true{console_text(locale,"已有当前采样","Current sample available")}else{console_text(locale,"未知 / 待检查","Unknown / needs checking")}}}}
                            div{small{{console_text(locale,"备份回报","Backup reports")}}strong{{if observed["latest_successful_backup"].is_null(){console_text(locale,"尚无成功回报","No successful report")}else{console_text(locale,"已有成功回报","Successful report available")}}}}
                        }
                    }
                } else {
                    div{class:"installation-summary",
                        div{small{{console_text(locale,"控制服务","Control service")}}strong{{console_text(locale,"可访问","Reachable")}}}
                        div{small{{console_text(locale,"审计观测","Audit observations")}}strong{{if observed["audit"]["fresh"]==true{console_text(locale,"已有当前采样","Current sample available")}else{console_text(locale,"未知 / 待检查","Unknown / needs checking")}}}}
                        div{small{{console_text(locale,"备份回报","Backup reports")}}strong{{if observed["latest_successful_backup"].is_null(){console_text(locale,"尚无成功回报","No successful report")}else{console_text(locale,"已有成功回报","Successful report available")}}}}
                    }
                    if let Some(alerts)=observed["alerts"].as_array(){
                        if alerts.is_empty(){p{role:"status",{console_message(locale,"operations-no-alerts")}}}
                        for alert in alerts{p{class:"installation-alert",role:"alert",{console_message(locale,match alert.as_str(){
                            Some("audit_observation_unknown")=>"operations-audit-unknown",Some("relay_observation_unknown")=>"operations-relay-unknown",
                            Some("relay_maintenance_failed")=>"operations-relay-failed",Some("installation_recovery_required")=>"operations-recovery-required",
                            Some("latest_backup_failed")=>"operations-backup-failed",_=>"operations-status-unknown",
                        })}}}
                    }
                    nav{class:"actions",aria_label:console_message(locale,"operations-next-actions"),
                        a{class:"secondary-link",href:format!("{maintenance_path}#relay-capacity"),{console_message(locale,"capacity-title")}}
                        a{class:"secondary-link",href:format!("{maintenance_path}#relay-maintenance"),{console_message(locale,"maintenance-title")}}
                        a{class:"secondary-link",href:format!("{maintenance_path}#installation-backups"),{console_message(locale,"deployment-title")}}
                    }
                    details{class:"condition-advanced",summary{{console_text(locale,"观测详情与存储统计","Observation details and storage statistics")}}
                        p{class:"muted",{console_message(locale,"operations-audit-boundary")}}
                        if observed["audit"]["fresh"]==true{dl{class:"inventory-facts",
                            dt{{console_message(locale,"operations-audit-bytes")}}dd{{observed["audit"]["storage_bytes"].to_string()}}
                            dt{{console_message(locale,"operations-audit-rows")}}dd{{observed["audit"]["estimated_rows"].to_string()}}
                            dt{{console_message(locale,"operations-audit-growth")}}dd{if observed["audit"]["estimated_growth_rows_per_hour"].is_null(){"—"}else{{observed["audit"]["estimated_growth_rows_per_hour"].to_string()}}}
                        }}
                        pre{{serde_json::to_string_pretty(&observed).unwrap_or_default()}}
                    }
                }
            }else if error().is_empty(){
                div{class:"feedback-state feedback-loading embedded-feedback",role:"status",aria_busy:"true",
                    span{class:"feedback-icon",aria_hidden:"true","…"}
                    div{class:"feedback-copy",strong{{console_text(locale,"正在读取安装状态","Loading installation status")}}p{{console_text(locale,"这里只在需要人工介入时突出安装级问题。","Installation-level items are highlighted here only when they need your attention.")}}}
                }
            }
        }
    }
}
