#[component]
pub fn ConsoleApp(
    route: ConsoleRoute,
    snapshot: ConsoleSnapshot,
    locale: Signal<Locale>,
    theme: Signal<Theme>,
    show_action_panel: bool,
    action_panel: Element,
    resource_extras: Element,
    client_routing: bool,
    #[props(default)] requested_resource: String,
    #[props(default)] requested_source: String,
) -> Element {
    rsx! {
        ConsoleShell { key:"{snapshot.mesh_id}", route, snapshot: snapshot.clone(), locale, theme, client_routing,
            Workflow { key:"{snapshot.mesh_id}:{route:?}", route, snapshot, locale:locale(), show_action_panel, action_panel, resource_extras, requested_resource, requested_source }
        }
    }
}

fn localized_route(locale: Locale, route: ConsoleRoute) -> &'static str {
    console_message(
        locale,
        match route {
            ConsoleRoute::Overview => "overview",
            ConsoleRoute::Meshes | ConsoleRoute::Networks => "meshes",
            ConsoleRoute::Authorities => "authorities",
            ConsoleRoute::Peers => "peers",
            ConsoleRoute::Relays => "relays",
            ConsoleRoute::JoinTickets => "join-tickets",
            ConsoleRoute::Policy => "policy",
            ConsoleRoute::Services => "services",
            ConsoleRoute::Audit => "audit",
            ConsoleRoute::Operations => "operations",
            ConsoleRoute::Webhooks => "webhooks-title",
        },
    )
}

#[component]
fn Workflow(
    route: ConsoleRoute,
    snapshot: ConsoleSnapshot,
    locale: Locale,
    show_action_panel: bool,
    action_panel: Element,
    resource_extras: Element,
    requested_resource: String,
    requested_source: String,
) -> Element {
    let mut advanced_open = use_signal(|| false);
    let mut groups_open = use_signal(|| false);
    let mut enrollment_open = use_signal(|| true);

    let mut browser_ready = use_signal(|| false);
    use_effect(move || browser_ready.set(true));
    let can_write = snapshot.has_capability("resource_write");
    use_effect(use_reactive((&route,), move |_| advanced_open.set(false)));
    if snapshot.mesh_id.is_empty()
        && matches!(
            route,
            ConsoleRoute::Peers
                | ConsoleRoute::Services
                | ConsoleRoute::Policy
                | ConsoleRoute::JoinTickets
                | ConsoleRoute::Authorities
                | ConsoleRoute::Webhooks
        )
    {
        return rsx! {section{class:"card empty-workspace",h2{{console_text(locale,"先选择一个网络","Select a network first")}}p{class:"muted",{console_text(locale,"设备、共享与访问设置均属于独立网络。选择网络后即可继续。","Devices, sharing and access settings belong to an independent network. Choose one to continue.")}}a{class:"primary-link",href:"/networks",{console_text(locale,"查看所有网络","View all networks")}}}};
    }
    match route {
        ConsoleRoute::Meshes | ConsoleRoute::Networks => {
            rsx! { {resource_extras} if show_action_panel {details { class:"card advanced-tools", id:"legacy-network-management", summary { {console_text(locale,"高级：手动网络管理","Advanced: manual network management")} } {action_panel} }} }
        }
        ConsoleRoute::Overview => rsx! {
            if snapshot.has_capability("resource_read"){ConsoleOverviewPanel { key:"{snapshot.mesh_id}", mesh:snapshot.mesh_id.clone(), locale, csrf:snapshot.csrf_token.clone(), can_write:can_write }}
            else{section{class:"card",p{{console_text(locale,"当前角色可以查看操作记录；查看设备和共享需要读取权限。","This role can view the activity log. Viewing devices and shares requires read permission.")}}a{class:"primary-link",href:"/audit",{console_message(locale,"audit")}}}}
            if snapshot.has_capability("resource_read") && !snapshot.mesh_id.is_empty(){ConsoleContextPanels{mesh:snapshot.mesh_id.clone(),locale,healthy:snapshot.healthy}}
        },
        ConsoleRoute::Operations => rsx! {
            div{class:"operations-workspace",
                ConsoleIssuesPanel { key:"{snapshot.mesh_id}", mesh:snapshot.mesh_id.clone(),locale,csrf:snapshot.csrf_token.clone() }
                if snapshot.has_capability("resource_read") && !snapshot.mesh_id.is_empty(){ConsoleNetworkHealthSummary{key:"{snapshot.mesh_id}",mesh:snapshot.mesh_id.clone(),locale}}
                if snapshot.has_capability("resource_read") && !snapshot.mesh_id.is_empty(){
                    details { class:"card advanced-tools", summary { {console_text(locale,"排障：网络拓扑","Troubleshooting: network topology")} }
                        TopologyGraph {resources:snapshot.resources.clone(),mesh_id:snapshot.mesh_id.clone(),locale}
                    }
                }
            }
            {resource_extras}
        },
        ConsoleRoute::Webhooks => rsx! { {resource_extras} },
        ConsoleRoute::Peers => rsx! {
            ConsoleDevicesPanel{mesh_name:snapshot.mesh_name.clone(),on_advanced:move |()| advanced_open.set(true),on_groups:move |()| groups_open.set(true),key:"{snapshot.mesh_id}:{snapshot.relay_filter:?}",requested_resource,relay_filter:snapshot.relay_filter.clone(),mesh:snapshot.mesh_id.clone(),locale,csrf:snapshot.csrf_token.clone(),can_write:can_write,can_renew:snapshot.has_capability("trust_manage"),initial:snapshot.resources}
            if groups_open() {
                ConsoleOverlay { title: console_text(locale,"设备组","Device groups"), on_close: move |()| groups_open.set(false),
                    CollectionPanel { mesh: snapshot.mesh_id.clone(), csrf:snapshot.csrf_token.clone(), can_write, locale, ready:browser_ready(), devices_only:true }
                }
            }
            if advanced_open() {
                ConsoleOverlay { wide: true, title: if can_write { console_text(locale,"高级设备工具","Advanced device tools") } else { console_text(locale,"高级设备信息","Advanced device information") }, on_close: move |()| advanced_open.set(false),
                    div { class: "advanced-drawer-intro",
                        strong {
                            if can_write { {console_text(locale,"这是故障处理和特殊场景入口","For troubleshooting and exceptional cases")} }
                            else { {console_text(locale,"这里提供只读的高级设备信息","Read-only advanced device information")} }
                        }
                        p { class:"muted",
                            if can_write { {console_text(locale,"普通添加、改名、查看共享、授权和退役设备不需要在这里操作。","Normal enrollment, naming, sharing, grants, and retirement do not require these tools.")} }
                            else { {console_text(locale,"可查看入网申请、底层状态和其他诊断信息；当前账号不会在这里修改设备。","Review enrollment requests, underlying state, and diagnostics here; this account cannot change devices from this view.")} }
                        }
                    }
                    if show_action_panel {
                        div { class: "advanced-action-panel", {action_panel} }
                    }
                    {resource_extras}
                }
            }
        },
        ConsoleRoute::Services => rsx! {
            ConsoleSharingPanel{key:"{snapshot.mesh_id}",requested_resource,mesh:snapshot.mesh_id.clone(),locale,csrf:snapshot.csrf_token.clone(),can_write:can_write}
            div { class: "advanced-entryline", id: "advanced-sharing",
                button { class: "text-link", onclick: move |_| advanced_open.set(true),
                    if can_write { {console_text(locale,"高级共享工具…","Advanced sharing tools…")} } else { {console_text(locale,"高级共享信息…","Advanced sharing information…")} }
                }
            }
            if advanced_open() {
                ConsoleOverlay { wide: true, title: if can_write { console_text(locale,"高级共享工具","Advanced sharing tools") } else { console_text(locale,"高级共享信息","Advanced sharing information") }, on_close: move |()| advanced_open.set(false),
                    div { class: "advanced-drawer-intro",
                        strong {
                            if can_write { {console_text(locale,"优先使用共享列表完成日常操作","Use the sharing list for routine work")} }
                            else { {console_text(locale,"这里提供只读的底层共享信息","Read-only underlying sharing information")} }
                        }
                        p { class:"muted",
                            if can_write { {console_text(locale,"设备服务、局域网资源和互联网出口的日常创建与检查都应先从共享列表进入。","Create and inspect device services, LAN resources, and internet exits from the sharing list first.")} }
                            else { {console_text(locale,"可查看网关、自动批准和底层网络资源状态；当前账号不会在这里修改共享。","Review gateways, auto-approval, and underlying network-resource state here; this account cannot change sharing from this view.")} }
                        }
                    }
                    if show_action_panel {
                        div { class: "advanced-action-panel", {action_panel} }
                    }
                    {resource_extras}
                }
            }
        },
        ConsoleRoute::Policy => rsx! {
            ConsoleAccessPanel{requested_resource,requested_source,key:"{snapshot.mesh_id}",mesh:snapshot.mesh_id.clone(),locale,csrf:snapshot.csrf_token.clone(),can_write:can_write}
            div { class: "advanced-entryline", id: "advanced-access",
                button { class: "text-link", onclick: move |_| advanced_open.set(true),
                    if can_write { {console_text(locale,"高级访问工具…","Advanced access tools…")} } else { {console_text(locale,"高级访问信息…","Advanced access information…")} }
                }
            }
            if advanced_open() {
                ConsoleOverlay { wide: true, title: if can_write { console_text(locale,"高级访问工具","Advanced access tools") } else { console_text(locale,"高级访问信息","Advanced access information") }, on_close: move |()| advanced_open.set(false),
                    div { class: "advanced-drawer-intro",
                        strong {
                            if can_write { {console_text(locale,"这里直接操作底层访问规则","These tools operate on the underlying access-rule model")} }
                            else { {console_text(locale,"这里以只读方式查看底层访问规则","Review the underlying access-rule model in read-only mode")} }
                        }
                        p { class:"muted", {console_text(locale,"已有高级 Allow / Deny、优先级或复杂选择器时，不会用简化结果静默覆盖。","Existing advanced Allow / Deny, priorities, or complex selectors are never silently replaced by the simplified view.")} }
                    }
                    section { class: if show_action_panel { "resource-workspace support-workspace" } else { "resource-workspace resource-workspace--read-only support-workspace" },
                        div { class: "resource-list-column",
                            section { class: "card",
                                h2 { {console_message(locale, "ordered-policy")} }
                                p { {console_message(locale, "policy-help")} }
                                ResourceTable { title: console_message(locale, "policy-document"), resources: snapshot.resources, next_cursor: None, locale }
                            }
                        }
                        if show_action_panel {
                            aside { class: "resource-action-column", aria_label: console_message(locale, "resource-actions"),
                                {action_panel}
                            }
                        }
                        div { class: "resource-extras-column",
                            {resource_extras}
                        }
                    }
                }
            }
        },
        ConsoleRoute::JoinTickets => rsx! {
            ConsoleDevicesPanel {
                mesh_name:snapshot.mesh_name.clone(), on_add:move |()| enrollment_open.set(true), on_advanced: move |()| advanced_open.set(true), on_groups: move |()| groups_open.set(true),
                requested_resource:String::new(), relay_filter:None, mesh:snapshot.mesh_id.clone(), locale,
                csrf:snapshot.csrf_token.clone(), can_write, can_renew:snapshot.has_capability("trust_manage"), initial:vec![],
            }
            if enrollment_open() {
                ConsoleOverlay { wizard:true, title:console_text(locale,"添加设备","Add device"), wizard_label:console_text(locale,"引导操作","Guided setup").to_owned(), on_close:move |()| enrollment_open.set(false),
                    ConsoleInvitation { requested_resource, mesh:snapshot.mesh_id.clone(), locale, csrf:snapshot.csrf_token.clone(), can_write, on_cancel:move |()| enrollment_open.set(false) }
                }
            }
            if groups_open() {
                ConsoleOverlay { title:console_text(locale,"设备组","Device groups"), on_close:move |()| groups_open.set(false),
                    CollectionPanel { mesh:snapshot.mesh_id.clone(), csrf:snapshot.csrf_token.clone(), can_write, locale, ready:browser_ready(), devices_only:true }
                }
            }
            {resource_extras}
            details{class:"card advanced-tools",open:advanced_open(),summary{{console_text(locale,"邀请记录与高级选项","Invitation history and advanced options")}}{action_panel}
                if !enrollment_open() {
                    JoinApplicationPanel { mesh:snapshot.mesh_id.clone(), csrf:snapshot.csrf_token.clone(), can_write, locale, ready:browser_ready() }
                }
                ResourceTable{title:console_message(locale,"join-tickets"),resources:snapshot.resources,next_cursor:snapshot.next_cursor,locale}
            }
        },
        ConsoleRoute::Audit => {
            rsx! {ConsoleActivityPanel{key:"{snapshot.mesh_id}",mesh:snapshot.mesh_id,locale}}
        }
        family => rsx! {
            ConsoleInfrastructureInventory{route:family,resources:snapshot.resources,locale}
            if show_action_panel {details{class:"card advanced-tools",summary{{console_text(locale,"配置与凭据操作","Configuration and credential operations")}}{action_panel}}}
            div{class:"tool-sections",{resource_extras}}
        },
    }
}

#[component]
fn SummaryCard(title: String, value: String) -> Element {
    rsx! { article { class: "card", h2 { "{title}" } p { "{value}" } } }
}

include!("ui_topology_document.rs");
include!("console_shell.rs");
include!("console_overview.rs");
include!("console_issues.rs");

include!("console_devices.rs");
include!("console_device_detail.rs");
include!("console_device_status.rs");
include!("console_device_access.rs");
include!("console_device_list.rs");
include!("console_sharing.rs");

include!("console_sharing_wizard.rs");
include!("console_sharing_steps.rs");
include!("console_sharing_fields.rs");
include!("console_sharing_access_choices.rs");
include!("console_sharing_review.rs");

include!("console_sharing_actions.rs");
include!("console_sharing_access.rs");
include!("console_network_edit.rs");
include!("console_gateways.rs");

include!("console_access_helpers.rs");
include!("console_access.rs");
include!("console_grant_form.rs");

include!("console_renewal.rs");

include!("console_managed_grants.rs");

include!("console_invitation.rs");
include!("console_enrollment_connect.rs");
include!("console_enrollment_groups.rs");

include!("console_retire.rs");

include!("console_access_detail.rs");
include!("console_sharing_draft.rs");
include!("interactive_mutation.rs");
include!("console_errors.rs");

include!("console_networks.rs");
include!("console_network_create.rs");
include!("console_settings.rs");
include!("console_activity.rs");

include!("console_infrastructure.rs");

include!("console_context_panels.rs");
