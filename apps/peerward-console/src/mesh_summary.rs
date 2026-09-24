#[component]
fn MeshSummaryTable(
    title: String,
    resources: Vec<ResourceSummary>,
    next_cursor: Option<String>,
    locale: Locale,
) -> Element {
    rsx! {
        section { class:"card mesh-summary",
            h2 { "{title}" }
            if resources.is_empty() { p {role:"status",{console_message(locale,"no-resources")}} }
            else { table {
                caption { class:"muted", {format!("{title} {}",console_message(locale,"visible-caption"))} }
                thead { tr { th {scope:"col",{console_message(locale,"name")}} th {scope:"col",{console_message(locale,"state")}} } }
                tbody { for resource in resources { tr {
                    td { a {href:format!("/meshes?mesh={}",resource.id),"{resource.name}"}
                        p {code {{resource.details.get("address_cidr").map(display_detail).unwrap_or_default()}}}
                        p {code {{resource.details.get("secondary_cidr").map(display_detail).unwrap_or_default()}}}
                        details {summary {{console_message(locale,"technical-details")}}
                            code {"{resource.id}"} CopyValue {value:resource.id.clone(),locale}
                            dl {for (key,value) in resource.details.iter().filter(|(key,_)|["dns_suffix","lease_seconds","version"].contains(&key.as_str())) {
                                dt {"{key}"} dd {{display_detail(value)}}
                            }}
                        }
                    }
                    td {{console_message(locale,match resource.details.get("lifecycle").and_then(Value::as_str) {Some("active")=>"mesh-state-active",Some("creating")=>"mesh-state-creating",Some("deleting")=>"mesh-state-deleting",Some("deleted")=>"mesh-state-deleted",_=>"mesh-state-unknown"})}}
                }} }
            } }
            if let Some(cursor)=next_cursor {a {href:format!("/meshes?cursor={cursor}"),rel:"next",{console_message(locale,"next-page")}}}
        }
    }
}
