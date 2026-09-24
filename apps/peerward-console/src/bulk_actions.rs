fn bulk_family(route: ConsoleRoute) -> Option<BulkResourceFamily> {
    match route {
        ConsoleRoute::Peers => Some(BulkResourceFamily::Peer),
        ConsoleRoute::Relays => Some(BulkResourceFamily::Relay),
        ConsoleRoute::JoinTickets => Some(BulkResourceFamily::JoinTicket),
        ConsoleRoute::Services => Some(BulkResourceFamily::Service),
        _ => None,
    }
}

fn captured_bulk_request(
    route: ConsoleRoute,
    snapshot: &ConsoleSnapshot,
    selected: &[String],
) -> Option<BulkRequest> {
    if selected.is_empty() || selected.len() > 100 {
        return None;
    }
    let items = selected
        .iter()
        .map(|id| {
            let resource = snapshot
                .resources
                .iter()
                .find(|resource| &resource.id == id)?;
            Some(BulkResourceItem {
                id: uuid::Uuid::parse_str(id).ok()?,
                version: resource.details.get("version")?.as_u64()?,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(BulkRequest {
        family: bulk_family(route)?,
        items,
    })
}

#[component]
fn BulkActions(
    route: ConsoleRoute,
    snapshot: Signal<ConsoleSnapshot>,
    loading: Signal<bool>,
    status: Signal<String>,
    locale: Locale,
) -> Element {
    let mut selected = use_signal(Vec::<String>::new);
    let mut preview = use_signal(|| None::<BulkPreviewResponse>);
    let mut captured = use_signal(|| None::<BulkRequest>);
    let mut mesh_confirmation = use_signal(String::new);
    let mut count_confirmation = use_signal(String::new);
    let expected_mesh = snapshot.read().mesh_name.clone();
    let expected_count = captured.read().as_ref().map_or(0, |body| body.items.len());
    let preview_valid = preview.read().as_ref().is_some_and(|value| value.valid);
    let invitations = route == ConsoleRoute::JoinTickets;

    rsx! {
        fieldset { class: "card bulk-actions",
            legend { {if invitations {console_text(locale,"批量取消邀请","Cancel invitations in bulk")} else {console_message(locale, "bulk-actions")}} }
            p { class: "muted", {if invitations {console_text(locale,"一次作废多张不再使用的邀请，最多选择 100 张。取消后不能再用这些邀请加入网络，不影响已加入的设备；入网申请仍需逐台核对。","Invalidate up to 100 invitations you no longer need. Cancelled invitations cannot be used to join; devices already enrolled are unaffected. Review admission requests individually.")} else {console_message(locale, "bulk-limit")}} }
            div { class: "bulk-grid",
                for resource in snapshot.read().resources.clone() {
                    label {
                        input {
                            r#type: "checkbox",
                            checked: selected.read().contains(&resource.id),
                            disabled: loading(),
                            onchange: move |event| {
                                let mut values = selected.write();
                                if event.checked() {
                                    if values.len() < 100 && !values.contains(&resource.id) {
                                        values.push(resource.id.clone());
                                    }
                                } else {
                                    values.retain(|id| id != &resource.id);
                                }
                                drop(values);
                                preview.set(None);
                                captured.set(None);
                                mesh_confirmation.set(String::new());
                                count_confirmation.set(String::new());
                            },
                        }
                        "{resource.name}"
                    }
                }
            }
            button {
                r#type: "button",
                disabled: loading() || selected.read().is_empty(),
                onclick: move |_| {
                    #[allow(unused_variables)]
                    let Some(body) = captured_bulk_request(route, &snapshot.read(), &selected.read()) else {
                        status.set(console_message(locale, "bulk-invalid-selection").into());
                        return;
                    };
                    #[cfg(target_arch = "wasm32")]
                    {
                        let api = browser_api_client();
                        let mesh = snapshot.read().mesh_id.clone();
                        loading.set(true);
                        status.set(console_message(locale, "bulk-previewing").into());
                        spawn(async move {
                            match api.preview_bulk(&mesh, &body).await {
                                Ok(result) => {
                                    captured.set(Some(body));
                                    status.set(console_message(locale, if result.valid { "bulk-preview-ready" } else { "bulk-preview-failed" }).into());
                                    preview.set(Some(result));
                                }
                                Err(error) => snapshot.write().error = Some(api_error_body(error)),
                            }
                            loading.set(false);
                        });
                    }
                },
                {if invitations {console_text(locale,"预览取消邀请","Preview invitation cancellation")} else {console_message(locale, "bulk-preview")}}
            }
            if let Some(result) = preview.read().clone() {
                ul { class: "bulk-preview", role: "status",
                    for item in result.items {
                        li { code { "{item.id}" } " · {item.current_state} · "
                            if item.ready { {console_message(locale, "ready")} }
                            else { {item.error_code.unwrap_or_else(|| "not_ready".into())} }
                        }
                    }
                }
            }
            if preview_valid {
                p { class: "risk-preview", role: "note", {if invitations {console_text(locale,"确认后，所选邀请将全部作废。如任何邀请已被使用或状态变化，本次不会取消任何邀请。","All selected invitations will be invalidated. If any invitation was used or changed, none will be cancelled.")} else {console_message(locale, "bulk-impact")}} }
                label { {console_message(locale, "confirm-mesh-name")}
                    input { value: "{mesh_confirmation}", disabled: loading(), autocomplete: "off",
                        oninput: move |event| mesh_confirmation.set(event.value()) }
                }
                label { {console_message(locale, "confirm-item-count")}
                    input { value: "{count_confirmation}", disabled: loading(), inputmode: "numeric",
                        oninput: move |event| count_confirmation.set(event.value()) }
                }
                button {
                    r#type: "button",
                    disabled: loading() || mesh_confirmation.read().as_str() != expected_mesh.as_str()
                        || count_confirmation.read().parse::<usize>().ok() != Some(expected_count),
                    onclick: move |_| {
                        #[allow(unused_variables)]
                    let Some(body) = captured.read().clone() else { return };
                        #[cfg(target_arch = "wasm32")]
                        {
                            let api = browser_api_client();
                            let mesh = snapshot.read().mesh_id.clone();
                            loading.set(true);
                            status.set(console_message(locale, "saving").into());
                            spawn(async move {
                                match api.commit_bulk(&mesh, &body).await {
                                    Ok(result) => match api.route_snapshot(route, Some(&mesh), None).await {
                                        Ok(value) => {
                                            snapshot.set(value);
                                            selected.set(Vec::new());
                                            preview.set(None);
                                            captured.set(None);
                                            mesh_confirmation.set(String::new());
                                            count_confirmation.set(String::new());
                                            status.set(format!("{}: {}", console_message(locale, "bulk-committed"), result.committed));
                                        }
                                        Err(error) => snapshot.write().error = Some(api_error_body(error)),
                                    },
                                    Err(error) => snapshot.write().error = Some(api_error_body(error)),
                                }
                                loading.set(false);
                            });
                        }
                    },
                    {if invitations {console_text(locale,"确认取消所选邀请","Cancel selected invitations")} else {console_message(locale, "bulk-commit")}}
                }
            }
        }
    }
}
