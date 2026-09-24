#[component]
fn ResourceTable(
    title: String,
    resources: Vec<ResourceSummary>,
    next_cursor: Option<String>,
    locale: Locale,
) -> Element {
    rsx! {
        section { class: "card",
            h2 { "{title}" }
            if resources.is_empty() {
                div { class: "empty", role: "status", {console_message(locale, "no-resources")} }
            } else {
                table {
                    caption { class: "muted", {format!("{title} {}", console_message(locale, "visible-caption"))} }
                    thead { tr { th { scope: "col", {console_message(locale, "name")} } th { scope: "col", {console_message(locale, "identifier")} } th { scope: "col", {console_message(locale, "state")} } } }
                    tbody {
                        for resource in resources {
                            tr {
                                td { "{resource.name}" }
                                td {
                                    code { "{resource.id}" }
                                    CopyValue { value: resource.id.clone(), locale }
                                }
                                td {
                                    dl { class: "resource-details",
                                        for (key, value) in resource.details {
                                            div { class: "resource-detail",
                                                dt { "{key}" }
                                                dd {
                                                    if key.ends_with("_at") && value.is_string() {
                                                        LocalDateTime { value: display_detail(&value), locale }
                                                    } else {
                                                        code { {display_detail(&value)} }
                                                    }
                                                    if is_copyable_detail(&key, &value) {
                                                        CopyValue { value: display_detail(&value), locale }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if let Some(cursor) = next_cursor {
                a { href: "?cursor={cursor}", rel: "next", {console_message(locale, "next-page")} }
            }
        }
    }
}

#[component]
fn LocalDateTime(value: String, locale: Locale) -> Element {
    let machine_value = value.clone();
    let mut displayed = use_signal(|| value.clone());
    use_effect(move || {
        #[cfg(target_arch = "wasm32")]
        {
            let milliseconds = js_sys::Date::parse(&value);
            if milliseconds.is_finite() {
                let date = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(milliseconds));
                let formatted = date
                    .to_locale_string(locale.tag(), &wasm_bindgen::JsValue::UNDEFINED)
                    .as_string();
                if let Some(formatted) = formatted {
                    displayed.set(formatted);
                }
            }
        }
        #[cfg(not(target_arch = "wasm32"))]
        let _ = (&value, locale, &mut displayed);
    });
    rsx! {
        time { datetime: "{machine_value}", title: "{machine_value}", "{displayed}" }
    }
}

include!("peer_details.rs");
