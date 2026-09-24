fn display_detail(value: &Value) -> String {
    match value {
        Value::Null => "—".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(values) => values.iter().map(display_detail).collect::<Vec<_>>().join(", "),
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| format!("{key}: {}", display_detail(value)))
            .collect::<Vec<_>>()
            .join(" · "),
    }
}

fn is_copyable_detail(key: &str, value: &Value) -> bool {
    value.is_string()
        && ["id", "uuid", "key", "serial", "certificate"]
            .iter()
            .any(|suffix| key.ends_with(suffix))
}

#[component]
fn CopyValue(value: String, locale: Locale) -> Element {
    let label = format!("{} {value}", console_message(locale, "copy-value"));
    rsx! {
        button {
            class: "copy-value",
            r#type: "button",
            aria_label: "{label}",
            title: console_message(locale, "copy"),
            "data-copy-value": value,
            "data-copy-ready": console_message(locale, "copy"),
            "data-copy-done": console_text(locale, "已复制", "Copied"),
            "data-copy-error": console_text(locale, "复制失败，请选择文字手动复制", "Copy failed; select the text to copy manually"),
            span { class: "copy-icon", aria_hidden: "true",
                dangerous_inner_html: include_str!("../assets/icons/copy.svg"),
            },
            span { class: "copy-done-icon", aria_hidden: "true",
                dangerous_inner_html: include_str!("../assets/icons/check-lg.svg"),
            }
            span { class: "sr-only copy-feedback", role: "status", aria_live: "polite" }
        }
    }
}
