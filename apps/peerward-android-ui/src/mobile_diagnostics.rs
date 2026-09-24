fn diagnostic_time(observed_at: Option<u64>, locale: Locale) -> String {
    let Some(timestamp) = observed_at else {
        return if locale == Locale::ZhCn { "暂无记录" } else { "No observation" }.into();
    };
    #[cfg(target_arch = "wasm32")]
    {
        // Saturate at JavaScript's Date limit, preserving an explicit unknown value.
        let millis = timestamp.saturating_mul(1000).min(8_640_000_000_000_000);
        #[allow(clippy::cast_precision_loss)]
        let date = js_sys::Date::new(&wasm_bindgen::JsValue::from_f64(millis as f64));
        date.to_locale_string(locale.tag(), &wasm_bindgen::JsValue::UNDEFINED).into()
    }
    #[cfg(not(target_arch = "wasm32"))]
    { timestamp.to_string() }
}

#[component]
fn MobileDiagnostics(observations: Vec<peerward_ui::RuntimeDiagnostic>, locale: Locale) -> Element {
    rsx! {
        for observation in observations {
            article { class: "mobile-card", role: "status",
                strong { {peerward_ui::diagnostic_label(locale, observation.code)} }
                p { {peerward_ui::diagnostic_next_step(locale, observation.retry_hint)} }
                small {
                    {if locale == Locale::ZhCn { "证据时间：" } else { "Observed at: " }}
                    {diagnostic_time(observation.observed_at, locale)}
                }
            }
        }
    }
}
