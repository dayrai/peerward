#[cfg(any(test, target_arch = "wasm32"))]
fn invitation_lifecycle(form: &serde_json::Map<String, Value>) -> Result<Value, ConsoleApiError> {
    match optional_form_string(form, "device_lifecycle")
        .as_deref()
        .unwrap_or("long_lived")
    {
        "long_lived" => Ok(json!({"kind":"long_lived"})),
        "ephemeral" => Ok(json!({"kind":"ephemeral"})),
        "expiring" => {
            let format = time::format_description::parse_borrowed::<2>(
                "[year]-[month]-[day]T[hour]:[minute]",
            )
            .map_err(|_| ConsoleApiError::InvalidResponse)?;
            let text = form_string(form, "device_deadline")?;
            let until = time::PrimitiveDateTime::parse(&text, &format)
                .map_err(|_| ConsoleApiError::InvalidResponse)?
                .assume_utc()
                .unix_timestamp();
            let valid_until = u64::try_from(until).map_err(|_| ConsoleApiError::InvalidResponse)?;
            Ok(json!({"kind":"expiring","valid_until":valid_until}))
        }
        _ => Err(ConsoleApiError::InvalidResponse),
    }
}
