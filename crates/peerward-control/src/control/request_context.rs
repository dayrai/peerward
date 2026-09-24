async fn request_context(mut request: Request, next: Next) -> Response {
    let request_id = request
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<Uuid>().ok())
        .filter(|value| value.get_version_num() == 4)
        .unwrap_or_else(Uuid::new_v4);
    let inbound = request
        .headers()
        .get("traceparent")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| CorrelationContext::from_traceparent(request_id, value).ok());
    let fallback = inbound.map_or_else(
        || {
            let root = CorrelationContext::root(false);
            CorrelationContext { request_id, ..root }
        },
        CorrelationContext::child,
    );
    let method = request.method().clone();
    let path = request_log_path(request.uri().path());
    let span = tracing::info_span!(
        "http.server",
        request_id = %request_id,
        trace_id = tracing::field::Empty,
        span_id = tracing::field::Empty,
        http.request.method = %method,
        url.path = path,
        http.response.status_code = tracing::field::Empty,
    );
    if let Some(parent) = inbound {
        let _ = span.set_parent(open_telemetry_parent(parent));
    }
    let correlation = correlation_from_span(&span, request_id).unwrap_or(fallback);
    span.record("trace_id", hex::encode(correlation.trace_id));
    span.record("span_id", hex::encode(correlation.span_id));
    request.extensions_mut().insert(request_id);
    request.extensions_mut().insert(correlation);
    REQUEST_ID.scope(request_id, CORRELATION_CONTEXT.scope(correlation, async move {
            let started = std::time::Instant::now();
            let mut response = next.run(request).await;
            if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
                response.headers_mut().insert("x-request-id", value);
            }
            if let Ok(value) = HeaderValue::from_str(&correlation.traceparent()) {
                response.headers_mut().insert("traceparent", value);
            }
            tracing::info!(
                request_id = %request_id,
                method = %method,
                path,
                status = response.status().as_u16(),
                duration_ms = started.elapsed().as_millis(),
                "Control request completed"
            );
            tracing::Span::current().record("http.response.status_code", response.status().as_u16());
            response
        }.instrument(span))).await
}

fn open_telemetry_parent(correlation: CorrelationContext) -> OpenTelemetryContext {
    let span = OpenTelemetrySpanContext::new(
        OpenTelemetryTraceId::from_bytes(correlation.trace_id),
        OpenTelemetrySpanId::from_bytes(correlation.span_id),
        OpenTelemetryTraceFlags::new(correlation.flags),
        true,
        OpenTelemetryTraceState::default(),
    );
    OpenTelemetryContext::new().with_remote_span_context(span)
}

fn correlation_from_span(span: &tracing::Span, request_id: Uuid) -> Option<CorrelationContext> {
    let context = span.context();
    let span = context.span();
    let span_context = span.span_context();
    span_context.is_valid().then(|| {
        CorrelationContext::from_parts(
            request_id,
            span_context.trace_id().to_bytes(),
            span_context.span_id().to_bytes(),
            span_context.trace_flags().to_u8(),
        )
        .expect("OpenTelemetry emitted valid UUIDv4-associated correlation")
    })
}

fn request_log_path(path: &str) -> String {
    let ticket = path
        .strip_prefix("/api/v1/join/")
        .and_then(|value| value.strip_suffix("/claim"));
    if ticket.is_some_and(|value| !value.is_empty() && !value.contains('/')) {
        "/api/v1/join/{ticket}/claim".to_owned()
    } else {
        path.split('/')
            .map(|segment| {
                if Uuid::parse_str(segment).is_ok() {
                    "{id}"
                } else {
                    segment
                }
            })
            .collect::<Vec<_>>()
            .join("/")
    }
}
