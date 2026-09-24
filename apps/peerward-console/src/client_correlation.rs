impl ApiClient {
    /// Sets the parent used to create a distinct child for every Control request.
    #[must_use]
    pub fn with_correlation_parent(mut self, correlation: CorrelationContext) -> Self {
        self.correlation = correlation;
        self
    }
}

fn outbound_correlation(parent: CorrelationContext) -> CorrelationContext {
    CorrelationContext {
        request_id: uuid::Uuid::new_v4(),
        ..parent.child()
    }
}

fn apply_outbound_correlation(
    request: reqwest::RequestBuilder,
    parent: CorrelationContext,
) -> reqwest::RequestBuilder {
    let context = outbound_correlation(parent);
    request
        .header("x-request-id", context.request_id.to_string())
        .header("traceparent", context.traceparent())
}

#[cfg(test)]
mod correlation_tests {
    use super::*;

    #[test]
    fn refreshes_share_a_trace_but_not_span_or_request_identity() {
        let parent = CorrelationContext::root(false);
        let first = outbound_correlation(parent);
        let second = outbound_correlation(parent);
        assert_eq!(first.trace_id, parent.trace_id);
        assert_eq!(second.trace_id, parent.trace_id);
        assert_ne!(first.span_id, parent.span_id);
        assert_ne!(first.span_id, second.span_id);
        assert_ne!(first.request_id, second.request_id);
    }
}
