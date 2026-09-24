impl PeerObservability {
    /// Records a mapping discovery or renewal without labeling a gateway or endpoint.
    pub fn record_gateway_mapping(&self, success: bool) {
        let metric = if success {
            &self.metrics.gateway_mapping_successes
        } else {
            &self.metrics.gateway_mapping_failures
        };
        metric.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a PCP/NAT-PMP epoch regression without exposing gateway identity.
    pub fn record_gateway_restart(&self) {
        self.metrics
            .gateway_restarts
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Records whether one rate-limited symmetric-NAT prediction round was stable.
    pub fn record_nat_prediction(&self, stable: bool) {
        let metric = if stable {
            &self.metrics.nat_prediction_successes
        } else {
            &self.metrics.nat_prediction_failures
        };
        metric.fetch_add(1, Ordering::Relaxed);
    }
}
