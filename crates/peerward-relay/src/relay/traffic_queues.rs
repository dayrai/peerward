#[derive(Default)]
struct QueueTotals {
    messages: u64,
    encoded_bytes: u64,
    backbone_pending: u64,
    audit_pending: u64,
}
impl QueueTotals {
    fn metrics(&self) -> String {
        use std::fmt::Write as _;
        let mut text = String::new();
        for (name, help, value) in [
            (
                "peerward_relay_router_queued_messages",
                "Opaque/control envelopes currently waiting in bounded Peer queues.",
                self.messages,
            ),
            (
                "peerward_relay_router_queued_encoded_bytes",
                "Encoded envelope bytes in Peer queues; excludes allocator/carrier overhead.",
                self.encoded_bytes,
            ),
            (
                "peerward_relay_backbone_pending_slots",
                "Reserved or queued backbone channel slots; excludes an item currently being sent.",
                self.backbone_pending,
            ),
            (
                "peerward_relay_audit_pending_slots",
                "Reserved or queued audit channel slots; excludes an item currently persisting.",
                self.audit_pending,
            ),
        ] {
            let _ = write!(
                text,
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n"
            );
        }
        text
    }
}
async fn queue_totals(runtimes: &[Arc<RelayShared>]) -> QueueTotals {
    let mut result = QueueTotals::default();
    // Clone the registry before calling this function; never hold its write
    // exclusion while awaiting a runtime's router/backbone lock.
    for shared in runtimes {
        let (messages, bytes) = shared.router.lock().await.queued_usage();
        result.messages = result.messages.saturating_add(messages);
        result.encoded_bytes = result.encoded_bytes.saturating_add(bytes);
        for sender in shared.backbones.lock().await.values() {
            result.backbone_pending = result.backbone_pending.saturating_add(
                u64::try_from(sender.max_capacity().saturating_sub(sender.capacity()))
                    .unwrap_or(u64::MAX),
            );
        }
        result.audit_pending = result.audit_pending.saturating_add(
            u64::try_from(
                shared
                    .audit_sender
                    .max_capacity()
                    .saturating_sub(shared.audit_sender.capacity()),
            )
            .unwrap_or(u64::MAX),
        );
    }
    result
}
