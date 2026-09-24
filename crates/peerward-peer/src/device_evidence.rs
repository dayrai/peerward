/// Admission quarantine must not stop the authenticated control-plane recovery
/// channel. Evidence renewal runs independently of DNS/route/platform readiness.
async fn run_device_evidence<C: ControlSender>(
    relay: C,
    rotator: Arc<Mutex<CredentialRotator>>,
    wireguard: WireguardPath,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut sent: Option<(CredentialSerial, Instant)> = None;
    loop {
        tokio::select! { _=interval.tick()=>{}, _=shutdown.changed()=>return }
        if *shutdown.borrow() {
            return;
        }
        let serial = rotator.lock().await.current.serial;
        if sent.is_some_and(|(previous, at)| {
            previous == serial && at.elapsed() < Duration::from_mins(5)
        }) {
            continue;
        }
        let operation = peerward_management::PeerOperation::DeviceEvidence {
            evidence: peerward_management::DeviceEvidence::current(
                peerward_management::DevicePlatform::Linux,
            ),
        };
        let result = tokio::select! {
            result=send_management_operation(&relay,&rotator,&wireguard,operation)=>result,
            _=shutdown.changed()=>return,
        };
        if result.is_ok() {
            sent = Some((serial, Instant::now()));
        }
    }
}
