use peerward_peer_core::{
    PlatformProtocolError, PlatformRequestBroker, PlatformRequestKind, RuntimeEvent,
    RuntimeHealthFingerprint, RuntimeOrchestrator, RuntimeSchedule, RuntimeScheduler, RuntimeView,
};

const RUNTIME_RECORD_VERSION: u8 = 1;

static NEXT_RUNTIME_HANDLE: AtomicI64 = AtomicI64::new(1);
struct AndroidRuntime {
    lifecycle: RuntimeOrchestrator,
    platform: PlatformRequestBroker,
    scheduler: RuntimeScheduler,
}

static RUNTIMES: OnceLock<Mutex<HashMap<i64, AndroidRuntime>>> = OnceLock::new();

fn runtimes() -> &'static Mutex<HashMap<i64, AndroidRuntime>> {
    RUNTIMES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn platform_kind(kind: jint) -> Result<PlatformRequestKind, MobileError> {
    match kind {
        1 => Ok(PlatformRequestKind::VpnPermission),
        2 => Ok(PlatformRequestKind::OpenTun),
        3 => Ok(PlatformRequestKind::ProtectedTcpSocket),
        4 => Ok(PlatformRequestKind::ProtectedUdpSocket),
        5 => Ok(PlatformRequestKind::KeystoreOperation),
        6 => Ok(PlatformRequestKind::AtomicPersistence),
        7 => Ok(PlatformRequestKind::AcquireUnderlay),
        8 => Ok(PlatformRequestKind::ExportDocument),
        9 => Ok(PlatformRequestKind::CloseRuntimeResources),
        _ => Err(MobileError::InvalidInput),
    }
}

fn encode_runtime(view: RuntimeView) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(25);
    bytes.push(RUNTIME_RECORD_VERSION);
    bytes.extend_from_slice(&view.sequence.to_be_bytes());
    bytes.push(view.phase as u8);
    let flags = u8::from(view.rust_runtime_running)
        | (u8::from(view.tun_open) << 1)
        | (u8::from(view.packet_pump_running) << 2)
        | (u8::from(view.primary_relay_authenticated) << 3)
        | (u8::from(view.signed_state_complete) << 4);
    bytes.push(flags);
    bytes.extend_from_slice(&view.standby_relay_count.to_be_bytes());
    bytes.extend_from_slice(&view.direct_path_count.to_be_bytes());
    bytes.extend_from_slice(&view.signed_state_revision.to_be_bytes());
    bytes
}

/// Projects the shared lifecycle into bounded, privacy-safe diagnostic JSON.
/// The optional input is a stable platform code, never an exception message.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRuntimeCoordinator_nativeDiagnostics(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    observed_at: jlong,
    error_code: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        if observed_at < 0 || environment.get_array_length(&error_code).map_err(|_| MobileError::InvalidInput)? > 128 {
            return Err(MobileError::InvalidInput);
        }
        let bytes = java_bytes(&environment, &error_code)?;
        let error = match std::str::from_utf8(&bytes).map_err(|_| MobileError::InvalidInput)? {
            "" => None,
            "vpn_permission_denied" => Some(peerward_types::DiagnosticCode::VpnPermissionRequired),
            "authentication_failed" => Some(peerward_types::DiagnosticCode::AuthenticationFailed),
            "policy_denied" => Some(peerward_types::DiagnosticCode::PolicyDenied),
            "dns_degraded" => Some(peerward_types::DiagnosticCode::DnsDegraded),
            "target_unreachable" => Some(peerward_types::DiagnosticCode::TargetUnreachable),
            "relay_reconnecting" => Some(peerward_types::DiagnosticCode::RelayUnavailable),
            "signed_state_incomplete" => Some(peerward_types::DiagnosticCode::SignedStateIncomplete),
            "underlay_unavailable" => Some(peerward_types::DiagnosticCode::UnderlayUnavailable),
            _ => Some(peerward_types::DiagnosticCode::RuntimeFailed),
        };
        let view = runtimes().lock().map_err(|_| MobileError::InvalidState)?
            .get(&handle).ok_or(MobileError::InvalidState)?.lifecycle.view();
        serde_json::to_vec(&view.diagnostics(u64::try_from(observed_at).map_err(|_| MobileError::InvalidInput)?, error))
            .map_err(|_| MobileError::InvalidState)
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => { fail(&mut environment, &error); std::ptr::null_mut() }
    }
}

fn runtime_event(
    event: jint,
    signed_complete: jboolean,
    signed_revision: jlong,
    primary_authenticated: jboolean,
    standby_count: jint,
    direct_count: jint,
) -> Result<RuntimeEvent, MobileError> {
    Ok(match event {
        0 => RuntimeEvent::Reset,
        1 => RuntimeEvent::PermissionRequired,
        2 => RuntimeEvent::StartRequested,
        3 => RuntimeEvent::TunOpened,
        4 => RuntimeEvent::Connecting,
        5 => {
            if signed_revision < 0
                || !(0..=u16::MAX.into()).contains(&standby_count)
                || direct_count < 0
            {
                return Err(MobileError::InvalidInput);
            }
            RuntimeEvent::TransportObserved {
                primary_relay_authenticated: primary_authenticated != 0,
                standby_relay_count: u16::try_from(standby_count)
                    .map_err(|_| MobileError::InvalidInput)?,
                direct_path_count: u32::try_from(direct_count)
                    .map_err(|_| MobileError::InvalidInput)?,
                signed_state_complete: signed_complete != 0,
                signed_state_revision: u64::try_from(signed_revision)
                    .map_err(|_| MobileError::InvalidInput)?,
            }
        }
        6 => RuntimeEvent::UnderlayLost,
        7 => RuntimeEvent::TransportLost,
        8 => RuntimeEvent::StopRequested,
        9 => RuntimeEvent::Stopped,
        10 => RuntimeEvent::Failed,
        11 => RuntimeEvent::UnderlayRestored,
        _ => return Err(MobileError::InvalidInput),
    })
}

/// Creates an isolated lifecycle state machine. It owns no descriptor or key material.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRuntimeCoordinator_nativeCreate(
    _environment: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jlong {
    insert_jni_handle(
        runtimes(),
        &NEXT_RUNTIME_HANDLE,
        AndroidRuntime {
            lifecycle: RuntimeOrchestrator::default(),
            platform: PlatformRequestBroker::new(64).expect("fixed non-zero capacity"),
            scheduler: RuntimeScheduler::default(),
        },
        MAX_JNI_HANDLES,
    )
    .unwrap_or(0)
}

/// Applies one bounded platform observation and returns the authoritative lifecycle record.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRuntimeCoordinator_nativeTransition(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    event: jint,
    signed_complete: jboolean,
    signed_revision: jlong,
    primary_authenticated: jboolean,
    standby_count: jint,
    direct_count: jint,
) -> jbyteArray {
    let result = (|| {
        let event = runtime_event(
            event,
            signed_complete,
            signed_revision,
            primary_authenticated,
            standby_count,
            direct_count,
        )?;
        let mut values = runtimes().lock().map_err(|_| MobileError::InvalidState)?;
        let runtime = values.get_mut(&handle).ok_or(MobileError::InvalidState)?;
        if matches!(
            event,
            RuntimeEvent::Reset | RuntimeEvent::UnderlayLost | RuntimeEvent::Stopped
        ) {
            runtime
                .platform
                .advance_generation()
                .map_err(|_| MobileError::InvalidState)?;
        }
        if matches!(
            event,
            RuntimeEvent::Reset
                | RuntimeEvent::StartRequested
                | RuntimeEvent::UnderlayLost
                | RuntimeEvent::UnderlayRestored
                | RuntimeEvent::TransportLost
                | RuntimeEvent::Stopped
                | RuntimeEvent::Failed
        ) {
            runtime.scheduler = RuntimeScheduler::default();
        }
        Ok(encode_runtime(runtime.lifecycle.transition(event)))
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

fn encode_schedule(schedule: RuntimeSchedule) -> Vec<u8> {
    let flags = u8::from(schedule.observe_status)
        | (u8::from(schedule.send_keepalive) << 1)
        | (u8::from(schedule.report_health) << 2);
    let mut bytes = Vec::with_capacity(10);
    bytes.push(RUNTIME_RECORD_VERSION);
    bytes.push(flags);
    bytes.extend_from_slice(&schedule.next_poll_millis.to_be_bytes());
    bytes
}

/// Returns Rust-owned observation, keepalive, and encrypted health-report deadlines.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRuntimeCoordinator_nativeSchedule(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    now_millis: jlong,
    signed_complete: jboolean,
    signed_revision: jlong,
    primary_authenticated: jboolean,
    standby_count: jint,
    direct_count: jint,
) -> jbyteArray {
    let result = (|| {
        if now_millis < 0
            || signed_revision < 0
            || !(0..=u16::MAX.into()).contains(&standby_count)
            || direct_count < 0
        {
            return Err(MobileError::InvalidInput);
        }
        let health = RuntimeHealthFingerprint {
            state_generation: 0,
            primary_relay_authenticated: primary_authenticated != 0,
            standby_relay_count: u16::try_from(standby_count)
                .map_err(|_| MobileError::InvalidInput)?,
            direct_path_count: u32::try_from(direct_count)
                .map_err(|_| MobileError::InvalidInput)?,
            signed_state_complete: signed_complete != 0,
            signed_state_revision: u64::try_from(signed_revision)
                .map_err(|_| MobileError::InvalidInput)?,
            degraded_reason_mask: u32::from(signed_complete == 0),
        };
        if !health.signed_state_complete && health.signed_state_revision != 0 {
            return Err(MobileError::InvalidInput);
        }
        let mut values = runtimes().lock().map_err(|_| MobileError::InvalidState)?;
        let runtime = values.get_mut(&handle).ok_or(MobileError::InvalidState)?;
        Ok(encode_schedule(runtime.scheduler.poll(
            u64::try_from(now_millis).map_err(|_| MobileError::InvalidInput)?,
            health,
        )))
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

/// Emits one opaque request ID/generation/kind tuple for an Android system operation.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRuntimeCoordinator_nativePlatformRequest(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    kind: jint,
) -> jbyteArray {
    let result = (|| {
        let kind = platform_kind(kind)?;
        let mut values = runtimes().lock().map_err(|_| MobileError::InvalidState)?;
        let runtime = values.get_mut(&handle).ok_or(MobileError::InvalidState)?;
        let request = runtime
            .platform
            .issue(kind)
            .map_err(|_| MobileError::InvalidState)?;
        let mut bytes = Vec::with_capacity(17);
        bytes.extend_from_slice(&request.request_id.to_be_bytes());
        bytes.extend_from_slice(&request.generation.to_be_bytes());
        bytes.push(request.kind as u8);
        Ok(bytes)
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

/// Completes one exact request once. Delayed or duplicate results return false and remain rejected.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRuntimeCoordinator_nativePlatformResult(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_id: jlong,
    generation: jlong,
    _success: jboolean,
) -> jboolean {
    let result = (|| {
        if request_id <= 0 || generation <= 0 {
            return Err(MobileError::InvalidInput);
        }
        let mut values = runtimes().lock().map_err(|_| MobileError::InvalidState)?;
        let runtime = values.get_mut(&handle).ok_or(MobileError::InvalidState)?;
        match runtime.platform.complete(
                u64::try_from(request_id).map_err(|_| MobileError::InvalidInput)?,
                u64::try_from(generation).map_err(|_| MobileError::InvalidInput)?,
            ) {
            Ok(_) => Ok(true),
            Err(PlatformProtocolError::Stale) => Ok(false),
            Err(_) => Err(MobileError::InvalidState),
        }
    })();
    match result {
        Ok(accepted) => jboolean::from(accepted),
        Err(error) => {
            fail(&mut environment, &error);
            0
        }
    }
}

/// Drops one lifecycle handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRuntimeCoordinator_nativeClose(
    _environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    if let Ok(mut values) = runtimes().lock() {
        values.remove(&handle);
    }
}

#[cfg(test)]
mod runtime_jni_tests {
    use super::*;

    #[test]
    fn fixed_record_round_trips_all_privacy_safe_fields() {
        let mut runtime = RuntimeOrchestrator::default();
        runtime.transition(RuntimeEvent::StartRequested);
        runtime.transition(RuntimeEvent::TunOpened);
        let encoded = encode_runtime(runtime.transition(RuntimeEvent::TransportObserved {
            primary_relay_authenticated: true,
            standby_relay_count: 2,
            direct_path_count: 3,
            signed_state_complete: true,
            signed_state_revision: 9,
        }));
        assert_eq!(encoded.len(), 25);
        assert_eq!(encoded[0], RUNTIME_RECORD_VERSION);
        assert_eq!(encoded[9], 4);
        assert_eq!(encoded[10], 0b1_1111);
        assert_eq!(&encoded[11..13], &2_u16.to_be_bytes());
        assert_eq!(&encoded[13..17], &3_u32.to_be_bytes());
        assert_eq!(&encoded[17..25], &9_u64.to_be_bytes());
    }
}
