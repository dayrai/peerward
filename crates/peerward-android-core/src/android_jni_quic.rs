#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelaySocket_nativeActivate(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    session_handle: jlong,
    monotonic_seconds: jlong,
) {
    let result = (|| {
        let now = u64::try_from(monotonic_seconds).map_err(|_| MobileError::InvalidInput)?;
        let socket = relay_socket(handle)?;
        let (transport, preface) = {
            let mut registry = sessions().lock().map_err(|_| MobileError::InvalidState)?;
            let session = &mut registry
                .get_mut(&session_handle)
                .ok_or(MobileError::InvalidState)?
                .session;
            let preface = peerward_wire::RelayPreface {
                mesh_id: session.trust.mesh_id,
                target: session.expected_relay.ok_or(MobileError::InvalidState)?,
                source: None,
            };
            let crate::State::Transport(transport) =
                std::mem::replace(&mut session.state, crate::State::CarrierAdmission)
            else {
                session.state = crate::State::Closed;
                return Err(MobileError::InvalidState);
            };
            (transport, preface)
        };
        // Network I/O never holds the process-wide session registry. Close or
        // Mesh deletion can retire the handle while exporter binding is pending.
        let Ok(transport) = socket.activate(transport, preface, now) else {
            socket.close();
            return Err(MobileError::InvalidState);
        };
        let mut registry = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        let Some(entry) = registry.get_mut(&session_handle) else {
            socket.close();
            return Err(MobileError::InvalidState);
        };
        if !matches!(entry.session.state, crate::State::CarrierAdmission) {
            socket.close();
            return Err(MobileError::InvalidState);
        }
        entry.session.state = crate::State::Transport(transport);
        Ok(())
    })();
    if let Err(error) = result {
        fail(&mut environment, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelaySocket_nativeAcknowledgeTerminal(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    let result = (|| {
        let socket = relay_socket(handle)?;
        let mut writer = socket
            .writer
            .lock()
            .map_err(|_| MobileError::InvalidState)?;
        write_all(&mut writer, b"PWTA")
    })();
    if let Err(error) = result {
        fail(&mut environment, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelaySocket_nativeConnect(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    let result = relay_socket(handle).and_then(|socket| {
        socket
            .connect()
            .map_err(|error| MobileError::Carrier(error.kind()))
    });
    if let Err(error) = result {
        fail(&mut environment, &error);
    }
}
