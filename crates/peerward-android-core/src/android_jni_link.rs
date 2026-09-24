#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeLinkReplacementDue(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    monotonic: jlong,
) -> jboolean {
    let result = (|| {
        let monotonic = u64::try_from(monotonic).map_err(|_| MobileError::InvalidInput)?;
        let values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        values
            .get(&handle)
            .ok_or(MobileError::InvalidState)?
            .session
            .link_replacement_due(monotonic)
    })();
    match result {
        Ok(due) => u8::from(due),
        Err(error) => {
            fail(&mut environment, &error);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeConfirmLink(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    frame: JByteArray<'_>,
    monotonic: jlong,
) {
    let result = (|| {
        let monotonic = u64::try_from(monotonic).map_err(|_| MobileError::InvalidInput)?;
        let frame = java_bytes(&environment, &frame)?;
        let mut values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        values
            .get_mut(&handle)
            .ok_or(MobileError::InvalidState)?
            .session
            .confirm_link_ready(&frame, monotonic)
    })();
    if let Err(error) = result {
        fail(&mut environment, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeLinkClose(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    monotonic: jlong,
) -> jbyteArray {
    let result = (|| {
        let monotonic = u64::try_from(monotonic).map_err(|_| MobileError::InvalidInput)?;
        let mut values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        let entry = values.get_mut(&handle).ok_or(MobileError::InvalidState)?;
        entry.session.encrypt(
            &Record::Control(ControlEnvelope {
                trace_context: None,
                message: Some(ControlMessage::Close(peerward_wire::GracefulClose {
                    mesh_id: entry.session.trust.mesh_id.as_bytes().to_vec(),
                    body: b"link_rekey".to_vec(),
                })),
            }),
            monotonic,
        )
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}
