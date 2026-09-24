/// Returns the exact rotation-request transcript the active wrapped identity
/// must sign.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeRotationRequestTranscript(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_id: JByteArray<'_>,
    identity_public_key: JByteArray<'_>,
    session_public_key: JByteArray<'_>,
    wireguard_public_key: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let request_id = fixed::<16>(java_bytes(&environment, &request_id)?)?;
        let identity_public_key = fixed::<32>(java_bytes(&environment, &identity_public_key)?)?;
        let session_public_key = fixed::<32>(java_bytes(&environment, &session_public_key)?)?;
        let wireguard_public_key = fixed::<32>(java_bytes(&environment, &wireguard_public_key)?)?;
        let values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        let entry = values.get(&handle).ok_or(MobileError::InvalidState)?;
        entry.session.rotation_request_transcript(
            request_id,
            identity_public_key,
            session_public_key,
            wireguard_public_key,
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

/// Creates the canonical rotation request for a key generated and retained by
/// `AndroidKeyStore`. An empty result means the renewal window has not opened.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeRotationRequest(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_id: JByteArray<'_>,
    identity_public_key: JByteArray<'_>,
    session_public_key: JByteArray<'_>,
    wireguard_public_key: JByteArray<'_>,
    signature: JByteArray<'_>,
    now: jlong,
) -> jbyteArray {
    let result = (|| {
        if now < 0 {
            return Err(MobileError::InvalidInput);
        }
        let request_id = fixed::<16>(java_bytes(&environment, &request_id)?)?;
        let identity_public_key = fixed::<32>(java_bytes(&environment, &identity_public_key)?)?;
        let session_public_key = fixed::<32>(java_bytes(&environment, &session_public_key)?)?;
        let wireguard_public_key = fixed::<32>(java_bytes(&environment, &wireguard_public_key)?)?;
        let signature = fixed::<64>(java_bytes(&environment, &signature)?)?;
        let mut values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        let entry = values.get_mut(&handle).ok_or(MobileError::InvalidState)?;
        Ok(entry
            .session
            .rotation_request(
                request_id,
                identity_public_key,
                session_public_key,
            wireguard_public_key,
                signature,
                UnixTime(u64::try_from(now).map_err(|_| MobileError::InvalidInput)?),
            )?
            .map_or_else(Vec::new, |envelope| envelope.encode_to_vec()))
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

/// Verifies the staged identity signature and encodes the canonical
/// activation control envelope.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeRotationActivation(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    signature: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let signature = fixed::<64>(java_bytes(&environment, &signature)?)?;
        let values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        let entry = values.get(&handle).ok_or(MobileError::InvalidState)?;
        Ok(entry.session.rotation_activation(signature)?.encode_to_vec())
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}
/// Checks the Rust renewal decision before Kotlin allocates new Keystore material.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeRotationDue(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    now: jlong,
) -> jboolean {
    let result = (|| {
        let now = UnixTime(u64::try_from(now).map_err(|_| MobileError::InvalidInput)?);
        let values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        let entry = values.get(&handle).ok_or(MobileError::InvalidState)?;
        entry.session.rotation_due(now)
    })();
    match result {
        Ok(due) => jboolean::from(due),
        Err(error) => {
            fail(&mut environment, &error);
            0
        }
    }
}
