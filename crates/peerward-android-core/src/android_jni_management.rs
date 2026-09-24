/// Returns a bounded configuration receipt transcript for the wrapped Ed25519 identity to sign.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeManagementTranscript(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    now: jlong,
) -> jbyteArray {
    let result = (|| {
        if now < 0 {
            return Err(MobileError::InvalidInput);
        }
        let mut values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        let entry = values.get_mut(&handle).ok_or(MobileError::InvalidState)?;
        entry.session.management_transcript(UnixTime(
            u64::try_from(now).map_err(|_| MobileError::InvalidInput)?,
        ))
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

/// Verifies the wrapped-identity signature and emits one device-signed core application receipt.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeCompleteManagement(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    signature: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let signature = fixed::<64>(java_bytes(&environment, &signature)?)?;
        let mut values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        let entry = values.get_mut(&handle).ok_or(MobileError::InvalidState)?;
        entry.session.complete_management(signature)
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}
