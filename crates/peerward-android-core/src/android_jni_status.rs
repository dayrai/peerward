/// Returns live native signed-state readiness as a fixed one-byte/64-bit record.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeRuntimeStatus(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jbyteArray {
    let result = (|| {
        let values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        let entry = values.get(&handle).ok_or(MobileError::InvalidState)?;
        let status = entry.session.runtime_status();
        let mut bytes = Vec::with_capacity(9);
        bytes.push(u8::from(status.signed_state_complete));
        bytes.extend_from_slice(&status.signed_revision.to_be_bytes());
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
