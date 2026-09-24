/// Returns a bounded encrypted-audit transcript for the wrapped Ed25519 identity to sign.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeAuditTranscript(
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
        entry
            .session
            .audit_signature_transcript(UnixTime(u64::try_from(now).map_err(|_| MobileError::InvalidInput)?))
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

/// Verifies the wrapped-identity signature and emits one Relay-addressed opaque audit control.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeCompleteAudit(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    signature: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let signature = fixed::<64>(java_bytes(&environment, &signature)?)?;
        let mut values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        let entry = values.get_mut(&handle).ok_or(MobileError::InvalidState)?;
        entry.session.complete_audit(signature)
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

/// Returns the `AndroidKeyStore` signature transcript for one privacy-safe current report.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeHealthTranscript(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    now: jlong,
    sequence: jlong,
    direct_path_count: jint,
    relay_packets: jlong,
    direct_packets: jlong,
    degraded_mask: jlong,
    signed_revision: jlong,
) -> jbyteArray {
    let result = (|| {
        if [now, sequence, relay_packets, direct_packets, degraded_mask, signed_revision]
            .into_iter()
            .any(|value| value < 0)
            || direct_path_count < 0
            || degraded_mask & !0x7f != 0
        {
            return Err(MobileError::InvalidInput);
        }
        let reasons = [
            peerward_wire::RuntimeDegradedReasonV1::RelayUnavailable,
            peerward_wire::RuntimeDegradedReasonV1::SignedStateIncomplete,
            peerward_wire::RuntimeDegradedReasonV1::DirectPathUnavailable,
            peerward_wire::RuntimeDegradedReasonV1::DnsDegraded,
            peerward_wire::RuntimeDegradedReasonV1::CredentialRotation,
            peerward_wire::RuntimeDegradedReasonV1::UnderlayUnavailable,
            peerward_wire::RuntimeDegradedReasonV1::PacketPumpUnavailable,
        ]
        .into_iter()
        .enumerate()
        .filter_map(|(bit, reason)| (degraded_mask & (1_i64 << bit) != 0).then_some(reason))
        .collect();
        let health = crate::MobileRuntimeHealth {
            sequence: u64::try_from(sequence).map_err(|_| MobileError::InvalidInput)?,
            direct_path_count: u32::try_from(direct_path_count)
                .map_err(|_| MobileError::InvalidInput)?,
            relay_packets: u64::try_from(relay_packets).map_err(|_| MobileError::InvalidInput)?,
            direct_packets: u64::try_from(direct_packets)
                .map_err(|_| MobileError::InvalidInput)?,
            degraded_reasons: reasons,
            signed_revision: u64::try_from(signed_revision)
                .map_err(|_| MobileError::InvalidInput)?,
        };
        let mut values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        let entry = values.get_mut(&handle).ok_or(MobileError::InvalidState)?;
        entry.session.health_signature_transcript(
            UnixTime(u64::try_from(now).map_err(|_| MobileError::InvalidInput)?),
            &health,
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

/// Verifies the Keystore signature and emits the Relay-addressed encrypted health envelope.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeCompleteHealth(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    signature: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let signature = fixed::<64>(java_bytes(&environment, &signature)?)?;
        let mut values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        let entry = values.get_mut(&handle).ok_or(MobileError::InvalidState)?;
        entry.session.complete_health(signature)
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}
