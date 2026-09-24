fn enrollment_string(
    environment: &mut JNIEnv<'_>,
    value: &JString<'_>,
) -> Result<String, MobileError> {
    let value: String = environment
        .get_string(value)
        .map_err(|_| MobileError::InvalidInput)?
        .into();
    if value.len() > 4096 {
        return Err(MobileError::InvalidInput);
    }
    Ok(value)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeEnrollment_nativePrepare(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    claim_url: JString<'_>,
    identity: JByteArray<'_>,
    session: JByteArray<'_>,
    wireguard: JByteArray<'_>,
    client_version: JString<'_>,
    nonce: JByteArray<'_>,
    device_name: JString<'_>,
    device_model: JString<'_>,
    platform_version: JString<'_>,
) -> jbyteArray {
    let result = (|| {
        let claim_url = Zeroizing::new(enrollment_string(&mut environment, &claim_url)?);
        crate::prepare_mobile_enrollment(
            &claim_url,
            fixed(java_bytes(&environment, &identity)?)?,
            fixed(java_bytes(&environment, &session)?)?,
            fixed(java_bytes(&environment, &wireguard)?)?,
            enrollment_string(&mut environment, &client_version)?,
            java_bytes(&environment, &nonce)?,
            enrollment_string(&mut environment, &device_name)?,
            enrollment_string(&mut environment, &device_model)?,
            enrollment_string(&mut environment, &platform_version)?,
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeEnrollment_nativeTranscript(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    draft: JByteArray<'_>,
) -> jbyteArray {
    let result = java_bytes(&environment, &draft)
        .and_then(|draft| crate::mobile_enrollment_transcript(&draft));
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeEnrollment_nativeComplete(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    draft: JByteArray<'_>,
    signature: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        crate::complete_mobile_enrollment(
            &java_bytes(&environment, &draft)?,
            fixed(java_bytes(&environment, &signature)?)?,
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeEnrollment_nativeVerifyResponse(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    response: JByteArray<'_>,
    root_fingerprint: JByteArray<'_>,
    identity: JByteArray<'_>,
    session: JByteArray<'_>,
    wireguard: JByteArray<'_>,
    now: jlong,
) -> jbyteArray {
    let result = (|| {
        if now < 0 {
            return Err(MobileError::InvalidInput);
        }
        let response = Zeroizing::new(java_bytes(&environment, &response)?);
        crate::verify_mobile_join_response(
            &response,
            fixed(java_bytes(&environment, &root_fingerprint)?)?,
            fixed(java_bytes(&environment, &identity)?)?,
            fixed(java_bytes(&environment, &session)?)?,
            fixed(java_bytes(&environment, &wireguard)?)?,
            UnixTime(u64::try_from(now).map_err(|_| MobileError::InvalidInput)?),
        )
        .map(Zeroizing::new)
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(
            MobileError::Credential(peerward_credentials::CredentialError::OutsideValidity)
            | MobileError::EnrollmentCredential(
                _,
                peerward_credentials::CredentialError::OutsideValidity,
            ),
        ) => {
            let _ = environment.throw_new(
                "io/github/peerward/peerward/nativecore/PeerwardNativeException",
                "enrollment_credential_outside_validity",
            );
            std::ptr::null_mut()
        }
        Err(MobileError::Credential(error)) => {
            // CredentialError variants contain no key, URL or received bytes.
            let code = format!("enrollment_credential_{error:?}").to_ascii_lowercase();
            let _ = environment.throw_new(
                "io/github/peerward/peerward/nativecore/PeerwardNativeException",
                code,
            );
            std::ptr::null_mut()
        }
        Err(MobileError::EnrollmentCredential(stage, error)) => {
            let code = format!("enrollment_credential_{stage}_{error:?}").to_ascii_lowercase();
            let _ = environment.throw_new(
                "io/github/peerward/peerward/nativecore/PeerwardNativeException",
                code,
            );
            std::ptr::null_mut()
        }
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}
