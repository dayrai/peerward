/// Stages a replacement, or builds a temporary candidate profile for crash recovery.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeProfileCodec_nativeRotationRecovery(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    blob: JByteArray<'_>,
    credential: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let blob = Zeroizing::new(java_bytes(&environment, &blob)?);
        let credential = Zeroizing::new(java_bytes(&environment, &credential)?);
        crate::mobile_rotation_recovery(&blob, &credential).map(Zeroizing::new)
    })();
    match result {
        Ok(blob) => output(&environment, &blob),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

/// Converts a Kotlin materialized profile into the canonical Rust-owned durable blob.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeProfileCodec_nativeEncode(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    json: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let json = Zeroizing::new(java_bytes(&environment, &json)?);
        crate::encode_mobile_profile(&json).map(Zeroizing::new)
    })();
    match result {
        Ok(blob) => output(&environment, &blob),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

/// Validates and materializes one canonical durable profile blob for Android runtime use.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeProfileCodec_nativeDecode(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    blob: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let blob = Zeroizing::new(java_bytes(&environment, &blob)?);
        crate::decode_mobile_profile(&blob).map(Zeroizing::new)
    })();
    match result {
        Ok(json) => output(&environment, &json),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

fn java_string(environment: &mut JNIEnv<'_>, value: &JString<'_>) -> Result<String, MobileError> {
    let value: String = environment
        .get_string(value)
        .map_err(|_| MobileError::InvalidInput)?
        .into();
    if value.is_empty() || value.len() > 128 {
        return Err(MobileError::InvalidInput);
    }
    Ok(value)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeProfileCodec_nativeRotationPlan(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    blob: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let blob = Zeroizing::new(java_bytes(&environment, &blob)?);
        let plan = crate::plan_mobile_rotation(&blob)?;
        let key = plan.key_id.as_bytes();
        let mut output = Vec::with_capacity(
            23 + key.len()
                + plan.staged_blob.as_ref().map_or(0, Vec::len)
                + usize::from(plan.expected_identity.is_some()) * 96,
        );
        output.push(2);
        output.push(
            u8::from(plan.staged_blob.is_some())
                | (u8::from(plan.expected_identity.is_some()) << 1),
        );
        output.extend_from_slice(&plan.request_id);
        output.push(u8::try_from(key.len()).map_err(|_| MobileError::InvalidState)?);
        output.extend_from_slice(key);
        if let (Some(identity), Some(noise), Some(wireguard)) = (
            plan.expected_identity,
            plan.expected_noise,
            plan.expected_wireguard,
        ) {
            output.extend_from_slice(&identity);
            output.extend_from_slice(&noise);
            output.extend_from_slice(&wireguard);
        }
        let staged = Zeroizing::new(plan.staged_blob.unwrap_or_default());
        output.extend_from_slice(
            &u32::try_from(staged.len())
                .map_err(|_| MobileError::InvalidState)?
                .to_be_bytes(),
        );
        output.extend_from_slice(&staged);
        Ok(Zeroizing::new(output))
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
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeProfileCodec_nativeInstallRotationPublics(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    blob: JByteArray<'_>,
    request_id: JByteArray<'_>,
    key_id: JString<'_>,
    identity: JByteArray<'_>,
    noise: JByteArray<'_>,
    wireguard: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let blob = Zeroizing::new(java_bytes(&environment, &blob)?);
        crate::install_mobile_rotation_publics(
            &blob,
            fixed(java_bytes(&environment, &request_id)?)?,
            &java_string(&mut environment, &key_id)?,
            fixed(java_bytes(&environment, &identity)?)?,
            fixed(java_bytes(&environment, &noise)?)?,
            fixed(java_bytes(&environment, &wireguard)?)?,
        )
        .map(Zeroizing::new)
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
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeProfileCodec_nativeCommitRotation(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    blob: JByteArray<'_>,
    credential: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let blob = Zeroizing::new(java_bytes(&environment, &blob)?);
        let credential = Zeroizing::new(java_bytes(&environment, &credential)?);
        crate::commit_mobile_rotation(&blob, &credential).map(Zeroizing::new)
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
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeProfileCodec_nativeCleanPreviousKey(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    blob: JByteArray<'_>,
    active_key_id: JString<'_>,
) -> jbyteArray {
    let result = (|| {
        let blob = Zeroizing::new(java_bytes(&environment, &blob)?);
        let cleanup = crate::clean_mobile_previous_key(
            &blob,
            &java_string(&mut environment, &active_key_id)?,
        )?;
        let mut output = vec![2, u8::from(cleanup.is_some())];
        if let Some(cleanup) = cleanup {
            output.push(u8::try_from(cleanup.key_id.len()).map_err(|_| MobileError::InvalidState)?);
            output.extend_from_slice(cleanup.key_id.as_bytes());
            output.extend_from_slice(
                &u32::try_from(cleanup.cleaned_blob.len())
                    .map_err(|_| MobileError::InvalidState)?
                    .to_be_bytes(),
            );
            let cleaned = Zeroizing::new(cleanup.cleaned_blob);
            output.extend_from_slice(&cleaned);
        }
        Ok(Zeroizing::new(output))
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
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeProfileCodec_nativeDecodeRotationReplacement(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    update: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let update = Zeroizing::new(java_bytes(&environment, &update)?);
        if update.len() < 8 {
            return Err(MobileError::InvalidInput);
        }
        let credential_length = u32::from_be_bytes(
            update[..4]
                .try_into()
                .map_err(|_| MobileError::InvalidInput)?,
        ) as usize;
        if credential_length == 0 || update.len() < 8 + credential_length {
            return Err(MobileError::InvalidInput);
        }
        let transcript_offset = 4 + credential_length;
        let transcript_length = u32::from_be_bytes(
            update[transcript_offset..transcript_offset + 4]
                .try_into()
                .map_err(|_| MobileError::InvalidInput)?,
        ) as usize;
        if transcript_length == 0 || transcript_offset + 4 + transcript_length != update.len() {
            return Err(MobileError::InvalidInput);
        }
        Ok(update)
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
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeProfileCodec_nativeInstallAuthorities(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    blob: JByteArray<'_>,
    revision: jlong,
    certificates: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        if revision <= 0 {
            return Err(MobileError::InvalidInput);
        }
        let certificates = java_bytes(&environment, &certificates)?;
        if certificates.is_empty() || certificates.len() % 144 != 0 || certificates.len() > 9 * 144
        {
            return Err(MobileError::InvalidInput);
        }
        let certificates = certificates
            .chunks_exact(144)
            .map(|certificate| {
                <[u8; 144]>::try_from(certificate).map_err(|_| MobileError::InvalidInput)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let blob = Zeroizing::new(java_bytes(&environment, &blob)?);
        crate::install_mobile_authorities(
            &blob,
            u64::try_from(revision).map_err(|_| MobileError::InvalidInput)?,
            &certificates,
        )
        .map(Zeroizing::new)
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}
