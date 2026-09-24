/// Generates an Ed25519 identity seed in Rust and returns only its verifier
/// followed by AndroidKeyStore-wrapped ciphertext. The seed is zeroized on
/// every return path.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_crypto_NativeKeyMaterial_nativeGenerateWrappedIdentity(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    alias: JString<'_>,
) -> jbyteArray {
    let result = (|| {
        let alias: String = environment
            .get_string(&alias)
            .map_err(|_| MobileError::InvalidInput)?
            .into();
        if alias.len() > 128
            || !alias.starts_with("peerward.")
            || alias.strip_suffix(".identity-wrap").is_none()
        {
            return Err(MobileError::InvalidInput);
        }
        let generated = SigningKey::generate(&mut OsRng);
        let private = Zeroizing::new(generated.to_bytes());
        let public = generated.verifying_key().to_bytes();
        drop(generated);
        let alias = environment
            .new_string(alias)
            .map_err(|_| MobileError::KeyAgreement)?;
        let public_array = environment
            .byte_array_from_slice(&public)
            .map_err(|_| MobileError::KeyAgreement)?;
        let private_array = environment
            .byte_array_from_slice(private.as_ref())
            .map_err(|_| MobileError::KeyAgreement)?;
        let alias_object = JObject::from(alias);
        let public_object = JObject::from(public_array);
        let private_object = JObject::from(private_array);
        let wrapped = environment
            .call_static_method(
                KEY_HELPER,
                "wrapIdentityGenerated",
                "(Ljava/lang/String;[B[B)[B",
                &[
                    JValue::Object(&alias_object),
                    JValue::Object(&public_object),
                    JValue::Object(&private_object),
                ],
            )
            .map_err(|_| MobileError::KeyAgreement)?;
        let wrapped = wrapped.l().map_err(|_| MobileError::KeyAgreement)?;
        let wrapped = environment
            .convert_byte_array(JByteArray::from(wrapped))
            .map_err(|_| MobileError::KeyAgreement)?;
        if !(MIN_WRAPPED_KEY..=MAX_WRAPPED_KEY).contains(&wrapped.len()) {
            return Err(MobileError::InvalidInput);
        }
        let mut output = Vec::with_capacity(public.len() + wrapped.len());
        output.extend_from_slice(&public);
        output.extend_from_slice(&wrapped);
        Ok(output)
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

/// Signs one bounded canonical transcript with a transient Ed25519 seed and
/// verifies the supplied public-key binding before returning the signature.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_crypto_NativeKeyMaterial_nativeSignTransient(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    private: JByteArray<'_>,
    public: JByteArray<'_>,
    message: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let private = java_secret32(&environment, &private)?;
        let public = fixed::<32>(java_bytes(&environment, &public)?)?;
        let message = java_bytes(&environment, &message)?;
        if message.is_empty() || message.len() > MAX_IDENTITY_MESSAGE {
            return Err(MobileError::InvalidInput);
        }
        let signing = SigningKey::from_bytes(&private);
        if signing.verifying_key().to_bytes() != public {
            return Err(MobileError::InvalidInput);
        }
        Ok(signing.sign(&message).to_bytes())
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}
