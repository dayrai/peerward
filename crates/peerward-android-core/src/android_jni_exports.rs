#[allow(clippy::too_many_arguments)]
fn create(
    environment: &mut JNIEnv<'_>,
    alias: &JString<'_>,
    key_mode: jint,
    wrapped_key: &JByteArray<'_>,
    local_identity: &JByteArray<'_>,
    local_public: &JByteArray<'_>,
    remote_public: &JByteArray<'_>,
    remote_relay: &JByteArray<'_>,
    credential: &JByteArray<'_>,
    attachment: &JByteArray<'_>,
    root_public: &JByteArray<'_>,
    mesh_id: &JByteArray<'_>,
    authorities: &JByteArray<'_>,
    authority_revision: jlong,
    distribution_public: &JByteArray<'_>,
    service_public: &JByteArray<'_>,
    audit_public: &JByteArray<'_>,
    distribution_certificate: &JByteArray<'_>,
    now: jlong,
    capabilities: jlong,
    wireguard_handle: jlong,
) -> Result<i64, MobileError> {
    let alias: String = environment
        .get_string(alias)
        .map_err(|_| MobileError::InvalidInput)?
        .into();
    if alias.is_empty() || alias.len() > 128 || now < 0 || authority_revision < 0 {
        return Err(MobileError::InvalidInput);
    }
    let wrapped_key = java_bytes(environment, wrapped_key)?;
    let wrapped = match key_mode {
        DIRECT_KEY if wrapped_key.is_empty() && alias.strip_suffix(".noise").is_some() => None,
        WRAPPED_KEY
            if (MIN_WRAPPED_KEY..=MAX_WRAPPED_KEY).contains(&wrapped_key.len())
                && alias.strip_suffix(".noise-wrap").is_some() =>
        {
            Some(wrapped_key)
        }
        _ => return Err(MobileError::InvalidInput),
    };
    let local_identity = fixed(java_bytes(environment, local_identity)?)?;
    let local_public = fixed(java_bytes(environment, local_public)?)?;
    let remote_public = fixed(java_bytes(environment, remote_public)?)?;
    let attachment = fixed(java_bytes(environment, attachment)?)?;
    let root_public = fixed(java_bytes(environment, root_public)?)?;
    let distribution_public = fixed(java_bytes(environment, distribution_public)?)?;
    let service_public = fixed(java_bytes(environment, service_public)?)?;
    let audit_public = fixed(java_bytes(environment, audit_public)?)?;
    let distribution_certificate =
        DistributionCertificate::decode(&java_bytes(environment, distribution_certificate)?)?;
    let mesh_uuid = Uuid::from_slice(&java_bytes(environment, mesh_id)?)
        .map_err(|_| MobileError::InvalidInput)?;
    let mesh = MeshId::from_uuid(mesh_uuid).map_err(|_| MobileError::InvalidInput)?;
    let now = UnixTime(u64::try_from(now).map_err(|_| MobileError::InvalidInput)?);
    let root = RootPublicKey::from_bytes(&root_public)?;
    let mut credentials = TrustSet::new(root, mesh);
    let authority_bytes = java_bytes(environment, authorities)?;
    if authority_bytes.is_empty() || authority_bytes.len() % 144 != 0 {
        return Err(MobileError::InvalidInput);
    }
    for encoded in authority_bytes.chunks_exact(144) {
        credentials.add_authority(AuthorityCertificate::decode(encoded)?, now)?;
    }
    if authority_revision > 0 {
        credentials.resume_authority_revision(
            u64::try_from(authority_revision).map_err(|_| MobileError::InvalidInput)?,
        )?;
    }
    let local_credential = SubjectCredential::decode(&java_bytes(environment, credential)?)?;
    if local_credential.identity_public_key != local_identity {
        return Err(MobileError::InvalidInput);
    }
    let trust = MobileTrust::new(
        mesh,
        credentials,
        DirectoryPublicKey::from_bytes(&distribution_public)?,
        ServiceSnapshotVerifier::from_bytes(&service_public)?,
        audit_public,
        &distribution_certificate,
        now,
    )?;
    let vm = Arc::new(
        environment
            .get_java_vm()
            .map_err(|_| MobileError::KeyAgreement)?,
    );
    let provider: Arc<dyn StaticDhProvider> = Arc::new(AndroidKeyProvider {
        vm,
        alias,
        public: local_public,
        wrapped,
    });
    let remote_relay = peerward_types::RelayId::from_uuid(
        Uuid::from_slice(&java_bytes(environment, remote_relay)?)
            .map_err(|_| MobileError::InvalidInput)?,
    )
    .map_err(|_| MobileError::InvalidInput)?;
    let (mut session, first_handshake) = NativeSession::initiate_routed(
        provider,
        remote_public,
        &local_credential,
        attachment,
        u64::from_ne_bytes(capabilities.to_ne_bytes()),
        now,
        trust,
        Some(remote_relay),
    )?;
    session.attach_wireguard(wireguard(wireguard_handle)?)?;
    insert_jni_handle(
        sessions(),
        &NEXT_HANDLE,
        Entry {
            session,
            first_handshake: Some(first_handshake),
        },
        MAX_JNI_HANDLES,
    )
}

/// Creates a bounded native Noise handle. No private key or socket descriptor crosses JNI.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeCreate(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    alias: JString<'_>,
    key_mode: jint,
    wrapped_key: JByteArray<'_>,
    local_identity: JByteArray<'_>,
    local_public: JByteArray<'_>,
    remote_public: JByteArray<'_>,
    remote_relay: JByteArray<'_>,
    credential: JByteArray<'_>,
    attachment: JByteArray<'_>,
    root_public: JByteArray<'_>,
    mesh_id: JByteArray<'_>,
    authorities: JByteArray<'_>,
    authority_revision: jlong,
    distribution_public: JByteArray<'_>,
    service_public: JByteArray<'_>,
    audit_public: JByteArray<'_>,
    distribution_certificate: JByteArray<'_>,
    now: jlong,
    capabilities: jlong,
    wireguard_handle: jlong,
) -> jlong {
    match create(
        &mut environment,
        &alias,
        key_mode,
        &wrapped_key,
        &local_identity,
        &local_public,
        &remote_public,
        &remote_relay,
        &credential,
        &attachment,
        &root_public,
        &mesh_id,
        &authorities,
        authority_revision,
        &distribution_public,
        &service_public,
        &audit_public,
        &distribution_certificate,
        now,
        capabilities,
        wireguard_handle,
    ) {
        Ok(handle) => handle,
        Err(error) => {
            fail(&mut environment, &error);
            0
        }
    }
}

/// Generates an X25519 scalar in Rust and returns only its public key followed
/// by AndroidKeyStore-wrapped ciphertext. The scalar is zeroized on all paths.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_crypto_NativeKeyMaterial_nativeGenerateWrapped(
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
            || !(alias.ends_with(".noise-wrap") || alias.ends_with(".wireguard-wrap"))
        {
            return Err(MobileError::InvalidInput);
        }
        let mut private = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(private.as_mut());
        let public = PublicKey::from(&StaticSecret::from(*private)).to_bytes();
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
                "wrapGenerated",
                "(Ljava/lang/String;[B[B)[B",
                &[
                    JValue::Object(&alias_object),
                    JValue::Object(&public_object),
                    JValue::Object(&private_object),
                ],
            )
            .map_err(|_| MobileError::KeyAgreement)?;
        let wrapped = wrapped.l().map_err(|_| MobileError::KeyAgreement)?;
        let wrapped_array = JByteArray::from(wrapped);
        let wrapped = environment
            .convert_byte_array(wrapped_array)
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

/// Computes one fallback X25519 agreement. The transient scalar arrives only
/// as a JNI argument and is zeroized before this call returns.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_crypto_NativeKeyMaterial_nativeAgreeTransient(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    private: JByteArray<'_>,
    remote: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let private = java_secret32(&environment, &private)?;
        let remote = fixed::<32>(java_bytes(&environment, &remote)?)?;
        let shared = Zeroizing::new(
            StaticSecret::from(*private)
                .diffie_hellman(&PublicKey::from(remote))
                .to_bytes(),
        );
        Ok(shared)
    })();
    match result {
        Ok(bytes) => output(&environment, bytes.as_ref()),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeFirstHandshake(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jbyteArray {
    let result = sessions()
        .lock()
        .map_err(|_| MobileError::InvalidState)
        .and_then(|mut values| {
            values
                .get_mut(&handle)
                .and_then(|entry| entry.first_handshake.take())
                .ok_or(MobileError::InvalidState)
        });
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeFinishHandshake(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    response: JByteArray<'_>,
    now: jlong,
    monotonic: jlong,
) -> jlong {
    let result = (|| {
        if now < 0 || monotonic < 0 {
            return Err(MobileError::InvalidInput);
        }
        let response = java_bytes(&environment, &response)?;
        let mut values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        let entry = values.get_mut(&handle).ok_or(MobileError::InvalidState)?;
        let negotiated = entry.session.finish_handshake(
            &response,
            UnixTime(u64::try_from(now).map_err(|_| MobileError::InvalidInput)?),
            u64::try_from(monotonic).map_err(|_| MobileError::InvalidInput)?,
        )?;
        Ok(i64::from_ne_bytes(negotiated.to_ne_bytes()))
    })();
    match result {
        Ok(value) => value,
        Err(error) => {
            fail(&mut environment, &error);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeEncrypt(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    kind: jint,
    payload: JByteArray<'_>,
    monotonic: jlong,
) -> jbyteArray {
    let result = (|| {
        if monotonic < 0 {
            return Err(MobileError::InvalidInput);
        }
        let payload = java_bytes(&environment, &payload)?;
        let record = match kind {
            1 => {
                let envelope = ControlEnvelope::decode(payload.as_slice())
                    .map_err(WireError::MalformedControl)?;
                if envelope.message.is_none() || envelope.encode_to_vec() != payload {
                    return Err(MobileError::InvalidInput);
                }
                Record::Control(envelope)
            }
            _ => return Err(MobileError::InvalidInput),
        };
        let mut values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        let entry = values.get_mut(&handle).ok_or(MobileError::InvalidState)?;
        entry.session.encrypt(
            &record,
            u64::try_from(monotonic).map_err(|_| MobileError::InvalidInput)?,
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
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeDecrypt(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    frame: JByteArray<'_>,
    monotonic: jlong,
) -> jbyteArray {
    let result = (|| {
        if monotonic < 0 {
            return Err(MobileError::InvalidInput);
        }
        let frame = java_bytes(&environment, &frame)?;
        let mut values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        let entry = values.get_mut(&handle).ok_or(MobileError::InvalidState)?;
        let (record, update) = entry.session.decrypt(
            &frame,
            u64::try_from(monotonic).map_err(|_| MobileError::InvalidInput)?,
        )?;
        let credential_update = match &update {
            Some(AcceptedUpdate::CredentialReplacement(replacement)) => {
                let credential_length = u32::try_from(replacement.credential.len())
                    .map_err(|_| MobileError::InvalidInput)?;
                let transcript_length = u32::try_from(replacement.activation_transcript.len())
                    .map_err(|_| MobileError::InvalidInput)?;
                let mut encoded = Vec::with_capacity(
                    8 + replacement.credential.len() + replacement.activation_transcript.len(),
                );
                encoded.extend_from_slice(&credential_length.to_be_bytes());
                encoded.extend_from_slice(&replacement.credential);
                encoded.extend_from_slice(&transcript_length.to_be_bytes());
                encoded.extend_from_slice(&replacement.activation_transcript);
                Some(encoded)
            }
            Some(
                AcceptedUpdate::CredentialActivated(credential)
                | AcceptedUpdate::Terminated(credential),
            ) => Some(credential.clone()),
            _ => None,
        };
        let update_tag = match &update {
            Some(AcceptedUpdate::PeerDirectory(_)) => 1,
            Some(AcceptedUpdate::Policy(_)) => 2,
            Some(AcceptedUpdate::Services) => 3,
            Some(AcceptedUpdate::Revocations(_)) => 4,
            Some(AcceptedUpdate::RelayDirectory(_)) => 5,
            Some(AcceptedUpdate::CredentialReplacement(_)) => 6,
            Some(AcceptedUpdate::Authorities(_)) => 7,
            Some(AcceptedUpdate::CredentialActivated(_)) => 8,
            Some(AcceptedUpdate::Terminated(_)) => 9,
            Some(AcceptedUpdate::CredentialRenewalRequested) => 10,
            Some(AcceptedUpdate::Control) | None => 0,
        };
        let authority = match &update {
            Some(AcceptedUpdate::Authorities(update)) => Some(encode_authority_update(update)?),
            _ => None,
        };
        let (kind, payload) = match (record, credential_update, authority) {
            (Record::Control(_), Some(credential), None) => (1, credential),
            (Record::Control(_), None, Some(authority)) => (1, authority),
            (Record::Control(envelope), None, None) => (1, envelope.encode_to_vec()),
            (Record::Control(_), Some(_), Some(_)) | (Record::Ipv4(_) | Record::Ipv6(_), _, _) => {
                return Err(MobileError::InvalidState);
            }
        };
        let mut output = Vec::with_capacity(payload.len() + 2);
        output.push(kind);
        output.push(update_tag);
        output.extend_from_slice(&payload);
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

include!("android_jni_export_helpers.rs");
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeKeepalive(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    timestamp: jlong,
    monotonic: jlong,
) -> jbyteArray {
    let result = (|| {
        if timestamp < 0 || monotonic < 0 {
            return Err(MobileError::InvalidInput);
        }
        let control = ControlEnvelope {
            trace_context: None,
            message: Some(ControlMessage::Keepalive(Keepalive {
                monotonic_timestamp: u64::try_from(timestamp)
                    .map_err(|_| MobileError::InvalidInput)?,
            })),
        };
        let mut values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        let entry = values.get_mut(&handle).ok_or(MobileError::InvalidState)?;
        entry.session.encrypt(
            &Record::Control(control),
            u64::try_from(monotonic).map_err(|_| MobileError::InvalidInput)?,
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

/// Resolves one DNS query from signed state, or returns an empty array for an upstream name.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeResolveDns(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    query: JByteArray<'_>,
    source: JByteArray<'_>,
    suffix: JString<'_>,
) -> jbyteArray {
    let result = (|| {
        let query = java_bytes(&environment, &query)?;
        let source = java_bytes(&environment, &source)?;
        let source = match source.as_slice() {
            [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
            bytes if bytes.len() == 16 => {
                let octets: [u8; 16] = bytes.try_into().map_err(|_| MobileError::InvalidInput)?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => return Err(MobileError::InvalidInput),
        };
        let suffix: String = environment
            .get_string(&suffix)
            .map_err(|_| MobileError::InvalidInput)?
            .into();
        let values = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        values
            .get(&handle)
            .ok_or(MobileError::InvalidState)?
            .session
            .resolve_dns(&query, source, &suffix)
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
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePeerCore_nativeClose(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    let result = sessions()
        .lock()
        .map_err(|_| MobileError::InvalidState)
        .and_then(|mut values| {
            values
                .remove(&handle)
                .map(|mut entry| entry.session.close())
                .ok_or(MobileError::InvalidState)
        });
    if let Err(error) = result {
        fail(&mut environment, &error);
    }
}
