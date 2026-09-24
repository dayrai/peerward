static NEXT_WIREGUARD_HANDLE: AtomicI64 = AtomicI64::new(1);
static WIREGUARDS: OnceLock<Mutex<HashMap<i64, crate::SharedMobileWireguard>>> = OnceLock::new();

fn wireguards() -> &'static Mutex<HashMap<i64, crate::SharedMobileWireguard>> {
    WIREGUARDS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn wireguard(handle: jlong) -> Result<crate::SharedMobileWireguard, MobileError> {
    wireguards()
        .lock()
        .map_err(|_| MobileError::InvalidState)?
        .get(&handle)
        .cloned()
        .ok_or(MobileError::InvalidState)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeWireguardRuntime_nativeInstall(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    profile: JByteArray<'_>,
    credential: JByteArray<'_>,
    private: JByteArray<'_>,
) -> jlong {
    let result = (|| {
        let private = Zeroizing::new(java_bytes(&environment, &private)?);
        let credential = Zeroizing::new(java_bytes(&environment, &credential)?);
        let scalar = Zeroizing::new(
            <[u8; 32]>::try_from(private.as_slice()).map_err(|_| MobileError::InvalidInput)?,
        );
        let private = StaticSecret::from(*scalar);
        let now = UnixTime(crate::wall_clock_seconds());
        if handle > 0 {
            wireguard(handle)?
                .lock()
                .map_err(|_| MobileError::InvalidState)?
                .core
                .stage(
                    SubjectCredential::decode(&credential)?,
                    private,
                    now,
                )?;
            return Ok(handle);
        }
        if handle != 0 || !credential.is_empty() {
            return Err(MobileError::InvalidInput);
        }
        let profile = Zeroizing::new(java_bytes(&environment, &profile)?);
        let owner = crate::mobile_wireguard_from_profile(
            &profile,
            private,
            now,
        )?;
        insert_jni_handle(
            wireguards(),
            &NEXT_WIREGUARD_HANDLE,
            Arc::new(Mutex::new(owner)),
            128,
        )
    })();
    match result {
        Ok(handle) => handle,
        Err(error) => {
            fail(&mut environment, &error);
            0
        }
    }
}

/// Commands carry bounded runtime input; output may include the confirmed credential.
/// Both directions are cleared after the JNI copy completes.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeWireguardRuntime_nativeExchange(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    operation: jint,
    input: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let input = Zeroizing::new(java_bytes(&environment, &input)?);
        if operation == 4 {
            if let Some(owner) = wireguards()
                .lock()
                .map_err(|_| MobileError::InvalidState)?
                .remove(&handle)
            {
                owner.lock().map_err(|_| MobileError::InvalidState)?.close();
            }
            return Ok(Vec::new());
        }
        let owner = wireguard(handle)?;
        let mut owner = owner.lock().map_err(|_| MobileError::InvalidState)?;
        let now = UnixTime(crate::wall_clock_seconds());
        let clock = std::time::Instant::now();
        match operation {
            0 => {
                owner.tick(now, clock)?;
                let tickets = owner.poll(now, clock);
                let mut result = vec![
                    2,
                    u8::try_from(tickets.len()).map_err(|_| MobileError::InvalidState)?,
                ];
                for ticket in tickets {
                    result.push(u8::from(ticket.tunnel));
                    result.extend_from_slice(&ticket.id.to_be_bytes());
                    let endpoint = ticket
                        .endpoint
                        .map_or_else(String::new, |address| address.to_string());
                    result
                        .push(u8::try_from(endpoint.len()).map_err(|_| MobileError::InvalidState)?);
                    result.extend_from_slice(endpoint.as_bytes());
                    let local = ticket
                        .local_endpoint
                        .map_or_else(String::new, |address| address.to_string());
                    result.push(u8::try_from(local.len()).map_err(|_| MobileError::InvalidState)?);
                    result.extend_from_slice(local.as_bytes());
                }
                return Ok(result);
            }
            1 => owner.send(&input, now, clock)?,
            2 => {
                let length = usize::from(*input.first().ok_or(MobileError::InvalidInput)?);
                let endpoint =
                    std::str::from_utf8(input.get(1..=length).ok_or(MobileError::InvalidInput)?)
                        .map_err(|_| MobileError::InvalidInput)?
                        .parse()
                        .map_err(|_| MobileError::InvalidInput)?;
                owner.receive(
                    peerward_peer_core::WireguardIngress::Direct(endpoint),
                    &input[1 + length..],
                    now,
                    clock,
                )?;
            }
            3 => {
                if input.len() > 8192 {
                    return Err(MobileError::InvalidInput);
                }
                let observed: Vec<std::net::SocketAddr> =
                    serde_json::from_slice(&input).map_err(|_| MobileError::InvalidInput)?;
                if observed.len() > 32 {
                    return Err(MobileError::InvalidInput);
                }
                owner
                    .core
                    .update_candidates(peerward_peer_core::filter_wireguard_candidates(observed))?;
            }
            10 => {
                let mut remaining = input.as_slice();
                let mut endpoint = || -> Result<std::net::SocketAddr, MobileError> {
                    let length = usize::from(*remaining.first().ok_or(MobileError::InvalidInput)?);
                    let value = std::str::from_utf8(
                        remaining.get(1..=length).ok_or(MobileError::InvalidInput)?,
                    )
                    .map_err(|_| MobileError::InvalidInput)?
                    .parse()
                    .map_err(|_| MobileError::InvalidInput)?;
                    remaining = remaining
                        .get(1 + length..)
                        .ok_or(MobileError::InvalidInput)?;
                    Ok(value)
                };
                let local = endpoint()?;
                let remote = endpoint()?;
                owner.receive(
                    peerward_peer_core::WireguardIngress::DirectPath { local, remote },
                    remaining,
                    now,
                    clock,
                )?;
            }
            11 => {
                if input.len() > 8192 {
                    return Err(MobileError::InvalidInput);
                }
                let (local, endpoints): (Vec<std::net::SocketAddr>, Vec<std::net::SocketAddr>) =
                    serde_json::from_slice(&input).map_err(|_| MobileError::InvalidInput)?;
                owner.core.update_local_paths(
                    local,
                    peerward_peer_core::filter_wireguard_candidates(endpoints),
                )?;
            }
            5 => {
                return Ok(u32::try_from(owner.core.direct_peers(now, clock).len())
                    .map_err(|_| MobileError::InvalidState)?
                    .to_be_bytes()
                    .to_vec());
            }
            6 => owner.fallback(u64::from_be_bytes(
                input
                    .as_slice()
                    .try_into()
                    .map_err(|_| MobileError::InvalidInput)?,
            )),
            7 => {
                use base64::Engine;
                let (query, source, suffix): (String, String, String) =
                    serde_json::from_slice(&input).map_err(|_| MobileError::InvalidInput)?;
                let query = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(query)
                    .map_err(|_| MobileError::InvalidInput)?;
                return owner.resolve_dns(
                    &query,
                    source.parse().map_err(|_| MobileError::InvalidInput)?,
                    &suffix,
                    now,
                );
            }
            8 => {
                return Ok(owner
                    .core
                    .confirmed_local_credential(now)
                    .map_or_else(Vec::new, |credential| credential.encode()));
            }
            12 => {
                use base64::Engine;
                let (query, source): (String, String) =
                    serde_json::from_slice(&input).map_err(|_| MobileError::InvalidInput)?;
                let query = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(query)
                    .map_err(|_| MobileError::InvalidInput)?;
                let question = crate::parse_question(&query)?;
                let (version, dns) = owner
                    .core
                    .effective_dns(source.parse().map_err(|_| MobileError::InvalidInput)?, now)?;
                let Some(route) = dns.route(&question.name) else {
                    return if owner.core.dns_system_fallback_allowed(now) {
                        Ok(Vec::new())
                    } else {
                        Err(MobileError::PolicyDenied)
                    };
                };
                let mut upstreams = Vec::new();
                for server in &route.upstreams {
                    let tunnel = owner.core.dns_requires_tunnel(server.ip(), now)?;
                    upstreams.push(serde_json::json!({"address":server.ip().to_string(),"port":server.port(),"tunnel":tunnel}));
                }
                return serde_json::to_vec(
                    &serde_json::json!({"configuration_version":version,"upstreams":upstreams}),
                )
                .map_err(|_| MobileError::InvalidState);
            }
            14 => {
                let source = std::str::from_utf8(&input)
                    .map_err(|_| MobileError::InvalidInput)?
                    .parse()
                    .map_err(|_| MobileError::InvalidInput)?;
                return serde_json::to_vec(&owner.managed_network(source, now)?)
                    .map_err(|_| MobileError::InvalidState);
            }
            15 => {
                if input.len() > 4096 {
                    return Err(MobileError::InvalidInput);
                }
                let observation =
                    serde_json::from_slice(&input).map_err(|_| MobileError::InvalidInput)?;
                owner.observe_network(observation, now)?;
            }
            16 => {
                if input.len() > 4096 {
                    return Err(MobileError::InvalidInput);
                }
                let request =
                    serde_json::from_slice(&input).map_err(|_| MobileError::InvalidInput)?;
                return serde_json::to_vec(&owner.client_preferences(request, now)?)
                    .map_err(|_| MobileError::InvalidState);
            }
            13 => {
                let (version, source): (u64, String) =
                    serde_json::from_slice(&input).map_err(|_| MobileError::InvalidInput)?;
                let valid = owner
                    .core
                    .effective_dns(source.parse().map_err(|_| MobileError::InvalidInput)?, now)
                    .is_ok_and(|(current, _)| current == version);
                return Ok(vec![u8::from(valid)]);
            }
            9 => {
                if input.len() > 4096 {
                    return Err(MobileError::InvalidInput);
                }
                let path = std::str::from_utf8(&input).map_err(|_| MobileError::InvalidInput)?;
                owner
                    .core
                    .enable_checkpoint(std::path::Path::new(path), now)?;
                owner.load_preferences(std::path::Path::new(path))?;
            }
            _ => return Err(MobileError::InvalidInput),
        }
        Ok(Vec::new())
    })();
    match result {
        Ok(bytes) => {
            let bytes = Zeroizing::new(bytes);
            output(&environment, &bytes)
        }
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

/// Rechecks authorization at the real TUN or Relay writer; no queued IP crosses JNI.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeWireguardRuntime_nativeDeliver(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    ticket: jlong,
    target: jlong,
    session: jlong,
    monotonic: jlong,
) -> jboolean {
    let result = (|| {
        let ticket = u64::try_from(ticket).map_err(|_| MobileError::InvalidInput)?;
        let owner = wireguard(handle)?;
        if session == 0 {
            let pump = tun_pump(target)?;
            let Ok(mut writer) = pump.writer.try_lock() else {
                return Ok(false);
            };
            let mut wrote = false;
            owner
                .lock()
                .map_err(|_| MobileError::InvalidState)?
                .deliver(
                    ticket,
                    UnixTime(crate::wall_clock_seconds()),
                    std::time::Instant::now(),
                    |output| {
                        let peerward_peer_core::WireguardOutput::Tunnel { packet, .. } = output
                        else {
                            return Err(MobileError::InvalidInput);
                        };
                        wrote = match std::io::Write::write(&mut *writer, packet) {
                            Ok(length) if length == packet.len() => true,
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
                            _ => return Err(MobileError::InvalidState),
                        };
                        Ok(())
                    },
                )?;
            return Ok(wrote);
        }
        // The same lock order as incoming signed updates: attachment, then Mesh owner.
        let mut sessions = sessions().lock().map_err(|_| MobileError::InvalidState)?;
        if !sessions
            .get(&session)
            .ok_or(MobileError::InvalidState)?
            .session
            .wireguard
            .as_ref()
            .is_some_and(|attached| Arc::ptr_eq(attached, &owner))
        {
            return Err(MobileError::InvalidInput);
        }
        let socket = relay_socket(target)?;
        let Ok(mut writer) = socket.writer.try_lock() else {
            return Ok(false);
        };
        owner
            .lock()
            .map_err(|_| MobileError::InvalidState)?
            .deliver(
                ticket,
                UnixTime(crate::wall_clock_seconds()),
                std::time::Instant::now(),
                |output| {
                    let peerward_peer_core::WireguardOutput::Network {
                        peer: Some(peer),
                        packet,
                        ..
                    } = output
                    else {
                        return Err(MobileError::InvalidInput);
                    };
                    let native = &mut sessions
                        .get_mut(&session)
                        .ok_or(MobileError::InvalidState)?
                        .session;
                    let frame = native.encrypt(
                        &Record::Control(ControlEnvelope {
                            trace_context: None,
                            message: Some(ControlMessage::Opaque(peerward_wire::RelayEnvelopeV2 {
                                major: peerward_wire::PROTOCOL_MAJOR,
                                mesh_id: native.trust.mesh_id.as_bytes().to_vec(),
                                source_peer: Vec::new(),
                                destination_peer: peer.as_bytes().to_vec(),
                                kind: peerward_wire::OpaqueFrameKind::Session as i32,
                                opaque: packet.clone(),
                            })),
                        }),
                        u64::try_from(monotonic).map_err(|_| MobileError::InvalidInput)?,
                    )?;
                    drop(sessions);
                    writer
                        .write_with_timeout(&frame, std::time::Duration::from_millis(20))
                        .map_err(|error| MobileError::Carrier(error.kind()))
                },
            )
    })();
    match result {
        Ok(delivered) => u8::from(delivered),
        Err(error) => {
            fail(&mut environment, &error);
            0
        }
    }
}
