const TUN_PUMP_RECORD_VERSION: u8 = 1;
const TUN_PUMP_IDLE: u8 = 0;
const TUN_PUMP_PACKET: u8 = 1;
const TUN_PUMP_RESOLVE: u8 = 2;
const MAX_TUN_POLL_MILLIS: jint = 1_000;

struct AndroidTunPump {
    reader: Mutex<std::fs::File>,
    dns: Mutex<TunDnsProxy>,
    writer: Mutex<std::fs::File>,
}

static NEXT_TUN_PUMP_HANDLE: AtomicI64 = AtomicI64::new(1);
static TUN_PUMPS: OnceLock<Mutex<HashMap<i64, Arc<AndroidTunPump>>>> = OnceLock::new();

fn tun_pumps() -> &'static Mutex<HashMap<i64, Arc<AndroidTunPump>>> {
    TUN_PUMPS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn tun_pump(handle: jlong) -> Result<Arc<AndroidTunPump>, MobileError> {
    tun_pumps()
        .lock()
        .map_err(|_| MobileError::InvalidState)?
        .get(&handle)
        .cloned()
        .ok_or(MobileError::InvalidState)
}

fn write_tun_packets(pump: &AndroidTunPump, packets: &[Vec<u8>]) -> Result<(), MobileError> {
    let mut writer = pump.writer.lock().map_err(|_| MobileError::InvalidState)?;
    for packet in packets {
        parse_packet(packet).map_err(|_| MobileError::InvalidInput)?;
        std::io::Write::write_all(&mut *writer, packet).map_err(|_| MobileError::InvalidState)?;
    }
    Ok(())
}

fn encode_tun_pump_decision(decision: TunDnsDecision) -> Result<Vec<u8>, MobileError> {
    let mut output = vec![TUN_PUMP_RECORD_VERSION];
    match decision {
        TunDnsDecision::Pass | TunDnsDecision::Replies(_) => output.push(TUN_PUMP_IDLE),
        TunDnsDecision::Resolve {
            token,
            transport,
            source,
            query,
        } => {
            output.push(TUN_PUMP_RESOLVE);
            output.extend_from_slice(&token.to_be_bytes());
            output.push(transport as u8);
            output.push(u8::try_from(source.len()).map_err(|_| MobileError::InvalidState)?);
            output.extend_from_slice(&source);
            output.extend_from_slice(
                &u16::try_from(query.len())
                    .map_err(|_| MobileError::InvalidState)?
                    .to_be_bytes(),
            );
            output.extend_from_slice(&query);
        }
    }
    Ok(output)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeTunPacketPump_nativeCreate(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    descriptor: jint,
    servers: JByteArray<'_>,
    mtu: jint,
) -> jlong {
    let result = (|| {
        if descriptor < 0 || mtu < 0 {
            return Err(MobileError::InvalidInput);
        }
        let dns = TunDnsProxy::new(
            decode_dns_servers(&java_bytes(&environment, &servers)?)?,
            usize::try_from(mtu).map_err(|_| MobileError::InvalidInput)?,
        )?;
        // SAFETY: Kotlin retains its ParcelFileDescriptor in a `use` block for this entire
        // call. Borrowing does not consume that owner; only duplicated FDs enter Rust state.
        // Thus an error after duplication cannot make both languages close the same FD.
        let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(descriptor) };
        let reader = std::fs::File::from(
            borrowed
                .try_clone_to_owned()
                .map_err(|_| MobileError::InvalidState)?,
        );
        let writer = reader.try_clone().map_err(|_| MobileError::InvalidState)?;
        insert_jni_handle(
            tun_pumps(),
            &NEXT_TUN_PUMP_HANDLE,
            Arc::new(AndroidTunPump {
                reader: Mutex::new(reader),
                dns: Mutex::new(dns),
                writer: Mutex::new(writer),
            }),
            MAX_JNI_HANDLES,
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeTunPacketPump_nativePoll(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    timeout_millis: jint,
) -> jbyteArray {
    let result = (|| {
        if !(0..=MAX_TUN_POLL_MILLIS).contains(&timeout_millis) {
            return Err(MobileError::InvalidInput);
        }
        let pump = tun_pump(handle)?;
        let mut reader = pump.reader.lock().map_err(|_| MobileError::InvalidState)?;
        let mut descriptor = libc::pollfd {
            fd: std::os::fd::AsRawFd::as_raw_fd(&*reader),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `descriptor` is a fully initialized single-element pollfd array and its mutable
        // address remains valid for this blocking call. The reader mutex keeps the underlying FD
        // open and prevents a concurrent native close until `poll` returns.
        let ready = unsafe { libc::poll(&raw mut descriptor, 1, timeout_millis) };
        if ready < 0 {
            return Err(MobileError::InvalidState);
        }
        if ready == 0 || descriptor.revents & libc::POLLIN == 0 {
            return Ok(vec![TUN_PUMP_RECORD_VERSION, TUN_PUMP_IDLE]);
        }
        let mut packet = Zeroizing::new(vec![0; 65_535]);
        let count = std::io::Read::read(&mut *reader, &mut packet)
            .map_err(|_| MobileError::InvalidState)?;
        drop(reader);
        if count == 0 {
            return Err(MobileError::InvalidState);
        }
        packet.truncate(count);
        parse_packet(&packet).map_err(|_| MobileError::InvalidInput)?;
        let decision = pump
            .dns
            .lock()
            .map_err(|_| MobileError::InvalidState)?
            .inspect(&packet)?;
        match decision {
            TunDnsDecision::Pass => {
                let mut output = Vec::with_capacity(packet.len() + 6);
                output.push(TUN_PUMP_RECORD_VERSION);
                output.push(TUN_PUMP_PACKET);
                output.extend_from_slice(
                    &u32::try_from(packet.len())
                        .map_err(|_| MobileError::InvalidState)?
                        .to_be_bytes(),
                );
                output.extend_from_slice(&packet);
                Ok(output)
            }
            TunDnsDecision::Replies(replies) => {
                write_tun_packets(&pump, &replies)?;
                Ok(vec![TUN_PUMP_RECORD_VERSION, TUN_PUMP_IDLE])
            }
            decision @ TunDnsDecision::Resolve { .. } => encode_tun_pump_decision(decision),
        }
    })();
    match result {
        Ok(bytes) => output(&environment, &Zeroizing::new(bytes)),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeTunPacketPump_nativeCompleteDns(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    token: jlong,
    response: JByteArray<'_>,
) {
    let result = (|| {
        if token <= 0 {
            return Err(MobileError::InvalidInput);
        }
        let pump = tun_pump(handle)?;
        let replies = pump
            .dns
            .lock()
            .map_err(|_| MobileError::InvalidState)?
            .complete(
                u64::try_from(token).map_err(|_| MobileError::InvalidInput)?,
                &java_bytes(&environment, &response)?,
            )?;
        write_tun_packets(&pump, &replies)
    })();
    if let Err(error) = result {
        fail(&mut environment, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeTunPacketPump_nativeWriteInbound(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    packet: JByteArray<'_>,
) {
    let result = (|| {
        let packet = java_bytes(&environment, &packet)?;
        let pump = tun_pump(handle)?;
        write_tun_packets(&pump, &[packet])
    })();
    if let Err(error) = result {
        fail(&mut environment, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeTunPacketPump_nativeClose(
    _environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    if let Ok(mut values) = tun_pumps().lock() {
        values.remove(&handle);
    }
}
