const MAX_RELAY_SOCKET_FRAME: usize = 65_535;

type AndroidRelaySocket = peerward_carrier::BlockingSocket;

static NEXT_RELAY_SOCKET_HANDLE: AtomicI64 = AtomicI64::new(1);
static RELAY_SOCKETS: OnceLock<Mutex<HashMap<i64, Arc<AndroidRelaySocket>>>> = OnceLock::new();

fn relay_sockets() -> &'static Mutex<HashMap<i64, Arc<AndroidRelaySocket>>> {
    RELAY_SOCKETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn relay_socket(handle: jlong) -> Result<Arc<AndroidRelaySocket>, MobileError> {
    relay_sockets()
        .lock()
        .map_err(|_| MobileError::InvalidState)?
        .get(&handle)
        .cloned()
        .ok_or(MobileError::InvalidState)
}

fn read_exact(file: &mut peerward_carrier::BlockingReader, bytes: &mut [u8]) -> Result<(), MobileError> {
    file.read_exact(bytes).map_err(|_| MobileError::InvalidState)
}

fn write_all(file: &mut peerward_carrier::BlockingWriter, bytes: &[u8]) -> Result<(), MobileError> {
    file.write_all(bytes).map_err(|_| MobileError::InvalidState)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelaySocket_nativeCreate(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    descriptor: jint,
    endpoint: JString<'_>,
    options: JString<'_>,
    remote: JString<'_>,
) -> jlong {
    let result = (|| {
        if descriptor < 0 {
            return Err(MobileError::InvalidInput);
        }
        // SAFETY: Kotlin detaches one sole-owned FD and never closes it after
        // this call, including on exceptions. Rust owns every error path.
        let file = unsafe {
            <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(descriptor)
        };
        let owned: std::os::fd::OwnedFd = file.into();
        let endpoint: String = environment.get_string(&endpoint)
            .map_err(|_| MobileError::InvalidInput)?.into();
        if endpoint.len() > 512 { return Err(MobileError::InvalidInput); }
        let endpoint = if endpoint.is_empty() { None } else {
            Some(endpoint.parse::<peerward_types::NetworkEndpoint>().map_err(|_| MobileError::InvalidInput)?)
        };
        let options: String = environment.get_string(&options)
            .map_err(|_| MobileError::InvalidInput)?.into();
        if options.len() > 70_000 { return Err(MobileError::InvalidInput); }
        let options: peerward_carrier::ClientOptions = serde_json::from_str(&options).map_err(|_| MobileError::InvalidInput)?;
        options.validate().map_err(|_| MobileError::InvalidInput)?;
        let socket = if let Some(endpoint) = endpoint.as_ref().filter(|target| target.is_quic()) {
            let remote: String = environment.get_string(&remote).map_err(|_| MobileError::InvalidInput)?.into();
            if remote.len() > 128 { return Err(MobileError::InvalidInput); }
            let remote = remote.parse().map_err(|_| MobileError::InvalidInput)?;
            AndroidRelaySocket::prepare_quic(std::net::UdpSocket::from(owned), remote, endpoint, &options)
        } else {
            AndroidRelaySocket::prepare_tcp(std::net::TcpStream::from(owned), endpoint.as_ref(), &options)
        }.map_err(|error| MobileError::Carrier(error.kind()))?;
        insert_jni_handle(
            relay_sockets(),
            &NEXT_RELAY_SOCKET_HANDLE,
            socket,
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
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelaySocket_nativeWriteHandshake(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    message: JByteArray<'_>,
) {
    let result = (|| {
        let message = java_bytes(&environment, &message)?;
        if message.len() <= peerward_wire::RELAY_PREFACE_LEN { return Err(MobileError::InvalidInput); }
        let (preface, message) = message.split_at(peerward_wire::RELAY_PREFACE_LEN);
        peerward_wire::RelayPreface::decode(preface)?;
        let length = u16::try_from(message.len()).map_err(|_| MobileError::InvalidInput)?;
        if length == 0 {
            return Err(MobileError::InvalidInput);
        }
        let socket = relay_socket(handle)?;
        let mut writer = socket.writer.lock().map_err(|_| MobileError::InvalidState)?;
        write_all(&mut writer, preface)?;
        write_all(&mut writer, &length.to_be_bytes())?;
        write_all(&mut writer, message)
    })();
    if let Err(error) = result {
        fail(&mut environment, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelaySocket_nativeReadHandshake(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jbyteArray {
    let result = (|| {
        let socket = relay_socket(handle)?;
        let mut reader = socket.reader.lock().map_err(|_| MobileError::InvalidState)?;
        let mut prefix = [0; 2];
        read_exact(&mut reader, &mut prefix)?;
        let length = usize::from(u16::from_be_bytes(prefix));
        if length == 0 {
            return Err(MobileError::InvalidInput);
        }
        let mut message = vec![0; length];
        read_exact(&mut reader, &mut message)?;
        Ok(message)
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
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelaySocket_nativeWriteFrame(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    frame: JByteArray<'_>,
) {
    let result = (|| {
        let frame = java_bytes(&environment, &frame)?;
        if frame.len() < 5 {
            return Err(MobileError::InvalidInput);
        }
        let declared = u32::from_be_bytes(
            frame[..4].try_into().map_err(|_| MobileError::InvalidInput)?,
        ) as usize;
        if declared == 0 || declared > MAX_RELAY_SOCKET_FRAME || declared + 4 != frame.len() {
            return Err(MobileError::InvalidInput);
        }
        let socket = relay_socket(handle)?;
        let mut writer = socket.writer.lock().map_err(|_| MobileError::InvalidState)?;
        write_all(&mut writer, &frame)
    })();
    if let Err(error) = result {
        fail(&mut environment, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelaySocket_nativeReadFrame(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jbyteArray {
    let result = (|| {
        let socket = relay_socket(handle)?;
        let mut reader = socket.reader.lock().map_err(|_| MobileError::InvalidState)?;
        let mut prefix = [0; 4];
        read_exact(&mut reader, &mut prefix)?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length == 0 || length > MAX_RELAY_SOCKET_FRAME {
            return Err(MobileError::InvalidInput);
        }
        let mut frame = Vec::with_capacity(length + 4);
        frame.extend_from_slice(&prefix);
        frame.resize(length + 4, 0);
        read_exact(&mut reader, &mut frame[4..])?;
        Ok(frame)
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
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelaySocket_nativeClose(
    _environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    let socket = relay_sockets()
        .lock()
        .ok()
        .and_then(|mut sockets| sockets.remove(&handle));
    if let Some(socket) = socket {
        socket.close();
    }
}
