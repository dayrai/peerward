use crate::{StunMapping, StunPoll, StunRuntime};

const STUN_RECORD_VERSION: u8 = 2;
static NEXT_STUN_HANDLE: AtomicI64 = AtomicI64::new(1);
static STUN_RUNTIMES: OnceLock<Mutex<HashMap<i64, StunRuntime>>> = OnceLock::new();

fn stun_runtimes() -> &'static Mutex<HashMap<i64, StunRuntime>> {
    STUN_RUNTIMES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn decode_stun_servers(bytes: &[u8]) -> Result<Vec<std::net::SocketAddr>, MobileError> {
    let Some((&count, mut remaining)) = bytes.split_first() else {
        return Err(MobileError::InvalidInput);
    };
    if !(1..=8).contains(&count) {
        return Err(MobileError::InvalidInput);
    }
    let mut servers = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let Some((&length, tail)) = remaining.split_first() else {
            return Err(MobileError::InvalidInput);
        };
        if !matches!(length, 4 | 16) || tail.len() < usize::from(length) + 2 {
            return Err(MobileError::InvalidInput);
        }
        let (address, tail) = tail.split_at(usize::from(length));
        let (port, tail) = tail.split_at(2);
        let ip = match address {
            [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
            address if address.len() == 16 => IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(address).map_err(|_| MobileError::InvalidInput)?,
            )),
            _ => return Err(MobileError::InvalidInput),
        };
        servers.push(std::net::SocketAddr::new(
            ip,
            u16::from_be_bytes([port[0], port[1]]),
        ));
        remaining = tail;
    }
    if !remaining.is_empty() {
        return Err(MobileError::InvalidInput);
    }
    Ok(servers)
}

fn encode_stun_poll(poll: StunPoll) -> Result<Vec<u8>, MobileError> {
    let mut bytes = Vec::with_capacity(10 + poll.probes.len() * 41);
    bytes.push(STUN_RECORD_VERSION);
    bytes.push(u8::try_from(poll.probes.len()).map_err(|_| MobileError::InvalidState)?);
    bytes.extend_from_slice(&poll.next_poll_millis.to_be_bytes());
    for probe in poll.probes {
        let address = match probe.server.ip() {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(address) => address.octets().to_vec(),
        };
        bytes.push(probe.server_index);
        bytes.push(u8::try_from(address.len()).map_err(|_| MobileError::InvalidState)?);
        bytes.extend_from_slice(&address);
        bytes.extend_from_slice(&probe.server.port().to_be_bytes());
        bytes.extend_from_slice(&probe.request);
    }
    Ok(bytes)
}

fn encode_stun_mapping(mapping: StunMapping) -> Result<Vec<u8>, MobileError> {
    let address = match mapping.mapped.ip() {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    };
    let mut bytes = Vec::with_capacity(6 + address.len() + mapping.predicted.len() * 2);
    bytes.push(STUN_RECORD_VERSION);
    bytes.push(mapping.server_index);
    bytes.push(u8::try_from(address.len()).map_err(|_| MobileError::InvalidState)?);
    bytes.extend_from_slice(&address);
    bytes.extend_from_slice(&mapping.mapped.port().to_be_bytes());
    bytes.push(u8::try_from(mapping.predicted.len()).map_err(|_| MobileError::InvalidState)?);
    for predicted in mapping.predicted {
        if predicted.ip() != mapping.mapped.ip() {
            return Err(MobileError::InvalidState);
        }
        bytes.extend_from_slice(&predicted.port().to_be_bytes());
    }
    Ok(bytes)
}

fn socket_address(address: &[u8], port: jint) -> Result<std::net::SocketAddr, MobileError> {
    if !(1..=i32::from(u16::MAX)).contains(&port) {
        return Err(MobileError::InvalidInput);
    }
    let ip = match address {
        [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
        address if address.len() == 16 => IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(address).map_err(|_| MobileError::InvalidInput)?,
        )),
        _ => return Err(MobileError::InvalidInput),
    };
    Ok(std::net::SocketAddr::new(
        ip,
        u16::try_from(port).map_err(|_| MobileError::InvalidInput)?,
    ))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeStunRuntime_nativeCreate(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    servers: JByteArray<'_>,
    prediction_enabled: jboolean,
) -> jlong {
    let result = (|| {
        let servers = decode_stun_servers(&java_bytes(&environment, &servers)?)?;
        let runtime = StunRuntime::with_prediction(servers, prediction_enabled != 0)?;
        insert_jni_handle(
            stun_runtimes(),
            &NEXT_STUN_HANDLE,
            runtime,
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
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeStunRuntime_nativePoll(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    now_millis: jlong,
) -> jbyteArray {
    let result = (|| {
        if now_millis < 0 {
            return Err(MobileError::InvalidInput);
        }
        let mut values = stun_runtimes()
            .lock()
            .map_err(|_| MobileError::InvalidState)?;
        let poll = values
            .get_mut(&handle)
            .ok_or(MobileError::InvalidState)?
            .poll(u64::try_from(now_millis).map_err(|_| MobileError::InvalidInput)?);
        encode_stun_poll(poll)
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
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeStunRuntime_nativeAccept(
    environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    source_address: JByteArray<'_>,
    source_port: jint,
    response: JByteArray<'_>,
    now_millis: jlong,
) -> jbyteArray {
    let result = (|| {
        let source = socket_address(&java_bytes(&environment, &source_address)?, source_port)?;
        let response = java_bytes(&environment, &response)?;
        let mut values = stun_runtimes()
            .lock()
            .map_err(|_| MobileError::InvalidState)?;
        let mapping = values
            .get_mut(&handle)
            .ok_or(MobileError::InvalidState)?
            .accept(source, &response, u64::try_from(now_millis).map_err(|_| MobileError::InvalidInput)?)?;
        encode_stun_mapping(mapping)
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(_) => output(&environment, &[]),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeStunRuntime_nativeClose(
    _environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    if let Ok(mut values) = stun_runtimes().lock() {
        values.remove(&handle);
    }
}

#[cfg(test)]
mod stun_jni_tests {
    use super::*;

    #[test]
    fn server_codec_rejects_trailing_and_zero_port_data() {
        assert!(decode_stun_servers(&[1, 4, 127, 0, 0, 1, 0x0d, 0x96]).is_ok());
        assert!(decode_stun_servers(&[1, 4, 127, 0, 0, 1, 0, 0]).is_err());
        assert!(decode_stun_servers(&[1, 4, 127, 0, 0, 1, 0x0d, 0x96, 1]).is_err());
    }
}
