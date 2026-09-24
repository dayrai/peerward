use peerward_peer_core::{RelayConnectCommit, RelayPoolOrchestrator, RelayRoute};

const RELAY_POOL_RECORD_VERSION: u8 = 1;
static NEXT_RELAY_POOL_HANDLE: AtomicI64 = AtomicI64::new(1);
static RELAY_POOLS: OnceLock<Mutex<HashMap<i64, RelayPoolOrchestrator>>> = OnceLock::new();

fn relay_pools() -> &'static Mutex<HashMap<i64, RelayPoolOrchestrator>> {
    RELAY_POOLS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn decode_endpoint_counts(bytes: &[u8]) -> Result<Vec<u16>, MobileError> {
    let Some((&count, remaining)) = bytes.split_first() else {
        return Err(MobileError::InvalidInput);
    };
    if !(1..=3).contains(&count) || remaining.len() != usize::from(count) * 2 {
        return Err(MobileError::InvalidInput);
    }
    remaining
        .chunks_exact(2)
        .map(|value| {
            let count = u16::from_be_bytes([value[0], value[1]]);
            (count > 0).then_some(count).ok_or(MobileError::InvalidInput)
        })
        .collect()
}

fn encode_routes(pool: &RelayPoolOrchestrator) -> Result<Vec<u8>, MobileError> {
    let routes = pool.active();
    let mut output = Vec::with_capacity(2 + routes.len() * 9);
    output.push(RELAY_POOL_RECORD_VERSION);
    output.push(u8::try_from(routes.len()).map_err(|_| MobileError::InvalidState)?);
    for route in routes {
        output.push(route.slot);
        output.extend_from_slice(&route.generation.to_be_bytes());
    }
    Ok(output)
}

fn encode_commit(commit: Option<RelayConnectCommit>) -> Vec<u8> {
    let mut output = Vec::with_capacity(28);
    output.push(RELAY_POOL_RECORD_VERSION);
    if let Some(commit) = commit {
        output.push(1);
        output.push(commit.slot);
        output.extend_from_slice(&commit.generation.to_be_bytes());
        output.extend_from_slice(&commit.replaced_generation.unwrap_or(0).to_be_bytes());
        output.push(commit.primary.map_or(u8::MAX, |route| route.slot));
        output.extend_from_slice(&commit.primary.map_or(0, |route| route.generation).to_be_bytes());
    } else {
        output.push(0);
    }
    output
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelayPoolCoordinator_nativeCreate(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    endpoint_counts: JByteArray<'_>,
) -> jlong {
    let result = (|| {
        let counts = decode_endpoint_counts(&java_bytes(&environment, &endpoint_counts)?)?;
        let pool = RelayPoolOrchestrator::new(&counts).map_err(|_| MobileError::InvalidInput)?;
        insert_jni_handle(
            relay_pools(),
            &NEXT_RELAY_POOL_HANDLE,
            pool,
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
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelayPoolCoordinator_nativePoll(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    now_millis: jlong,
) -> jbyteArray {
    let result = (|| {
        if now_millis < 0 {
            return Err(MobileError::InvalidInput);
        }
        let mut values = relay_pools().lock().map_err(|_| MobileError::InvalidState)?;
        let pool = values.get_mut(&handle).ok_or(MobileError::InvalidState)?;
        let now = u64::try_from(now_millis).map_err(|_| MobileError::InvalidInput)?;
        let requests = pool.poll(now).map_err(|_| MobileError::InvalidState)?;
        let mut output = Vec::with_capacity(10 + requests.len() * 28);
        output.push(RELAY_POOL_RECORD_VERSION);
        output.push(u8::try_from(requests.len()).map_err(|_| MobileError::InvalidState)?);
        output.extend_from_slice(&pool.next_poll_millis(now).to_be_bytes());
        for request in requests {
            output.extend_from_slice(&request.request_id.to_be_bytes());
            output.push(request.slot);
            output.extend_from_slice(&request.endpoint_index.to_be_bytes());
            output.extend_from_slice(&request.candidate_generation.to_be_bytes());
            output.extend_from_slice(&request.replacing_generation.unwrap_or(0).to_be_bytes());
        }
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

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelayPoolCoordinator_nativeComplete(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    request_id: jlong,
    success: jboolean,
    now_millis: jlong,
) -> jbyteArray {
    let result = (|| {
        if request_id <= 0 || now_millis < 0 {
            return Err(MobileError::InvalidInput);
        }
        let commit = relay_pools()
            .lock()
            .map_err(|_| MobileError::InvalidState)?
            .get_mut(&handle)
            .ok_or(MobileError::InvalidState)?
            .complete(
                u64::try_from(request_id).map_err(|_| MobileError::InvalidInput)?,
                success != 0,
                u64::try_from(now_millis).map_err(|_| MobileError::InvalidInput)?,
            )
            .map_err(|_| MobileError::InvalidState)?;
        Ok(encode_commit(commit))
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

fn relay_route(slot: jint, generation: jlong) -> Result<RelayRoute, MobileError> {
    if !(0..=2).contains(&slot) || generation <= 0 {
        return Err(MobileError::InvalidInput);
    }
    Ok(RelayRoute {
        slot: u8::try_from(slot).map_err(|_| MobileError::InvalidInput)?,
        generation: u64::try_from(generation).map_err(|_| MobileError::InvalidInput)?,
    })
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelayPoolCoordinator_nativeFailed(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    slot: jint,
    generation: jlong,
    now_millis: jlong,
) {
    let result = (|| {
        if now_millis < 0 {
            return Err(MobileError::InvalidInput);
        }
        relay_pools()
            .lock()
            .map_err(|_| MobileError::InvalidState)?
            .get_mut(&handle)
            .ok_or(MobileError::InvalidState)?
            .failed(
                relay_route(slot, generation)?,
                u64::try_from(now_millis).map_err(|_| MobileError::InvalidInput)?,
            )
            .map_err(|_| MobileError::InvalidState)?;
        Ok(())
    })();
    if let Err(error) = result {
        fail(&mut environment, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelayPoolCoordinator_nativeRefresh(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    slot: jint,
    generation: jlong,
    now_millis: jlong,
) {
    let result = (|| {
        if now_millis < 0 {
            return Err(MobileError::InvalidInput);
        }
        relay_pools()
            .lock()
            .map_err(|_| MobileError::InvalidState)?
            .get_mut(&handle)
            .ok_or(MobileError::InvalidState)?
            .refresh(
                relay_route(slot, generation)?,
                u64::try_from(now_millis).map_err(|_| MobileError::InvalidInput)?,
            )
            .map_err(|_| MobileError::InvalidState)
    })();
    if let Err(error) = result {
        fail(&mut environment, &error);
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelayPoolCoordinator_nativeRoutes(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jbyteArray {
    let result = relay_pools()
        .lock()
        .map_err(|_| MobileError::InvalidState)
        .and_then(|values| {
            encode_routes(values.get(&handle).ok_or(MobileError::InvalidState)?)
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
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelayPoolCoordinator_nativeIsPrimary(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    slot: jint,
    generation: jlong,
) -> jboolean {
    let result = relay_pools()
        .lock()
        .map_err(|_| MobileError::InvalidState)
        .and_then(|values| {
            Ok(values
                .get(&handle)
                .ok_or(MobileError::InvalidState)?
                .accepts_inbound(relay_route(slot, generation)?))
        });
    match result {
        Ok(primary) => jboolean::from(primary),
        Err(error) => {
            fail(&mut environment, &error);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeRelayPoolCoordinator_nativeClose(
    environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) -> jbyteArray {
    let bytes = relay_pools()
        .lock()
        .ok()
        .and_then(|mut values| values.remove(&handle))
        .and_then(|mut pool| {
            let routes = pool.close();
            let mut output = vec![RELAY_POOL_RECORD_VERSION, u8::try_from(routes.len()).ok()?];
            for route in routes {
                output.push(route.slot);
                output.extend_from_slice(&route.generation.to_be_bytes());
            }
            Some(output)
        })
        .unwrap_or_default();
    output(&environment, &bytes)
}

#[cfg(test)]
mod relay_pool_jni_tests {
    use super::*;

    #[test]
    fn endpoint_count_codec_is_strict() {
        assert_eq!(decode_endpoint_counts(&[2, 0, 2, 0, 1]).unwrap(), [2, 1]);
        assert_eq!(
            decode_endpoint_counts(&[3, 0, 2, 0, 1, 0, 3]).unwrap(),
            [2, 1, 3]
        );
        assert!(decode_endpoint_counts(&[0]).is_err());
        assert!(decode_endpoint_counts(&[1, 0, 0]).is_err());
        assert!(decode_endpoint_counts(&[1, 0, 1, 0]).is_err());
    }

    #[test]
    fn all_three_native_relay_slots_are_valid_routes() {
        assert_eq!(relay_route(2, 7).unwrap().slot, 2);
        assert!(relay_route(3, 7).is_err());
    }
}
