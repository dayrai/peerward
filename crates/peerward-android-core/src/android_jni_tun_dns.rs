use crate::{TunDnsDecision, TunDnsProxy};
#[cfg(test)]
use crate::TunDnsTransport;

const TUN_DNS_RECORD_VERSION: u8 = 1;
const TUN_DNS_PASS: u8 = 0;
const TUN_DNS_REPLIES: u8 = 1;
const TUN_DNS_RESOLVE: u8 = 2;

static NEXT_TUN_DNS_HANDLE: AtomicI64 = AtomicI64::new(1);
static TUN_DNS_PROXIES: OnceLock<Mutex<HashMap<i64, TunDnsProxy>>> = OnceLock::new();

fn tun_dns_proxies() -> &'static Mutex<HashMap<i64, TunDnsProxy>> {
    TUN_DNS_PROXIES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn decode_dns_servers(bytes: &[u8]) -> Result<Vec<Vec<u8>>, MobileError> {
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
        if !matches!(length, 4 | 16) || tail.len() < usize::from(length) {
            return Err(MobileError::InvalidInput);
        }
        let (address, tail) = tail.split_at(usize::from(length));
        servers.push(address.to_vec());
        remaining = tail;
    }
    if !remaining.is_empty() {
        return Err(MobileError::InvalidInput);
    }
    Ok(servers)
}

fn encode_dns_decision(decision: TunDnsDecision) -> Result<Vec<u8>, MobileError> {
    let mut output = vec![TUN_DNS_RECORD_VERSION];
    match decision {
        TunDnsDecision::Pass => output.push(TUN_DNS_PASS),
        TunDnsDecision::Replies(replies) => {
            output.push(TUN_DNS_REPLIES);
            output.extend_from_slice(
                &u16::try_from(replies.len())
                    .map_err(|_| MobileError::InvalidState)?
                    .to_be_bytes(),
            );
            for reply in replies {
                output.extend_from_slice(
                    &u32::try_from(reply.len())
                        .map_err(|_| MobileError::InvalidState)?
                        .to_be_bytes(),
                );
                output.extend_from_slice(&reply);
            }
        }
        TunDnsDecision::Resolve {
            token,
            transport,
            source,
            query,
        } => {
            output.push(TUN_DNS_RESOLVE);
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
    if output.len() > MAX_JNI_BYTES {
        return Err(MobileError::InvalidState);
    }
    Ok(output)
}

/// Creates one Rust-owned TUN DNS flow table. The encoded server list contains
/// count:u8 followed by repeated address-length:u8/address bytes.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeTunDnsProxy_nativeCreate(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    servers: JByteArray<'_>,
    mtu: jint,
) -> jlong {
    let result = (|| {
        if mtu < 0 {
            return Err(MobileError::InvalidInput);
        }
        let servers = decode_dns_servers(&java_bytes(&environment, &servers)?)?;
        let proxy = TunDnsProxy::new(
            servers,
            usize::try_from(mtu).map_err(|_| MobileError::InvalidInput)?,
        )?;
        insert_jni_handle(
            tun_dns_proxies(),
            &NEXT_TUN_DNS_HANDLE,
            proxy,
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

/// Parses one TUN packet and returns a fixed-version pass/replies/resolve record.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeTunDnsProxy_nativeInspect(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    packet: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let packet = java_bytes(&environment, &packet)?;
        let mut values = tun_dns_proxies()
            .lock()
            .map_err(|_| MobileError::InvalidState)?;
        let decision = values
            .get_mut(&handle)
            .ok_or(MobileError::InvalidState)?
            .inspect(&packet)?;
        encode_dns_decision(decision)
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

/// Completes one exact opaque resolver token. Duplicate and stale tokens fail closed.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeTunDnsProxy_nativeComplete(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
    token: jlong,
    response: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        if token <= 0 {
            return Err(MobileError::InvalidInput);
        }
        let response = java_bytes(&environment, &response)?;
        let mut values = tun_dns_proxies()
            .lock()
            .map_err(|_| MobileError::InvalidState)?;
        let replies = values
            .get_mut(&handle)
            .ok_or(MobileError::InvalidState)?
            .complete(
                u64::try_from(token).map_err(|_| MobileError::InvalidInput)?,
                &response,
            )?;
        encode_dns_decision(TunDnsDecision::Replies(replies))
    })();
    match result {
        Ok(bytes) => output(&environment, &bytes),
        Err(error) => {
            fail(&mut environment, &error);
            std::ptr::null_mut()
        }
    }
}

/// Drops every pending query and TCP flow owned by this proxy.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeTunDnsProxy_nativeClose(
    _environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    if let Ok(mut values) = tun_dns_proxies().lock() {
        values.remove(&handle);
    }
}

#[cfg(test)]
mod tun_dns_jni_tests {
    use super::*;

    #[test]
    fn server_list_and_records_are_strictly_bounded() {
        assert_eq!(decode_dns_servers(&[1, 4, 10, 0, 0, 1]).unwrap().len(), 1);
        assert!(decode_dns_servers(&[1, 5, 10, 0, 0, 1, 2]).is_err());
        assert_eq!(
            encode_dns_decision(TunDnsDecision::Pass).unwrap(),
            [TUN_DNS_RECORD_VERSION, TUN_DNS_PASS]
        );
        let resolve = encode_dns_decision(TunDnsDecision::Resolve {
            token: 7,
            transport: TunDnsTransport::Udp,
            source: vec![10, 0, 0, 2],
            query: vec![0; 12],
        })
        .unwrap();
        assert_eq!(resolve[0..2], [TUN_DNS_RECORD_VERSION, TUN_DNS_RESOLVE]);
    }
}
