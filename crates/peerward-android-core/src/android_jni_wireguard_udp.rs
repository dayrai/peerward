static NEXT_WIREGUARD_UDP: AtomicI64 = AtomicI64::new(1);
static WIREGUARD_UDP: OnceLock<Mutex<HashMap<i64, Arc<std::net::UdpSocket>>>> = OnceLock::new();

fn wireguard_udp() -> &'static Mutex<HashMap<i64, Arc<std::net::UdpSocket>>> {
    WIREGUARD_UDP.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Receives an owned duplicate of the already protected, Network-bound data socket.
#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeWireguardUdp_nativeCreate(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    descriptor: jint,
) -> jlong {
    let result = (|| {
        if descriptor < 0 {
            return Err(MobileError::InvalidInput);
        }
        // SAFETY: ParcelFileDescriptor.detachFd transfers ownership of this duplicate exactly
        // once. Java retains its separate receiver FD; this owned socket closes only the duplicate.
        let socket =
            unsafe { <std::net::UdpSocket as std::os::fd::FromRawFd>::from_raw_fd(descriptor) };
        let ipv6 = socket
            .local_addr()
            .map_err(|_| MobileError::InvalidState)?
            .is_ipv6();
        peerward_peer_core::configure_wireguard_udp(&socket, ipv6)
            .map_err(|_| MobileError::InvalidState)?;
        insert_jni_handle(
            wireguard_udp(),
            &NEXT_WIREGUARD_UDP,
            Arc::new(socket),
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
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeWireguardUdp_nativeDeliver(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    socket: jlong,
    owner: jlong,
    ticket: jlong,
) -> jboolean {
    let result = (|| {
        let socket = wireguard_udp()
            .lock()
            .map_err(|_| MobileError::InvalidState)?
            .get(&socket)
            .cloned()
            .ok_or(MobileError::InvalidState)?;
        wireguard(owner)?
            .lock()
            .map_err(|_| MobileError::InvalidState)?
            .deliver_direct_on(
                u64::try_from(ticket).map_err(|_| MobileError::InvalidInput)?,
                Some(canonical_udp_endpoint(
                    socket.local_addr().map_err(|_| MobileError::InvalidState)?,
                )),
                UnixTime(crate::wall_clock_seconds()),
                std::time::Instant::now(),
                |endpoint, packet| {
                    socket2::SockRef::from(socket.as_ref())
                        .send_to_with_flags(packet, &endpoint.into(), libc::MSG_DONTWAIT)
                        .is_ok_and(|sent| sent == packet.len())
                },
            )
    })();
    match result {
        Ok(sent) => u8::from(sent),
        Err(error) => {
            fail(&mut environment, &error);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativeWireguardUdp_nativeClose(
    mut environment: JNIEnv<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    match wireguard_udp().lock() {
        Ok(mut sockets) => {
            sockets.remove(&handle);
        }
        Err(_) => fail(&mut environment, &MobileError::InvalidState),
    }
}

fn canonical_udp_endpoint(endpoint: std::net::SocketAddr) -> std::net::SocketAddr {
    if let std::net::SocketAddr::V6(address) = endpoint
        && let Some(ipv4) = address.ip().to_ipv4_mapped()
    {
        return std::net::SocketAddr::new(ipv4.into(), endpoint.port());
    }
    endpoint
}
