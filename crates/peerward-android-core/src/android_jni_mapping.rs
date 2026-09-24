use peerward_p2p::{
    MappingLease, MappingProtocol, NAT_PMP_PUBLIC_ADDRESS_REQUEST, NatPmpMappingRequest,
    PcpMappingRequest, accept_nat_pmp_public_address, gateway_epoch_restarted,
};

const MAPPING_RECORD_VERSION: u8 = 1;

fn mapping_lifetime(value: jlong) -> Result<u32, MobileError> {
    u32::try_from(value).map_err(|_| MobileError::InvalidInput)
}

fn mapping_nonce(
    environment: &JNIEnv<'_>,
    value: &JByteArray<'_>,
) -> Result<Option<[u8; 12]>, MobileError> {
    let bytes = java_bytes(environment, value)?;
    match bytes.as_slice() {
        [] => Ok(None),
        bytes => Ok(Some(
            bytes.try_into().map_err(|_| MobileError::InvalidInput)?,
        )),
    }
}

fn encode_mapping_lease(lease: &MappingLease) -> Result<Vec<u8>, MobileError> {
    let address = match lease.external.ip() {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    };
    let protocol = match lease.protocol {
        MappingProtocol::Pcp => 1,
        MappingProtocol::NatPmp => 2,
        MappingProtocol::Upnp => return Err(MobileError::InvalidState),
    };
    let mut bytes = Vec::with_capacity(13 + address.len());
    bytes.push(MAPPING_RECORD_VERSION);
    bytes.push(protocol);
    bytes.push(u8::try_from(address.len()).map_err(|_| MobileError::InvalidState)?);
    bytes.extend_from_slice(&address);
    bytes.extend_from_slice(&lease.external.port().to_be_bytes());
    bytes.extend_from_slice(&lease.lifetime_seconds.to_be_bytes());
    bytes.extend_from_slice(&lease.epoch.unwrap_or(0).to_be_bytes());
    Ok(bytes)
}

fn mapping_output(environment: &JNIEnv<'_>, result: Result<Vec<u8>, MobileError>) -> jbyteArray {
    output(environment, &result.unwrap_or_default())
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePortMappingCodec_nativePcpRequest(
    environment: JNIEnv<'_>,
    _class: JClass<'_>,
    internal_address: JByteArray<'_>,
    internal_port: jint,
    lifetime: jlong,
    nonce: JByteArray<'_>,
    external_address: JByteArray<'_>,
    external_port: jint,
) -> jbyteArray {
    let result = (|| {
        let internal =
            socket_address(&java_bytes(&environment, &internal_address)?, internal_port)?;
        let mut request = PcpMappingRequest::new(
            internal,
            mapping_lifetime(lifetime)?,
            mapping_nonce(&environment, &nonce)?,
        )?;
        let external = java_bytes(&environment, &external_address)?;
        if !external.is_empty() {
            request = request.suggest_external(socket_address(&external, external_port)?);
        }
        let mut bytes = Vec::with_capacity(73);
        bytes.push(MAPPING_RECORD_VERSION);
        bytes.extend_from_slice(&request.nonce());
        bytes.extend_from_slice(request.bytes());
        Ok(bytes)
    })();
    mapping_output(&environment, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePortMappingCodec_nativePcpAccept(
    environment: JNIEnv<'_>,
    _class: JClass<'_>,
    internal_address: JByteArray<'_>,
    internal_port: jint,
    nonce: JByteArray<'_>,
    response: JByteArray<'_>,
    deleting: jboolean,
) -> jbyteArray {
    let result = (|| {
        let internal =
            socket_address(&java_bytes(&environment, &internal_address)?, internal_port)?;
        let nonce = mapping_nonce(&environment, &nonce)?.ok_or(MobileError::InvalidInput)?;
        let request = PcpMappingRequest::new(internal, u32::from(deleting == 0), Some(nonce))?;
        let lease = request.accept(&java_bytes(&environment, &response)?)?;
        encode_mapping_lease(&lease)
    })();
    mapping_output(&environment, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePortMappingCodec_nativeNatPmpPublicAccept(
    environment: JNIEnv<'_>,
    _class: JClass<'_>,
    response: JByteArray<'_>,
) -> jbyteArray {
    let result = (|| {
        let (address, epoch) =
            accept_nat_pmp_public_address(&java_bytes(&environment, &response)?)?;
        let mut bytes = Vec::with_capacity(9);
        bytes.push(MAPPING_RECORD_VERSION);
        bytes.extend_from_slice(&address.octets());
        bytes.extend_from_slice(&epoch.to_be_bytes());
        Ok(bytes)
    })();
    mapping_output(&environment, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePortMappingCodec_nativeNatPmpRequest(
    environment: JNIEnv<'_>,
    _class: JClass<'_>,
    internal_address: JByteArray<'_>,
    internal_port: jint,
    lifetime: jlong,
    external_port: jint,
) -> jbyteArray {
    let result = (|| {
        let internal =
            socket_address(&java_bytes(&environment, &internal_address)?, internal_port)?;
        let request = NatPmpMappingRequest::new(internal, mapping_lifetime(lifetime)?)?;
        let port = u16::try_from(external_port).map_err(|_| MobileError::InvalidInput)?;
        Ok(request.suggest_external_port(port).bytes().to_vec())
    })();
    mapping_output(&environment, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePortMappingCodec_nativeNatPmpAccept(
    environment: JNIEnv<'_>,
    _class: JClass<'_>,
    internal_address: JByteArray<'_>,
    internal_port: jint,
    external_address: JByteArray<'_>,
    response: JByteArray<'_>,
    deleting: jboolean,
) -> jbyteArray {
    let result = (|| {
        let internal =
            socket_address(&java_bytes(&environment, &internal_address)?, internal_port)?;
        let [a, b, c, d] = java_bytes(&environment, &external_address)?[..] else {
            return Err(MobileError::InvalidInput);
        };
        let request = NatPmpMappingRequest::new(internal, u32::from(deleting == 0))?;
        let lease = request.accept(
            &java_bytes(&environment, &response)?,
            Ipv4Addr::new(a, b, c, d),
        )?;
        encode_mapping_lease(&lease)
    })();
    mapping_output(&environment, result)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePortMappingCodec_nativeGatewayRestarted(
    _environment: JNIEnv<'_>,
    _class: JClass<'_>,
    previous: jint,
    current: jint,
) -> jboolean {
    jboolean::from(gateway_epoch_restarted(
        Some(previous.cast_unsigned()),
        Some(current.cast_unsigned()),
    ))
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_io_github_peerward_peerward_nativecore_NativePortMappingCodec_nativeNatPmpPublicRequest(
    environment: JNIEnv<'_>,
    _class: JClass<'_>,
) -> jbyteArray {
    output(&environment, &NAT_PMP_PUBLIC_ADDRESS_REQUEST)
}
