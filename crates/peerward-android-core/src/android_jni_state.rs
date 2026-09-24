use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicI64, Ordering},
    },
};

use jni::{
    JNIEnv, JavaVM,
    objects::{JByteArray, JClass, JObject, JString, JValue},
    sys::{jboolean, jbyteArray, jint, jlong},
};
use ed25519_dalek::{Signer, SigningKey};
use peerward_credentials::{
    AuthorityCertificate, DistributionCertificate, RootPublicKey, SubjectCredential, TrustSet,
};
use peerward_dataplane::parse_packet;
use peerward_directory::DirectoryPublicKey;
use peerward_service::ServiceSnapshotVerifier;
use peerward_types::{MeshId, UnixTime};
use peerward_wire::{
    ControlEnvelope, Keepalive, Record, WireError, control_envelope::Message as ControlMessage,
};
use prost::Message;
use rand::{RngCore, rngs::OsRng};
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{AcceptedUpdate, MobileError, MobileTrust, NativeSession, StaticDhProvider};

const KEY_HELPER: &str = "io/github/peerward/peerward/crypto/NativeKeyAgreement";
const MAX_JNI_BYTES: usize = 1_048_576;
const MAX_JNI_HANDLES: usize = 256;
const DIRECT_KEY: jint = 1;
const WRAPPED_KEY: jint = 2;
const MIN_WRAPPED_KEY: usize = 61;
const MAX_WRAPPED_KEY: usize = 480;
const MAX_IDENTITY_MESSAGE: usize = 4096;

struct AndroidKeyProvider {
    vm: Arc<JavaVM>,
    alias: String,
    public: [u8; 32],
    wrapped: Option<Vec<u8>>,
}

impl StaticDhProvider for AndroidKeyProvider {
    fn public_key(&self) -> [u8; 32] {
        self.public
    }

    fn agree(&self, remote_public: &[u8; 32]) -> Result<[u8; 32], MobileError> {
        let mut environment = self
            .vm
            .attach_current_thread()
            .map_err(|_| MobileError::KeyAgreement)?;
        let alias = environment
            .new_string(&self.alias)
            .map_err(|_| MobileError::KeyAgreement)?;
        let remote = environment
            .byte_array_from_slice(remote_public)
            .map_err(|_| MobileError::KeyAgreement)?;
        let alias_object = JObject::from(alias);
        let remote_object = JObject::from(remote);
        let value = if let Some(wrapped) = &self.wrapped {
            let public = environment
                .byte_array_from_slice(&self.public)
                .map_err(|_| MobileError::KeyAgreement)?;
            let wrapped = environment
                .byte_array_from_slice(wrapped)
                .map_err(|_| MobileError::KeyAgreement)?;
            let public_object = JObject::from(public);
            let wrapped_object = JObject::from(wrapped);
            environment.call_static_method(
                KEY_HELPER,
                "agreeWrapped",
                "(Ljava/lang/String;[B[B[B)[B",
                &[
                    JValue::Object(&alias_object),
                    JValue::Object(&public_object),
                    JValue::Object(&wrapped_object),
                    JValue::Object(&remote_object),
                ],
            )
        } else {
            environment.call_static_method(
                KEY_HELPER,
                "agree",
                "(Ljava/lang/String;[B)[B",
                &[
                    JValue::Object(&alias_object),
                    JValue::Object(&remote_object),
                ],
            )
        }
        .map_err(|_| MobileError::KeyAgreement)?;
        let value = value.l().map_err(|_| MobileError::KeyAgreement)?;
        let array = JByteArray::from(value);
        if environment.get_array_length(&array).map_err(|_| MobileError::KeyAgreement)? != 32 {
            return Err(MobileError::KeyAgreement);
        }
        let copied = environment
            .convert_byte_array(&array)
            .map(Zeroizing::new);
        // Erase the Java result even if copying failed; the Rust temporary is
        // also cleared after the fixed-size result has been transferred to Snow.
        let cleared = environment.set_byte_array_region(&array, 0, &[0_i8; 32]);
        let output = copied.map_err(|_| MobileError::KeyAgreement)?;
        cleared.map_err(|_| MobileError::KeyAgreement)?;
        output.as_slice().try_into().map_err(|_| MobileError::KeyAgreement)
    }
}

struct Entry {
    session: NativeSession,
    first_handshake: Option<Vec<u8>>,
}

static NEXT_HANDLE: AtomicI64 = AtomicI64::new(1);
static SESSIONS: OnceLock<Mutex<HashMap<i64, Entry>>> = OnceLock::new();

fn sessions() -> &'static Mutex<HashMap<i64, Entry>> {
    SESSIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn insert_jni_handle<T>(
    values: &Mutex<HashMap<i64, T>>,
    next: &AtomicI64,
    value: T,
    capacity: usize,
) -> Result<i64, MobileError> {
    let mut values = values.lock().map_err(|_| MobileError::InvalidState)?;
    if values.len() >= capacity {
        return Err(MobileError::InvalidState);
    }
    let handle = next.fetch_add(1, Ordering::Relaxed);
    if handle <= 0 {
        return Err(MobileError::InvalidState);
    }
    match values.entry(handle) {
        std::collections::hash_map::Entry::Vacant(entry) => {
            entry.insert(value);
            Ok(handle)
        }
        std::collections::hash_map::Entry::Occupied(_) => Err(MobileError::InvalidState),
    }
}

fn java_bytes(environment: &JNIEnv<'_>, value: &JByteArray<'_>) -> Result<Vec<u8>, MobileError> {
    let length = environment
        .get_array_length(value)
        .map_err(|_| MobileError::InvalidInput)?;
    if usize::try_from(length).map_err(|_| MobileError::InvalidInput)? > MAX_JNI_BYTES {
        return Err(MobileError::InvalidInput);
    }
    environment.convert_byte_array(value).map_err(|_| MobileError::InvalidInput)
}

fn java_secret32(environment: &JNIEnv<'_>, value: &JByteArray<'_>) -> Result<Zeroizing<[u8; 32]>, MobileError> {
    if environment.get_array_length(value).map_err(|_| MobileError::InvalidInput)? != 32 {
        return Err(MobileError::InvalidInput);
    }
    // Converting Vec directly into an array would release a heap allocation
    // containing an unzeroized seed/scalar, even if the array is later cleared.
    let bytes = Zeroizing::new(java_bytes(environment, value)?);
    bytes.as_slice().try_into().map(Zeroizing::new).map_err(|_| MobileError::InvalidInput)
}

fn fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N], MobileError> {
    bytes.try_into().map_err(|_| MobileError::InvalidInput)
}

fn output(environment: &JNIEnv<'_>, bytes: &[u8]) -> jbyteArray {
    environment
        .byte_array_from_slice(bytes)
        .map_or(std::ptr::null_mut(), JByteArray::into_raw)
}

fn fail(environment: &mut JNIEnv<'_>, error: &MobileError) {
    let exception = match error {
        MobileError::PolicyDenied | MobileError::Peer(peerward_peer_core::PeerError::PolicyDenied) => {
            "io/github/peerward/peerward/nativecore/PeerwardPacketDeniedException"
        }
        MobileError::InvalidInput => {
            "io/github/peerward/peerward/nativecore/PeerwardInvalidInputException"
        }
        MobileError::Credential(_) | MobileError::EnrollmentCredential(_, _)
        | MobileError::Wire(WireError::Authentication | WireError::Noise(snow::Error::Decrypt))
        | MobileError::Noise(snow::Error::Decrypt)
        | MobileError::Peer(peerward_peer_core::PeerError::Revoked
            | peerward_peer_core::PeerError::Credential(_)
            | peerward_peer_core::PeerError::Wire(WireError::Authentication | WireError::Noise(snow::Error::Decrypt))) => {
            "io/github/peerward/peerward/nativecore/PeerwardAuthenticationException"
        }
        _ => "io/github/peerward/peerward/nativecore/PeerwardNativeException",
    };
    let _ = environment.throw_new(
        exception,
        error.to_string(),
    );
}
