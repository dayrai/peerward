# Android client

The Android application uses namespace/application ID
`io.github.peerward.peerward` and accepts only validated `peerward://join` deep
links. Rust constructs the ticket-bound Join transcript and exact request JSON;
Kotlin performs only the `AndroidKeyStore` signature and HTTPS exchange. Rust
then verifies the invited Root SHA-256 fingerprint, Root-anchored Authority and
Peer credential, distribution certificate, Relay keys, routes, DNS and bounds
before the profile can be stored.

The Join screen can launch a non-exported CameraX scanner backed by ZXing. The
app declares camera access but requests it only while that scanner Activity is
visible. Decoding accepts QR format only, caps UTF-8 payloads at 16 KiB, and
fully validates the `peerward://join` scheme, bundle schema, HTTPS Control
origin, optional canonical Mesh UUIDv4, fingerprint, nonce, and expiry before
returning to the WebView. New Console QR bundles include the Mesh UUID, so the
confirmation view shows Control origin plus Mesh/Ticket summaries; older valid
bundles defer the Mesh display until claim. Scanning only stages the
invitation: the user must press the separate confirmation button before any
claim or profile mutation occurs. Permission denial and cancellation leave the
existing profile unchanged.

Each Peer has separate Ed25519 identity, Relay Noise X25519, and WireGuard
X25519 data keys. Relay key agreement uses AndroidKeyStore directly where
supported, with a wrapped-key fallback. Identity and independent WireGuard
material are AES-GCM wrapped under separate non-exportable AndroidKeyStore
aliases. The app-private record contains versioned metadata, public keys, IVs,
and ciphertext. Temporary unwrap copies are cleared after the native operation;
the WireGuard engine owns the live data key for its credential's lifetime.
Private material is never stored in plaintext profiles, logged, or sent over
the network.

The native session reports Android software version and supported capabilities
using the existing signed `DeviceEvidence` management command. It retries the
same request until acknowledged, refreshes acknowledged evidence every five
minutes, and reports again after reconnect or identity rotation. An Android
device advertises consumer and managed-DNS capabilities, not gateway support.
This is a signed device self-report, not hardware attestation. Expired evidence
does not prevent sending a fresh report through the authenticated management
channel; server-side device-condition policy still controls data access.

The durable profile is a strict, versioned opaque blob generated and decoded by
Rust, then AES-256-GCM wrapped under a non-exportable `AndroidKeyStore` key and
atomically written by Kotlin. The pre-blob development format is never migrated
or silently deleted: the UI requires an explicit stop-and-clear/rejoin flow.

Credential renewal generates fresh local identity, Relay, and WireGuard keys,
sends only public material over the authenticated Relay control channel, and
accepts a replacement only when its request ID, Peer identity, Mesh, all public
keys, validity, and Authority signature match. Pending rotation metadata
survives process restart. Activation, observation in the signed directory, and
atomic profile commit precede old-key cleanup; overlap is bounded by the
credential's trusted deadline.

Kotlin creates each control/data/DNS socket and calls `VpnService.protect()` and
`Network.bindSocket()`. A new Java `Socket` may not yet own a kernel FD, so the
Relay path first materializes it through a side-effect-free socket option,
verifies that `protect()` accepted the resulting descriptor, and only then
binds/connects. For Relay TCP it then returns a detached FD to Rust;
Rust owns blocking handshake/record framing and closes the FD. For protected
UDP/DNS operations Kotlin returns only bounded results against the exact native
request or one-shot token. The core performs rooted credential verification,
Noise IK, encrypted control framing/rekey, signed ordered updates, exact
revocation, and handle lifecycle. QUIC DATAGRAM and WSS carry opaque standard
WireGuard packets; WSS supports explicit HTTP CONNECT proxies. TLS protects
the carrier and does not replace Mesh/Peer admission checks.

The foreground `VpnService` executes TUN and protected-socket lifecycle requests
while Rust remains authoritative for the lifecycle phase, bounded reconnect
policy, one-second observation, ten-second keepalive, state-change/30-second
health-report cadence, authenticated session, signed state, policy, direct-path
and diagnostic readiness. Android sends observed platform events to a separate native runtime
coordinator; the Rust projection is the only source allowed to publish
`healthy`, `degraded`, or `reconnecting`. Generation fencing discards delayed
callbacks from a replaced packet pump. In particular, an authenticated Relay
alone is never “connected”: the UI remains degraded until the live Rust runtime
has accepted every required monotonic signed-state family. DNS packets
to the virtual Mesh gateway are intercepted before Relay routing: signed
Peer/Service answers and ACL visibility are decided in Rust; a Peer may resolve
its own signed name under default-deny, while every other Peer name remains
policy-gated. External
queries use protected Android UDP/TCP sockets. TCP DNS state, response
segmentation, retransmission, checksums, flow count, message size, and one-shot
resolver tokens are owned and bounded by Rust; Kotlin only performs the
protected upstream exchange. An upstream I/O or bounded-input failure returns
an empty platform result, which Rust turns into a bounded `SERVFAIL` instead of
terminating the VPN coroutine. Logout or revocation
closes sessions, clears TUN/routes, deletes encrypted profiles and wrapped key
records, and deletes both direct/wrapping Keystore aliases.

At the link-key soft boundary, Rust marks the authenticated transport due but
keeps it usable. The bounded Relay pool opens a fresh protected socket in
parallel, waits for the encrypted `link_ready` confirmation emitted after the
Relay installs the new presence fence, swaps the slot, and sends
`GracefulClose(link_rekey)` on the predecessor. The hard time/message boundary
still fails closed if no replacement has completed.

The Kotlin adapter registers a `ConnectivityManager.NetworkCallback`. Default-network,
availability, link-property, and DNS changes invalidate the old underlay and
rebuild protected Control, Relay, STUN, direct, and DNS sockets. The encrypted
profile and VPN interface remain authoritative while transport tasks use
Rust-owned reconnect backoff and authenticated Relay fallback. The native Relay
pool owns exactly three slots (one primary and up to two warm standbys),
primary/warm-standby selection, endpoint rotation, retry deadlines,
promotion, make-before-break refresh, and stale-result fencing. Kotlin executes
only the exact outstanding connect request and returns its protected FD/result.
Completion returns whether that exact generation accepted the result. A stale
permission callback is ignored; stale TUN and socket results close their local
resource immediately. An atomic write that already succeeded remains a durable
success even when a concurrent network change has fenced its observation.

After the request-ID `OPEN_TUN` result, JNI borrows and duplicates the TUN
`ParcelFileDescriptor` while Kotlin retains its original owner for the entire call.
Kotlin closes that original exactly once, including validation failures; Rust owns
only its duplicates. Rust owns reads, writes, packet validation and DNS
flow decisions; Kotlin never opens a TUN input/output stream. Credential
rotation is likewise a Rust transaction: Rust creates/replays the UUIDv4 plan,
validates public keys and replacement credential, and returns the complete
opaque profile or cleanup blob. Kotlin executes only request-ID Keystore and
atomic-persistence operations and never constructs or patches rotation JSON.
Protected DNS sockets remain a platform operation, while DNS flow and fallback
policy are native.

Android direct P2P uses the same protected UDP socket for bounded STUN
discovery and standard WireGuard packets. Rust owns the jittered refresh deadline,
transaction identifiers, response parsing, replay rejection, and exact-source
validation; Kotlin only sends and receives on the protected socket. An
encrypted profile may opt in with `symmetric_nat_prediction = true`. Rust then
requires at least three stable observations from distinct STUN servers, emits
only the bounded center-port ±2 set, applies the shared 30-second rate limit and
ten-minute failure cooldown. The setting defaults to false, and generating a
predicted candidate does not count as a successful direct connection.
Candidates are exchanged only through the WireGuard-encrypted internal
coordination channel. Candidate changes advance path state while retaining the
WireGuard session. An authenticated round trip on the actual direct path is
required before selecting it; receiving through a Relay never proves a direct
address reachable. Default inner MTU is 1280, with bounded path checks and
Relay fallback when a direct path cannot carry the packet.
With the default `nat_mapping = "auto"`, Android resolves the selected
underlay's default gateway and tries PCP, NAT-PMP, then UPnP. PCP and NAT-PMP
reuse the exact direct UDP socket and internal port already protected with
`VpnService.protect()` and pinned with `Network.bindSocket()`; no Rust-owned
Android network socket is created. Rust owns their fixed-size codecs, PCP nonce,
strict response validation, lease lifetime, and gateway-epoch restart check.
UPnP needs SSDP multicast plus HTTP control connections, so Kotlin creates each
of those sockets explicitly, protects and binds it before the first send or
connect, bounds discovery/HTTP/XML input, and accepts a numeric `LOCATION` only
from the current gateway. Renewal rereads the external address; cancellation
and absolute I/O deadlines close blocked sockets. Leases renew around their half-life with
jitter, are withdrawn before rediscovery, and are best-effort deleted on normal
shutdown. An underlay/link-property change rebuilds the direct socket and mapping;
`nat_mapping = "off"` disables the controller. Mapping failure always preserves
the authenticated Relay fallback.
The native core binds the independent WireGuard public key to the exact signed
Peer credential, rejects replay, confirms direct paths with authenticated
round trips, drives WireGuard timers independently of Relay availability, and falls back to the
authenticated primary/warm-standby Relay pool in the same send attempt when a
direct path is unavailable. The release gate still requires the complete
physical NAT matrix; unit, emulator, or host-native tests alone do not satisfy
the 1.0 release gate.

Build with Java 17, Android SDK 36, Rust Android targets, and cargo-ndk:

```sh
cd apps/peerward-android
./gradlew lintDebug testDebugUnitTest assembleDebug assembleDebugAndroidTest buildPeerwardNativeRelease
./gradlew connectedDebugAndroidTest
```

Debug and release native libraries have separate Gradle tasks and output roots:
`buildPeerwardNativeDebug` uses Cargo's development profile under
`app/build/generated/peerwardJni/debug`, while `buildPeerwardNativeRelease`
uses `cargo ndk build --release --locked` under the corresponding `release`
directory. Each Android source set consumes only its own directory, and every
APK/AAB is restricted to `arm64-v8a` and `x86_64` for the complete package (not
only the Peerward library). A variant build first deletes its generated native
root, so a prior build cannot leave a stale cross-profile library behind. Run
`scripts/verify-android-native-artifacts.py` against an APK or AAB to require
that exact two-ABI inventory and compare the packaged Peerward libraries
byte-for-byte with that variant's generated libraries.
`scripts/verify.sh android` always verifies the Debug package and Release native
outputs. When all four release-signing environment variables are present it
also builds and verifies the Release APK/AAB. The local `standard` gate supplies
a fresh one-day verification certificate when no signing variables are set;
this exercises packaging without creating publishable release evidence.
`scripts/release-local.sh artifacts` instead requires the protected product
keystore and rebuilds the artifacts from a clean commit.

The workspace denies unsafe Rust. Its documented platform/JNI exceptions and
export attributes are pinned by `scripts/check-unsafe-boundary.py`. Expanding or
moving that inventory fails normal verification and requires a focused safety
review.

The Wire 5 management bridge adds two reviewed exports in
`android_jni_management.rs`. The transcript is constructed by the authenticated
native session from its active configuration; Kotlin cannot supply a different
receipt or device identity. Completion accepts exactly a 64-byte Ed25519
signature and verifies it against the current credential before encoding the
control message. Both entry points use the existing bounded byte-array helpers
and session mutex. They add no raw pointer dereferences or ownership transfers;
invalid handles, timestamps and signatures return the existing JNI errors.

`android_jni_rotation.rs` additionally exposes the read-only `nativeRotationDue`
decision. It accepts only a session handle and nonnegative wall-clock seconds,
holds the existing session mutex and returns a boolean. It uses no raw pointers
or ownership transfers. Kotlin checks this Rust decision before creating a
Keystore identity or rotation journal; request construction checks the same
signed command/window again. Reconnecting with a fresh credential therefore
does not stage an unrequested rotation. The JNI export inventory includes this
entry point; the unsafe-block inventory is unchanged.

`android_jni_runtime.rs` also exposes `nativeDiagnostics`. It accepts an existing
lifecycle handle, nonnegative observation time and at most 128 bytes of a stable
platform error code. The shared Rust lifecycle produces bounded JSON observations
with reason codes, original observation times and retry hints. It neither parses
exception messages nor transfers pointers or descriptors. Typed credential/Noise
authentication errors use `PeerwardAuthenticationException`; a failed connection
is projected only after its generation is accepted by the Relay pool. Preference
and VPN-protection renders cannot clear a failure or refresh its evidence time.
JNI tests cover input limits, permission guidance and late callbacks after failure.

`scripts/run-android-emulator.sh 28|36` creates a fresh, headless x86_64 AVD,
prints the actual WebView provider and runs the connected scenario against a
fresh isolated PostgreSQL 18 database and real Control/Relay processes. It uses
the separate validation application and generated one-time enrollment material;
`scripts/test-android-wireguard.py` records the tested APK and backend hashes.
For a debuggable `google_apis` image, the wrapper synchronizes only its own new
AVD's clock to the host before installing an identity. The gate records clock
observations throughout; physical-device clocks and credential time validation
are unchanged. The local target accepts the system VPN permission, joins the
real Control, authenticates the Relay, and checks renewal, recovery and cleanup. The
debug manifest alone permits cleartext loopback traffic for this emulator gate;
the release manifest continues to require encrypted transport. The local
release assembler requires a protected keystore, builds both AAB and APK, and
verifies both signatures before publishing any artifact.

An earlier pre-Wire 4 API 36 `google_apis` run, with Chromium WebView 133, completed
16 instrumented scenarios. Its API 28 Play Store image was
frozen at WebView 69: it lacked the secure WebView message-listener capability
and cannot parse the current wasm-bindgen output (`externref`). Peerward fails
closed on that provider instead of enabling an insecure JavaScript interface.
Consequently, API 28 remains an explicitly failing compatibility target until
the lab provides an API 28 device/image with an updated supported WebView, or
the UI toolchain produces and tests an equivalent legacy-compatible bundle.
`minSdk = 28` describes Android API compatibility; it must not be presented as
proof that every system-image WebView shipped with API 28 can execute the UI.

Use the isolated Wire 5 runner with an explicitly selected handset and a LAN
address reachable from its Wi-Fi network:

```sh
ANDROID_HOME=/path/to/sdk scripts/run-android-physical.sh \
  --serial DEVICE_SERIAL --lan-address HOST_LAN_IPV4 \
  --relay-carrier quic --tun-peer --network-attempts 100
```

The wrapper builds only the separate validation application. It creates a fresh
PostgreSQL/Control/Relay backend, uses ADB reverse only for enrollment, and tests
Relay/data traffic through protected sockets on the real Android Network.
It never reads the live root `.env` or clears the normal application profile.
The old `--network-profile`, `--passed-scenario`, `--artifact-set-sha256` and
`--no-evidence` runner flags are retired; observed successes, failures, APK hashes
and backend hashes are always saved. `--power-seconds 60 --restart-process
--os-revoke` adds deep Doze, stored-key process recovery and actual OS VPN
revocation. `--reboot-device` additionally requires the user to unlock the phone
after boot. These are local observations, not an independently signed release
gate. For `scripts/local-ci.sh android-target`, set `ANDROID_SERIAL` and
`PEERWARD_ANDROID_LAN_ADDRESS` explicitly for a physical device.

Add `--console-ui` to issue the administrative credential renewal from a real
browser device drawer in a disposable SSR/WASM Console. It checks exact-request
retry, trusted device completion and persistence after reloading, retaining
screenshots and `console-browser-renewal.json`. The admin credential remains in
the host process; the browser and phone do not receive it. With `--tun-peer`,
the runner also checks actual UDP echoes after interrupted-rotation recovery,
before entering Doze, so a credential result cannot hide a broken data path.
System VPN permission revocation stops the live TUN/WireGuard owner and preserves
the enrolled profile and Keystore keys. Deleting those requires explicit local
profile removal or an authenticated Mesh termination. The revocation fixture
returns from the separate test APK to the product Activity for its assertions.

Physical-device reports must bind native tests, browser-initiated renewal,
Linux/Android TUN echoes, Wi-Fi recovery, interrupted rotation, Doze, process
restart and OS VPN revocation to the tested APK. Generate fresh reports with the
physical runner above; throughput, battery, public Internet and long-duration
acceptance remain separate checks. See [implementation status](status.zh-CN.md).

After restart or suspend, a device cannot reactivate a persisted authorization
lease by replaying it. A signed Core rejection with reason
`fresh_authorization_required` requests a new lease; Control coalesces requests
for the current sequence without changing its configuration. Android readiness
also requires live data authorization, not only complete distribution chunks.

The default runner executes native/platform tests and the isolated product
scenario in separate processes. `--backend-only` runs the latter alone and
explicitly leaves native/platform acceptance unclaimed; it cannot erase a
failed full run. Stored-key recovery models the user opening the app after
process death or reboot. Its driver opens the validation Activity at process
creation, before waiting for test progress; this does not establish unattended
background boot recovery. Diagnostic intervention during a stalled run is
recorded separately and disqualifies that run from unattended acceptance.

The following paragraph records the earlier pre-Wire 4 local run. Current
implementation and evidence are tracked in
[the gap closure record](analysis/wireguard-gap-closure.zh-CN.md).

That earlier local physical regression used an OPPO PFEM10 running API 36 with
security patch 2026-06-01. All 16 instrumented tests passed with no skips,
including real Join/Relay/signed state and self Mesh DNS, airplane-mode
recovery, disconnect/cleanup, Keystore persistence and rotation, three Relay
slots, TUN, STUN, PCP/NAT-PMP and raw-FD closure. This is a recorded local
verification result only: it is unsigned, covers one handset/API/network setup,
and therefore leaves `android_physical_matrix` explicitly `missing`.
