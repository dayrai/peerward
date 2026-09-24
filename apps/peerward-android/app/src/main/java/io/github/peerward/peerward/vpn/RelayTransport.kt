package io.github.peerward.peerward.vpn

import android.os.SystemClock
import android.net.Network
import android.util.Log
import io.github.peerward.peerward.BuildConfig
import io.github.peerward.peerward.crypto.DeviceKeyStore
import io.github.peerward.peerward.nativecore.NativePeerCore
import io.github.peerward.peerward.nativecore.NativePlatformOperation
import io.github.peerward.peerward.nativecore.NativeRelaySocket
import io.github.peerward.peerward.nativecore.NativeSessionConfig
import io.github.peerward.peerward.nativecore.NativeRuntimeStatus
import io.github.peerward.peerward.nativecore.NativeWireguardRuntime
import io.github.peerward.peerward.nativecore.NativeTunPacketPump
import io.github.peerward.peerward.net.DatagramProtector
import io.github.peerward.peerward.net.SocketProtector
import io.github.peerward.peerward.profile.PeerProfile
import io.github.peerward.peerward.runtime.MobileRuntimeState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.isActive
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Inet4Address
import java.net.InetAddress
import java.net.Socket
import java.net.DatagramSocket
import java.net.URI
import java.nio.ByteBuffer
import java.util.Base64
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong

interface PacketTransport : AutoCloseable {
    suspend fun send(packet: ByteArray)
    suspend fun receive(): ByteArray
    suspend fun sendWireguard(ticket: Long): Boolean = false
    fun writeInbound(packet: ByteArray, tun: NativeTunPacketPump) = tun.writeInbound(packet)
    suspend fun awaitStopped() = Unit
    suspend fun keepalive(timestamp: Long) = Unit
    suspend fun reportHealth() = Unit
    fun replacementDue(): Boolean = false
    fun closeForReplacement() = close()
    suspend fun resolveDns(query: ByteArray, sourceAddress: ByteArray, suffix: String): ByteArray? = null
    suspend fun managedDnsRoute(query: ByteArray, sourceAddress: ByteArray): io.github.peerward.peerward.nativecore.ManagedDnsRoute? = null
    fun dnsConfigurationActive(version: Long, sourceAddress: ByteArray): Boolean = false
    fun runtimeStatus(): NativeRuntimeStatus? = null
}

fun interface PacketTransportFactory {
    suspend fun connect(endpoint: String, profile: PeerProfile): PacketTransport
    suspend fun connectAny(endpoints: List<String>, profile: PeerProfile): PacketTransport = connect(endpoints.first(), profile)
}

/**
 * Exact Peerward Noise IK/Prost record adapter. Kotlin creates, protects and
 * binds the raw socket; Rust takes its FD and owns blocking framing from then on.
 */
class NoiseRelayTransport private constructor(
    private val relaySocket: NativeRelaySocket,
    private val native: NativePeerCore,
    private val wireguard: NativeWireguardRuntime,
    private val onCredentialReplacement: (ByteArray) -> ByteArray,
    private val onCredentialActivated: (ByteArray) -> Unit,
    private val onCredentialRenewal: () -> ByteArray?,
    private val onMeshTerminated: (ByteArray) -> Unit,
    private val onAuthorityUpdate: (Long, List<ByteArray>) -> Unit,
    private val signAudit: (ByteArray) -> ByteArray,
    private val relayCarrier: String,
) : PacketTransport {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val inbound = Channel<ByteArray>(256)
    private val healthSequence = AtomicLong(System.currentTimeMillis().coerceAtLeast(1) * 1_000)

    init {
        scope.launch { readRelayRecords() }
    }

    override suspend fun send(packet: ByteArray) { error("TUN packets belong to the Mesh WireGuard runtime") }

    override suspend fun sendWireguard(ticket: Long): Boolean = withContext(Dispatchers.IO) {
        wireguard.writeRelay(ticket, relaySocket, native)
    }

    override suspend fun receive(): ByteArray = inbound.receive()

    @Synchronized override fun runtimeStatus(): NativeRuntimeStatus? {
        if (!scope.isActive) return null
        return native.runtimeStatus().copy(
            directPathCount = wireguard.directPathCount(),
            primaryRelayAuthenticated = true,
            relayCarrier = relayCarrier,
        )
    }

    override suspend fun keepalive(timestamp: Long) = withContext(Dispatchers.IO) {
        val frame = native.keepalive(timestamp, monotonicSeconds())
        writeFrame(frame)
        native.auditTranscript().takeIf(ByteArray::isNotEmpty)?.let { transcript ->
            sendControl(native.completeAudit(signAudit(transcript)))
        }
        Unit
    }

    override suspend fun reportHealth() = withContext(Dispatchers.IO) {
        val directCount = wireguard.directPathCount()
        val directTotal = wireguard.directPackets.get()
        val relayTotal = wireguard.relayPackets.get()
        val runtime = native.runtimeStatus()
        val degradedMask = if (runtime.signedStateComplete) 0 else SIGNED_STATE_INCOMPLETE_MASK
        val transcript = native.healthTranscript(
            healthSequence.incrementAndGet(), directCount, relayTotal, directTotal,
            degradedMask, runtime.signedRevision,
        )
        sendControl(native.completeHealth(signAudit(transcript)))
        native.managementTranscript().takeIf(ByteArray::isNotEmpty)?.let { receipt ->
            sendControl(native.completeManagement(signAudit(receipt)))
        }
        Unit
    }

    override fun replacementDue(): Boolean = native.linkReplacementDue(monotonicSeconds())

    override fun closeForReplacement() {
        runCatching { writeFrame(native.linkClose(monotonicSeconds())) }
        close()
    }

    private suspend fun readRelayRecords() {
        try {
            while (scope.isActive) {
                val frame = relaySocket.readFrame()
                val record = native.decrypt(frame, monotonicSeconds())
                when (record.kind) {
                    2, 3 -> error("raw Relay IP records are forbidden")
                    1 -> {
                        if (record.updateKind == 9) {
                            onMeshTerminated(record.payload)
                            close()
                            return
                        } else if (record.updateKind == CREDENTIAL_REPLACEMENT) {
                            val signature = onCredentialReplacement(record.payload)
                            sendControl(native.rotationActivation(signature))
                        } else if (record.updateKind == 10) {
                            // Rust already checked the rooted signature, target serial and deadline.
                            // Reuse the same Keystore/profile journal as automatic renewal.
                            onCredentialRenewal()?.let { sendControl(it) }
                        } else if (record.updateKind == CREDENTIAL_ACTIVATED) {
                            onCredentialActivated(record.payload)
                        } else if (record.updateKind == AUTHORITY_UPDATE) {
                            val input = ByteBuffer.wrap(record.payload)
                            require(input.remaining() >= 10) { "Authority update is truncated" }
                            val revision = input.long
                            val count = input.short.toInt() and 0xffff
                            require(count in 1..9 && input.remaining() == count * AUTHORITY_CERTIFICATE_SIZE) {
                                "Authority update certificate set is invalid"
                            }
                            val certificates = List(count) {
                                ByteArray(AUTHORITY_CERTIFICATE_SIZE).also(input::get)
                            }
                            onAuthorityUpdate(revision, certificates)
                        }
                    }
                    else -> error("native returned an unknown record kind")
                }
            }
        } catch (error: Exception) {
            if (scope.isActive) {
                logFailure("record-read", error)
                inbound.close(error)
            } else {
                inbound.close()
            }
        }
    }

    private fun sendControl(envelope: ByteArray) {
        writeFrame(native.encryptControl(envelope, monotonicSeconds()))
    }

    private fun writeFrame(frame: ByteArray) {
        relaySocket.writeFrame(frame)
    }

    override suspend fun resolveDns(query: ByteArray, sourceAddress: ByteArray, suffix: String): ByteArray =
        withContext(Dispatchers.Default) { native.resolveDns(query, sourceAddress, suffix) }

    @Synchronized override fun close() {
        scope.cancel()
        relaySocket.close()
        inbound.close()
        native.close()
    }

    companion object {
        const val MAX_PACKET = 65_535
        private const val CREDENTIAL_REPLACEMENT = 6
        private const val AUTHORITY_UPDATE = 7
        private const val CREDENTIAL_ACTIVATED = 8
        private const val AUTHORITY_CERTIFICATE_SIZE = 144
        private const val SIGNED_STATE_INCOMPLETE_MASK = 1L shl 1
        private const val TRACE_CONTEXT_V1_CAPABILITY = 1L shl 0
        private const val EXTENDED_CANDIDATES_V1_CAPABILITY = 1L shl 1
        private const val SPARSE_BACKBONE_V1_CAPABILITY = 1L shl 2
        private const val CREDENTIAL_RENEWAL_V1_CAPABILITY = 1L shl 3
        private const val PRIMARY_ATTACHMENT_CAPABILITY = Long.MIN_VALUE
        private const val SUPPORTED_WIRE_CAPABILITIES =
            TRACE_CONTEXT_V1_CAPABILITY or
                EXTENDED_CANDIDATES_V1_CAPABILITY or
                SPARSE_BACKBONE_V1_CAPABILITY or
                CREDENTIAL_RENEWAL_V1_CAPABILITY
        private val decoder = Base64.getUrlDecoder()

        fun factory(
            protector: SocketProtector,
            datagramProtector: DatagramProtector,
            keys: DeviceKeyStore,
            rotation: CredentialRotationCoordinator,
            wireguard: NativeWireguardRuntime,
            network: Network,
            gatewayAddresses: List<InetAddress>,
            recoveryOnly: Boolean = false,
        ): PacketTransportFactory =
            object : PacketTransportFactory {
                override suspend fun connect(endpoint: String, profile: PeerProfile): PacketTransport = connectAny(listOf(endpoint), profile)
                override suspend fun connectAny(endpoints: List<String>, profile: PeerProfile): PacketTransport =
                    withContext(Dispatchers.IO) {
                        connect(endpoints, profile, protector, datagramProtector, keys, rotation, wireguard, network, gatewayAddresses, recoveryOnly)
                    }
            }

        private suspend fun connect(
            endpoints: List<String>,
            profile: PeerProfile,
            protector: SocketProtector,
            datagramProtector: DatagramProtector,
            keys: DeviceKeyStore,
            rotation: CredentialRotationCoordinator,
            wireguard: NativeWireguardRuntime,
            network: Network,
            gatewayAddresses: List<InetAddress>,
            recoveryOnly: Boolean,
        ): PacketTransport {
            rotation.assertMeshActive()
            var stage = "profile-validation"
            val endpoint = endpoints.first()
            val relays = profile.relayTargets()
            val relayIndex = relays.indexOfFirst { endpoint in it.endpoints }
            require(relayIndex >= 0 && endpoints.all { it in relays[relayIndex].endpoints })
            require(relayIndex >= 0 && relays[relayIndex].noisePublicKey.isNotEmpty()) {
                "relay endpoint has no authenticated Noise key"
            }
            val uri = URI(endpoint)
            require((uri.scheme in setOf("tcp", "quic", "wss")) && uri.host != null && uri.userInfo == null && uri.fragment == null) {
                "relay endpoint must use QUIC, WSS or TCP"
            }
            val deadline = ConnectionDeadline(if (recoveryOnly) 3_000 else 10_000)
            var relaySocket: NativeRelaySocket? = null
            var nativeOwner: NativePeerCore? = null
            try {
                stage = "carrier-connect"
                val (selectedEndpoint, nativeSocket) = kotlinx.coroutines.withTimeout(if (recoveryOnly) 3_000L else 10_000L) {
                    dialRelayCarriers(endpoints, profile, network, protector, datagramProtector).also {
                        relaySocket = it.second
                        deadline.adopt(it.second)
                    }
                }
                relaySocket = nativeSocket
                deadline.adopt(nativeSocket)
                val context = currentCoroutineContext()
                return carrierBlocking(AutoCloseable { deadline.abort() }, onAbandoned = { it: NoiseRelayTransport -> it.close() }) {
                    try {
                        context.ensureActive()
                stage = "noise-initialization"
                val native = NativePeerCore(nativeConfig(profile, relayIndex, keys), wireguard)
                nativeOwner = native
                stage = "noise-handshake-write"
                val first = native.firstHandshake()
                nativeSocket.writeHandshake(first)
                stage = "noise-handshake-read"
                val response = nativeSocket.readHandshake()
                stage = "noise-handshake-finish"
                native.finishHandshake(response, monotonicSeconds())
                if (response.size == 228 && response.copyOfRange(0, 4).contentEquals("PWM1".toByteArray())) {
                    if (URI(selectedEndpoint).scheme == "quic") nativeSocket.acknowledgeTerminal()
                    rotation.terminateMesh(response)
                    native.close()
                    error("mesh_deleted")
                }
                context.ensureActive()
                stage = "carrier-binding"
                nativeSocket.activate(native, monotonicSeconds())
                stage = "link-confirmation"
                native.confirmLink(nativeSocket.readFrame(), monotonicSeconds())
                stage = "credential-rotation"
                if (!recoveryOnly) rotation.authenticated(profile)
                fun renewalRequest(): ByteArray? {
                    if (!native.rotationDue()) return null
                    val material = rotation.pendingMaterial()
                    val transcript = native.rotationRequestTranscript(
                        material.requestId,
                        material.identityPublicKey,
                        material.sessionPublicKey,
                        material.wireguardPublicKey,
                    )
                    val signature = rotation.signCurrent(transcript)
                    return native.rotationRequest(
                        material.requestId,
                        material.identityPublicKey,
                        material.sessionPublicKey,
                        material.wireguardPublicKey,
                        signature,
                    )
                }
                if (relayIndex == 0 && !recoveryOnly) {
                    renewalRequest()?.let { request ->
                        nativeSocket.writeFrame(native.encryptControl(request, monotonicSeconds()))
                    }
                }
                NoiseRelayTransport(
                    nativeSocket,
                    native,
                    wireguard,
                    { update -> rotation.acceptReplacement(update, wireguard) },
                    rotation::commitActivated,
                    ::renewalRequest,
                    rotation::terminateMesh,
                    rotation::installAuthorities,
                    { transcript -> keys.sign(profile.deviceKeyId, transcript) },
                    selectedEndpoint.substringBefore("://"),
                )
                    } catch (error: Exception) {
                        nativeSocket.close()
                        nativeOwner?.close()
                        throw error
                    }
                }
            } catch (error: Exception) {
                relaySocket?.close()
                nativeOwner?.close()
                logFailure(stage, error)
                throw error
            } finally {
                deadline.close()
            }
        }

        internal fun nativeConfig(profile: PeerProfile, relayIndex: Int, keys: DeviceKeyStore): NativeSessionConfig {
            val key = keys.handle(profile.deviceKeyId)
            require(decode32(profile.localNoisePublic).contentEquals(key.noiseX25519)) {
                "profile and device Noise key do not match"
            }
            require(decode32(profile.localIdentityPublic).contentEquals(key.identityEd25519)) {
                "profile and device identity key do not match"
            }
            require(decode32(profile.localWireguardPublic).contentEquals(key.wireguardX25519)) {
                "profile and device WireGuard key do not match"
            }
            val authorities = profile.authorityCertificates
                .map(decoder::decode)
                .onEach { require(it.size == 144) }
                .fold(ByteArray(0)) { current, next -> current + next }
            return NativeSessionConfig(
                keyAlias = key.keyAlias,
                keyMode = key.mode,
                wrappedKeyMaterial = key.wrappedMaterial,
                localIdentityPublic = key.identityEd25519,
                localNoisePublic = key.noiseX25519,
                remoteNoisePublic = decode32(profile.relayTargets()[relayIndex].noisePublicKey),
                remoteRelayId = uuidBytes(UUID.fromString(profile.relayTargets()[relayIndex].relayId)),
                credential = decoder.decode(profile.credential),
                attachmentId = uuidBytes(UUID.randomUUID()),
                rootPublic = decode32(profile.rootPublicKey),
                meshId = uuidBytes(UUID.fromString(profile.meshId)),
                authorityCertificates = authorities,
                authorityRevision = profile.authorityRevision,
                distributionPublic = decode32(profile.distributionPublicKey),
                servicePublic = decode32(profile.servicePublicKey),
                auditPublic = decode32(profile.auditPublicKey),
                distributionCertificate = decoder.decode(profile.distributionCertificate)
                    .also { require(it.size == 208) },
                capabilities = if (relayIndex == 0) {
                    PRIMARY_ATTACHMENT_CAPABILITY or SUPPORTED_WIRE_CAPABILITIES
                } else {
                    SUPPORTED_WIRE_CAPABILITIES
                },
            )
        }

        private fun decode32(encoded: String): ByteArray = decoder.decode(encoded).also { require(it.size == 32) }

        private fun uuidBytes(uuid: UUID): ByteArray = ByteBuffer.allocate(16)
            .putLong(uuid.mostSignificantBits)
            .putLong(uuid.leastSignificantBits)
            .array()

        fun isIpPacket(packet: ByteArray): Boolean = when (packet.firstOrNull()?.toInt()?.ushr(4)?.and(0x0f)) {
            4 -> packet.size >= 20 && (((packet[2].toInt() and 0xff) shl 8) or
                (packet[3].toInt() and 0xff)) == packet.size
            6 -> packet.size >= 40 && (((packet[4].toInt() and 0xff) shl 8) or
                (packet[5].toInt() and 0xff)) + 40 == packet.size
            else -> false
        }

        private fun monotonicSeconds(): Long = SystemClock.elapsedRealtime() / 1_000

        private const val LOG_TAG = "PeerwardRelay"

        private fun logFailure(stage: String, error: Throwable) {
            if (BuildConfig.DEBUG) {
                Log.w(LOG_TAG, "Relay attachment failed at $stage", error)
            } else {
                Log.w(LOG_TAG, "Relay attachment failed at $stage (${error.javaClass.simpleName})")
            }
        }
    }
}
