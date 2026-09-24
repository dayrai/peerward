package io.github.peerward.peerward.nativecore

import java.io.Closeable
import java.time.Instant
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicLong

open class PeerwardNativeException(message: String) : Exception(message)
class PeerwardInvalidInputException(message: String) : PeerwardNativeException(message)
class PeerwardAuthenticationException(message: String) : PeerwardNativeException(message)
class PeerwardPacketDeniedException(message: String) : Exception(message)

data class NativeSessionConfig(
    val keyAlias: String,
    val keyMode: Int,
    val wrappedKeyMaterial: ByteArray,
    val localIdentityPublic: ByteArray,
    val localNoisePublic: ByteArray,
    val remoteNoisePublic: ByteArray,
    val remoteRelayId: ByteArray,
    val credential: ByteArray,
    val attachmentId: ByteArray,
    val rootPublic: ByteArray,
    val meshId: ByteArray,
    val authorityCertificates: ByteArray,
    val authorityRevision: Long,
    val distributionPublic: ByteArray,
    val servicePublic: ByteArray,
    val auditPublic: ByteArray,
    val distributionCertificate: ByteArray,
    val capabilities: Long,
)

data class NativeRecord(val kind: Int, val updateKind: Int, val payload: ByteArray)
data class NativeRuntimeStatus(
    val signedStateComplete: Boolean,
    val signedRevision: Long,
    val directPathCount: Int = 0,
    val primaryRelayAuthenticated: Boolean = false,
    val standbyRelayCount: Int = 0,
    val relayCarrier: String? = null,
    val diagnosticCode: String? = null,
    val diagnosticObservedAt: Long? = null,
)

/** Thread-safe ownership wrapper around one bounded Rust Noise state handle. */
class NativePeerCore(config: NativeSessionConfig, wireguard: NativeWireguardRuntime) : Closeable {
    private val handle = AtomicLong(
        nativeCreate(
            config.keyAlias,
            config.keyMode,
            config.wrappedKeyMaterial,
            config.localIdentityPublic,
            config.localNoisePublic,
            config.remoteNoisePublic,
            config.remoteRelayId,
            config.credential,
            config.attachmentId,
            config.rootPublic,
            config.meshId,
            config.authorityCertificates,
            config.authorityRevision,
            config.distributionPublic,
            config.servicePublic,
            config.auditPublic,
            config.distributionCertificate,
            Instant.now().epochSecond,
            config.capabilities,
            wireguard.openHandle(),
        ).also { check(it > 0) },
    )

    @Synchronized
    fun firstHandshake(): ByteArray = nativeFirstHandshake(openHandle())

    @Synchronized
    fun finishHandshake(response: ByteArray, monotonicSeconds: Long): Long =
        nativeFinishHandshake(openHandle(), response, Instant.now().epochSecond, monotonicSeconds)

    @Synchronized
    fun confirmLink(frame: ByteArray, monotonicSeconds: Long) =
        nativeConfirmLink(openHandle(), frame, monotonicSeconds)

    @Synchronized
    fun linkReplacementDue(monotonicSeconds: Long): Boolean =
        nativeLinkReplacementDue(openHandle(), monotonicSeconds)

    @Synchronized
    fun linkClose(monotonicSeconds: Long): ByteArray = nativeLinkClose(openHandle(), monotonicSeconds)

    @Synchronized
    fun encryptControl(envelope: ByteArray, monotonicSeconds: Long): ByteArray =
        nativeEncrypt(openHandle(), 1, envelope, monotonicSeconds)

    @Synchronized
    fun keepalive(timestamp: Long, monotonicSeconds: Long): ByteArray =
        nativeKeepalive(openHandle(), timestamp, monotonicSeconds)

    @Synchronized
    fun managementTranscript(): ByteArray = nativeManagementTranscript(openHandle(), Instant.now().epochSecond)
    fun completeManagement(signature: ByteArray): ByteArray = nativeCompleteManagement(openHandle(), signature)

    fun auditTranscript(): ByteArray = nativeAuditTranscript(openHandle(), Instant.now().epochSecond)

    @Synchronized
    fun completeAudit(signature: ByteArray): ByteArray = nativeCompleteAudit(openHandle(), signature)

    @Synchronized
    fun healthTranscript(
        sequence: Long,
        directPathCount: Int,
        relayPackets: Long,
        directPackets: Long,
        degradedMask: Long,
        signedRevision: Long,
    ): ByteArray = nativeHealthTranscript(
        openHandle(), Instant.now().epochSecond, sequence, directPathCount,
        relayPackets, directPackets, degradedMask, signedRevision,
    )

    @Synchronized
    fun completeHealth(signature: ByteArray): ByteArray = nativeCompleteHealth(openHandle(), signature)

    @Synchronized
    fun runtimeStatus(): NativeRuntimeStatus {
        val input = ByteBuffer.wrap(nativeRuntimeStatus(openHandle()))
        require(input.remaining() == 9) { "native runtime status has an invalid length" }
        val complete = input.get().toInt() == 1
        val revision = input.long
        require(revision >= 0 && (complete || revision == 0L)) { "native runtime status is invalid" }
        return NativeRuntimeStatus(complete, revision)
    }

    @Synchronized
    fun rotationDue(now: Long = Instant.now().epochSecond): Boolean =
        nativeRotationDue(openHandle(), now)

    @Synchronized
    fun rotationRequestTranscript(
        requestId: ByteArray,
        identityPublicKey: ByteArray,
        sessionPublicKey: ByteArray,
        wireguardPublicKey: ByteArray,
    ): ByteArray = nativeRotationRequestTranscript(
        openHandle(), requestId, identityPublicKey, sessionPublicKey, wireguardPublicKey,
    )

    @Synchronized
    fun rotationRequest(
        requestId: ByteArray,
        identityPublicKey: ByteArray,
        sessionPublicKey: ByteArray,
        wireguardPublicKey: ByteArray,
        signature: ByteArray,
        now: Long = Instant.now().epochSecond,
    ): ByteArray? = nativeRotationRequest(
        openHandle(), requestId, identityPublicKey, sessionPublicKey, wireguardPublicKey, signature,
        now,
    )
            .takeIf(ByteArray::isNotEmpty)

    @Synchronized
    fun rotationActivation(signature: ByteArray): ByteArray =
        nativeRotationActivation(openHandle(), signature)

    @Synchronized
    fun resolveDns(query: ByteArray, sourceAddress: ByteArray, suffix: String): ByteArray =
        nativeResolveDns(openHandle(), query, sourceAddress, suffix)

    @Synchronized
    fun decrypt(frame: ByteArray, monotonicSeconds: Long): NativeRecord {
        val decoded = nativeDecrypt(openHandle(), frame, monotonicSeconds)
        require(decoded.size >= 2) { "native record is truncated" }
        return NativeRecord(decoded[0].toInt() and 0xff, decoded[1].toInt() and 0xff, decoded.copyOfRange(2, decoded.size))
    }

    override fun close() {
        val value = handle.getAndSet(0)
        if (value > 0) nativeClose(value)
    }

    internal fun openHandle(): Long = handle.get().also { check(it > 0) { "native session is closed" } }

    companion object {
        init {
            System.loadLibrary("peerward_android_core")
        }

        @JvmStatic private external fun nativeCreate(
            keyAlias: String,
            keyMode: Int,
            wrappedKeyMaterial: ByteArray,
            localIdentityPublic: ByteArray,
            localNoisePublic: ByteArray,
            remoteNoisePublic: ByteArray,
            remoteRelayId: ByteArray,
            credential: ByteArray,
            attachmentId: ByteArray,
            rootPublic: ByteArray,
            meshId: ByteArray,
            authorities: ByteArray,
            authorityRevision: Long,
            distributionPublic: ByteArray,
            servicePublic: ByteArray,
            auditPublic: ByteArray,
            distributionCertificate: ByteArray,
            now: Long,
            capabilities: Long,
            wireguardHandle: Long,
        ): Long

        @JvmStatic private external fun nativeFirstHandshake(handle: Long): ByteArray
        @JvmStatic private external fun nativeFinishHandshake(
            handle: Long,
            response: ByteArray,
            now: Long,
            monotonic: Long,
        ): Long
        @JvmStatic private external fun nativeConfirmLink(handle: Long, frame: ByteArray, monotonic: Long)
        @JvmStatic private external fun nativeLinkReplacementDue(handle: Long, monotonic: Long): Boolean
        @JvmStatic private external fun nativeLinkClose(handle: Long, monotonic: Long): ByteArray
        @JvmStatic private external fun nativeEncrypt(
            handle: Long,
            kind: Int,
            payload: ByteArray,
            monotonic: Long,
        ): ByteArray
        @JvmStatic private external fun nativeDecrypt(handle: Long, frame: ByteArray, monotonic: Long): ByteArray
        @JvmStatic private external fun nativeKeepalive(handle: Long, timestamp: Long, monotonic: Long): ByteArray
        @JvmStatic private external fun nativeManagementTranscript(handle: Long, now: Long): ByteArray
        @JvmStatic private external fun nativeCompleteManagement(handle: Long, signature: ByteArray): ByteArray
        @JvmStatic private external fun nativeAuditTranscript(handle: Long, now: Long): ByteArray
        @JvmStatic private external fun nativeCompleteAudit(handle: Long, signature: ByteArray): ByteArray
        @JvmStatic private external fun nativeHealthTranscript(
            handle: Long,
            now: Long,
            sequence: Long,
            directPathCount: Int,
            relayPackets: Long,
            directPackets: Long,
            degradedMask: Long,
            signedRevision: Long,
        ): ByteArray
        @JvmStatic private external fun nativeCompleteHealth(handle: Long, signature: ByteArray): ByteArray
        @JvmStatic private external fun nativeRuntimeStatus(handle: Long): ByteArray
        @JvmStatic private external fun nativeRotationDue(handle: Long, now: Long): Boolean
        @JvmStatic private external fun nativeRotationRequest(
            handle: Long,
            requestId: ByteArray,
            identityPublicKey: ByteArray,
            sessionPublicKey: ByteArray,
        wireguardPublicKey: ByteArray,
            signature: ByteArray,
            now: Long,
        ): ByteArray
        @JvmStatic private external fun nativeRotationRequestTranscript(
            handle: Long,
            requestId: ByteArray,
            identityPublicKey: ByteArray,
            sessionPublicKey: ByteArray,
        wireguardPublicKey: ByteArray,
        ): ByteArray
        @JvmStatic private external fun nativeRotationActivation(handle: Long, signature: ByteArray): ByteArray
        @JvmStatic private external fun nativeResolveDns(
            handle: Long,
            query: ByteArray,
            sourceAddress: ByteArray,
            suffix: String,
        ): ByteArray
        @JvmStatic private external fun nativeClose(handle: Long)
    }
}
