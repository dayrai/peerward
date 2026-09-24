package io.github.peerward.peerward.nativecore

import java.io.Closeable
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicLong

enum class NativeRuntimePhase(val code: Int) {
    STOPPED(0),
    PERMISSION_REQUIRED(1),
    STARTING(2),
    CONNECTING(3),
    HEALTHY(4),
    DEGRADED(5),
    RECONNECTING(6),
    STOPPING(7),
    FAILED(8),
}

data class NativeLifecycleStatus(
    val sequence: Long,
    val phase: NativeRuntimePhase,
    val rustRuntimeRunning: Boolean,
    val tunOpen: Boolean,
    val packetPumpRunning: Boolean,
    val primaryRelayAuthenticated: Boolean,
    val standbyRelayCount: Int,
    val directPathCount: Int,
    val signedStateComplete: Boolean,
    val signedStateRevision: Long,
)

enum class NativePlatformOperation(val code: Int) {
    VPN_PERMISSION(1),
    OPEN_TUN(2),
    PROTECTED_TCP_SOCKET(3),
    PROTECTED_UDP_SOCKET(4),
    KEYSTORE_OPERATION(5),
    ATOMIC_PERSISTENCE(6),
    ACQUIRE_UNDERLAY(7),
    EXPORT_DOCUMENT(8),
    CLOSE_RUNTIME_RESOURCES(9),
}

data class NativePlatformRequest(
    val requestId: Long,
    val generation: Long,
    val operation: NativePlatformOperation,
)

data class NativeRuntimeSchedule(
    val observeStatus: Boolean,
    val sendKeepalive: Boolean,
    val reportHealth: Boolean,
    val nextPollMillis: Long,
)

/**
 * Bounded JNI adapter for the platform-neutral Rust lifecycle state machine.
 * It owns no key, socket, TUN descriptor, address, endpoint, or packet payload.
 */
class NativeRuntimeCoordinator : Closeable {
    private val handle = AtomicLong(nativeCreate().also { check(it > 0) })

    @Synchronized
    fun reset(): NativeLifecycleStatus = transition(RESET)

    @Synchronized
    fun permissionRequired(): NativeLifecycleStatus = transition(PERMISSION_REQUIRED)

    @Synchronized
    fun startRequested(): NativeLifecycleStatus = transition(START_REQUESTED)

    @Synchronized
    fun tunOpened(): NativeLifecycleStatus = transition(TUN_OPENED)

    @Synchronized
    fun connecting(): NativeLifecycleStatus = transition(CONNECTING)

    @Synchronized
    fun observe(status: NativeRuntimeStatus): NativeLifecycleStatus = transition(
        TRANSPORT_OBSERVED,
        status.signedStateComplete,
        status.signedRevision,
        status.primaryRelayAuthenticated,
        status.standbyRelayCount,
        status.directPathCount,
    )

    @Synchronized
    fun underlayLost(): NativeLifecycleStatus = transition(UNDERLAY_LOST)

    @Synchronized
    fun underlayRestored(): NativeLifecycleStatus = transition(UNDERLAY_RESTORED)

    @Synchronized
    fun transportLost(): NativeLifecycleStatus = transition(TRANSPORT_LOST)

    @Synchronized
    fun stopRequested(): NativeLifecycleStatus = transition(STOP_REQUESTED)

    @Synchronized
    fun stopped(): NativeLifecycleStatus = transition(STOPPED)

    @Synchronized
    fun failed(): NativeLifecycleStatus = transition(FAILED)

    @Synchronized
    fun diagnostics(observedAt: Long, errorCode: String?): String =
        nativeDiagnostics(openHandle(), observedAt, (errorCode ?: "").toByteArray(Charsets.UTF_8))
            .toString(Charsets.UTF_8)

    @Synchronized
    fun request(operation: NativePlatformOperation): NativePlatformRequest {
        val input = ByteBuffer.wrap(nativePlatformRequest(openHandle(), operation.code))
        require(input.remaining() == PLATFORM_REQUEST_SIZE) { "native platform request is truncated" }
        val requestId = input.long
        val generation = input.long
        val returned = input.get().toInt() and 0xff
        require(requestId > 0 && generation > 0 && returned == operation.code) {
            "native platform request is invalid"
        }
        return NativePlatformRequest(requestId, generation, operation)
    }

    @Synchronized
    fun complete(request: NativePlatformRequest, success: Boolean): Boolean =
        nativePlatformResult(openHandle(), request.requestId, request.generation, success)

    @Synchronized
    fun schedule(nowMillis: Long, status: NativeRuntimeStatus): NativeRuntimeSchedule {
        require(nowMillis >= 0)
        val input = ByteBuffer.wrap(
            nativeSchedule(
                openHandle(), nowMillis, status.signedStateComplete, status.signedRevision,
                status.primaryRelayAuthenticated, status.standbyRelayCount, status.directPathCount,
            ),
        )
        require(input.remaining() == SCHEDULE_SIZE && input.get().toInt() == RECORD_VERSION) {
            "native runtime schedule has an invalid shape"
        }
        val flags = input.get().toInt() and 0xff
        require(flags and SCHEDULE_FLAGS.inv() == 0)
        val nextPollMillis = input.long
        require(nextPollMillis in 1..60_000)
        return NativeRuntimeSchedule(
            observeStatus = flags and OBSERVE_STATUS != 0,
            sendKeepalive = flags and SEND_KEEPALIVE != 0,
            reportHealth = flags and REPORT_HEALTH != 0,
            nextPollMillis = nextPollMillis,
        )
    }

    override fun close() {
        val value = handle.getAndSet(0)
        if (value > 0) nativeClose(value)
    }

    private fun transition(
        event: Int,
        signedComplete: Boolean = false,
        signedRevision: Long = 0,
        primaryAuthenticated: Boolean = false,
        standbyCount: Int = 0,
        directCount: Int = 0,
    ): NativeLifecycleStatus {
        val input = ByteBuffer.wrap(
            nativeTransition(
                openHandle(), event, signedComplete, signedRevision,
                primaryAuthenticated, standbyCount, directCount,
            ),
        )
        require(input.remaining() == RECORD_SIZE && input.get().toInt() == RECORD_VERSION) {
            "native lifecycle status has an invalid shape"
        }
        val sequence = input.long
        val phaseCode = input.get().toInt() and 0xff
        val phase = NativeRuntimePhase.entries.singleOrNull { it.code == phaseCode }
            ?: error("native lifecycle phase is unknown")
        val flags = input.get().toInt() and 0xff
        require(flags and FLAGS_MASK.inv() == 0) { "native lifecycle flags are invalid" }
        val standby = input.short.toInt() and 0xffff
        val direct = input.int
        val revision = input.long
        val complete = flags and SIGNED_COMPLETE != 0
        require(sequence > 0 && direct >= 0 && revision >= 0 && (complete || revision == 0L)) {
            "native lifecycle values are invalid"
        }
        return NativeLifecycleStatus(
            sequence = sequence,
            phase = phase,
            rustRuntimeRunning = flags and RUST_RUNNING != 0,
            tunOpen = flags and TUN_OPEN != 0,
            packetPumpRunning = flags and PUMP_RUNNING != 0,
            primaryRelayAuthenticated = flags and PRIMARY_AUTHENTICATED != 0,
            standbyRelayCount = standby,
            directPathCount = direct,
            signedStateComplete = complete,
            signedStateRevision = revision,
        )
    }

    private fun openHandle(): Long = handle.get().also { check(it > 0) { "native runtime is closed" } }

    companion object {
        private const val RESET = 0
        private const val PERMISSION_REQUIRED = 1
        private const val START_REQUESTED = 2
        private const val TUN_OPENED = 3
        private const val CONNECTING = 4
        private const val TRANSPORT_OBSERVED = 5
        private const val UNDERLAY_LOST = 6
        private const val TRANSPORT_LOST = 7
        private const val STOP_REQUESTED = 8
        private const val STOPPED = 9
        private const val FAILED = 10
        private const val UNDERLAY_RESTORED = 11
        private const val RECORD_VERSION = 1
        private const val RECORD_SIZE = 25
        private const val PLATFORM_REQUEST_SIZE = 17
        private const val SCHEDULE_SIZE = 10
        private const val RUST_RUNNING = 1
        private const val TUN_OPEN = 1 shl 1
        private const val PUMP_RUNNING = 1 shl 2
        private const val PRIMARY_AUTHENTICATED = 1 shl 3
        private const val SIGNED_COMPLETE = 1 shl 4
        private const val FLAGS_MASK = RUST_RUNNING or TUN_OPEN or PUMP_RUNNING or
            PRIMARY_AUTHENTICATED or SIGNED_COMPLETE
        private const val OBSERVE_STATUS = 1
        private const val SEND_KEEPALIVE = 1 shl 1
        private const val REPORT_HEALTH = 1 shl 2
        private const val SCHEDULE_FLAGS = OBSERVE_STATUS or SEND_KEEPALIVE or REPORT_HEALTH

        init {
            System.loadLibrary("peerward_android_core")
        }

        @JvmStatic private external fun nativeCreate(): Long
        @JvmStatic private external fun nativeDiagnostics(handle: Long, observedAt: Long, errorCode: ByteArray): ByteArray
        @JvmStatic private external fun nativeTransition(
            handle: Long,
            event: Int,
            signedComplete: Boolean,
            signedRevision: Long,
            primaryAuthenticated: Boolean,
            standbyCount: Int,
            directCount: Int,
        ): ByteArray
        @JvmStatic private external fun nativeSchedule(
            handle: Long,
            nowMillis: Long,
            signedComplete: Boolean,
            signedRevision: Long,
            primaryAuthenticated: Boolean,
            standbyCount: Int,
            directCount: Int,
        ): ByteArray
        @JvmStatic private external fun nativePlatformRequest(handle: Long, kind: Int): ByteArray
        @JvmStatic private external fun nativePlatformResult(
            handle: Long,
            requestId: Long,
            generation: Long,
            success: Boolean,
        ): Boolean
        @JvmStatic private external fun nativeClose(handle: Long)
    }
}
