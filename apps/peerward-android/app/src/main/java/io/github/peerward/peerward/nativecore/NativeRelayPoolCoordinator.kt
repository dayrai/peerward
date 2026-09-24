package io.github.peerward.peerward.nativecore

import android.os.SystemClock
import java.io.Closeable
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicLong

data class NativeRelayRoute(val slot: Int, val generation: Long)

data class NativeRelayConnectRequest(
    val requestId: Long,
    val slot: Int,
    val endpointIndex: Int,
    val candidateGeneration: Long,
    val replacingGeneration: Long?,
)

data class NativeRelayPoll(
    val requests: List<NativeRelayConnectRequest>,
    val nextPollMillis: Long,
)

data class NativeRelayCommit(
    val route: NativeRelayRoute,
    val replacedGeneration: Long?,
    val primary: NativeRelayRoute?,
)

/** JNI projection of the Rust-owned Relay slot and retry state machine. */
class NativeRelayPoolCoordinator(endpointCounts: List<Int>) : Closeable {
    private val handle = AtomicLong(
        nativeCreate(encodeCounts(endpointCounts)).also { check(it > 0) },
    )

    @Synchronized
    fun poll(nowMillis: Long = SystemClock.elapsedRealtime()): NativeRelayPoll {
        val input = ByteBuffer.wrap(nativePoll(openHandle(), nowMillis))
        require(input.remaining() >= POLL_HEADER && input.get().unsigned() == VERSION)
        val count = input.get().unsigned()
        require(count in 0..MAX_SLOTS)
        val next = input.long
        require(next in 1..10_000 && input.remaining() == count * REQUEST_SIZE)
        val requests = List(count) {
            val requestId = input.long
            val slot = input.get().unsigned()
            val endpoint = input.short.toInt() and 0xffff
            val candidate = input.long
            val replacing = input.long.takeIf { value -> value > 0 }
            require(requestId > 0 && slot in 0 until MAX_SLOTS && candidate > 0)
            NativeRelayConnectRequest(requestId, slot, endpoint, candidate, replacing)
        }
        return NativeRelayPoll(requests, next)
    }

    @Synchronized
    fun complete(
        request: NativeRelayConnectRequest,
        success: Boolean,
        nowMillis: Long = SystemClock.elapsedRealtime(),
    ): NativeRelayCommit? {
        val input = ByteBuffer.wrap(nativeComplete(openHandle(), request.requestId, success, nowMillis))
        require(input.remaining() >= 2 && input.get().unsigned() == VERSION)
        if (input.get().unsigned() == 0) {
            require(!input.hasRemaining())
            return null
        }
        require(input.remaining() == COMMIT_BODY)
        val route = NativeRelayRoute(input.get().unsigned(), input.long)
        val replaced = input.long.takeIf { it > 0 }
        val primarySlot = input.get().unsigned()
        val primaryGeneration = input.long
        val primary = if (primarySlot == NO_SLOT) null else {
            require(primarySlot in 0 until MAX_SLOTS && primaryGeneration > 0)
            NativeRelayRoute(primarySlot, primaryGeneration)
        }
        require(route.slot == request.slot && route.generation == request.candidateGeneration)
        return NativeRelayCommit(route, replaced, primary)
    }

    @Synchronized
    fun failed(route: NativeRelayRoute, nowMillis: Long = SystemClock.elapsedRealtime()) {
        nativeFailed(openHandle(), route.slot, route.generation, nowMillis)
    }

    @Synchronized
    fun refresh(route: NativeRelayRoute, nowMillis: Long = SystemClock.elapsedRealtime()) {
        nativeRefresh(openHandle(), route.slot, route.generation, nowMillis)
    }

    @Synchronized
    fun routes(): List<NativeRelayRoute> = decodeRoutes(nativeRoutes(openHandle()))

    @Synchronized
    fun isPrimary(route: NativeRelayRoute): Boolean =
        nativeIsPrimary(openHandle(), route.slot, route.generation)

    @Synchronized
    override fun close() {
        val value = handle.getAndSet(0)
        if (value > 0) decodeRoutes(nativeClose(value))
    }

    private fun openHandle(): Long = handle.get().also { check(it > 0) }

    companion object {
        private const val VERSION = 1
        private const val MAX_SLOTS = 3
        private const val NO_SLOT = 0xff
        private const val POLL_HEADER = 10
        private const val REQUEST_SIZE = 27
        private const val COMMIT_BODY = 26

        init {
            System.loadLibrary("peerward_android_core")
        }

        private fun encodeCounts(counts: List<Int>): ByteArray {
            require(counts.size in 1..MAX_SLOTS && counts.all { it in 1..0xffff })
            return ByteBuffer.allocate(1 + counts.size * 2)
                .put(counts.size.toByte())
                .apply { counts.forEach { putShort(it.toShort()) } }
                .array()
        }

        private fun decodeRoutes(record: ByteArray): List<NativeRelayRoute> {
            val input = ByteBuffer.wrap(record)
            require(input.remaining() >= 2 && input.get().unsigned() == VERSION)
            val count = input.get().unsigned()
            require(count in 0..MAX_SLOTS && input.remaining() == count * 9)
            return List(count) {
                NativeRelayRoute(input.get().unsigned(), input.long).also { route ->
                    require(route.slot in 0 until MAX_SLOTS && route.generation > 0)
                }
            }
        }

        private fun Byte.unsigned(): Int = toInt() and 0xff

        @JvmStatic private external fun nativeCreate(endpointCounts: ByteArray): Long
        @JvmStatic private external fun nativePoll(handle: Long, nowMillis: Long): ByteArray
        @JvmStatic private external fun nativeComplete(
            handle: Long,
            requestId: Long,
            success: Boolean,
            nowMillis: Long,
        ): ByteArray
        @JvmStatic private external fun nativeFailed(
            handle: Long,
            slot: Int,
            generation: Long,
            nowMillis: Long,
        )
        @JvmStatic private external fun nativeRefresh(
            handle: Long,
            slot: Int,
            generation: Long,
            nowMillis: Long,
        )
        @JvmStatic private external fun nativeRoutes(handle: Long): ByteArray
        @JvmStatic private external fun nativeIsPrimary(
            handle: Long,
            slot: Int,
            generation: Long,
        ): Boolean
        @JvmStatic private external fun nativeClose(handle: Long): ByteArray
    }
}
