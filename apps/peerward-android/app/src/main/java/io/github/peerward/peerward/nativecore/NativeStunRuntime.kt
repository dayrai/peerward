package io.github.peerward.peerward.nativecore

import android.os.SystemClock
import java.io.Closeable
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicLong

data class NativeStunProbe(
    val serverIndex: Int,
    val server: InetSocketAddress,
    val request: ByteArray,
)

data class NativeStunPoll(
    val probes: List<NativeStunProbe>,
    val nextPollMillis: Long,
)

data class NativeStunMapping(
    val serverIndex: Int,
    val mapped: InetSocketAddress,
    val predicted: List<InetSocketAddress>,
)

/** Rust-owned STUN transactions, exact-source validation, and refresh cadence. */
class NativeStunRuntime(
    servers: List<InetSocketAddress>,
    predictionEnabled: Boolean = false,
) : Closeable {
    private val handle = AtomicLong(
        nativeCreate(encodeServers(servers), predictionEnabled).also { check(it > 0) },
    )

    @Synchronized
    fun poll(nowMillis: Long): NativeStunPoll {
        require(nowMillis >= 0)
        val input = ByteBuffer.wrap(nativePoll(openHandle(), nowMillis))
        require(input.remaining() >= POLL_HEADER && input.get().toInt() and 0xff == RECORD_VERSION)
        val count = input.get().toInt() and 0xff
        require(count <= MAX_SERVERS)
        val nextPollMillis = input.long
        require(nextPollMillis in 1..MAX_POLL_MILLIS)
        val probes = List(count) {
            require(input.remaining() >= 24)
            val serverIndex = input.get().toInt() and 0xff
            val addressLength = input.get().toInt() and 0xff
            require(serverIndex < MAX_SERVERS && (addressLength == 4 || addressLength == 16) &&
                input.remaining() >= addressLength + 22)
            val address = ByteArray(addressLength).also(input::get)
            val port = input.short.toInt() and 0xffff
            val request = ByteArray(STUN_REQUEST_BYTES).also(input::get)
            require(port > 0)
            NativeStunProbe(
                serverIndex,
                InetSocketAddress(InetAddress.getByAddress(address), port),
                request,
            )
        }
        require(!input.hasRemaining())
        return NativeStunPoll(probes, nextPollMillis)
    }

    @Synchronized
    fun accept(source: InetSocketAddress, response: ByteArray): NativeStunMapping? {
        val sourceAddress = source.address?.address ?: return null
        if (source.port !in 1..65_535 || response.size > MAX_RESPONSE_BYTES) return null
        val record = nativeAccept(openHandle(), sourceAddress, source.port, response, SystemClock.elapsedRealtime())
        if (record.isEmpty()) return null
        val input = ByteBuffer.wrap(record)
        require(input.remaining() >= 10 && input.get().toInt() and 0xff == RECORD_VERSION)
        val serverIndex = input.get().toInt() and 0xff
        val addressLength = input.get().toInt() and 0xff
        require(serverIndex < MAX_SERVERS && (addressLength == 4 || addressLength == 16) &&
            input.remaining() >= addressLength + 3)
        val mappedAddress = ByteArray(addressLength).also(input::get)
        val mappedPort = input.short.toInt() and 0xffff
        val predictedCount = input.get().toInt() and 0xff
        require(mappedPort > 0 && predictedCount <= MAX_PREDICTED && input.remaining() == predictedCount * 2)
        val address = InetAddress.getByAddress(mappedAddress)
        val predicted = List(predictedCount) {
            val port = input.short.toInt() and 0xffff
            require(port > 0)
            InetSocketAddress(address, port)
        }
        return NativeStunMapping(
            serverIndex,
            InetSocketAddress(address, mappedPort),
            predicted,
        )
    }

    override fun close() {
        val value = handle.getAndSet(0)
        if (value > 0) nativeClose(value)
    }

    private fun openHandle(): Long = handle.get().also { check(it > 0) { "native STUN runtime is closed" } }

    companion object {
        private const val RECORD_VERSION = 2
        private const val MAX_SERVERS = 8
        private const val STUN_REQUEST_BYTES = 20
        private const val MAX_RESPONSE_BYTES = 1_024
        private const val MAX_PREDICTED = 5
        private const val POLL_HEADER = 10
        private const val MAX_POLL_MILLIS = 330_000L

        init {
            System.loadLibrary("peerward_android_core")
        }

        private fun encodeServers(servers: List<InetSocketAddress>): ByteArray {
            require(servers.isNotEmpty() && servers.size <= MAX_SERVERS)
            val resolved = servers.map { server ->
                val address = requireNotNull(server.address) { "STUN server must be resolved" }.address
                require(address.size == 4 || address.size == 16)
                require(server.port in 1..65_535)
                address to server.port
            }.distinctBy { (address, port) -> address.toList() to port }
            require(resolved.size == servers.size)
            return ByteBuffer.allocate(1 + resolved.sumOf { (address, _) -> 1 + address.size + 2 })
                .put(resolved.size.toByte())
                .apply {
                    resolved.forEach { (address, port) ->
                        put(address.size.toByte()).put(address).putShort(port.toShort())
                    }
                }
                .array()
        }

        @JvmStatic private external fun nativeCreate(servers: ByteArray, predictionEnabled: Boolean): Long
        @JvmStatic private external fun nativePoll(handle: Long, nowMillis: Long): ByteArray
        @JvmStatic private external fun nativeAccept(
            handle: Long,
            sourceAddress: ByteArray,
            sourcePort: Int,
            response: ByteArray,
            nowMillis: Long,
        ): ByteArray
        @JvmStatic private external fun nativeClose(handle: Long)
    }
}
