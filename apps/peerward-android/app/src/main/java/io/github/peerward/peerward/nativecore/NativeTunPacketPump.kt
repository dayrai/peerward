package io.github.peerward.peerward.nativecore

import android.os.ParcelFileDescriptor
import java.io.Closeable
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicLong

sealed interface NativeTunPumpAction {
    data object Idle : NativeTunPumpAction
    data class Packet(val bytes: ByteArray) : NativeTunPumpAction
    data class Resolve(
        val token: Long,
        val transport: NativeDnsTransport,
        val sourceAddress: ByteArray,
        val query: ByteArray,
    ) : NativeTunPumpAction
}

/** Rust owns duplicated TUN FDs, reads, writes and DNS flow processing. */
class NativeTunPacketPump(
    descriptor: ParcelFileDescriptor,
    dnsServers: List<String>,
    mtu: Int,
) : Closeable {
    private val handle: AtomicLong

    init {
        // Keep one Java owner until JNI has duplicated the borrowed descriptor.
        // Validation/allocation failures close that owner exactly once as well.
        handle = AtomicLong(descriptor.use {
            nativeCreate(it.fd, encodeServers(dnsServers), mtu).also { value -> check(value > 0) }
        })
    }

    fun poll(timeoutMillis: Int): NativeTunPumpAction {
        require(timeoutMillis in 0..1_000)
        val input = ByteBuffer.wrap(nativePoll(openHandle(), timeoutMillis))
        require(input.remaining() >= 2 && input.get().unsigned() == VERSION)
        val action = when (input.get().unsigned()) {
            IDLE -> NativeTunPumpAction.Idle
            PACKET -> {
                require(input.remaining() >= 4)
                val length = input.int
                require(length in 20..MAX_PACKET && input.remaining() == length)
                NativeTunPumpAction.Packet(ByteArray(length).also(input::get))
            }
            RESOLVE -> {
                require(input.remaining() >= 12)
                val token = input.long
                val transportCode = input.get().unsigned()
                val transport = NativeDnsTransport.entries.singleOrNull { it.code == transportCode }
                    ?: error("native TUN DNS transport is unknown")
                val sourceLength = input.get().unsigned()
                require(token > 0 && sourceLength in listOf(4, 16) && input.remaining() >= sourceLength + 2)
                val source = ByteArray(sourceLength).also(input::get)
                val queryLength = input.short.toInt() and 0xffff
                require(queryLength in 12..MAX_DNS && input.remaining() == queryLength)
                NativeTunPumpAction.Resolve(
                    token,
                    transport,
                    source,
                    ByteArray(queryLength).also(input::get),
                )
            }
            else -> error("native TUN action is unknown")
        }
        require(!input.hasRemaining())
        return action
    }

    fun completeDns(token: Long, response: ByteArray) {
        require(token > 0 && response.size <= MAX_DNS)
        nativeCompleteDns(openHandle(), token, response)
    }

    fun writeInbound(packet: ByteArray) {
        require(packet.size in 20..MAX_PACKET)
        nativeWriteInbound(openHandle(), packet)
    }

    override fun close() {
        val value = handle.getAndSet(0)
        if (value > 0) nativeClose(value)
    }

    internal fun openHandle(): Long = handle.get().also { check(it > 0) }

    companion object {
        private const val VERSION = 1
        private const val IDLE = 0
        private const val PACKET = 1
        private const val RESOLVE = 2
        private const val MAX_PACKET = 65_535
        private const val MAX_DNS = 65_535

        init {
            System.loadLibrary("peerward_android_core")
        }

        private fun encodeServers(servers: List<String>): ByteArray {
            require(servers.isNotEmpty() && servers.size <= 8)
            val addresses = servers.map { value ->
                InetAddress.getByName(value).address.also { require(it.size == 4 || it.size == 16) }
            }.distinctBy { it.toList() }
            require(addresses.isNotEmpty() && addresses.size <= 8)
            return ByteBuffer.allocate(1 + addresses.sumOf { 1 + it.size })
                .put(addresses.size.toByte())
                .apply { addresses.forEach { address -> put(address.size.toByte()).put(address) } }
                .array()
        }

        private fun Byte.unsigned(): Int = toInt() and 0xff

        @JvmStatic private external fun nativeCreate(
            descriptor: Int,
            servers: ByteArray,
            mtu: Int,
        ): Long
        @JvmStatic private external fun nativePoll(
            handle: Long,
            timeoutMillis: Int,
        ): ByteArray
        @JvmStatic private external fun nativeCompleteDns(
            handle: Long,
            token: Long,
            response: ByteArray,
        )
        @JvmStatic private external fun nativeWriteInbound(handle: Long, packet: ByteArray)
        @JvmStatic private external fun nativeClose(handle: Long)
    }
}
