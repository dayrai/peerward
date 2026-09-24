package io.github.peerward.peerward.nativecore

import java.io.Closeable
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicLong

enum class NativeDnsTransport(val code: Int) {
    UDP(1),
    TCP(2),
}

sealed interface NativeTunDnsDecision {
    data object Pass : NativeTunDnsDecision
    data class Replies(val packets: List<ByteArray>) : NativeTunDnsDecision
    data class Resolve(
        val token: Long,
        val transport: NativeDnsTransport,
        val sourceAddress: ByteArray,
        val query: ByteArray,
    ) : NativeTunDnsDecision
}

/** Bounded JNI adapter for the Rust-owned UDP/TCP TUN DNS flow table. */
class NativeTunDnsProxy(dnsServers: List<String>, mtu: Int) : Closeable {
    private val handle = AtomicLong(nativeCreate(encodeServers(dnsServers), mtu).also { check(it > 0) })

    @Synchronized
    fun inspect(packet: ByteArray): NativeTunDnsDecision = decode(nativeInspect(openHandle(), packet))

    @Synchronized
    fun complete(token: Long, response: ByteArray): List<ByteArray> {
        require(token > 0 && response.size <= MAX_DNS_MESSAGE)
        val decision = decode(nativeComplete(openHandle(), token, response))
        return (decision as? NativeTunDnsDecision.Replies)?.packets
            ?: error("native DNS completion returned an invalid decision")
    }

    override fun close() {
        val value = handle.getAndSet(0)
        if (value > 0) nativeClose(value)
    }

    private fun openHandle(): Long = handle.get().also { check(it > 0) { "native DNS proxy is closed" } }

    companion object {
        private const val RECORD_VERSION = 1
        private const val PASS = 0
        private const val REPLIES = 1
        private const val RESOLVE = 2
        private const val MAX_PACKETS = 256
        private const val MAX_PACKET = 65_535
        private const val MAX_DNS_MESSAGE = 65_535

        init {
            System.loadLibrary("peerward_android_core")
        }

        private fun encodeServers(servers: List<String>): ByteArray {
            require(servers.isNotEmpty() && servers.size <= 8)
            val addresses = servers.map { server ->
                InetAddress.getByName(server).address.also { require(it.size == 4 || it.size == 16) }
            }.distinctBy { it.toList() }
            require(addresses.isNotEmpty() && addresses.size <= 8)
            return ByteBuffer.allocate(1 + addresses.sumOf { 1 + it.size })
                .put(addresses.size.toByte())
                .apply { addresses.forEach { address -> put(address.size.toByte()).put(address) } }
                .array()
        }

        private fun decode(record: ByteArray): NativeTunDnsDecision {
            val input = ByteBuffer.wrap(record)
            require(input.remaining() >= 2 && input.get().toInt() and 0xff == RECORD_VERSION) {
                "native DNS decision has an invalid shape"
            }
            val decision = when (input.get().toInt() and 0xff) {
                PASS -> NativeTunDnsDecision.Pass
                REPLIES -> {
                    require(input.remaining() >= 2)
                    val count = input.short.toInt() and 0xffff
                    require(count <= MAX_PACKETS)
                    NativeTunDnsDecision.Replies(List(count) {
                        require(input.remaining() >= 4)
                        val length = input.int
                        require(length in 0..MAX_PACKET && input.remaining() >= length)
                        ByteArray(length).also(input::get)
                    })
                }
                RESOLVE -> {
                    require(input.remaining() >= 12)
                    val token = input.long
                    val transportCode = input.get().toInt() and 0xff
                    val transport = NativeDnsTransport.entries.singleOrNull { it.code == transportCode }
                        ?: error("native DNS transport is unknown")
                    val sourceLength = input.get().toInt() and 0xff
                    require(token > 0 && (sourceLength == 4 || sourceLength == 16) &&
                        input.remaining() >= sourceLength + 2)
                    val source = ByteArray(sourceLength).also(input::get)
                    val queryLength = input.short.toInt() and 0xffff
                    require(queryLength in 12..MAX_DNS_MESSAGE && input.remaining() == queryLength)
                    NativeTunDnsDecision.Resolve(
                        token,
                        transport,
                        source,
                        ByteArray(queryLength).also(input::get),
                    )
                }
                else -> error("native DNS decision kind is unknown")
            }
            require(!input.hasRemaining()) { "native DNS decision has trailing bytes" }
            return decision
        }

        @JvmStatic private external fun nativeCreate(servers: ByteArray, mtu: Int): Long
        @JvmStatic private external fun nativeInspect(handle: Long, packet: ByteArray): ByteArray
        @JvmStatic private external fun nativeComplete(
            handle: Long,
            token: Long,
            response: ByteArray,
        ): ByteArray
        @JvmStatic private external fun nativeClose(handle: Long)
    }
}
