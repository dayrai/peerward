package io.github.peerward.peerward.nativecore

import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer

enum class NativeMappingProtocol { PCP, NAT_PMP, UPNP }

data class NativePcpRequest(val nonce: ByteArray, val payload: ByteArray)

data class NativeNatPmpPublicAddress(val address: InetAddress, val epoch: Int)

data class NativeMappingLease(
    val protocol: NativeMappingProtocol,
    val external: InetSocketAddress,
    val lifetimeSeconds: Long,
    val epoch: Int?,
    val nonce: ByteArray? = null,
)

/** Strict Rust-owned PCP/NAT-PMP codecs transported on Android-owned protected sockets. */
object NativePortMappingCodec {
    private const val RECORD_VERSION = 1
    private const val PCP_REQUEST_BYTES = 60
    private const val PCP_NONCE_BYTES = 12
    private const val MAX_RESPONSE_BYTES = 1_024

    init {
        System.loadLibrary("peerward_android_core")
    }

    fun pcpRequest(
        internal: InetSocketAddress,
        lifetimeSeconds: Long,
        nonce: ByteArray? = null,
        suggested: InetSocketAddress? = null,
    ): NativePcpRequest {
        require(lifetimeSeconds in 0..UInt.MAX_VALUE.toLong())
        val record = nativePcpRequest(
            resolvedAddress(internal),
            internal.port,
            lifetimeSeconds,
            nonce ?: byteArrayOf(),
            suggested?.let(::resolvedAddress) ?: byteArrayOf(),
            suggested?.port ?: 0,
        )
        require(record.size == 1 + PCP_NONCE_BYTES + PCP_REQUEST_BYTES)
        val input = ByteBuffer.wrap(record)
        require(input.get().toInt() and 0xff == RECORD_VERSION)
        return NativePcpRequest(
            ByteArray(PCP_NONCE_BYTES).also(input::get),
            ByteArray(PCP_REQUEST_BYTES).also(input::get),
        )
    }

    fun acceptPcp(
        internal: InetSocketAddress,
        nonce: ByteArray,
        response: ByteArray,
        deleting: Boolean = false,
    ): NativeMappingLease? {
        if (nonce.size != PCP_NONCE_BYTES || response.size > MAX_RESPONSE_BYTES) return null
        return decodeLease(
            nativePcpAccept(
                resolvedAddress(internal),
                internal.port,
                nonce,
                response,
                deleting,
            ),
            nonce,
        )
    }

    fun natPmpPublicRequest(): ByteArray = nativeNatPmpPublicRequest().also {
        require(it.contentEquals(byteArrayOf(0, 0)))
    }

    fun acceptNatPmpPublic(response: ByteArray): NativeNatPmpPublicAddress? {
        if (response.size > MAX_RESPONSE_BYTES) return null
        val record = nativeNatPmpPublicAccept(response)
        if (record.isEmpty()) return null
        require(record.size == 9)
        val input = ByteBuffer.wrap(record)
        require(input.get().toInt() and 0xff == RECORD_VERSION)
        return NativeNatPmpPublicAddress(
            InetAddress.getByAddress(ByteArray(4).also(input::get)),
            input.int,
        )
    }

    fun natPmpRequest(internal: InetSocketAddress, lifetimeSeconds: Long, suggestedPort: Int = internal.port): ByteArray {
        require(suggestedPort in 0..65_535)
        require(lifetimeSeconds in 0..UInt.MAX_VALUE.toLong())
        return nativeNatPmpRequest(
            resolvedAddress(internal),
            internal.port,
            lifetimeSeconds,
            suggestedPort,
        ).also { require(it.size == 12) }
    }

    fun acceptNatPmp(
        internal: InetSocketAddress,
        externalAddress: InetAddress,
        response: ByteArray,
        deleting: Boolean = false,
    ): NativeMappingLease? {
        if (externalAddress.address.size != 4 || response.size > MAX_RESPONSE_BYTES) return null
        return decodeLease(
            nativeNatPmpAccept(
                resolvedAddress(internal),
                internal.port,
                externalAddress.address,
                response,
                deleting,
            ),
            null,
        )
    }

    fun gatewayRestarted(previousEpoch: Int, currentEpoch: Int): Boolean =
        nativeGatewayRestarted(previousEpoch, currentEpoch)

    private fun decodeLease(record: ByteArray, nonce: ByteArray?): NativeMappingLease? {
        if (record.isEmpty()) return null
        val input = ByteBuffer.wrap(record)
        require(input.remaining() >= 15 && input.get().toInt() and 0xff == RECORD_VERSION)
        val protocol = when (input.get().toInt() and 0xff) {
            1 -> NativeMappingProtocol.PCP
            2 -> NativeMappingProtocol.NAT_PMP
            else -> error("unknown native mapping protocol")
        }
        val addressLength = input.get().toInt() and 0xff
        require((addressLength == 4 || addressLength == 16) && input.remaining() == addressLength + 10)
        val address = InetAddress.getByAddress(ByteArray(addressLength).also(input::get))
        val port = input.short.toInt() and 0xffff
        val lifetime = input.int.toLong() and 0xffff_ffffL
        val epoch = input.int
        require(port > 0 || lifetime == 0L)
        return NativeMappingLease(
            protocol,
            InetSocketAddress(address, port.takeIf { it > 0 } ?: 1),
            lifetime,
            epoch,
            nonce?.copyOf(),
        )
    }

    private fun resolvedAddress(endpoint: InetSocketAddress): ByteArray {
        require(endpoint.port in 1..65_535)
        return requireNotNull(endpoint.address) { "mapping endpoint must be resolved" }.address
    }

    @JvmStatic private external fun nativePcpRequest(
        internalAddress: ByteArray,
        internalPort: Int,
        lifetime: Long,
        nonce: ByteArray,
        externalAddress: ByteArray,
        externalPort: Int,
    ): ByteArray

    @JvmStatic private external fun nativePcpAccept(
        internalAddress: ByteArray,
        internalPort: Int,
        nonce: ByteArray,
        response: ByteArray,
        deleting: Boolean,
    ): ByteArray

    @JvmStatic private external fun nativeNatPmpPublicRequest(): ByteArray
    @JvmStatic private external fun nativeNatPmpPublicAccept(response: ByteArray): ByteArray

    @JvmStatic private external fun nativeNatPmpRequest(
        internalAddress: ByteArray,
        internalPort: Int,
        lifetime: Long,
        externalPort: Int,
    ): ByteArray

    @JvmStatic private external fun nativeNatPmpAccept(
        internalAddress: ByteArray,
        internalPort: Int,
        externalAddress: ByteArray,
        response: ByteArray,
        deleting: Boolean,
    ): ByteArray

    @JvmStatic private external fun nativeGatewayRestarted(previous: Int, current: Int): Boolean
}
