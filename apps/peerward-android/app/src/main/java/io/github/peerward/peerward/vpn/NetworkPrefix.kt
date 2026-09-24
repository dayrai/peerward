package io.github.peerward.peerward.vpn

import java.math.BigInteger
import java.net.InetAddress

/** Avoids IpPrefix constructors that are public only from API 33. Parsing performs no DNS. */
internal data class NetworkPrefix(private val value: BigInteger, val bits: Int, val width: Int) {
    val address: InetAddress get() {
        val bytes = value.toByteArray().takeLast(width / 8).toByteArray()
        return InetAddress.getByAddress(ByteArray(width / 8 - bytes.size) + bytes)
    }
    fun contains(other: NetworkPrefix): Boolean = width == other.width && bits <= other.bits &&
        value.shiftRight(width - bits) == other.value.shiftRight(width - bits)
    fun contains(address: InetAddress): Boolean = width == address.address.size * 8 &&
        value.shiftRight(width - bits) == BigInteger(1, address.address).shiftRight(width - bits)
    fun children(): List<NetworkPrefix> {
        require(bits < width)
        return listOf(copy(bits = bits + 1), copy(value = value.setBit(width - bits - 1), bits = bits + 1))
    }
    override fun toString(): String = requireNotNull(address.hostAddress) + "/" + bits
    companion object {
        fun parse(text: String): NetworkPrefix {
            val parts = text.split('/')
            require(parts.size == 2)
            val (literal, length) = parts
            require(literal.all { it.isDigit() || it in ".:abcdefABCDEF" })
            require(':' in literal || literal.split('.').let { labels -> labels.size == 4 && labels.all { it.toIntOrNull() in 0..255 } })
            val bytes = InetAddress.getByName(literal).address
            val bits = length.toInt(); val width = bytes.size * 8
            require(bits in 0..width)
            val value = BigInteger(1, bytes).shiftRight(width - bits).shiftLeft(width - bits)
            return NetworkPrefix(value, bits, width)
        }
    }
}
