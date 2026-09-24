package io.github.peerward.peerward.net

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.security.SecureRandom

data class DnsReply(val bytes: ByteArray, val truncated: Boolean, val responseCode: Int)

object DnsWire {
    const val UDP_SAFE_SIZE = 1232
    private const val HEADER_SIZE = 12

    fun query(id: Int, hostname: String, type: Int = 1): ByteArray {
        require(id in 0..0xffff && type in setOf(1, 28)) { "invalid DNS query fields" }
        val labels = hostname.trimEnd('.').split('.')
        require(labels.isNotEmpty() && labels.sumOf { it.length + 1 } <= 253) { "invalid DNS name" }
        val output = java.io.ByteArrayOutputStream()
        DataOutputStream(output).use { wire ->
            wire.writeShort(id)
            wire.writeShort(0x0100)
            wire.writeShort(1)
            wire.writeShort(0)
            wire.writeShort(0)
            wire.writeShort(0)
            labels.forEach { label ->
                val ascii = label.toByteArray(Charsets.US_ASCII)
                require(ascii.size in 1..63 && label.all { it.isLetterOrDigit() || it == '-' }) {
                    "invalid DNS label"
                }
                wire.writeByte(ascii.size)
                wire.write(ascii)
            }
            wire.writeByte(0)
            wire.writeShort(type)
            wire.writeShort(1)
        }
        return output.toByteArray()
    }

    fun validateReply(query: ByteArray, reply: ByteArray): DnsReply {
        require(query.size >= HEADER_SIZE && reply.size in HEADER_SIZE..65535) { "short DNS message" }
        val q = ByteBuffer.wrap(query)
        val r = ByteBuffer.wrap(reply)
        val expectedId = q.short.toInt() and 0xffff
        val actualId = r.short.toInt() and 0xffff
        require(expectedId == actualId) { "DNS transaction mismatch" }
        val flags = r.short.toInt() and 0xffff
        require(flags and 0x8000 != 0) { "DNS packet is not a response" }
        val questions = r.short.toInt() and 0xffff
        require(questions == 1) { "unexpected DNS question count" }
        require(question(query) == question(reply)) { "DNS response question mismatch" }
        return DnsReply(reply.copyOf(), flags and 0x0200 != 0, flags and 0x000f)
    }

    private fun question(message: ByteArray): Triple<String, Int, Int> {
        var cursor = HEADER_SIZE
        var end = -1
        var expanded = 0
        val labels = mutableListOf<String>()
        val visited = mutableSetOf<Int>()
        while (true) {
            require(cursor in message.indices && visited.add(cursor) && visited.size <= 128) { "invalid DNS question name" }
            val length = message[cursor++].toInt() and 0xff
            if (length == 0) break
            if (length and 0xc0 == 0xc0) {
                require(cursor in message.indices) { "truncated DNS pointer" }
                if (end == -1) end = cursor + 1
                val offset = ((length and 0x3f) shl 8) or (message[cursor].toInt() and 0xff)
                require(offset < cursor - 1) { "forward DNS pointer" }
                cursor = offset
            } else {
                require(length <= 63 && cursor + length <= message.size) { "invalid DNS label" }
                val bytes = message.copyOfRange(cursor, cursor + length)
                require(bytes.all { (it.toInt() and 0xff) in 33..126 }) { "unsupported DNS label" }
                labels += bytes.toString(Charsets.US_ASCII).lowercase(java.util.Locale.ROOT)
                expanded += length + 1
                require(expanded <= 254) { "oversized DNS name" }
                cursor += length
            }
        }
        if (end == -1) end = cursor
        require(end + 4 <= message.size) { "truncated DNS question" }
        val fields = ByteBuffer.wrap(message, end, 4)
        return Triple(labels.joinToString("."), fields.short.toInt() and 0xffff, fields.short.toInt() and 0xffff)
    }

    fun tcpFrame(message: ByteArray): ByteArray {
        require(message.size in 1..65535) { "invalid DNS TCP message length" }
        return ByteBuffer.allocate(message.size + 2).putShort(message.size.toShort()).put(message).array()
    }

    fun readTcpFrame(input: DataInputStream): ByteArray {
        val size = input.readUnsignedShort()
        require(size in HEADER_SIZE..65535) { "invalid DNS TCP frame" }
        return ByteArray(size).also { input.readFully(it) }
    }
}

class ProtectedDnsClient(
    private val upstream: InetSocketAddress,
    private val socketProtector: SocketProtector,
    private val datagramProtector: DatagramProtector,
    private val timeoutMillis: Int = 3_000,
    private val random: SecureRandom = SecureRandom(),
) {
    fun resolve(hostname: String): List<InetAddress> {
        val addresses = mutableListOf<InetAddress>()
        for (type in listOf(1, 28)) {
            val query = DnsWire.query(random.nextInt(0x10000), hostname, type)
            val reply = exchange(query)
            if (reply.responseCode == 0) addresses += readAddresses(reply.bytes, type)
        }
        if (addresses.isEmpty()) throw java.net.UnknownHostException(hostname)
        return addresses
    }

    fun exchange(query: ByteArray): DnsReply {
        val udpReply = exchangeUdp(query)
        if (!udpReply.truncated) return udpReply
        return exchangeTcp(query)
    }

    fun exchangeUdp(query: ByteArray): DnsReply = DatagramSocket().use { socket ->
            if (!datagramProtector.protect(socket)) throw IOException("VPN refused to protect DNS UDP socket")
            socket.soTimeout = timeoutMillis
            socket.connect(upstream)
            socket.send(DatagramPacket(query, query.size))
            val buffer = ByteArray(DnsWire.UDP_SAFE_SIZE)
            val packet = DatagramPacket(buffer, buffer.size)
            socket.receive(packet)
            DnsWire.validateReply(query, packet.data.copyOf(packet.length))
        }

    fun exchangeTcp(query: ByteArray): DnsReply = Socket().use { socket ->
            if (!socketProtector.protect(socket)) throw IOException("VPN refused to protect DNS TCP socket")
            socket.soTimeout = timeoutMillis
            socket.connect(upstream, timeoutMillis)
            val output = DataOutputStream(socket.getOutputStream())
            output.write(DnsWire.tcpFrame(query))
            output.flush()
            DnsWire.validateReply(query, DnsWire.readTcpFrame(DataInputStream(socket.getInputStream())))
        }

    private fun readAddresses(message: ByteArray, expectedType: Int): List<InetAddress> {
        val buffer = ByteBuffer.wrap(message)
        buffer.position(4)
        val questions = buffer.short.toInt() and 0xffff
        val answers = buffer.short.toInt() and 0xffff
        buffer.position(12)
        repeat(questions) {
            skipName(buffer, message)
            require(buffer.remaining() >= 4) { "truncated DNS question" }
            buffer.position(buffer.position() + 4)
        }
        val result = mutableListOf<InetAddress>()
        repeat(answers.coerceAtMost(128)) {
            skipName(buffer, message)
            require(buffer.remaining() >= 10) { "truncated DNS answer" }
            val type = buffer.short.toInt() and 0xffff
            val klass = buffer.short.toInt() and 0xffff
            buffer.int
            val length = buffer.short.toInt() and 0xffff
            require(length <= buffer.remaining()) { "truncated DNS rdata" }
            if (klass == 1 && type == expectedType && length == if (type == 1) 4 else 16) {
                val raw = ByteArray(length)
                buffer.get(raw)
                result += InetAddress.getByAddress(raw)
            } else {
                buffer.position(buffer.position() + length)
            }
        }
        return result
    }

    private fun skipName(buffer: ByteBuffer, message: ByteArray) {
        var labels = 0
        while (true) {
            require(buffer.hasRemaining() && labels++ < 128) { "invalid DNS name" }
            val length = buffer.get().toInt() and 0xff
            when {
                length == 0 -> return
                length and 0xc0 == 0xc0 -> {
                    require(buffer.hasRemaining()) { "truncated DNS pointer" }
                    val offset = ((length and 0x3f) shl 8) or (buffer.get().toInt() and 0xff)
                    require(offset in 0 until message.size) { "invalid DNS pointer" }
                    return
                }
                length <= 63 -> {
                    require(buffer.remaining() >= length) { "truncated DNS label" }
                    buffer.position(buffer.position() + length)
                }
                else -> throw IllegalArgumentException("invalid DNS label encoding")
            }
        }
    }
}
