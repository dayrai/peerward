package io.github.peerward.peerward.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer

class DnsWireTest {
    @Test
    fun vpnRevocationClosesDnsSocketsBeforeNetworkIo() {
        var udp: DatagramSocket? = null
        var tcp: Socket? = null
        val client = ProtectedDnsClient(
            InetSocketAddress(InetAddress.getLoopbackAddress(), 9),
            { socket -> tcp = socket; false },
            { socket -> udp = socket; false },
        )
        val query = DnsWire.query(7, "outside.example")
        assertThrows(IOException::class.java) { client.exchangeUdp(query) }
        assertTrue(requireNotNull(udp).isClosed)
        assertFalse(requireNotNull(udp).isConnected)
        assertThrows(IOException::class.java) { client.exchangeTcp(query) }
        assertTrue(requireNotNull(tcp).isClosed)
        assertFalse(requireNotNull(tcp).isConnected)
    }

    @Test
    fun createsStrictQueryAndFramesTcp() {
        val query = DnsWire.query(0x1234, "peer.mesh.test")
        assertEquals(0x1234, ByteBuffer.wrap(query).short.toInt() and 0xffff)
        val frame = DnsWire.tcpFrame(query)
        assertEquals(query.size, ByteBuffer.wrap(frame).short.toInt() and 0xffff)
        assertTrue(query.contentEquals(DnsWire.readTcpFrame(DataInputStream(ByteArrayInputStream(frame)))))
        assertThrows(IllegalArgumentException::class.java) { DnsWire.query(1, "bad_label.mesh") }
    }

    @Test
    fun validatesTruncationAndRejectsMismatch() {
        val query = DnsWire.query(7, "peer.mesh")
        val truncated = query.copyOf().also { it[2] = 0x82.toByte(); it[3] = 0 }
        val reply = DnsWire.validateReply(query, truncated)
        assertTrue(reply.truncated)
        assertEquals(0, reply.responseCode)
        val complete = truncated.copyOf().also { it[2] = 0x81.toByte(); it[3] = 0x80.toByte() }
        assertFalse(DnsWire.validateReply(query, complete).truncated)
        complete[1] = 8
        assertThrows(IllegalArgumentException::class.java) { DnsWire.validateReply(query, complete) }
        val wrongQuestion = DnsWire.query(7, "evil.mesh").also { it[2] = 0x81.toByte() }
        assertThrows(IllegalArgumentException::class.java) { DnsWire.validateReply(query, wrongQuestion) }
        assertThrows(IllegalArgumentException::class.java) { DnsWire.validateReply(query, truncated.copyOf(12)) }
    }
}
