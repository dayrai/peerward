package io.github.peerward.peerward.net

import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket

/** Management-configured resolvers follow VPN routing, including a selected Internet exit. */
class RoutedDnsClient(private val upstream: InetSocketAddress, private val timeoutMillis: Int = 1_000) {
    fun exchangeUdp(query: ByteArray): DnsReply = DatagramSocket().use { socket ->
        socket.soTimeout = timeoutMillis
        socket.connect(upstream)
        socket.send(DatagramPacket(query, query.size))
        val buffer = ByteArray(4096)
        val packet = DatagramPacket(buffer, buffer.size)
        socket.receive(packet)
        DnsWire.validateReply(query, buffer.copyOf(packet.length))
    }
    fun exchangeTcp(query: ByteArray): DnsReply = Socket().use { socket ->
        socket.soTimeout = timeoutMillis
        socket.connect(upstream, timeoutMillis)
        val output = DataOutputStream(socket.getOutputStream())
        output.write(DnsWire.tcpFrame(query)); output.flush()
        DnsWire.validateReply(query, DnsWire.readTcpFrame(DataInputStream(socket.getInputStream())))
    }
}
