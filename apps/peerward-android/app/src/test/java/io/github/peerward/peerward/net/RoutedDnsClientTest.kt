package io.github.peerward.peerward.net

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertTrue
import org.junit.Test

class RoutedDnsClientTest {
    @Test
    fun configuredUdpResolverReturnsOnlyAMatchingQuestion() {
        val executor = Executors.newSingleThreadExecutor()
        try {
            DatagramSocket(0, InetAddress.getLoopbackAddress()).use { server ->
                server.soTimeout = 2000
                val task = executor.submit {
                    val packet = DatagramPacket(ByteArray(4096), 4096)
                    server.receive(packet)
                    val reply = packet.data.copyOf(packet.length).also { it[2] = 0x81.toByte(); it[3] = 0x80.toByte() }
                    server.send(DatagramPacket(reply, reply.size, packet.socketAddress))
                }
                val query = DnsWire.query(712, "printer.office.example")
                val result = RoutedDnsClient(InetSocketAddress(server.localAddress, server.localPort)).exchangeUdp(query)
                assertTrue(result.bytes.copyOfRange(12, result.bytes.size).contentEquals(query.copyOfRange(12, query.size)))
                task.get(3, TimeUnit.SECONDS)
            }
        } finally { executor.shutdownNow() }
    }
}
