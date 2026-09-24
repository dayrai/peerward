package io.github.peerward.peerward

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.peerward.peerward.net.DnsWire
import io.github.peerward.peerward.net.ProtectedDnsClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

@RunWith(AndroidJUnit4::class)
class ProtectedDnsInstrumentedTest {
    @Test
    fun udpTruncationRetriesOverProtectedTcp() {
        ServerSocket(0, 1, InetAddress.getLoopbackAddress()).use { tcpServer ->
            DatagramSocket(tcpServer.localPort, InetAddress.getLoopbackAddress()).use { udpServer ->
                tcpServer.soTimeout = 5000
                udpServer.soTimeout = 5000
                val serverError = AtomicReference<Throwable>()
                val udpThread = thread {
                    runCatching {
                    val request = DatagramPacket(ByteArray(512), 512)
                    udpServer.receive(request)
                    val id = ByteBuffer.wrap(request.data).short
                    val response = dnsHeader(id, 0x8200) + request.data.copyOfRange(12, request.length)
                    udpServer.send(DatagramPacket(response, response.size, request.socketAddress))
                    }.onFailure { serverError.set(it) }
                }
                val tcpThread = thread {
                    runCatching {
                    tcpServer.accept().use { socket ->
                        val query = DnsWire.readTcpFrame(DataInputStream(socket.getInputStream()))
                        val response = dnsHeader(ByteBuffer.wrap(query).short, 0x8180) + query.copyOfRange(12, query.size)
                        DataOutputStream(socket.getOutputStream()).write(DnsWire.tcpFrame(response))
                    }
                    }.onFailure { serverError.set(it) }
                }
                val tcpProtected = AtomicInteger()
                val udpProtected = AtomicInteger()
                val client = ProtectedDnsClient(
                    InetSocketAddress(InetAddress.getLoopbackAddress(), tcpServer.localPort),
                    { tcpProtected.incrementAndGet(); true },
                    { udpProtected.incrementAndGet(); true },
                )
                val reply = client.exchange(DnsWire.query(99, "peer.mesh"))
                assertFalse(reply.truncated)
                assertEquals(1, tcpProtected.get())
                assertEquals(1, udpProtected.get())
                udpThread.join()
                tcpThread.join()
                serverError.get()?.let { throw AssertionError("DNS fixture failed", it) }
            }
        }
    }

    private fun dnsHeader(id: Short, flags: Int): ByteArray = ByteBuffer.allocate(12)
        .putShort(id).putShort(flags.toShort()).putShort(1).putShort(0).putShort(0).putShort(0).array()
}
