package io.github.peerward.peerward.vpn

import io.github.peerward.peerward.nativecore.NativeDnsTransport
import io.github.peerward.peerward.nativecore.NativeTunPumpAction
import io.github.peerward.peerward.net.DnsWire
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class TunDnsProxyTest {
    @Test
    fun privateFailureDoesNotUseThePublicFallback() = runBlocking {
        val fallback = java.net.DatagramSocket(0, java.net.InetAddress.getLoopbackAddress())
        fallback.use {
            fallback.soTimeout = 100
            val upstream = io.github.peerward.peerward.net.ProtectedDnsClient(
                java.net.InetSocketAddress(fallback.localAddress, fallback.localPort), { true }, { true }, 100,
            )
            val transport = object : PacketTransport {
                override suspend fun send(packet: ByteArray) = error("unused")
                override suspend fun receive(): ByteArray = error("unused")
                override suspend fun resolveDns(query: ByteArray, sourceAddress: ByteArray, suffix: String) = ByteArray(0)
                override suspend fun managedDnsRoute(query: ByteArray, sourceAddress: ByteArray) =
                    io.github.peerward.peerward.nativecore.ManagedDnsRoute(7, listOf(java.net.InetSocketAddress("10.0.0.1", 53)))
                override fun dnsConfigurationActive(version: Long, sourceAddress: ByteArray) = version == 7L
                override fun close() = Unit
            }
            val request = NativeTunPumpAction.Resolve(1, NativeDnsTransport.UDP, byteArrayOf(10,0,0,2), DnsWire.query(91, "private.office.example"))
            // The configured upstream would recurse into the local proxy. It is skipped,
            // and exhaustion remains terminal even when a public fallback is available.
            assertTrue(TunDnsProxy(listOf("10.0.0.1"), "mesh.test", upstream, 1280).resolve(request, transport).isEmpty())
            org.junit.Assert.assertThrows(java.net.SocketTimeoutException::class.java) {
                fallback.receive(java.net.DatagramPacket(ByteArray(4096), 4096))
            }
        }
        Unit
    }

    @Test
    fun executesOnlyTheRustIssuedSignedStateResolution() = runBlocking {
        val query = DnsWire.query(0x1234, "laptop.mesh.test")
        val request = NativeTunPumpAction.Resolve(
            9,
            NativeDnsTransport.UDP,
            byteArrayOf(10, 0, 0, 2),
            query,
        )
        val transport = object : PacketTransport {
            override suspend fun send(packet: ByteArray) = error("unused")
            override suspend fun receive(): ByteArray = error("unused")
            override suspend fun resolveDns(
                query: ByteArray,
                sourceAddress: ByteArray,
                suffix: String,
            ): ByteArray {
                assertEquals("mesh.test", suffix)
                assertTrue(sourceAddress.contentEquals(byteArrayOf(10, 0, 0, 2)))
                return query.copyOf().also { it[2] = 0x84.toByte() }
            }
            override fun close() = Unit
        }
        val response = TunDnsProxy(listOf("10.0.0.1"), "mesh.test", null, 1_380)
            .resolve(request, transport)
        assertEquals(0x84, response[2].toInt() and 0xff)
    }

    @Test
    fun missingPlatformResolverReturnsEmptyForNativeServfail() = runBlocking {
        val request = NativeTunPumpAction.Resolve(
            12,
            NativeDnsTransport.TCP,
            byteArrayOf(10, 0, 0, 2),
            DnsWire.query(0x7788, "outside.example"),
        )
        val response = TunDnsProxy(listOf("10.0.0.1"), "mesh.test", null, 1_280)
            .resolve(request, null)
        assertTrue(response.isEmpty())
    }
}
