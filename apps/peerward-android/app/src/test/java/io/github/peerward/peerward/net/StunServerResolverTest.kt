package io.github.peerward.peerward.net

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class StunServerResolverTest {
    @Test
    fun resolvesBothFamiliesAndGivesEveryServerABoundedShare() = runBlocking {
        val servers = listOf("many.example:3478", "other.example:443")
        val lookup: (String) -> Array<InetAddress> = { host ->
            if (host == "other.example") arrayOf(InetAddress.getByName("192.0.2.200")) else {
                (listOf("0.0.0.0", "224.0.0.1", "255.255.255.255", "2001:db8::1") +
                    (1..32).map { "192.0.2.$it" }).map(InetAddress::getByName).toTypedArray()
            }
        }
        val ipv4 = StunServerResolver.resolveWith(servers, false, lookup)
        assertEquals(8, ipv4.size)
        assertEquals(InetSocketAddress("192.0.2.1", 3478), ipv4[0])
        assertEquals(InetSocketAddress("192.0.2.200", 443), ipv4[1])
        assertEquals(listOf(InetSocketAddress("2001:db8::1", 3478)),
            StunServerResolver.resolveWith(servers, true, lookup))
        val allServers = (1..8).map { "s$it.example:3478" }
        assertEquals(8, StunServerResolver.resolveWith(allServers, false, { host ->
            arrayOf(InetAddress.getByName("192.0.2.${host.substringBefore('.').drop(1)}"))
        }).size)
    }

    @Test
    fun stalledNetworkDnsTimesOutWhileLiteralAddressesRemainUsable() = runBlocking {
        val release = CountDownLatch(1)
        val entered = CountDownLatch(1)
        try {
            val results = StunServerResolver.resolveWith(
                listOf("stall.example:3478", "192.0.2.1:443", "[::1]:3478"), false,
                { entered.countDown(); release.await(5, TimeUnit.SECONDS); emptyArray() }, 50,
            )
            assertTrue(entered.await(1, TimeUnit.SECONDS))
            assertEquals(listOf(InetSocketAddress("192.0.2.1", 443)), results)
            assertEquals(listOf(InetSocketAddress("::1", 3478)),
                StunServerResolver.resolveWith(listOf("[::1]:3478"), true, { error("literal lookup") }))
        } finally {
            release.countDown()
        }
    }

    @Test
    fun newDiscoveryUsesNewNetworkAnswersAndDeduplicatesDestinations() = runBlocking {
        val servers = listOf("stun.example:3478", "same.example:3478")
        for (address in listOf("192.0.2.1", "192.0.2.2")) {
            val result = StunServerResolver.resolveWith(servers, false,
                { Array(32) { InetAddress.getByName(address) } })
            assertEquals(listOf(InetSocketAddress(address, 3478)), result)
        }
        assertTrue(StunServerResolver.resolveWith(servers, false, { throw java.net.UnknownHostException() }).isEmpty())
    }
}
