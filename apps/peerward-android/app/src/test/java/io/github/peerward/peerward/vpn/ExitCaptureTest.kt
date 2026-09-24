package io.github.peerward.peerward.vpn

import java.math.BigInteger
import java.net.InetAddress
import org.junit.Assert.*
import org.junit.Test

class ExitCaptureTest {
    private fun captured(routes: List<String>, address: String): Boolean {
        val target = InetAddress.getByName(address).address
        return routes.any { route ->
            val (network, length) = route.split('/')
            val bytes = InetAddress.getByName(network).address
            bytes.size == target.size && BigInteger(1, bytes).shiftRight(bytes.size * 8 - length.toInt()) ==
                BigInteger(1, target).shiftRight(target.size * 8 - length.toInt())
        }
    }
    @Test fun defaults_capture_both_families_and_exceptions_are_exact() {
        val defaults = exitCapture(emptyList())
        assertEquals(2, defaults.size)
        for (ip in listOf("8.8.8.8", "192.168.1.2", "2606:4700::1", "fd80::10")) assertTrue(captured(defaults, ip))
        val routes = exitCapture(listOf("192.168.80.0/24", "fd80::/64"))
        assertFalse(captured(routes,"192.168.80.10")); assertFalse(captured(routes,"fd80::10"))
        assertTrue(captured(routes,"192.168.81.10")); assertTrue(captured(routes,"fd81::10"))
        assertTrue(captured(routes,"8.8.8.8")); assertTrue(captured(routes,"2606:4700::1"))
        assertEquals(routes, exitCapture(listOf("192.168.80.1/24", "fd80::1/64", "192.168.80.0/24")))
    }
    @Test fun default_route_or_hostname_is_not_a_local_lan_exception() {
        for (value in listOf("0.0.0.0/0", "::/0", "localhost/32", "192.168.1.1/33")) {
            assertThrows(IllegalArgumentException::class.java) { exitCapture(listOf(value)) }
        }
    }
}
