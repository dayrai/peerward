package io.github.peerward.peerward.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assert.assertSame
import org.junit.Test
import java.net.Socket

class SocketProtectionTest {
    @Test
    fun protectsSocketAtCreationAndFailsClosed() {
        var calls = 0
        ProtectingSocketFactory { socket ->
            calls++
            assertFalse(socket.isConnected)
            true
        }.createSocket().close()
        assertEquals(1, calls)
        var refused: Socket? = null
        assertThrows(IllegalStateException::class.java) {
            ProtectingSocketFactory { refused = it; false }.createSocket()
        }
        assertTrue(requireNotNull(refused).isClosed)
    }

    @Test fun protectionExceptionClosesSocketAndKeepsOriginalFailure() {
        var socket: Socket? = null
        val failure = IllegalStateException("VPN was revoked")
        val thrown = assertThrows(IllegalStateException::class.java) {
            ProtectingSocketFactory { socket = it; throw failure }.createSocket()
        }
        assertSame(failure, thrown)
        assertTrue(requireNotNull(socket).isClosed)
    }

    @Test fun connectionSetupFailureClosesProtectedSocket() {
        var socket: Socket? = null
        assertThrows(IllegalArgumentException::class.java) {
            ProtectingSocketFactory { socket = it; true }.createSocket("127.0.0.1", -1)
        }
        assertTrue(requireNotNull(socket).isClosed)
    }
}
