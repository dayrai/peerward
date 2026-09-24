package io.github.peerward.peerward.vpn

import io.github.peerward.peerward.nativecore.NativeRuntimeStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RelayTransportTest {
    @Test
    fun tunnelHealthFailsClosedWithoutEveryNativeProof() {
        assertEquals(TunnelHealth.DEGRADED, authoritativeTunnelHealth(null))
        assertEquals(
            TunnelHealth.DEGRADED,
            authoritativeTunnelHealth(NativeRuntimeStatus(true, 9)),
        )
        assertEquals(
            TunnelHealth.DEGRADED,
            authoritativeTunnelHealth(
                NativeRuntimeStatus(
                    signedStateComplete = false,
                    signedRevision = 0,
                    primaryRelayAuthenticated = true,
                ),
            ),
        )
        assertEquals(
            TunnelHealth.DEGRADED,
            authoritativeTunnelHealth(
                NativeRuntimeStatus(
                    signedStateComplete = true,
                    signedRevision = 0,
                    primaryRelayAuthenticated = true,
                ),
            ),
        )
        assertEquals(
            TunnelHealth.HEALTHY,
            authoritativeTunnelHealth(
                NativeRuntimeStatus(
                    signedStateComplete = true,
                    signedRevision = 9,
                    primaryRelayAuthenticated = true,
                ),
            ),
        )
    }

    @Test
    fun validatesExactIpv4AndIpv6Lengths() {
        val ipv4 = ByteArray(20).also { it[0] = 0x45; it[2] = 0; it[3] = 20 }
        val ipv6 = ByteArray(40).also { it[0] = 0x60 }
        assertTrue(NoiseRelayTransport.isIpPacket(ipv4))
        assertTrue(NoiseRelayTransport.isIpPacket(ipv6))
        assertFalse(NoiseRelayTransport.isIpPacket(ipv4 + 0))
        assertFalse(NoiseRelayTransport.isIpPacket(ByteArray(20)))
    }

}
