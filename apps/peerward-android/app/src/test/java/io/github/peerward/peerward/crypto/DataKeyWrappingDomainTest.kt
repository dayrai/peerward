package io.github.peerward.peerward.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class DataKeyWrappingDomainTest {
    @Test fun independentWireguardAliasHasItsOwnAuthenticatedPurpose() {
        val noise = dataKeyWrappingDomain("peerward.device.noise-wrap")
        val wireguard = dataKeyWrappingDomain("peerward.device.wireguard-wrap")
        assertArrayEquals("peerward/android-noise-key/v1\u0000".toByteArray(), noise)
        assertArrayEquals("peerward/android-wireguard-key/v1\u0000".toByteArray(), wireguard)
        assertFalse(noise.contentEquals(wireguard))
        assertThrows(IllegalStateException::class.java) {
            dataKeyWrappingDomain("peerward.device.identity-wrap")
        }
        assertThrows(IllegalArgumentException::class.java) {
            dataKeyWrappingDomain("foreign.device.wireguard-wrap")
        }
    }
}
