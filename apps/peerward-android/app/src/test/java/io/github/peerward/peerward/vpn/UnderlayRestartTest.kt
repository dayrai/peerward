package io.github.peerward.peerward.vpn

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class UnderlayRestartTest {
    @Test
    fun privateRelayNetworkIsUsableBeforePublicValidationWithValidatedFallbackPreferred() {
        val selection = UnderlaySelection<String>()
        val privateWifi = underlayPreference(true, true, false, 2)
        val cellular = underlayPreference(true, true, true, 1)
        val validatedWifi = underlayPreference(true, true, true, 2)
        assertEquals("private-wifi", selection.update("private-wifi", privateWifi))
        assertEquals("cellular", selection.update("cellular", cellular))
        assertEquals("private-wifi", selection.update("private-wifi", validatedWifi))
        assertNull(underlayPreference(false, true, true, 1)) // IMS/MMS without Internet.
        assertNull(underlayPreference(true, false, true, 2)) // Another VPN.
    }
    @Test
    fun initialCallbackDoesNotRestartBeforeTheRuntimeStarts() {
        assertFalse(shouldRestartForUnderlayChange(false, TunnelHealth.STOPPED))
        assertFalse(shouldRestartForUnderlayChange(false, TunnelHealth.CONNECTING))
    }

    @Test
    fun activeRuntimeAndNetworkRecoveryBothRestart() {
        assertTrue(shouldRestartForUnderlayChange(true, TunnelHealth.HEALTHY))
        assertTrue(shouldRestartForUnderlayChange(false, TunnelHealth.RECONNECTING))
    }

    @Test
    fun validatedWifiReplacesCellularEvenWhenCellularArrivedFirst() {
        val selection = UnderlaySelection<String>()
        assertEquals("cellular", selection.update("cellular", 1))
        assertEquals("cellular", selection.update("wifi", null)) // Not yet validated.
        assertEquals("wifi", selection.update("wifi", 2))
        assertEquals("wifi", selection.update("cellular", 1)) // Later capability callback.
    }

    @Test
    fun lostWifiFallsBackToAnAlreadyKnownNetworkThenCanReturn() {
        val selection = UnderlaySelection<String>()
        selection.update("cellular", 1)
        selection.update("wifi", 2)
        assertEquals("cellular", selection.update("wifi", null))
        assertEquals("replacement-wifi", selection.update("replacement-wifi", 2))
        assertEquals("replacement-wifi", selection.update("wifi", null)) // Delayed old loss callback.
    }

    @Test
    fun equalPreferenceAndUnrelatedLossDoNotSwitchTheCurrentNetwork() {
        val selection = UnderlaySelection<String>()
        selection.update("wifi-a", 2)
        assertEquals("wifi-a", selection.update("wifi-b", 2))
        assertEquals("wifi-a", selection.update("cellular", null))
        assertEquals("wifi-b", selection.update("wifi-a", null))
    }

    @Test
    fun losingAllValidatedNetworksWaitsForAUsableReplacement() {
        val selection = UnderlaySelection<String>()
        assertNull(selection.update("unvalidated", null))
        selection.update("wifi", 2)
        assertNull(selection.update("wifi", null))
        assertEquals("cellular", selection.update("cellular", 1))
    }
}
