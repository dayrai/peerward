package io.github.peerward.peerward.vpn

import org.junit.Assert.*
import org.junit.Test

class VpnProtectionTest {
    @Test fun only_verified_consistent_system_state_can_claim_lockdown() {
        assertEquals("unknown", observeVpnProtection(28) { error("unsupported query") }.state)
        assertEquals("unknown", observeVpnProtection(29) { throw SecurityException() }.state)
        assertEquals("unknown", observeVpnProtection(36) { false to true }.state)
        assertEquals("runtime_only", observeVpnProtection(29) { false to false }.state)
        assertEquals("runtime_only", observeVpnProtection(36) { true to false }.state)
        assertEquals("system_locked", observeVpnProtection(29) { true to true }.state)
        // Returning from settings must reflect disabling the lock, without sticky state.
        assertEquals("runtime_only", observeVpnProtection(29) { true to false }.state)
        assertEquals("unknown", VpnProtection().state)
    }
}
