package io.github.peerward.peerward

import io.github.peerward.peerward.vpn.PeerwardVpnService
import org.json.JSONObject
import org.junit.Assert.*

/** Runs against the real joined runtime; no invented Control receipt or simulated TUN. */
internal object ClientPreferencesScenario {
    fun verify() {
        fun read() = PeerwardVpnService.clientPreferences(JSONObject().put("operation","get"))
        val before = read()
        val identity = requireNotNull(PeerwardVpnService.activeResourceIdentity)
        val preferences = JSONObject(before.getJSONObject("preferences").toString()).put("allow_inbound",false)
        val change = JSONObject().put("operation","set").put("change",JSONObject()
            .put("request_id",java.util.UUID.randomUUID().toString()).put("expected_version",before.getLong("version"))
            .put("preferences",preferences))
        val saved = PeerwardVpnService.clientPreferences(change)
        assertEquals(before.getLong("version") + 1,saved.getLong("version"))
        assertFalse(saved.getJSONObject("preferences").getBoolean("allow_inbound"))
        assertEquals(saved.getLong("version"),PeerwardVpnService.clientPreferences(change).getLong("version"))
        val substituted = JSONObject(change.toString())
        substituted.getJSONObject("change").getJSONObject("preferences").put("allow_inbound",true)
        assertTrue(runCatching { PeerwardVpnService.clientPreferences(substituted) }.isFailure)
        val restore = JSONObject().put("operation","set").put("change",JSONObject()
            .put("request_id",java.util.UUID.randomUUID().toString()).put("expected_version",saved.getLong("version"))
            .put("preferences",before.getJSONObject("preferences")))
        PeerwardVpnService.clientPreferences(restore)
        assertEquals("A preference-only change must preserve the WireGuard owner",identity.second,PeerwardVpnService.activeResourceIdentity?.second)
        assertEquals(before.getJSONObject("preferences").getBoolean("allow_inbound"),read().getJSONObject("preferences").getBoolean("allow_inbound"))
    }
}
