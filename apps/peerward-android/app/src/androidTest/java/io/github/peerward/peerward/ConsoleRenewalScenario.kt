package io.github.peerward.peerward

import android.content.Context
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import io.github.peerward.peerward.profile.ProfileStore
import io.github.peerward.peerward.runtime.MobileRuntimeState
import io.github.peerward.peerward.vpn.PeerwardVpnService
import io.github.peerward.peerward.vpn.TunnelHealth
import org.json.JSONObject
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import java.io.File

/** Host requests renewal through Control; this code cannot impersonate a control message. */
object ConsoleRenewalScenario {
    fun optional(context: Context) {
        if (InstrumentationRegistry.getArguments().getString("peerwardConsoleRenewal") != "true") return
        val original = requireNotNull(ProfileStore(context).load())
        val marker = File(context.filesDir, "console-renewal-ready.json")
        try {
            val pending = File(context.filesDir, "console-renewal-ready.tmp")
            pending.writeText(JSONObject().put("mesh_id", original.meshId).put("peer_id", original.peerId).toString())
            check(pending.renameTo(marker)) { "could not publish test readiness" }
            val deadline = SystemClock.elapsedRealtime() + 120_000
            var stableSince: Long? = null
            while (SystemClock.elapsedRealtime() < deadline) {
                val current = ProfileStore(context).load()
                if (current != null && current.deviceKeyId != original.deviceKeyId &&
                    current.pendingRotationId == null && PeerwardVpnService.health.value == TunnelHealth.HEALTHY) {
                    assertNotEquals("renewal retained the old credential", original.credential, current.credential)
                    assertNotEquals("renewal retained the old Noise key", original.localNoisePublic, current.localNoisePublic)
                    assertNotEquals("renewal retained the old WireGuard key", original.localWireguardPublic, current.localWireguardPublic)
                    assertTrue("renewal changed the device identity", current.peerId == original.peerId && current.meshId == original.meshId)
                    // A new connection must not immediately stage another unrequested rotation.
                    val now = SystemClock.elapsedRealtime()
                    if (stableSince == null) stableSince = now
                    if (now - requireNotNull(stableSince) >= 2_000) return
                } else {
                    stableSince = null
                }
                SystemClock.sleep(100)
            }
            val current = ProfileStore(context).load()
            throw AssertionError("console renewal did not settle within 120 seconds: " +
                "key_changed=${current?.deviceKeyId != original.deviceKeyId}, " +
                "pending=${current?.pendingRotationId != null}, health=${PeerwardVpnService.health.value}, " +
                "runtime=${MobileRuntimeState.diagnosticsJson()}")
        } finally {
            marker.delete()
        }
    }
}
