package io.github.peerward.peerward

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import io.github.peerward.peerward.crypto.DeviceKeyStore
import io.github.peerward.peerward.profile.ProfileStore
import io.github.peerward.peerward.vpn.PeerwardVpnService
import io.github.peerward.peerward.vpn.TunnelHealth
import org.json.JSONObject
import org.junit.Assert.assertNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import java.io.File

internal object VpnRevocationScenario {
    fun optional(context: Context, device: UiDevice) {
        if (InstrumentationRegistry.getArguments().getString("peerwardOsRevoke") != "true") return
        val profile = requireNotNull(ProfileStore(context).load())
        val keyIds = listOfNotNull(profile.deviceKeyId, profile.previousDeviceKeyId, profile.pendingDeviceKeyId).distinct()
        val activity = Intent().setComponent(ComponentName(context.packageName + ".test", VpnRevocationActivity::class.java.name))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        val report = JSONObject().put("passed", false).put("scope", "Android revokes the VPN when the separate test APK obtains VPN ownership")
        val file = File(context.filesDir, "wireguard-os-revocation.json")
        try {
            assertEquals(TunnelHealth.HEALTHY, PeerwardVpnService.health.value)
            assertNotNull(PeerwardVpnService.activeResourceIdentity)
            context.startActivity(activity)
            val deadline = SystemClock.elapsedRealtime() + 15_000
            // prepare() can prepare a previously consented app again; it is not
            // a read-only revocation check. Observe the real onRevoke shutdown.
            while ((PeerwardVpnService.activeResourceIdentity != null || PeerwardVpnService.health.value != TunnelHealth.STOPPED)
                && SystemClock.elapsedRealtime() < deadline) {
                device.findObject(By.res("android:id/button1"))?.click()
                SystemClock.sleep(100)
            }
            assertEquals("Android did not stop the revoked product VPN", TunnelHealth.STOPPED, PeerwardVpnService.health.value)
            assertNull("OS revocation retained TUN/WireGuard ownership", PeerwardVpnService.activeResourceIdentity)
            assertEquals("permission revocation must preserve the enrolled profile", profile, ProfileStore(context).load())
            assertTrue("permission revocation must preserve enrolled keys", keyIds.all { DeviceKeyStore(context).exists(it) })
            report.put("vpn_ownership_revoked", true).put("profile_preserved", true)
                .put("keys_preserved", true).put("owner_released", true).put("passed", true)
        } finally {
            context.startActivity(Intent(activity).setAction("peerward.test.STOP_VPN"))
            file.writeText(report.toString(2))
        }
    }
}
