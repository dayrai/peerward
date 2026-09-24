package io.github.peerward.peerward

import android.content.Context
import android.os.PowerManager
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import io.github.peerward.peerward.vpn.PeerwardVpnService
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import java.io.File

/** Real OS idle transition; USB-powered observations are not battery-drain measurements. */
internal object PowerLifecycleScenario {
    fun optional(context: Context, device: UiDevice, probe: TunPeerScenario?) {
        val seconds = InstrumentationRegistry.getArguments().getString("peerwardPowerSeconds")?.toLong() ?: return
        require(seconds in 30..300 && probe != null)
        val report = JSONObject().put("requested_idle_seconds", seconds).put("passed", false)
            .put("scope", "screen off, forced deep Doze, wake and same-owner TUN recovery; no battery-drain claim")
        val file = File(context.filesDir, "wireguard-power-lifecycle.json")
        val identity = requireNotNull(PeerwardVpnService.activeResourceIdentity)
        val power = context.getSystemService(PowerManager::class.java)
        try {
            device.sleep()
            val command = device.executeShellCommand("dumpsys deviceidle force-idle deep")
            report.put("force_idle_response", command.trim())
            val deadline = SystemClock.elapsedRealtime() + 10_000
            while (!power.isDeviceIdleMode && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(100)
            report.put("deep_idle_entered", power.isDeviceIdleMode)
            assertTrue("OS did not enter deep Doze", power.isDeviceIdleMode)
            assertTrue("screen remained interactive", !power.isInteractive)
            val started = SystemClock.elapsedRealtime()
            file.writeText(report.toString(2))
            // The host wakes us after its elapsed timer. An app sleep uses CPU uptime
            // and can remain suspended far longer than the requested idle interval.
            while (power.isDeviceIdleMode && SystemClock.elapsedRealtime() - started < (seconds + 90) * 1_000) {
                SystemClock.sleep(250)
            }
            val observed = SystemClock.elapsedRealtime() - started
            report.put("observed_idle_ms", observed)
            assertTrue("OS left deep Doze early", observed >= seconds * 1_000)
            assertTrue("host did not wake the device", !power.isDeviceIdleMode)
            assertEquals("Doze replaced the live TUN/WireGuard owner", identity, PeerwardVpnService.activeResourceIdentity)
        } finally {
            device.executeShellCommand("dumpsys deviceidle unforce")
            device.wakeUp()
            device.executeShellCommand("wm dismiss-keyguard")
            file.writeText(report.toString(2))
        }
        val ready = SystemClock.elapsedRealtime()
        assertTrue("TUN did not recover after deep Doze", probe.roundTrip(30_000))
        report.put("wake_to_reply_ms", SystemClock.elapsedRealtime() - ready)
        report.put("owner_retained", identity == PeerwardVpnService.activeResourceIdentity)
        assertEquals(identity, PeerwardVpnService.activeResourceIdentity)
        report.put("passed", true)
        file.writeText(report.toString(2))
    }
}
