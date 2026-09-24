package io.github.peerward.peerward

import android.content.Context
import android.content.Intent
import android.app.Activity
import android.net.VpnService
import android.os.Process
import android.os.SystemClock
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import io.github.peerward.peerward.crypto.DeviceKeyStore
import io.github.peerward.peerward.profile.PeerProfile
import io.github.peerward.peerward.profile.ProfileStore
import io.github.peerward.peerward.vpn.PeerwardVpnService
import io.github.peerward.peerward.vpn.TunnelHealth
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.MessageDigest

/** Host kills the old process (and optionally reboots); this runner then resumes stored keys. */
@RunWith(AndroidJUnit4::class)
class StoredRuntimeRestartInstrumentedTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test fun reopensStoredKeysAndAuthenticatesTunAfterHostRestart() {
        val reportFile = File(context.filesDir, "wireguard-process-restart.json")
        val report = JSONObject().put("passed", false).put("new_pid", Process.myPid())
            .put("scope", "manual restart from persisted committed profile and Keystore after actual process death")
        val diagnostics = RuntimeStopDiagnostics { null }
        fun phase(value: String) {
            diagnostics.phase.set(value)
            report.put("phase", value).put("uptime_ms", SystemClock.elapsedRealtime())
            reportFile.writeText(report.toString(2))
        }
        var activity: Activity? = null
        try {
            phase("reading_restart_baseline")
            val before = JSONObject(File(context.filesDir, "wireguard-restart-baseline.json").readText())
            report.put("old_pid", before.getInt("pid"))
            phase("loading_committed_profile")
            val profile = requireNotNull(ProfileStore(context).load())
            assertEquals("restart changed committed identity", before.getString("identity_digest"), digest(profile))
            assertNotEquals("host did not replace the application process", before.getInt("pid"), Process.myPid())
            phase("checking_keystore")
            assertTrue(DeviceKeyStore(context).exists(profile.deviceKeyId))
            phase("checking_vpn_permission")
            assertNull("VPN permission was lost across process restart", VpnService.prepare(context))
            phase("launching_activity")
            activity = InstrumentationRegistry.getInstrumentation().startActivitySync(
                Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
            phase("starting_vpn_service")
            context.startService(Intent(context, PeerwardVpnService::class.java).setAction(PeerwardVpnService.ACTION_START))
            phase("awaiting_runtime_health")
            val deadline = SystemClock.elapsedRealtime() + 30_000
            while (PeerwardVpnService.health.value != TunnelHealth.HEALTHY && SystemClock.elapsedRealtime() < deadline) SystemClock.sleep(100)
            assertEquals(TunnelHealth.HEALTHY, PeerwardVpnService.health.value)
            phase("verifying_tun_echo")
            requireNotNull(TunPeerScenario.optional()).use { it.verify("after host process restart") }
            phase("verifying_committed_identity")
            assertEquals(before.getString("identity_digest"), digest(requireNotNull(ProfileStore(context).load())))
            report.put("keys_restored", true).put("tun_echo_verified", true).put("passed", true)
            phase("verifying_optional_os_revocation")
            VpnRevocationScenario.optional(context, UiDevice.getInstance(InstrumentationRegistry.getInstrumentation()))
            phase("complete")
        } finally {
            reportFile.writeText(report.toString(2))
            diagnostics.close()
            activity?.let { opened -> opened.runOnUiThread { opened.finish() } }
        }
    }

    @After fun cleanup() {
        context.startService(Intent(context, PeerwardVpnService::class.java).setAction(PeerwardVpnService.ACTION_STOP))
        ProfileStore(context).load()?.let { profile ->
            listOfNotNull(profile.deviceKeyId, profile.previousDeviceKeyId, profile.pendingDeviceKeyId).distinct()
                .forEach { DeviceKeyStore(context).delete(it) }
        }
        ProfileStore(context).clear()
    }

    companion object {
        private fun digest(profile: PeerProfile): String = MessageDigest.getInstance("SHA-256")
            .digest(listOf(profile.meshId, profile.peerId, profile.deviceKeyId, profile.credential).joinToString("\n").toByteArray())
            .joinToString("") { "%02x".format(it) }

        fun saveBaseline(context: Context) {
            val profile = requireNotNull(ProfileStore(context).load())
            File(context.filesDir, "wireguard-restart-baseline.json").writeText(JSONObject()
                .put("pid", Process.myPid()).put("identity_digest", digest(profile))
                .put("uptime_ms", SystemClock.elapsedRealtime()).toString(2))
        }
    }
}
