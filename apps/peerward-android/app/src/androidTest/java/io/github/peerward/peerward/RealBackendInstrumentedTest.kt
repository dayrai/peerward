package io.github.peerward.peerward

import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.SystemClock
import android.webkit.WebView
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.By
import androidx.test.uiautomator.UiDevice
import androidx.test.uiautomator.Until
import io.github.peerward.peerward.crypto.DeviceKeyStore
import io.github.peerward.peerward.join.JoinBundle
import io.github.peerward.peerward.profile.PeerProfile
import io.github.peerward.peerward.profile.ProfileStore
import io.github.peerward.peerward.vpn.PeerwardVpnService
import io.github.peerward.peerward.vpn.TunnelHealth
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.junit.After
import org.junit.Before
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.regex.Pattern

@RunWith(AndroidJUnit4::class)
class RealBackendInstrumentedTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private var preserveForHostRestart = false

    @Before
    fun prepareCleanProfile() {
        clearStoredProfile()
    }

    @After
    fun cleanup() {
        if (preserveForHostRestart) return
        context.startService(
            Intent(context, PeerwardVpnService::class.java).setAction(PeerwardVpnService.ACTION_STOP),
        )
        clearStoredProfile()
    }

    private fun clearStoredProfile() {
        val profiles = ProfileStore(context)
        profiles.load()?.let { profile ->
            listOfNotNull(profile.deviceKeyId, profile.previousDeviceKeyId, profile.pendingDeviceKeyId)
                .distinct().forEach { runCatching { DeviceKeyStore(context).delete(it) } }
        }
        profiles.clear()
        java.io.File(context.filesDir, "console-renewal-ready.json").delete()
    }

    @Test
    fun joinsResolvesMeshDnsAndRecoversAcrossARealUnderlayChange() {
        val link = requireNotNull(
            InstrumentationRegistry.getArguments().getString(JOIN_ARGUMENT),
        ) { "the API 28/36 emulator gate requires a real one-time Join link" }
        val device = UiDevice.getInstance(InstrumentationRegistry.getInstrumentation())
        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(link), context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

        val activity = InstrumentationRegistry.getInstrumentation().startActivitySync(intent) as MainActivity
        var tunnelProbe: TunPeerScenario? = null
        try {
            assertTrue(
                waitForWebElementText(
                    activity,
                    "#join-submit",
                    UI_TIMEOUT_MS,
                    "Verify and join",
                    "验证并加入",
                ),
            )
            assertTrue(clickWebElement(activity, "join-submit"))

            var profile = waitForProfile(activity)
            InstrumentationRegistry.getArguments().getString("peerwardRelayTransport")?.let { encoded ->
                val settings = org.json.JSONObject(String(android.util.Base64.decode(encoded, android.util.Base64.DEFAULT), Charsets.UTF_8))
                val carrier = InstrumentationRegistry.getArguments().getString("peerwardExpectedCarrier") ?: "wss"
                assertTrue(profile.relays.flatMap { it.endpoints }.all { it.startsWith("$carrier://") })
                profile = profile.copy(
                    relayCaPem = settings.getString("ca_pem"),
                    relayHttpConnectProxy = settings.optString("http_connect_proxy").ifEmpty { null },
                )
                ProfileStore(context).save(profile)
                assertEquals(profile, ProfileStore(context).load())
            }
            verifyCheckpointOwnership(profile)
            InstrumentationRegistry.getArguments().getString("peerwardExpectedStunServer")?.let { expected ->
                assertEquals("dynamic Mesh did not advertise its shared STUN service", listOf(expected), profile.stunServers)
            }
            val expectedRelayHost = InstrumentationRegistry.getArguments()
                .getString(EXPECTED_RELAY_HOST_ARGUMENT) ?: "10.0.2.2"
            val expectedRelayPort = InstrumentationRegistry.getArguments()
                .getString("peerwardExpectedRelayPort")?.toInt() ?: 7777
            assertTrue(
                profile.relays.flatMap { it.endpoints }
                    .any { endpoint -> java.net.URI(endpoint).let { it.host == expectedRelayHost && it.port == expectedRelayPort } },
            )

            assertTrue(
                waitForWebElementText(
                    activity,
                    "#connection-toggle",
                    UI_TIMEOUT_MS,
                    "Connect",
                    "连接",
                ),
            )
            assertTrue(clickWebElement(activity, "connection-toggle"))
            acceptVpnPermission(device)
            waitForHealth { it == TunnelHealth.HEALTHY }
            assertTrue(
                waitForWebElementText(
                    activity,
                    ".mobile-status",
                    UI_TIMEOUT_MS,
                    "Connected",
                    "已连接",
                ),
            )

            val bundle = JoinBundle.parse(link)
            val peerName = enrollmentPeerName(Build.MODEL, bundle.nonce)
            val resolved = runBlocking {
                withContext(Dispatchers.IO) {
                    InetAddress.getAllByName("$peerName.${profile.dnsSuffix}")
                }
            }
            assertTrue(resolved.any { it.hostAddress == profile.address.substringBefore('/') })
            ConsoleRenewalScenario.optional(context)
            ClientPreferencesScenario.verify()
            tunnelProbe = TunPeerScenario.optional()
            tunnelProbe?.verify("initial connection")
            val resources = requireNotNull(PeerwardVpnService.activeResourceIdentity)

            val wifiChange = InstrumentationRegistry.getArguments().getString("peerwardUnderlayChange") == "wifi"
            device.executeShellCommand(if (wifiChange) "svc wifi disable" else "cmd connectivity airplane-mode enable")
            try {
                waitForHealth { it != TunnelHealth.HEALTHY }
            } finally {
                device.executeShellCommand(if (wifiChange) "svc wifi enable" else "cmd connectivity airplane-mode disable")
            }
            waitForHealth { it == TunnelHealth.HEALTHY }
            assertEquals(TunnelHealth.HEALTHY, PeerwardVpnService.health.value)
            assertEquals("Network replacement reopened TUN or WireGuard ownership", resources, PeerwardVpnService.activeResourceIdentity)
            tunnelProbe?.verify("after underlay replacement")
            NetworkRecoveryScenario.optional(context, device, tunnelProbe)

            assertTrue(
                waitForWebElementText(
                    activity,
                    "#connection-toggle",
                    UI_TIMEOUT_MS,
                    "Disconnect",
                    "断开连接",
                ),
            )
            assertTrue(clickWebElement(activity, "connection-toggle"))
            waitForHealth { it == TunnelHealth.STOPPED }
            assertTrue(
                waitForWebElementText(
                    activity,
                    ".mobile-status",
                    UI_TIMEOUT_MS,
                    "Disconnected",
                    "未连接",
                ),
            )
            val recoveredKey = runBlocking { stageRecoveryFault(context) }
            context.startService(Intent(context, PeerwardVpnService::class.java).setAction(PeerwardVpnService.ACTION_START))
            waitForHealth { it == TunnelHealth.HEALTHY }
            assertEquals("staged identity was not committed after verified recovery", recoveredKey, requireNotNull(ProfileStore(context).load()).deviceKeyId)
            // Explicit disconnect destroyed the VPN Network. Application sockets
            // created on that Network may retain its netId; open a new socket for
            // this new VPN lifetime, then retain it across the Doze transition.
            tunnelProbe?.close()
            tunnelProbe = TunPeerScenario.optional()
            tunnelProbe?.verify("after explicit VPN restart and credential recovery")
            // Complete foreground UI/rotation checks before deliberate lockscreen
            // testing. Doze recovery itself uses authenticated TUN traffic and
            // must not depend on a hidden WebView gaining focus afterwards.
            PowerLifecycleScenario.optional(context, device, tunnelProbe)
            if (InstrumentationRegistry.getArguments().getString("peerwardHostRestart") == "true") {
                StoredRuntimeRestartInstrumentedTest.saveBaseline(context)
                preserveForHostRestart = true
                return
            }
            VpnRevocationScenario.optional(context, device)
            context.startService(Intent(context, PeerwardVpnService::class.java).setAction(PeerwardVpnService.ACTION_STOP))
            waitForHealth { it == TunnelHealth.STOPPED }
        } finally {
            tunnelProbe?.close()
            activity.runOnUiThread { activity.finish() }
        }
    }

    private fun waitForProfile(activity: MainActivity): PeerProfile {
        val deadline = SystemClock.elapsedRealtime() + NETWORK_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            runCatching { ProfileStore(context).load() }.getOrNull()?.let { return it }
            SystemClock.sleep(100)
        }
        val completed = CountDownLatch(1)
        var alert = "unavailable"
        activity.runOnUiThread {
            activity.findViewById<WebView>(R.id.peerward_web_view)?.evaluateJavascript(
                "(document.querySelector('.pw-error')?.textContent||'no error displayed').slice(0,300)",
            ) { value -> alert = value; completed.countDown() }
        }
        completed.await(WEB_ACTION_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        throw AssertionError("Join did not persist a profile before the timeout; alert=$alert, " +
            "runtime=${io.github.peerward.peerward.runtime.MobileRuntimeState.snapshots.value.payloadJson()}")
    }

    private fun clickWebElement(activity: MainActivity, id: String): Boolean {
        require(id.matches(Regex("[a-z-]+")))
        return evaluateWebBoolean(
            activity,
            "(function(){const element=document.getElementById('$id');" +
                "if(!element||element.disabled){return false;}" +
                "element.scrollIntoView({block:'center'});element.click();return true;})()",
        )
    }

    private fun waitForWebElementText(
        activity: MainActivity,
        selector: String,
        timeoutMillis: Long,
        vararg values: String,
    ): Boolean {
        require(selector.matches(Regex("[.#a-z-]+")))
        val expected = JSONArray(values.toList()).toString()
        val script = "(function(){const element=document.querySelector('$selector');" +
            "return !!element&&!element.disabled&&$expected.includes((element.textContent||'').trim());})()"
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (SystemClock.elapsedRealtime() < deadline) {
            if (evaluateWebBoolean(activity, script)) {
                return true
            }
            SystemClock.sleep(100)
        }
        val completed = CountDownLatch(1)
        var observed = "unavailable"
        activity.runOnUiThread {
            activity.findViewById<WebView>(R.id.peerward_web_view)?.evaluateJavascript(
                "(document.querySelector('$selector')?.textContent||'missing').trim().slice(0,100)",
            ) { value -> observed = value; completed.countDown() }
        }
        completed.await(WEB_ACTION_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        val state = io.github.peerward.peerward.runtime.MobileRuntimeState.snapshots.value
        throw AssertionError("UI $selector did not reach ${values.toList()}; observed=$observed, " +
            "phase=${state.connection}, sequence=${state.sequence}, focus=${activity.hasWindowFocus()}, " +
            "keyguard=${context.getSystemService(KeyguardManager::class.java).isKeyguardLocked}, " +
            "health=${PeerwardVpnService.health.value}, error=${state.lastError?.code}")
    }

    private fun evaluateWebBoolean(activity: MainActivity, script: String): Boolean {
        val completed = CountDownLatch(1)
        var value = false
        activity.runOnUiThread {
            val webView = activity.findViewById<WebView>(R.id.peerward_web_view)
            if (webView == null) {
                completed.countDown()
                return@runOnUiThread
            }
            webView.evaluateJavascript(script) { result ->
                value = result == "true"
                completed.countDown()
            }
        }
        return completed.await(WEB_ACTION_TIMEOUT_MS, TimeUnit.MILLISECONDS) && value
    }

    private fun acceptVpnPermission(device: UiDevice) {
        if (VpnService.prepare(context) == null) return
        val permissionPackage = VpnService.prepare(context)?.component?.packageName
            ?: "com.android.vpndialogs"
        val selectors = listOf(
            By.res("android:id/button1").pkg(permissionPackage),
            By.res("$permissionPackage:id/button1").pkg(permissionPackage),
            By.text(Pattern.compile("(?i)^(ok|allow)$")).pkg(permissionPackage),
        )
        val deadline = SystemClock.elapsedRealtime() + PERMISSION_TIMEOUT_MS
        while (SystemClock.elapsedRealtime() < deadline) {
            if (VpnService.prepare(context) == null) return
            for (selector in selectors) {
                val button = device.findObject(selector) ?: continue
                if (button.isEnabled) {
                    button.click()
                    break
                }
            }
            SystemClock.sleep(500)
        }
        val hierarchy = java.io.ByteArrayOutputStream()
        device.dumpWindowHierarchy(hierarchy)
        fail("VPN consent was not granted; foreground=${device.currentPackageName}, hierarchy=$hierarchy")
    }

    private fun verifyCheckpointOwnership(profile: PeerProfile) {
        val profiles = ProfileStore(context)
        val key = DeviceKeyStore(context).handle(profile.deviceKeyId)
        val opaque = requireNotNull(profiles.loadOpaque())
        val state = profiles.wireguardStateDirectory(profile)
        try {
            val ceiling = io.github.peerward.peerward.nativecore.NativeWireguardRuntime(opaque, key, state).use {
                org.junit.Assert.assertThrows(io.github.peerward.peerward.nativecore.PeerwardNativeException::class.java) {
                    io.github.peerward.peerward.nativecore.NativeWireguardRuntime(opaque, key, state).close()
                }
                org.json.JSONObject(java.io.File(state, "state.json").readText()).getLong("generation_ceiling")
            }
            io.github.peerward.peerward.nativecore.NativeWireguardRuntime(opaque, key, state).use {
                assertTrue(org.json.JSONObject(java.io.File(state, "state.json").readText()).getLong("generation_ceiling") > ceiling)
            }
        } finally { opaque.fill(0) }
    }

    private fun waitForHealth(predicate: (TunnelHealth) -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + NETWORK_TIMEOUT_MS
        while (!predicate(PeerwardVpnService.health.value)) {
            if (SystemClock.elapsedRealtime() >= deadline) {
                val evidence = io.github.peerward.peerward.runtime.MobileRuntimeState.snapshots.value.payloadJson()
                fail("VPN health transition timed out: health=${PeerwardVpnService.health.value}, runtime=$evidence")
            }
            SystemClock.sleep(100)
        }
    }

    private fun enrollmentPeerName(model: String, nonce: ByteArray): String {
        val base = model.mapNotNull { character ->
            when (character) {
                in 'a'..'z', in '0'..'9' -> character
                in 'A'..'Z' -> character.lowercaseChar()
                '-', ' ', '_' -> '-'
                else -> null
            }
        }
            .joinToString("")
            .trim('-')
            .ifEmpty { "device" }
            .take(50)
        val suffix = MessageDigest.getInstance("SHA-256")
            .digest(nonce)
            .take(6)
            .joinToString("") { "%02x".format(it) }
        return "$base-$suffix"
    }

    companion object {
        private const val JOIN_ARGUMENT = "peerwardJoinLink"
        private const val EXPECTED_RELAY_HOST_ARGUMENT = "peerwardExpectedRelayHost"
        private const val UI_TIMEOUT_MS = 15_000L
        private const val NETWORK_TIMEOUT_MS = 45_000L
        private const val PERMISSION_TIMEOUT_MS = 20_000L
        private const val WEB_ACTION_TIMEOUT_MS = 5_000L
    }
}
