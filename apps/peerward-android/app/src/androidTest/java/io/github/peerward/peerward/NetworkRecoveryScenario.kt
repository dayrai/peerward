package io.github.peerward.peerward

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.uiautomator.UiDevice
import io.github.peerward.peerward.vpn.PeerwardVpnService
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertTrue
import java.io.File
import java.util.concurrent.atomic.AtomicLong

/** Physical Wi-Fi replacement trials; failures remain in the incremental evidence file. */
internal object NetworkRecoveryScenario {
    fun optional(context: Context, device: UiDevice, probe: TunPeerScenario?) {
        val attempts = InstrumentationRegistry.getArguments().getString("peerwardNetworkAttempts")?.toInt() ?: 0
        if (attempts == 0) return
        require(attempts in 1..100 && probe != null)
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val results = JSONArray()
        val evidence = File(context.filesDir, "wireguard-network-recovery.json")
        val owner = requireNotNull(PeerwardVpnService.activeResourceIdentity)
        repeat(attempts) { index ->
            val readyAt = AtomicLong(0)
            val armedAt = AtomicLong(0)
            val oldNetworks = connectivity.allNetworks.toSet()
            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
                    val now = SystemClock.elapsedRealtime()
                    if (armedAt.get() > 0 && now >= armedAt.get() && network !in oldNetworks &&
                        properties.linkAddresses.any { !it.address.isAnyLocalAddress && !it.address.isLinkLocalAddress && !it.address.isLoopbackAddress }) {
                        readyAt.compareAndSet(0, now)
                    }
                }
            }
            val result = JSONObject().put("attempt", index + 1).put("recovered", false)
            connectivity.registerNetworkCallback(NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback)
            try {
                device.executeShellCommand("svc wifi disable")
                val downDeadline = SystemClock.elapsedRealtime() + 20_000
                while (connectivity.allNetworks.any { it in oldNetworks &&
                        connectivity.getNetworkCapabilities(it)?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true } &&
                    SystemClock.elapsedRealtime() < downDeadline) SystemClock.sleep(50)
                armedAt.set(SystemClock.elapsedRealtime())
                device.executeShellCommand("svc wifi enable")
                val readyDeadline = SystemClock.elapsedRealtime() + 45_000
                while (readyAt.get() == 0L && SystemClock.elapsedRealtime() < readyDeadline) SystemClock.sleep(20)
                if (readyAt.get() == 0L) {
                    result.put("failure", "underlay_ready_timeout")
                } else {
                    result.put("underlay_ready_ms", readyAt.get())
                    result.put("runtime_health_at_ready", PeerwardVpnService.health.value.name)
                    val recovered = probe.roundTrip(30_000)
                    val elapsed = SystemClock.elapsedRealtime() - readyAt.get()
                    val retained = PeerwardVpnService.activeResourceIdentity == owner
                    result.put("recovery_ms", elapsed).put("owner_retained", retained)
                        .put("recovered", recovered && retained)
                    result.put("runtime_health_after_probe", PeerwardVpnService.health.value.name)
                    if (!recovered) result.put("failure", "authenticated_echo_timeout")
                    if (!retained) result.put("failure", "runtime_owner_replaced")
                }
            } catch (error: Exception) {
                result.put("failure", error.javaClass.simpleName)
            } finally {
                device.executeShellCommand("svc wifi enable")
                connectivity.unregisterNetworkCallback(callback)
                results.put(result)
                val temporary = File(evidence.parentFile, evidence.name + ".tmp")
                temporary.writeText(JSONObject().put("attempts", attempts).put("trials", results).toString(2))
                check(temporary.renameTo(evidence))
            }
        }
        val times = (0 until results.length()).mapNotNull { index ->
            results.getJSONObject(index).takeIf { it.optBoolean("recovered") }?.getLong("recovery_ms")
        }.sorted()
        val p95 = times.getOrNull(((times.size * 95 + 99) / 100 - 1).coerceAtLeast(0))
        val passed = times.size == attempts && p95 != null && p95 <= 5_000
        evidence.writeText(JSONObject().put("attempts", attempts).put("trials", results)
            .put("p95_ms", p95 ?: JSONObject.NULL).put("passed", passed).toString(2))
        assertTrue("Wi-Fi recovery SLO or owner retention failed; see wireguard-network-recovery.json", passed)
    }
}
