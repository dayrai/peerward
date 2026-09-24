package io.github.peerward.peerward.vpn

import android.net.LinkProperties
import android.net.Network
import android.net.VpnService
import io.github.peerward.peerward.profile.PeerProfile
import io.github.peerward.peerward.runtime.MobileRuntimeState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject

/** Interface replacement preserves the WG owner. Rejected changes keep existing capture. */
internal class ManagedTunnelController(
    private val service: VpnService,
    private val profile: PeerProfile,
    private val transport: WireguardTransport,
    private val pump: PacketPump,
    initialRoutes: List<String>,
    initialDns: Boolean,
    private val underlay: () -> Pair<Network?, LinkProperties?>,
    private val replaced: (Long) -> Unit,
) : AutoCloseable {
    private var routes = initialRoutes.sorted()
    private var search = emptyList<String>()
    private var acceptDns = initialDns
    private var privateRoutes = emptyList<String>()
    private var job: kotlinx.coroutines.Job? = null

    fun start(scope: CoroutineScope) {
        check(job == null)
        job = scope.launch {
            while (isActive) {
                synchronized(service) { update() }
                delay(5_000)
            }
        }
    }

    /** Same service monitor as network callbacks and periodic application. */
    fun change(request: JSONObject): JSONObject {
        val desired = request.optJSONObject("change")?.optJSONObject("preferences")
        if (request.optString("operation") == "set" && desired != null && !desired.isNull("exit_resource")) {
            // Capture before accepting the new intent; a failed establish leaves the old choice.
            replace((routes + listOf("0.0.0.0/0", "::/0")).distinct().sorted(), search, true)
        }
        transport.clientPreferences(request)
        if (request.optString("operation") == "set" && desired != null && desired.isNull("exit_resource")) {
            val accepted = if (desired.getBoolean("accept_private_routes")) privateRoutes else emptyList()
            replace((profile.routes + accepted).distinct().sorted(), search, desired.getBoolean("accept_dns"))
        }
        update()
        return transport.clientPreferences()
    }

    private fun replace(desired: List<String>, domains: List<String>, dns: Boolean) {
        if (desired == routes && domains == search && dns == acceptDns) return
        val builder = service.Builder().setSession(profile.meshName).setMtu(profile.mtu)
            .addAddress(profile.address.substringBefore('/'), profile.address.substringAfter('/').toInt())
        profile.secondaryAddress?.let { builder.addAddress(it.substringBefore('/'), it.substringAfter('/').toInt()) }
        desired.forEach { builder.addRoute(it.substringBefore('/'), it.substringAfter('/').toInt()) }
        if (dns) profile.dnsServers.forEach(builder::addDnsServer)
        domains.forEach(builder::addSearchDomain)
        builder.setUnderlyingNetworks(underlay().first?.let { arrayOf(it) })
        val descriptor = builder.establish() ?: error("vpn_permission_unavailable")
        val handle = pump.replaceTunnel(descriptor)
        routes = desired; search = domains; acceptDns = dns
        replaced(handle)
    }

    private fun update() {
        val candidate = try { transport.managedNetwork() }
        catch (_: io.github.peerward.peerward.nativecore.PeerwardPacketDeniedException) {
            // A cold start, revoked lease or incomplete signed dependency set is
            // an expected closed state. Keep TUN capture and retry the same owner.
            runCatching { MobileRuntimeState.preferencesObserved(transport.clientPreferences()) }; return
        }
        catch (_: io.github.peerward.peerward.nativecore.PeerwardNativeException) {
            runCatching { MobileRuntimeState.preferencesObserved(transport.clientPreferences()) }; return
        }
        catch (_: IllegalStateException) { return }
        try {
            val properties = underlay().second
            val families = listOfNotNull(profile.address, profile.secondaryAddress).map { it.contains(':') }.toSet()
            val local = properties?.routes?.filter { !it.isDefaultRoute && it.gateway?.isAnyLocalAddress != false }?.map { NetworkPrefix.parse(it.destination.toString()) }.orEmpty()
            require(candidate.routes.size <= 128 && candidate.searchDomains.size <= 6)
            val private = candidate.routes.filter { !it.endsWith("/0") }
            for (route in private) {
                val prefix = NetworkPrefix.parse(route)
                require(prefix.address.hostAddress!!.contains(':') in families) { "resource_address_family_unavailable" }
                require(local.none { it.contains(prefix.address) || prefix.contains(it.address) }) { "resource_route_conflict" }
            }
            val exceptions = if (candidate.exitSelected && candidate.allowLocalLan) local.map { it.toString() } else emptyList()
            val capture = if (candidate.exitSelected) exitCapture(exceptions) else emptyList()
            privateRoutes = private
            val desired = (profile.routes + private + capture).distinct().sorted()
            replace(desired, candidate.searchDomains, candidate.acceptDns)
            transport.observeNetwork(candidate.version, candidate.preferencesVersion, routes, true, null)
            MobileRuntimeState.preferencesObserved(transport.clientPreferences().put("local_lan",org.json.JSONArray(exceptions)))
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) {
            runCatching { transport.observeNetwork(candidate.version, candidate.preferencesVersion, routes, false,
                "VPN route or DNS application failed; inspect local route conflicts, address families and VPN permission") }
            runCatching { MobileRuntimeState.preferencesObserved(transport.clientPreferences()) }
            MobileRuntimeState.failed("managed_network_apply_failed",true)
        }
    }

    override fun close() { job?.cancel(); job = null }
}
