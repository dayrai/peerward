package io.github.peerward.peerward.vpn

import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import io.github.peerward.peerward.MainActivity
import io.github.peerward.peerward.R
import io.github.peerward.peerward.crypto.DeviceKeyStore
import io.github.peerward.peerward.net.VpnSocketProtector
import io.github.peerward.peerward.net.ProtectedDnsClient
import io.github.peerward.peerward.profile.ProfileStore
import io.github.peerward.peerward.nativecore.NativePlatformOperation
import io.github.peerward.peerward.runtime.MobileRuntimeState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Job
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetSocketAddress

internal fun shouldRestartForUnderlayChange(
    runtimeActive: Boolean,
    health: TunnelHealth,
): Boolean = runtimeActive || health == TunnelHealth.RECONNECTING

class PeerwardVpnService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var pump: PacketPump? = null
    private var wireguard: WireguardTransport? = null
    private var managedTunnel: ManagedTunnelController? = null
    private var dnsProxy: TunDnsProxy? = null
    private lateinit var connectivity: ConnectivityManager
    private var underlay: Network? = null
    private val underlaySelection = UnderlaySelection<Network>()
    private var underlaySignature: String? = null
    private var networkRestart: Job? = null
    private var startup: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var runtimeGeneration = 0L

    private var protectionObservation: Job? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        connectivity = getSystemService(ConnectivityManager::class.java)
        registerUnderlayCallback()
        activeService = java.lang.ref.WeakReference(this)
        protectionObservation = scope.launch {
            while (true) {
                refreshProtection()
                delay(10_000)
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        refreshProtection()
        when (intent?.action) {
            ACTION_STOP -> {
                if (Build.VERSION.SDK_INT >= 29 && runCatching { isAlwaysOn }.getOrDefault(false)) {
                    MobileRuntimeState.failed("always_on_managed_by_system", false)
                } else stopTunnel()
            }
            ACTION_STOP_AND_CLEAR -> beginProfileRemoval()
            ACTION_START, SERVICE_INTERFACE, null -> runCatching { startTunnel() }.onFailure {
                MobileRuntimeState.failed("tunnel_start_failed", true)
            }
        }
        return START_NOT_STICKY
    }

    private fun refreshProtection() {
        MobileRuntimeState.protectionObserved(observeVpnProtection(Build.VERSION.SDK_INT) {
            if (Build.VERSION.SDK_INT >= 29) isAlwaysOn to isLockdownEnabled
            else false to false
        })
    }

    @Synchronized
    private fun startTunnel() {
        if (hasRemovalTombstone(this)) {
            beginProfileRemoval()
            return
        }
        if (pump != null || startup != null) return
        check(!RuntimeCleanup.pending()) { "runtime_cleanup_pending" }
        val profile = ProfileStore(this).load() ?: run {
            MobileRuntimeState.failed("profile_missing", false)
            stopSelf()
            return
        }
        MobileRuntimeState.starting(profile)
        ServiceCompat.startForeground(
            this, NOTIFICATION_ID, notification(getString(R.string.vpn_connecting)),
            if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0,
        )
        val network = underlay ?: connectivity.activeNetwork?.takeIf(::isUsableUnderlay) ?: run {
            _health.value = TunnelHealth.RECONNECTING
            MobileRuntimeState.reconnecting()
            return
        }
        underlay = network
        val generation = ++runtimeGeneration
        startup = scope.launch(start = CoroutineStart.LAZY) {
            try {
                android.util.Log.i("PeerwardVpnStart", "credential recovery started")
                recoverActivatedCredential(ProfileStore(this@PeerwardVpnService), DeviceKeyStore(this@PeerwardVpnService),
                    VpnSocketProtector(this@PeerwardVpnService), network) { scope.launch { beginProfileRemoval() } }
                android.util.Log.i("PeerwardVpnStart", "credential recovery completed")
                synchronized(this@PeerwardVpnService) {
                    if (generation == runtimeGeneration && underlay == network) establishTunnel()
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                android.util.Log.w("PeerwardVpnStart", "startup failed (${error.javaClass.simpleName})")
                synchronized(this@PeerwardVpnService) {
                    if (generation == runtimeGeneration) MobileRuntimeState.failed("credential_recovery_or_tunnel_start_failed", true)
                }
            } finally {
                val completed = currentCoroutineContext()[Job]
                synchronized(this@PeerwardVpnService) { if (startup === completed) startup = null }
            }
        }.also { it.start() }
    }

    @Synchronized
    private fun establishTunnel() {
        if (pump != null) return
        val profile = ProfileStore(this).load() ?: run {
            MobileRuntimeState.failed("profile_missing", false)
            stopSelf()
            return
        }
        MobileRuntimeState.starting(profile)
        ServiceCompat.startForeground(
            this,
            NOTIFICATION_ID,
            notification(getString(R.string.vpn_connecting)),
            if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0,
        )
        val (address, prefix) = splitAddress(profile.address)
        require(profile.mtu in 1280..9000) { "profile MTU is outside its safe bound" }
        require(profile.routes.isNotEmpty()) { "profile has no mesh route" }
        require(profile.dnsServers.isNotEmpty()) { "profile has no mesh DNS server" }
        val network = underlay ?: connectivity.activeNetwork?.takeIf(::isUsableUnderlay) ?: run {
            _health.value = TunnelHealth.RECONNECTING
            MobileRuntimeState.reconnecting()
            return
        }
        underlay = network
        val linkProperties = connectivity.getLinkProperties(network)
        // Establish the comparison baseline before callbacks can interpret the
        // initial LinkProperties delivery as a replacement and tear down a new TUN.
        underlaySignature = linkPropertiesSignature(linkProperties)
        val upstream = linkProperties
            ?.dnsServers
            ?.firstOrNull { server -> profile.dnsServers.none { it == server.hostAddress } }
        val gatewayAddresses = linkProperties
            ?.routes
            ?.filter { route -> route.isDefaultRoute }
            ?.mapNotNull { route -> route.gateway }
            ?.distinct()
            .orEmpty()
        val protector = VpnSocketProtector(this)
        val profileStore = ProfileStore(this)
        val keys = DeviceKeyStore(this)
        val rotation = CredentialRotationCoordinator(profileStore, keys, profile, onTerminated = { scope.launch { beginProfileRemoval() } }) {
            scope.launch { restartAfterCredentialRotation() }
        }
        val dnsClient = upstream?.let {
            ProtectedDnsClient(InetSocketAddress(it, 53), protector, protector)
        }
        val opaqueProfile = requireNotNull(profileStore.loadOpaque())
        android.util.Log.i("PeerwardVpnStart", "creating data runtime")
        val data = try {
            WireguardTransport(profile, opaqueProfile, profileStore.wireguardStateDirectory(profile), keys, rotation, protector, protector)
        } catch (error: Exception) {
            throw error
        } finally {
            opaqueProfile.fill(0)
        }
        android.util.Log.i("PeerwardVpnStart", "data runtime created")
        val savedPreferences = data.clientPreferences().getJSONObject("preferences")
        val initialRoutes = (profile.routes + if (!savedPreferences.isNull("exit_resource")) listOf("0.0.0.0/0", "::/0") else emptyList()).distinct()
        val builder = Builder()
            .setSession(profile.meshName)
            .setMtu(profile.mtu)
            .addAddress(address, prefix)
        profile.secondaryAddress?.let { val (secondary, bits) = splitAddress(it); builder.addAddress(secondary, bits) }
        initialRoutes.forEach { route ->
            val (network, routePrefix) = splitAddress(route)
            builder.addRoute(network, routePrefix)
        }
        if (savedPreferences.getBoolean("accept_dns")) profile.dnsServers.forEach(builder::addDnsServer)
        builder.setUnderlyingNetworks(arrayOf(network))
        val tunRequest = MobileRuntimeState.platformRequest(NativePlatformOperation.OPEN_TUN)
        android.util.Log.i("PeerwardVpnStart", "opening TUN")
        val descriptorResult = runCatching { builder.establish() }
        val descriptor = descriptorResult.getOrNull()
        android.util.Log.i("PeerwardVpnStart", "TUN open returned: ${descriptor != null}")
        val tunAccepted = MobileRuntimeState.platformResult(
            tunRequest,
            descriptor != null,
        )
        if (!tunAccepted) {
            descriptor?.close()
            data.close()
            return
        }
        descriptorResult.exceptionOrNull()?.let {
            data.close()
            throw it
        }
        if (descriptor == null) {
            data.close()
            MobileRuntimeState.failed("tun_establish_failed", true)
            return
        }
        wireguard = data
        data.rebind(network, linkProperties)
        android.util.Log.i("PeerwardVpnStart", "data runtime bound")
        val resolver = TunDnsProxy(profile.dnsServers, profile.dnsSuffix, dnsClient, profile.mtu)
        dnsProxy = resolver
        val generation = ++runtimeGeneration
        MobileRuntimeState.tunnelEstablished()
        pump = PacketPump(
            descriptor,
            profile,
            { data },
            resolver,
            onRuntimeStatus = { status ->
                if (generation == runtimeGeneration) MobileRuntimeState.fromNativeRuntimeStatus(status)
            },
            onHealth = health@{ health ->
                if (generation != runtimeGeneration) return@health
                _health.value = health
                MobileRuntimeState.fromTunnelHealth(health)
                val text = if (health == TunnelHealth.HEALTHY) {
                    getString(R.string.vpn_connected)
                } else {
                    getString(R.string.vpn_connecting)
                }
                getSystemService(NotificationManager::class.java)
                    .notify(NOTIFICATION_ID, notification(text))
            },
        ).also {
            activeResourceIdentity = it.tunnelIdentity() to data.runtimeIdentity()
            it.start(scope)
            managedTunnel = ManagedTunnelController(this,profile,data,it,initialRoutes,savedPreferences.getBoolean("accept_dns"),
                underlay = { underlay to underlay?.let(connectivity::getLinkProperties) },
                replaced = { handle -> activeResourceIdentity = handle to data.runtimeIdentity() },
            ).also { controller -> controller.start(scope) }
        }
    }

    @Synchronized
    private fun restartAfterCredentialRotation() {
        restartTunnel()
    }

    @Synchronized
    private fun restartTunnel() {
        if (pump == null) {
            startup?.cancel()
            startup = null
            startTunnel()
            return
        }
        val network = underlay
        val properties = network?.let(connectivity::getLinkProperties)
        val profile = ProfileStore(this).load() ?: return
        setUnderlyingNetworks(network?.let { arrayOf(it) })
        val protector = VpnSocketProtector(this)
        val upstream = properties?.dnsServers?.firstOrNull { address -> address.hostAddress?.let { it !in profile.dnsServers } == true }
        dnsProxy?.replaceUpstream(upstream?.let { ProtectedDnsClient(InetSocketAddress(it, 53), protector, protector) })
        wireguard?.rebind(network, properties, profile)
        if (network != null) MobileRuntimeState.underlayRestored()
    }

    private fun registerUnderlayCallback() {
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onLost(network: Network) {
                synchronized(this@PeerwardVpnService) {
                    selectUnderlay(underlaySelection.update(network, null))
                }
            }

            override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) {
                synchronized(this@PeerwardVpnService) {
                    if (underlay != network) return
                    val previous = underlaySignature
                    val signature = linkPropertiesSignature(properties)
                    underlaySignature = signature
                    if (
                        previous != null && previous != signature &&
                        shouldRestartForUnderlayChange(pump != null, _health.value)
                    ) {
                        scheduleNetworkRestart()
                    }
                }
            }

            override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
                synchronized(this@PeerwardVpnService) {
                    selectUnderlay(underlaySelection.update(network, underlayPreference(capabilities)))
                }
            }
        }
        connectivity.registerNetworkCallback(
            NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build(),
            callback,
        )
        networkCallback = callback
    }

    private fun selectUnderlay(replacement: Network?) {
        if (underlay == replacement) return
        underlay = replacement
        underlaySignature = null
        networkRestart?.cancel()
        suspendForNetworkLoss()
        if (startup != null && pump == null) {
            // Initial capability callbacks can replace a cellular candidate with
            // Wi-Fi while staged credential recovery still owns the checkpoint.
            _health.value = TunnelHealth.RECONNECTING
            MobileRuntimeState.reconnecting()
        }
        if (replacement != null && shouldRestartForUnderlayChange(pump != null, _health.value)) {
            scheduleNetworkRestart()
        }
    }

    private fun isUsableUnderlay(network: Network): Boolean = connectivity
        .getNetworkCapabilities(network)
        ?.let(::isUsableCapabilities) == true

    private fun isUsableCapabilities(capabilities: NetworkCapabilities): Boolean =
        underlayPreference(capabilities) != null

    private fun linkPropertiesSignature(properties: LinkProperties?): String =
        if (properties == null) {
            "unavailable"
        } else {
            properties.interfaceName + "|" +
                properties.linkAddresses.joinToString(",") + "|" +
                (if (Build.VERSION.SDK_INT >= 29) properties.mtu else 0) + "|" +
                properties.dnsServers.joinToString(",") { it.hostAddress.orEmpty() } + "|" +
                properties.routes.joinToString(",")
        }

    @Synchronized
    private fun suspendForNetworkLoss() {
        if (pump == null) return
        wireguard?.rebind(null, null)
        dnsProxy?.replaceUpstream(null)
        setUnderlyingNetworks(emptyArray())
        _health.value = TunnelHealth.RECONNECTING
        MobileRuntimeState.reconnecting()
    }

    private fun scheduleNetworkRestart() {
        networkRestart?.cancel()
        networkRestart = scope.launch {
            delay(350)
            // Recovery must release its exclusive checkpoint before its successor
            // starts. It has a bounded deadline; never overlap native owners.
            synchronized(this@PeerwardVpnService) { startup }?.join()
            synchronized(this@PeerwardVpnService) {
                if (underlay != null) restartTunnel()
            }
        }
    }

    @Synchronized
    private fun stopTunnel() {
        val closingStartup = startup
        val closingPump = pump
        val closingWireguard = wireguard
        startup?.cancel()
        startup = null
        activeResourceIdentity = null
        networkRestart?.cancel()
        networkRestart = null
        val closeRequest = MobileRuntimeState.platformRequest(
            NativePlatformOperation.CLOSE_RUNTIME_RESOURCES,
        )
        runtimeGeneration++
        managedTunnel?.close()
        managedTunnel = null
        pump?.close()
        pump = null
        wireguard?.close()
        wireguard = null
        dnsProxy = null
        RuntimeCleanup.track(closingStartup, closingPump, closingWireguard)
        MobileRuntimeState.platformResult(closeRequest, true)
        _health.value = TunnelHealth.STOPPED
        MobileRuntimeState.stopped()
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    @SuppressLint("ApplySharedPref", "UseKtx")
    private fun beginProfileRemoval() {
        // Record actual durability; a failed write must still close the revoked VPN.
        val request = MobileRuntimeState.platformRequest(NativePlatformOperation.ATOMIC_PERSISTENCE)
        val persisted = runCatching {
            getSharedPreferences(REMOVAL_PREFERENCES, MODE_PRIVATE)
                .edit().putBoolean(REMOVAL_TOMBSTONE, true).commit()
        }.getOrDefault(false)
        MobileRuntimeState.platformResult(request, persisted)
        MobileRuntimeState.stopping()
        if (pump == null) {
            ServiceCompat.startForeground(
                this,
                NOTIFICATION_ID,
                notification(getString(R.string.vpn_connecting)),
                if (Build.VERSION.SDK_INT >= 34) ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE else 0,
            )
        }
        scope.launch { completeProfileRemoval() }
    }

    @SuppressLint("ApplySharedPref", "UseKtx")
    private suspend fun completeProfileRemoval() {
        activeResourceIdentity = null
        val closeRequest = MobileRuntimeState.platformRequest(
            NativePlatformOperation.CLOSE_RUNTIME_RESOURCES,
        )
        var closingStartup: Job? = null
        val closing = synchronized(this) {
            closingStartup = startup
            startup?.cancel()
            startup = null
            networkRestart?.cancel()
            runtimeGeneration++
            managedTunnel?.close()
            managedTunnel = null
            pump.also { pump = null }
        }
        closing?.close()
        val closingData = wireguard
        wireguard = null
        closingData?.close()
        dnsProxy = null
        val stoppedInTime = withTimeoutOrNull(REMOVAL_TIMEOUT_MS) {
            closingStartup?.join()
            closing?.awaitStopped()
            closingData?.awaitStopped()
            true
        } == true
        MobileRuntimeState.platformResult(closeRequest, stoppedInTime)
        val profiles = ProfileStore(this)
        val profile = runCatching { profiles.loadForRemoval() }.getOrNull()
        val removed = runCatching {
            profile?.let {
                listOfNotNull(it.deviceKeyId, it.previousDeviceKeyId, it.pendingDeviceKeyId)
                    .distinct()
                    .forEach { keyId -> DeviceKeyStore(this).delete(keyId) }
            }
            profiles.clear()
        }.isSuccess
        if (!removed || !stoppedInTime) {
            MobileRuntimeState.failed("profile_removal_incomplete", true)
            return
        }
        // Synchronous removal makes a completed delete distinguishable after process death.
        val cleared = getSharedPreferences(REMOVAL_PREFERENCES, MODE_PRIVATE)
            .edit()
            .remove(REMOVAL_TOMBSTONE)
            .commit()
        if (!cleared) {
            MobileRuntimeState.failed("profile_removal_incomplete", true)
            return
        }
        _health.value = TunnelHealth.STOPPED
        MobileRuntimeState.initialize(null)
        MobileRuntimeState.stopped()
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onRevoke() {
        // Revoking VPN permission stops local networking; it does not revoke the Peer
        // credential or authorize deleting the saved profile and keys.
        MobileRuntimeState.protectionObserved(VpnProtection())
        stopTunnel()
    }

    override fun onDestroy() {
        protectionObservation?.cancel()
        activeService = null
        MobileRuntimeState.protectionObserved(VpnProtection())
        networkRestart?.cancel()
        networkCallback?.let { runCatching { connectivity.unregisterNetworkCallback(it) } }
        networkCallback = null
        stopTunnel()
        scope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    private fun notification(text: String): Notification {
        val pending = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_peerward)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(text)
            .setContentIntent(pending)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    private fun createNotificationChannel() {
        getSystemService(NotificationManager::class.java).createNotificationChannel(
            NotificationChannel(CHANNEL_ID, getString(R.string.vpn_channel_name), NotificationManager.IMPORTANCE_LOW),
        )
    }

    private fun splitAddress(value: String): Pair<String, Int> {
        val parts = value.split('/', limit = 2)
        val prefix = parts.getOrNull(1)?.toIntOrNull() ?: if (parts[0].contains(':')) 128 else 32
        return parts[0] to prefix
    }

    companion object {
        @Volatile private var activeService: java.lang.ref.WeakReference<PeerwardVpnService>? = null

        fun canChangeProfile(): Boolean = activeService?.get() == null && !RuntimeCleanup.pending()

        fun clientPreferences(request: org.json.JSONObject): org.json.JSONObject {
            val service = activeService?.get() ?: error("client_runtime_stopped")
            return synchronized(service) {
                val controller = service.managedTunnel ?: error("client_runtime_not_ready")
                controller.change(request)
            }
        }

        fun refreshSystemProtection() {
            val service = activeService?.get()
            if (service == null) MobileRuntimeState.protectionObserved(VpnProtection())
            else service.refreshProtection()
        }

        /** Local diagnostics can distinguish a carrier replacement from reopening the VPN. */
        @Volatile internal var activeResourceIdentity: Pair<Long, Long>? = null
            private set
        const val ACTION_START = "io.github.peerward.peerward.START"
        const val ACTION_STOP = "io.github.peerward.peerward.STOP"
        const val ACTION_STOP_AND_CLEAR = "io.github.peerward.peerward.STOP_AND_CLEAR"
        private const val REMOVAL_PREFERENCES = "peerward.profile_removal"
        private const val REMOVAL_TOMBSTONE = "pending"
        private const val REMOVAL_TIMEOUT_MS = 10_000L
        private const val CHANNEL_ID = "peerward.vpn"
        private const val NOTIFICATION_ID = 1_807
        private val _health = MutableStateFlow(TunnelHealth.STOPPED)
        val health: StateFlow<TunnelHealth> = _health

        fun hasRemovalTombstone(context: android.content.Context): Boolean =
            context.getSharedPreferences(REMOVAL_PREFERENCES, MODE_PRIVATE)
                .getBoolean(REMOVAL_TOMBSTONE, false)
    }
}
