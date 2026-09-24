package io.github.peerward.peerward.vpn

import android.net.LinkProperties
import android.net.Network
import io.github.peerward.peerward.crypto.DeviceKeyStore
import io.github.peerward.peerward.nativecore.NativeRuntimeStatus
import io.github.peerward.peerward.nativecore.NativeTunPacketPump
import io.github.peerward.peerward.nativecore.NativeWireguardRuntime
import io.github.peerward.peerward.nativecore.PeerwardNativeException
import io.github.peerward.peerward.nativecore.PeerwardPacketDeniedException
import io.github.peerward.peerward.net.DatagramProtector
import io.github.peerward.peerward.net.SocketProtector
import io.github.peerward.peerward.profile.PeerProfile
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.net.Inet6Address
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/** Mesh lifetime and carrier lifetime are independent, including when all carriers disappear. */
class WireguardTransport(
    profile: PeerProfile,
    opaqueProfile: ByteArray,
    stateDirectory: java.io.File,
    private val keys: DeviceKeyStore,
    private val rotation: CredentialRotationCoordinator,
    private val protector: SocketProtector,
    private val datagramProtector: DatagramProtector,
) : PacketTransport {
    private val native = NativeWireguardRuntime(opaqueProfile, keys.handle(profile.deviceKeyId), stateDirectory)
    internal fun runtimeIdentity(): Long = native.openHandle()
    private val supervisor = SupervisorJob()
    private val scope = CoroutineScope(supervisor + Dispatchers.IO)
    private val closed = AtomicBoolean(false)
    private val generation = AtomicLong(0)
    private val inbound = Channel<ByteArray>(256)
    private val relayOutput = Channel<Long>(64)
    @Volatile private var profile = profile
    @Volatile private var installedPrefixes = profile.routes.map(NetworkPrefix::parse)
    @Volatile private var pool: RelayPoolTransport? = null
    @Volatile private var direct: List<DirectUdpTransport> = emptyList()
    @Volatile private var lastStatus: NativeRuntimeStatus? = null
    private var lastCandidates: List<String> = emptyList()
    private var lastLocalPaths: List<String> = emptyList()

    init {
        scope.launch {
            while (isActive) {
                try {
                    refreshCandidates()
                    native.poll().forEach { ticket ->
                        if (ticket.tunnel) {
                            inbound.trySend(ByteBuffer.allocate(8).putLong(ticket.id).array())
                        } else if (ticket.endpoint != null) {
                            val socket = direct.firstOrNull { ticket.localEndpoint?.let(it::owns) ?: (it.isIpv6() == ticket.endpoint.startsWith("[")) }
                            if (socket == null) native.fallback(ticket.id)
                            else runCatching { socket.send(ticket.id) }.onFailure { native.fallback(ticket.id) }
                        } else {
                            relayOutput.trySend(ticket.id)
                        }
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: PeerwardPacketDeniedException) {
                    // Expected while signed authorization is incomplete or expired.
                } catch (_: PeerwardNativeException) {
                    // Expired credentials and revoked Mesh state stay closed while control reconnects.
                } catch (error: IllegalStateException) {
                    if (closed.get()) break
                    throw error
                }
                delay(50)
            }
        }
        scope.launch {
            for (ticket in relayOutput) pool?.sendWireguard(ticket)
        }
    }

    override suspend fun send(packet: ByteArray) {
        try {
            native.send(packet)
        } catch (_: PeerwardPacketDeniedException) {
            // A denied application packet must not terminate the transport worker.
        } catch (_: PeerwardNativeException) {
            // Before a verified directory/credential is usable, drop this packet without buffering
            // it in Kotlin. The shared Rust queue handles an authorized peer's pending handshake.
        }
    }

    override suspend fun receive(): ByteArray = inbound.receive()

    override fun writeInbound(packet: ByteArray, tun: NativeTunPacketPump) {
        require(packet.size == 8)
        native.writeTunnel(ByteBuffer.wrap(packet).long, tun)
    }

    @Synchronized override fun runtimeStatus(): NativeRuntimeStatus? {
        if (closed.get()) return null
        val current = pool?.runtimeStatus()
        if (current != null) lastStatus = current
        return (current ?: lastStatus?.copy(primaryRelayAuthenticated = false, standbyRelayCount = 0))
            ?.copy(directPathCount = native.directPathCount())
    }

    fun managedNetwork() = native.managedNetwork(profile.address.substringBefore('/'))
    fun clientPreferences(request: org.json.JSONObject = org.json.JSONObject().put("operation", "get")) = native.clientPreferences(request)
    fun observeNetwork(version: Long, preferencesVersion: Long, routes: List<String>, applied: Boolean, reason: String?) {
        if (applied) installedPrefixes = routes.map(NetworkPrefix::parse)
        native.observeNetwork(version, preferencesVersion, profile.address.substringBefore('/'), applied, reason)
    }

    override suspend fun keepalive(timestamp: Long) { pool?.keepalive(timestamp) }
    override suspend fun reportHealth() { pool?.reportHealth() }
    override suspend fun resolveDns(query: ByteArray, sourceAddress: ByteArray, suffix: String): ByteArray? =
        native.resolveDns(query, sourceAddress, suffix)
    override suspend fun managedDnsRoute(query: ByteArray, sourceAddress: ByteArray): io.github.peerward.peerward.nativecore.ManagedDnsRoute? {
        val route = native.managedDnsRoute(query, sourceAddress) ?: return null
        if (route.tunnelUpstreams.any { server -> installedPrefixes.none { it.contains(server.address) } }) {
            throw io.github.peerward.peerward.nativecore.PeerwardPacketDeniedException("DNS upstream requires an installed approved VPN route")
        }
        return route
    }
    override fun dnsConfigurationActive(version: Long, sourceAddress: ByteArray) = native.dnsConfigurationActive(version, sourceAddress)

    /** Cancels only this Mesh's affected protected sockets and Relay attachments. */
    fun rebind(network: Network?, properties: LinkProperties?, updated: PeerProfile? = null) {
        if (closed.get()) return
        if (updated != null) profile = updated
        val replacementGeneration = generation.incrementAndGet()
        val previous = synchronized(this) {
            if (closed.get() || generation.get() != replacementGeneration) return
            val resources = pool to direct
            pool = null
            direct = emptyList()
            lastCandidates = emptyList()
            try { native.localPaths(emptyList(), emptyList())
            lastLocalPaths = emptyList() } catch (_: PeerwardPacketDeniedException) {
                // Authorization may close concurrently with network replacement.
            } catch (_: PeerwardNativeException) {
                // A trusted Mesh termination may close authorization before service cleanup runs.
            }
            resources
        }
        scope.launch(start = CoroutineStart.UNDISPATCHED) {
            withContext(NonCancellable + Dispatchers.IO) {
                previous.first?.close()
                previous.second.forEach { it.close() }
            }
        }
        if (network == null) return
        val snapshot = profile
        scope.launch {
            var replacementPool: RelayPoolTransport? = null
            val replacementDirect = mutableListOf<DirectUdpTransport>()
            try {
                val gateways = properties?.routes?.filter { it.isDefaultRoute }?.mapNotNull { it.gateway }.orEmpty()
                replacementPool = RelayPoolTransport.open(snapshot, NoiseRelayTransport.factory(
                    protector, datagramProtector, keys, rotation, native, network, gateways,
                ))
                // Discovery and Relay dialing start together; an empty usable address set is valid.
                properties?.linkAddresses.orEmpty().map { it.address }
                    .filter { !it.isAnyLocalAddress && !it.isLoopbackAddress && !it.isLinkLocalAddress && !it.isMulticastAddress }
                    .distinct().sortedBy { it is Inet6Address }.let { addresses ->
                        val v4 = addresses.filter { it !is Inet6Address }; val v6 = addresses.filterIsInstance<Inet6Address>()
                        (0 until 8).flatMap { index -> listOfNotNull(v4.getOrNull(index), v6.getOrNull(index)) }.take(8)
                    }.forEach { address ->
                        runCatching { DirectUdpTransport.open(
                            address, protector, datagramProtector, native,
                            snapshot.p2pEndpoints, snapshot.stunServers, snapshot.symmetricNatPrediction,
                            snapshot.natMapping, gateways.firstOrNull { (it is Inet6Address) == (address is Inet6Address) }, network,
                        ) }.getOrNull()?.let(replacementDirect::add)
                    }
                synchronized(this@WireguardTransport) {
                    if (closed.get() || generation.get() != replacementGeneration) return@synchronized
                    pool = replacementPool
                    direct = replacementDirect.toList()
                    replacementDirect.forEach { it.start(scope) }
                    replacementPool = null
                    replacementDirect.clear()
                    refreshCandidates()
                }
            } finally {
                replacementPool?.close()
                replacementDirect.forEach { it.close() }
            }
        }
    }

    @Synchronized private fun refreshCandidates() {
        if (closed.get()) return
        val byFamily = direct.map { it.candidateSnapshot() }
        val candidates = (0 until 32).flatMap { index -> byFamily.mapNotNull { it.getOrNull(index) } }
            .distinct().take(32)
        val local = direct.map { it.localEndpoint() }
        if (candidates != lastCandidates || local != lastLocalPaths) {
            try {
                native.localPaths(local, candidates)
                lastLocalPaths = local
                lastCandidates = candidates
            } catch (_: PeerwardNativeException) {
                // Root-authorized termination stays closed while its service owner is stopping.
            }
        }
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        generation.incrementAndGet()
        val retired = synchronized(this) {
            // Close authorization before releasing any queued writer or carrier.
            native.close()
            val resources = pool to direct
            pool = null
            direct = emptyList()
            resources
        }
        scope.launch(start = CoroutineStart.UNDISPATCHED) {
            withContext(NonCancellable + Dispatchers.IO) {
                retired.first?.close()
                retired.second.forEach { it.close() }
            }
        }
        scope.cancel()
        inbound.close()
        relayOutput.close()
    }

    override suspend fun awaitStopped() { supervisor.join() }
}
