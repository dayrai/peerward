package io.github.peerward.peerward.vpn

import android.os.SystemClock
import android.net.Network
import io.github.peerward.peerward.nativecore.NativeWireguardRuntime
import io.github.peerward.peerward.nativecore.NativeWireguardUdp
import io.github.peerward.peerward.nativecore.NativePlatformOperation
import io.github.peerward.peerward.nativecore.NativeStunRuntime
import io.github.peerward.peerward.net.DatagramProtector
import io.github.peerward.peerward.net.SocketProtector
import io.github.peerward.peerward.net.StunServerResolver
import io.github.peerward.peerward.runtime.MobileRuntimeState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.net.URI

/** One Network's protected STUN and standard WireGuard data socket. */
class DirectUdpTransport private constructor(
    private val socket: DatagramSocket,
    private val native: NativeWireguardRuntime,
    private val network: Network,
    private val stunServers: List<String>,
    private val symmetricNatPrediction: Boolean,
    private val candidates: LinkedHashMap<String, Pair<String, Int>>,
) : AutoCloseable {
    private val stunLock = Any()
    private var stun: NativeStunRuntime? = null
    private var resolvedStun = emptyList<InetSocketAddress>()
    private var receiver: Job? = null
    private var stunScheduler: Job? = null
    private val writer = NativeWireguardUdp(socket)
    private val baseCandidates = LinkedHashMap(candidates)
    private data class StunCandidate(val endpoint: String, val expiresAtMillis: Long)
    private val stunCandidates = mutableMapOf<Int, StunCandidate>()
    private var predictedExpiresAtMillis = 0L
    private val predictedCandidates = linkedMapOf<String, Pair<String, Int>>()
    private var mappedExpiresAtMillis = 0L
    private var mappedCandidate: Pair<String, Pair<String, Int>>? = null
    private var gatewayMapping: GatewayPortMapping? = null

    fun localEndpoint(): String = formatEndpoint(socket.localSocketAddress as InetSocketAddress)
    fun owns(endpoint: String): Boolean = runCatching { parseEndpoint(endpoint) == socket.localSocketAddress }.getOrDefault(false)

    fun start(scope: CoroutineScope) {
        check(receiver == null) { "direct receiver already started" }
        receiver = scope.launch(Dispatchers.IO) {
            val buffer = ByteArray(MAX_DATAGRAM)
            while (isActive && !socket.isClosed) {
                try {
                    val datagram = DatagramPacket(buffer, buffer.size)
                    socket.receive(datagram)
                    val source = datagram.socketAddress as? InetSocketAddress ?: continue
                    val payload = datagram.data.copyOfRange(
                        datagram.offset,
                        datagram.offset + datagram.length,
                    )
                    if (gatewayMapping?.accept(source, payload) == true) continue
                    val consumed = synchronized(stunLock) {
                        val mapping = stun?.accept(source, payload)
                        if (mapping == null) false else {
                            synchronized(candidates) {
                                stunCandidates[mapping.serverIndex] = StunCandidate(
                                    formatEndpoint(mapping.mapped), SystemClock.elapsedRealtime() + 90_000,
                                )
                                predictedCandidates.clear()
                                predictedExpiresAtMillis = SystemClock.elapsedRealtime() + 30_000
                                mapping.predicted.forEachIndexed { index, endpoint ->
                                    predictedCandidates[formatEndpoint(endpoint)] = "predicted" to (15_000 - index)
                                }
                                rebuildCandidatesLocked()
                            }
                            true
                        }
                    }
                    if (consumed) continue
                    native.receiveOn(localEndpoint(), formatEndpoint(source), payload)
                } catch (_: SocketTimeoutException) {
                    continue
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    if (socket.isClosed) break
                }
            }
        }
        if (stunServers.isNotEmpty()) {
            stunScheduler = scope.launch(Dispatchers.IO) {
                var refreshAt = 0L
                while (isActive && !socket.isClosed) {
                    if (SystemClock.elapsedRealtime() >= refreshAt) {
                        val resolved = StunServerResolver.resolve(network, stunServers, isIpv6())
                        synchronized(stunLock) {
                            if (!socket.isClosed && resolved != resolvedStun) {
                                stun?.close()
                                stun = resolved.takeIf { it.isNotEmpty() }
                                    ?.let { NativeStunRuntime(it, symmetricNatPrediction) }
                                resolvedStun = resolved
                                synchronized(candidates) {
                                    stunCandidates.clear()
                                    predictedCandidates.clear()
                                    predictedExpiresAtMillis = 0
                                    rebuildCandidatesLocked()
                                }
                            }
                        }
                        refreshAt = SystemClock.elapsedRealtime() + if (resolved.isEmpty()) 15_000 else 60_000
                    }
                    val poll = synchronized(stunLock) { stun?.poll(SystemClock.elapsedRealtime()) }
                    poll?.probes?.forEach { probe ->
                        runCatching {
                            socket.send(
                                DatagramPacket(
                                    probe.request,
                                    probe.request.size,
                                    probe.server,
                                ),
                            )
                        }
                    }
                    val now = SystemClock.elapsedRealtime()
                    val expiresIn = synchronized(candidates) {
                        stunCandidates.entries.removeAll { it.value.expiresAtMillis <= now }
                        if (predictedExpiresAtMillis <= now) predictedCandidates.clear()
                        rebuildCandidatesLocked()
                        val nextStun = stunCandidates.values.minOfOrNull { it.expiresAtMillis } ?: Long.MAX_VALUE
                        val nextPrediction = if (predictedCandidates.isEmpty()) Long.MAX_VALUE else predictedExpiresAtMillis
                        minOf(nextStun, nextPrediction).let { if (it == Long.MAX_VALUE) it else (it - now).coerceAtLeast(1) }
                    }
                    delay(minOf(poll?.nextPollMillis ?: 15_000, expiresIn,
                        (refreshAt - SystemClock.elapsedRealtime()).coerceAtLeast(1)))
                }
            }
        }
        gatewayMapping?.start(scope)
    }

    fun send(ticket: Long): Boolean = writer.send(native, ticket)

    fun isIpv6(): Boolean = socket.localAddress is Inet6Address

    fun candidateSnapshot(): List<String> = synchronized(candidates) {
        expireObservationsLocked()
        candidates.entries.sortedByDescending { it.value.second }.take(32).map { it.key }
    }

    override fun close() {
        runBlocking(Dispatchers.IO) { gatewayMapping?.stop() }
        gatewayMapping = null
        writer.close()
        socket.close()
        receiver?.cancel()
        receiver = null
        stunScheduler?.cancel()
        stunScheduler = null
        synchronized(stunLock) { stun?.close(); stun = null }
    }

    private fun updateMappedCandidate(endpoint: InetSocketAddress?, lifetimeSeconds: Long) = synchronized(candidates) {
        mappedExpiresAtMillis = SystemClock.elapsedRealtime() + lifetimeSeconds.coerceIn(0, 86_400) * 1_000
        mappedCandidate = endpoint?.let { formatEndpoint(it) to ("mapped" to 25_000) }
        rebuildCandidatesLocked()
    }

    private fun expireObservationsLocked() {
        val now = SystemClock.elapsedRealtime()
        var changed = stunCandidates.entries.removeAll { it.value.expiresAtMillis <= now }
        if (predictedExpiresAtMillis <= now && predictedCandidates.isNotEmpty()) {
            predictedCandidates.clear()
            changed = true
        }
        if (mappedExpiresAtMillis <= now && mappedCandidate != null) {
            mappedCandidate = null
            changed = true
        }
        if (changed) rebuildCandidatesLocked()
    }

    private fun rebuildCandidatesLocked() {
        candidates.clear()
        baseCandidates.forEach { (endpoint, attributes) ->
            mergeCandidate(endpoint, attributes)
        }
        stunCandidates.entries.sortedBy { it.key }.forEach { (index, candidate) ->
            mergeCandidate(candidate.endpoint, "server_reflexive" to (20_000 - index))
        }
        predictedCandidates.forEach(::mergeCandidate)
        mappedCandidate?.let { (endpoint, attributes) -> mergeCandidate(endpoint, attributes) }
    }

    private fun mergeCandidate(endpoint: String, attributes: Pair<String, Int>) {
        val current = candidates[endpoint]
        if (current == null || attributes.second > current.second) {
            candidates[endpoint] = attributes
        }
    }

    companion object {
        private const val MAX_DATAGRAM = 65_535

        fun open(
            localAddress: java.net.InetAddress,
            socketProtector: SocketProtector,
            protector: DatagramProtector,
            native: NativeWireguardRuntime,
            staticCandidates: List<String>,
            stunServers: List<String>,
            symmetricNatPrediction: Boolean,
            natMapping: String,
            gatewayAddress: java.net.InetAddress?,
            network: Network,
        ): DirectUdpTransport {
            require(natMapping == "auto" || natMapping == "off") { "invalid NAT mapping mode" }
            require(staticCandidates.size <= 8 && staticCandidates.distinct().size == staticCandidates.size) {
                "at most eight unique static P2P endpoints are allowed"
            }
            require(stunServers.size <= 8 && stunServers.distinct().size == stunServers.size) {
                "at most eight unique STUN servers are allowed"
            }
            val platformRequest = MobileRuntimeState.platformRequest(
                NativePlatformOperation.PROTECTED_UDP_SOCKET,
            )
            var platformCompleted = false
            val socket = DatagramSocket(null)
            var transportOwner: DirectUdpTransport? = null
            try {
                check(protector.protect(socket)) { "VPN refused to protect direct UDP socket" }
                network.bindSocket(socket)
                socket.soTimeout = 1_000
                socket.bind(InetSocketAddress(localAddress, 0))
                check(MobileRuntimeState.platformResult(platformRequest, true)) {
                    "protected UDP socket belongs to a stale network generation"
                }
                platformCompleted = true
                val local = socket.localSocketAddress as InetSocketAddress
                val candidates = linkedMapOf<String, Pair<String, Int>>()
                staticCandidates.take(8).forEachIndexed { index, endpoint ->
                    val parsed = parseEndpoint(endpoint)
                    if ((parsed.address is Inet6Address) != (localAddress is Inet6Address)) return@forEachIndexed
                    candidates.putIfAbsent(
                        formatEndpoint(parsed),
                        "static" to (30_000 - index),
                    )
                }
                candidates.putIfAbsent(formatEndpoint(local), "host" to 10_000)
                val transport = DirectUdpTransport(
                    socket, native, network, stunServers.toList(), symmetricNatPrediction, candidates,
                )
                transportOwner = transport
                if (natMapping == "auto") {
                    val gateway = gatewayAddress?.let { InetSocketAddress(it, 5_351) }
                    transport.gatewayMapping = GatewayPortMapping(
                        socket,
                        local,
                        gateway,
                        network,
                        socketProtector,
                        protector,
                        transport::updateMappedCandidate,
                    )
                }
                return transport
            } catch (error: Exception) {
                if (!platformCompleted) {
                    runCatching { MobileRuntimeState.platformResult(platformRequest, false) }
                }
                runCatching { transportOwner?.close() }
                socket.close()
                throw error
            }
        }

        private fun parseEndpoint(value: String): InetSocketAddress {
            val uri = URI("udp://$value")
            require(uri.host != null && uri.port in 1..65_535) { "invalid direct endpoint" }
            return InetSocketAddress(uri.host, uri.port)
        }

        private fun formatEndpoint(value: InetSocketAddress): String {
            val address = value.address
            val host = requireNotNull(address.hostAddress).substringBefore('%')
            return if (address is Inet6Address) "[$host]:${value.port}" else "$host:${value.port}"
        }

    }
}
