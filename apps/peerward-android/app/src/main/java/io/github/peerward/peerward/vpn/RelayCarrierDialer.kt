package io.github.peerward.peerward.vpn

import android.net.Network
import io.github.peerward.peerward.nativecore.NativeRelaySocket
import io.github.peerward.peerward.nativecore.NativePlatformOperation
import io.github.peerward.peerward.runtime.MobileRuntimeState
import io.github.peerward.peerward.net.DatagramProtector
import io.github.peerward.peerward.net.SocketProtector
import io.github.peerward.peerward.profile.PeerProfile
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.io.IOException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine

/** Only carrier establishment races. Root/Noise verification and lease admission
 * happen once, after selection. Every FD is protected and bound to this Network. */
internal suspend fun dialRelayCarriers(
    endpoints: List<String>, profile: PeerProfile, network: Network,
    protector: SocketProtector, datagramProtector: DatagramProtector,
): Pair<String, NativeRelaySocket> = coroutineScope {
    require(endpoints.size in 1..16)
    val results = Channel<Result<Pair<String, NativeRelaySocket>>>(64,
        onUndeliveredElement = { it.getOrNull()?.second?.close() })
    val workers = launch {
        try {
            coroutineScope {
                endpoints.forEachIndexed { index, endpoint -> launch {
                    delay(index * 250L)
                    try {
                        val target = URI(endpoint)
                        require(target.scheme in setOf("quic", "wss", "tcp") && target.port in 1..65535)
                        val dial = profile.relayHttpConnectProxy?.let {
                            require(target.scheme == "wss")
                            URI(it)
                        } ?: target
                        val resolved = carrierBlocking(CarrierAttempt()) { network.getAllByName(dial.host).toList() }
                        val families = resolved.distinct().groupBy { it is Inet4Address }
                        val addresses = (0..1).flatMap { position ->
                            listOfNotNull(families[false]?.getOrNull(position), families[true]?.getOrNull(position))
                        }
                        if (addresses.isEmpty()) throw IOException("Relay has no address on selected Network")
                        coroutineScope {
                            addresses.forEachIndexed { position, address -> launch {
                                delay(position * 250L)
                                var socket: NativeRelaySocket? = null
                                try {
                                    val attempt = CarrierAttempt()
                                    socket = carrierBlocking(attempt) {
                                        val options = org.json.JSONObject().put("ca_pem", profile.relayCaPem)
                                            .put("http_connect_proxy", profile.relayHttpConnectProxy).toString()
                                        val request = MobileRuntimeState.platformRequest(if (target.scheme == "quic")
                                            NativePlatformOperation.PROTECTED_UDP_SOCKET else NativePlatformOperation.PROTECTED_TCP_SOCKET)
                                        var completed = false
                                        try {
                                        val native = if (target.scheme == "quic") {
                                            val udp = DatagramSocket(null)
                                            attempt.adopt(udp)
                                            check(datagramProtector.protect(udp)) { "VPN refused to protect QUIC socket" }
                                            network.bindSocket(udp)
                                            udp.bind(InetSocketAddress(InetAddress.getByAddress(ByteArray(if (address is Inet4Address) 4 else 16)), 0))
                                            NativeRelaySocket.prepare(udp, endpoint, options, InetSocketAddress(address, target.port))
                                        } else {
                                            val tcp = Socket()
                                            attempt.adopt(tcp)
                                            check(protector.protect(tcp)) { "VPN refused to protect Relay socket" }
                                            network.bindSocket(tcp)
                                            tcp.tcpNoDelay = true
                                            tcp.connect(InetSocketAddress(address, dial.port), 5_000)
                                            NativeRelaySocket.prepare(tcp, endpoint, options)
                                        }
                                        attempt.adopt(native)
                                        native.connect()
                                        check(MobileRuntimeState.platformResult(request, true)) {
                                            "Relay socket belongs to a stale network generation"
                                        }
                                        completed = true
                                        native
                                        } finally {
                                            if (!completed) runCatching { MobileRuntimeState.platformResult(request, false) }
                                        }
                                    }
                                    results.send(Result.success(endpoint to requireNotNull(socket)))
                                    socket = null // Channel now owns this result, including cancellation.
                                } catch (cancelled: CancellationException) {
                                    throw cancelled
                                } catch (error: Exception) {
                                    results.send(Result.failure(error))
                                } finally { socket?.close() }
                            } }
                        }
                    } catch (cancelled: CancellationException) {
                        throw cancelled
                    } catch (error: Exception) { results.send(Result.failure(error)) }
                } }
            }
        } finally { results.close() }
    }
    var failure: Throwable = IOException("No Relay carrier is available")
    try {
        for (result in results) {
            result.getOrNull()?.let { return@coroutineScope it }
            failure = result.exceptionOrNull() ?: failure
        }
        throw failure
    } finally {
        workers.cancel()
        results.cancel()
    }
}

/** A changing Network can close native TLS/QUIC before its blocking call returns. */
private class CarrierAttempt : AutoCloseable {
    private var owner: AutoCloseable? = null
    private var cancelled = false
    @Synchronized fun adopt(value: AutoCloseable) {
        if (cancelled) { value.close(); throw CancellationException("Relay candidate cancelled") }
        owner = value
    }
    override fun close() {
        val closing = synchronized(this) { cancelled = true; owner.also { owner = null } }
        runCatching { closing?.close() }
    }
}

private val carrierExecutor = ThreadPoolExecutor(4, 8, 30, TimeUnit.SECONDS,
    ArrayBlockingQueue(64), { task -> Thread(task, "peerward-relay-dial").apply { isDaemon = true } }).apply {
    allowCoreThreadTimeOut(true)
}

internal suspend fun <T> carrierBlocking(attempt: AutoCloseable, onAbandoned: (T) -> Unit = { attempt.close() }, block: () -> T): T =
    suspendCancellableCoroutine { continuation ->
        continuation.invokeOnCancellation { attempt.close() }
        try {
            carrierExecutor.execute {
                if (!continuation.isActive) return@execute
                try {
                    val value = block()
                    continuation.resume(value) { _, abandoned, _ -> onAbandoned(abandoned) }
                } catch (error: Exception) {
                    attempt.close()
                    continuation.resumeWithException(error)
                }
            }
        } catch (error: Exception) {
            attempt.close()
            continuation.resumeWithException(error)
        }
    }
