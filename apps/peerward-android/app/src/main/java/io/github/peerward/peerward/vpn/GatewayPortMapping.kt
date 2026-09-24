package io.github.peerward.peerward.vpn

import android.net.Network
import io.github.peerward.peerward.nativecore.NativeMappingLease
import io.github.peerward.peerward.nativecore.NativeMappingProtocol
import io.github.peerward.peerward.nativecore.NativePortMappingCodec
import io.github.peerward.peerward.net.DatagramProtector
import io.github.peerward.peerward.net.SocketProtector
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetSocketAddress
import kotlin.random.Random

internal class GatewayPortMapping(
    private val socket: DatagramSocket,
    private val internal: InetSocketAddress,
    private val gateway: InetSocketAddress?,
    private val network: Network,
    private val socketProtector: SocketProtector,
    private val datagramProtector: DatagramProtector,
    private val onMapping: (InetSocketAddress?, Long) -> Unit,
) {
    private val responses = Channel<ByteArray>(capacity = RESPONSE_CAPACITY)
    private val upnp = AndroidUpnpClient(network, socketProtector, datagramProtector, internal, gateway)
    private var job: Job? = null

    fun start(scope: CoroutineScope) {
        check(job == null) { "gateway mapping already started" }
        job = scope.launch { run() }
    }

    fun accept(source: InetSocketAddress, payload: ByteArray): Boolean {
        val expected = gateway ?: return false
        if (!isGatewayResponse(expected, source, payload)) return false
        responses.trySend(payload)
        return true
    }

    suspend fun stop() {
        val active = job ?: return
        active.cancel()
        withTimeoutOrNull(STOP_TIMEOUT_MILLIS) { active.join() }
        job = null
    }

    private suspend fun run() {
        var lease: AndroidMappingLease? = null
        try {
            while (currentCoroutineContext().isActive) {
                if (lease == null) {
                    lease = mappingAttempt { discover() }
                    if (lease == null) {
                        onMapping(null, 0)
                        delay(RETRY_MILLIS)
                        continue
                    }
                    onMapping(lease.external, lease.lifetimeSeconds)
                }
                val current = lease
                delay(renewalDelayMillis(current.lifetimeSeconds))
                val renewed = mappingAttempt { renew(current) }
                if (renewed == null) {
                    onMapping(null, 0)
                    withContext(NonCancellable) {
                        withTimeoutOrNull(IO_TIMEOUT_MILLIS) {
                            mappingAttempt { delete(current) }
                        }
                    }
                    lease = null
                } else {
                    lease = renewed
                    onMapping(renewed.external, renewed.lifetimeSeconds)
                }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } finally {
            onMapping(null, 0)
            lease?.let { current ->
                withContext(NonCancellable) {
                    withTimeoutOrNull(STOP_TIMEOUT_MILLIS) {
                        mappingAttempt { delete(current) }
                    }
                }
            }
        }
    }

    private suspend fun discover(): AndroidMappingLease? {
        gateway?.let { target ->
            pcp(target, LIFETIME_SECONDS, null)?.let { return AndroidMappingLease.Datagram(it) }
            if (target.address is Inet4Address && internal.address is Inet4Address) {
                natPmp(target, LIFETIME_SECONDS, null)?.let {
                    return AndroidMappingLease.Datagram(it)
                }
            }
        }
        return upnp.discoverAndMap(LIFETIME_SECONDS)?.let(AndroidMappingLease::Upnp)
    }

    private suspend fun renew(lease: AndroidMappingLease): AndroidMappingLease? = when (lease) {
        is AndroidMappingLease.Datagram -> when (lease.value.protocol) {
            NativeMappingProtocol.PCP -> {
                val target = gateway ?: return null
                val renewed = pcp(target, LIFETIME_SECONDS, lease.value.nonce, suggested = lease.value.external) ?: return null
                if (NativePortMappingCodec.gatewayRestarted(lease.value.epoch ?: 0, renewed.epoch ?: 0)) {
                    null
                } else {
                    AndroidMappingLease.Datagram(renewed)
                }
            }
            NativeMappingProtocol.NAT_PMP -> {
                val target = gateway ?: return null
                val renewed = natPmp(target, LIFETIME_SECONDS, lease.value) ?: return null
                if (NativePortMappingCodec.gatewayRestarted(lease.value.epoch ?: 0, renewed.epoch ?: 0)) {
                    null
                } else {
                    AndroidMappingLease.Datagram(renewed)
                }
            }
            NativeMappingProtocol.UPNP -> null
        }
        is AndroidMappingLease.Upnp -> upnp.renew(lease.value)?.let(AndroidMappingLease::Upnp)
    }

    private suspend fun delete(lease: AndroidMappingLease) {
        when (lease) {
            is AndroidMappingLease.Datagram -> {
                val target = gateway ?: return
                when (lease.value.protocol) {
                    NativeMappingProtocol.PCP -> pcp(target, 0, lease.value.nonce, deleting = true)
                    NativeMappingProtocol.NAT_PMP -> natPmp(target, 0, lease.value, deleting = true)
                    NativeMappingProtocol.UPNP -> Unit
                }
            }
            is AndroidMappingLease.Upnp -> upnp.delete(lease.value)
        }
    }

    private suspend fun pcp(
        target: InetSocketAddress,
        lifetime: Long,
        nonce: ByteArray?,
        deleting: Boolean = false,
        suggested: InetSocketAddress? = null,
    ): NativeMappingLease? {
        drainResponses()
        val request = NativePortMappingCodec.pcpRequest(internal, lifetime, nonce, suggested)
        return transact(target, request.payload) { response ->
            NativePortMappingCodec.acceptPcp(internal, request.nonce, response, deleting)
        }
    }

    private suspend fun natPmp(
        target: InetSocketAddress,
        lifetime: Long,
        previous: NativeMappingLease?,
        deleting: Boolean = false,
    ): NativeMappingLease? {
        drainResponses()
        val public = if (!deleting) {
            val request = NativePortMappingCodec.natPmpPublicRequest()
            transact(target, request, NativePortMappingCodec::acceptNatPmpPublic) ?: return null
        } else {
            val current = previous ?: return null
            io.github.peerward.peerward.nativecore.NativeNatPmpPublicAddress(
                current.external.address,
                current.epoch ?: 0,
            )
        }
        val request = NativePortMappingCodec.natPmpRequest(internal, lifetime, previous?.external?.port ?: internal.port)
        return transact(target, request) { response ->
            NativePortMappingCodec.acceptNatPmp(
                internal,
                public.address,
                response,
                deleting,
            )
        }
    }

    private suspend fun <T> transact(target: InetSocketAddress, request: ByteArray, decoder: (ByteArray) -> T?): T? =
        withTimeoutOrNull(IO_TIMEOUT_MILLIS) {
            var retryMillis = 250L
            while (currentCoroutineContext().isActive) {
                socket.send(DatagramPacket(request, request.size, target))
                withTimeoutOrNull(retryMillis) { receiveDecoded(decoder) }?.let { return@withTimeoutOrNull it }
                retryMillis = (retryMillis * 2).coerceAtMost(1_000)
            }
            null
        }

    private suspend fun <T> receiveDecoded(decoder: (ByteArray) -> T?): T? =
        withTimeoutOrNull(IO_TIMEOUT_MILLIS) {
            while (currentCoroutineContext().isActive) {
                decoder(responses.receive())?.let { return@withTimeoutOrNull it }
            }
            null
        }

    private suspend fun <T> mappingAttempt(operation: suspend () -> T): T? = try {
        operation()
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        null
    }

    private fun drainResponses() {
        while (responses.tryReceive().isSuccess) Unit
    }

    private fun renewalDelayMillis(lifetimeSeconds: Long): Long {
        val bounded = lifetimeSeconds.coerceIn(MIN_LIFETIME_SECONDS, MAX_LIFETIME_SECONDS)
        val half = bounded * 500
        val jitter = (bounded * 50).coerceAtLeast(1)
        return half + Random.nextLong(-jitter, jitter + 1)
    }

    private sealed interface AndroidMappingLease {
        val external: InetSocketAddress
        val lifetimeSeconds: Long

        data class Datagram(val value: NativeMappingLease) : AndroidMappingLease {
            override val external: InetSocketAddress = value.external
            override val lifetimeSeconds: Long = value.lifetimeSeconds
        }

        data class Upnp(val value: AndroidUpnpLease) : AndroidMappingLease {
            override val external: InetSocketAddress = value.external
            override val lifetimeSeconds: Long = value.lifetimeSeconds
        }
    }

    companion object {
        private const val PCP_VERSION = 2
        private const val NAT_PMP_VERSION = 0
        private const val PCP_RESPONSE_BYTES = 60
        private const val NAT_PMP_MIN_RESPONSE = 12
        private const val NAT_PMP_MAX_RESPONSE = 16
        private const val MAX_GATEWAY_DATAGRAM = 1_024
        private const val RESPONSE_CAPACITY = 8
        private const val LIFETIME_SECONDS = 600L
        private const val MIN_LIFETIME_SECONDS = 2L
        private const val MAX_LIFETIME_SECONDS = 86_400L
        private const val IO_TIMEOUT_MILLIS = 2_000L
        // Relay-pool shutdown may close three transports on the service thread.
        // Deletion is best-effort and must not accumulate into an Android ANR.
        private const val STOP_TIMEOUT_MILLIS = 500L
        private const val RETRY_MILLIS = 30_000L

        internal fun isGatewayResponse(
            expected: InetSocketAddress,
            source: InetSocketAddress,
            payload: ByteArray,
        ): Boolean {
            if (source != expected || payload.isEmpty() || payload.size > MAX_GATEWAY_DATAGRAM) {
                return false
            }
            return when (payload[0].toInt() and 0xff) {
                PCP_VERSION -> payload.size == PCP_RESPONSE_BYTES &&
                    payload.getOrNull(1)?.toInt()?.and(0x80) != 0
                NAT_PMP_VERSION -> payload.size in NAT_PMP_MIN_RESPONSE..NAT_PMP_MAX_RESPONSE &&
                    payload.getOrNull(1)?.toInt()?.and(0x80) != 0
                else -> false
            }
        }
    }
}
