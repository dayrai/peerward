package io.github.peerward.peerward.vpn

import android.os.ParcelFileDescriptor
import io.github.peerward.peerward.profile.PeerProfile
import io.github.peerward.peerward.nativecore.PeerwardPacketDeniedException
import io.github.peerward.peerward.nativecore.PeerwardInvalidInputException
import io.github.peerward.peerward.nativecore.PeerwardNativeException
import io.github.peerward.peerward.nativecore.NativeRuntimeStatus
import io.github.peerward.peerward.nativecore.NativeTunPacketPump
import io.github.peerward.peerward.nativecore.NativeTunPumpAction
import io.github.peerward.peerward.runtime.MobileRuntimeState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.joinAll
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.IOException
import java.util.concurrent.atomic.AtomicReference

enum class TunnelHealth { STOPPED, CONNECTING, HEALTHY, DEGRADED, RECONNECTING }

internal fun authoritativeTunnelHealth(status: NativeRuntimeStatus?): TunnelHealth =
    if (
        status != null &&
        status.primaryRelayAuthenticated &&
        status.signedStateComplete &&
        status.signedRevision > 0
    ) {
        TunnelHealth.HEALTHY
    } else {
        TunnelHealth.DEGRADED
    }

internal class PacketPump(
    tun: ParcelFileDescriptor,
    private val profile: PeerProfile,
    private val openTransport: suspend () -> PacketTransport,
    private val dnsProxy: TunDnsProxy? = null,
    private val onRuntimeStatus: (NativeRuntimeStatus) -> Unit = {},
    private val onHealth: (TunnelHealth) -> Unit = {},
) : AutoCloseable {
    private val current = AtomicReference<PacketTransport?>()
    private val retired = AtomicReference<PacketTransport?>()
    private val currentHealth = AtomicReference<TunnelHealth?>()
    private data class Outbound(val bytes: ByteArray, val expires: Long)
    private val outbound = Channel<Outbound>(capacity = 256, onUndeliveredElement = { it.bytes.fill(0) })
    private val nativeTun = ReplaceableTun(tun, profile.dnsServers, profile.mtu)
    internal fun tunnelIdentity(): Long = nativeTun.get().openHandle()
    fun replaceTunnel(descriptor: ParcelFileDescriptor): Long = nativeTun.replace(descriptor)
    private var job: Job? = null
    private val dnsSlots = kotlinx.coroutines.sync.Semaphore(32)

    fun start(scope: CoroutineScope) {
        check(job == null) { "packet pump already started" }
        job = scope.launch(Dispatchers.IO) {
            val reader = launch {
                try {
                    while (isActive) {
                        val tunnel = nativeTun.get()
                        val action = try {
                            tunnel.poll(250)
                        } catch (_: PeerwardInvalidInputException) {
                            // A malformed packet from the local TUN is untrusted input. Drop it
                            // without taking down the VPN process or reopening the data path.
                            continue
                        } catch (error: Exception) {
                            if (!nativeTun.isCurrent(tunnel)) continue
                            throw error
                        }
                        if (!nativeTun.isCurrent(tunnel)) {
                            if (action is NativeTunPumpAction.Packet) action.bytes.fill(0)
                            continue
                        }
                        when (action) {
                            NativeTunPumpAction.Idle -> Unit
                            is NativeTunPumpAction.Packet -> {
                                if (action.bytes.size > profile.mtu) action.bytes.fill(0)
                                else outbound.send(Outbound(
                                    action.bytes, android.os.SystemClock.elapsedRealtime() + 3_000,
                                ))
                            }
                            is NativeTunPumpAction.Resolve -> {
                                if (!dnsSlots.tryAcquire()) {
                                    completeDns(tunnel, action.token, ByteArray(0))
                                } else launch {
                                    try {
                                        // Routed upstream sockets feed this same TUN. Keep its reader
                                        // running while DNS waits, with a fixed concurrency bound.
                                        val response = dnsProxy?.resolve(action, current.get()) ?: ByteArray(0)
                                        completeDns(tunnel, action.token, response)
                                    } finally { dnsSlots.release() }
                                }
                            }
                        }
                    }
                } catch (error: IOException) {
                    // Closing the TUN interrupts a blocking read during normal
                    // shutdown. A live-reader failure still cancels the pump.
                    if (currentCoroutineContext().isActive) throw error
                } catch (error: PeerwardNativeException) {
                    // Removing the native handle may race a final canceled poll.
                    // A native state error while the reader is live remains fatal.
                    if (currentCoroutineContext().isActive) throw error
                } catch (error: IllegalStateException) {
                    // A DNS completion may resume after close() has atomically retired the
                    // TUN handle. Suppress that closed-handle state only after cancellation.
                    if (currentCoroutineContext().isActive) throw error
                }
            }
            try {
                runRuntime()
            } finally {
                reader.cancel()
                retireTransport()
                updateHealth(TunnelHealth.STOPPED)
            }
        }
    }

    private suspend fun runRuntime() {
        updateHealth(TunnelHealth.CONNECTING)
        val transport = openTransport()
        current.set(transport)
        transport.runtimeStatus()?.let { publishTransportHealth(transport, it) }
        kotlinx.coroutines.coroutineScope {
            val heartbeat = launch {
                var hadAuthenticatedRoute = false
                while (isActive) {
                    val status = transport.runtimeStatus()
                    if (status == null) {
                        updateHealth(
                            if (hadAuthenticatedRoute) {
                                TunnelHealth.RECONNECTING
                            } else {
                                TunnelHealth.CONNECTING
                            },
                        )
                        kotlinx.coroutines.delay(NO_ROUTE_OBSERVE_MILLIS)
                        continue
                    }
                    hadAuthenticatedRoute = hadAuthenticatedRoute || status.primaryRelayAuthenticated
                    val schedule = MobileRuntimeState.schedule(status)
                    if (schedule.observeStatus) publishTransportHealth(transport, status)
                    if (schedule.sendKeepalive) {
                        transport.keepalive(android.os.SystemClock.elapsedRealtime())
                    }
                    if (schedule.reportHealth) transport.reportHealth()
                    kotlinx.coroutines.delay(schedule.nextPollMillis)
                }
            }
            val inbound = launch {
                while (isActive) {
                    try {
                        val packet = transport.receive()
                        val tunnel = nativeTun.get()
                        try { transport.writeInbound(packet, tunnel) }
                        catch (error: Exception) { if (nativeTun.isCurrent(tunnel)) throw error }
                    } catch (_: PeerwardInvalidInputException) {
                        // Authenticated but malformed inbound packets remain fail-closed.
                    } catch (error: PeerwardNativeException) {
                        if (currentCoroutineContext().isActive) throw error
                    }
                }
            }
            try {
                while (isActive) {
                    try {
                        val packet = outbound.receive()
                        try {
                            if (packet.expires > android.os.SystemClock.elapsedRealtime()) transport.send(packet.bytes)
                        } finally {
                            packet.bytes.fill(0)
                        }
                    } catch (_: PeerwardPacketDeniedException) {
                        // Signed ACL rejection is a packet decision, not Relay health.
                    }
                }
            } finally {
                heartbeat.cancel()
                inbound.cancel()
            }
        }
    }

    private suspend fun publishTransportHealth(
        transport: PacketTransport,
        observed: NativeRuntimeStatus? = null,
    ) {
        val status = observed ?: transport.runtimeStatus()
        if (status == null) {
            updateHealth(authoritativeTunnelHealth(null))
            return
        }
        onRuntimeStatus(status)
        updateHealth(authoritativeTunnelHealth(status))
    }

    private fun completeDns(tunnel: NativeTunPacketPump, token: Long, response: ByteArray) {
        if (!nativeTun.isCurrent(tunnel)) return
        try { tunnel.completeDns(token, response) }
        catch (error: Exception) { if (nativeTun.isCurrent(tunnel)) throw error }
    }

    private fun updateHealth(health: TunnelHealth) {
        if (currentHealth.getAndSet(health) != health) onHealth(health)
    }

    override fun close() {
        job?.cancel()
        retireTransport()
        dnsProxy?.close()
        nativeTun.close()
        outbound.cancel()
    }

    suspend fun awaitStopped() {
        listOfNotNull(job).joinAll()
        retired.get()?.awaitStopped()
    }

    private fun retireTransport() {
        current.getAndSet(null)?.let { transport ->
            retired.set(transport)
            transport.close()
        }
    }

    private companion object {
        const val NO_ROUTE_OBSERVE_MILLIS = 250L
    }
}
