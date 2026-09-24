package io.github.peerward.peerward.vpn

import android.util.Log
import io.github.peerward.peerward.BuildConfig
import io.github.peerward.peerward.nativecore.NativeRelayConnectRequest
import io.github.peerward.peerward.nativecore.NativeRelayPoolCoordinator
import io.github.peerward.peerward.nativecore.NativeRelayRoute
import io.github.peerward.peerward.nativecore.NativeRuntimeStatus
import io.github.peerward.peerward.nativecore.PeerwardPacketDeniedException
import io.github.peerward.peerward.nativecore.PeerwardAuthenticationException
import java.time.Instant
import io.github.peerward.peerward.profile.PeerProfile
import java.io.IOException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.withContext

/** Platform I/O adapter for the Rust-owned primary/two-standby Relay state machine. */
class RelayPoolTransport private constructor(
    private val profile: PeerProfile,
    private val factory: PacketTransportFactory,
    private val endpointSets: List<List<String>>,
    private val native: NativeRelayPoolCoordinator,
) : PacketTransport {
    private data class OwnedTransport(
        val route: NativeRelayRoute,
        val transport: PacketTransport,
    )

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val state = Mutex()
    private val transports = mutableMapOf<Long, OwnedTransport>()
    private val inbound = Channel<ByteArray>(256)
    private val wake = Channel<Unit>(Channel.CONFLATED)
    private var worker: Job? = null
    private var closed = false
    private data class ConnectionFailure(val code: String, val observedAt: Long)
    private val failures = mutableMapOf<Int, ConnectionFailure>()

    override suspend fun send(packet: ByteArray) {
        while (scope.isActive) {
            val selected = primaryTransport()
            if (selected == null) {
                wake.trySend(Unit)
                delay(NO_RELAY_POLL_MILLIS)
                continue
            }
            try {
                maybeRefresh(selected)
                selected.transport.send(packet)
                return
            } catch (denied: PeerwardPacketDeniedException) {
                throw denied
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                fail(selected)
            }
        }
        throw IOException("Relay pool is closed")
    }

    override suspend fun receive(): ByteArray = inbound.receiveCatching().getOrNull()
        ?: throw CancellationException("Relay pool is closed")

    /** Never wait for a Relay while a WireGuard timer or direct path needs service. */
    override suspend fun sendWireguard(ticket: Long): Boolean {
        val selected = primaryTransport() ?: return false
        return try {
            selected.transport.sendWireguard(ticket)
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            fail(selected)
            false
        }
    }

    override fun runtimeStatus(): NativeRuntimeStatus? = runBlocking {
        val routes = runCatching(native::routes).getOrDefault(emptyList())
        val primary = routes.firstOrNull() ?: return@runBlocking state.withLock {
            if (closed) null else failures.values.maxByOrNull { it.observedAt }?.let { failure ->
                NativeRuntimeStatus(false, 0, diagnosticCode = failure.code, diagnosticObservedAt = failure.observedAt)
            }
        }
        val selected = state.withLock { transports[primary.generation] } ?: return@runBlocking null
        selected.transport.runtimeStatus()?.copy(
            primaryRelayAuthenticated = true,
            standbyRelayCount = routes.size.minus(1).coerceAtLeast(0),
        )
    }

    override suspend fun resolveDns(
        query: ByteArray,
        sourceAddress: ByteArray,
        suffix: String,
    ): ByteArray? = primaryTransport()?.transport?.resolveDns(query, sourceAddress, suffix)

    override suspend fun keepalive(timestamp: Long) {
        activeTransports().forEach { owned ->
            try {
                maybeRefresh(owned)
                owned.transport.keepalive(timestamp)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                logFailure("record-forward", error)
                fail(owned)
            }
        }
    }

    override suspend fun reportHealth() {
        activeTransports().forEach { owned ->
            try {
                owned.transport.reportHealth()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                fail(owned)
            }
        }
    }

    private suspend fun primaryTransport(): OwnedTransport? {
        val route = runCatching(native::routes).getOrDefault(emptyList()).firstOrNull() ?: return null
        return state.withLock { transports[route.generation] }
    }

    private suspend fun activeTransports(): List<OwnedTransport> {
        val generations = runCatching(native::routes)
            .getOrDefault(emptyList())
            .map(NativeRelayRoute::generation)
            .toSet()
        return state.withLock { transports.values.filter { it.route.generation in generations } }
    }

    private fun startWorker() {
        check(worker == null)
        worker = scope.launch {
            while (isActive) {
                val poll = native.poll()
                poll.requests.forEach { request ->
                    launch {
                        execute(request)
                        wake.trySend(Unit)
                    }
                }
                withTimeoutOrNull(poll.nextPollMillis) { wake.receiveCatching().getOrNull() }
            }
        }
        wake.trySend(Unit)
    }

    private suspend fun execute(request: NativeRelayConnectRequest) {
        var failure: ConnectionFailure? = null
        val endpoint = endpointSets
            .getOrNull(request.slot)
            ?.getOrNull(request.endpointIndex)
        val replacement = endpoint?.let { value ->
            try {
                factory.connectAny(listOf(value) + endpointSets[request.slot].filter { it != value }, profile)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (error: Exception) {
                failure = ConnectionFailure(
                    if (error is PeerwardAuthenticationException) "authentication_failed" else "relay_reconnecting",
                    Instant.now().epochSecond,
                )
                null
            }
        }
        val completion = runCatching { native.complete(request, replacement != null) }
            .onFailure { error -> logFailure("pool-commit", error) }
        // Only accepted, current-generation completions can publish a failure.
        if (completion.isSuccess) state.withLock {
            if (!closed) {
                if (replacement != null) failures.remove(request.slot)
                else failure?.let { failures[request.slot] = it }
            }
        }
        val commit = completion.getOrNull()
        if (replacement == null || commit == null) {
            replacement?.close()
            return
        }
        val installed = withContext(NonCancellable) {
            state.withLock {
                if (closed) {
                    null
                } else {
                    val old = commit.replacedGeneration?.let(transports::remove)
                    val owned = OwnedTransport(commit.route, replacement)
                    transports[commit.route.generation] = owned
                    owned to old
                }
            }
        }
        if (installed == null) {
            replacement.close()
            return
        }
        startReader(installed.first)
        installed.second?.transport?.closeForReplacement()
    }

    private fun startReader(owned: OwnedTransport) {
        scope.launch {
            try {
                while (isActive) {
                    val packet = owned.transport.receive()
                    if (runCatching { native.isPrimary(owned.route) }.getOrDefault(false)) {
                        inbound.send(packet)
                    }
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                fail(owned)
            }
        }
    }

    private suspend fun fail(owned: OwnedTransport) {
        val removed = state.withLock {
            if (transports[owned.route.generation]?.transport !== owned.transport) false else {
                transports.remove(owned.route.generation)
                true
            }
        }
        if (!removed) return
        owned.transport.close()
        runCatching { native.failed(owned.route) }
        wake.trySend(Unit)
    }

    private suspend fun maybeRefresh(owned: OwnedTransport) {
        if (!runCatching(owned.transport::replacementDue).getOrDefault(false)) return
        runCatching { native.refresh(owned.route) }
        wake.trySend(Unit)
    }

    override fun close() {
        scope.cancel()
        inbound.close()
        wake.close()
        runBlocking {
            state.withLock {
                closed = true
                transports.values.forEach { it.transport.close() }
                transports.clear()
                failures.clear()
            }
        }
        native.close()
    }

    companion object {
        private const val NO_RELAY_POLL_MILLIS = 25L
        private const val LOG_TAG = "PeerwardRelay"

        private fun logFailure(stage: String, error: Throwable) {
            if (BuildConfig.DEBUG) {
                Log.w(LOG_TAG, "Relay pool failed at $stage", error)
            } else {
                Log.w(LOG_TAG, "Relay pool failed at $stage (${error.javaClass.simpleName})")
            }
        }

        suspend fun open(
            profile: PeerProfile,
            factory: PacketTransportFactory,
        ): RelayPoolTransport {
            val endpoints = profile.relayTargets().take(3).map { relay ->
                relay.endpoints.distinct()
                    .filter { profile.relayHttpConnectProxy == null || it.startsWith("wss://") }
                    .sortedBy { when { it.startsWith("quic://") -> 0; it.startsWith("wss://") -> 1; else -> 2 } }
            }
            require(endpoints.isNotEmpty() && endpoints.all { it.isNotEmpty() }) {
                "profile has no Relay endpoint"
            }
            return RelayPoolTransport(
                profile,
                factory,
                endpoints,
                NativeRelayPoolCoordinator(endpoints.map(List<String>::size)),
            ).also { pool ->
                pool.startWorker()
            }
        }
    }
}
