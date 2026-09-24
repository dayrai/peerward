package io.github.peerward.peerward.net

import android.net.Network
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withTimeoutOrNull
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URI
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume

/** DNS uses the same Android Network as the protected data socket, including DNS64. */
internal object StunServerResolver {
    // getAllByName can outlive cancellation on API 28. No waiting queue and at most four
    // running OS lookups keep repeated network changes bounded even if DNS never returns.
    private val workers = ThreadPoolExecutor(0, 4, 30, TimeUnit.SECONDS, SynchronousQueue<Runnable>()) {
        Thread(it, "peerward-stun-dns").apply { isDaemon = true }
    }

    suspend fun resolve(network: Network, servers: List<String>, ipv6: Boolean): List<InetSocketAddress> =
        resolveWith(servers, ipv6, network::getAllByName)

    internal suspend fun resolveWith(
        servers: List<String>,
        ipv6: Boolean,
        lookup: (String) -> Array<InetAddress>,
        timeoutMillis: Long = 1_000,
    ): List<InetSocketAddress> = coroutineScope {
        // Two family rounds can share the four workers; queued coroutines also expire
        // at the round deadline, without queueing blocking work in the executor.
        val concurrency = Semaphore(2)
        val results = servers.take(8).map { value ->
            async {
                val endpoint = URI("udp://$value")
                val host = requireNotNull(endpoint.host).removePrefix("[").removeSuffix("]")
                require(endpoint.port in 1..65_535)
                val addresses = if (host.contains(':') || host.all { it.isDigit() || it == '.' }) {
                    // The Rust profile codec already requires canonical numeric IP literals.
                    runCatching { arrayOf(InetAddress.getByName(host)) }.getOrDefault(emptyArray())
                } else {
                    withTimeoutOrNull(timeoutMillis) { concurrency.withPermit { query(host, lookup) } }.orEmpty()
                }
                addresses.asSequence().take(64)
                    .filter { (it is Inet6Address) == ipv6 && validAddress(it) }
                    .map { InetSocketAddress(it, endpoint.port) }.distinct().take(8).toList()
            }
        }.map { it.await() }
        // Keep configured-server order and give each server a slot before extra answers.
        (0 until 8).asSequence().flatMap { offset -> results.mapNotNull { it.getOrNull(offset) } }
            .distinct().take(8).toList()
    }

    private suspend fun query(host: String, lookup: (String) -> Array<InetAddress>): Array<InetAddress> =
        suspendCancellableCoroutine { continuation ->
            try {
                workers.execute {
                    val result = runCatching { lookup(host) }.getOrDefault(emptyArray())
                    if (continuation.isActive) continuation.resume(result)
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                continuation.resume(emptyArray())
            }
        }

    private fun validAddress(address: InetAddress): Boolean =
        !address.isAnyLocalAddress && !address.isMulticastAddress &&
            (address !is Inet6Address || (!address.isLinkLocalAddress && address.scopeId == 0)) &&
            !address.address.contentEquals(byteArrayOf(-1, -1, -1, -1))
}
