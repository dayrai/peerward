package io.github.peerward.peerward.vpn

import android.util.Log
import io.github.peerward.peerward.BuildConfig
import io.github.peerward.peerward.nativecore.NativeDnsTransport
import io.github.peerward.peerward.nativecore.PeerwardInvalidInputException
import io.github.peerward.peerward.nativecore.NativeTunPumpAction
import io.github.peerward.peerward.net.ProtectedDnsClient
import java.io.Closeable
import java.io.IOException

/** Thin protected-socket resolver for a Rust-issued DNS request. */
internal class TunDnsProxy(
    dnsServers: List<String>,
    private val suffix: String,
    @Volatile private var upstream: ProtectedDnsClient?,
    @Suppress("UNUSED_PARAMETER") mtu: Int,
) : Closeable {
    private val localServers = dnsServers.map(java.net.InetAddress::getByName).toSet()
    fun replaceUpstream(client: ProtectedDnsClient?) { upstream = client }
    suspend fun resolve(
        request: NativeTunPumpAction.Resolve,
        transport: PacketTransport?,
    ): ByteArray {
        if (transport == null) return ByteArray(0)
        val local = try {
            transport?.resolveDns(request.query, request.sourceAddress, suffix)
        } catch (error: PeerwardInvalidInputException) {
            logRejectedQuery(request, error)
            // Never leak a malformed Mesh DNS query to an upstream resolver. The empty
            // completion is converted to a bounded SERVFAIL by the native TUN proxy.
            return ByteArray(0)
        } catch (_: io.github.peerward.peerward.nativecore.PeerwardPacketDeniedException) {
            return ByteArray(0)
        } catch (_: io.github.peerward.peerward.nativecore.PeerwardNativeException) {
            return ByteArray(0)
        }
        if (local != null && local.isNotEmpty()) return local
        val route = try { transport?.managedDnsRoute(request.query, request.sourceAddress) }
            catch (_: io.github.peerward.peerward.nativecore.PeerwardNativeException) { return ByteArray(0) }
            catch (_: io.github.peerward.peerward.nativecore.PeerwardPacketDeniedException) { return ByteArray(0) }
            catch (_: io.github.peerward.peerward.nativecore.PeerwardInvalidInputException) { return ByteArray(0) }
        if (route != null) {
            for (server in route.upstreams) {
                if (server.port == 53 && server.address in localServers) continue
                if (!runCatching { transport.dnsConfigurationActive(route.configurationVersion, request.sourceAddress) }.getOrDefault(false)) return ByteArray(0)
                val reply = try {
                    val client = io.github.peerward.peerward.net.RoutedDnsClient(server)
                    when (request.transport) {
                        NativeDnsTransport.UDP -> client.exchangeUdp(request.query)
                        NativeDnsTransport.TCP -> client.exchangeTcp(request.query)
                    }
                } catch (_: IOException) { continue } catch (_: IllegalArgumentException) { continue }
                if (reply.responseCode in setOf(2, 5)) continue
                return if (runCatching { transport.dnsConfigurationActive(route.configurationVersion, request.sourceAddress) }.getOrDefault(false)) reply.bytes else ByteArray(0)
            }
            // A private namespace has only its explicitly configured equivalent upstreams.
            return ByteArray(0)
        }
        return try {
            when (request.transport) {
                NativeDnsTransport.UDP -> upstream?.exchangeUdp(request.query)?.bytes
                NativeDnsTransport.TCP -> upstream?.exchangeTcp(request.query)?.bytes
            } ?: ByteArray(0)
        } catch (error: IOException) {
            logUpstreamFailure(request, error)
            ByteArray(0)
        } catch (error: IllegalArgumentException) {
            logUpstreamFailure(request, error)
            ByteArray(0)
        }
    }

    override fun close() = Unit

    private fun logRejectedQuery(request: NativeTunPumpAction.Resolve, error: Throwable) {
        val counts = if (request.query.size >= 12) {
            (4..10 step 2).joinToString(",") { offset ->
                (((request.query[offset].toInt() and 0xff) shl 8) or
                    (request.query[offset + 1].toInt() and 0xff)).toString()
            }
        } else {
            "truncated"
        }
        val shape = dnsQuestionShape(request.query)
        val summary = "Mesh DNS input rejected " +
            "(query_bytes=${request.query.size},source_bytes=${request.sourceAddress.size}," +
            "counts=$counts,$shape)"
        if (BuildConfig.DEBUG) Log.w(LOG_TAG, summary, error) else Log.w(LOG_TAG, summary)
    }

    private fun dnsQuestionShape(query: ByteArray): String {
        if (query.size < 12) return "flags=truncated"
        val flags = ((query[2].toInt() and 0xff) shl 8) or (query[3].toInt() and 0xff)
        var cursor = 12
        var labels = 0
        var canonical = true
        while (cursor < query.size) {
            val length = query[cursor].toInt() and 0xff
            cursor += 1
            if (length == 0) break
            if (length > 63 || cursor + length > query.size) {
                canonical = false
                break
            }
            canonical = canonical && query.copyOfRange(cursor, cursor + length).all { byte ->
                val value = byte.toInt() and 0xff
                value in 'a'.code..'z'.code || value in 'A'.code..'Z'.code ||
                    value in '0'.code..'9'.code || value == '-'.code
            }
            labels += 1
            cursor += length
        }
        val qtype = if (cursor + 3 < query.size) {
            ((query[cursor].toInt() and 0xff) shl 8) or (query[cursor + 1].toInt() and 0xff)
        } else {
            -1
        }
        val qclass = if (cursor + 3 < query.size) {
            ((query[cursor + 2].toInt() and 0xff) shl 8) or (query[cursor + 3].toInt() and 0xff)
        } else {
            -1
        }
        return "flags=$flags,labels=$labels,canonical=$canonical,qtype=$qtype,qclass=$qclass,end=${cursor + 4}"
    }

    private fun logUpstreamFailure(request: NativeTunPumpAction.Resolve, error: Exception) {
        if (!BuildConfig.DEBUG) return
        Log.d(
            LOG_TAG,
            "Protected DNS upstream failed (${dnsQuestionShape(request.query)}," +
                "failure=${error.javaClass.simpleName})",
        )
    }

    private companion object {
        const val LOG_TAG = "PeerwardDns"
    }
}
