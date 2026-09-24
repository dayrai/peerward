package io.github.peerward.peerward.nativecore

import android.os.SystemClock
import io.github.peerward.peerward.crypto.NativeKeyAgreement
import io.github.peerward.peerward.crypto.NoiseKeyHandle
import org.json.JSONArray
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicLong

data class WireguardTicket(val id: Long, val tunnel: Boolean, val endpoint: String?, val localEndpoint: String?)
data class ManagedDnsRoute(val configurationVersion: Long, val upstreams: List<java.net.InetSocketAddress>, val tunnelUpstreams: Set<java.net.InetSocketAddress> = emptySet())

data class ManagedNetworkConfiguration(val version: Long, val preferencesVersion: Long, val routes: List<String>, val searchDomains: List<String>, val acceptDns: Boolean, val exitSelected: Boolean, val allowLocalLan: Boolean)

/** One Mesh owns this handle, including while every Relay or underlay is unavailable. */
class NativeWireguardRuntime(profile: ByteArray, key: NoiseKeyHandle, stateDirectory: java.io.File) : AutoCloseable {
    val directPackets = AtomicLong(0)
    val relayPackets = AtomicLong(0)
    private val handle = AtomicLong(NativeKeyAgreement.installWireguard(
        key.wireguardKeyAlias, key.wireguardX25519, key.wrappedWireguardMaterial,
        0, profile, ByteArray(0),
    ).also { check(it > 0) })

    init {
        try { nativeExchange(openHandle(), 9, stateDirectory.canonicalPath.toByteArray(Charsets.UTF_8)) }
        catch (failure: Throwable) { close(); throw failure }
    }

    internal fun openHandle(): Long = handle.get().also { check(it > 0) }

    fun stage(credential: ByteArray, key: NoiseKeyHandle) {
        NativeKeyAgreement.installWireguard(
            key.wireguardKeyAlias, key.wireguardX25519, key.wrappedWireguardMaterial,
            openHandle(), ByteArray(0), credential,
        )
    }

    fun managedNetwork(source: String): ManagedNetworkConfiguration {
        val value = org.json.JSONObject(nativeExchange(openHandle(), 14, source.toByteArray()).toString(Charsets.UTF_8))
        fun strings(key: String): List<String> = value.getJSONArray(key).let { array -> (0 until array.length()).map(array::getString) }
        return ManagedNetworkConfiguration(value.getLong("configuration_version"), value.getLong("preferences_version"), strings("routes"), strings("search_domains"), value.getBoolean("accept_dns"), value.getBoolean("exit_selected"), value.getBoolean("allow_local_lan"))
    }

    fun observeNetwork(version: Long, preferencesVersion: Long, source: String, applied: Boolean, reason: String?) {
        val value = org.json.JSONObject().put("configuration_version", version).put("preferences_version", preferencesVersion).put("source",source)
            .put("result",if (applied) "applied" else "rejected").put("reason",reason ?: org.json.JSONObject.NULL)
        nativeExchange(openHandle(),15,value.toString().toByteArray())
    }

    fun clientPreferences(request: org.json.JSONObject = org.json.JSONObject().put("operation", "get")): org.json.JSONObject =
        org.json.JSONObject(nativeExchange(openHandle(), 16, request.toString().toByteArray()).toString(Charsets.UTF_8))

    fun send(packet: ByteArray) { nativeExchange(openHandle(), 1, packet) }
    fun receive(datagram: ByteArray) { nativeExchange(openHandle(), 2, datagram) }
    fun candidates(endpoints: List<String>) {
        require(endpoints.size <= 32)
        nativeExchange(openHandle(), 3, JSONArray(endpoints).toString().toByteArray())
    }

    fun localPaths(local: List<String>, endpoints: List<String>) {
        require(local.size <= 8 && endpoints.size <= 32)
        nativeExchange(openHandle(), 11, JSONArray().put(JSONArray(local)).put(JSONArray(endpoints)).toString().toByteArray())
    }

    fun receiveOn(local: String, remote: String, packet: ByteArray) {
        val source = local.toByteArray(Charsets.US_ASCII)
        val target = remote.toByteArray(Charsets.US_ASCII)
        require(source.size in 1..64 && target.size in 1..64)
        nativeExchange(openHandle(), 10, byteArrayOf(source.size.toByte()) + source + byteArrayOf(target.size.toByte()) + target + packet)
    }

    fun poll(): List<WireguardTicket> {
        val input = ByteBuffer.wrap(nativeExchange(openHandle(), 0, ByteArray(0)))
        require(input.remaining() >= 2 && input.get().toInt() == 2)
        val count = input.get().toInt() and 0xff
        require(count <= 64)
        val tickets = List(count) {
            require(input.remaining() >= 10)
            val tunnel = input.get().toInt()
            require(tunnel in 0..1)
            val id = input.long
            require(id > 0)
            val length = input.get().toInt() and 0xff
            require(length <= input.remaining())
            val endpoint = ByteArray(length).also(input::get).toString(Charsets.US_ASCII)
            require(input.hasRemaining())
            val localLength = input.get().toInt() and 0xff
            require(localLength <= input.remaining())
            val local = ByteArray(localLength).also(input::get).toString(Charsets.US_ASCII)
            WireguardTicket(id, tunnel == 1, endpoint.takeIf(String::isNotEmpty), local.takeIf(String::isNotEmpty))
        }
        require(!input.hasRemaining())
        return tickets
    }

    fun directPathCount(): Int = ByteBuffer.wrap(nativeExchange(openHandle(), 5, ByteArray(0))).int
    fun confirmedCredential(): ByteArray? = nativeExchange(openHandle(), 8, ByteArray(0)).takeIf(ByteArray::isNotEmpty)
    fun resolveDns(query: ByteArray, source: ByteArray, suffix: String): ByteArray = nativeExchange(
        openHandle(), 7, JSONArray().put(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(query))
            .put(java.net.InetAddress.getByAddress(source).hostAddress).put(suffix).toString().toByteArray(),
    )
    fun managedDnsRoute(query: ByteArray, source: ByteArray): ManagedDnsRoute? {
        val bytes = nativeExchange(openHandle(), 12, JSONArray()
            .put(java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(query))
            .put(java.net.InetAddress.getByAddress(source).hostAddress).toString().toByteArray())
        if (bytes.isEmpty()) return null
        val value = org.json.JSONObject(bytes.toString(Charsets.UTF_8))
        val servers = value.getJSONArray("upstreams")
        require(servers.length() in 1..4)
        val tunnelUpstreams = mutableSetOf<java.net.InetSocketAddress>()
        val upstreams = List(servers.length()) { index ->
            val server = servers.getJSONObject(index)
            val address = server.getString("address")
            require(address.all { it.isDigit() || it in ".:abcdefABCDEF" })
            java.net.InetSocketAddress(java.net.InetAddress.getByName(address), server.getInt("port")).also {
                if (server.getBoolean("tunnel")) tunnelUpstreams += it
            }
        }
        return ManagedDnsRoute(value.getLong("configuration_version"), upstreams, tunnelUpstreams)
    }
    fun dnsConfigurationActive(version: Long, source: ByteArray): Boolean = nativeExchange(
        openHandle(), 13, JSONArray().put(version).put(java.net.InetAddress.getByAddress(source).hostAddress).toString().toByteArray(),
    ).contentEquals(byteArrayOf(1))
    fun fallback(ticket: Long) { nativeExchange(openHandle(), 6, ByteBuffer.allocate(8).putLong(ticket).array()) }

    fun writeTunnel(ticket: Long, tun: NativeTunPacketPump): Boolean = nativeDeliver(
        openHandle(), ticket, tun.openHandle(), 0, 0,
    )

    fun writeRelay(ticket: Long, relay: NativeRelaySocket, session: NativePeerCore): Boolean = nativeDeliver(
        openHandle(), ticket, relay.openHandle(), session.openHandle(), SystemClock.elapsedRealtime() / 1_000,
    ).also { if (it) relayPackets.incrementAndGet() }

    override fun close() {
        val value = handle.getAndSet(0)
        if (value > 0) nativeExchange(value, 4, ByteArray(0))
    }

    companion object {
        init { System.loadLibrary("peerward_android_core") }

        /** Called only inside the Keystore unwrap/finally-zeroize boundary. */
        @JvmStatic external fun nativeInstall(
            handle: Long, profile: ByteArray, credential: ByteArray, privateKey: ByteArray,
        ): Long
        @JvmStatic private external fun nativeExchange(handle: Long, operation: Int, input: ByteArray): ByteArray
        @JvmStatic private external fun nativeDeliver(
            handle: Long, ticket: Long, target: Long, session: Long, monotonic: Long,
        ): Boolean
    }
}
