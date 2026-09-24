package io.github.peerward.peerward

import android.os.SystemClock
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.security.SecureRandom

/** One ordinary application socket traverses Android TUN, WireGuard and the Linux TUN. */
internal class TunPeerScenario private constructor(private val destination: InetAddress) : AutoCloseable {
    private val socket = DatagramSocket().apply { soTimeout = 1000 }

    fun verify(phase: String) {
        val initial = diagnostics()
        val deadline = SystemClock.elapsedRealtime() + 30_000
        var received = 0
        while (received < 20 && SystemClock.elapsedRealtime() < deadline) {
            if (roundTrip(deadline - SystemClock.elapsedRealtime())) received++ else break
        }
        assertTrue("$phase: only $received/20 complete Linux TUN echoes; before=$initial; after=${diagnostics()}", received == 20)
    }

    private fun diagnostics(): String {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val connectivity = context.getSystemService(android.net.ConnectivityManager::class.java)
        val networks = connectivity.allNetworks.filter {
            connectivity.getNetworkCapabilities(it)?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) == true
        }.map { network -> "$network:${connectivity.getLinkProperties(network)?.interfaceName}" }
        return "socket=${socket.localPort},vpn=$networks,owner=${io.github.peerward.peerward.vpn.PeerwardVpnService.activeResourceIdentity}," +
            io.github.peerward.peerward.runtime.MobileRuntimeState.diagnosticsJson()
    }

    fun roundTrip(timeoutMillis: Long): Boolean {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        // One nonce per probe, including retransmissions. Sending a new nonce after
        // every delayed reply creates an endless FIFO lag and a false recovery failure.
        val payload = ByteArray(1200).also { SecureRandom().nextBytes(it) }
        "peerward-tun-probe:".toByteArray(Charsets.US_ASCII).copyInto(payload)
        var nextSend = 0L
        socket.soTimeout = 250
        try {
            while (SystemClock.elapsedRealtime() < deadline) {
                val now = SystemClock.elapsedRealtime()
                if (now >= nextSend) {
                    socket.send(DatagramPacket(payload, payload.size, destination, 24445))
                    nextSend = now + 250
                }
                try {
                    val reply = DatagramPacket(ByteArray(2048), 2048)
                    socket.receive(reply)
                    if (reply.address == destination && reply.port == 24445 && reply.data.copyOf(reply.length).contentEquals(payload)) return true
                } catch (_: SocketTimeoutException) { }
            }
            return false
        } finally { socket.soTimeout = 1000 }
    }

    override fun close() = socket.close()

    companion object {
        fun optional(): TunPeerScenario? = InstrumentationRegistry.getArguments()
            .getString("peerwardTunPeer")?.let { TunPeerScenario(InetAddress.getByName(it)) }
    }
}
