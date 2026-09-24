package io.github.peerward.peerward

import android.content.Context
import android.net.ConnectivityManager
import android.os.SystemClock
import io.github.peerward.peerward.crypto.DeviceKeyStore
import io.github.peerward.peerward.nativecore.NativePeerCore
import io.github.peerward.peerward.nativecore.NativeRelaySocket
import io.github.peerward.peerward.nativecore.NativeWireguardRuntime
import io.github.peerward.peerward.profile.ProfileStore
import io.github.peerward.peerward.vpn.ConnectionDeadline
import io.github.peerward.peerward.vpn.CredentialRotationCoordinator
import io.github.peerward.peerward.vpn.NoiseRelayTransport
import io.github.peerward.peerward.vpn.underlayPreference
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetSocketAddress
import java.net.Socket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Inet4Address
import java.net.URI

/** Uses the real Control/Relay and Keystore, then loses the old key before local commit.
 * A normal restart using the stored old identity must fail; only verified staged recovery works. */
internal suspend fun stageRecoveryFault(context: Context): String = withContext(Dispatchers.IO) {
    val profiles = ProfileStore(context)
    val old = requireNotNull(profiles.load())
    val keys = DeviceKeyStore(context)
    val opaque = requireNotNull(profiles.loadOpaque())
    val owner = try { NativeWireguardRuntime(opaque, keys.handle(old.deviceKeyId), profiles.wireguardStateDirectory(old)) } finally { opaque.fill(0) }
    owner.use {
        val rotation = CredentialRotationCoordinator(profiles, keys, old) { error("test must not commit locally") }
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
        val started = SystemClock.elapsedRealtime()
        fun stage(name: String) = println("rotation recovery: $name after ${SystemClock.elapsedRealtime() - started} ms")
        val network = requireNotNull(connectivity.allNetworks.mapNotNull { network ->
            connectivity.getNetworkCapabilities(network)?.let(::underlayPreference)?.let { network to it }
        }.maxByOrNull { it.second }?.first)
        stage("selected network: wifi=" + (connectivity.getNetworkCapabilities(network)
            ?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI) == true))
        val endpoint = old.relays.first().endpoints.first()
        val dial = URI(old.relayHttpConnectProxy ?: endpoint)
        for (attempt in 0..1) {
            try {
                ConnectionDeadline(10_000).use { deadline ->
                    val options = org.json.JSONObject().put("ca_pem", old.relayCaPem)
                        .put("http_connect_proxy", old.relayHttpConnectProxy).toString()
                    val address = network.getAllByName(dial.host).first()
                    stage("carrier connect")
                    val socketOwner = if (URI(endpoint).scheme == "quic") {
                        DatagramSocket(null).use { socket ->
                            deadline.adopt(socket)
                            network.bindSocket(socket)
                            socket.bind(InetSocketAddress(InetAddress.getByAddress(ByteArray(if (address is Inet4Address) 4 else 16)), 0))
                            NativeRelaySocket.take(socket, endpoint, options, InetSocketAddress(address, dial.port))
                        }
                    } else {
                        Socket().use { socket ->
                            deadline.adopt(socket)
                            network.bindSocket(socket)
                            socket.connect(InetSocketAddress(address, dial.port), 3_000)
                            NativeRelaySocket.take(socket, endpoint, options)
                        }
                    }
                    socketOwner.use { carrier ->
                            stage("carrier connected")
                            deadline.adopt(carrier)
                            NativePeerCore(NoiseRelayTransport.nativeConfig(old, 0, keys), owner).use { core ->
                                fun clock() = SystemClock.elapsedRealtime() / 1_000
                                carrier.writeHandshake(core.firstHandshake())
                                core.finishHandshake(carrier.readHandshake(), clock())
                                stage("Noise verified")
                                carrier.activate(core, clock())
                                core.confirmLink(carrier.readFrame(), clock())
                                stage("link confirmed")
                                val material = rotation.pendingMaterial()
                                val transcript = core.rotationRequestTranscript(material.requestId, material.identityPublicKey,
                                    material.sessionPublicKey, material.wireguardPublicKey)
                                // Only the local renewal scheduler's clock is advanced. The server still
                                // verifies the real, current identity proof and issues/activates normally.
                                val request = requireNotNull(core.rotationRequest(material.requestId, material.identityPublicKey,
                                    material.sessionPublicKey, material.wireguardPublicKey, rotation.signCurrent(transcript), Long.MAX_VALUE))
                                carrier.writeFrame(core.encryptControl(request, clock()))
                                while (true) {
                                    val record = core.decrypt(carrier.readFrame(), clock())
                                    when (record.updateKind) {
                                        6 -> carrier.writeFrame(core.encryptControl(core.rotationActivation(
                                            rotation.acceptReplacement(record.payload, owner)), clock()))
                                        8 -> { stage("activation observed"); break } // Signed activation observed; deliberately lose local commit.
                                    }
                                }
                            }
                    }
                }
                break
            } catch (error: io.github.peerward.peerward.nativecore.PeerwardNativeException) {
                if (attempt != 0 || error.message != "credential validation failed") throw error
                // A just-issued credential may be ahead of the device's wall clock. Reconnect
                // using the same persisted request ID; never relax not_before or replay link frames.
                println("rotation fault setup: retrying credential validation with the same request ID")
                kotlinx.coroutines.delay(1_100)
            }
        }
        val staged = requireNotNull(profiles.load())
        check(staged.deviceKeyId == old.deviceKeyId && staged.pendingCredential != null)
        val replacement = requireNotNull(staged.pendingDeviceKeyId)
        keys.delete(old.deviceKeyId) // Fault injection confined to the isolated test profile.
        check(runCatching { keys.handle(old.deviceKeyId) }.isFailure)
        replacement
    }
}
