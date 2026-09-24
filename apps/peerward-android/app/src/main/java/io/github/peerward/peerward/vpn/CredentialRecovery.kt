package io.github.peerward.peerward.vpn

import android.net.Network
import io.github.peerward.peerward.crypto.DeviceKeyStore
import io.github.peerward.peerward.nativecore.NativeProfileCodec
import io.github.peerward.peerward.nativecore.NativeWireguardRuntime
import io.github.peerward.peerward.net.VpnSocketProtector
import io.github.peerward.peerward.profile.ProfileStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull
import java.util.Base64

/** No TUN or committed identity is replaced until the staged credential is signed as active. */
internal suspend fun recoverActivatedCredential(
    profiles: ProfileStore,
    keys: DeviceKeyStore,
    protector: VpnSocketProtector,
    network: Network,
    onTerminated: () -> Unit,
): Boolean {
    val original = profiles.load() ?: return false
    if (original.pendingCredential == null) return false
    val opaque = profiles.loadOpaque() ?: return false
    val candidate = try { NativeProfileCodec.recoveryProfile(opaque) } finally { opaque.fill(0) }
        ?: return false
    try {
        val profile = profiles.materializeOpaque(candidate)
        val expected = Base64.getUrlDecoder().decode(profile.credential)
        try {
            val rotation = CredentialRotationCoordinator(profiles, keys, original, onTerminated) {}
            NativeWireguardRuntime(candidate, keys.handle(profile.deviceKeyId), profiles.wireguardStateDirectory(profile)).use { owner ->
                return withTimeoutOrNull(3_000) {
                    val factory = NoiseRelayTransport.factory(
                        protector, protector, keys, rotation, owner, network, emptyList(), recoveryOnly = true,
                    )
                    for (endpoint in profile.relays.flatMap { it.endpoints }) {
                        val connection = try { factory.connect(endpoint, profile) }
                        catch (_: TimeoutCancellationException) {
                            // A carrier's shorter deadline is a failed attempt, not cancellation
                            // of this startup. Only propagate cancellation of our own caller.
                            currentCoroutineContext().ensureActive()
                            rotation.assertMeshActive()
                            continue
                        }
                        catch (cancelled: CancellationException) { throw cancelled }
                        catch (_: Exception) { rotation.assertMeshActive(); continue }
                        connection.use {
                            while (true) {
                                val verified = owner.confirmedCredential()
                                if (verified != null) {
                                    try {
                                        require(verified.contentEquals(expected)) { "recovery credential changed" }
                                        rotation.assertMeshActive()
                                        rotation.commitActivated(verified)
                                        return@withTimeoutOrNull true
                                    } finally {
                                        verified.fill(0)
                                    }
                                }
                                delay(20)
                            }
                        }
                    }
                    false
                } ?: false
            }
        } finally {
            expected.fill(0)
        }
    } finally {
        candidate.fill(0)
    }
}
