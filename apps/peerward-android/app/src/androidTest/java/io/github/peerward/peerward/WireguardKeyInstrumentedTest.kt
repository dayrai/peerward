package io.github.peerward.peerward

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.peerward.peerward.crypto.DeviceKeyStore
import io.github.peerward.peerward.crypto.NativeKeyAgreement
import io.github.peerward.peerward.nativecore.PeerwardInvalidInputException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import javax.crypto.AEADBadTagException

/** Uses an isolated random key id; never edits or clears the user's profile. */
@RunWith(AndroidJUnit4::class)
class WireguardKeyInstrumentedTest {
    @Test fun independentDataKeySurvivesKeystoreReloadAndRejectsAadSubstitution() {
        val rejectedSeed = ByteArray(32) { 0x53 }
        assertThrows(IllegalArgumentException::class.java) {
            NativeKeyAgreement.wrapIdentityGenerated("invalid-alias", ByteArray(32), rejectedSeed)
        }
        assertArrayEquals("rejected identity seed was not cleared", ByteArray(32), rejectedSeed)
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val keys = DeviceKeyStore(context, forceWrapped = true)
        val id = "wg_test_${UUID.randomUUID()}"
        val concurrentId = "wg_test_${UUID.randomUUID()}"
        try {
            val first = keys.create(id)
            val restored = DeviceKeyStore(context, forceWrapped = true).create(id)
            assertArrayEquals(first.wireguardX25519, restored.wireguardX25519)
            assertFalse(first.noiseX25519.contentEquals(first.wireguardX25519))
            val key = keys.handle(id)
            val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val aes = store.getEntry(key.wireguardKeyAlias, null) as KeyStore.SecretKeyEntry
            assertNull(aes.secretKey.encoded)
            // A valid unwrap reaches Rust and is rejected only for the intentionally empty profile.
            assertThrows(PeerwardInvalidInputException::class.java) {
                NativeKeyAgreement.installWireguard(key.wireguardKeyAlias, key.wireguardX25519,
                    key.wrappedWireguardMaterial, 0, ByteArray(0), ByteArray(0))
            }
            assertThrows(AEADBadTagException::class.java) {
                NativeKeyAgreement.installWireguard(key.wireguardKeyAlias, key.noiseX25519,
                    key.wrappedWireguardMaterial, 0, ByteArray(0), ByteArray(0))
            }

            val executor = Executors.newFixedThreadPool(8)
            try {
                val start = CountDownLatch(1)
                val results = List(8) {
                    executor.submit<io.github.peerward.peerward.crypto.PublicDeviceKeys> {
                        start.await()
                        DeviceKeyStore(context, forceWrapped = true).create(concurrentId)
                    }
                }
                start.countDown()
                val created = results.map { it.get() }
                created.drop(1).forEach { candidate ->
                    assertArrayEquals(created.first().identityEd25519, candidate.identityEd25519)
                    assertArrayEquals(created.first().noiseX25519, candidate.noiseX25519)
                    assertArrayEquals(created.first().wireguardX25519, candidate.wireguardX25519)
                }
            } finally {
                executor.shutdownNow()
            }
        } finally {
            keys.delete(id)
            runCatching { keys.delete(concurrentId) }
        }
    }
}
