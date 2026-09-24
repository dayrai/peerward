package io.github.peerward.peerward

import android.util.AtomicFile
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.peerward.peerward.crypto.DeviceKeyStore
import io.github.peerward.peerward.crypto.DeviceKeyUnavailable
import io.github.peerward.peerward.join.JoinBundle
import io.github.peerward.peerward.join.PendingEnrollmentStore
import io.github.peerward.peerward.profile.PeerProfile
import io.github.peerward.peerward.profile.ProfileStore
import io.github.peerward.peerward.profile.RelayProfileTarget
import io.github.peerward.peerward.vpn.CredentialRotationCoordinator
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.net.URLEncoder
import java.nio.ByteBuffer
import java.io.File
import java.io.RandomAccessFile
import java.security.KeyStore
import java.time.Instant
import java.util.Base64
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class JoinStorageInstrumentedTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val keyId = "instrumented_device"

    @After
    fun cleanup() {
        runCatching { DeviceKeyStore(context).delete(keyId) }
        ProfileStore(context).clear()
    }

    @Test
    fun joinLinkKeysAndEncryptedProfileRemainPrivate() {
        val json = JSONObject()
            .put("claim_url", "https://control.example/api/v1/join/token/claim")
            .put("root_fingerprint", "42".repeat(32))
            .put("expires_at", Instant.now().plusSeconds(600).epochSecond)
            .put("nonce", Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(24) { it.toByte() }))
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(json.toString().toByteArray())
        val bundle = JoinBundle.parse("peerward://join?bundle=${URLEncoder.encode(encoded, "UTF-8")}")
        assertEquals("control.example", bundle.claimUrl.host)

        val publicKeys = DeviceKeyStore(context).create(keyId)
        assertNotNull(publicKeys.noiseX25519)

        val secretCredential = "credential-that-must-be-encrypted"
        val profile = PeerProfile(
            profileId = "profile",
            deviceKeyId = keyId,
            meshId = UUID.randomUUID().toString(),
            peerId = UUID.randomUUID().toString(),
            meshName = "Test mesh",
            address = "10.2.3.3/32",
            dnsSuffix = "test.peerward",
            routes = listOf("10.2.3.0/24"),
            dnsServers = listOf("10.2.3.1"),
            mtu = 1380,
            credential = secretCredential,
            localWireguardPublic = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKeys.wireguardX25519),
            relays = listOf(
                RelayProfileTarget("relay", listOf("tcp://relay.example:443"), ""),
            ),
        )
        ProfileStore(context).save(profile)
        assertEquals(profile, ProfileStore(context).load())
        val proxied = profile.copy(relayHttpConnectProxy = "tcp://proxy.example:3128")
        ProfileStore(context).save(proxied)
        assertEquals(proxied, ProfileStore(context).load())
        ProfileStore(context).save(profile)
        val diskValues = context.getSharedPreferences("peerward.profiles.encrypted", 0).all.values
        assertFalse(diskValues.any { it.toString().contains(secretCredential) })
    }

    @Test
    fun wrappedFallbackPersistsAcrossRestartRejectsTamperAndDeletes() {
        val firstStore = DeviceKeyStore(context, forceWrapped = true)
        val first = firstStore.create(keyId)
        val wrappingAlias = firstStore.handle(keyId).keyAlias
        val remote = NativeTestKeys.publicFromPrivate(ByteArray(32) { (it + 1).toByte() })
        val shared = firstStore.agree(keyId, remote)
        assertEquals(32, shared.size)

        val restarted = DeviceKeyStore(context, forceWrapped = true)
        val restored = restarted.create(keyId)
        assertArrayEquals(first.noiseX25519, restored.noiseX25519)
        assertArrayEquals(shared, restarted.agree(keyId, remote))

        val preferences = context.getSharedPreferences(DeviceKeyStore.KEY_PREFERENCES, 0)
        val recordKey = DeviceKeyStore.recordKeyForTest(keyId)
        val record = JSONObject(preferences.getString(recordKey, null)!!)
        val wrapped = Base64.getUrlDecoder().decode(record.getString("wrapped_material"))
        wrapped[wrapped.lastIndex] = (wrapped.last().toInt() xor 0x01).toByte()
        record.put("wrapped_material", Base64.getUrlEncoder().withoutPadding().encodeToString(wrapped))
        assertTrue(preferences.edit().putString(recordKey, record.toString()).commit())
        try {
            restarted.agree(keyId, remote)
            fail("tampered wrapped key was accepted")
        } catch (_: DeviceKeyUnavailable) {
            // AES-GCM authentication fails closed.
        }

        restarted.delete(keyId)
        assertFalse(restarted.exists(keyId))
        assertFalse(preferences.contains(recordKey))
        val androidKeyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(androidKeyStore.containsAlias(wrappingAlias))

        val pending = File(context.noBackupFilesDir, "pending-enrollment.v4.aesgcm")
        try {
            RandomAccessFile(pending, "rw").use { it.setLength(32 * 1024L + 29) }
            assertThrows(IllegalArgumentException::class.java) {
                PendingEnrollmentStore(context).load()
            }
        } finally {
            pending.delete()
        }
    }

    @Test
    fun profilePlaintextIsClearedWhenAtomicWriteFails() {
        val blocker = File(context.noBackupFilesDir, "profile-write-blocker")
        blocker.deleteRecursively()
        assertTrue(blocker.createNewFile())
        val plaintext = "credential-that-must-not-survive-write-failure".toByteArray()
        try {
            assertThrows(Exception::class.java) {
                ProfileStore(context).archiveOpaque(
                    AtomicFile(File(blocker, "unwritable-profile.aesgcm")),
                    plaintext,
                )
            }
            assertTrue(plaintext.all { it == 0.toByte() })
        } finally {
            blocker.delete()
        }
    }

    @Test
    fun credentialRotationRecoversPendingKeyAndDeletesOverlapOnlyAfterAuthentication() {
        val keys = DeviceKeyStore(context, forceWrapped = true)
        val currentKeys = keys.create(keyId)
        val meshId = UUID.randomUUID()
        val peerId = UUID.randomUUID()
        val profile = PeerProfile(
            profileId = "rotation-profile",
            deviceKeyId = keyId,
            meshId = meshId.toString(),
            peerId = peerId.toString(),
            meshName = "Rotation mesh",
            address = "10.1.2.3/32",
            dnsSuffix = "rotation.peerward",
            credential = "current",
            relays = listOf(
                RelayProfileTarget("relay", listOf("tcp://relay.example:443"), ""),
            ),
            routes = listOf("10.1.2.0/24"),
            dnsServers = listOf("10.1.2.1"),
            localIdentityPublic = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(currentKeys.identityEd25519),
            localNoisePublic = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(currentKeys.noiseX25519),
            localWireguardPublic = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(currentKeys.wireguardX25519),
        )
        val profiles = ProfileStore(context).also { it.save(profile) }
        val first = CredentialRotationCoordinator(profiles, keys, profile) {}
        val material = first.pendingMaterial()
        val pending = requireNotNull(profiles.load())
        val pendingId = requireNotNull(pending.pendingDeviceKeyId)

        val restarted = CredentialRotationCoordinator(profiles, keys, pending) {}
        assertArrayEquals(material.requestId, restarted.pendingMaterial().requestId)
        assertArrayEquals(material.identityPublicKey, restarted.pendingMaterial().identityPublicKey)
        assertArrayEquals(material.sessionPublicKey, restarted.pendingMaterial().sessionPublicKey)
        val replacement = ByteArray(225).apply {
            this[0] = 1
            uuidBytes(meshId).copyInto(this, 1)
            uuidBytes(peerId).copyInto(this, 17)
            material.identityPublicKey.copyInto(this, 33)
            material.sessionPublicKey.copyInto(this, 65)
            material.wireguardPublicKey.copyInto(this, 97)
            uuidBytes(UUID.randomUUID()).copyInto(this, 129)
            ByteBuffer.wrap(this, 145, 16).putLong(1).putLong(2)
        }
        restarted.commitActivated(replacement)
        val rotated = requireNotNull(profiles.load())
        assertEquals(keyId, rotated.previousDeviceKeyId)
        assertTrue(keys.exists(keyId))
        assertTrue(keys.exists(pendingId))

        restarted.authenticated(rotated)
        assertFalse(keys.exists(keyId))
        assertTrue(keys.exists(pendingId))
        assertNull(profiles.load()?.previousDeviceKeyId)
        keys.delete(pendingId)
    }

    private fun uuidBytes(value: UUID): ByteArray = ByteBuffer.allocate(16)
        .putLong(value.mostSignificantBits)
        .putLong(value.leastSignificantBits)
        .array()
}
