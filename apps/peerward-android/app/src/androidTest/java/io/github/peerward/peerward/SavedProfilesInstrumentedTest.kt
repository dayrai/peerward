package io.github.peerward.peerward

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.peerward.peerward.crypto.DeviceKeyStore
import io.github.peerward.peerward.profile.PeerProfile
import io.github.peerward.peerward.profile.ProfileCatalog
import io.github.peerward.peerward.profile.ProfileStore
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.util.Base64
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class SavedProfilesInstrumentedTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val profiles = ProfileStore(context)
    private val catalog = ProfileCatalog(context)
    private val keys = DeviceKeyStore(context)
    private val created = mutableListOf<PeerProfile>()

    private fun create(name: String): PeerProfile {
        val key = "saved-${UUID.randomUUID()}"
        val public = keys.create(key)
        return PeerProfile(
            profileId = name, deviceKeyId = key, meshId = UUID.randomUUID().toString(),
            peerId = UUID.randomUUID().toString(), meshName = name, address = "10.8.0.2/32",
            dnsSuffix = "example.peerward", credential = "private-credential-$name", routes = listOf("10.8.0.0/24"),
            dnsServers = listOf("10.8.0.1"),
            relays = listOf(io.github.peerward.peerward.profile.RelayProfileTarget("relay", listOf("tcp://relay.example:443"), "")),
            localWireguardPublic = Base64.getUrlEncoder().withoutPadding().encodeToString(public.wireguardX25519),
        ).also(created::add)
    }

    @After fun cleanup() {
        created.forEach { catalog.deleteArchivedCopy(it.peerId); keys.delete(it.deviceKeyId) }
        profiles.clear()
    }

    @Test fun savedNetworksPreserveLatestCredentialKeysAndTrustHistoryAcrossSwitches() {
        val first = create("Home")
        val second = create("Office")
        profiles.save(first)
        val history = File(profiles.wireguardStateDirectory(first).apply { mkdirs() }, "catalog-test-history")
        history.writeText("persistent anti-rollback marker")
        catalog.deactivate()
        assertNull(profiles.load())
        profiles.save(second)
        catalog.select(first.peerId)
        assertEquals(first, profiles.load())
        val rotated = first.copy(credential = "newer-committed-credential")
        profiles.save(rotated)
        catalog.select(second.peerId)
        ProfileCatalog(context).select(first.peerId)
        assertEquals(rotated, profiles.load())
        assertEquals("persistent anti-rollback marker", history.readText())
        assertTrue(keys.exists(first.deviceKeyId))
        assertTrue(keys.exists(second.deviceKeyId))
        assertEquals(2, catalog.list().length())
        val stored = File(context.noBackupFilesDir, "saved-profiles-v4").listFiles()!!
        assertTrue(stored.all { !it.readBytes().toString(Charsets.ISO_8859_1).contains("credential") })
        profiles.clear() // Removes only first; shared envelope key must survive for second.
        catalog.select(second.peerId)
        assertEquals(second, profiles.load())
        history.delete()
    }

    @Test fun missingKeysAndTerminatedOrTamperedArchivesCannotReplaceTheActiveSelection() {
        val first = create("Home")
        val second = create("Office")
        profiles.save(first)
        catalog.deactivate()
        profiles.save(second)
        keys.delete(first.deviceKeyId)
        assertThrows(IllegalStateException::class.java) { catalog.select(first.peerId) }
        assertEquals(second, profiles.load())
        // This storage test supplies an existing terminal marker. Cryptographic
        // terminal-record verification is covered by the Rust protocol tests.
        File(context.noBackupFilesDir, "mesh-terminated-${first.meshId}").writeBytes(ByteArray(228))
        assertThrows(IllegalStateException::class.java) { catalog.select(first.peerId) }
        val file = File(context.noBackupFilesDir, "saved-profiles-v4/${first.peerId}.aesgcm")
        file.writeBytes(file.readBytes().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() })
        assertThrows(Exception::class.java) { catalog.select(first.peerId) }
        assertEquals(second, profiles.load())
        assertFalse(catalog.list().let { array -> (0 until array.length()).map(array::getJSONObject)
            .single { it.getString("peer_id") == first.peerId }.getBoolean("available") })
        assertThrows(IllegalArgumentException::class.java) { catalog.select("../../outside") }
        assertEquals(second, profiles.load())
        assertThrows(IllegalStateException::class.java) { catalog.forget(second.peerId) }
        catalog.forget(first.peerId)
        assertEquals(1, catalog.list().length())
        assertEquals(second, profiles.load())
        assertTrue(keys.exists(second.deviceKeyId))
        assertTrue(File(context.noBackupFilesDir, "saved-profiles-v4").listFiles().orEmpty().none { it.name.startsWith(first.peerId) })
    }
}
