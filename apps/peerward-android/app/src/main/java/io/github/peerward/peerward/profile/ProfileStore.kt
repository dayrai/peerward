package io.github.peerward.peerward.profile

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import io.github.peerward.peerward.nativecore.NativeProfileCodec
import io.github.peerward.peerward.storage.readBounded
import org.json.JSONArray
import org.json.JSONObject
import java.io.DataInputStream
import java.io.File
import java.nio.ByteBuffer
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class RelayProfileTarget(
    val relayId: String,
    val endpoints: List<String>,
    val noisePublicKey: String,
)

data class PeerProfile(
    val profileId: String,
    val deviceKeyId: String,
    val meshId: String,
    val peerId: String,
    val meshName: String,
    val address: String,
    val dnsSuffix: String,
    val credential: String,
    val secondaryAddress: String? = null,
    val relays: List<RelayProfileTarget> = emptyList(),
    val relayCaPem: String? = null,
    val relayHttpConnectProxy: String? = null,
    val stunServers: List<String> = emptyList(),
    val p2pEndpoints: List<String> = emptyList(),
    val natMapping: String = "auto",
    val symmetricNatPrediction: Boolean = false,
    val routes: List<String> = emptyList(),
    val dnsServers: List<String> = emptyList(),
    val mtu: Int = 1280,
    val localIdentityPublic: String = "",
    val localNoisePublic: String = "",
    val localWireguardPublic: String = "",
    val rootPublicKey: String = "",
    val authorityCertificates: List<String> = emptyList(),
    val authorityRevision: Long = 0,
    val distributionPublicKey: String = "",
    val servicePublicKey: String = "",
    val auditPublicKey: String = "",
    val distributionCertificate: String = "",
    val previousDeviceKeyId: String? = null,
    val pendingRotationId: String? = null,
    val pendingDeviceKeyId: String? = null,
    val pendingIdentityPublic: String? = null,
    val pendingNoisePublic: String? = null,
    val pendingWireguardPublic: String? = null,
    val pendingCredential: String? = null,
) {
    fun relayTargets(): List<RelayProfileTarget> = relays
}

class LegacyProfileUnsupportedException : IllegalStateException("legacy_profile_unsupported")

class ProfileStore(context: Context) {
    private val appContext = context.applicationContext
    private val profileFile = AtomicFile(File(appContext.noBackupFilesDir, PROFILE_FILE))
    private val legacyFile = File(
        appContext.applicationInfo.dataDir,
        "shared_prefs/$LEGACY_PREFERENCES.xml",
    )
    private val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    /** Trust history survives rotations/removal and is excluded from Android backup. */
    fun wireguardStateDirectory(profile: PeerProfile): File {
        val mesh = java.util.UUID.fromString(profile.meshId).toString()
        val peer = java.util.UUID.fromString(profile.peerId).toString()
        return File(appContext.noBackupFilesDir.canonicalFile, "wireguard/$mesh/$peer")
    }

    fun isMeshTerminated(meshId: String): Boolean = terminationFile(meshId).baseFile.exists()

    private fun terminationFile(meshId: String): AtomicFile {
        val canonical = java.util.UUID.fromString(meshId).toString()
        return AtomicFile(File(appContext.noBackupFilesDir, "mesh-terminated-$canonical"))
    }

    /** Called only with a Rust-verified, root-anchored terminal record. */
    fun markMeshTerminated(meshId: String, signedRecord: ByteArray) {
        require(signedRecord.size == 228)
        val file = terminationFile(meshId)
        val output = file.startWrite()
        try { output.write(signedRecord); file.finishWrite(output) }
        catch (error: Exception) { file.failWrite(output); throw error }
    }

    fun save(profile: PeerProfile) {
        check(!isMeshTerminated(profile.meshId)) { "mesh_deleted" }
        val json = JSONObject()
            .put("profile_id", profile.profileId)
            .put("device_key_id", profile.deviceKeyId)
            .put("mesh_id", profile.meshId)
            .put("peer_id", profile.peerId)
            .put("mesh_name", profile.meshName)
            .put("address", profile.address)
            .put("secondary_address", profile.secondaryAddress ?: JSONObject.NULL)
            .put("dns_suffix", profile.dnsSuffix)
            .put("credential", profile.credential)
            .put("config_version", PROFILE_SCHEMA)
            .put("relays", JSONArray(profile.relays.map { relay ->
                JSONObject()
                    .put("relay_id", relay.relayId)
                    .put("endpoints", JSONArray(relay.endpoints))
                    .put("noise_public_key", relay.noisePublicKey)
            }))
            .put("relay_transport", JSONObject().put("ca_pem", profile.relayCaPem)
                .put("http_connect_proxy", profile.relayHttpConnectProxy))
            .put("stun_servers", JSONArray(profile.stunServers))
            .put("p2p_endpoints", JSONArray(profile.p2pEndpoints))
            .put("nat_mapping", profile.natMapping)
            .put("symmetric_nat_prediction", profile.symmetricNatPrediction)
            .put("routes", JSONArray(profile.routes))
            .put("dns_servers", JSONArray(profile.dnsServers))
            .put("mtu", profile.mtu)
            .put("local_identity_public", profile.localIdentityPublic)
            .put("local_noise_public", profile.localNoisePublic)
            .put("local_wireguard_public", profile.localWireguardPublic)
            .put("root_public_key", profile.rootPublicKey)
            .put("authority_certificates", JSONArray(profile.authorityCertificates))
            .put("authority_revision", profile.authorityRevision)
            .put("distribution_public_key", profile.distributionPublicKey)
            .put("service_public_key", profile.servicePublicKey)
            .put("audit_public_key", profile.auditPublicKey)
            .put("distribution_certificate", profile.distributionCertificate)
        profile.previousDeviceKeyId?.let { json.put("previous_device_key_id", it) }
        profile.pendingRotationId?.let { json.put("pending_rotation_id", it) }
        profile.pendingDeviceKeyId?.let { json.put("pending_device_key_id", it) }
        profile.pendingIdentityPublic?.let { json.put("pending_identity_public", it) }
        profile.pendingNoisePublic?.let { json.put("pending_noise_public", it) }
        profile.pendingWireguardPublic?.let { json.put("pending_wireguard_public", it) }
        profile.pendingCredential?.let { json.put("pending_credential", it) }
        val materialized = json.toString().toByteArray(Charsets.UTF_8)
        try {
            writeEncrypted(NativeProfileCodec.encode(materialized))
        } finally {
            materialized.fill(0)
        }
    }

    fun load(): PeerProfile? = loadForRemoval()?.takeUnless { isMeshTerminated(it.meshId) }

    /** Cleanup can still locate Keystore aliases after a durable terminal marker. */
    fun loadForRemoval(): PeerProfile? {
        val opaque = loadOpaque() ?: return null
        return try {
            materializeOpaque(opaque)
        } finally {
            opaque.fill(0)
        }
    }

    /** Materializes a temporary recovery candidate without replacing the stored active profile. */
    fun materializeOpaque(opaque: ByteArray): PeerProfile {
        val materialized = NativeProfileCodec.decode(opaque)
        val json = try {
            JSONObject(materialized.toString(Charsets.UTF_8))
        } finally {
            materialized.fill(0)
        }
        if (!json.has("config_version")) throw LegacyProfileUnsupportedException()
        if (json.getInt("config_version") != PROFILE_SCHEMA) throw LegacyProfileUnsupportedException()
        val unknown = json.keys().asSequence().firstOrNull { it !in PROFILE_FIELDS }
        require(unknown == null) { "unknown profile field: $unknown" }
        val values = json.getJSONArray("relays")
        val relays = List(values.length()) { index ->
            val relay = values.getJSONObject(index)
            val endpoints = relay.getJSONArray("endpoints")
            RelayProfileTarget(
                relayId = relay.getString("relay_id"),
                endpoints = List(endpoints.length()) { endpoint -> endpoints.getString(endpoint) },
                noisePublicKey = relay.getString("noise_public_key"),
            )
        }
        val authorities = json.optJSONArray("authority_certificates")
        val stunServers = json.optJSONArray("stun_servers")
        val p2pEndpoints = json.optJSONArray("p2p_endpoints")
        val routes = json.getJSONArray("routes")
        val dnsServers = json.getJSONArray("dns_servers")
        return PeerProfile(
            profileId = json.getString("profile_id"),
            deviceKeyId = json.getString("device_key_id"),
            meshId = json.getString("mesh_id"),
            peerId = json.getString("peer_id"),
            meshName = json.getString("mesh_name"),
            address = json.getString("address"),
            secondaryAddress = if (json.isNull("secondary_address")) null else json.getString("secondary_address"),
            dnsSuffix = json.getString("dns_suffix"),
            credential = json.getString("credential"),
            relays = relays,
            relayCaPem = json.optJSONObject("relay_transport")?.optionalString("ca_pem"),
            relayHttpConnectProxy = json.optJSONObject("relay_transport")?.optionalString("http_connect_proxy"),
            stunServers = stunServers?.let { List(it.length()) { index -> it.getString(index) } }.orEmpty(),
            p2pEndpoints = p2pEndpoints?.let {
                List(it.length()) { index -> it.getString(index) }
            }.orEmpty(),
            natMapping = json.optString("nat_mapping", "auto").also {
                require(it == "auto" || it == "off") { "invalid NAT mapping mode" }
            },
            symmetricNatPrediction = json.optBoolean("symmetric_nat_prediction", false),
            routes = List(routes.length()) { routes.getString(it) },
            dnsServers = List(dnsServers.length()) { dnsServers.getString(it) },
            mtu = json.getInt("mtu"),
            localIdentityPublic = json.getString("local_identity_public"),
            localNoisePublic = json.optString("local_noise_public"),
            localWireguardPublic = json.getString("local_wireguard_public"),
            rootPublicKey = json.optString("root_public_key"),
            authorityCertificates = authorities?.let { List(it.length()) { index -> it.getString(index) } }.orEmpty(),
            authorityRevision = json.optLong("authority_revision", 0),
            distributionPublicKey = json.optString("distribution_public_key"),
            servicePublicKey = json.optString("service_public_key"),
            auditPublicKey = json.optString("audit_public_key"),
            distributionCertificate = json.optString("distribution_certificate"),
            previousDeviceKeyId = json.optionalString("previous_device_key_id"),
            pendingRotationId = json.optionalString("pending_rotation_id"),
            pendingDeviceKeyId = json.optionalString("pending_device_key_id"),
            pendingIdentityPublic = json.optionalString("pending_identity_public"),
            pendingNoisePublic = json.optionalString("pending_noise_public"),
            pendingWireguardPublic = json.optionalString("pending_wireguard_public"),
            pendingCredential = json.optionalString("pending_credential"),
        )
    }

    /** Returns the Rust-versioned profile without materializing its fields in Kotlin. */
    fun loadOpaque(): ByteArray? {
        if (!profileFile.baseFile.exists()) {
            if (legacyFile.exists()) throw LegacyProfileUnsupportedException()
            return null
        }
        val opaque = readEncrypted()
        try {
            val materialized = NativeProfileCodec.decode(opaque)
            materialized.fill(0)
            return opaque
        } catch (error: Throwable) {
            opaque.fill(0)
            throw error
        }
    }

    /** Atomically persists one Rust-produced opaque profile; the input is consumed. */
    fun replaceOpaque(opaque: ByteArray) {
        try {
            val materialized = NativeProfileCodec.decode(opaque)
            materialized.fill(0)
            writeEncrypted(opaque)
        } finally {
            opaque.fill(0)
        }
    }

    fun clear() {
        // Delete only this selection's archive. Other saved networks share the
        // envelope key, but retain independent device keys and trust history.
        runCatching { loadForRemoval() }.getOrNull()?.let {
            ProfileCatalog(appContext).deleteArchivedCopy(it.peerId)
        }
        profileFile.delete()
        appContext.deleteSharedPreferences(LEGACY_PREFERENCES)
        if (!ProfileCatalog(appContext).hasArchives()) runCatching { keyStore.deleteEntry(PROFILE_KEY_ALIAS) }
        runCatching { keyStore.deleteEntry(LEGACY_MASTER_KEY_ALIAS) }
        check(!profileFile.baseFile.exists() && !legacyFile.exists()) { "profile removal failed" }
    }

    internal fun detachActive() {
        profileFile.delete()
        check(!profileFile.baseFile.exists()) { "profile_detach_failed" }
    }

    internal fun archiveOpaque(file: AtomicFile, opaque: ByteArray) = writeEncrypted(opaque, file)
    internal fun readArchive(file: AtomicFile): ByteArray = readEncrypted(file)

    private fun writeEncrypted(plaintext: ByteArray, destination: AtomicFile = profileFile) {
        var ciphertext = ByteArray(0)
        var iv = ByteArray(0)
        var encoded = ByteArray(0)
        try {
            require(plaintext.size <= MAX_PROFILE_BYTES) { "profile exceeds encrypted blob bound" }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, profileKey())
            cipher.updateAAD(PROFILE_AAD)
            ciphertext = cipher.doFinal(plaintext)
            iv = cipher.iv
            encoded = ByteArray(PROFILE_MAGIC.size + 1 + 1 + iv.size + 4 + ciphertext.size)
            ByteBuffer.wrap(encoded)
                .put(PROFILE_MAGIC)
                .put(PROFILE_FORMAT.toByte())
                .put(iv.size.toByte())
                .put(iv)
                .putInt(ciphertext.size)
                .put(ciphertext)
            val output = destination.startWrite()
            try {
                output.write(encoded)
                output.fd.sync()
                destination.finishWrite(output)
            } catch (error: Throwable) {
                destination.failWrite(output)
                throw error
            }
        } finally {
            plaintext.fill(0)
            ciphertext.fill(0)
            iv.fill(0)
            encoded.fill(0)
        }
    }

    private fun readEncrypted(source: AtomicFile = profileFile): ByteArray {
        val encoded = source.readBounded(
            MIN_ENVELOPE_BYTES,
            MAX_ENVELOPE_BYTES,
            "encrypted profile",
        )
        var magic = ByteArray(0)
        var iv = ByteArray(0)
        var ciphertext = ByteArray(0)
        return try {
            val input = DataInputStream(encoded.inputStream())
            magic = ByteArray(PROFILE_MAGIC.size).also(input::readFully)
            require(magic.contentEquals(PROFILE_MAGIC)) { "invalid encrypted profile magic" }
            if (input.readUnsignedByte() != PROFILE_FORMAT) throw LegacyProfileUnsupportedException()
            val ivSize = input.readUnsignedByte()
            require(ivSize == GCM_IV_BYTES) { "invalid encrypted profile IV" }
            iv = ByteArray(ivSize).also(input::readFully)
            val ciphertextSize = input.readInt()
            require(ciphertextSize in GCM_TAG_BYTES..MAX_PROFILE_BYTES + GCM_TAG_BYTES) {
                "invalid encrypted profile payload length"
            }
            ciphertext = ByteArray(ciphertextSize).also(input::readFully)
            require(input.read() == -1) { "trailing encrypted profile data" }
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, profileKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
                updateAAD(PROFILE_AAD)
                doFinal(ciphertext)
            }
        } finally {
            encoded.fill(0)
            magic.fill(0)
            ciphertext.fill(0)
            iv.fill(0)
        }
    }

    private fun profileKey(): SecretKey {
        (keyStore.getKey(PROFILE_KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE).run {
            init(
                KeyGenParameterSpec.Builder(
                    PROFILE_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .setRandomizedEncryptionRequired(true)
                    .build(),
            )
            generateKey()
        }
    }

    companion object {
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val PROFILE_FILE = "peerward-profile.v1.aesgcm"
        private const val PROFILE_KEY_ALIAS = "peerward.profile.v1.aesgcm"
        private const val LEGACY_PREFERENCES = "peerward.profiles.encrypted"
        private const val LEGACY_MASTER_KEY_ALIAS = "_androidx_security_master_key_"
        private const val PROFILE_FORMAT = 4
        private const val PROFILE_SCHEMA = 4
        private const val GCM_IV_BYTES = 12
        private const val GCM_TAG_BYTES = 16
        private const val GCM_TAG_BITS = 128
        // Rust's bounded opaque envelope adds 9 bytes to its 1 MiB JSON payload.
        private const val MAX_PROFILE_BYTES = 1024 * 1024 + 9
        private const val MIN_ENVELOPE_BYTES = 4 + 1 + 1 + GCM_IV_BYTES + 4 + GCM_TAG_BYTES
        private const val MAX_ENVELOPE_BYTES = MIN_ENVELOPE_BYTES + MAX_PROFILE_BYTES
        private val PROFILE_MAGIC = byteArrayOf('P'.code.toByte(), 'W'.code.toByte(), 'P'.code.toByte(), 'F'.code.toByte())
        private val PROFILE_AAD = "peerward-profile-v4".toByteArray(Charsets.US_ASCII)
        private val PROFILE_FIELDS = setOf(
            "config_version", "profile_id", "device_key_id", "mesh_id", "peer_id",
            "mesh_name", "address", "secondary_address", "dns_suffix", "credential", "relays", "relay_transport", "stun_servers",
            "p2p_endpoints", "routes", "dns_servers", "mtu", "local_identity_public", "local_noise_public", "local_wireguard_public",
            "nat_mapping", "symmetric_nat_prediction",
            "root_public_key", "authority_certificates", "authority_revision",
            "distribution_public_key", "service_public_key", "audit_public_key", "distribution_certificate",
            "previous_device_key_id", "pending_rotation_id", "pending_device_key_id",
            "pending_identity_public", "pending_noise_public", "pending_wireguard_public", "pending_credential",
        )
    }
}

private fun JSONObject.optionalString(name: String): String? =
    if (!has(name) || isNull(name)) null else getString(name).takeIf(String::isNotEmpty)
