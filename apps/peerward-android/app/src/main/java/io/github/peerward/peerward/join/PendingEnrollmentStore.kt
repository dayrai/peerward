package io.github.peerward.peerward.join

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import io.github.peerward.peerward.crypto.DeviceKeyStore
import io.github.peerward.peerward.storage.readBounded
import org.json.JSONObject
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

data class PendingEnrollment(
    val keyId: String,
    val invitationDigest: String? = null,
    val payload: ByteArray? = null,
)

/** Token-free exact claims survive network loss and process death. Keys stay in
 * DeviceKeyStore; this authenticated file is excluded from Android backups. */
class PendingEnrollmentStore(context: Context) {
    private val context = context.applicationContext
    private val file = AtomicFile(File(this.context.noBackupFilesDir, "pending-enrollment.v4.aesgcm"))

    fun load(): PendingEnrollment? {
        if (!file.baseFile.exists()) return null
        val bytes = file.readBounded(29, MAX_BYTES + ENVELOPE_OVERHEAD, "pending enrollment")
        val plaintext = try {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
                updateAAD(AAD)
                doFinal(bytes, 12, bytes.size - 12)
            }
        } finally { bytes.fill(0) }
        return try {
            val json = JSONObject(plaintext.toString(Charsets.UTF_8))
            require(json.getInt("version") == 4)
            val digest = if (json.isNull("invitation_digest")) null else json.getString("invitation_digest")
            val payload = if (json.isNull("payload")) null else Base64.getDecoder().decode(json.getString("payload"))
            require((digest == null) == (payload == null))
            PendingEnrollment(json.getString("key_id"), digest, payload)
        } finally { plaintext.fill(0) }
    }

    fun prepare(): PendingEnrollment = load() ?: PendingEnrollment(
        "profile-${UUID.randomUUID().toString().replace("-", "")}",
    ).also { pending ->
        DeviceKeyStore(context).create(pending.keyId)
        save(pending)
    }

    fun save(pending: PendingEnrollment) {
        val plaintext = JSONObject().put("version", 4).put("key_id", pending.keyId)
            .put("invitation_digest", pending.invitationDigest ?: JSONObject.NULL)
            .put("payload", pending.payload?.let { Base64.getEncoder().encodeToString(it) } ?: JSONObject.NULL)
            .toString().toByteArray(Charsets.UTF_8)
        require(plaintext.size <= MAX_BYTES)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(AAD)
        val ciphertext = try { cipher.doFinal(plaintext) } finally { plaintext.fill(0) }
        val output = file.startWrite()
        try {
            output.write(cipher.iv); output.write(ciphertext); output.fd.sync(); file.finishWrite(output)
        } catch (error: Throwable) { file.failWrite(output); throw error }
        finally { ciphertext.fill(0) }
    }

    /** Clear only after the verified profile is durable, or explicit abandonment. */
    fun clear(deleteDeviceKeys: Boolean = false) {
        if (deleteDeviceKeys) load()?.let { DeviceKeyStore(context).delete(it.keyId) }
        file.delete()
    }

    fun fingerprint(pending: PendingEnrollment): String = digest(
        DeviceKeyStore(context).handle(pending.keyId).identityEd25519,
    )

    private fun key(): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(KEY_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(KeyGenParameterSpec.Builder(KEY_ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).setRandomizedEncryptionRequired(true).build())
            generateKey()
        }
    }

    companion object {
        private const val KEY_ALIAS = "peerward.pending-enrollment.v4"
        private const val MAX_BYTES = 32 * 1024
        private const val ENVELOPE_OVERHEAD = 28
        private val AAD = "peerward/pending-enrollment/v4".toByteArray(Charsets.US_ASCII)
        fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
            .joinToString("") { "%02x".format(it.toInt() and 255) }
    }
}
