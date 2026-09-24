package io.github.peerward.peerward.crypto

import android.content.Context
import android.annotation.SuppressLint
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.NamedParameterSpec
import java.util.Base64
import javax.crypto.KeyAgreement
import javax.crypto.KeyGenerator

class DeviceKeyUnavailable(message: String, cause: Throwable? = null) : Exception(message, cause)

data class PublicDeviceKeys(
    val identityEd25519: ByteArray,
    val noiseX25519: ByteArray,
    val wireguardX25519: ByteArray,
)

data class NoiseKeyHandle(
    val mode: Int,
    val keyAlias: String,
    val noiseX25519: ByteArray,
    val wrappedMaterial: ByteArray,
    val identityKeyAlias: String,
    val identityEd25519: ByteArray,
    val wrappedIdentityMaterial: ByteArray,
    val wireguardKeyAlias: String,
    val wireguardX25519: ByteArray,
    val wrappedWireguardMaterial: ByteArray,
)

/**
 * Owns the device Noise key without placing private material in profiles.
 *
 * AndroidKeyStore X25519 is used only after a real agreement self-test. On
 * devices where it is absent or unusable, Rust generates the X25519 scalar and
 * it is immediately AES-GCM wrapped by a non-exportable AndroidKeyStore key.
 * The app-private record contains only authenticated metadata and ciphertext.
 */
class DeviceKeyStore(
    context: Context,
    private val forceWrapped: Boolean = false,
    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) },
) {
    private val preferences = context.applicationContext.getSharedPreferences(KEY_PREFERENCES, Context.MODE_PRIVATE)

    fun create(profileId: String): PublicDeviceKeys = synchronized(KEY_LOCK) {
        validateProfileId(profileId)
        val existing = preferences.getString(recordKey(profileId), null)
        val handle = if (existing != null) {
            val restored = decode(profileId, existing)
            if (forceWrapped && restored.mode == MODE_DIRECT) {
                delete(profileId)
                createWrapped(profileId)
            } else {
                restored
            }
        } else {
            (if (forceWrapped) null else createDirect(profileId)) ?: createWrapped(profileId)
        }
        PublicDeviceKeys(
            handle.identityEd25519.copyOf(),
            handle.noiseX25519.copyOf(),
            handle.wireguardX25519.copyOf(),
        )
    }

    fun handle(profileId: String): NoiseKeyHandle {
        validateProfileId(profileId)
        val raw = preferences.getString(recordKey(profileId), null)
            ?: throw DeviceKeyUnavailable("device Noise key does not exist")
        val handle = decode(profileId, raw)
        when (handle.mode) {
            MODE_DIRECT -> if (!keyStore.containsAlias(handle.keyAlias)) {
                throw DeviceKeyUnavailable("direct device Noise key is missing")
            }
            MODE_WRAPPED -> if (!keyStore.containsAlias(handle.keyAlias)) {
                throw DeviceKeyUnavailable("device wrapping key is missing")
            }
            else -> throw DeviceKeyUnavailable("unsupported device key mode")
        }
        if (!keyStore.containsAlias(handle.identityKeyAlias)) {
            throw DeviceKeyUnavailable("device identity wrapping key is missing")
        }
        if (!keyStore.containsAlias(handle.wireguardKeyAlias)) {
            throw DeviceKeyUnavailable("device WireGuard wrapping key is missing")
        }
        return handle
    }

    /** Signs a bounded canonical protocol transcript without persisting plaintext seed bytes. */
    fun sign(profileId: String, message: ByteArray): ByteArray {
        require(message.size in 1..MAX_SIGNED_MESSAGE_BYTES) { "identity transcript is outside its bound" }
        val handle = handle(profileId)
        return runCatching {
            NativeKeyAgreement.signWrapped(
                handle.identityKeyAlias,
                handle.identityEd25519,
                handle.wrappedIdentityMaterial,
                message,
            )
        }.getOrElse { throw DeviceKeyUnavailable("device identity signing failed", it) }
    }

    /** Performs agreement without revealing the static private key. */
    fun agree(profileId: String, remoteX25519: ByteArray): ByteArray {
        require(remoteX25519.size == X25519_BYTES) { "invalid remote X25519 key" }
        val handle = handle(profileId)
        return runCatching {
            when (handle.mode) {
                MODE_DIRECT -> {
                    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) {
                        throw DeviceKeyUnavailable("direct X25519 requires Android 13 or newer")
                    }
                    NativeKeyAgreement.agree(handle.keyAlias, remoteX25519)
                }
                MODE_WRAPPED -> NativeKeyAgreement.agreeWrapped(
                    handle.keyAlias,
                    handle.noiseX25519,
                    handle.wrappedMaterial,
                    remoteX25519,
                )
                else -> error("unsupported key mode")
            }
        }.getOrElse { throw DeviceKeyUnavailable("device key agreement failed", it) }
    }

    fun exists(profileId: String): Boolean = runCatching { handle(profileId) }.isSuccess

    @SuppressLint("ApplySharedPref", "UseKtx")
    fun delete(profileId: String) = synchronized(KEY_LOCK) {
        validateProfileId(profileId)
        var failure: Throwable? = null
        listOf(
            noiseAlias(profileId),
            wrappingAlias(profileId),
            identityWrappingAlias(profileId),
            wireguardWrappingAlias(profileId),
            // Delete aliases left by pre-1.0 development builds as well.
            "peerward.$profileId.signing",
        ).forEach { alias ->
            runCatching { keyStore.deleteEntry(alias) }
                .onFailure { if (failure == null) failure = it }
        }
        val committed = preferences.edit().remove(recordKey(profileId)).commit()
        if ((!committed || preferences.contains(recordKey(profileId))) && failure == null) {
            failure = IllegalStateException("metadata commit failed")
        }
        if (failure != null) {
            throw DeviceKeyUnavailable("device key removal was incomplete", failure)
        }
    }

    private fun createDirect(profileId: String): NoiseKeyHandle? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return null
        val alias = noiseAlias(profileId)
        return runCatching {
            val existing = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            val pair = if (existing == null) {
                KeyPairGenerator.getInstance("XDH", ANDROID_KEY_STORE).run {
                    initialize(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_AGREE_KEY).build())
                    generateKeyPair()
                }
            } else {
                java.security.KeyPair(existing.certificate.publicKey, existing.privateKey)
            }
            check(pair.private.encoded == null) { "AndroidKeyStore exported a private key" }
            val public = rawX25519(pair.public.encoded)
            val probe = KeyPairGenerator.getInstance("XDH").run {
                initialize(NamedParameterSpec("X25519"))
                generateKeyPair()
            }
            val shared = KeyAgreement.getInstance("XDH").run {
                init(pair.private)
                doPhase(probe.public, true)
                generateSecret()
            }
            try {
                check(shared.size == X25519_BYTES && shared.any { it.toInt() != 0 })
            } finally {
                shared.fill(0)
            }
            val identity = createIdentity(profileId)
            val wireguard = createWireguard(profileId)
            NoiseKeyHandle(
                MODE_DIRECT,
                alias,
                public,
                ByteArray(0),
                identity.first,
                identity.second.first,
                identity.second.second,
                wireguard.first,
                wireguard.second.first,
                wireguard.second.second,
            ).also { persist(profileId, it) }
        }.onFailure {
            runCatching { keyStore.deleteEntry(alias) }
            runCatching { keyStore.deleteEntry(identityWrappingAlias(profileId)) }
            runCatching { keyStore.deleteEntry(wireguardWrappingAlias(profileId)) }
        }.getOrNull()
    }

    private fun createWrapped(profileId: String): NoiseKeyHandle {
        val alias = wrappingAlias(profileId)
        ensureWrappingKey(alias)
        val generated = NativeKeyMaterial.generateWrapped(alias)
        if (generated.size !in (X25519_BYTES + MIN_WRAPPED_BYTES)..MAX_GENERATED_BYTES) {
            generated.fill(0)
            keyStore.deleteEntry(alias)
            throw DeviceKeyUnavailable("native key generator returned malformed output")
        }
        val public = generated.copyOfRange(0, X25519_BYTES)
        val wrapped = generated.copyOfRange(X25519_BYTES, generated.size)
        generated.fill(0)
        val identity = createIdentity(profileId)
        val wireguard = createWireguard(profileId)
        return NoiseKeyHandle(
            MODE_WRAPPED,
            alias,
            public,
            wrapped,
            identity.first,
            identity.second.first,
            identity.second.second,
            wireguard.first,
            wireguard.second.first,
            wireguard.second.second,
        ).also { persist(profileId, it) }
    }

    private fun createIdentity(profileId: String): Pair<String, Pair<ByteArray, ByteArray>> {
        val alias = identityWrappingAlias(profileId)
        ensureWrappingKey(alias)
        val generated = NativeKeyMaterial.generateWrappedIdentity(alias)
        if (generated.size !in (ED25519_BYTES + MIN_WRAPPED_BYTES)..MAX_GENERATED_BYTES) {
            generated.fill(0)
            keyStore.deleteEntry(alias)
            throw DeviceKeyUnavailable("native identity generator returned malformed output")
        }
        val public = generated.copyOfRange(0, ED25519_BYTES)
        val wrapped = generated.copyOfRange(ED25519_BYTES, generated.size)
        generated.fill(0)
        return alias to (public to wrapped)
    }

    /** A fresh independent scalar; WireGuard never reuses the Noise key. */
    private fun createWireguard(profileId: String): Pair<String, Pair<ByteArray, ByteArray>> {
        val alias = wireguardWrappingAlias(profileId)
        ensureWrappingKey(alias)
        val generated = NativeKeyMaterial.generateWrapped(alias)
        try {
            require(generated.size in (X25519_BYTES + MIN_WRAPPED_BYTES)..MAX_GENERATED_BYTES) {
                "native WireGuard key generator returned malformed output"
            }
            return alias to (generated.copyOfRange(0, X25519_BYTES) to generated.copyOfRange(X25519_BYTES, generated.size))
        } finally {
            generated.fill(0)
        }
    }

    private fun ensureWrappingKey(alias: String) {
        if (keyStore.containsAlias(alias)) return
        runCatching {
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE).run {
                init(
                    KeyGenParameterSpec.Builder(
                        alias,
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
        }.getOrElse { throw DeviceKeyUnavailable("AndroidKeyStore AES-GCM is unavailable", it) }
    }

    @SuppressLint("ApplySharedPref", "UseKtx")
    private fun persist(profileId: String, handle: NoiseKeyHandle) {
        val mode = if (handle.mode == MODE_DIRECT) "direct" else "wrapped"
        val encoded = JSONObject()
            .put("schema_version", SCHEMA_VERSION)
            .put("mode", mode)
            .put("key_alias", handle.keyAlias)
            .put("noise_public_key", ENCODER.encodeToString(handle.noiseX25519))
            .put("wrapped_material", ENCODER.encodeToString(handle.wrappedMaterial))
            .put("identity_key_alias", handle.identityKeyAlias)
            .put("identity_public_key", ENCODER.encodeToString(handle.identityEd25519))
            .put("wrapped_identity_material", ENCODER.encodeToString(handle.wrappedIdentityMaterial))
            .put("wireguard_key_alias", handle.wireguardKeyAlias)
            .put("wireguard_public_key", ENCODER.encodeToString(handle.wireguardX25519))
            .put("wrapped_wireguard_material", ENCODER.encodeToString(handle.wrappedWireguardMaterial))
            .toString()
        // SharedPreferences updates its memory cache even when the disk write fails.
        val committed = preferences.edit().putString(recordKey(profileId), encoded).commit()
        if (!committed || preferences.getString(recordKey(profileId), null) != encoded) {
            val failure = DeviceKeyUnavailable("device key metadata persistence failed")
            runCatching { delete(profileId) }.onFailure(failure::addSuppressed)
            throw failure
        }
    }

    private fun decode(profileId: String, encoded: String): NoiseKeyHandle {
        return runCatching {
            val json = JSONObject(encoded)
            val fields = json.keys().asSequence().toSet()
            require(fields == RECORD_FIELDS)
            require(json.getInt("schema_version") == SCHEMA_VERSION) { "old device keys require joining again" }
            val mode = when (json.getString("mode")) {
                "direct" -> MODE_DIRECT
                "wrapped" -> MODE_WRAPPED
                else -> error("unknown key mode")
            }
            val expectedAlias = if (mode == MODE_DIRECT) noiseAlias(profileId) else wrappingAlias(profileId)
            require(json.getString("key_alias") == expectedAlias)
            val public = DECODER.decode(json.getString("noise_public_key"))
            val wrapped = DECODER.decode(json.getString("wrapped_material"))
            val identityAlias = identityWrappingAlias(profileId)
            require(json.getString("identity_key_alias") == identityAlias)
            val identityPublic = DECODER.decode(json.getString("identity_public_key"))
            val wrappedIdentity = DECODER.decode(json.getString("wrapped_identity_material"))
            val wireguardAlias = wireguardWrappingAlias(profileId)
            require(json.getString("wireguard_key_alias") == wireguardAlias)
            val wireguardPublic = DECODER.decode(json.getString("wireguard_public_key"))
            val wrappedWireguard = DECODER.decode(json.getString("wrapped_wireguard_material"))
            require(wireguardPublic.size == X25519_BYTES && !wireguardPublic.contentEquals(public))
            require(wrappedWireguard.size in MIN_WRAPPED_BYTES..MAX_GENERATED_BYTES)
            require(public.size == X25519_BYTES)
            require(identityPublic.size == ED25519_BYTES)
            require(wrappedIdentity.size in MIN_WRAPPED_BYTES..MAX_GENERATED_BYTES)
            require(
                (mode == MODE_DIRECT && wrapped.isEmpty()) ||
                    (mode == MODE_WRAPPED && wrapped.size in MIN_WRAPPED_BYTES..MAX_GENERATED_BYTES),
            )
            NoiseKeyHandle(
                mode,
                expectedAlias,
                public,
                wrapped,
                identityAlias,
                identityPublic,
                wrappedIdentity,
                wireguardAlias,
                wireguardPublic,
                wrappedWireguard,
            )
        }.getOrElse { throw DeviceKeyUnavailable("device key metadata is invalid", it) }
    }

    private fun rawX25519(subjectPublicKeyInfo: ByteArray): ByteArray {
        if (subjectPublicKeyInfo.size < X25519_BYTES) throw DeviceKeyUnavailable("invalid X25519 public key")
        return subjectPublicKeyInfo.copyOfRange(subjectPublicKeyInfo.size - X25519_BYTES, subjectPublicKeyInfo.size)
    }

    private fun validateProfileId(profileId: String) {
        require(profileId.matches(Regex("[A-Za-z0-9_-]{1,64}"))) { "invalid profile id" }
    }

    private fun recordKey(profileId: String) = "noise.$profileId"
    private fun noiseAlias(profileId: String) = "peerward.$profileId.noise"
    private fun wrappingAlias(profileId: String) = "peerward.$profileId.noise-wrap"
    private fun identityWrappingAlias(profileId: String) = "peerward.$profileId.identity-wrap"
    private fun wireguardWrappingAlias(profileId: String) = "peerward.$profileId.wireguard-wrap"

    companion object {
        internal const val KEY_PREFERENCES = "peerward.noise_keys"
        internal fun recordKeyForTest(profileId: String) = "noise.$profileId"
        const val MODE_DIRECT = 1
        const val MODE_WRAPPED = 2
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val SCHEMA_VERSION = 3
        private const val X25519_BYTES = 32
        private const val ED25519_BYTES = 32
        private const val MAX_SIGNED_MESSAGE_BYTES = 4096
        private const val MIN_WRAPPED_BYTES = 1 + 12 + 16 + X25519_BYTES
        private const val MAX_GENERATED_BYTES = 512
        private val RECORD_FIELDS = setOf(
            "schema_version",
            "mode",
            "key_alias",
            "noise_public_key",
            "wrapped_material",
            "identity_key_alias",
            "identity_public_key",
            "wrapped_identity_material",
            "wireguard_key_alias",
            "wireguard_public_key",
            "wrapped_wireguard_material",
        )
        private val ENCODER = Base64.getUrlEncoder().withoutPadding()
        private val DECODER = Base64.getUrlDecoder()
        private val KEY_LOCK = Any()
    }
}
