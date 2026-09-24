package io.github.peerward.peerward.crypto

import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyStore
import java.security.spec.NamedParameterSpec
import java.security.spec.XECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Keystore callbacks used only by the native Snow DH resolver. */
object NativeKeyAgreement {
    /** The data scalar exists in Java only during this call and is never returned. */
    fun installWireguard(
        alias: String, publicKey: ByteArray, wrapped: ByteArray,
        owner: Long, profile: ByteArray, credential: ByteArray,
    ): Long {
        require(alias.endsWith(".wireguard-wrap") && publicKey.size == X25519_BYTES)
        require(wrapped.size in MIN_WRAPPED_BYTES..MAX_WRAPPED_BYTES)
        val ivLength = wrapped[0].toInt() and 0xff
        require(ivLength in 12..16 && wrapped.size > 1 + ivLength + 16)
        val iv = wrapped.copyOfRange(1, 1 + ivLength)
        val privateKey = Cipher.getInstance(TRANSFORMATION).run {
            init(Cipher.DECRYPT_MODE, secretKey(alias), GCMParameterSpec(128, iv))
            updateAAD(metadata(dataKeyWrappingDomain(alias), alias, publicKey))
            doFinal(wrapped, 1 + ivLength, wrapped.size - 1 - ivLength)
        }
        return try {
            require(privateKey.size == X25519_BYTES)
            io.github.peerward.peerward.nativecore.NativeWireguardRuntime.nativeInstall(
                owner, profile, credential, privateKey,
            )
        } finally {
            privateKey.fill(0)
            iv.fill(0)
        }
    }
    @JvmStatic
    @RequiresApi(33)
    fun agree(alias: String, remoteRaw: ByteArray): ByteArray {
        require(alias.startsWith("peerward.") && alias.endsWith(".noise")) { "invalid key alias" }
        require(remoteRaw.size == X25519_BYTES) { "invalid remote X25519 key" }
        val store = keyStore()
        val privateKey = (store.getEntry(alias, null) as? KeyStore.PrivateKeyEntry)?.privateKey
            ?: throw DeviceKeyUnavailable("device Noise key does not exist")
        val unsignedBigEndian = byteArrayOf(0) + remoteRaw.reversedArray()
        val remote = KeyFactory.getInstance("XDH").generatePublic(
            XECPublicKeySpec(NamedParameterSpec("X25519"), BigInteger(unsignedBigEndian)),
        )
        return KeyAgreement.getInstance("XDH").run {
            init(privateKey)
            doPhase(remote, true)
            generateSecret().also { require(it.size == X25519_BYTES) }
        }
    }

    /** Encrypts native-generated key material; plaintext is cleared before return. */
    @JvmStatic
    fun wrapGenerated(alias: String, publicKey: ByteArray, privateKey: ByteArray): ByteArray {
        try {
            require(publicKey.size == X25519_BYTES && privateKey.size == X25519_BYTES)
            return wrap(alias, publicKey, privateKey, dataKeyWrappingDomain(alias))
        } finally {
            privateKey.fill(0)
        }
    }

    /** Encrypts a Rust-generated Ed25519 seed under its dedicated non-exportable AES key. */
    @JvmStatic
    fun wrapIdentityGenerated(alias: String, publicKey: ByteArray, privateKey: ByteArray): ByteArray {
        try {
            require(alias.startsWith("peerward.") && alias.endsWith(".identity-wrap")) {
                "invalid identity wrapping alias"
            }
            require(publicKey.size == ED25519_BYTES && privateKey.size == ED25519_BYTES)
            return wrap(alias, publicKey, privateKey, IDENTITY_DOMAIN)
        } finally {
            privateKey.fill(0)
        }
    }

    private fun wrap(alias: String, publicKey: ByteArray, privateKey: ByteArray, domain: ByteArray): ByteArray {
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey(alias))
            cipher.updateAAD(metadata(domain, alias, publicKey))
            val ciphertext = cipher.doFinal(privateKey)
            require(cipher.iv.size in 12..16)
            ByteBuffer.allocate(1 + cipher.iv.size + ciphertext.size)
                .put(cipher.iv.size.toByte())
                .put(cipher.iv)
                .put(ciphertext)
                .array()
        } finally {
            privateKey.fill(0)
        }
    }

    /** Unwraps only for one agreement and clears the transient scalar. */
    @JvmStatic
    fun agreeWrapped(
        alias: String,
        publicKey: ByteArray,
        wrapped: ByteArray,
        remoteRaw: ByteArray,
    ): ByteArray {
        require(alias.startsWith("peerward.") && alias.endsWith(".noise-wrap")) { "invalid wrapping alias" }
        require(publicKey.size == X25519_BYTES && remoteRaw.size == X25519_BYTES)
        require(wrapped.size in MIN_WRAPPED_BYTES..MAX_WRAPPED_BYTES)
        val ivLength = wrapped[0].toInt() and 0xff
        require(ivLength in 12..16 && wrapped.size > 1 + ivLength + 16)
        val iv = wrapped.copyOfRange(1, 1 + ivLength)
        val ciphertext = wrapped.copyOfRange(1 + ivLength, wrapped.size)
        val privateKey = Cipher.getInstance(TRANSFORMATION).run {
            init(Cipher.DECRYPT_MODE, secretKey(alias), GCMParameterSpec(128, iv))
            updateAAD(metadata(NOISE_DOMAIN, alias, publicKey))
            doFinal(ciphertext)
        }
        return try {
            require(privateKey.size == X25519_BYTES)
            NativeKeyMaterial.agreeTransient(privateKey, remoteRaw)
        } finally {
            privateKey.fill(0)
            iv.fill(0)
            ciphertext.fill(0)
        }
    }

    /** Unwraps an Ed25519 seed only long enough for one native signature. */
    @JvmStatic
    fun signWrapped(
        alias: String,
        publicKey: ByteArray,
        wrapped: ByteArray,
        message: ByteArray,
    ): ByteArray {
        require(alias.startsWith("peerward.") && alias.endsWith(".identity-wrap")) {
            "invalid identity wrapping alias"
        }
        require(publicKey.size == ED25519_BYTES && message.size in 1..MAX_SIGNED_MESSAGE_BYTES)
        require(wrapped.size in MIN_WRAPPED_BYTES..MAX_WRAPPED_BYTES)
        val ivLength = wrapped[0].toInt() and 0xff
        require(ivLength in 12..16 && wrapped.size > 1 + ivLength + 16)
        val iv = wrapped.copyOfRange(1, 1 + ivLength)
        val ciphertext = wrapped.copyOfRange(1 + ivLength, wrapped.size)
        val privateKey = Cipher.getInstance(TRANSFORMATION).run {
            init(Cipher.DECRYPT_MODE, secretKey(alias), GCMParameterSpec(128, iv))
            updateAAD(metadata(IDENTITY_DOMAIN, alias, publicKey))
            doFinal(ciphertext)
        }
        return try {
            require(privateKey.size == ED25519_BYTES)
            NativeKeyMaterial.signTransient(privateKey, publicKey, message)
        } finally {
            privateKey.fill(0)
            iv.fill(0)
            ciphertext.fill(0)
        }
    }

    private fun metadata(domain: ByteArray, alias: String, publicKey: ByteArray): ByteArray {
        val aliasBytes = alias.toByteArray(StandardCharsets.UTF_8)
        require(aliasBytes.size <= 128)
        return ByteBuffer.allocate(domain.size + 2 + aliasBytes.size + publicKey.size)
            .put(domain)
            .putShort(aliasBytes.size.toShort())
            .put(aliasBytes)
            .put(publicKey)
            .array()
    }

    private fun secretKey(alias: String): SecretKey {
        val entry = keyStore().getEntry(alias, null) as? KeyStore.SecretKeyEntry
            ?: throw DeviceKeyUnavailable("device wrapping key does not exist")
        check(entry.secretKey.encoded == null) { "AndroidKeyStore exported a wrapping key" }
        return entry.secretKey
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    private const val ANDROID_KEY_STORE = "AndroidKeyStore"
    private const val TRANSFORMATION = "${KeyProperties.KEY_ALGORITHM_AES}/${KeyProperties.BLOCK_MODE_GCM}/${KeyProperties.ENCRYPTION_PADDING_NONE}"
    private const val X25519_BYTES = 32
    private const val ED25519_BYTES = 32
    private const val MAX_SIGNED_MESSAGE_BYTES = 4096
    private const val MIN_WRAPPED_BYTES = 61
    private const val MAX_WRAPPED_BYTES = 480
    private val NOISE_DOMAIN = "peerward/android-noise-key/v1\u0000".toByteArray(StandardCharsets.US_ASCII)
    private val IDENTITY_DOMAIN = "peerward/android-identity-key/v1\u0000".toByteArray(StandardCharsets.US_ASCII)
}

/** Narrow JNI surface: no function returns a private key. */
object NativeKeyMaterial {
    init {
        System.loadLibrary("peerward_android_core")
    }

    fun generateWrapped(alias: String): ByteArray = nativeGenerateWrapped(alias)

    fun generateWrappedIdentity(alias: String): ByteArray = nativeGenerateWrappedIdentity(alias)

    fun agreeTransient(privateKey: ByteArray, remotePublic: ByteArray): ByteArray =
        nativeAgreeTransient(privateKey, remotePublic)

    fun signTransient(privateKey: ByteArray, publicKey: ByteArray, message: ByteArray): ByteArray =
        nativeSignTransient(privateKey, publicKey, message)

    @JvmStatic private external fun nativeGenerateWrapped(alias: String): ByteArray
    @JvmStatic private external fun nativeGenerateWrappedIdentity(alias: String): ByteArray
    @JvmStatic private external fun nativeAgreeTransient(privateKey: ByteArray, remotePublic: ByteArray): ByteArray
    @JvmStatic private external fun nativeSignTransient(
        privateKey: ByteArray,
        publicKey: ByteArray,
        message: ByteArray,
    ): ByteArray
}
