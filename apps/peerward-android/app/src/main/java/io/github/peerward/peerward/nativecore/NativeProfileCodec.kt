package io.github.peerward.peerward.nativecore

import java.nio.ByteBuffer

data class NativeRotationPlan(
    val requestId: ByteArray,
    val keyId: String,
    val expectedIdentity: ByteArray?,
    val expectedNoise: ByteArray?,
    val expectedWireguard: ByteArray?,
    val stagedProfile: ByteArray?,
)

data class NativePreviousKeyCleanup(val keyId: String, val cleanedProfile: ByteArray)

data class NativeRotationReplacement(val credential: ByteArray, val activationTranscript: ByteArray)

/** Rust-owned durable profile codec. Kotlin persists only the returned opaque bytes. */
object NativeProfileCodec {
    fun encode(materializedJson: ByteArray): ByteArray = nativeEncode(materializedJson)
    fun decode(opaqueBlob: ByteArray): ByteArray = nativeDecode(opaqueBlob)

    fun rotationPlan(opaqueBlob: ByteArray): NativeRotationPlan {
        val encoded = nativeRotationPlan(opaqueBlob)
        var staged: ByteArray? = null
        try {
            val input = ByteBuffer.wrap(encoded)
            require(input.remaining() >= 23 && input.get().unsigned() == VERSION)
            val flags = input.get().unsigned()
            require(flags and FLAGS.inv() == 0)
            val request = ByteArray(16).also(input::get)
            val keyLength = input.get().unsigned()
            require(keyLength in 1..64 && input.remaining() >= keyLength + 4)
            val key = ByteArray(keyLength).also(input::get).toString(Charsets.US_ASCII)
            val expectedIdentity: ByteArray?
            val expectedNoise: ByteArray?
            val expectedWireguard: ByteArray?
            if (flags and HAS_EXPECTED_KEYS != 0) {
                require(input.remaining() >= 100)
                expectedIdentity = ByteArray(32).also(input::get)
                expectedNoise = ByteArray(32).also(input::get)
                expectedWireguard = ByteArray(32).also(input::get)
            } else {
                expectedIdentity = null
                expectedNoise = null
                expectedWireguard = null
            }
            val stagedLength = input.int
            require(stagedLength in 0..MAX_PROFILE && input.remaining() == stagedLength)
            staged = ByteArray(stagedLength).also(input::get).takeIf(ByteArray::isNotEmpty)
            require((flags and HAS_STAGED_PROFILE != 0) == (staged != null))
            return NativeRotationPlan(request, key, expectedIdentity, expectedNoise, expectedWireguard, staged)
        } catch (error: Throwable) {
            staged?.fill(0)
            throw error
        } finally {
            encoded.fill(0)
        }
    }

    fun installRotationPublics(
        opaqueBlob: ByteArray,
        plan: NativeRotationPlan,
        identity: ByteArray,
        noise: ByteArray,
        wireguard: ByteArray,
    ): ByteArray = nativeInstallRotationPublics(
        opaqueBlob,
        plan.requestId,
        plan.keyId,
        identity,
        noise,
        wireguard,
    )

    fun commitRotation(opaqueBlob: ByteArray, credential: ByteArray): ByteArray =
        nativeCommitRotation(opaqueBlob, credential)

    fun stageRotationCredential(opaqueBlob: ByteArray, credential: ByteArray): ByteArray =
        nativeRotationRecovery(opaqueBlob, credential)

    fun recoveryProfile(opaqueBlob: ByteArray): ByteArray? =
        nativeRotationRecovery(opaqueBlob, ByteArray(0)).takeIf(ByteArray::isNotEmpty)

    fun cleanPreviousKey(
        opaqueBlob: ByteArray,
        activeKeyId: String,
    ): NativePreviousKeyCleanup? {
        val encoded = nativeCleanPreviousKey(opaqueBlob, activeKeyId)
        try {
            val input = ByteBuffer.wrap(encoded)
            require(input.remaining() >= 2 && input.get().unsigned() == VERSION)
            if (input.get().unsigned() == 0) {
                require(!input.hasRemaining())
                return null
            }
            require(input.remaining() >= 5)
            val keyLength = input.get().unsigned()
            require(keyLength in 1..64 && input.remaining() >= keyLength + 4)
            val key = ByteArray(keyLength).also(input::get).toString(Charsets.US_ASCII)
            val blobLength = input.int
            require(blobLength in 1..MAX_PROFILE && input.remaining() == blobLength)
            return NativePreviousKeyCleanup(key, ByteArray(blobLength).also(input::get))
        } finally {
            encoded.fill(0)
        }
    }

    fun decodeRotationReplacement(update: ByteArray): NativeRotationReplacement {
        val encoded = nativeDecodeRotationReplacement(update)
        var credential = ByteArray(0)
        try {
            val input = ByteBuffer.wrap(encoded)
            require(input.remaining() >= 8)
            val credentialLength = input.int
            require(credentialLength > 0 && input.remaining() >= credentialLength + 4)
            credential = ByteArray(credentialLength).also(input::get)
            val transcriptLength = input.int
            require(transcriptLength > 0 && input.remaining() == transcriptLength)
            return NativeRotationReplacement(
                credential,
                ByteArray(transcriptLength).also(input::get),
            )
        } catch (error: Throwable) {
            credential.fill(0)
            throw error
        } finally {
            encoded.fill(0)
        }
    }

    fun installAuthorities(
        opaqueBlob: ByteArray,
        revision: Long,
        certificates: List<ByteArray>,
    ): ByteArray {
        require(revision > 0 && certificates.size in 1..9 && certificates.all { it.size == 144 })
        val flattened = ByteArray(certificates.size * 144)
        certificates.forEachIndexed { index, certificate ->
            certificate.copyInto(flattened, index * 144)
        }
        return nativeInstallAuthorities(opaqueBlob, revision, flattened)
    }

    init {
        System.loadLibrary("peerward_android_core")
    }

    private const val VERSION = 2
    private const val HAS_STAGED_PROFILE = 1
    private const val HAS_EXPECTED_KEYS = 1 shl 1
    private const val FLAGS = HAS_STAGED_PROFILE or HAS_EXPECTED_KEYS
    private const val MAX_PROFILE = 1024 * 1024 + 9

    private fun Byte.unsigned(): Int = toInt() and 0xff

    @JvmStatic private external fun nativeEncode(materializedJson: ByteArray): ByteArray
    @JvmStatic private external fun nativeRotationRecovery(opaqueBlob: ByteArray, credential: ByteArray): ByteArray
    @JvmStatic private external fun nativeDecode(opaqueBlob: ByteArray): ByteArray
    @JvmStatic private external fun nativeRotationPlan(opaqueBlob: ByteArray): ByteArray
    @JvmStatic private external fun nativeInstallRotationPublics(
        opaqueBlob: ByteArray,
        requestId: ByteArray,
        keyId: String,
        identity: ByteArray,
        noise: ByteArray,
        wireguard: ByteArray,
    ): ByteArray
    @JvmStatic private external fun nativeCommitRotation(
        opaqueBlob: ByteArray,
        credential: ByteArray,
    ): ByteArray
    @JvmStatic private external fun nativeCleanPreviousKey(
        opaqueBlob: ByteArray,
        activeKeyId: String,
    ): ByteArray
    @JvmStatic private external fun nativeDecodeRotationReplacement(update: ByteArray): ByteArray
    @JvmStatic private external fun nativeInstallAuthorities(
        opaqueBlob: ByteArray,
        revision: Long,
        certificates: ByteArray,
    ): ByteArray
}
