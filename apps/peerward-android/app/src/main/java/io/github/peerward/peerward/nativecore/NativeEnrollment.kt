package io.github.peerward.peerward.nativecore

import java.time.Instant

/** Rust-owned canonical Join request construction; Kotlin only signs and transports it. */
object NativeEnrollment {
    fun prepare(
        claimUrl: String,
        identityPublic: ByteArray,
        sessionPublic: ByteArray,
        wireguardPublic: ByteArray,
        clientVersion: String,
        nonce: ByteArray,
        deviceName: String,
        deviceModel: String,
        platformVersion: String,
    ): ByteArray = nativePrepare(
        claimUrl, identityPublic, sessionPublic, wireguardPublic, clientVersion, nonce,
        deviceName, deviceModel, platformVersion,
    )

    fun transcript(draft: ByteArray): ByteArray = nativeTranscript(draft)
    fun complete(draft: ByteArray, signature: ByteArray): ByteArray = nativeComplete(draft, signature)
    fun verifyResponse(
        response: ByteArray,
        rootFingerprint: ByteArray,
        identityPublic: ByteArray,
        sessionPublic: ByteArray,
        wireguardPublic: ByteArray,
    ): ByteArray = nativeVerifyResponse(
        response, rootFingerprint, identityPublic, sessionPublic, wireguardPublic, Instant.now().epochSecond,
    )

    init {
        System.loadLibrary("peerward_android_core")
    }

    @JvmStatic private external fun nativePrepare(
        claimUrl: String,
        identityPublic: ByteArray,
        sessionPublic: ByteArray,
        wireguardPublic: ByteArray,
        clientVersion: String,
        nonce: ByteArray,
        deviceName: String,
        deviceModel: String,
        platformVersion: String,
    ): ByteArray
    @JvmStatic private external fun nativeTranscript(draft: ByteArray): ByteArray
    @JvmStatic private external fun nativeComplete(draft: ByteArray, signature: ByteArray): ByteArray
    @JvmStatic private external fun nativeVerifyResponse(
        response: ByteArray,
        rootFingerprint: ByteArray,
        identityPublic: ByteArray,
        sessionPublic: ByteArray,
        wireguardPublic: ByteArray,
        now: Long,
    ): ByteArray
}
