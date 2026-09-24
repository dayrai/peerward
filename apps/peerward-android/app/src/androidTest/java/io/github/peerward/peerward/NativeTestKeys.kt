package io.github.peerward.peerward

import io.github.peerward.peerward.crypto.NativeKeyMaterial

/** Instrumentation-only X25519 helper; returns public/shared values only. */
object NativeTestKeys {
    fun publicFromPrivate(privateKey: ByteArray): ByteArray {
        val basePoint = ByteArray(32).also { it[0] = 9 }
        return try {
            NativeKeyMaterial.agreeTransient(privateKey, basePoint)
        } finally {
            privateKey.fill(0)
        }
    }
}
