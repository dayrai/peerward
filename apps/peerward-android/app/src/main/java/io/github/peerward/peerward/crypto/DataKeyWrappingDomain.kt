package io.github.peerward.peerward.crypto

/** Separate authenticated key purposes, including the complete Keystore alias in the AAD. */
internal fun dataKeyWrappingDomain(alias: String): ByteArray {
    require(alias.startsWith("peerward.") && alias.length <= 128) { "invalid wrapping alias" }
    val purpose = when {
        alias.endsWith(".wireguard-wrap") -> "wireguard"
        alias.endsWith(".noise-wrap") -> "noise"
        else -> error("invalid data key purpose")
    }
    return "peerward/android-$purpose-key/v1\u0000".toByteArray(Charsets.US_ASCII)
}
