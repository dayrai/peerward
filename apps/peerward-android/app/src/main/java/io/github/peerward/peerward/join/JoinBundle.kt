package io.github.peerward.peerward.join

import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.time.Clock
import java.time.Instant
import java.util.Base64
import java.util.UUID

data class JoinBundle(
    val claimUrl: URI,
    val rootFingerprint: ByteArray,
    val expiresAt: Instant,
    val nonce: ByteArray,
    val meshId: UUID? = null,
) {
    init {
        val host = claimUrl.host.orEmpty()
        val ipv4 = host.split('.')
        val loopback = host in setOf("localhost", "::1", "[::1]") ||
            (ipv4.size == 4 && ipv4[0] == "127" && ipv4.all { it.toIntOrNull() in 0..255 })
        val loopbackHttp = claimUrl.scheme == "http" && loopback
        require(claimUrl.scheme == "https" || loopbackHttp) {
            "claim URL must use HTTPS outside a loopback development environment"
        }
        require(claimUrl.host != null && claimUrl.userInfo == null && claimUrl.fragment == null && claimUrl.query == null) {
            "claim URL is not an absolute, uncredentialed HTTPS URL"
        }
        require(rootFingerprint.size == SHA256_BYTES) { "root fingerprint must be SHA-256" }
        require(nonce.size in MIN_NONCE_BYTES..MAX_NONCE_BYTES) { "nonce length is invalid" }
    }

    fun isExpired(clock: Clock = Clock.systemUTC()): Boolean = !expiresAt.isAfter(clock.instant())

    companion object {
        private const val SHA256_BYTES = 32
        private const val MIN_NONCE_BYTES = 16
        private const val MAX_NONCE_BYTES = 64
        private val requiredFields = setOf("claim_url", "root_fingerprint", "expires_at", "nonce")
        private val allowedFields = requiredFields + "mesh_id"

        fun parse(deepLink: String, clock: Clock = Clock.systemUTC(), allowExpiredResume: Boolean = false): JoinBundle {
            val uri = runCatching { URI(deepLink) }.getOrElse { throw IllegalArgumentException("invalid join URI", it) }
            require(uri.scheme == "peerward" && uri.host == "join" && uri.path.orEmpty().isEmpty() &&
                uri.userInfo == null && uri.port == -1 && uri.fragment == null) {
                "join URI must be peerward://join"
            }
            val query = decodeQuery(uri.rawQuery)
            require(query.keys == setOf("bundle")) { "join URI must contain only one bundle parameter" }
            val encoded = query.getValue("bundle")
            val decoded = decodeBase64Url(encoded, "bundle")
            require(decoded.size <= 8 * 1024) { "join bundle is too large" }
            val json = runCatching { JSONObject(String(decoded, StandardCharsets.UTF_8)) }
                .getOrElse { throw IllegalArgumentException("join bundle is not JSON", it) }
            val fields = json.keys().asSequence().toSet()
            require(fields.containsAll(requiredFields) && allowedFields.containsAll(fields)) {
                "join bundle fields do not match schema"
            }
            val result = JoinBundle(
                claimUrl = URI(json.getString("claim_url")),
                rootFingerprint = decodeFingerprint(json.getString("root_fingerprint")),
                expiresAt = Instant.ofEpochSecond(json.getLong("expires_at")),
                nonce = decodeBase64Url(json.getString("nonce"), "nonce"),
                meshId = if (json.has("mesh_id")) decodeMeshId(json.getString("mesh_id")) else null,
            )
            require(allowExpiredResume || !result.isExpired(clock)) { "join bundle has expired" }
            return result
        }

        private fun decodeQuery(raw: String?): Map<String, String> {
            require(!raw.isNullOrBlank()) { "join URI has no query" }
            val pairs = raw.split('&')
            val result = linkedMapOf<String, String>()
            for (pair in pairs) {
                val parts = pair.split('=', limit = 2)
                require(parts.size == 2) { "malformed join query" }
                val key = URLDecoder.decode(parts[0], StandardCharsets.UTF_8.name())
                val value = URLDecoder.decode(parts[1], StandardCharsets.UTF_8.name())
                require(result.put(key, value) == null) { "duplicate join query parameter" }
            }
            return result
        }

        private fun decodeFingerprint(value: String): ByteArray {
            require(value.length == SHA256_BYTES * 2 && value.all { it.isDigit() || it.lowercaseChar() in 'a'..'f' }) {
                "root fingerprint must be 64 hexadecimal characters"
            }
            return ByteArray(SHA256_BYTES) { index ->
                value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
            }
        }

        private fun decodeMeshId(value: String): UUID {
            require(value.matches(Regex("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"))) {
                "mesh ID must be a canonical UUIDv4"
            }
            return UUID.fromString(value)
        }

        private fun decodeBase64Url(value: String, label: String): ByteArray {
            require(value.isNotEmpty() && value.none { it == '=' || it.isWhitespace() }) {
                "$label must be unpadded base64url"
            }
            return runCatching { Base64.getUrlDecoder().decode(value) }
                .getOrElse { throw IllegalArgumentException("$label is not base64url", it) }
        }
    }

    override fun equals(other: Any?): Boolean = other is JoinBundle &&
        claimUrl == other.claimUrl && rootFingerprint.contentEquals(other.rootFingerprint) &&
        expiresAt == other.expiresAt && nonce.contentEquals(other.nonce) && meshId == other.meshId

    override fun hashCode(): Int = 31 * (31 * claimUrl.hashCode() + rootFingerprint.contentHashCode()) +
        31 * expiresAt.hashCode() + nonce.contentHashCode() + 31 * (meshId?.hashCode() ?: 0)
}
