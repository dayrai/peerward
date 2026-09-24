package io.github.peerward.peerward.join

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Base64

class JoinBundleTest {
    private val now = Instant.parse("2030-01-01T00:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)

    @Test
    fun parsesStrictUnpaddedBundle() {
        val nonce = ByteArray(24) { it.toByte() }
        val json = JSONObject()
            .put("claim_url", "https://control.example/api/v1/join/token/claim")
            .put("root_fingerprint", "ab".repeat(32))
            .put("expires_at", now.plusSeconds(600).epochSecond)
            .put("nonce", Base64.getUrlEncoder().withoutPadding().encodeToString(nonce))
            .put("mesh_id", "00000000-0000-4000-8000-000000000002")
        val link = link(json)

        val bundle = JoinBundle.parse(link, clock)

        assertEquals("control.example", bundle.claimUrl.host)
        assertArrayEquals(nonce, bundle.nonce)
        assertArrayEquals(ByteArray(32) { 0xab.toByte() }, bundle.rootFingerprint)
        assertEquals("00000000-0000-4000-8000-000000000002", bundle.meshId.toString())
    }

    @Test
    fun rejectsExpiryHttpDuplicateAndUnknownFields() {
        val valid = JSONObject()
            .put("claim_url", "https://control.example/api/v1/join/x/claim")
            .put("root_fingerprint", "01".repeat(32))
            .put("expires_at", now.minusSeconds(1).epochSecond)
            .put("nonce", Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16)))
        assertThrows(IllegalArgumentException::class.java) { JoinBundle.parse(link(valid), clock) }

        valid.put("expires_at", now.plusSeconds(1).epochSecond).put("claim_url", "http://control.example/claim")
        assertThrows(IllegalArgumentException::class.java) { JoinBundle.parse(link(valid), clock) }

        valid.put("claim_url", "https://control.example/claim").put("extra", true)
        assertThrows(IllegalArgumentException::class.java) { JoinBundle.parse(link(valid), clock) }

        val normal = link(JSONObject(valid.toString()).apply { remove("extra") })
        assertThrows(IllegalArgumentException::class.java) { JoinBundle.parse("$normal&bundle=again", clock) }

        val invalidMesh = JSONObject(valid.toString()).apply {
            remove("extra")
            put("mesh_id", "00000000-0000-0000-0000-000000000002")
        }
        assertThrows(IllegalArgumentException::class.java) { JoinBundle.parse(link(invalidMesh), clock) }
    }

    private fun link(json: JSONObject): String {
        val payload = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(json.toString().toByteArray(StandardCharsets.UTF_8))
        return "peerward://join?bundle=${URLEncoder.encode(payload, StandardCharsets.UTF_8.name())}"
    }

    @Test
    fun acceptsIpv6LoopbackButRejectsCredentialsQueriesAndDecoratedLinks() {
        val json = JSONObject()
            .put("claim_url", "http://[::1]:8081/api/v1/join/token/claim")
            .put("root_fingerprint", "ab".repeat(32))
            .put("expires_at", now.plusSeconds(600).epochSecond)
            .put("nonce", Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16)))
        assertEquals("[::1]", JoinBundle.parse(link(json), clock).claimUrl.host)
        val normal = link(json)
        for (value in listOf(normal + "#fragment", normal.replace("//join", "//user@join"), normal.replace("//join", "//join:443"))) {
            assertThrows(IllegalArgumentException::class.java) { JoinBundle.parse(value, clock) }
        }
        for (url in listOf("https://user:secret@control.example/claim", "https://control.example/claim?x=y", "http://192.0.2.1/claim")) {
            json.put("claim_url", url)
            assertThrows(IllegalArgumentException::class.java) { JoinBundle.parse(link(json), clock) }
        }
    }
}
