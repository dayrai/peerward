package io.github.peerward.peerward.join

import io.github.peerward.peerward.crypto.PublicDeviceKeys
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.time.Instant
import java.util.UUID

class ClaimPollingTest {
    private val keys = PublicDeviceKeys(ByteArray(32) { 1 }, ByteArray(32) { 2 }, ByteArray(32) { 3 })
    private val application = UUID.randomUUID().toString()
    private val id = UUID.randomUUID().toString()
    private val mesh = UUID.randomUUID()
    private val now = Instant.now().epochSecond
    private fun status(fingerprint: String = PendingEnrollmentStore.digest(keys.identityEd25519), expires: Long = now + 1800) = JSONObject()
        .put("application", JSONObject().put("status", "pending").put("id", application)
            .put("claim_id", id).put("mesh_id", mesh.toString()).put("identity_fingerprint", fingerprint)
            .put("created_at", now).put("expires_at", expires)).toString()

    @Test fun pendingResponsesResendTheExactBodyAndReturnOnlyTheFinalBundle() {
        MockWebServer().use { server ->
            server.enqueue(MockResponse().setResponseCode(202).setBody(status()))
            server.enqueue(MockResponse().setResponseCode(202).setBody(status()))
            server.enqueue(MockResponse().setResponseCode(201).setBody("final signed bundle"))
            server.start()
            val url = server.url("/api/v1/join/test/claim")
            val bundle = JoinBundle(url.toUri(), ByteArray(32), Instant.ofEpochSecond(now + 300), ByteArray(32), mesh)
            val request = Request.Builder().url(url).post("exact signed request".toRequestBody()).build()
            var observations = 0
            val result = claimResponse(OkHttpClient(), request, bundle, JSONObject().put("claim_id", id), keys, { observations++ }, {})
            assertArrayEquals("final signed bundle".toByteArray(), result)
            assertEquals(2, observations)
            repeat(3) { assertEquals("exact signed request", server.takeRequest().body.readUtf8()) }
        }
    }

    @Test fun unrelatedIdentityAndDeadlineExtensionsAreRejectedWithoutAnotherPoll() {
        for (responses in listOf(listOf(status("0".repeat(64))), listOf(status(), status(expires = now + 1799)))) {
            MockWebServer().use { server ->
                responses.forEach { server.enqueue(MockResponse().setResponseCode(202).setBody(it)) }
                server.start()
                val url = server.url("/api/v1/join/test/claim")
                val bundle = JoinBundle(url.toUri(), ByteArray(32), Instant.ofEpochSecond(now + 300), ByteArray(32), mesh)
                assertThrows(IllegalArgumentException::class.java) {
                    claimResponse(OkHttpClient(), Request.Builder().url(url).post("fixed".toRequestBody()).build(), bundle,
                        JSONObject().put("claim_id", id), keys, {}, {})
                }
                assertEquals(responses.size, server.requestCount)
            }
        }
    }
}
