package io.github.peerward.peerward.join

import io.github.peerward.peerward.crypto.PublicDeviceKeys
import okhttp3.OkHttpClient
import okhttp3.ResponseBody
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import java.util.UUID
import okio.Buffer
import okio.BufferedSource

class TicketClaimerTest {
    @Test
    fun boundsUnknownLengthClaimResponses() {
        fun body(bytes: ByteArray) = object : ResponseBody() {
            override fun contentType() = null
            override fun contentLength() = -1L
            override fun source(): BufferedSource = Buffer().write(bytes)
        }
        val accepted = ByteArray(9_001) { (it % 251).toByte() }
        assertArrayEquals(accepted, readBoundedBytes(body(accepted)))
        assertThrows(IllegalArgumentException::class.java) {
            readBoundedBytes(body(ByteArray(1024 * 1024 + 1)))
        }
    }

    @Test
    fun clearsPreparedClaimWhenPendingPersistenceFails() {
        val identity = ByteArray(32) { 8 }
        val session = ByteArray(32) { 9 }
        val wireguard = ByteArray(32) { 12 }
        var captured: ByteArray? = null
        val bundle = JoinBundle(
            java.net.URI("https://control.example/api/v1/join/${encoded(ByteArray(32) { 10 })}/claim"),
            ByteArray(32),
            Instant.now().plusSeconds(60),
            ByteArray(24) { it.toByte() },
        )
        assertThrows(IllegalStateException::class.java) {
            TicketClaimer(OkHttpClient(), TestEnrollmentProtocol()).claim(
                bundle,
                "device-key",
                PublicDeviceKeys(identity, session, wireguard),
                ClaimIdentitySigner { ByteArray(64) { 11 } },
                ClaimDevice("Phone", "Test model", "36"),
                savePayload = {
                    captured = it
                    error("simulated persistence failure")
                },
            )
        }
        assertTrue(requireNotNull(captured).all { it == 0.toByte() })
    }

    @Test
    fun claimsOverHttpsPinsRootAndSendsNoPrivateMaterial() {
        val serverCertificate = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
        val serverTls = HandshakeCertificates.Builder().heldCertificate(serverCertificate).build()
        val clientTls = HandshakeCertificates.Builder().addTrustedCertificate(serverCertificate.certificate).build()
        val root = ByteArray(32) { (it * 7).toByte() }
        val identity = ByteArray(32) { 8 }
        val session = ByteArray(32) { 9 }
        val wireguard = ByteArray(32) { 12 }
        val credential = ByteArray(225).apply {
            this[0] = 1
            identity.copyInto(this, 33)
            session.copyInto(this, 65)
            wireguard.copyInto(this, 97)
        }
        val ticket = encoded(ByteArray(32) { 10 })
        MockWebServer().use { server ->
            server.useHttps(serverTls.sslSocketFactory(), false)
            server.enqueue(
                MockResponse().setHeader("content-type", "application/json").setBody(
                    JSONObject()
                        .put("root_public_key", Base64.getUrlEncoder().withoutPadding().encodeToString(root))
                        .put("profile_id", "profile")
                        .put("mesh_id", "mesh")
                        .put("peer_id", "peer")
                        .put("mesh_name", "Test mesh")
                        .put("address", "10.2.3.4/32")
                        .put("dns_suffix", "test.mesh")
                        .put("credential", encoded(credential))
                        .put("relays", listOf(
                            JSONObject()
                                .put("relay_id", "00000000-0000-4000-8000-000000000010")
                                .put("endpoints", listOf("tcp://relay.test:443"))
                                .put("public_key", encoded(ByteArray(32) { 3 })),
                        ))
                        .put("routes", listOf("10.2.3.0/24"))
                        .put("dns_servers", listOf("10.2.3.1"))
                        .put("mtu", 1380)
                        .put("stun_servers", emptyList<String>())
                        .put("authority_certificates", listOf(encoded(ByteArray(144) { 4 })))
                        .put("authority_revision", 1)
                        .put("distribution_public_key", encoded(ByteArray(32) { 5 }))
                        .put("service_public_key", encoded(ByteArray(32) { 6 }))
                        .put("audit_public_key", encoded(ByteArray(32) { 8 }))
                        .put("distribution_certificate", encoded(ByteArray(208) { 7 }))
                        .toString(),
                ),
            )
            server.start()
            val client = OkHttpClient.Builder()
                .sslSocketFactory(clientTls.sslSocketFactory(), clientTls.trustManager)
                .build()
            val bundle = JoinBundle(
                server.url("/api/v1/join/$ticket/claim").toUri(),
                MessageDigest.getInstance("SHA-256").digest(root),
                Instant.now().plusSeconds(60),
                ByteArray(24) { it.toByte() },
            )
            val profile = TicketClaimer(client, TestEnrollmentProtocol()).claim(
                bundle,
                "device-key",
                PublicDeviceKeys(identity, session, wireguard),
                ClaimIdentitySigner { ByteArray(64) { 11 } },
                ClaimDevice("Phone", "Test model", "34"),
            )
            assertEquals("peer", profile.peerId)
            assertEquals("device-key", profile.deviceKeyId)
            assertEquals("tcp://relay.test:443", profile.relays.single().endpoints.single())
            val request = server.takeRequest()
            assertEquals("/api/v1/join/$ticket/claim", request.path)
            val body = JSONObject(request.body.readUtf8())
            assertEquals(
                setOf(
                    "schema_version", "claim_id", "identity_public_key", "session_public_key", "wireguard_public_key",
                    "client_version", "supported_wire_major", "device_name", "device_model",
                    "platform", "platform_version", "nonce", "signature",
                ),
                body.keys().asSequence().toSet(),
            )
            assertFalse(body.toString().contains("private", ignoreCase = true))
        }
    }

    private fun encoded(bytes: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private class TestEnrollmentProtocol : EnrollmentProtocol {
        private lateinit var identity: ByteArray
        private lateinit var session: ByteArray
        private lateinit var wireguard: ByteArray
        private lateinit var nonce: ByteArray
        private lateinit var version: String
        private lateinit var deviceName: String
        private lateinit var deviceModel: String
        private lateinit var platformVersion: String

        override fun prepare(
            claimUrl: String, identityPublic: ByteArray, sessionPublic: ByteArray, wireguardPublic: ByteArray,
            clientVersion: String, nonce: ByteArray, deviceName: String,
            deviceModel: String, platformVersion: String,
        ): ByteArray {
            identity = identityPublic
            session = sessionPublic
            wireguard = wireguardPublic
            this.nonce = nonce
            version = clientVersion
            this.deviceName = deviceName
            this.deviceModel = deviceModel
            this.platformVersion = platformVersion
            return claimUrl.toByteArray()
        }

        override fun transcript(draft: ByteArray) = ByteArray(32) { 1 }

        override fun complete(draft: ByteArray, signature: ByteArray): ByteArray = JSONObject()
            .put("schema_version", 2)
            .put("claim_id", UUID.randomUUID().toString())
            .put("identity_public_key", encoded(identity))
            .put("session_public_key", encoded(session))
            .put("wireguard_public_key", encoded(wireguard))
            .put("client_version", version)
            .put("supported_wire_major", 2)
            .put("device_name", deviceName)
            .put("device_model", deviceModel)
            .put("platform", "android")
            .put("platform_version", platformVersion)
            .put("nonce", encoded(nonce))
            .put("signature", encoded(signature))
            .toString().toByteArray()

        override fun verifyResponse(
            response: ByteArray, rootFingerprint: ByteArray,
            identityPublic: ByteArray, sessionPublic: ByteArray, wireguardPublic: ByteArray,
        ) = response.copyOf()

        private fun encoded(bytes: ByteArray) =
            Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}
