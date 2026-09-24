package io.github.peerward.peerward.join

import io.github.peerward.peerward.BuildConfig
import io.github.peerward.peerward.net.ProtectedDnsClient
import io.github.peerward.peerward.net.ProtectingSocketFactory
import io.github.peerward.peerward.net.SocketProtector
import io.github.peerward.peerward.crypto.PublicDeviceKeys
import io.github.peerward.peerward.nativecore.NativeEnrollment
import io.github.peerward.peerward.profile.PeerProfile
import io.github.peerward.peerward.profile.RelayProfileTarget
import okhttp3.Dns
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.concurrent.TimeUnit

data class ClaimDevice(val name: String, val model: String, val platformVersion: String)
fun interface ClaimIdentitySigner {
    fun sign(transcript: ByteArray): ByteArray
}

private const val MAX_CLAIM_RESPONSE = 1024 * 1024

internal interface EnrollmentProtocol {
    fun prepare(
        claimUrl: String, identityPublic: ByteArray, sessionPublic: ByteArray, wireguardPublic: ByteArray,
        clientVersion: String, nonce: ByteArray, deviceName: String,
        deviceModel: String, platformVersion: String,
    ): ByteArray
    fun transcript(draft: ByteArray): ByteArray
    fun complete(draft: ByteArray, signature: ByteArray): ByteArray
    fun verifyResponse(
        response: ByteArray, rootFingerprint: ByteArray,
        identityPublic: ByteArray, sessionPublic: ByteArray, wireguardPublic: ByteArray,
    ): ByteArray
}

private object RustEnrollmentProtocol : EnrollmentProtocol {
    override fun prepare(
        claimUrl: String, identityPublic: ByteArray, sessionPublic: ByteArray, wireguardPublic: ByteArray,
        clientVersion: String, nonce: ByteArray, deviceName: String,
        deviceModel: String, platformVersion: String,
    ) = NativeEnrollment.prepare(
        claimUrl, identityPublic, sessionPublic, wireguardPublic, clientVersion, nonce,
        deviceName, deviceModel, platformVersion,
    )
    override fun transcript(draft: ByteArray) = NativeEnrollment.transcript(draft)
    override fun complete(draft: ByteArray, signature: ByteArray) = NativeEnrollment.complete(draft, signature)
    override fun verifyResponse(
        response: ByteArray, rootFingerprint: ByteArray,
        identityPublic: ByteArray, sessionPublic: ByteArray, wireguardPublic: ByteArray,
    ) = NativeEnrollment.verifyResponse(response, rootFingerprint, identityPublic, sessionPublic, wireguardPublic)
}

class TicketClaimer internal constructor(
    private val client: OkHttpClient,
    private val enrollment: EnrollmentProtocol,
) {
    constructor(
        protector: SocketProtector,
        dnsClient: ProtectedDnsClient,
        client: OkHttpClient = protectedClient(protector, dnsClient),
    ) : this(client, RustEnrollmentProtocol)

    /** Enrollment runs before a VPN exists, so the system network is safe. */
    constructor() : this(defaultClient(), RustEnrollmentProtocol)
    fun claim(
        bundle: JoinBundle,
        deviceKeyId: String,
        publicKeys: PublicDeviceKeys,
        signer: ClaimIdentitySigner,
        device: ClaimDevice,
        retainedPayload: ByteArray? = null,
        savePayload: (ByteArray) -> Unit = {},
        onPending: (JSONObject) -> Unit = {},
    ): PeerProfile {
        require(retainedPayload != null || !bundle.isExpired()) { "join bundle has expired" }
        require(publicKeys.identityEd25519.size == 32) { "invalid public identity key" }
        require(publicKeys.noiseX25519.size == 32) { "invalid public Noise key" }
        require(publicKeys.wireguardX25519.size == 32) { "invalid public WireGuard key" }
        require(device.name.isNotBlank()) { "invalid device name" }
        val payload = retainedPayload?.copyOf() ?: preparePayload(bundle, publicKeys, signer, device)
        try {
            require(payload.size in 1..MAX_CLAIM_RESPONSE) { "claim request exceeds one MiB" }
            if (retainedPayload == null) savePayload(payload)
            val original = JSONObject(payload.toString(StandardCharsets.UTF_8))
            require(original.getString("identity_public_key") == ENCODER.encodeToString(publicKeys.identityEd25519))
            require(original.getString("session_public_key") == ENCODER.encodeToString(publicKeys.noiseX25519))
            require(original.getString("wireguard_public_key") == ENCODER.encodeToString(publicKeys.wireguardX25519))
            val request = Request.Builder()
                .url(bundle.claimUrl.toURL())
                .post(payload.toRequestBody(JSON))
                .header("Accept", "application/json")
                .build()
            val raw = claimResponse(client, request, bundle, original, publicKeys, onPending)
            val verified = try {
                verifyEnrollmentResponse { enrollment.verifyResponse(
                    raw, bundle.rootFingerprint, publicKeys.identityEd25519, publicKeys.noiseX25519, publicKeys.wireguardX25519,
                ) }
            } finally {
                raw.fill(0)
            }
            val json = try {
                JSONObject(verified.toString(StandardCharsets.UTF_8))
            } finally {
                verified.fill(0)
            }
            val credential = DECODER.decode(json.getString("credential"))
            try {
                require(credential.size == 225 && credential[0].toInt() == 1) {
                    "claim returned a malformed Peer credential"
                }
                require(credential.matchesAt(33, publicKeys.identityEd25519)) {
                    "claim credential identity key does not match this device"
                }
                require(credential.matchesAt(65, publicKeys.noiseX25519)) {
                    "claim credential session key does not match this device"
                }
                require(credential.matchesAt(97, publicKeys.wireguardX25519)) {
                    "claim credential WireGuard key does not match this device"
                }
            } finally {
                credential.fill(0)
            }
            val relays = json.getJSONArray("relays")
            val authorityCertificates = json.getJSONArray("authority_certificates")
            val stunServers = json.getJSONArray("stun_servers")
            val routes = json.getJSONArray("routes")
            val dnsServers = json.getJSONArray("dns_servers")
            return PeerProfile(
                profileId = json.getString("profile_id"),
                deviceKeyId = deviceKeyId,
                meshId = json.getString("mesh_id"),
                peerId = json.getString("peer_id"),
                meshName = json.getString("mesh_name"),
                address = json.getString("address"),
                secondaryAddress = if (json.isNull("secondary_address")) null else json.getString("secondary_address"),
                dnsSuffix = json.getString("dns_suffix"),
                credential = json.getString("credential"),
                relays = List(relays.length()) { index ->
                    val relay = relays.getJSONObject(index)
                    val endpoints = relay.getJSONArray("endpoints")
                    RelayProfileTarget(
                        relayId = relay.getString("relay_id"),
                        endpoints = List(endpoints.length()) { endpoint -> endpoints.getString(endpoint) },
                        noisePublicKey = relay.getString("public_key"),
                    ).also { target ->
                        require(target.endpoints.size in 1..16 && target.endpoints.distinct().size == target.endpoints.size) {
                            "claim returned an invalid Relay endpoint set"
                        }
                    }
                },
                stunServers = List(stunServers.length()) { stunServers.getString(it) },
                natMapping = "auto",
                routes = List(routes.length()) { routes.getString(it) },
                dnsServers = List(dnsServers.length()) { dnsServers.getString(it) },
                mtu = json.getInt("mtu"),
                localIdentityPublic = ENCODER.encodeToString(publicKeys.identityEd25519),
                localNoisePublic = ENCODER.encodeToString(publicKeys.noiseX25519),
                localWireguardPublic = ENCODER.encodeToString(publicKeys.wireguardX25519),
                rootPublicKey = json.getString("root_public_key"),
                authorityCertificates = List(authorityCertificates.length()) { authorityCertificates.getString(it) },
                authorityRevision = json.getLong("authority_revision"),
                distributionPublicKey = json.getString("distribution_public_key"),
                servicePublicKey = json.getString("service_public_key"),
                auditPublicKey = json.getString("audit_public_key"),
                distributionCertificate = json.getString("distribution_certificate"),
            )
        } finally {
            payload.fill(0)
        }
    }

    private fun preparePayload(bundle: JoinBundle, publicKeys: PublicDeviceKeys, signer: ClaimIdentitySigner, device: ClaimDevice): ByteArray {
        val clientVersion = BuildConfig.VERSION_NAME
        val deviceName = device.name.takeUtf8(128)
        val deviceModel = device.model.takeUtf8(128)
        val platformVersion = device.platformVersion.takeUtf8(64)
        require(deviceName.isNotBlank()) { "invalid device name" }
        val draft = enrollment.prepare(
            bundle.claimUrl.toASCIIString(),
            publicKeys.identityEd25519,
            publicKeys.noiseX25519,
            publicKeys.wireguardX25519,
            clientVersion,
            bundle.nonce,
            deviceName,
            deviceModel,
            platformVersion,
        )
        return try {
            val transcript = enrollment.transcript(draft)
            val signature = try {
                signer.sign(transcript).also { require(it.size == 64) }
            } finally {
                transcript.fill(0)
            }
            try {
                enrollment.complete(draft, signature)
            } finally {
                signature.fill(0)
            }
        } finally {
            draft.fill(0)
        }
    }

    companion object {
        private val JSON = "application/json; charset=utf-8".toMediaType()
        private val ENCODER = Base64.getUrlEncoder().withoutPadding()
        private val DECODER = Base64.getUrlDecoder()
        private fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .callTimeout(20, TimeUnit.SECONDS)
            .followRedirects(false)
            .build()

        private fun protectedClient(
            protector: SocketProtector,
            dnsClient: ProtectedDnsClient,
        ): OkHttpClient = OkHttpClient.Builder()
            .socketFactory(ProtectingSocketFactory(protector))
            .dns(object : Dns {
                override fun lookup(hostname: String) = dnsClient.resolve(hostname)
            })
            .callTimeout(20, TimeUnit.SECONDS)
            .followRedirects(false)
            .build()
    }
}

private fun ByteArray.matchesAt(offset: Int, expected: ByteArray): Boolean =
    offset >= 0 && offset <= size - expected.size && expected.indices.all { this[offset + it] == expected[it] }

private fun String.takeUtf8(maxBytes: Int): String {
    require(maxBytes >= 0)
    val result = StringBuilder()
    var offset = 0
    var bytes = 0
    while (offset < length) {
        val next = offsetByCodePoints(offset, 1)
        val part = substring(offset, next)
        val partBytes = part.toByteArray(StandardCharsets.UTF_8).size
        if (bytes + partBytes > maxBytes) break
        result.append(part)
        bytes += partBytes
        offset = next
    }
    return result.toString()
}

internal fun readBoundedBytes(body: okhttp3.ResponseBody): ByteArray {
    val declared = body.contentLength()
    require(declared < 0 || declared <= MAX_CLAIM_RESPONSE) {
        "claim response exceeds one MiB"
    }
    var storage = ByteArray(declared.takeIf { it > 0 }?.toInt() ?: 8_192)
    val chunk = ByteArray(8_192)
    var size = 0
    try {
        body.byteStream().use { input ->
            while (true) {
                val count = input.read(chunk)
                if (count < 0) break
                require(size <= MAX_CLAIM_RESPONSE - count) {
                    "claim response exceeds one MiB"
                }
                val required = size + count
                if (required > storage.size) {
                    var capacity = storage.size.coerceAtLeast(1)
                    while (capacity < required) {
                        capacity = (capacity * 2).coerceAtMost(MAX_CLAIM_RESPONSE)
                    }
                    val replacement = ByteArray(capacity)
                    storage.copyInto(replacement, endIndex = size)
                    storage.fill(0)
                    storage = replacement
                }
                chunk.copyInto(storage, size, 0, count)
                size = required
            }
        }
        return storage.copyOf(size)
    } finally {
        chunk.fill(0)
        storage.fill(0)
    }
}
