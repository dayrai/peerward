package io.github.peerward.peerward.join

import io.github.peerward.peerward.crypto.PublicDeviceKeys
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.time.Instant
import java.util.concurrent.TimeUnit

class EnrollmentFailure(val code: String) : IllegalStateException(code)

/** Only an exact authenticated claim is retried. Pending status is not a trust
 * bundle; final activation still passes through the Rust Root-chain verifier. */
internal fun claimResponse(
    client: OkHttpClient, request: Request, bundle: JoinBundle, original: JSONObject,
    keys: PublicDeviceKeys, onPending: (JSONObject) -> Unit,
    waitForRetry: () -> Unit = { Thread.sleep(5_000) },
): ByteArray {
    var deadline: Long? = null
    var applicationId: String? = null
    val started = System.nanoTime()
    while (true) {
        check(System.nanoTime() - started < TimeUnit.MINUTES.toNanos(31)) { "approval wait timed out; original claim retained" }
        check(deadline == null || Instant.now().epochSecond < deadline) { "approval expired; original claim retained" }
        client.newCall(request).execute().use { response ->
            val raw = readBoundedBytes(response.body ?: error("empty claim response"))
            if (response.code !in setOf(200, 201, 202)) {
                val code = try { runCatching { JSONObject(raw.toString(Charsets.UTF_8)).getJSONObject("error").getString("code") }.getOrNull() }
                    finally { raw.fill(0) }
                throw EnrollmentFailure(when (code) {
                    "application_rejected", "application_cancelled", "application_expired", "prebound_identity_mismatch", "state_conflict", "not_found" -> code
                    else -> "enrollment_failed_claim_retained"
                })
            }
            if (response.code != 202) return raw
            val pending = try { JSONObject(raw.toString(Charsets.UTF_8)).getJSONObject("application") }
                finally { raw.fill(0) }
            val id = java.util.UUID.fromString(pending.getString("id")).toString()
            require(applicationId == null || applicationId == id) { "approval application changed" }
            applicationId = id
            val expires = pending.getLong("expires_at")
            val created = pending.getLong("created_at")
            require(pending.getString("status") == "pending" && expires > created && expires - created <= 1800)
            require(deadline == null || deadline == expires) { "approval deadline changed" }
            require(pending.getString("claim_id") == original.getString("claim_id")) { "approval claim mismatch" }
            require(bundle.meshId == null || pending.getString("mesh_id") == bundle.meshId.toString()) { "approval Mesh mismatch" }
            require(pending.getString("identity_fingerprint") == PendingEnrollmentStore.digest(keys.identityEd25519)) { "approval identity mismatch" }
            deadline = expires
            onPending(pending)
        }
        waitForRetry()
    }
}
