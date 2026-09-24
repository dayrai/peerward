package io.github.peerward.peerward.join

import io.github.peerward.peerward.nativecore.PeerwardNativeException

/** Re-check the same signed response with the real wall clock. A just-issued
 * credential may precede the device clock by a fraction of a second. Never
 * advance the verification clock, change not-before, or accept an invalid chain. */
internal fun verifyEnrollmentResponse(
    waitForRetry: () -> Unit = { Thread.sleep(500) },
    verify: () -> ByteArray,
): ByteArray {
    repeat(7) { attempt ->
        try { return verify() }
        catch (error: PeerwardNativeException) {
            if (error.message != "enrollment_credential_outside_validity") throw error
            if (attempt == 6) throw EnrollmentFailure("enrollment_credential_outside_validity")
            waitForRetry()
        }
    }
    error("bounded verification exhausted")
}
