package io.github.peerward.peerward.join

import io.github.peerward.peerward.nativecore.PeerwardNativeException
import org.junit.Assert.*
import org.junit.Test

class EnrollmentVerificationTest {
    @Test fun acceptsOnlyAfterRealVerificationSucceeds() {
        var attempts = 0
        var waits = 0
        val verified = verifyEnrollmentResponse({ waits++ }) {
            if (attempts++ == 0) throw PeerwardNativeException("enrollment_credential_outside_validity")
            byteArrayOf(1, 2, 3)
        }
        assertArrayEquals(byteArrayOf(1, 2, 3), verified)
        assertEquals(1, waits)
        assertEquals(2, attempts)
    }
    @Test fun expiredOrFarFutureCredentialsRemainRejected() {
        var attempts = 0
        val error = assertThrows(EnrollmentFailure::class.java) {
            verifyEnrollmentResponse({}) {
                attempts++
                throw PeerwardNativeException("enrollment_credential_outside_validity")
            }
        }
        assertEquals("enrollment_credential_outside_validity", error.code)
        assertEquals(7, attempts)
    }
    @Test fun otherValidationErrorsNeverRetry() {
        var attempts = 0
        assertThrows(PeerwardNativeException::class.java) {
            verifyEnrollmentResponse({ fail("must not retry") }) {
                attempts++
                throw PeerwardNativeException("credential validation failed")
            }
        }
        assertEquals(1, attempts)
    }
}
