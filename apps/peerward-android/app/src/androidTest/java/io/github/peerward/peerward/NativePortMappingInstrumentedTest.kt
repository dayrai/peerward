package io.github.peerward.peerward

import androidx.test.ext.junit.runners.AndroidJUnit4
import io.github.peerward.peerward.nativecore.NativeMappingProtocol
import io.github.peerward.peerward.nativecore.NativePortMappingCodec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.net.InetAddress
import java.net.InetSocketAddress

@RunWith(AndroidJUnit4::class)
class NativePortMappingInstrumentedTest {
    private val internal = InetSocketAddress(InetAddress.getByName("192.0.2.10"), 41_000)

    @Test
    fun pcpCodecRetainsNonceAndExactInternalPort() {
        val nonce = ByteArray(12) { 9 }
        val request = NativePortMappingCodec.pcpRequest(internal, 600, nonce)
        assertArrayEquals(nonce, request.nonce)
        assertEquals(41_000, unsignedShort(request.payload, 40))

        val response = request.payload.copyOf().also {
            it[1] = 0x81.toByte()
            it[3] = 0
            writeInt(it, 4, 900)
            writeInt(it, 8, 55)
            it.fill(0, 12, 24)
            writeShort(it, 42, 42_000)
            val external = InetAddress.getByName("203.0.113.5").address
            it.fill(0, 44, 54)
            it[54] = 0xff.toByte()
            it[55] = 0xff.toByte()
            external.copyInto(it, 56)
        }
        val lease = NativePortMappingCodec.acceptPcp(internal, nonce, response)
        assertNotNull(lease)
        requireNotNull(lease)
        assertEquals(NativeMappingProtocol.PCP, lease.protocol)
        assertEquals(42_000, lease.external.port)
        assertEquals(900, lease.lifetimeSeconds)
        assertEquals(55, lease.epoch)
        val renewal = NativePortMappingCodec.pcpRequest(internal, 600, nonce, lease.external)
        assertEquals(42_000, unsignedShort(renewal.payload, 42))
        assertArrayEquals(nonce, renewal.nonce)
        assertArrayEquals(response.copyOfRange(44, 60), renewal.payload.copyOfRange(44, 60))
        assertNull(NativePortMappingCodec.acceptPcp(internal, ByteArray(12) { 8 }, response))
    }

    @Test
    fun natPmpCodecAndEpochRestartCheckAreStrict() {
        assertArrayEquals(byteArrayOf(0, 0), NativePortMappingCodec.natPmpPublicRequest())
        val publicResponse = ByteArray(12).also {
            it[1] = 128.toByte()
            writeInt(it, 4, 77)
            byteArrayOf(203.toByte(), 0, 113, 6).copyInto(it, 8)
        }
        val public = requireNotNull(NativePortMappingCodec.acceptNatPmpPublic(publicResponse))
        assertEquals(77, public.epoch)

        val request = NativePortMappingCodec.natPmpRequest(internal, 600)
        assertEquals(41_000, unsignedShort(request, 4))
        assertEquals(41_000, unsignedShort(request, 6))
        val response = ByteArray(16).also {
            it[1] = 129.toByte()
            writeInt(it, 4, 78)
            writeShort(it, 8, 41_000)
            writeShort(it, 10, 42_001)
            writeInt(it, 12, 600)
        }
        val lease = NativePortMappingCodec.acceptNatPmp(internal, public.address, response)
        assertEquals(42_001, requireNotNull(lease).external.port)
        val renewal = NativePortMappingCodec.natPmpRequest(internal, 600, 42_001)
        assertEquals(42_001, unsignedShort(renewal, 6))
        val deletion = NativePortMappingCodec.natPmpRequest(internal, 0, 42_001)
        assertEquals(41_000, unsignedShort(deletion, 4))
        assertEquals(0, unsignedShort(deletion, 6))
        assertFalse(NativePortMappingCodec.gatewayRestarted(77, 78))
        assertTrue(NativePortMappingCodec.gatewayRestarted(10_000, 3))
    }

    private fun unsignedShort(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private fun writeShort(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }

    private fun writeInt(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 24).toByte()
        bytes[offset + 1] = (value ushr 16).toByte()
        bytes[offset + 2] = (value ushr 8).toByte()
        bytes[offset + 3] = value.toByte()
    }
}
