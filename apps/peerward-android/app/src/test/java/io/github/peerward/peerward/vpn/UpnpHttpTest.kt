package io.github.peerward.peerward.vpn

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.InputStream

class UpnpHttpTest {
    @Test fun readsFixedAndChunkedBodies() {
        val fixed = parse("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc")
        assertEquals(200, fixed.status)
        assertArrayEquals("abc".toByteArray(), fixed.body)
        val chunked = parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n2\r\nbc\r\n0\r\nX-End: yes\r\n\r\n")
        assertArrayEquals(fixed.body, chunked.body)
    }

    @Test fun rejectsOverflowingChunkBeforeReadingOrAllocatingItsBody() {
        val prefix = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n7fffffff\r\n".toByteArray()
        val source = object : InputStream() {
            var offset = 0
            override fun read(): Int {
                check(offset < prefix.size) { "rejected chunk body must never be read" }
                return prefix[offset++].toInt() and 255
            }
            override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
                if (length == 0) return 0
                bytes[offset] = read().toByte()
                return 1
            }
        }
        assertThrows(IllegalArgumentException::class.java) { UpnpHttp.readResponse(BufferedInputStream(source)) }
    }

    @Test fun boundsTotalTrailerBytesAcrossManySmallLines() {
        val trailers = "X-Padding: abcdefghijklmnop\r\n".repeat(1_000)
        assertThrows(IllegalArgumentException::class.java) {
            parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n$trailers\r\n")
        }
    }

    private fun parse(response: String): UpnpHttpResponse = UpnpHttp.readResponse(
        BufferedInputStream(ByteArrayInputStream(response.toByteArray(Charsets.US_ASCII))),
    )
}
