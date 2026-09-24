package io.github.peerward.peerward.vpn

import java.io.BufferedInputStream
import java.nio.charset.StandardCharsets

internal data class UpnpHttpResponse(val status: Int, val body: ByteArray)

/** Bounded HTTP parser shared by the UPnP description and SOAP requests. */
internal object UpnpHttp {
    private const val MAX_HTTP_HEADER = 16_384
    private const val MAX_HTTP_BODY = 262_144

    fun readResponse(input: BufferedInputStream): UpnpHttpResponse {
        val header = readHeader(input)
        val lines = header.split("\r\n")
        val status = lines.firstOrNull()?.split(' ')?.getOrNull(1)?.toIntOrNull()
            ?: error("invalid UPnP HTTP status")
        val headers = lines.drop(1).associate { line ->
            val separator = line.indexOf(':')
            require(separator > 0)
            line.substring(0, separator).trim().lowercase() to line.substring(separator + 1).trim()
        }
        val body = when {
            headers["transfer-encoding"]?.equals("chunked", ignoreCase = true) == true -> readChunks(input)
            headers["content-length"] != null -> {
                val length = headers.getValue("content-length").toInt()
                require(length in 0..MAX_HTTP_BODY)
                readExact(input, length)
            }
            else -> readToEnd(input)
        }
        return UpnpHttpResponse(status, body)
    }

    private fun readHeader(input: BufferedInputStream): String {
        val bytes = ArrayList<Byte>()
        while (bytes.size < MAX_HTTP_HEADER) {
            val value = input.read()
            require(value >= 0)
            bytes += value.toByte()
            if (bytes.size >= 4 && bytes.takeLast(4) == listOf<Byte>(13, 10, 13, 10)) {
                return bytes.dropLast(4).toByteArray().toString(StandardCharsets.US_ASCII)
            }
        }
        error("UPnP HTTP header exceeds bound")
    }

    private fun readChunks(input: BufferedInputStream): ByteArray {
        val output = ArrayList<Byte>()
        while (true) {
            val size = readAsciiLine(input).substringBefore(';').trim().toInt(16)
            require(size >= 0 && size <= MAX_HTTP_BODY - output.size)
            if (size == 0) {
                var trailerBytes = 0
                while (true) {
                    val line = readAsciiLine(input)
                    trailerBytes += line.length + 2
                    require(trailerBytes <= MAX_HTTP_HEADER)
                    if (line.isEmpty()) break
                }
                return output.toByteArray()
            }
            repeat(size) { output += input.read().also { require(it >= 0) }.toByte() }
            require(input.read() == 13 && input.read() == 10)
        }
    }

    private fun readAsciiLine(input: BufferedInputStream): String {
        val bytes = ArrayList<Byte>()
        while (bytes.size < MAX_HTTP_HEADER) {
            val value = input.read()
            require(value >= 0)
            if (value == 13) {
                require(input.read() == 10)
                return bytes.toByteArray().toString(StandardCharsets.US_ASCII)
            }
            bytes += value.toByte()
        }
        error("UPnP HTTP line exceeds bound")
    }

    private fun readToEnd(input: BufferedInputStream): ByteArray {
        val output = ArrayList<Byte>()
        while (true) {
            val value = input.read()
            if (value < 0) return output.toByteArray()
            require(output.size < MAX_HTTP_BODY)
            output += value.toByte()
        }
    }

    private fun readExact(input: BufferedInputStream, length: Int): ByteArray {
        val bytes = ByteArray(length)
        var offset = 0
        while (offset < length) {
            val read = input.read(bytes, offset, length - offset)
            require(read > 0)
            offset += read
        }
        return bytes
    }

}
