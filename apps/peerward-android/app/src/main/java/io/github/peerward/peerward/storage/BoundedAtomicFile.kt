package io.github.peerward.peerward.storage

import android.util.AtomicFile

/** Reads one AtomicFile without allocating beyond its declared application bound. */
internal fun AtomicFile.readBounded(minBytes: Int, maxBytes: Int, label: String): ByteArray {
    require(minBytes >= 0 && maxBytes >= minBytes)
    return openRead().use { input ->
        val declared = input.channel.size()
        require(declared in minBytes.toLong()..maxBytes.toLong()) {
            "$label is outside its bound"
        }
        val bytes = ByteArray(declared.toInt())
        try {
            var offset = 0
            while (offset < bytes.size) {
                val count = input.read(bytes, offset, bytes.size - offset)
                if (count < 0) break
                offset += count
            }
            require(offset == bytes.size && input.read() == -1) {
                "$label changed while it was read"
            }
            bytes
        } catch (error: Throwable) {
            bytes.fill(0)
            throw error
        }
    }
}
