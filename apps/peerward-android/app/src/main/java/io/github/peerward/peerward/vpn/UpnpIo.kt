package io.github.peerward.peerward.vpn

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext

/** Socket ownership and an absolute deadline also cover trickling HTTP/SSDP replies. */
internal suspend fun <S : AutoCloseable, T> upnpBlocking(
    socket: S,
    timeoutMillis: Int,
    operation: (S) -> T,
): T {
    try {
        return withContext(Dispatchers.IO) {
            ConnectionDeadline(timeoutMillis.toLong()).use { deadline ->
                deadline.adopt(socket)
                suspendCancellableCoroutine { continuation ->
                    continuation.invokeOnCancellation { runCatching { socket.close() } }
                    continuation.resumeWith(runCatching {
                        continuation.context.ensureActive()
                        operation(socket)
                    })
                }
            }
        }
    } finally {
        runCatching { socket.close() }
    }
}
