package io.github.peerward.peerward.vpn

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.net.SocketTimeoutException

/** Interrupts native blocking handshake I/O, including the Java-to-Rust FD handoff. */
internal class ConnectionDeadline(milliseconds: Long) : AutoCloseable {
    private var target: AutoCloseable? = null
    private var expired = false
    private val task = scope.launch {
        delay(milliseconds)
        abort()
    }

    fun abort() {
        val closing = synchronized(this) { expired = true; target.also { target = null } }
        runCatching { closing?.close() }
    }

    @Synchronized
    fun adopt(value: AutoCloseable) {
        if (expired) {
            value.close()
            throw SocketTimeoutException("Relay authentication deadline expired")
        }
        target = value
    }

    override fun close() {
        task.cancel()
        synchronized(this) { target = null }
    }

    private companion object {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    }
}
