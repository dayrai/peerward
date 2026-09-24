package io.github.peerward.peerward.vpn

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class UpnpIoTest {
    @Test fun cancellationClosesTheBlockedSocketAndReleasesItsWorker() = runBlocking {
        ServerSocket(0).use { server ->
            val socket = Socket("127.0.0.1", server.localPort)
            server.accept().use {
                val entered = CompletableDeferred<Unit>()
                val released = CountDownLatch(1)
                val job = launch {
                    upnpBlocking(socket, 10_000) {
                        entered.complete(Unit)
                        try { it.getInputStream().read() } finally { released.countDown() }
                    }
                }
                withTimeout(2_000) { entered.await(); job.cancelAndJoin() }
                assertTrue(socket.isClosed)
                assertTrue(released.await(2, TimeUnit.SECONDS))
            }
        }
    }

    @Test fun absoluteDeadlineBoundsAnUnresponsiveGateway() = runBlocking {
        ServerSocket(0).use { server ->
            val socket = Socket("127.0.0.1", server.localPort)
            server.accept().use {
                withTimeout(2_000) {
                    val result = runCatching { upnpBlocking(socket, 100) { it.getInputStream().read() } }
                    assertTrue(result.isFailure || result.getOrNull() == -1)
                }
                assertTrue(socket.isClosed)
            }
        }
    }
}
