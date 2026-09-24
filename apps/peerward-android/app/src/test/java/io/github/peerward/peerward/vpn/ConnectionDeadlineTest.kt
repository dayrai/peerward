package io.github.peerward.peerward.vpn

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class ConnectionDeadlineTest {
    @Test
    fun cancellationAbortsBlockingAuthenticationAndClosesItsLateResult() = runBlocking {
        val entered = CompletableDeferred<Unit>()
        val abandoned = CompletableDeferred<Unit>()
        val unblocked = CountDownLatch(1)
        val job = launch(Dispatchers.IO) {
            carrierBlocking(AutoCloseable { unblocked.countDown() }, onAbandoned = { it: AutoCloseable -> it.close() }) {
                entered.complete(Unit)
                check(unblocked.await(2, TimeUnit.SECONDS))
                AutoCloseable { abandoned.complete(Unit) }
            }
        }
        withTimeout(2_000) { entered.await() }
        job.cancelAndJoin()
        withTimeout(2_000) { abandoned.await() }
    }

    @Test
    fun interruptsAConnectedSocketWhoseRelayNeverReplies() = runBlocking {
        ServerSocket(0).use { server ->
            Socket("127.0.0.1", server.localPort).use { socket ->
                server.accept().use {
                    ConnectionDeadline(100).use { deadline ->
                        deadline.adopt(socket)
                        withTimeout(2_000) {
                            val read = async(Dispatchers.IO) { runCatching { socket.getInputStream().read() } }
                            val result = read.await()
                            assertTrue(result.isFailure || result.getOrNull() == -1)
                        }
                    }
                }
            }
        }
    }

    @Test
    fun expiredDeadlineClosesTheNewOwnerDuringDescriptorHandoff() = runBlocking {
        val oldClosed = AtomicBoolean(false)
        val replacementClosed = AtomicBoolean(false)
        ConnectionDeadline(20).use { deadline ->
            deadline.adopt { oldClosed.set(true) }
            withTimeout(2_000) { while (!oldClosed.get()) kotlinx.coroutines.delay(5) }
            assertTrue(runCatching { deadline.adopt { replacementClosed.set(true) } }.isFailure)
            assertTrue(replacementClosed.get())
        }
    }
}
