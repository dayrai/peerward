package io.github.peerward.peerward.vpn

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicInteger

/** Service destruction must not allow an old rotation writer to race profile selection. */
internal object RuntimeCleanup {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val remaining = AtomicInteger(0)
    fun pending(): Boolean = remaining.get() != 0

    fun track(startup: Job?, pump: PacketPump?, transport: WireguardTransport?) {
        if (startup == null && pump == null && transport == null) return
        remaining.incrementAndGet()
        scope.launch {
            try {
                startup?.join()
                pump?.awaitStopped()
                transport?.awaitStopped()
            } finally { remaining.decrementAndGet() }
        }
    }
}
