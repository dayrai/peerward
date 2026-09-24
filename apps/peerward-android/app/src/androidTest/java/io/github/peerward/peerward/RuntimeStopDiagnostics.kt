package io.github.peerward.peerward

import androidx.test.core.app.ApplicationProvider
import io.github.peerward.peerward.vpn.PacketPump
import kotlinx.coroutines.Job
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.atomic.AtomicReference

/** Capture only this validation process when an otherwise short lifecycle test stalls. */
internal class RuntimeStopDiagnostics(private val pump: () -> PacketPump?) : AutoCloseable {
    val phase = AtomicReference("starting")
    private val observer = Thread({
        android.util.Log.i("PeerwardStop", "observer running")
        try { Thread.sleep(3_000) } catch (_: InterruptedException) { return@Thread }
        android.util.Log.i("PeerwardStop", "observer collecting")
        val field = PacketPump::class.java.getDeclaredField("job").apply { isAccessible = true }
        val job = pump()?.let { field.get(it) as? Job }
        fun jobs(owner: Job?, depth: Int = 0): JSONObject = JSONObject()
            .put("job", owner.toString())
            .put("children", JSONArray(if (depth >= 4) emptyList<JSONObject>() else
                owner?.children?.take(16)?.map { jobs(it, depth + 1) }?.toList().orEmpty()))
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val file = File(context.filesDir, "wireguard-stop-diagnostics.json")
        val report = JSONObject().put("phase", phase.get()).put("coroutines", jobs(job))
        file.writeText(report.toString())
        val threads = Thread.getAllStackTraces().entries.sortedBy { it.key.name }.take(64).map { (thread, stack) ->
            JSONObject().put("name", thread.name).put("state", thread.state.toString())
                .put("stack", JSONArray(stack.take(40).map { it.toString() }))
        }
        file.writeText(report.put("threads", JSONArray(threads)).toString())
    }, "peerward-stop-test-observer").apply { isDaemon = true; start() }

    override fun close() { observer.interrupt() }
}
