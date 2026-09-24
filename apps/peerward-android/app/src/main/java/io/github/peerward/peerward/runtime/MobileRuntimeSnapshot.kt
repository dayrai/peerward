package io.github.peerward.peerward.runtime

import android.os.SystemClock
import io.github.peerward.peerward.vpn.VpnProtection
import io.github.peerward.peerward.profile.PeerProfile
import io.github.peerward.peerward.nativecore.NativeLifecycleStatus
import io.github.peerward.peerward.nativecore.NativePlatformOperation
import io.github.peerward.peerward.nativecore.NativePlatformRequest
import io.github.peerward.peerward.nativecore.NativeRuntimeCoordinator
import io.github.peerward.peerward.nativecore.NativeRuntimePhase
import io.github.peerward.peerward.nativecore.NativeRuntimeSchedule
import io.github.peerward.peerward.nativecore.NativeRuntimeStatus
import io.github.peerward.peerward.vpn.TunnelHealth
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import org.json.JSONArray
import org.json.JSONObject
import java.time.Instant

enum class ConnectionPhase(val wireName: String) {
    STOPPED("stopped"),
    PERMISSION_REQUIRED("permission_required"),
    STARTING("starting"),
    CONNECTING("connecting"),
    HEALTHY("healthy"),
    DEGRADED("degraded"),
    RECONNECTING("reconnecting"),
    STOPPING("stopping"),
    FAILED("failed"),
}

data class RuntimeError(val code: String, val retryable: Boolean)

data class MobileRuntimeSnapshot(
    val sequence: Long,
    val profile: PeerProfile?,
    val connection: ConnectionPhase,
    val rustRuntimeRunning: Boolean,
    val tunOpen: Boolean,
    val packetPumpRunning: Boolean,
    val relayAuthenticated: Boolean,
    val standbyRelayCount: Int,
    val directPeerCount: Int,
    val signedStateRevision: Long,
    val signedStateComplete: Boolean,
    val rotationState: String,
    val lastError: RuntimeError?,
    val legacyProfilePresent: Boolean,
    val relayCarrier: String? = null,
    val vpnProtection: VpnProtection = VpnProtection(),
    val clientPreferences: String? = null,
    val observedAt: Long? = null,
    val diagnostics: String = "[]",
) {
    fun envelopeJson(): String = JSONObject()
        .put("version", CONTRACT_VERSION)
        .put("sequence", sequence)
        .put("kind", "snapshot")
        .put("payload", payloadJson())
        .toString()

    fun payloadJson(): JSONObject = JSONObject()
        .put("observed_at", observedAt ?: JSONObject.NULL)
        .put("diagnostics", JSONArray(diagnostics))
        .put("profile", profile?.let {
            JSONObject()
                .put("mesh_name", it.meshName)
                .put("address", it.address)
                .put("peer_id", it.peerId)
        } ?: JSONObject.NULL)
        .put("connection", connection.wireName)
        .put("tasks", JSONObject()
            .put("rust_runtime", rustRuntimeRunning)
            .put("tun_open", tunOpen)
            .put("packet_pump_running", packetPumpRunning))
        .put("relays", JSONObject()
            .put("primary_authenticated", relayAuthenticated)
            .put("carrier", relayCarrier ?: JSONObject.NULL)
            .put("standby_count", standbyRelayCount))
        .put("direct_peer_count", directPeerCount)
        .put("signed_state", JSONObject()
            .put("revision", signedStateRevision)
            .put("complete", signedStateComplete))
        .put("rotation", JSONObject().put("state", rotationState))
        .put("last_error", lastError?.let {
            JSONObject().put("code", it.code).put("retryable", it.retryable)
        } ?: JSONObject.NULL)
        .put("legacy_profile_present", legacyProfilePresent)
        .put("client_preferences", clientPreferences?.let(::JSONObject) ?: JSONObject.NULL)
        .put("vpn_protection", JSONObject()
            .put("state", vpnProtection.state)
            .put("always_on", vpnProtection.alwaysOn ?: JSONObject.NULL)
            .put("lockdown", vpnProtection.lockdown ?: JSONObject.NULL))

    companion object {
        const val CONTRACT_VERSION = 1
    }
}

/** Process-local projection of authoritative runtime events for the Web UI. */
object MobileRuntimeState {
    private data class Transition(val elapsedMs: Long, val phase: ConnectionPhase, val error: String?)

    private val transitions = ArrayDeque<Transition>()
    private val coordinator = NativeRuntimeCoordinator()
    private var current = MobileRuntimeSnapshot(
        sequence = 0,
        profile = null,
        connection = ConnectionPhase.STOPPED,
        rustRuntimeRunning = false,
        tunOpen = false,
        packetPumpRunning = false,
        relayAuthenticated = false,
        standbyRelayCount = 0,
        directPeerCount = 0,
        signedStateRevision = 0,
        signedStateComplete = false,
        rotationState = "idle",
        lastError = null,
        legacyProfilePresent = false,
    )
    private val mutableSnapshots = MutableStateFlow(current)
    val snapshots: StateFlow<MobileRuntimeSnapshot> = mutableSnapshots

    @Synchronized
    fun preferencesObserved(view: JSONObject?) {
        val next = view?.toString()
        if (current.clientPreferences == next) return
        current = current.copy(clientPreferences = next)
        refreshObservedRuntime(preserveObservation = true)
    }

    @Synchronized
    fun protectionObserved(protection: VpnProtection) {
        if (current.vpnProtection == protection) return
        current = current.copy(vpnProtection = protection)
        refreshObservedRuntime(preserveObservation = true)
    }

    @Synchronized
    fun initialize(profile: PeerProfile?, legacyProfilePresent: Boolean = false) {
        publishNative(
            current.copy(
                profile = profile,
                clientPreferences = null,
                rotationState = if (profile?.pendingRotationId == null) "idle" else "pending",
                legacyProfilePresent = legacyProfilePresent,
            ),
            coordinator.reset(),
            if (legacyProfilePresent) RuntimeError("legacy_profile_unsupported", false) else null,
        )
    }

    @Synchronized
    fun permissionRequired() = publishNative(current, coordinator.permissionRequired())

    @Synchronized
    fun starting(profile: PeerProfile) {
        initialize(profile)
        publishNative(current, coordinator.startRequested())
    }

    @Synchronized
    fun tunnelEstablished() = publishNative(current, coordinator.tunOpened())

    @Synchronized
    fun underlayRestored() = publishNative(current, coordinator.underlayRestored())

    @Synchronized
    fun fromTunnelHealth(health: TunnelHealth) {
        when (health) {
            TunnelHealth.STOPPED -> stopped()
            TunnelHealth.CONNECTING -> publishNative(current, coordinator.connecting())
            TunnelHealth.RECONNECTING -> publishNative(
                current,
                coordinator.transportLost(),
                RuntimeError("relay_reconnecting", true),
            )
            // These transport summaries carry no new evidence. The native status callback
            // already published the authoritative facts and any typed failure.
            TunnelHealth.DEGRADED, TunnelHealth.HEALTHY -> Unit
        }
    }

    @Synchronized
    fun fromNativeRuntimeStatus(status: NativeRuntimeStatus) {
        val terminal = current.connection in setOf(
            ConnectionPhase.STOPPED, ConnectionPhase.STOPPING,
            ConnectionPhase.PERMISSION_REQUIRED, ConnectionPhase.FAILED,
        )
        val native = coordinator.observe(status)
        publishNative(
            current.copy(relayCarrier = status.relayCarrier?.takeIf { it in setOf("quic", "wss", "tcp") }),
            native,
            if (terminal) {
                current.lastError
            } else if (status.diagnosticCode != null) {
                RuntimeError(status.diagnosticCode, true)
            } else if (native.phase == NativeRuntimePhase.DEGRADED) {
                RuntimeError("signed_state_incomplete", false)
            } else {
                null
            },
            if (terminal) current.observedAt else status.diagnosticObservedAt ?: Instant.now().epochSecond,
        )
    }

    @Synchronized
    fun reconnecting(code: String = "underlay_unavailable") = publishNative(
        current,
        coordinator.underlayLost(),
        RuntimeError(code, true),
    )

    @Synchronized
    fun stopping() = publishNative(current, coordinator.stopRequested())

    @Synchronized
    fun failed(code: String, retryable: Boolean) = publishNative(
        current,
        coordinator.failed(),
        RuntimeError(code, retryable),
    )

    @Synchronized
    fun stopped() = publishNative(current.copy(clientPreferences = null), coordinator.stopped())

    @Synchronized
    fun platformRequest(operation: NativePlatformOperation): NativePlatformRequest =
        coordinator.request(operation)

    @Synchronized
    fun platformResult(request: NativePlatformRequest, success: Boolean): Boolean =
        coordinator.complete(request, success)

    @Synchronized
    fun schedule(status: NativeRuntimeStatus): NativeRuntimeSchedule =
        coordinator.schedule(SystemClock.elapsedRealtime(), status)

    @Synchronized
    fun diagnosticsJson(): String {
        val transitionJson = JSONArray()
        transitions.forEach { item ->
            transitionJson.put(
                JSONObject()
                    .put("elapsed_ms", item.elapsedMs)
                    .put("phase", item.phase.wireName)
                    .put("error_code", item.error ?: JSONObject.NULL),
            )
        }
        return JSONObject()
            .put("schema_version", 1)
            .put("contract_version", MobileRuntimeSnapshot.CONTRACT_VERSION)
            .put("snapshot_sequence", current.sequence)
            .put("observed_at", current.observedAt ?: JSONObject.NULL)
            .put("diagnostics", JSONArray(current.diagnostics))
            .put("connection", current.connection.wireName)
            .put("tasks", JSONObject()
                .put("rust_runtime", current.rustRuntimeRunning)
                .put("tun_open", current.tunOpen)
                .put("packet_pump_running", current.packetPumpRunning))
            .put("relay", JSONObject()
                .put("primary", if (current.relayAuthenticated) "relay-1" else JSONObject.NULL)
                .put("standby_count", current.standbyRelayCount))
            .put("direct_peer_count", current.directPeerCount)
            .put("signed_state", JSONObject()
                .put("revision", current.signedStateRevision)
                .put("complete", current.signedStateComplete))
            .put("rotation_state", current.rotationState)
            .put("last_error", current.lastError?.let {
                JSONObject().put("code", it.code).put("retryable", it.retryable)
            } ?: JSONObject.NULL)
            .put("state_transitions", transitionJson)
            .toString(2)
    }

    private fun refreshObservedRuntime(preserveObservation: Boolean = false) {
        val status = NativeRuntimeStatus(
                signedStateComplete = current.signedStateComplete,
                signedRevision = current.signedStateRevision,
                directPathCount = current.directPeerCount,
                primaryRelayAuthenticated = current.relayAuthenticated,
                standbyRelayCount = current.standbyRelayCount,
                relayCarrier = current.relayCarrier,
            )
        if (preserveObservation) {
            // A preference render is not new network evidence and cannot clear a failure.
            publishNative(current, coordinator.observe(status), current.lastError, current.observedAt)
        } else {
            fromNativeRuntimeStatus(status)
        }
    }

    private fun publishNative(
        snapshot: MobileRuntimeSnapshot,
        native: NativeLifecycleStatus,
        error: RuntimeError? = null,
        observedAt: Long? = Instant.now().epochSecond,
    ) {
        val observedError = error.takeUnless {
            native.phase == NativeRuntimePhase.STOPPED || native.phase == NativeRuntimePhase.STOPPING
        }
        current = snapshot.copy(
            sequence = native.sequence,
            connection = native.phase.toConnectionPhase(),
            rustRuntimeRunning = native.rustRuntimeRunning,
            tunOpen = native.tunOpen,
            packetPumpRunning = native.packetPumpRunning,
            relayAuthenticated = native.primaryRelayAuthenticated,
            relayCarrier = snapshot.relayCarrier.takeIf { native.primaryRelayAuthenticated },
            standbyRelayCount = native.standbyRelayCount,
            directPeerCount = native.directPathCount,
            signedStateRevision = native.signedStateRevision,
            signedStateComplete = native.signedStateComplete,
            lastError = observedError,
            observedAt = observedAt,
            diagnostics = if (observedAt == null) "[]" else coordinator.diagnostics(observedAt, observedError?.code),
        )
        transitions.addLast(
            Transition(SystemClock.elapsedRealtime(), current.connection, current.lastError?.code),
        )
        while (transitions.size > MAX_TRANSITIONS) transitions.removeFirst()
        mutableSnapshots.value = current
    }

    private const val MAX_TRANSITIONS = 64
}

private fun NativeRuntimePhase.toConnectionPhase(): ConnectionPhase = when (this) {
    NativeRuntimePhase.STOPPED -> ConnectionPhase.STOPPED
    NativeRuntimePhase.PERMISSION_REQUIRED -> ConnectionPhase.PERMISSION_REQUIRED
    NativeRuntimePhase.STARTING -> ConnectionPhase.STARTING
    NativeRuntimePhase.CONNECTING -> ConnectionPhase.CONNECTING
    NativeRuntimePhase.HEALTHY -> ConnectionPhase.HEALTHY
    NativeRuntimePhase.DEGRADED -> ConnectionPhase.DEGRADED
    NativeRuntimePhase.RECONNECTING -> ConnectionPhase.RECONNECTING
    NativeRuntimePhase.STOPPING -> ConnectionPhase.STOPPING
    NativeRuntimePhase.FAILED -> ConnectionPhase.FAILED
}
