package io.github.peerward.peerward

import android.app.Activity
import android.annotation.SuppressLint
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.TextView
import androidx.core.content.ContextCompat
import androidx.webkit.JavaScriptReplyProxy
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import io.github.peerward.peerward.crypto.DeviceKeyStore
import io.github.peerward.peerward.join.ClaimDevice
import io.github.peerward.peerward.join.ClaimIdentitySigner
import io.github.peerward.peerward.join.JoinBundle
import io.github.peerward.peerward.join.QrScanActivity
import io.github.peerward.peerward.join.TicketClaimer
import io.github.peerward.peerward.join.PendingEnrollmentStore
import io.github.peerward.peerward.nativecore.NativePlatformOperation
import io.github.peerward.peerward.nativecore.NativePlatformRequest
import io.github.peerward.peerward.profile.LegacyProfileUnsupportedException
import io.github.peerward.peerward.profile.ProfileStore
import io.github.peerward.peerward.runtime.MobileRuntimeSnapshot
import io.github.peerward.peerward.runtime.MobileRuntimeState
import io.github.peerward.peerward.vpn.PeerwardVpnService
import java.util.UUID
import kotlin.concurrent.thread
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import org.json.JSONObject

/** Android system bridge. Runtime state is delivered only through an origin-bound message port. */
class MainActivity : Activity() {
    private lateinit var webView: WebView
    private val activityScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var replyProxy: JavaScriptReplyProxy? = null
    private var pendingInvitation: String? = null
    private var pendingDiagnostics: String? = null
    private var pendingExportRequestId: String? = null
    private var pendingVpnPermission: NativePlatformRequest? = null
    private var pendingQrRequestId: String? = null

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        initializeRuntimeState()
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            setContentView(TextView(this).apply {
                setText(R.string.webview_message_bridge_required)
            })
            return
        }
        pendingInvitation = boundedInvitation(intent?.dataString)
        val loader = WebViewAssetLoader.Builder()
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()
        webView = WebView(this).apply {
            id = R.id.peerward_web_view
            settings.javaScriptEnabled = true
            settings.allowFileAccess = false
            settings.allowContentAccess = false
            webViewClient = object : WebViewClient() {
                override fun shouldInterceptRequest(view: WebView, request: WebResourceRequest) =
                    loader.shouldInterceptRequest(request.url)

                override fun shouldOverrideUrlLoading(
                    view: WebView,
                    request: WebResourceRequest,
                ): Boolean = request.url.scheme != "https" || request.url.host != APP_HOST
            }
        }
        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            WebViewCompat.addWebMessageListener(
                webView,
                BRIDGE_NAME,
                setOf(APP_ORIGIN),
            ) { _, message, sourceOrigin, isMainFrame, proxy ->
                if (isMainFrame && sourceOrigin.toString() == APP_ORIGIN) {
                    handleWebMessage(message.data, proxy)
                }
            }
        }
        setContentView(webView)
        webView.loadUrl("$APP_ORIGIN/assets/dioxus/index.html#/")
        activityScope.launch {
            MobileRuntimeState.snapshots.collectLatest { snapshot ->
                replyProxy?.let { postBridge(it, snapshot.envelopeJson()) }
            }
        }
        if (PeerwardVpnService.hasRemovalTombstone(this)) requestProfileRemoval()
    }

    override fun onResume() {
        super.onResume()
        PeerwardVpnService.refreshSystemProtection()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        pendingInvitation = boundedInvitation(intent.dataString)
        sendPendingInvitation()
    }

    @Deprecated("Android system VPN permission callback")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        when (requestCode) {
            VPN_PERMISSION_REQUEST -> {
                val accepted = pendingVpnPermission?.let {
                    MobileRuntimeState.platformResult(it, resultCode == RESULT_OK)
                } == true
                pendingVpnPermission = null
                if (accepted) {
                    if (resultCode == RESULT_OK) {
                        startVpn()
                    } else {
                        MobileRuntimeState.failed("vpn_permission_denied", true)
                    }
                }
            }
            DIAGNOSTICS_EXPORT_REQUEST -> completeDiagnosticsExport(resultCode, data?.data)
            QR_SCAN_REQUEST -> completeQrScan(resultCode, data)
        }
    }

    override fun onDestroy() {
        if (::webView.isInitialized &&
            WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)
        ) {
            WebViewCompat.removeWebMessageListener(webView, BRIDGE_NAME)
        }
        enrollmentThread?.interrupt()
        replyProxy = null
        activityScope.cancel()
        if (::webView.isInitialized) webView.destroy()
        super.onDestroy()
    }

    private fun initializeRuntimeState() {
        try {
            MobileRuntimeState.initialize(ProfileStore(this).load())
        } catch (_: LegacyProfileUnsupportedException) {
            MobileRuntimeState.initialize(null, legacyProfilePresent = true)
        }
    }

    private fun handleWebMessage(raw: String?, proxy: JavaScriptReplyProxy) {
        if (raw == null || raw.length > MAX_BRIDGE_MESSAGE_BYTES) return
        if (raw.toByteArray(Charsets.UTF_8).size > MAX_BRIDGE_MESSAGE_BYTES) return
        val message = runCatching { JSONObject(raw) }.getOrNull() ?: return
        if (message.optInt("version") != MobileRuntimeSnapshot.CONTRACT_VERSION) return
        val kind = message.optString("kind")
        val requestId = message.optString("request_id").takeIf { it.length in 1..128 }
        when (kind) {
            "subscribe" -> {
                replyProxy = proxy
                postBridge(proxy, MobileRuntimeState.snapshots.value.envelopeJson())
                sendPendingInvitation()
                showPendingEnrollment()
                sendSavedProfiles()
            }
            "saved_profiles" -> requestId?.let { sendSavedProfiles(); commandResult(it, true) }
            "select_profile", "save_and_add_network", "forget_saved_profile" -> requestId?.let { changeSavedProfile(it, kind, message.optJSONObject("payload")) }
            "connect" -> requestId?.let { requestConnect(it) }
            "disconnect" -> requestId?.let {
                startService(Intent(this, PeerwardVpnService::class.java).setAction(PeerwardVpnService.ACTION_STOP))
                commandResult(it, true)
            }
            "join" -> requestId?.let { id ->
                message.optJSONObject("payload")?.optString("invitation")
                    ?.let(::boundedInvitation)
                    ?.takeIf { it.startsWith("peerward://join?") }
                    ?.let { enroll(id, it) }
                    ?: commandResult(id, false, "invalid_invitation")
            }
            "prepare_join" -> requestId?.let { id ->
                if (ENROLLMENT_BUSY.compareAndSet(false, true)) thread(name = "peerward-prepare-enrollment") {
                    runCatching { check(ProfileStore(this).load() == null); PendingEnrollmentStore(this).prepare() }
                        .onSuccess { showPendingEnrollment(); webView.post { commandResult(id, true) } }
                        .onFailure { webView.post { commandResult(id, false, "enrollment_prepare_failed") } }
                    ENROLLMENT_BUSY.set(false)
                } else commandResult(id, false, "enrollment_in_progress")
            }
            "discard_join" -> requestId?.let { id ->
                if (message.optJSONObject("payload")?.optBoolean("confirm_discard") == true && ENROLLMENT_BUSY.compareAndSet(false, true)) {
                    runCatching { check(ProfileStore(this).load() == null); PendingEnrollmentStore(this).clear(deleteDeviceKeys = true) }
                        .onSuccess { showPendingEnrollment(); commandResult(id, true) }
                        .onFailure { commandResult(id, false, "enrollment_discard_failed") }
                    ENROLLMENT_BUSY.set(false)
                } else commandResult(id, false, "enrollment_in_progress")
            }
            "scan_join_qr" -> requestId?.let(::requestQrScan)
            "remove_profile", "clear_legacy" -> requestId?.let {
                requestProfileRemoval()
                commandResult(it, true)
            }
            "export_diagnostics" -> requestId?.let(::requestDiagnosticsExport)
            "client_preferences" -> requestId?.let { id ->
                val request = message.optJSONObject("payload") ?: return
                thread(name = "peerward-client-preferences") {
                    runCatching { PeerwardVpnService.clientPreferences(request) }
                        .onSuccess { webView.post { commandResult(id, true) } }
                        .onFailure { webView.post { commandResult(id, false, "client_change_rejected_refresh_preferences") } }
                }
            }
            "open_vpn_settings" -> requestId?.let { id ->
                val opened = runCatching { startActivity(Intent(android.provider.Settings.ACTION_VPN_SETTINGS)) }.isSuccess
                commandResult(id, opened, if (opened) null else "vpn_settings_unavailable")
            }
            "refresh_vpn_protection" -> requestId?.let {
                PeerwardVpnService.refreshSystemProtection()
                commandResult(it, true)
            }
        }
    }

    private fun boundedInvitation(raw: String?): String? = raw?.takeIf {
        it.isNotBlank() &&
            it.length <= MAX_INVITATION_BYTES &&
            it.toByteArray(Charsets.UTF_8).size <= MAX_INVITATION_BYTES
    }

    private fun requestConnect(requestId: String) {
        val profile = runCatching { ProfileStore(this).load() }.getOrNull()
        if (profile == null) {
            MobileRuntimeState.failed("profile_missing", false)
            commandResult(requestId, false, "profile_missing")
            return
        }
        val permission = VpnService.prepare(this)
        if (permission == null) {
            startVpn()
        } else {
            MobileRuntimeState.permissionRequired()
            pendingVpnPermission = MobileRuntimeState.platformRequest(
                NativePlatformOperation.VPN_PERMISSION,
            )
            @Suppress("DEPRECATION")
            startActivityForResult(permission, VPN_PERMISSION_REQUEST)
        }
        commandResult(requestId, true)
    }

    private fun startVpn() {
        val profile = runCatching { ProfileStore(this).load() }.getOrNull() ?: run {
            MobileRuntimeState.failed("profile_missing", false)
            return
        }
        MobileRuntimeState.starting(profile)
        ContextCompat.startForegroundService(
            this,
            Intent(this, PeerwardVpnService::class.java).setAction(PeerwardVpnService.ACTION_START),
        )
    }

    private var savedProfileReadSequence = 0L
    private fun sendSavedProfiles() {
        val sequence = ++savedProfileReadSequence
        thread(name = "peerward-saved-profiles") {
            val result = runCatching { io.github.peerward.peerward.profile.ProfileCatalog(this).list() }
            webView.post {
                if (sequence != savedProfileReadSequence) return@post
                result.onSuccess { entries ->
                    val envelope = JSONObject().put("version", MobileRuntimeSnapshot.CONTRACT_VERSION)
                        .put("kind", "saved_profiles").put("payload", entries).toString()
                    replyProxy?.let { postBridge(it, envelope) }
                }.onFailure { commandResult("saved-profiles", false, "saved_profiles_unavailable") }
            }
        }
    }

    private fun changeSavedProfile(requestId: String, kind: String, payload: JSONObject?) {
        // Activity and service start callbacks share the main Looper. The cleanup
        // barrier also waits for the old IO/rotation workers after service stop.
        if (pendingVpnPermission != null || !PeerwardVpnService.canChangeProfile()
            || PeerwardVpnService.hasRemovalTombstone(this)
            || !ENROLLMENT_BUSY.compareAndSet(false, true)) {
            commandResult(requestId, false, "profile_change_requires_stopped_runtime")
            return
        }
        try {
            check(PendingEnrollmentStore(this).load() == null) { "enrollment_in_progress" }
            val catalog = io.github.peerward.peerward.profile.ProfileCatalog(this)
            when (kind) {
                "select_profile" -> catalog.select(requireNotNull(payload).getString("peer_id"))
                "forget_saved_profile" -> {
                    check(payload?.optBoolean("confirm_forget") == true)
                    catalog.forget(requireNotNull(payload).getString("peer_id"))
                }
                "save_and_add_network" -> {
                    check(payload?.optBoolean("confirm_disconnect") == true)
                    catalog.deactivate()
                }
            }
            MobileRuntimeState.initialize(ProfileStore(this).load())
            sendSavedProfiles()
            commandResult(requestId, true)
        } catch (_: Exception) {
            commandResult(requestId, false, "saved_profile_change_failed")
        } finally { ENROLLMENT_BUSY.set(false) }
    }

    private fun requestProfileRemoval() {
        startService(
            Intent(this, PeerwardVpnService::class.java)
                .setAction(PeerwardVpnService.ACTION_STOP_AND_CLEAR),
        )
    }

    private var enrollmentThread: Thread? = null

    private fun showPendingEnrollment() {
        thread(name = "peerward-enrollment-status") {
            runCatching {
                val store = PendingEnrollmentStore(this)
                store.load()?.let { JSONObject().put("identity_fingerprint", store.fingerprint(it)).put("status", if (it.payload == null) "prepared" else "retained") }
                    ?: JSONObject().put("status", "none")
            }.onSuccess { payload -> webView.post { postEnrollmentStatus(payload) } }
        }
    }

    private fun postEnrollmentStatus(payload: JSONObject) {
        val message = JSONObject().put("version", MobileRuntimeSnapshot.CONTRACT_VERSION)
            .put("kind", "join_pending").put("payload", payload).toString()
        replyProxy?.let { postBridge(it, message) }
    }

    private fun enroll(requestId: String, invitation: String) {
        if (!ENROLLMENT_BUSY.compareAndSet(false, true)) { commandResult(requestId, false, "enrollment_in_progress"); return }
        enrollmentThread = thread(name = "peerward-enrollment") {
            val profiles = ProfileStore(this)
            var stage = "precondition"
            runCatching {
                check(profiles.load() == null) { "an active profile already exists" }
                io.github.peerward.peerward.profile.ProfileCatalog(this).checkRoomForEnrollment()
                stage = "invitation_parse"
                val pendingStore = PendingEnrollmentStore(this)
                val retained = pendingStore.load()
                val digest = PendingEnrollmentStore.digest(invitation.toByteArray(Charsets.UTF_8))
                check(retained?.invitationDigest == null || retained.invitationDigest == digest) { "another invitation has a retained claim" }
                val bundle = JoinBundle.parse(invitation, allowExpiredResume = retained?.payload != null)
                stage = "key_creation"
                val pending = retained ?: pendingStore.prepare()
                val keyId = pending.keyId
                val keys = DeviceKeyStore(this)
                val publicKeys = keys.create(keyId)
                stage = "ticket_claim"
                val profile = TicketClaimer().claim(
                    bundle,
                    keyId,
                    publicKeys,
                    ClaimIdentitySigner { transcript -> keys.sign(keyId, transcript) },
                    ClaimDevice(Build.MODEL.take(128), Build.MODEL.take(128), Build.VERSION.RELEASE),
                    retainedPayload = pending.payload,
                    savePayload = { payload -> pendingStore.save(pending.copy(invitationDigest = digest, payload = payload)) },
                    onPending = { status -> webView.post { postEnrollmentStatus(status) } },
                )
                stage = "profile_persistence"
                profiles.save(profile)
                stage = "runtime_initialization"
                MobileRuntimeState.initialize(profile)
                pendingStore.clear()
                webView.post { postEnrollmentStatus(JSONObject().put("status", "none")) }
            }.onSuccess {
                webView.post { commandResult(requestId, true) }
            }.onFailure { error ->
                val category = error.message?.takeIf { message ->
                    message.matches(Regex("enrollment_credential_[a-z_]+")) || message in setOf(
                        "credential validation failed", "wire protocol rejected input", "peer session state rejected input",
                        "native session state is invalid", "Noise handshake rejected input", "device key agreement failed",
                    )
                } ?: "unclassified"
                Log.w(LOG_TAG, "Enrollment failed at $stage (${error.javaClass.simpleName}; $category)")
                // A lost response may already have consumed the ticket. Keep original keys and claim.
                showPendingEnrollment()
                webView.post { commandResult(requestId, false, (error as? io.github.peerward.peerward.join.EnrollmentFailure)?.code ?: "enrollment_failed_claim_retained") }
            }
            ENROLLMENT_BUSY.set(false)
        }
    }

    private fun requestDiagnosticsExport(requestId: String) {
        pendingDiagnostics = MobileRuntimeState.diagnosticsJson()
        pendingExportRequestId = requestId
        @Suppress("DEPRECATION")
        startActivityForResult(
            Intent(Intent.ACTION_CREATE_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/json")
                .putExtra(Intent.EXTRA_TITLE, "peerward-diagnostics.json"),
            DIAGNOSTICS_EXPORT_REQUEST,
        )
    }

    private fun requestQrScan(requestId: String) {
        if (pendingQrRequestId != null) {
            commandResult(requestId, false, "qr_scan_in_progress")
            return
        }
        pendingQrRequestId = requestId
        @Suppress("DEPRECATION")
        startActivityForResult(Intent(this, QrScanActivity::class.java), QR_SCAN_REQUEST)
    }

    private fun completeQrScan(resultCode: Int, data: Intent?) {
        val requestId = pendingQrRequestId ?: return
        pendingQrRequestId = null
        val invitation = data?.getStringExtra(QrScanActivity.EXTRA_INVITATION)
        if (resultCode != RESULT_OK || invitation == null) {
            commandResult(
                requestId,
                false,
                data?.getStringExtra(QrScanActivity.EXTRA_ERROR) ?: "qr_scan_cancelled",
            )
            return
        }
        // The scanner only stages a validated invitation. Enrollment still requires a separate tap.
        pendingInvitation = invitation
        sendPendingInvitation()
        commandResult(requestId, true)
    }

    private fun completeDiagnosticsExport(resultCode: Int, destination: Uri?) {
        val requestId = pendingExportRequestId
        val body = pendingDiagnostics
        pendingExportRequestId = null
        pendingDiagnostics = null
        if (requestId == null) return
        if (resultCode != RESULT_OK || destination == null || body == null) {
            commandResult(requestId, false, "export_cancelled")
            return
        }
        val written = runCatching {
            contentResolver.openOutputStream(destination, "wt")?.use {
                it.write(body.toByteArray(Charsets.UTF_8))
            } ?: error("export destination unavailable")
        }.isSuccess
        commandResult(requestId, written, if (written) null else "export_failed")
    }

    private fun sendPendingInvitation() {
        val invitation = pendingInvitation ?: return
        val preview = runCatching { JoinBundle.parse(invitation) }.getOrNull()
        val payload = JSONObject().put("invitation", invitation)
        preview?.let { bundle ->
            val origin = "${bundle.claimUrl.scheme}://${bundle.claimUrl.authority}"
            val fingerprint = bundle.rootFingerprint
                .take(6)
                .joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
            payload
                .put("control_origin", origin)
                .put(
                    "mesh_summary",
                    bundle.meshId?.toString() ?: "Confirmed by Control during claim",
                )
                .put("ticket_summary", "$fingerprint… · expires ${bundle.expiresAt}")
        }
        val message = JSONObject()
            .put("version", MobileRuntimeSnapshot.CONTRACT_VERSION)
            .put("sequence", MobileRuntimeState.snapshots.value.sequence)
            .put("kind", "invitation")
            .put("payload", payload)
            .toString()
        replyProxy?.let { proxy ->
            postBridge(proxy, message)
            pendingInvitation = null
        }
    }

    private fun commandResult(requestId: String, success: Boolean, errorCode: String? = null) {
        val message = JSONObject()
            .put("version", MobileRuntimeSnapshot.CONTRACT_VERSION)
            .put("request_id", requestId)
            .put("kind", "command_result")
            .put("payload", JSONObject()
                .put("success", success)
                .put("error_code", errorCode ?: JSONObject.NULL))
            .toString()
        replyProxy?.let { postBridge(it, message) }
    }

    private fun postBridge(proxy: JavaScriptReplyProxy, message: String) {
        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER)) {
            proxy.postMessage(message)
        }
    }

    private companion object {
        val ENROLLMENT_BUSY = java.util.concurrent.atomic.AtomicBoolean(false)
        const val LOG_TAG = "PeerwardEnrollment"
        const val APP_HOST = "appassets.androidplatform.net"
        const val APP_ORIGIN = "https://$APP_HOST"
        const val BRIDGE_NAME = "peerwardNative"
        const val VPN_PERMISSION_REQUEST = 7001
        const val DIAGNOSTICS_EXPORT_REQUEST = 7002
        const val QR_SCAN_REQUEST = 7003
        const val MAX_BRIDGE_MESSAGE_BYTES = 64 * 1024
        const val MAX_INVITATION_BYTES = 16 * 1024
    }
}
