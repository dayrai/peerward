package io.github.peerward.peerward.profile

import android.content.Context
import android.util.AtomicFile
import io.github.peerward.peerward.crypto.DeviceKeyStore
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.UUID

/** Archives contain encrypted opaque configurations, never refreshed authorization leases. */
class ProfileCatalog(context: Context) {
    private val appContext = context.applicationContext
    private val profiles = ProfileStore(appContext)
    private val directory = File(appContext.noBackupFilesDir.canonicalFile, "saved-profiles-v4")

    fun list(): JSONArray = synchronized(LOCK) {
        val active = profiles.loadForRemoval()
        val entries = linkedMapOf<String, JSONObject>()
        archiveFiles().forEach { file ->
            val id = file.baseFile.name.removeSuffix(SUFFIX)
            if (id != active?.peerId) {
                entries[id] = runCatching {
                    val opaque = profiles.readArchive(file)
                    try {
                        val profile = profiles.materializeOpaque(opaque)
                        check(profile.peerId == id) { "saved_profile_identity_mismatch" }
                        describe(profile, false)
                    } finally { opaque.fill(0) }
                }.getOrElse {
                    JSONObject().put("peer_id", id).put("mesh_name", "")
                        .put("address", "").put("active", false).put("available", false)
                }
            }
        }
        active?.let { entries[it.peerId] = describe(it, true) }
        check(entries.size <= MAX_PROFILES) { "saved_profile_limit" }
        JSONArray(entries.values.sortedWith(compareBy({ it.getString("mesh_name") }, { it.getString("peer_id") })))
    }

    fun checkRoomForEnrollment() = synchronized(LOCK) {
        check(profiles.loadForRemoval() == null && archiveFiles().size < MAX_PROFILES) { "saved_profile_limit" }
    }

    /** Caller holds the stopped-runtime and enrollment barrier. */
    fun select(peerId: String) = synchronized(LOCK) {
        val active = profiles.loadForRemoval()
        if (active?.peerId == peerId) return@synchronized
        val opaque = profiles.readArchive(archiveFile(peerId))
        try {
            val target = profiles.materializeOpaque(opaque)
            check(target.peerId == peerId) { "saved_profile_identity_mismatch" }
            check(!profiles.isMeshTerminated(target.meshId)) { "mesh_deleted" }
            check(DeviceKeyStore(appContext).exists(target.deviceKeyId)) { "saved_profile_key_missing" }
            archiveActive()
            // The final atomic replacement is the selection commit. A crash before
            // it retains the original selection; afterwards only the target is active.
            profiles.replaceOpaque(opaque)
        } finally { opaque.fill(0) }
    }

    /** Saves the current network and opens the existing invitation flow. */
    fun deactivate() = synchronized(LOCK) {
        archiveActive()
        profiles.detachActive()
    }

    /** Removes an inactive catalog entry only. It cannot revoke remote access or
     * identify and delete keys from an unreadable archive. Trust history remains. */
    fun forget(peerId: String) = synchronized(LOCK) {
        check(profiles.loadForRemoval()?.peerId != peerId) { "saved_profile_is_active" }
        val archive = archiveFile(peerId)
        archive.delete()
        check(listOf(archive.baseFile, File(archive.baseFile.path + ".bak"), File(archive.baseFile.path + ".new")).none { it.exists() }) {
            "saved_profile_remove_failed"
        }
    }

    private fun archiveActive() {
        val active = profiles.loadForRemoval() ?: return
        val files = archiveFiles()
        check(files.size < MAX_PROFILES || files.any { it.baseFile == archiveFile(active.peerId).baseFile }) {
            "saved_profile_limit"
        }
        val opaque = requireNotNull(profiles.loadOpaque()) { "profile_missing" }
        try { profiles.archiveOpaque(archiveFile(active.peerId), opaque) }
        finally { opaque.fill(0) }
    }

    private fun describe(profile: PeerProfile, active: Boolean) = JSONObject()
        .put("peer_id", profile.peerId).put("mesh_name", profile.meshName)
        .put("address", profile.address).put("active", active)
        .put("available", !profiles.isMeshTerminated(profile.meshId) && DeviceKeyStore(appContext).exists(profile.deviceKeyId))

    internal fun deleteArchivedCopy(peerId: String) = synchronized(LOCK) { archiveFile(peerId).delete() }
    internal fun hasArchives(): Boolean = synchronized(LOCK) { archiveFiles().isNotEmpty() }

    private fun archiveFile(peerId: String): AtomicFile {
        require(UUID.fromString(peerId).toString() == peerId) { "saved_profile_identity_invalid" }
        check(directory.mkdirs() || directory.isDirectory) { "saved_profile_directory_unavailable" }
        check(directory.canonicalFile == directory.absoluteFile) { "saved_profile_directory_invalid" }
        val file = File(directory, "$peerId$SUFFIX")
        listOf(file, File(file.path + ".bak"), File(file.path + ".new")).forEach {
            check(it.canonicalFile == it.absoluteFile) { "saved_profile_file_invalid" }
        }
        return AtomicFile(file)
    }

    private fun archiveFiles(): List<AtomicFile> {
        if (!directory.exists()) return emptyList()
        check(directory.isDirectory && directory.canonicalFile == directory.absoluteFile) { "saved_profile_directory_invalid" }
        val files = requireNotNull(directory.listFiles()) { "saved_profile_directory_unavailable" }
        // AtomicFile may leave a backup after interruption. Opening its logical
        // base name lets Android recover it before reading the authenticated blob.
        val ids = files.map { it.name.removeSuffix(".bak").removeSuffix(".new") }
            .filter { it.endsWith(SUFFIX) }.distinct()
        check(ids.size <= MAX_PROFILES) { "saved_profile_limit" }
        return ids.map { name ->
            val result = archiveFile(name.removeSuffix(SUFFIX))
            check(result.baseFile.canonicalFile == result.baseFile.absoluteFile) { "saved_profile_file_invalid" }
            result
        }
    }

    companion object {
        private val LOCK = Any()
        private const val SUFFIX = ".aesgcm"
        private const val MAX_PROFILES = 32
    }
}
