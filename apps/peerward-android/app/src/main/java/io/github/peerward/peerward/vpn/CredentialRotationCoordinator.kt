package io.github.peerward.peerward.vpn

import io.github.peerward.peerward.crypto.DeviceKeyStore
import io.github.peerward.peerward.nativecore.NativePlatformOperation
import io.github.peerward.peerward.nativecore.NativeProfileCodec
import io.github.peerward.peerward.profile.PeerProfile
import io.github.peerward.peerward.profile.ProfileStore
import io.github.peerward.peerward.runtime.MobileRuntimeState
import java.util.Base64

data class RotationMaterial(
    val requestId: ByteArray,
    val identityPublicKey: ByteArray,
    val sessionPublicKey: ByteArray,
    val wireguardPublicKey: ByteArray,
)

/** Executes Keystore and atomic-file requests emitted by Rust's rotation transaction. */
class CredentialRotationCoordinator(
    private val profiles: ProfileStore,
    private val keys: DeviceKeyStore,
    initial: PeerProfile,
    private val onTerminated: () -> Unit = {},
    private val onCommitted: (PeerProfile) -> Unit,
) {
    private var profile = initial

    @Synchronized
    fun assertMeshActive() { check(!profiles.isMeshTerminated(profile.meshId)) { "mesh_deleted" } }

    @Synchronized
    fun terminateMesh(signedRecord: ByteArray) {
        profiles.markMeshTerminated(profile.meshId, signedRecord)
        onTerminated()
    }

    @Synchronized
    fun pendingMaterial(): RotationMaterial {
        var opaque = requireNotNull(profiles.loadOpaque()) { "rotation profile is missing" }
        try {
            var plan = NativeProfileCodec.rotationPlan(opaque)
            plan.stagedProfile?.let { staged ->
                persist(staged)
                opaque.fill(0)
                opaque = requireNotNull(profiles.loadOpaque())
                plan = NativeProfileCodec.rotationPlan(opaque)
            }
            val publicKeys = keys.create(plan.keyId)
            val expectedIdentity = plan.expectedIdentity
            val expectedNoise = plan.expectedNoise
            val expectedWireguard = plan.expectedWireguard
            if (expectedIdentity == null || expectedNoise == null || expectedWireguard == null) {
                persist(
                    NativeProfileCodec.installRotationPublics(
                        opaque,
                        plan,
                        publicKeys.identityEd25519,
                        publicKeys.noiseX25519,
                        publicKeys.wireguardX25519,
                    ),
                )
            } else {
                require(expectedIdentity.contentEquals(publicKeys.identityEd25519)) {
                    "Rust-staged rotation identity changed"
                }
                require(expectedWireguard.contentEquals(publicKeys.wireguardX25519)) {
                    "Rust-staged rotation WireGuard key changed"
                }
                require(expectedNoise.contentEquals(publicKeys.noiseX25519)) {
                    "Rust-staged rotation session key changed"
                }
            }
            return RotationMaterial(
                plan.requestId,
                publicKeys.identityEd25519,
                publicKeys.noiseX25519,
                        publicKeys.wireguardX25519,
            )
        } finally {
            opaque.fill(0)
        }
    }

    /** Keystore signs only the Rust-canonical phase-one transcript. */
    @Synchronized
    fun signCurrent(transcript: ByteArray): ByteArray {
        val handle = keys.handle(profile.deviceKeyId)
        require(
            Base64.getUrlDecoder().decode(profile.localIdentityPublic)
                .contentEquals(handle.identityEd25519),
        ) { "active profile identity changed" }
        return keys.sign(profile.deviceKeyId, transcript)
    }

    /** Rust decodes the verified replacement; Kotlin only invokes the pending key. */
    @Synchronized
    fun acceptReplacement(update: ByteArray, wireguard: io.github.peerward.peerward.nativecore.NativeWireguardRuntime): ByteArray {
        val replacement = NativeProfileCodec.decodeRotationReplacement(update)
        try {
            val opaque = requireNotNull(profiles.loadOpaque()) { "rotation profile is missing" }
            try {
                val plan = NativeProfileCodec.rotationPlan(opaque)
                val expectedIdentity = requireNotNull(plan.expectedIdentity) {
                    "replacement has no staged identity"
                }
                val handle = keys.handle(plan.keyId)
                require(expectedIdentity.contentEquals(handle.identityEd25519)) {
                    "staged Keystore identity changed"
                }
                wireguard.stage(replacement.credential, handle)
                persist(NativeProfileCodec.stageRotationCredential(opaque, replacement.credential))
                return keys.sign(plan.keyId, replacement.activationTranscript)
            } finally {
                opaque.fill(0)
            }
        } finally {
            replacement.credential.fill(0)
            replacement.activationTranscript.fill(0)
        }
    }

    /** Rust produces the complete replacement profile; Kotlin performs one atomic write. */
    @Synchronized
    fun commitActivated(credential: ByteArray) {
        val opaque = requireNotNull(profiles.loadOpaque()) { "rotation profile is missing" }
        try {
            persist(NativeProfileCodec.commitRotation(opaque, credential))
        } finally {
            opaque.fill(0)
        }
        val updated = requireNotNull(profiles.load())
        if (updated == profile) return
        profile = updated
        onCommitted(updated)
    }

    /** Authority bytes were Root-verified in Rust before this platform write. */
    @Synchronized
    fun installAuthorities(revision: Long, certificates: List<ByteArray>) {
        val opaque = requireNotNull(profiles.loadOpaque()) { "profile is missing" }
        try {
            persist(NativeProfileCodec.installAuthorities(opaque, revision, certificates))
        } finally {
            opaque.fill(0)
        }
        profile = requireNotNull(profiles.load())
    }

    /** Rust selects the exact overlapped key and opaque cleanup profile. */
    @Synchronized
    fun authenticated(authenticated: PeerProfile) {
        val opaque = requireNotNull(profiles.loadOpaque()) { "rotation profile is missing" }
        val cleanup = try {
            NativeProfileCodec.cleanPreviousKey(opaque, authenticated.deviceKeyId)
        } finally {
            opaque.fill(0)
        }
        if (cleanup == null) return
        keys.delete(cleanup.keyId)
        persist(cleanup.cleanedProfile)
        profile = requireNotNull(profiles.load())
    }

    private fun persist(opaque: ByteArray) {
        val request = MobileRuntimeState.platformRequest(NativePlatformOperation.ATOMIC_PERSISTENCE)
        val result = runCatching { profiles.replaceOpaque(opaque) }
        MobileRuntimeState.platformResult(request, result.isSuccess)
        result.getOrThrow()
    }
}
