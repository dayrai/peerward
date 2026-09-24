package io.github.peerward.peerward.vpn

/** A process-local observation, never a persisted promise about the system VPN lock. */
data class VpnProtection(
    val alwaysOn: Boolean? = null,
    val lockdown: Boolean? = null,
) {
    val state: String get() = when {
        alwaysOn == null || lockdown == null -> "unknown"
        alwaysOn && lockdown -> "system_locked"
        else -> "runtime_only"
    }
}

/** Unsupported APIs, vendor failures and inconsistent observations must not claim protection. */
internal fun observeVpnProtection(sdk: Int, query: () -> Pair<Boolean, Boolean>): VpnProtection {
    if (sdk < 29) return VpnProtection()
    return try {
        val (alwaysOn, lockdown) = query()
        if (lockdown && !alwaysOn) VpnProtection() else VpnProtection(alwaysOn, lockdown)
    } catch (_: Exception) {
        VpnProtection()
    }
}
