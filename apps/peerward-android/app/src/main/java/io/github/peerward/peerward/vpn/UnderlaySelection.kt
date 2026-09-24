package io.github.peerward.peerward.vpn

import android.net.NetworkCapabilities

/** Exclude IMS/MMS and VPN networks; Internet validation is a preference, not a Relay gate.
 * Private Relay networks may intentionally block Android's public connectivity probes. */
internal fun underlayPreference(capabilities: NetworkCapabilities): Int? {
    val transport = when {
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 3
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 2
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 1
        else -> 0
    }
    return underlayPreference(
        capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
        capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN),
        capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED), transport,
    )
}

internal fun underlayPreference(internet: Boolean, notVpn: Boolean, validated: Boolean, transport: Int): Int? =
    if (!internet || !notVpn) null else (if (validated) 4 else 0) + transport

/** All entries come from ordered capability callbacks, not synchronous callback-time queries.
 * Higher preference wins; equal-preference updates keep the current network to avoid churn. */
internal class UnderlaySelection<T> {
    private val available = linkedMapOf<T, Int>()
    var current: T? = null
        private set

    fun update(network: T, preference: Int?): T? {
        if (preference == null) available.remove(network) else available[network] = preference
        val highest = available.values.maxOrNull()
        current = if (highest == null) null else
            current?.takeIf { available[it] == highest }
                ?: available.entries.first { it.value == highest }.key
        return current
    }
}
