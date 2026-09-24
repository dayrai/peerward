package io.github.peerward.peerward.vpn

/** Prefix subtraction works on API 28 too; never fall back to a missing family. */
internal fun exitCapture(exceptions: List<String>): List<String> {
    require(exceptions.size <= 32)
    var prefixes = listOf(NetworkPrefix.parse("0.0.0.0/0"), NetworkPrefix.parse("::/0"))
    for (text in exceptions.distinct()) {
        val exception = NetworkPrefix.parse(text)
        require(exception.bits > 0)
        val remaining = mutableListOf<NetworkPrefix>()
        val work = java.util.ArrayDeque(prefixes)
        while (work.isNotEmpty()) {
            val candidate = work.removeFirst()
            when {
                exception.contains(candidate) -> Unit
                candidate.contains(exception) -> candidate.children().forEach(work::addLast)
                else -> remaining += candidate
            }
            require(remaining.size + work.size <= 256) { "too_many_local_exceptions" }
        }
        prefixes = remaining
    }
    return prefixes.map { it.toString() }.sorted()
}
