package io.github.peerward.peerward.vpn

import android.os.ParcelFileDescriptor
import io.github.peerward.peerward.nativecore.NativeTunPacketPump
import java.util.concurrent.atomic.AtomicReference

/** Readers hold native Arc references while a handover retires the old handle. */
internal class ReplaceableTun(descriptor: ParcelFileDescriptor, private val dns: List<String>, private val mtu: Int) : AutoCloseable {
    private val current = AtomicReference(NativeTunPacketPump(descriptor, dns, mtu))
    private var closed = false
    // If native allocation fails after Android establishes a new interface, keep
    // that interface open and blackhole traffic until a retry or explicit stop.
    private var blocked: ParcelFileDescriptor? = null

    fun get(): NativeTunPacketPump = current.get()
    fun isCurrent(tun: NativeTunPacketPump): Boolean = current.get() === tun

    @Synchronized fun replace(descriptor: ParcelFileDescriptor): Long {
        if (closed) { descriptor.close(); error("tunnel already stopped") }
        val previousBlocked = blocked
        blocked = descriptor
        previousBlocked?.close()
        val replacement = NativeTunPacketPump(ParcelFileDescriptor.dup(descriptor.fileDescriptor), dns, mtu)
        val previous = current.getAndSet(replacement)
        previous.close()
        blocked = null
        descriptor.close()
        return replacement.openHandle()
    }

    @Synchronized override fun close() {
        closed = true
        current.get().close()
        blocked?.close()
        blocked = null
    }
}
