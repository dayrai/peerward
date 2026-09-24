package io.github.peerward.peerward.nativecore

import android.os.ParcelFileDescriptor
import java.net.DatagramSocket
import java.util.concurrent.atomic.AtomicLong

/** The duplicate shares the STUN/data port; nonblocking writes stay inside the Rust guard. */
class NativeWireguardUdp(socket: DatagramSocket) : AutoCloseable {
    private val handle = AtomicLong(nativeCreate(
        ParcelFileDescriptor.fromDatagramSocket(socket).detachFd(),
    ).also { check(it > 0) })

    fun send(owner: NativeWireguardRuntime, ticket: Long): Boolean =
        nativeDeliver(handle.get().also { check(it > 0) }, owner.openHandle(), ticket)
            .also { if (it) owner.directPackets.incrementAndGet() }

    override fun close() {
        val value = handle.getAndSet(0)
        if (value > 0) nativeClose(value)
    }

    companion object {
        init { System.loadLibrary("peerward_android_core") }
        @JvmStatic private external fun nativeCreate(descriptor: Int): Long
        @JvmStatic private external fun nativeDeliver(handle: Long, owner: Long, ticket: Long): Boolean
        @JvmStatic private external fun nativeClose(handle: Long)
    }
}
