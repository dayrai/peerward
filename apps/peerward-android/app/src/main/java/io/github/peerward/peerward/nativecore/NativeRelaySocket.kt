package io.github.peerward.peerward.nativecore

import android.os.ParcelFileDescriptor
import java.io.Closeable
import java.net.Socket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicLong

/** Owns one detached protected Relay socket FD and all blocking wire framing. */
class NativeRelaySocket private constructor(rawDescriptor: Int, endpoint: String, options: String, remote: String = "") : Closeable {
    // Native always consumes the descriptor, including failed upgrades.
    private val handle = AtomicLong(nativeCreate(rawDescriptor, endpoint, options, remote).also { check(it > 0) })

    fun connect() = nativeConnect(openHandle())

    fun activate(session: NativePeerCore, monotonicSeconds: Long) =
        nativeActivate(openHandle(), session.openHandle(), monotonicSeconds)

    /** Called only after Rust has verified the Root-signed terminal response. */
    fun acknowledgeTerminal() = nativeAcknowledgeTerminal(openHandle())

    fun writeHandshake(message: ByteArray) {
        require(message.size in 1..0xffff)
        nativeWriteHandshake(openHandle(), message)
    }

    fun readHandshake(): ByteArray = nativeReadHandshake(openHandle()).also {
        require(it.size in 1..0xffff)
    }

    fun writeFrame(frame: ByteArray) {
        require(frame.size in 5..MAX_FRAMED_BYTES)
        nativeWriteFrame(openHandle(), frame)
    }

    fun readFrame(): ByteArray = nativeReadFrame(openHandle()).also {
        require(it.size in 5..MAX_FRAMED_BYTES)
    }

    override fun close() {
        val value = handle.getAndSet(0)
        if (value > 0) nativeClose(value)
    }

    internal fun openHandle(): Long = handle.get().also { check(it > 0) }

    companion object {
        private const val MAX_FRAMED_BYTES = 65_535 + 4

        init {
            System.loadLibrary("peerward_android_core")
        }

        /** Transfers a duplicate of the connected socket FD to Rust, then closes Java ownership. */
        fun take(socket: Socket, endpoint: String = "", options: String = "{}"): NativeRelaySocket =
            prepare(socket, endpoint, options).also { try { it.connect() } catch (error: Exception) { it.close(); throw error } }

        fun prepare(socket: Socket, endpoint: String, options: String): NativeRelaySocket {
            val descriptor = ParcelFileDescriptor.fromSocket(socket)
            val rawDescriptor = descriptor.detachFd()
            socket.close()
            return NativeRelaySocket(rawDescriptor, endpoint, options)
        }

        fun take(socket: DatagramSocket, endpoint: String, options: String, remote: InetSocketAddress): NativeRelaySocket =
            prepare(socket, endpoint, options, remote).also { try { it.connect() } catch (error: Exception) { it.close(); throw error } }

        fun prepare(socket: DatagramSocket, endpoint: String, options: String, remote: InetSocketAddress): NativeRelaySocket {
            require(!remote.isUnresolved)
            val address = remote.address.hostAddress ?: error("missing QUIC address")
            val authority = if (address.contains(':')) "[$address]:${remote.port}" else "$address:${remote.port}"
            val descriptor = ParcelFileDescriptor.fromDatagramSocket(socket)
            val rawDescriptor = descriptor.detachFd()
            socket.close()
            return NativeRelaySocket(rawDescriptor, endpoint, options, authority)
        }

        @JvmStatic private external fun nativeCreate(descriptor: Int, endpoint: String, options: String, remote: String): Long
        @JvmStatic private external fun nativeConnect(handle: Long)
        @JvmStatic private external fun nativeActivate(handle: Long, session: Long, monotonicSeconds: Long)
        @JvmStatic private external fun nativeAcknowledgeTerminal(handle: Long)
        @JvmStatic private external fun nativeWriteHandshake(handle: Long, message: ByteArray)
        @JvmStatic private external fun nativeReadHandshake(handle: Long): ByteArray
        @JvmStatic private external fun nativeWriteFrame(handle: Long, frame: ByteArray)
        @JvmStatic private external fun nativeReadFrame(handle: Long): ByteArray
        @JvmStatic private external fun nativeClose(handle: Long)
    }
}
