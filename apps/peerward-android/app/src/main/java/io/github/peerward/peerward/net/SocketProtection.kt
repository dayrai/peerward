package io.github.peerward.peerward.net

import android.net.VpnService
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.SocketFactory

fun interface SocketProtector {
    fun protect(socket: Socket): Boolean
}

fun interface DatagramProtector {
    fun protect(socket: DatagramSocket): Boolean
}

class VpnSocketProtector(private val service: VpnService) : SocketProtector, DatagramProtector {
    override fun protect(socket: Socket): Boolean {
        // Android's java.net.Socket constructor is lazy: before the first option, bind or
        // connect operation, its FileDescriptor is invalid. VpnService.protect(Socket)
        // forwards that descriptor directly to the kernel, so materialize it without
        // binding or performing route-dependent I/O and preserve the option value.
        val tcpNoDelay = socket.tcpNoDelay
        socket.tcpNoDelay = tcpNoDelay
        return service.protect(socket)
    }

    override fun protect(socket: DatagramSocket): Boolean = service.protect(socket)
}

/** Protects an unconnected socket before any route lookup or network I/O. */
class ProtectingSocketFactory(private val protector: SocketProtector) : SocketFactory() {
    override fun createSocket(): Socket = protectedSocket()

    override fun createSocket(host: String, port: Int): Socket =
        protectedSocket { connect(InetSocketAddress(host, port)) }

    override fun createSocket(host: String, port: Int, localHost: InetAddress, localPort: Int): Socket =
        protectedSocket {
            bind(InetSocketAddress(localHost, localPort))
            connect(InetSocketAddress(host, port))
        }

    override fun createSocket(host: InetAddress, port: Int): Socket =
        protectedSocket { connect(InetSocketAddress(host, port)) }

    override fun createSocket(
        address: InetAddress,
        port: Int,
        localAddress: InetAddress,
        localPort: Int,
    ): Socket = protectedSocket {
        bind(InetSocketAddress(localAddress, localPort))
        connect(InetSocketAddress(address, port))
    }

    private fun protectedSocket(configure: Socket.() -> Unit = {}): Socket {
        val socket = Socket()
        try {
            check(protector.protect(socket)) { "VPN refused to protect control/data socket" }
            socket.configure()
            return socket
        } catch (error: Throwable) {
            runCatching { socket.close() }.onFailure(error::addSuppressed)
            throw error
        }
    }
}
