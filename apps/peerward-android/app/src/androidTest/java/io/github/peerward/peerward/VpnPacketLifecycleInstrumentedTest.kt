package io.github.peerward.peerward

import android.os.ParcelFileDescriptor
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.ext.junit.rules.ActivityScenarioRule
import io.github.peerward.peerward.profile.PeerProfile
import io.github.peerward.peerward.profile.RelayProfileTarget
import io.github.peerward.peerward.nativecore.NativeRuntimeStatus
import io.github.peerward.peerward.nativecore.NativeRelayPoolCoordinator
import io.github.peerward.peerward.nativecore.NativeRelaySocket
import io.github.peerward.peerward.nativecore.NativeRuntimeCoordinator
import io.github.peerward.peerward.nativecore.NativeRuntimePhase
import io.github.peerward.peerward.nativecore.NativePlatformOperation
import io.github.peerward.peerward.nativecore.NativeDnsTransport
import io.github.peerward.peerward.nativecore.NativeTunDnsDecision
import io.github.peerward.peerward.nativecore.NativeTunDnsProxy
import io.github.peerward.peerward.nativecore.NativeTunPacketPump
import io.github.peerward.peerward.nativecore.NativeTunPumpAction
import io.github.peerward.peerward.nativecore.PeerwardInvalidInputException
import io.github.peerward.peerward.nativecore.NativeStunRuntime
import io.github.peerward.peerward.nativecore.PeerwardNativeException
import io.github.peerward.peerward.net.DnsWire
import io.github.peerward.peerward.vpn.PacketPump
import io.github.peerward.peerward.vpn.PacketTransport
import io.github.peerward.peerward.vpn.PacketTransportFactory
import io.github.peerward.peerward.vpn.TunnelHealth
import io.github.peerward.peerward.vpn.VpnProtection
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.async
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicBoolean

@RunWith(AndroidJUnit4::class)
class VpnPacketLifecycleInstrumentedTest {
    @get:org.junit.Rule
    // AndroidJUnitRunner finishes Activities between test methods. A one-time
    // host launch cannot keep these synthetic socket tests in the foreground.
    // This rule is deliberately absent from real service/Doze recovery tests.
    val foregroundController = ActivityScenarioRule(io.github.peerward.peerward.testing.NativeTestActivity::class.java)

    @Test
    fun nativeLifecycleMatchesSharedRustFaultTrace() {
        NativeRuntimeCoordinator().use { runtime ->
            assertTrue(runtime.permissionRequired().phase == NativeRuntimePhase.PERMISSION_REQUIRED)
            val permission = org.json.JSONArray(runtime.diagnostics(123, null)).getJSONObject(0)
            assertEquals("vpn_permission_required", permission.getString("code"))
            assertEquals(123L, permission.getLong("observed_at"))
            assertEquals("grant_vpn_permission", permission.getString("retry_hint"))
            assertThrows(PeerwardInvalidInputException::class.java) { runtime.diagnostics(-1, null) }
            assertThrows(PeerwardInvalidInputException::class.java) { runtime.diagnostics(1, "x".repeat(129)) }
            assertTrue(runtime.startRequested().phase == NativeRuntimePhase.STARTING)
            assertTrue(runtime.tunOpened().phase == NativeRuntimePhase.CONNECTING)
            assertTrue(
                runtime.observe(
                    NativeRuntimeStatus(
                        signedStateComplete = false,
                        signedRevision = 99,
                        primaryRelayAuthenticated = true,
                        standbyRelayCount = 1,
                    ),
                ).let {
                    it.phase == NativeRuntimePhase.DEGRADED && it.signedStateRevision == 0L
                },
            )
            assertTrue(
                runtime.observe(
                    NativeRuntimeStatus(
                        signedStateComplete = true,
                        signedRevision = 7,
                        directPathCount = 2,
                        primaryRelayAuthenticated = true,
                        standbyRelayCount = 1,
                    ),
                ).phase == NativeRuntimePhase.HEALTHY,
            )
            val healthy = NativeRuntimeStatus(
                signedStateComplete = true,
                signedRevision = 7,
                directPathCount = 2,
                primaryRelayAuthenticated = true,
                standbyRelayCount = 1,
            )
            val initialSchedule = runtime.schedule(1_000, healthy)
            assertTrue(initialSchedule.reportHealth && !initialSchedule.sendKeepalive)
            assertTrue(runtime.schedule(11_000, healthy).sendKeepalive)
            assertTrue(
                runtime.schedule(12_000, healthy.copy(directPathCount = 1)).reportHealth,
            )
            assertTrue(runtime.underlayLost().phase == NativeRuntimePhase.RECONNECTING)
            assertTrue(runtime.observe(healthy).phase == NativeRuntimePhase.RECONNECTING)
            assertTrue(runtime.underlayRestored().let {
                it.phase == NativeRuntimePhase.RECONNECTING && it.tunOpen && it.packetPumpRunning
            })
            assertTrue(runtime.observe(healthy).phase == NativeRuntimePhase.HEALTHY)
            assertTrue(runtime.stopRequested().phase == NativeRuntimePhase.STOPPING)
            assertTrue(runtime.stopped().phase == NativeRuntimePhase.STOPPED)
            assertEquals("[]", runtime.diagnostics(124, "authentication_failed"))
        }
    }

    @Test
    fun presentationChangesAndLateCallbacksPreserveFailureEvidence() {
        val state = io.github.peerward.peerward.runtime.MobileRuntimeState
        state.initialize(null)
        try {
            state.failed("authentication_failed", true)
            val before = state.snapshots.value
            assertEquals("authentication_failed", org.json.JSONArray(before.diagnostics).getJSONObject(0).getString("code"))
            state.preferencesObserved(org.json.JSONObject().put("version", 2))
            state.protectionObserved(VpnProtection(alwaysOn = true, lockdown = true))
            state.fromNativeRuntimeStatus(NativeRuntimeStatus(true, 7, primaryRelayAuthenticated = true))
            val after = state.snapshots.value
            assertEquals(before.connection, after.connection)
            assertEquals(before.lastError, after.lastError)
            assertEquals(before.observedAt, after.observedAt)
            assertEquals(before.diagnostics, after.diagnostics)
            state.stopped()
            assertEquals("[]", state.snapshots.value.diagnostics)
        } finally {
            state.initialize(null)
            state.protectionObserved(VpnProtection())
        }
    }

    @Test
    fun platformRequestIdsReportRejectedDuplicateAndOldGenerationResults() {
        NativeRuntimeCoordinator().use { runtime ->
            val tun = runtime.request(NativePlatformOperation.OPEN_TUN)
            assertTrue(runtime.complete(tun, true))
            assertFalse(runtime.complete(tun, true))

            val socket = runtime.request(NativePlatformOperation.PROTECTED_TCP_SOCKET)
            runtime.underlayLost()
            assertFalse(runtime.complete(socket, false))
        }
    }

    @Test
    fun relayAuthenticationFailureRemainsTypedUntilAConnectionSucceeds() = runBlocking {
        val profile = PeerProfile("profile", "key", "mesh", "peer", "Mesh", "10.0.0.2/32", "mesh.test", "credential",
            relays = listOf(RelayProfileTarget("relay", listOf("tcp://relay.test"), "")))
        val authenticated = AtomicBoolean(false)
        val blocked = Channel<ByteArray>()
        val factory = PacketTransportFactory { _, _ ->
            if (!authenticated.get()) throw io.github.peerward.peerward.nativecore.PeerwardAuthenticationException("redacted")
            object : PacketTransport {
                override suspend fun send(packet: ByteArray) = Unit
                override suspend fun receive(): ByteArray = blocked.receive()
                override fun runtimeStatus() = NativeRuntimeStatus(true, 7, primaryRelayAuthenticated = true)
                override fun close() = Unit
            }
        }
        val pool = io.github.peerward.peerward.vpn.RelayPoolTransport.open(profile, factory)
        try {
            withTimeout(5_000) {
                while (pool.runtimeStatus()?.diagnosticCode != "authentication_failed") delay(25)
            }
            val failure = pool.runtimeStatus()!!
            assertTrue(!failure.primaryRelayAuthenticated)
            assertTrue(failure.diagnosticObservedAt!! > 0)
            authenticated.set(true)
            withTimeout(5_000) {
                while (pool.runtimeStatus()?.primaryRelayAuthenticated != true) delay(25)
            }
            assertEquals(null, pool.runtimeStatus()!!.diagnosticCode)
        } finally { pool.close(); blocked.close() }
    }

    @Test
    fun nativeRelayPoolOwnsPromotionRetryAndGenerationFences() {
        NativeRelayPoolCoordinator(listOf(2, 1, 1)).use { pool ->
            val initial = pool.poll(0)
            assertTrue(initial.requests.size == 3)
            val primary = pool.complete(initial.requests[0], true, 0)!!.route
            val standby = pool.complete(initial.requests[1], true, 0)!!.route
            val secondStandby = pool.complete(initial.requests[2], true, 0)!!.route
            assertTrue(pool.routes() == listOf(primary, standby, secondStandby))
            assertTrue(
                pool.isPrimary(primary) &&
                    !pool.isPrimary(standby) &&
                    !pool.isPrimary(secondStandby),
            )
            pool.failed(primary, 10)
            assertTrue(pool.routes() == listOf(standby, secondStandby))
            assertTrue(pool.isPrimary(standby))
            val retry = pool.poll(261).requests.single()
            assertTrue(retry.slot == 0 && retry.endpointIndex == 1)
            pool.complete(retry, true, 261)
            assertThrows(PeerwardNativeException::class.java) {
                pool.complete(retry, true, 261)
            }
        }
    }

    @Test
    fun nativeRelaySocketOwnsHandshakeAndEncryptedFrameIo() = runBlocking {
        val server = ServerSocket(0)
        val handshake = byteArrayOf(1, 2, 3)
        val preface = ByteBuffer.allocate(56).apply {
            put("PWR4".toByteArray()).put(4).put(1).putShort(0)
            repeat(2) {
                val id = java.util.UUID.randomUUID()
                putLong(id.mostSignificantBits).putLong(id.leastSignificantBits)
            }
        }.array()
        val response = byteArrayOf(4, 5)
        val frame = ByteBuffer.allocate(7).putInt(3).put(byteArrayOf(6, 7, 8)).array()
        val reply = ByteBuffer.allocate(6).putInt(2).put(byteArrayOf(9, 10)).array()
        val accepted = async(Dispatchers.IO) {
            server.accept().use { socket ->
                val input = DataInputStream(socket.getInputStream())
                val output = DataOutputStream(socket.getOutputStream())
                assertArrayEquals(preface, ByteArray(56).also(input::readFully))
                val length = input.readUnsignedShort()
                assertArrayEquals(handshake, ByteArray(length).also(input::readFully))
                output.writeShort(response.size)
                output.write(response)
                output.flush()
                assertArrayEquals(frame, ByteArray(frame.size).also(input::readFully))
                output.write(reply)
                output.flush()
            }
        }
        NativeRelaySocket.take(Socket("127.0.0.1", server.localPort)).use { socket ->
            socket.writeHandshake(preface + handshake)
            assertArrayEquals(response, socket.readHandshake())
            socket.writeFrame(frame)
            assertArrayEquals(reply, socket.readFrame())
        }
        accepted.await()
        server.close()
    }

    @Test
    fun nativeRelaySocketCloseInterruptsABlockedRead() {
        RuntimeStopDiagnostics { null }.use { diagnostics ->
            fun phase(value: String) {
                diagnostics.phase.set(value)
                android.util.Log.i("PeerwardStop", "socket close test: $value")
            }
            phase("before runBlocking")
            runBlocking {
                phase("creating server")
                val server = ServerSocket(0)
                val accepted = CompletableDeferred<Unit>()
                val peer = async(Dispatchers.IO) {
                    server.accept().use {
                        phase("server accepted")
                        accepted.complete(Unit)
                        delay(5_000)
                    }
                }
                phase("taking native socket")
                val socket = NativeRelaySocket.take(Socket("127.0.0.1", server.localPort))
                try {
                    phase("waiting accept")
                    accepted.await()
                    val blocked = async(Dispatchers.IO) {
                        phase("reading native frame")
                        runCatching { socket.readFrame() }.also { phase("native read returned") }
                    }
                    delay(50)
                    phase("closing native socket")
                    socket.close()
                    phase("waiting blocked read")
                    assertTrue(withTimeout(1_000) { blocked.await() }.isFailure)
                    phase("read interruption verified")
                } finally {
                    socket.close()
                    peer.cancel()
                    server.close()
                    phase("server closed")
                }
            }
            phase("runBlocking finished")
        }
    }

    @Test
    fun nativeTunDnsOwnsUdpFramingAndRejectsDuplicateCompletion() {
        // Different valid IPs can share Arrays.hashCode; neither may disappear.
        val servers = listOf("10.0.1.32", "10.0.2.1")
        val addresses = servers.map { java.net.InetAddress.getByName(it).address }
        assertEquals(addresses[0].contentHashCode(), addresses[1].contentHashCode())
        NativeTunDnsProxy(servers, 1_380).use { proxy ->
            addresses.forEach { server ->
                val query = DnsWire.query(0x3344, "peer.mesh.test")
                val packet = ipv4UdpDns(query).also { server.copyInto(it, 16) }
                val decision = proxy.inspect(packet)
                assertTrue(decision is NativeTunDnsDecision.Resolve)
                decision as NativeTunDnsDecision.Resolve
                assertTrue(decision.transport == NativeDnsTransport.UDP)
                assertArrayEquals(byteArrayOf(10, 0, 0, 2), decision.sourceAddress)
                assertArrayEquals(query, decision.query)
                val reply = proxy.complete(decision.token, query).single()
                assertArrayEquals(server, reply.copyOfRange(12, 16))
                assertArrayEquals(byteArrayOf(10, 0, 0, 2), reply.copyOfRange(16, 20))
                assertThrows(PeerwardNativeException::class.java) {
                    proxy.complete(decision.token, query)
                }
            }
        }
        val pair = ParcelFileDescriptor.createSocketPair()
        try {
            NativeTunPacketPump(pair[0], servers, 1_380).use { pump ->
                val output = FileOutputStream(pair[1].fileDescriptor)
                addresses.forEach { server ->
                    val packet = ipv4UdpDns(DnsWire.query(0x3345, "peer.mesh.test")).also {
                        server.copyInto(it, 16)
                        writeU16(it, 10, internetChecksum(it, 0, 20))
                    }
                    output.write(packet)
                    assertTrue("TUN pump lost a colliding DNS address", pump.poll(1_000) is NativeTunPumpAction.Resolve)
                }
            }
        } finally {
            pair.forEach { it.close() }
        }
    }

    @Test
    fun nativeStunSchedulesRetriesAndMatchesExactServerTransaction() = runBlocking {
        val context = androidx.test.platform.app.InstrumentationRegistry.getInstrumentation().targetContext
        val networks = context.getSystemService(android.net.ConnectivityManager::class.java)
        val network = networks.allNetworks.first { candidate ->
            networks.getNetworkCapabilities(candidate)
                ?.hasCapability(android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN) == true
        }
        val servers = io.github.peerward.peerward.net.StunServerResolver.resolve(
            network, listOf("localhost:3478"), false,
        )
        val server = InetSocketAddress("127.0.0.1", 3_478)
        assertEquals(listOf(server), servers)
        NativeStunRuntime(servers).use { runtime ->
            val now = android.os.SystemClock.elapsedRealtime()
            val first = runtime.poll(now)
            assertTrue(first.probes.size == 1 && first.nextPollMillis == 250L)
            assertTrue(runtime.poll(now).probes.isEmpty())
            val probe = first.probes.single()
            val response = stunResponse(
                probe.request,
                byteArrayOf(203.toByte(), 0, 113, 9),
                54_321,
            )
            val mapping = runtime.accept(server, response)
            assertTrue(mapping?.serverIndex == 0)
            assertTrue(mapping?.mapped == InetSocketAddress("203.0.113.9", 54_321))
            assertTrue(runtime.accept(server, response) == null)
        }
        val colliding = listOf("192.0.1.32", "192.0.2.1").map { InetSocketAddress(it, 3_478) }
        assertEquals(colliding[0].address.address.contentHashCode(), colliding[1].address.address.contentHashCode())
        NativeStunRuntime(colliding).use { runtime ->
            assertEquals(colliding.toSet(), runtime.poll(android.os.SystemClock.elapsedRealtime()).probes.map { it.server }.toSet())
        }
    }

    @Test
    fun malformedTunPacketIsDroppedWithoutPoisoningTheNativePump() {
        val descriptorDirectory = java.io.File("/proc/self/fd")
        val before = requireNotNull(descriptorDirectory.list()).size
        repeat(20) {
            val invalid = ParcelFileDescriptor.createSocketPair()
            try {
                assertThrows(IllegalArgumentException::class.java) {
                    NativeTunPacketPump(invalid[0], emptyList(), 1_280)
                }
                assertTrue("Kotlin validation retained the TUN owner", !invalid[0].fileDescriptor.valid())
            } finally {
                invalid.forEach { it.close() }
            }
        }
        assertTrue("failed TUN creation leaked descriptors", requireNotNull(descriptorDirectory.list()).size <= before + 2)
        val pair = ParcelFileDescriptor.createSocketPair()
        val output = FileOutputStream(pair[1].fileDescriptor)
        NativeTunPacketPump(pair[0], listOf("10.0.0.1"), 1_380).use { pump ->
            assertTrue("JNI retained the Java TUN owner", !pair[0].fileDescriptor.valid())
            output.write(ByteArray(20))
            assertThrows(PeerwardInvalidInputException::class.java) { pump.poll(1_000) }
            val expected = ipv4Packet(17)
            output.write(expected)
            val actual = pump.poll(1_000)
            assertTrue(actual is NativeTunPumpAction.Packet)
            actual as NativeTunPumpAction.Packet
            assertArrayEquals(expected, actual.bytes)
        }
        pair[1].close()
    }

    @Test
    fun tunStartReconnectDeliveryAndStop() {
        android.util.Log.i("PeerwardStop", "before runBlocking")
        runBlocking {
        android.util.Log.i("PeerwardStop", "entered runBlocking")
        var observedPump: PacketPump? = null
        val diagnostics = RuntimeStopDiagnostics { observedPump }
        android.util.Log.i("PeerwardStop", "observer started")
        diagnostics.phase.set("creating socket pair")
        val pair = ParcelFileDescriptor.createSocketPair()
        val testInput = FileInputStream(pair[1].fileDescriptor)
        val testOutput = FileOutputStream(pair[1].fileDescriptor)
        val sent = CompletableDeferred<ByteArray>()
        val inbound = Channel<ByteArray>(1)
        val attempts = AtomicInteger()
        val signedStateComplete = AtomicBoolean(false)
        val primaryCreated = AtomicBoolean(false)
        val primaryConnectionStarted = CompletableDeferred<Unit>()
        val health = mutableListOf<TunnelHealth>()
        val stalledPrimary = Channel<ByteArray>()
        val factory = PacketTransportFactory { endpoint, _ ->
            attempts.incrementAndGet()
            if (endpoint.contains("primary")) {
                if (!primaryCreated.compareAndSet(false, true)) {
                    throw IOException("planned primary reconnect failure")
                }
                primaryConnectionStarted.complete(Unit)
                object : PacketTransport {
                    override suspend fun send(packet: ByteArray) { throw IOException("planned primary failure") }
                    override suspend fun receive(): ByteArray = stalledPrimary.receive()
                    override fun runtimeStatus() = NativeRuntimeStatus(
                        signedStateComplete = false,
                        signedRevision = 0,
                        primaryRelayAuthenticated = true,
                    )
                    override fun close() = Unit
                }
            } else {
                // Relay candidates are opened concurrently. Preserve the scenario's
                // intended slot ordering without relying on dispatcher timing.
                primaryConnectionStarted.await()
                delay(100)
                object : PacketTransport {
                    override suspend fun send(packet: ByteArray) {
                        sent.complete(packet.copyOf())
                        signedStateComplete.set(true)
                    }
                    override suspend fun receive(): ByteArray = inbound.receive()
                    override fun runtimeStatus() = NativeRuntimeStatus(
                        signedStateComplete.get(),
                        if (signedStateComplete.get()) 7 else 0,
                        primaryRelayAuthenticated = true,
                    )
                    override fun close() = Unit
                }
            }
        }
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val testProfile = PeerProfile(
                profileId = "profile",
                deviceKeyId = "device",
                meshId = "mesh",
                peerId = "peer",
                meshName = "Mesh",
                address = "10.0.0.2/32",
                dnsSuffix = "mesh.test",
                routes = listOf("10.0.0.0/24"),
                dnsServers = listOf("10.0.0.1"),
                mtu = 1380,
                credential = "credential",
                relays = listOf(
                    RelayProfileTarget("primary", listOf("tcp://primary.test"), ""),
                    RelayProfileTarget("standby", listOf("tcp://standby.test"), ""),
                ),
            )
        diagnostics.phase.set("constructing native pump")
        android.util.Log.i("PeerwardStop", "constructing native pump")
        val pump = PacketPump(
            pair[0],
            testProfile,
            { io.github.peerward.peerward.vpn.RelayPoolTransport.open(testProfile, factory) },
        ) { synchronized(health) { health += it } }
        observedPump = pump
        android.util.Log.i("PeerwardStop", "native pump constructed")
        try {
            pump.start(scope)
            val packet = ipv4Packet(17)
            testOutput.write(packet)
            val sentPacket = withTimeoutOrNull(5_000) { sent.await() }
                ?: throw AssertionError("outbound packet was not retried through the promoted Relay")
            assertArrayEquals(packet, sentPacket)
            diagnostics.phase.set("outbound delivered")
            val becameHealthy = withTimeoutOrNull(5_000) {
                while (synchronized(health) { TunnelHealth.HEALTHY !in health }) delay(25)
                true
            }
            assertTrue(
                "promoted Relay did not become healthy: ${synchronized(health) { health.toList() }}",
                becameHealthy == true,
            )
            val returned = ipv4Packet(1)
            inbound.send(returned)
            val received = ByteArray(returned.size)
            // InputStream.available() is not a readiness primitive for an AF_UNIX
            // socket and can remain zero on some emulator kernels. Poll the exact FD,
            // then consume the complete packet so the assertion measures delivery.
            val poll = StructPollfd().apply {
                fd = pair[1].fileDescriptor
                events = OsConstants.POLLIN.toShort()
            }
            val ready = withContext(Dispatchers.IO) { Os.poll(arrayOf(poll), 5_000) }
            assertTrue(
                "promoted Relay did not deliver its inbound packet",
                ready > 0 && poll.revents.toInt() and OsConstants.POLLIN != 0,
            )
            var offset = 0
            while (offset < received.size) {
                val count = testInput.read(received, offset, received.size - offset)
                assertTrue("promoted Relay closed before the full packet arrived", count > 0)
                offset += count
            }
            assertArrayEquals(returned, received)
            diagnostics.phase.set("closing")
            android.util.Log.i("PeerwardStop", "closing")
            pump.close()
            diagnostics.phase.set("awaiting stop")
            android.util.Log.i("PeerwardStop", "awaiting stop")
            val stopped = withTimeoutOrNull(5_000) {
                pump.awaitStopped()
                true
            }
            assertTrue("packet pump did not stop after close", stopped == true)
            scope.cancel()
            pair[1].close()
            assertTrue(attempts.get() >= 2)
            assertTrue(health.contains(TunnelHealth.CONNECTING))
            assertTrue(health.contains(TunnelHealth.HEALTHY))
            assertTrue(health.contains(TunnelHealth.STOPPED))
        } finally {
            diagnostics.close()
            pump.close()
            scope.cancel()
            pair[1].close()
        }
        }
    }

    private fun ipv4Packet(protocol: Int): ByteArray = ByteArray(28).also {
        it[0] = 0x45
        writeU16(it, 2, it.size)
        it[8] = 64
        it[9] = protocol.toByte()
        byteArrayOf(10, 0, 0, 2).copyInto(it, 12)
        byteArrayOf(10, 0, 0, 3).copyInto(it, 16)
        when (protocol) {
            17 -> {
                writeU16(it, 20, 40_000)
                writeU16(it, 22, 40_001)
                writeU16(it, 24, 8)
                // An IPv4 UDP checksum of zero explicitly means no checksum.
            }
            1 -> {
                it[20] = 8
                writeU16(it, 22, internetChecksum(it, 20, 8))
            }
            else -> error("unsupported test protocol")
        }
        writeU16(it, 10, internetChecksum(it, 0, 20))
    }

    private fun internetChecksum(bytes: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += ((bytes[index].toInt() and 0xff) shl 8) or
                (bytes[index + 1].toInt() and 0xff)
            index += 2
        }
        if (index < end) sum += (bytes[index].toInt() and 0xff) shl 8
        while (sum ushr 16 != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.inv().toInt() and 0xffff
    }

    private fun ipv4UdpDns(query: ByteArray): ByteArray = ByteArray(28 + query.size).also {
        it[0] = 0x45
        writeU16(it, 2, it.size)
        it[8] = 64
        it[9] = 17
        byteArrayOf(10, 0, 0, 2).copyInto(it, 12)
        byteArrayOf(10, 0, 0, 1).copyInto(it, 16)
        writeU16(it, 20, 49_152)
        writeU16(it, 22, 53)
        writeU16(it, 24, query.size + 8)
        query.copyInto(it, 28)
    }

    private fun writeU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }

    private fun stunResponse(request: ByteArray, address: ByteArray, port: Int): ByteArray {
        val magic = 0x2112A442
        val mask = ByteBuffer.allocate(4).putInt(magic).array()
        return ByteBuffer.allocate(32)
            .putShort(0x0101.toShort())
            .putShort(12.toShort())
            .putInt(magic)
            .put(request.copyOfRange(8, 20))
            .putShort(0x0020.toShort())
            .putShort(8.toShort())
            .put(0)
            .put(1)
            .putShort((port xor (magic ushr 16)).toShort())
            .apply {
                address.indices.forEach { index ->
                    put((address[index].toInt() xor mask[index].toInt()).toByte())
                }
            }
            .array()
    }
}
