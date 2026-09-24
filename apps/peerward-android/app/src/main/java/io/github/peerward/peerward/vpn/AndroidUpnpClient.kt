package io.github.peerward.peerward.vpn

import android.net.Network
import io.github.peerward.peerward.net.DatagramProtector
import io.github.peerward.peerward.net.SocketProtector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.xmlpull.v1.XmlPullParser
import org.xmlpull.v1.XmlPullParserFactory
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.URI
import java.nio.charset.StandardCharsets

internal data class AndroidUpnpLease(
    val serviceType: String,
    val controlUri: URI,
    val external: InetSocketAddress,
    val internal: InetSocketAddress,
    val lifetimeSeconds: Long,
)

internal class AndroidUpnpClient(
    private val network: Network,
    private val socketProtector: SocketProtector,
    private val datagramProtector: DatagramProtector,
    private val internal: InetSocketAddress,
    private val gateway: InetSocketAddress?,
) {
    suspend fun discoverAndMap(lifetimeSeconds: Long): AndroidUpnpLease? = withContext(Dispatchers.IO) {
        if (internal.address !is Inet4Address) return@withContext null
        discoverServices().firstNotNullOfOrNull { service ->
            runCatching { add(service, lifetimeSeconds) }.getOrNull()
        }
    }

    suspend fun renew(lease: AndroidUpnpLease): AndroidUpnpLease? = withContext(Dispatchers.IO) {
        runCatching {
            val response = soap(
                lease.controlUri,
                lease.serviceType,
                "AddPortMapping",
                mappingArguments(lease.external.port, lease.internal, lease.lifetimeSeconds),
            )
            response.takeIf { it.status in 200..299 }?.let {
                externalAddress(lease.serviceType, lease.controlUri)?.let { address ->
                    lease.copy(external = InetSocketAddress(address, lease.external.port))
                }
            }
        }.getOrNull()
    }

    suspend fun delete(lease: AndroidUpnpLease) = withContext(Dispatchers.IO) {
        runCatching {
            soap(
                lease.controlUri,
                lease.serviceType,
                "DeletePortMapping",
                linkedMapOf(
                    "NewRemoteHost" to "",
                    "NewExternalPort" to lease.external.port.toString(),
                    "NewProtocol" to "UDP",
                ),
                DELETE_TIMEOUT_MILLIS,
            )
        }
        Unit
    }

    private suspend fun externalAddress(serviceType: String, controlUri: URI): Inet4Address? = soap(
            controlUri,
            serviceType,
            "GetExternalIPAddress",
            emptyMap(),
        ).takeIf { it.status in 200..299 }
            ?.body
            ?.let { xmlValue(it, "NewExternalIPAddress") }
            ?.let(::parseIpv4)
            ?.takeUnless { it.isAnyLocalAddress || it.isLoopbackAddress || it.isMulticastAddress }

    private suspend fun add(service: UpnpService, lifetimeSeconds: Long): AndroidUpnpLease? {
        val externalAddress = externalAddress(service.serviceType, service.controlUri) ?: return null
        val preferredPort = internal.port
        val externalPort = if (service.serviceType.endsWith(":2")) {
            val response = soap(
                service.controlUri,
                service.serviceType,
                "AddAnyPortMapping",
                mappingArguments(0, internal, lifetimeSeconds),
            )
            if (response.status in 200..299) {
                xmlValue(response.body, "NewReservedPort")?.toIntOrNull()
                    ?.takeIf { it in 1..65_535 }
            } else {
                null
            }
        } else {
            null
        } ?: run {
            val response = soap(
                service.controlUri,
                service.serviceType,
                "AddPortMapping",
                mappingArguments(preferredPort, internal, lifetimeSeconds),
            )
            preferredPort.takeIf { response.status in 200..299 }
        } ?: return null
        return AndroidUpnpLease(
            service.serviceType,
            service.controlUri,
            InetSocketAddress(externalAddress, externalPort),
            internal,
            lifetimeSeconds,
        )
    }

    private suspend fun discoverServices(): List<UpnpService> {
        val expectedGateway = gateway?.address as? Inet4Address ?: return emptyList()
        val locations = linkedSetOf<URI>()
        upnpBlocking(DatagramSocket(null), SSDP_TOTAL_MILLIS.toInt()) { socket ->
            check(datagramProtector.protect(socket)) { "VPN refused to protect UPnP SSDP socket" }
            network.bindSocket(socket)
            socket.reuseAddress = true
            socket.soTimeout = SSDP_TIMEOUT_MILLIS
            socket.bind(InetSocketAddress(internal.address, 0))
            SEARCH_TARGETS.forEach { target ->
                val request = ssdpRequest(target)
                socket.send(DatagramPacket(request, request.size, SSDP_ENDPOINT))
            }
            val deadline = System.nanoTime() + SSDP_TOTAL_MILLIS * 1_000_000
            while (locations.size < MAX_LOCATIONS && System.nanoTime() < deadline) {
                val remaining = ((deadline - System.nanoTime()) / 1_000_000)
                    .coerceIn(1, SSDP_TIMEOUT_MILLIS.toLong())
                socket.soTimeout = remaining.toInt()
                val buffer = ByteArray(MAX_SSDP_BYTES)
                val packet = DatagramPacket(buffer, buffer.size)
                try {
                    socket.receive(packet)
                } catch (_: SocketTimeoutException) {
                    break
                }
                val source = packet.address as? Inet4Address ?: continue
                parseSsdpLocation(buffer.copyOf(packet.length), source, expectedGateway)?.let(locations::add)
            }
        }
        val services = linkedSetOf<UpnpService>()
        for (location in locations) {
            val described = runCatching { describe(location) }.getOrDefault(emptyList())
            for (service in described) {
                services += service
                if (services.size == MAX_SERVICES) return services.toList()
            }
        }
        return services.toList()
    }

    private suspend fun describe(location: URI): List<UpnpService> {
        val response = request(location, "GET", emptyMap(), byteArrayOf())
        if (response.status !in 200..299) return emptyList()
        rejectXmlFeatures(response.body)
        val parser = XmlPullParserFactory.newInstance().newPullParser()
        parser.setInput(response.body.inputStream(), StandardCharsets.UTF_8.name())
        val services = mutableListOf<UpnpService>()
        var insideService = false
        var serviceType: String? = null
        var controlUrl: String? = null
        while (parser.eventType != XmlPullParser.END_DOCUMENT) {
            when (parser.eventType) {
                XmlPullParser.START_TAG -> when (parser.name.substringAfter(':')) {
                    "service" -> {
                        insideService = true
                        serviceType = null
                        controlUrl = null
                    }
                    "serviceType" -> if (insideService) serviceType = parser.nextText().trim()
                    "controlURL" -> if (insideService) controlUrl = parser.nextText().trim()
                }
                XmlPullParser.END_TAG -> if (parser.name.substringAfter(':') == "service") {
                    val type = serviceType
                    val path = controlUrl
                    if (
                        services.size < MAX_SERVICES_PER_DESCRIPTION &&
                        type != null && path != null && type in SUPPORTED_SERVICES
                    ) {
                        validateControlUri(location.resolve(path), location)?.let { uri ->
                            services += UpnpService(type, uri)
                        }
                    }
                    insideService = false
                }
            }
            parser.next()
        }
        return services.distinct()
    }

    private suspend fun soap(
        uri: URI,
        serviceType: String,
        action: String,
        arguments: Map<String, String>,
        timeoutMillis: Int = HTTP_TIMEOUT_MILLIS,
    ): UpnpHttpResponse {
        val body = buildString {
            append("<?xml version=\"1.0\"?>")
            append("<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"")
            append(" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">")
            append("<s:Body><u:").append(action).append(" xmlns:u=\"")
            append(serviceType).append("\">")
            arguments.forEach { (name, value) ->
                append('<').append(name).append('>')
                append(xmlEscape(value))
                append("</").append(name).append('>')
            }
            append("</u:").append(action).append("></s:Body></s:Envelope>")
        }.toByteArray(StandardCharsets.UTF_8)
        return request(
            uri,
            "POST",
            linkedMapOf(
                "Content-Type" to "text/xml; charset=\"utf-8\"",
                "SOAPAction" to "\"$serviceType#$action\"",
            ),
            body,
            timeoutMillis,
        )
    }

    private suspend fun request(
        uri: URI,
        method: String,
        headers: Map<String, String>,
        body: ByteArray,
        timeoutMillis: Int = HTTP_TIMEOUT_MILLIS,
    ): UpnpHttpResponse {
        require(body.size <= MAX_HTTP_BODY)
        val address = parseIpv4(requireNotNull(uri.host)) ?: error("UPnP host must be numeric IPv4")
        val port = effectivePort(uri)
        return upnpBlocking(Socket(), timeoutMillis) { socket ->
            check(socketProtector.protect(socket)) { "VPN refused to protect UPnP HTTP socket" }
            network.bindSocket(socket)
            socket.soTimeout = timeoutMillis
            socket.connect(InetSocketAddress(address, port), timeoutMillis)
            val output = BufferedOutputStream(socket.getOutputStream())
            val path = uri.rawPath.takeUnless(String?::isNullOrEmpty) ?: "/"
            val target = uri.rawQuery?.let { "$path?$it" } ?: path
            val host = if (port == 80) uri.host else "${uri.host}:$port"
            output.write("$method $target HTTP/1.1\r\n".toByteArray(StandardCharsets.US_ASCII))
            output.write("Host: $host\r\nConnection: close\r\n".toByteArray(StandardCharsets.US_ASCII))
            headers.forEach { (name, value) ->
                output.write("$name: $value\r\n".toByteArray(StandardCharsets.US_ASCII))
            }
            output.write("Content-Length: ${body.size}\r\n\r\n".toByteArray(StandardCharsets.US_ASCII))
            output.write(body)
            output.flush()
            UpnpHttp.readResponse(BufferedInputStream(socket.getInputStream()))
        }
    }

    private fun xmlValue(body: ByteArray, wanted: String): String? {
        rejectXmlFeatures(body)
        val parser = XmlPullParserFactory.newInstance().newPullParser()
        parser.setInput(body.inputStream(), StandardCharsets.UTF_8.name())
        while (parser.eventType != XmlPullParser.END_DOCUMENT) {
            if (parser.eventType == XmlPullParser.START_TAG && parser.name.substringAfter(':') == wanted) {
                return parser.nextText().trim().takeIf(String::isNotEmpty)
            }
            parser.next()
        }
        return null
    }

    private fun rejectXmlFeatures(body: ByteArray) {
        val prefix = body.toString(StandardCharsets.UTF_8).uppercase()
        require("<!DOCTYPE" !in prefix && "<!ENTITY" !in prefix)
    }

    private data class UpnpService(val serviceType: String, val controlUri: URI)

    companion object {
        private val SSDP_ENDPOINT = InetSocketAddress("239.255.255.250", 1900)
        private val SEARCH_TARGETS = listOf(
            "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
            "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        )
        private val SUPPORTED_SERVICES = setOf(
            "urn:schemas-upnp-org:service:WANIPConnection:2",
            "urn:schemas-upnp-org:service:WANIPConnection:1",
            "urn:schemas-upnp-org:service:WANPPPConnection:1",
        )
        private const val SSDP_TIMEOUT_MILLIS = 750
        private const val SSDP_TOTAL_MILLIS = 2_000L
        private const val HTTP_TIMEOUT_MILLIS = 2_000
        private const val DELETE_TIMEOUT_MILLIS = 250
        private const val MAX_LOCATIONS = 8
        private const val MAX_SERVICES = 8
        private const val MAX_SERVICES_PER_DESCRIPTION = 4
        private const val MAX_SSDP_BYTES = 8_192
        private const val MAX_HTTP_BODY = 262_144

        private fun ssdpRequest(target: String): ByteArray = (
            "M-SEARCH * HTTP/1.1\r\n" +
                "HOST: 239.255.255.250:1900\r\n" +
                "MAN: \"ssdp:discover\"\r\n" +
                "MX: 1\r\n" +
                "ST: $target\r\n\r\n"
            ).toByteArray(StandardCharsets.US_ASCII)

        internal fun parseSsdpLocation(response: ByteArray, source: Inet4Address, gateway: Inet4Address?): URI? {
            if (source != gateway || response.size > MAX_SSDP_BYTES) return null
            val lines = response.toString(StandardCharsets.US_ASCII).split("\r\n")
            val status = lines.firstOrNull()?.split(' ')?.filter(String::isNotEmpty)
            if (status?.getOrNull(0) != "HTTP/1.1" || status.getOrNull(1) != "200") return null
            val location = lines.drop(1).firstNotNullOfOrNull { line ->
                val separator = line.indexOf(':')
                if (separator > 0 && line.substring(0, separator).trim().equals("location", true)) {
                    line.substring(separator + 1).trim()
                } else {
                    null
                }
            } ?: return null
            if (location.length > 2_048) return null
            return runCatching { URI(location) }.getOrNull()?.takeIf { uri ->
                uri.scheme == "http" && uri.userInfo == null && uri.fragment == null &&
                    parseIpv4(uri.host) == source && effectivePort(uri) in 1..65_535
            }
        }

        private fun validateControlUri(control: URI, location: URI): URI? = control.takeIf { uri ->
            uri.scheme == "http" && uri.userInfo == null && uri.fragment == null &&
                parseIpv4(uri.host) == parseIpv4(location.host) && effectivePort(uri) in 1..65_535
        }

        private fun effectivePort(uri: URI): Int = if (uri.port == -1) 80 else uri.port

        internal fun parseIpv4(value: String?): Inet4Address? {
            val parts = value?.split('.') ?: return null
            if (parts.size != 4) return null
            val bytes = ByteArray(4)
            for ((index, part) in parts.withIndex()) {
                if (part.isEmpty() || (part.length > 1 && part.startsWith('0'))) return null
                val octet = part.toIntOrNull()?.takeIf { it in 0..255 } ?: return null
                bytes[index] = octet.toByte()
            }
            return InetAddress.getByAddress(bytes) as Inet4Address
        }

        private fun mappingArguments(
            externalPort: Int,
            internal: InetSocketAddress,
            lifetimeSeconds: Long,
        ): LinkedHashMap<String, String> = linkedMapOf(
            "NewRemoteHost" to "",
            "NewExternalPort" to externalPort.toString(),
            "NewProtocol" to "UDP",
            "NewInternalPort" to internal.port.toString(),
            "NewInternalClient" to internal.address.hostAddress.orEmpty(),
            "NewEnabled" to "1",
            "NewPortMappingDescription" to "Peerward direct UDP",
            "NewLeaseDuration" to lifetimeSeconds.toString(),
        )

        private fun xmlEscape(value: String): String = buildString(value.length) {
            value.forEach { character ->
                append(
                    when (character) {
                        '&' -> "&amp;"
                        '<' -> "&lt;"
                        '>' -> "&gt;"
                        '"' -> "&quot;"
                        '\'' -> "&apos;"
                        else -> character
                    },
                )
            }
        }
    }
}
