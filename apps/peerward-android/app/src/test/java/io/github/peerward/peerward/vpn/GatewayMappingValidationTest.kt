package io.github.peerward.peerward.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress

class GatewayMappingValidationTest {
    private val gatewayAddress = ipv4(192, 168, 1, 1)
    private val gateway = InetSocketAddress(gatewayAddress, 5_351)

    @Test
    fun acceptsOnlyBoundedResponsesFromTheExactGateway() {
        val pcp = ByteArray(60).also {
            it[0] = 2
            it[1] = 0x81.toByte()
        }
        assertTrue(GatewayPortMapping.isGatewayResponse(gateway, gateway, pcp))
        assertFalse(
            GatewayPortMapping.isGatewayResponse(
                gateway,
                InetSocketAddress(ipv4(192, 168, 1, 2), 5_351),
                pcp,
            ),
        )
        assertFalse(GatewayPortMapping.isGatewayResponse(gateway, gateway, pcp.copyOf(59)))

        val natPmp = ByteArray(16).also { it[1] = 0x81.toByte() }
        assertTrue(GatewayPortMapping.isGatewayResponse(gateway, gateway, natPmp))
        natPmp[1] = 1
        assertFalse(GatewayPortMapping.isGatewayResponse(gateway, gateway, natPmp))
        assertFalse(GatewayPortMapping.isGatewayResponse(gateway, gateway, ByteArray(1_025)))
    }

    @Test
    fun ssdpLocationIsNumericHttpAndBoundToTheResponder() {
        val valid = ssdp("http://192.168.1.1:5000/igd.xml")
        assertNotNull(AndroidUpnpClient.parseSsdpLocation(valid, gatewayAddress, gatewayAddress))
        assertNull(AndroidUpnpClient.parseSsdpLocation(valid, ipv4(192, 168, 1, 2), gatewayAddress))
        assertNull(AndroidUpnpClient.parseSsdpLocation(valid, gatewayAddress, null))
        assertNull(AndroidUpnpClient.parseSsdpLocation(ssdp("http://192.168.1.2/igd.xml"), ipv4(192, 168, 1, 2), gatewayAddress))
        assertNull(
            AndroidUpnpClient.parseSsdpLocation(
                ssdp("http://router.local:5000/igd.xml"),
                gatewayAddress,
                gatewayAddress,
            ),
        )
        assertNull(
            AndroidUpnpClient.parseSsdpLocation(
                ssdp("https://192.168.1.1/igd.xml"),
                gatewayAddress,
                gatewayAddress,
            ),
        )
        assertNull(
            AndroidUpnpClient.parseSsdpLocation(
                ssdp("http://user@192.168.1.1/igd.xml"),
                gatewayAddress,
                gatewayAddress,
            ),
        )
    }

    @Test
    fun numericIpv4ParserRejectsAmbiguousAndOutOfRangeForms() {
        assertEquals(gatewayAddress, AndroidUpnpClient.parseIpv4("192.168.1.1"))
        assertNull(AndroidUpnpClient.parseIpv4("192.168.001.1"))
        assertNull(AndroidUpnpClient.parseIpv4("192.168.1.256"))
        assertNull(AndroidUpnpClient.parseIpv4("router.local"))
    }

    private fun ssdp(location: String): ByteArray = (
        "HTTP/1.1 200 OK\r\n" +
            "LOCATION: $location\r\n" +
            "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\n\r\n"
        ).toByteArray(Charsets.US_ASCII)

    private fun ipv4(a: Int, b: Int, c: Int, d: Int): Inet4Address =
        InetAddress.getByAddress(byteArrayOf(a.toByte(), b.toByte(), c.toByte(), d.toByte())) as Inet4Address
}
