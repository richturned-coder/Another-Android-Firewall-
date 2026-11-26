package org.aafw.firewall

import kotlinx.coroutines.test.runTest
import org.aafw.firewall.engine.bluetooth.BleDeviceSighting
import org.aafw.firewall.engine.bluetooth.BleThreatClass
import org.aafw.firewall.engine.bluetooth.BleThreatMonitor
import org.aafw.firewall.engine.bluetooth.BtSnoopParser
import org.aafw.firewall.engine.bluetooth.HciPacketLayer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

/**
 * Verification tests for Bluetooth audit findings:
 * - Loopback-only enforcement & port bounds on live BTSnoop socket
 * - RFC 1761 datalink 1001 unencapsulated HCI decoding (HCI_Reset starting with 0x03)
 * - SMP (CID 0x0006) opcode dissection
 * - Pure-Kotlin BleAdParser-backed Service Data (0x16) and Manufacturer Specific (0xFF) tracker/spam classification
 * - Tracker-preserving eviction under rotating-MAC BLE spam floods
 */
class BluetoothAuditUnitTest {

    @Test
    fun liveBtSnoopSocketRejectsNonLoopbackHostsAndInvalidPorts() = runTest {
        assertNull(BtSnoopParser.validateLocalSocketEndpoint("127.0.0.1", 8872))
        assertNull(BtSnoopParser.validateLocalSocketEndpoint("localhost", 8872))
        assertNull(BtSnoopParser.validateLocalSocketEndpoint("::1", 8872))

        assertNotNull(BtSnoopParser.validateLocalSocketEndpoint("192.168.1.50", 8872))
        assertNotNull(BtSnoopParser.validateLocalSocketEndpoint("169.254.169.254", 80))
        assertNotNull(BtSnoopParser.validateLocalSocketEndpoint("evil.example", 8872))
        assertNotNull(BtSnoopParser.validateLocalSocketEndpoint("127.0.0.1", 0))
        assertNotNull(BtSnoopParser.validateLocalSocketEndpoint("127.0.0.1", 70000))

        var receivedError: String? = null
        BtSnoopParser.streamLiveSocket(
            host = "10.0.0.99",
            port = 8872,
            onConnected = { error("Non-loopback host must never connect") },
            onFrame = { error("Non-loopback host must never emit frames") },
            onError = { receivedError = it }
        )
        assertNotNull(receivedError)
        assertTrue(receivedError!!.contains("loopback", ignoreCase = true))
    }

    @Test
    fun btSnoopDatalink1001DecodesUnframedHciResetWithoutFalseH4Stripping() {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        // RFC 1761 Header: "btsnoop\0", version=1, datalink=1001 (unencapsulated HCI)
        dos.write(byteArrayOf(0x62, 0x74, 0x73, 0x6E, 0x6F, 0x6F, 0x70, 0x00))
        dos.writeInt(1)
        dos.writeInt(1001)

        // Unframed HCI_Reset command: opcode 0x0C03 (LE: 0x03, 0x0C), paramLen=0
        // Note: first byte is 0x03, which previously collided with H4 SCO indicator!
        val unframedReset = byteArrayOf(0x03, 0x0C, 0x00)
        dos.writeInt(unframedReset.size)
        dos.writeInt(unframedReset.size)
        dos.writeInt(0x02) // TX Command (bit 0 = 0 sent, bit 1 = 1 cmd/evt)
        dos.writeInt(0)
        dos.writeLong(0x00dcddb30f2f8000L + 500_000L)
        dos.write(unframedReset)
        dos.flush()

        val result = BtSnoopParser.parseBtSnoopStream(ByteArrayInputStream(baos.toByteArray()), "dl1001.log")
        assertNull(result.error)
        assertEquals(1, result.totalFrames)
        assertEquals(HciPacketLayer.HCI_CMD, result.frames.single().layer)
        assertEquals("HCI_Reset", result.frames.single().summary)
    }

    @Test
    fun btSnoopDecodesSmpPairingRequestOnCid0006() {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        dos.write(byteArrayOf(0x62, 0x74, 0x73, 0x6E, 0x6F, 0x6F, 0x70, 0x00))
        dos.writeInt(1)
        dos.writeInt(1002) // H4 UART

        // H4 ACL (0x02) + ACL hdr (4B) + L2CAP len=7 CID=0x0006 (SMP) + SMP Pairing Request (0x01)
        val smpPacket = byteArrayOf(
            0x02,
            0x40, 0x20, 0x0B, 0x00,
            0x07, 0x00, 0x06, 0x00,
            0x01, 0x03, 0x00, 0x01, 0x10, 0x07, 0x07
        )
        dos.writeInt(smpPacket.size)
        dos.writeInt(smpPacket.size)
        dos.writeInt(0)
        dos.writeInt(0)
        dos.writeLong(0x00dcddb30f2f8000L + 2_000_000L)
        dos.write(smpPacket)
        dos.flush()

        val result = BtSnoopParser.parseBtSnoopStream(ByteArrayInputStream(baos.toByteArray()), "smp.log")
        assertEquals(1, result.totalFrames)
        assertEquals(HciPacketLayer.SMP, result.frames.single().layer)
        assertEquals("SMP Pairing Request", result.frames.single().summary)
    }

    @Test
    fun bleRawAdClassifierDetectsTrackersViaServiceDataAndManufacturerPayloads() {
        // Samsung SmartTag via Service Data (AD type 0x16, UUID 0xFD5A LE -> 5A FD)
        val smartTagAd = byteArrayOf(0x05, 0x16, 0x5A, 0xFD.toByte(), 0x10, 0x20)
        val smartTag = BleThreatMonitor.classifyRawAdPayload(smartTagAd)
        assertNotNull(smartTag)
        assertEquals(BleThreatClass.TRACKER_WATCH, smartTag!!.threatClass)
        assertTrue(smartTag.vendorTag.contains("SmartTag"))

        // Google Fast Pair / FMD via Service Data (AD type 0x16, UUID 0xFE2C LE -> 2C FE)
        val fastPairAd = byteArrayOf(0x06, 0x16, 0x2C, 0xFE.toByte(), 0x01, 0x02, 0x03)
        val fastPair = BleThreatMonitor.classifyRawAdPayload(fastPairAd)
        assertNotNull(fastPair)
        assertEquals(BleThreatClass.TRACKER_WATCH, fastPair!!.threatClass)
        assertTrue(fastPair.isSpamCandidate)

        // Apple Find My / AirTag via Manufacturer Specific Data (AD type 0xFF, 0x004C LE -> 4C 00, subtype 0x12)
        val airTagAd = byteArrayOf(0x05, 0xFF.toByte(), 0x4C, 0x00, 0x12, 0x19)
        val airTag = BleThreatMonitor.classifyRawAdPayload(airTagAd)
        assertNotNull(airTag)
        assertEquals(BleThreatClass.TRACKER_WATCH, airTag!!.threatClass)
        assertTrue(airTag.vendorTag.contains("AirTag"))

        // Samsung Easy Setup spam candidate (AD type 0xFF, 0x0075 LE -> 75 00, subtype 0x42)
        val samsungSpamAd = byteArrayOf(0x05, 0xFF.toByte(), 0x75, 0x00, 0x42, 0x04)
        val samsungSpam = BleThreatMonitor.classifyRawAdPayload(samsungSpamAd)
        assertNotNull(samsungSpam)
        assertTrue(samsungSpam!!.isSpamCandidate)
    }

    @Test
    fun evictionPolicyPreservesPersistentTrackersOverOlderNormalDevices() {
        val sightings = linkedMapOf<String, BleDeviceSighting>()
        // Oldest entry overall is a persistent AirTag tracker
        sightings["AA:BB:CC:DD:EE:01"] = BleDeviceSighting(
            address = "AA:BB:CC:DD:EE:01",
            name = null,
            rssi = -55,
            rssiHistory = listOf(-55),
            vendorTag = "Apple Find My / AirTag",
            threatClass = BleThreatClass.TRACKER_PERSISTENT,
            threatNote = "Persistent tracker",
            firstSeenAt = 1_000L,
            lastSeenAt = 1_000L,
            packetCount = 20,
            rawAdvHex = ""
        )
        // Newer NORMAL device should be evicted before the persistent tracker
        sightings["11:22:33:44:55:02"] = BleDeviceSighting(
            address = "11:22:33:44:55:02",
            name = "Headphones",
            rssi = -70,
            rssiHistory = listOf(-70),
            vendorTag = "BLE Device",
            threatClass = BleThreatClass.NORMAL,
            threatNote = "Standard BLE advertising packet",
            firstSeenAt = 5_000L,
            lastSeenAt = 5_000L,
            packetCount = 1,
            rawAdvHex = ""
        )

        val victim = BleThreatMonitor.selectEvictionKey(sightings)
        assertEquals("11:22:33:44:55:02", victim)
    }
}
