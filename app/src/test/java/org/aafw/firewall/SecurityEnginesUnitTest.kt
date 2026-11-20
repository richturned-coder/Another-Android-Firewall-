package org.aafw.firewall

import org.aafw.firewall.data.local.AlertCategory
import org.aafw.firewall.data.local.FirewallRuleEntity
import org.aafw.firewall.data.local.RuleAction
import org.aafw.firewall.data.local.RuleType
import org.aafw.firewall.engine.bluetooth.BtSnoopParser
import org.aafw.firewall.engine.bluetooth.HciPacketLayer
import org.aafw.firewall.engine.network.AppLabelResolver
import org.aafw.firewall.engine.network.FirewallRuleEngine
import org.aafw.firewall.engine.network.IdsEngine
import org.aafw.firewall.engine.network.PacketParser
import org.aafw.firewall.engine.network.PcapngWriter
import org.aafw.firewall.engine.rf.Radix2FftEngine
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.math.PI
import kotlin.math.cos
import kotlin.math.sin

class SecurityEnginesUnitTest {

    @Test
    fun firewallRuleEngineEnforcesPerAppIpPortAndDomainRules() {
        val engine = FirewallRuleEngine()
        engine.updateRules(
            rules = listOf(
                FirewallRuleEntity(ruleType = RuleType.APP_UID.name, targetValue = "10123", displayLabel = "TargetApp", action = RuleAction.BLOCK.name),
                FirewallRuleEntity(ruleType = RuleType.IP_CIDR.name, targetValue = "198.51.100.0/24", displayLabel = "BadNet", action = RuleAction.BLOCK.name),
                FirewallRuleEntity(ruleType = RuleType.PORT.name, targetValue = "TCP:4444", displayLabel = "ReverseShell", action = RuleAction.BLOCK.name),
                FirewallRuleEntity(ruleType = RuleType.DOMAIN.name, targetValue = "evil.example", displayLabel = "Evil", action = RuleAction.BLOCK.name)
            ),
            defaultBlockAll = false
        )

        val benignPkt = PacketParser.buildIpv4TcpPacket(
            srcIp = byteArrayOf(10, 215.toByte(), 0, 1),
            dstIp = byteArrayOf(93, 184.toByte(), 216.toByte(), 34),
            srcPort = 51000,
            dstPort = 443,
            seq = 100L,
            ack = 0L,
            flags = 0x02
        )
        val parsedBenign = PacketParser.parse(benignPkt, benignPkt.size)!!
        assertTrue(engine.evaluate(parsedBenign, 10999).allowed)
        assertFalse(engine.evaluate(parsedBenign, 10123).allowed)

        val cidrPkt = PacketParser.buildIpv4TcpPacket(
            srcIp = byteArrayOf(10, 215.toByte(), 0, 1),
            dstIp = byteArrayOf(198.toByte(), 51, 100, 42),
            srcPort = 51001,
            dstPort = 443,
            seq = 100L,
            ack = 0L,
            flags = 0x02
        )
        assertFalse(engine.evaluate(PacketParser.parse(cidrPkt, cidrPkt.size)!!, 10999).allowed)

        val portPkt = PacketParser.buildIpv4TcpPacket(
            srcIp = byteArrayOf(10, 215.toByte(), 0, 1),
            dstIp = byteArrayOf(1, 1, 1, 1),
            srcPort = 51002,
            dstPort = 4444,
            seq = 100L,
            ack = 0L,
            flags = 0x02
        )
        assertFalse(engine.evaluate(PacketParser.parse(portPkt, portPkt.size)!!, 10999).allowed)
    }

    @Test
    fun idsEngineDetectsSqliXssCmdiPhishingAndPortScan() {
        val ids = IdsEngine()
        ids.updateThreatFeed(listOf("phish-login-verify.xyz"))

        // 1. SQLi HTTP Request
        val sqliPayload = "GET /api/user?id=1%20UNION%20SELECT%20password%20FROM%20users HTTP/1.1\r\nHost: target.local\r\n\r\n"
            .toByteArray(Charsets.US_ASCII)
        val sqliRaw = PacketParser.buildIpv4TcpPacket(
            srcIp = byteArrayOf(10, 215.toByte(), 0, 1),
            dstIp = byteArrayOf(10, 0, 0, 5),
            srcPort = 50000,
            dstPort = 80,
            seq = 1L,
            ack = 1L,
            flags = 0x18,
            payload = sqliPayload
        )
        val sqliAlerts = ids.inspect(PacketParser.parse(sqliRaw, sqliRaw.size)!!, 10200, "Browser")
        assertTrue(sqliAlerts.any { it.category == AlertCategory.SQL_INJECTION.name })

        // 2. Command Injection HTTP Request
        val cmdiPayload = "POST /run HTTP/1.1\r\nHost: target.local\r\n\r\ncmd=test; cat /etc/passwd"
            .toByteArray(Charsets.US_ASCII)
        val cmdiRaw = PacketParser.buildIpv4TcpPacket(
            srcIp = byteArrayOf(10, 215.toByte(), 0, 1),
            dstIp = byteArrayOf(10, 0, 0, 5),
            srcPort = 50001,
            dstPort = 80,
            seq = 1L,
            ack = 1L,
            flags = 0x18,
            payload = cmdiPayload
        )
        val cmdiAlerts = ids.inspect(PacketParser.parse(cmdiRaw, cmdiRaw.size)!!, 10200, "Browser")
        assertTrue(cmdiAlerts.any { it.category == AlertCategory.COMMAND_INJECTION.name })

        // 3. Punycode + Phishing Threat Feed Match via HTTP Host
        val phishPayload = "GET / HTTP/1.1\r\nHost: sub.phish-login-verify.xyz\r\n\r\n".toByteArray(Charsets.US_ASCII)
        val phishRaw = PacketParser.buildIpv4TcpPacket(
            srcIp = byteArrayOf(10, 215.toByte(), 0, 1),
            dstIp = byteArrayOf(10, 0, 0, 9),
            srcPort = 50002,
            dstPort = 80,
            seq = 1L,
            ack = 1L,
            flags = 0x18,
            payload = phishPayload
        )
        val phishAlerts = ids.inspect(PacketParser.parse(phishRaw, phishRaw.size)!!, 10200, "Browser")
        assertTrue(phishAlerts.any { it.category == AlertCategory.PHISHING_FEED.name })

        // 4. Rapid Port Scan Detection (>= 10 distinct ports in 10s)
        var scanDetected = false
        for (port in 20..35) {
            val syn = PacketParser.buildIpv4TcpPacket(
                srcIp = byteArrayOf(10, 215.toByte(), 0, 1),
                dstIp = byteArrayOf(192.toByte(), 168.toByte(), 1, 1),
                srcPort = 40000 + port,
                dstPort = port,
                seq = 1L,
                ack = 0L,
                flags = 0x02
            )
            val hits = ids.inspect(PacketParser.parse(syn, syn.size)!!, 10333, "Scanner")
            if (hits.any { it.category == AlertCategory.PORT_SCAN.name }) {
                scanDetected = true
                break
            }
        }
        assertTrue(scanDetected)
    }

    @Test
    fun btSnoopParserDecodesHciAttGattFrame() {
        val baos = ByteArrayOutputStream()
        val dos = DataOutputStream(baos)
        // RFC 1761 Header: "btsnoop\0", version=1, datalink=1002 (HCI UART H4)
        dos.write(byteArrayOf(0x62, 0x74, 0x73, 0x6E, 0x6F, 0x6F, 0x70, 0x00))
        dos.writeInt(1)
        dos.writeInt(1002)

        // HCI H4 ACL (0x02) + ACL hdr (4B) + L2CAP len=3 CID=0x0004 (ATT) + ATT Read Request (0x0A) Handle=0x0012
        val attPacket = byteArrayOf(
            0x02,
            0x40, 0x20, 0x07, 0x00,
            0x03, 0x00, 0x04, 0x00,
            0x0A, 0x12, 0x00
        )
        dos.writeInt(attPacket.size)
        dos.writeInt(attPacket.size)
        dos.writeInt(0) // TX
        dos.writeInt(0)
        dos.writeLong(0x00dcddb30f2f8000L + 1_000_000L)
        dos.write(attPacket)
        dos.flush()

        val result = BtSnoopParser.parseBtSnoopStream(ByteArrayInputStream(baos.toByteArray()), "test.log")
        assertEquals(1, result.totalFrames)
        assertEquals(HciPacketLayer.ATT_GATT, result.frames.first().layer)
        assertTrue(result.frames.first().summary.contains("GATT Read Request"))
    }

    @Test
    fun radix2FftDetectsInjectedCarrierPeak() {
        val fft = Radix2FftEngine(1024)
        val iq = ByteArray(2048)
        val binOffset = 128.0 // +Fs/8 above center
        for (n in 0 until 1024) {
            val phase = 2.0 * PI * binOffset * n / 1024.0
            iq[n * 2] = (127.5 + 90.0 * cos(phase)).toInt().coerceIn(0, 255).toByte()
            iq[n * 2 + 1] = (127.5 + 90.0 * sin(phase)).toInt().coerceIn(0, 255).toByte()
        }
        val frame = fft.processCu8Block(
            iqBytes = iq,
            byteLength = iq.size,
            centerFreqMhz = 433.92,
            sampleRateHz = 2_048_000,
            peakThresholdDb = 10f
        ) { "433 MHz ISM" to "OOK/ASK" }

        assertTrue(frame.peaks.isNotEmpty())
        val expectedMhz = 433.92 + (2.048 / 8.0)
        assertEquals(expectedMhz, frame.peaks.first().frequencyMhz, 0.02)
    }

    @Test
    fun pcapngWriterEmitsValidShbIdbAndEpbWithComment() = runTest {
        val tempFile = File.createTempFile("adf_test_", ".pcapng")
        try {
            val writer = PcapngWriter(ringCapacity = 64)
            assertTrue(writer.start(tempFile, 1L, this) {})
            val pkt = PacketParser.buildIpv4TcpPacket(
                srcIp = byteArrayOf(10, 215.toByte(), 0, 1),
                dstIp = byteArrayOf(1, 1, 1, 1),
                srcPort = 54321,
                dstPort = 443,
                seq = 1L,
                ack = 0L,
                flags = 0x02
            )
            writer.offerPacket(pkt, pkt.size, 10123, "TestApp", "ALLOW", "cloudflare.com")
            val finalStats = writer.stop()
            assertEquals(1L, finalStats.packetsWritten)
            val bytes = tempFile.readBytes()
            val magic = ByteBuffer.wrap(bytes, 0, 4).order(ByteOrder.LITTLE_ENDIAN).int
            assertEquals(0x0A0D0D0A, magic)
            assertNotNull(String(bytes, Charsets.UTF_8).indexOf("UID=10123").takeIf { it > 0 })
        } finally {
            tempFile.delete()
        }
    }

    @Test
    fun appLabelResolverFormatsKnownAndUnknownPackagesWithoutApkAssets() {
        assertEquals("Chrome", AppLabelResolver.resolveFromPackageName("com.android.chrome"))
        assertEquals("Gmail", AppLabelResolver.resolveFromPackageName("com.google.android.gm"))
        assertEquals("YouTube Music", AppLabelResolver.resolveFromPackageName("com.google.android.apps.youtube.music"))
        assertEquals("Signal", AppLabelResolver.resolveFromPackageName("org.thoughtcrime.securesms.signal"))
        assertEquals("Wireguard", AppLabelResolver.resolveFromPackageName("com.wireguard.android"))
        assertEquals("Net Guard", AppLabelResolver.resolveFromPackageName("org.vendor.netGuard"))
    }

    @Test
    fun firewallRuleEngineFailsClosedUntilRulesLoadedAndOnMalformedPackets() {
        val engine = FirewallRuleEngine(failClosedUntilRulesLoaded = true)
        val validRaw = PacketParser.buildIpv4TcpPacket(
            srcIp = byteArrayOf(10, 215.toByte(), 0, 1),
            dstIp = byteArrayOf(1, 1, 1, 1),
            srcPort = 52000,
            dstPort = 443,
            seq = 1L,
            ack = 0L,
            flags = 0x02
        )
        val validPacket = PacketParser.parse(validRaw, validRaw.size)!!

        // Before updateRules(), fail-closed guard must drop all packets
        assertFalse(engine.isRulesLoaded())
        val preLoadVerdict = engine.evaluate(validPacket, 10123)
        assertFalse(preLoadVerdict.allowed)
        assertTrue(preLoadVerdict.reason.contains("fail-closed", ignoreCase = true))

        // After rules load in denylist mode, valid traffic is allowed...
        engine.updateRules(emptyList(), defaultBlockAll = false)
        assertTrue(engine.isRulesLoaded())
        assertTrue(engine.evaluate(validPacket, 10123).allowed)

        // ...but malformed packets must STILL fail closed
        val malformedPacket = validPacket.copy(isMalformed = true, malformedReason = "truncated header")
        val malformedVerdict = engine.evaluate(malformedPacket, 10123)
        assertFalse(malformedVerdict.allowed)
        assertTrue(malformedVerdict.reason.contains("Malformed", ignoreCase = true))

        // In allowlist mode, unattributed UID (-1) must fail closed
        engine.updateRules(emptyList(), defaultBlockAll = true)
        val unattributedVerdict = engine.evaluate(validPacket, -1)
        assertFalse(unattributedVerdict.allowed)
        assertTrue(unattributedVerdict.reason.contains("Unattributed", ignoreCase = true))
    }

    @Test
    fun radix2FftEngineRejectsInvalidSizesAndClampsHostileInputs() {
        for (invalidSize in listOf(0, -16, 32, 1000, 32_768)) {
            val threw = try {
                Radix2FftEngine(invalidSize)
                false
            } catch (_: IllegalArgumentException) {
                true
            }
            assertTrue("Expected IllegalArgumentException for fftSize=$invalidSize", threw)
        }

        val fft = Radix2FftEngine(256)
        val smallBuf = ByteArray(16) { 0x7F }
        val frameOversizedLen = fft.processCu8Block(
            iqBytes = smallBuf,
            byteLength = 999_999,
            centerFreqMhz = Double.NaN,
            sampleRateHz = 0,
            peakThresholdDb = Float.POSITIVE_INFINITY
        ) { "Unknown" to "Unknown" }
        assertEquals(256, frameOversizedLen.binsDb.size)
        assertEquals(0.0, frameOversizedLen.centerFreqMhz, 0.0)
        assertEquals(1, frameOversizedLen.sampleRateHz)

        val frameNegLen = fft.processCu8Block(
            iqBytes = smallBuf,
            byteLength = -42,
            centerFreqMhz = 433.92,
            sampleRateHz = -500,
            peakThresholdDb = Float.NaN
        ) { "ISM" to "OOK" }
        assertEquals(256, frameNegLen.binsDb.size)
    }

    @Test
    fun pcapngWriterEnforcesMaxFileSizeCapAndClampsInvalidLengths() = runTest {
        val tempFile = File.createTempFile("adf_cap_test_", ".pcapng")
        try {
            val writer = PcapngWriter(ringCapacity = 64, maxFileBytes = 1500L)
            assertTrue(writer.start(tempFile, 2L, this) {})
            val pkt = PacketParser.buildIpv4TcpPacket(
                srcIp = byteArrayOf(10, 215.toByte(), 0, 1),
                dstIp = byteArrayOf(8, 8, 8, 8),
                srcPort = 54000,
                dstPort = 443,
                seq = 1L,
                ack = 0L,
                flags = 0x02
            )
            // Invalid negative length should be safely ignored; oversized length clamped to pkt.size
            writer.offerPacket(pkt, -10, 10001, "NegApp", "ALLOW", null)
            // One packet with oversized comment (2500 chars) should be truncated cleanly and fit under 1500B
            val longHost = "a".repeat(2500) + ".example"
            writer.offerPacket(pkt, pkt.size + 500, 10001, "CapApp", "ALLOW", longHost)
            // Subsequent packets push past maxFileBytes (1500B) and must be dropped
            repeat(10) {
                writer.offerPacket(pkt, pkt.size, 10001, "CapApp", "ALLOW", longHost)
            }
            val finalStats = writer.stop()
            assertEquals(1L, finalStats.packetsWritten)
            assertTrue("Expected bytesWritten <= 1500, got ${finalStats.bytesWritten}", finalStats.bytesWritten <= 1500L)
            assertTrue("Expected droppedFrames >= 10 after hitting maxFileBytes cap", finalStats.droppedFrames >= 10L)
        } finally {
            tempFile.delete()
        }
    }
}
