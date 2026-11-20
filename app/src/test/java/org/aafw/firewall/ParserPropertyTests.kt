package org.aafw.firewall

import net.jqwik.api.Arbitraries
import net.jqwik.api.Arbitrary
import net.jqwik.api.Example
import net.jqwik.api.ForAll
import net.jqwik.api.Property
import net.jqwik.api.Provide
import net.jqwik.api.constraints.IntRange
import net.jqwik.api.constraints.Size
import org.aafw.firewall.engine.bluetooth.BleAdParser
import org.aafw.firewall.engine.bluetooth.BtSnoopParser
import org.aafw.firewall.engine.network.IdsEngine
import org.aafw.firewall.engine.network.PacketParser
import org.aafw.firewall.engine.network.TransportProtocol
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Tier 1: Fast deterministic property-based tests (jqwik) and adversarial regression suite
 * validating Zero-Crash, Bounded-Time O(n), and Bounded-Memory invariants across all
 * untrusted binary parsers and the inline IDS engine.
 */
class ParserPropertyTests {

    private val sharedIds = IdsEngine()

    init {
        // Warm up JIT paths before property timing checks
        PacketParser.parse(FuzzCorpusLoader.loadHexResource("ipv4_tcp_http.hex"))
        PacketParser.parse(FuzzCorpusLoader.loadHexResource("tls13_client_hello_sni.hex"))
        BtSnoopParser.parse(ByteArrayInputStream(FuzzCorpusLoader.loadHexResource("btsnoop_hci_sample.hex")))
        BleAdParser.parseAdStructures(FuzzCorpusLoader.loadHexResource("ble_ad_tlv_sample.hex"))
    }

    @Property(tries = 5_000)
    fun packetParserNeverCrashesOrHangs(
        @ForAll @Size(max = 2048) raw: ByteArray
    ) {
        val startNs = System.nanoTime()
        val parsed = PacketParser.parse(raw)
        if (parsed != null) {
            sharedIds.inspect(parsed, appUid = 10042, appLabel = "FuzzTarget")
        }
        val elapsedNs = System.nanoTime() - startNs
        assertTrue(elapsedNs < 50_000_000L, "Packet parse+IDS exceeded hang budget: ${elapsedNs}ns")
    }

    @Property(tries = 2_000)
    fun truncatedValidPacketsNeverCrash(
        @ForAll("validSeedPackets") packet: ByteArray,
        @ForAll @IntRange(min = 0, max = 512) cutAt: Int
    ) {
        val truncated = packet.copyOf(minOf(cutAt, packet.size))
        val parsed = PacketParser.parse(truncated)
        if (parsed != null) {
            sharedIds.inspect(parsed, appUid = 10042, appLabel = "TruncatedTarget")
        }
    }

    @Property(tries = 2_000)
    fun btSnoopParserRejectsArbitraryInputSafely(
        @ForAll @Size(max = 4096) raw: ByteArray
    ) {
        val result = BtSnoopParser.parse(ByteArrayInputStream(raw), "prop-fuzz")
        assertNotNull(result)
        assertTrue(result.frames.size <= 2000)
    }

    @Property(tries = 1_000)
    fun bleAdTlvParserNeverLoopsOrCrashes(
        @ForAll @Size(max = 512) raw: ByteArray
    ) {
        val startNs = System.nanoTime()
        val structures = BleAdParser.parseAdStructures(raw)
        val elapsedNs = System.nanoTime() - startNs
        assertTrue(structures.size <= BleAdParser.MAX_AD_STRUCTURES)
        assertTrue(elapsedNs < 25_000_000L, "BLE AD parse exceeded hang budget: ${elapsedNs}ns")
    }

    @Provide
    fun validSeedPackets(): Arbitrary<ByteArray> = Arbitraries.of(
        FuzzCorpusLoader.loadHexResource("ipv4_tcp_http.hex"),
        FuzzCorpusLoader.loadHexResource("ipv4_udp_dns.hex"),
        FuzzCorpusLoader.loadHexResource("ipv6_ext_headers.hex"),
        FuzzCorpusLoader.loadHexResource("tls13_client_hello_sni.hex"),
        FuzzCorpusLoader.loadHexResource("truncated_ipv4.hex")
    )

    // -------------------------------------------------------------------------
    // Deterministic Adversarial Regression Suite
    // -------------------------------------------------------------------------

    @Example
    fun corpusSeedsParseCleanlyWithExpectedMetadata() {
        val httpPkt = PacketParser.parse(FuzzCorpusLoader.loadHexResource("ipv4_tcp_http.hex"))
        assertNotNull(httpPkt)
        assertFalse(httpPkt!!.isMalformed)
        assertEquals(TransportProtocol.TCP, httpPkt.protocol)
        assertEquals("example.com", httpPkt.httpInfo?.hostHeader)

        val dnsPkt = PacketParser.parse(FuzzCorpusLoader.loadHexResource("ipv4_udp_dns.hex"))
        assertNotNull(dnsPkt)
        assertFalse(dnsPkt!!.isMalformed)
        assertEquals("api.example.com", dnsPkt.dnsQueryDomain)

        val ipv6Pkt = PacketParser.parse(FuzzCorpusLoader.loadHexResource("ipv6_ext_headers.hex"))
        assertNotNull(ipv6Pkt)
        assertFalse(ipv6Pkt!!.isMalformed)
        assertEquals(6, ipv6Pkt.ipVersion)
        assertEquals(TransportProtocol.UDP, ipv6Pkt.protocol)
        assertEquals(443, ipv6Pkt.dstPort)
        assertEquals(4, ipv6Pkt.payloadLength)

        val tlsPkt = PacketParser.parse(FuzzCorpusLoader.loadHexResource("tls13_client_hello_sni.hex"))
        assertNotNull(tlsPkt)
        assertFalse(tlsPkt!!.isMalformed)
        assertEquals("secure.example.org", tlsPkt.tlsInfo?.sniHost)
        assertEquals("TLS 1.3", tlsPkt.tlsInfo?.tlsVersionLabel)

        val truncPkt = PacketParser.parse(FuzzCorpusLoader.loadHexResource("truncated_ipv4.hex"))
        assertNotNull(truncPkt)
        assertTrue(truncPkt!!.isMalformed)

        val btResult = BtSnoopParser.parse(ByteArrayInputStream(FuzzCorpusLoader.loadHexResource("btsnoop_hci_sample.hex")))
        assertNull(btResult.error)
        assertEquals(2, btResult.totalFrames)
        assertEquals("HCI_Reset", btResult.frames[0].summary)
        assertEquals("LE Advertising Report", btResult.frames[1].summary)
        assertTrue(btResult.frames[1].detail.contains("AD_Structures=2"))

        val bleAds = BleAdParser.parseAdStructures(FuzzCorpusLoader.loadHexResource("ble_ad_tlv_sample.hex"))
        assertEquals(3, bleAds.size)
        assertEquals(0x01, bleAds[0].adType)
        assertEquals(0x09, bleAds[1].adType)
        assertEquals(0xFF, bleAds[2].adType)
    }

    @Example
    fun ipv4AdversarialIhlTotalLenAndZeroLengthOptionLoopAreRejected() {
        // 1. IHL < 5 (0x42 => IHL = 8 bytes)
        val badIhl = ByteArray(40)
        badIhl[0] = 0x42
        badIhl[3] = 40
        assertTrue(PacketParser.parse(badIhl)!!.isMalformed)

        // 2. totalLength < IHL
        val badTotalLen = ByteArray(40)
        badTotalLen[0] = 0x45
        badTotalLen[2] = 0x00
        badTotalLen[3] = 0x0A // 10 < 20
        assertTrue(PacketParser.parse(badTotalLen)!!.isMalformed)

        // 3. IPv4 options with option type 0x07 (Record Route) and option length = 0 (classic infinite loop bug)
        val zeroLenOpt = ByteArray(48)
        zeroLenOpt[0] = 0x47 // IHL = 7 * 4 = 28 bytes (8 bytes of options)
        zeroLenOpt[3] = 48
        zeroLenOpt[9] = 17 // UDP
        zeroLenOpt[20] = 0x07 // Option kind != 0, != 1
        zeroLenOpt[21] = 0x00 // Zero length!
        assertTrue(PacketParser.parse(zeroLenOpt)!!.isMalformed)
    }

    @Example
    fun ipv6ExtensionHeaderChainBeyondMaxCapTerminatesAndFlagsMalformed() {
        // Chain 12 Hop-by-Hop headers (exceeds MAX_IPV6_EXT_HEADERS = 8)
        val extCount = 12
        val totalLen = 40 + extCount * 8 + 8
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x60 // IPv6
        val payloadLen = extCount * 8 + 8
        pkt[4] = ((payloadLen ushr 8) and 0xFF).toByte()
        pkt[5] = (payloadLen and 0xFF).toByte()
        pkt[6] = 0x00 // Hop-by-Hop
        pkt[7] = 64
        for (i in 0 until extCount) {
            val off = 40 + i * 8
            pkt[off] = if (i == extCount - 1) 17 else 0 // Next header = Hop-by-Hop, then UDP
            pkt[off + 1] = 0 // (0 + 1) * 8 = 8 bytes
        }
        val parsed = PacketParser.parse(pkt)
        assertNotNull(parsed)
        assertTrue(parsed!!.isMalformed)
    }

    @Example
    fun tcpZeroLengthOptionsAndInvalidDataOffsetAreRejected() {
        // TCP dataOffset < 5 (0x30 => 12 bytes)
        val badOffset = ByteArray(40)
        badOffset[0] = 0x45
        badOffset[3] = 40
        badOffset[9] = 6 // TCP
        badOffset[32] = 0x30
        assertTrue(PacketParser.parse(badOffset)!!.isMalformed)

        // TCP option kind 0x02 (MSS) with optLen = 0 (infinite loop attempt)
        val zeroTcpOpt = ByteArray(48)
        zeroTcpOpt[0] = 0x45
        zeroTcpOpt[3] = 48
        zeroTcpOpt[9] = 6 // TCP
        zeroTcpOpt[32] = 0x70 // 28-byte TCP header (8 bytes of options)
        zeroTcpOpt[40] = 0x02 // MSS kind
        zeroTcpOpt[41] = 0x00 // Zero length!
        assertTrue(PacketParser.parse(zeroTcpOpt)!!.isMalformed)
    }

    @Example
    fun udpInvalidLengthsAreFlaggedMalformed() {
        // UDP length < 8
        val udpShort = ByteArray(32)
        udpShort[0] = 0x45
        udpShort[3] = 32
        udpShort[9] = 17
        udpShort[24] = 0x00
        udpShort[25] = 0x04 // 4 < 8
        assertTrue(PacketParser.parse(udpShort)!!.isMalformed)

        // UDP length > remaining
        val udpOversized = ByteArray(32)
        udpOversized[0] = 0x45
        udpOversized[3] = 32
        udpOversized[9] = 17
        udpOversized[24] = 0x10
        udpOversized[25] = 0x00 // 4096 > 12 remaining
        assertTrue(PacketParser.parse(udpOversized)!!.isMalformed)
    }

    @Example
    fun dnsCompressionPointerCyclesAndHeaderJumpsNeverHang() {
        // Self-referencing pointer at offset 12 -> 0xC0 0x0C
        val selfLoopDns = byteArrayOf(
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0.toByte(), 0x0C, 0x00, 0x01, 0x00, 0x01
        )
        assertNull(PacketParser.extractDnsQueryDomain(selfLoopDns, 0, selfLoopDns.size))

        // 2-node mutual pointer cycle: offset 12 -> 14, offset 14 -> 12
        val twoNodeCycleDns = byteArrayOf(
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0.toByte(), 0x0E,
            0xC0.toByte(), 0x0C,
            0x00, 0x01, 0x00, 0x01
        )
        assertNull(PacketParser.extractDnsQueryDomain(twoNodeCycleDns, 0, twoNodeCycleDns.size))

        // Pointer jumping into DNS header (< 12)
        val headerJumpDns = byteArrayOf(
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xC0.toByte(), 0x00, 0x00, 0x01, 0x00, 0x01
        )
        assertNull(PacketParser.extractDnsQueryDomain(headerJumpDns, 0, headerJumpDns.size))
    }

    @Example
    fun idsEngineIsImmuneToReDoSAndEnforcesLruFlowCap() {
        val ids = IdsEngine()

        // 1. Pathological 8 KB ReDoS input targeting SQLi / CMDi / path traversal patterns
        val evilPayload = buildString {
            append("GET /search?q=")
            append("; cat ")
            repeat(2000) { append("a") }
            append("../".repeat(500))
            append("union")
            repeat(1500) { append(" ") }
            append("select HTTP/1.1\r\nHost: target.example\r\n\r\n")
        }.toByteArray(Charsets.ISO_8859_1)

        val tcpPacket = PacketParser.buildIpv4TcpPacket(
            srcIp = byteArrayOf(10, 0, 0, 2),
            dstIp = byteArrayOf(93.toByte(), 184.toByte(), 216.toByte(), 34),
            srcPort = 51000,
            dstPort = 80,
            seq = 1,
            ack = 1,
            flags = 0x18,
            payload = evilPayload
        )
        val parsed = PacketParser.parse(tcpPacket)!!
        assertTrue(parsed.httpInfo!!.inspectableText.length <= PacketParser.MAX_HTTP_INSPECT_BYTES)

        val startNs = System.nanoTime()
        repeat(20) {
            ids.inspect(parsed, appUid = 10100, appLabel = "ReDoSTest")
        }
        val elapsedMs = (System.nanoTime() - startNs) / 1_000_000L
        assertTrue(elapsedMs < 200L, "RE2J IDS inspection took too long: ${elapsedMs}ms")

        // 2. Spoofed-IP flow table flood (> MAX_TRACKED_FLOWS = 4,096)
        val floodIds = IdsEngine()
        for (i in 0 until 6_000) {
            val dstIp = byteArrayOf(
                198.toByte(),
                18,
                ((i ushr 8) and 0xFF).toByte(),
                (i and 0xFF).toByte()
            )
            val syn = PacketParser.buildIpv4TcpPacket(
                srcIp = byteArrayOf(10, 0, 0, 2),
                dstIp = dstIp,
                srcPort = 40000 + (i % 1000),
                dstPort = 443,
                seq = i.toLong(),
                ack = 0,
                flags = 0x02 // SYN
            )
            floodIds.inspect(PacketParser.parse(syn)!!, appUid = 10200, appLabel = "FloodSim")
        }
        assertTrue(
            floodIds.trackedFlowCount() <= IdsEngine.MAX_TRACKED_FLOWS,
            "Flow table exceeded LRU cap: ${floodIds.trackedFlowCount()}"
        )
    }

    @Example
    fun btSnoopRejectsOomLengthFieldsAndHandlesTruncatedTrailingRecordsGracefully() {
        fun buildHeader(datalink: Int = 1002): ByteArray = ByteBuffer.allocate(16)
            .order(ByteOrder.BIG_ENDIAN)
            .put(byteArrayOf(0x62, 0x74, 0x73, 0x6E, 0x6F, 0x6F, 0x70, 0x00))
            .putInt(1)
            .putInt(datalink)
            .array()

        fun buildRecordHeader(origLen: Int, inclLen: Int): ByteArray = ByteBuffer.allocate(24)
            .order(ByteOrder.BIG_ENDIAN)
            .putInt(origLen)
            .putInt(inclLen)
            .putInt(2)
            .putInt(0)
            .putLong(0x00dcddb30f2f8000L)
            .array()

        // 1. Huge inclLen = Int.MAX_VALUE on 40-byte stream must NOT trigger OOM
        val oomAttempt = buildHeader() + buildRecordHeader(Int.MAX_VALUE, Int.MAX_VALUE)
        val oomResult = BtSnoopParser.parse(ByteArrayInputStream(oomAttempt), "oom-test")
        assertEquals(0, oomResult.totalFrames)

        // 2. Negative inclLen = -1 must NOT throw NegativeArraySizeException
        val negAttempt = buildHeader() + buildRecordHeader(-1, -1)
        val negResult = BtSnoopParser.parse(ByteArrayInputStream(negAttempt), "neg-test")
        assertEquals(0, negResult.totalFrames)

        // 3. Invalid datalink (9999) rejected explicitly
        val badDatalink = BtSnoopParser.parse(ByteArrayInputStream(buildHeader(datalink = 9999)), "bad-dl")
        assertNotNull(badDatalink.error)

        // 4. Valid first record + truncated trailing record retains first record cleanly
        val baos = ByteArrayOutputStream()
        baos.write(buildHeader())
        baos.write(buildRecordHeader(4, 4))
        baos.write(byteArrayOf(0x01, 0x03, 0x0C, 0x00)) // Valid HCI_Reset
        baos.write(buildRecordHeader(32, 32))
        baos.write(byteArrayOf(0x04, 0x3E, 0x05)) // Truncated (only 3 of 32 bytes present)
        val partialResult = BtSnoopParser.parse(ByteArrayInputStream(baos.toByteArray()), "partial-test")
        assertNull(partialResult.error)
        assertEquals(1, partialResult.totalFrames)
        assertEquals("HCI_Reset", partialResult.frames.single().summary)
    }

    @Example
    fun bleAdTlvHandlesZeroLengthTerminatorAndOversizedField() {
        // Explicit 0x00 terminator followed by garbage must stop immediately
        val zeroTerminated = byteArrayOf(0x02, 0x01, 0x06, 0x00, 0x05, 0x09, 0x41, 0x42)
        assertEquals(1, BleAdParser.parseAdStructures(zeroTerminated).size)

        // Oversized length (0xFF) on 4-byte buffer must return safely without throwing
        val oversized = byteArrayOf(0xFF.toByte(), 0x09, 0x41, 0x42)
        assertEquals(0, BleAdParser.parseAdStructures(oversized).size)
    }
}
