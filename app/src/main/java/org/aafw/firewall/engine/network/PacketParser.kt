package org.aafw.firewall.engine.network

import org.aafw.firewall.engine.SafeByteCursor
import java.nio.ByteBuffer
import java.security.MessageDigest

enum class TransportProtocol(val ipProto: Int, val label: String) {
    TCP(6, "TCP"),
    UDP(17, "UDP"),
    ICMP(1, "ICMP"),
    ICMPV6(58, "ICMPv6"),
    OTHER(-1, "OTHER");

    companion object {
        fun fromIpProto(proto: Int): TransportProtocol = when (proto) {
            6 -> TCP
            17 -> UDP
            1 -> ICMP
            58 -> ICMPV6
            else -> OTHER
        }
    }
}

data class HttpParsedPayload(
    val isRequest: Boolean,
    val method: String?,
    val rawTarget: String?,
    val statusCode: Int?,
    val hostHeader: String?,
    val inspectableText: String
)

data class TlsClientHelloInfo(
    val sniHost: String?,
    val ja3Hash: String,
    val tlsVersionLabel: String
)

data class ParsedPacket(
    val ipVersion: Int,
    val headerLength: Int,
    val totalLength: Int,
    val protocol: TransportProtocol,
    val srcIp: String,
    val dstIp: String,
    val srcIpBytes: ByteArray,
    val dstIpBytes: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val tcpFlags: Int,
    val tcpSeq: Long,
    val tcpAck: Long,
    val payloadOffset: Int,
    val payloadLength: Int,
    val dnsQueryDomain: String?,
    val tlsInfo: TlsClientHelloInfo?,
    val httpInfo: HttpParsedPayload?,
    val isMalformed: Boolean
) {
    val isTcpSyn: Boolean get() = protocol == TransportProtocol.TCP && (tcpFlags and 0x02) != 0 && (tcpFlags and 0x10) == 0
    val isTcpAck: Boolean get() = protocol == TransportProtocol.TCP && (tcpFlags and 0x10) != 0
    val isTcpFin: Boolean get() = protocol == TransportProtocol.TCP && (tcpFlags and 0x01) != 0
    val isTcpRst: Boolean get() = protocol == TransportProtocol.TCP && (tcpFlags and 0x04) != 0
    val domainOrSni: String? get() = dnsQueryDomain ?: tlsInfo?.sniHost ?: httpInfo?.hostHeader
}

/**
 * Hardened zero-crash, O(n), bounded-memory binary packet dissector for untrusted TUN packets.
 *
 * Defends against:
 * - Signed-byte bitshift pitfalls (all reads go through unsigned [SafeByteCursor])
 * - IPv4 IHL < 5, truncated totalLength, and zero-length IPv4 options infinite loops
 * - IPv6 extension-header chains/cycles (strict [MAX_IPV6_EXT_HEADERS] cap + monotonic offset advance)
 * - TCP dataOffset < 5 and zero/invalid-length TCP option loops
 * - UDP length < 8 or exceeding packet bounds
 * - DNS compression pointer self-loops / cycles ([MAX_DNS_POINTER_JUMPS] + visited offset set)
 * - Nested TLS ClientHello extension/SNI over-reads
 */
object PacketParser {
    const val MAX_IPV4_OPTIONS = 40
    const val MAX_IPV6_EXT_HEADERS = 8
    const val MAX_TCP_OPTIONS = 40
    const val MAX_DNS_POINTER_JUMPS = 16
    const val MAX_DNS_LABELS = 128
    const val MAX_TLS_EXTENSIONS = 64
    const val MAX_TLS_CIPHERS = 512
    const val MAX_HTTP_INSPECT_BYTES = 2048

    private val httpMethods = listOf("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")

    private val ipv6ExtHeaders = setOf(
        0,  // Hop-by-Hop Options
        43, // Routing
        44, // Fragment
        51, // Authentication Header (AH)
        60  // Destination Options
    )

    fun parse(raw: ByteArray): ParsedPacket? = parse(raw, raw.size)

    fun parse(raw: ByteArray, length: Int): ParsedPacket? {
        if (length <= 0 || raw.isEmpty()) return null
        val safeLen = minOf(length, raw.size)
        if (safeLen < 20) {
            return malformedStub(4, safeLen)
        }
        val cursor = SafeByteCursor.of(raw, 0, safeLen) ?: return malformedStub(4, safeLen)
        val versionByte = cursor.peekU8() ?: return malformedStub(4, safeLen)
        val version = (versionByte ushr 4) and 0x0F
        return when (version) {
            4 -> parseIpv4(raw, cursor, safeLen)
            6 -> parseIpv6(raw, cursor, safeLen)
            else -> malformedStub(version, safeLen)
        }
    }

    private fun parseIpv4(raw: ByteArray, cursor: SafeByteCursor, safeLen: Int): ParsedPacket {
        val verIhl = cursor.readU8() ?: return malformedStub(4, safeLen)
        val ihl = (verIhl and 0x0F) * 4
        if (ihl < 20 || ihl > safeLen) return malformedStub(4, safeLen)

        if (!cursor.skip(1)) return malformedStub(4, safeLen) // DSCP/ECN
        val totalLen = cursor.readU16BE() ?: return malformedStub(4, safeLen)
        val effectiveLen = minOf(safeLen, maxOf(totalLen, ihl))
        var isMalformed = totalLen < ihl || totalLen > safeLen

        if (!cursor.skip(5)) return malformedStub(4, safeLen) // ID(2) + Flags/Frag(2) + TTL(1)
        val protoByte = cursor.readU8() ?: return malformedStub(4, safeLen)
        val proto = TransportProtocol.fromIpProto(protoByte)
        if (!cursor.skip(2)) return malformedStub(4, safeLen) // Header checksum

        val srcBytes = cursor.readBytes(4, 4) ?: return malformedStub(4, safeLen)
        val dstBytes = cursor.readBytes(4, 4) ?: return malformedStub(4, safeLen)

        // Validate IPv4 options TLV (defends against zero-length option infinite loops)
        val optionsLen = ihl - 20
        if (optionsLen > 0) {
            val optCursor = cursor.slice(optionsLen)
            if (optCursor == null || !validateIpv4Options(optCursor)) {
                isMalformed = true
            }
        }

        val transportCursor = SafeByteCursor.of(raw, ihl, effectiveLen - ihl)
            ?: return malformedStub(4, safeLen)

        return parseTransport(
            raw = raw,
            transportCursor = transportCursor,
            ipVersion = 4,
            ipHeaderLen = ihl,
            totalLen = effectiveLen,
            proto = proto,
            srcIp = formatIpv4(srcBytes),
            dstIp = formatIpv4(dstBytes),
            srcBytes = srcBytes,
            dstBytes = dstBytes,
            initialMalformed = isMalformed
        )
    }

    private fun validateIpv4Options(optCursor: SafeByteCursor): Boolean {
        var count = 0
        while (!optCursor.isExhausted && count < MAX_IPV4_OPTIONS) {
            count++
            val beforePos = optCursor.pos
            val optType = optCursor.readU8() ?: return false
            when (optType) {
                0x00 -> return true // End of Option List
                0x01 -> Unit // NOP (1 byte)
                else -> {
                    val optLen = optCursor.readU8() ?: return false
                    if (optLen < 2 || !optCursor.skip(optLen - 2)) return false
                }
            }
            if (optCursor.pos <= beforePos) return false
        }
        return true
    }

    private fun parseIpv6(raw: ByteArray, cursor: SafeByteCursor, safeLen: Int): ParsedPacket {
        if (safeLen < 40) return malformedStub(6, safeLen)
        if (!cursor.skip(4)) return malformedStub(6, safeLen) // Version/TC/FlowLabel
        val payloadLen = cursor.readU16BE() ?: return malformedStub(6, safeLen)
        var nextHeader = cursor.readU8() ?: return malformedStub(6, safeLen)
        if (!cursor.skip(1)) return malformedStub(6, safeLen) // Hop Limit

        val srcBytes = cursor.readBytes(16, 16) ?: return malformedStub(6, safeLen)
        val dstBytes = cursor.readBytes(16, 16) ?: return malformedStub(6, safeLen)

        val effectiveLen = minOf(safeLen, 40 + payloadLen)
        var isMalformed = (40 + payloadLen) > safeLen

        val payloadCursor = SafeByteCursor.of(raw, 40, effectiveLen - 40)
            ?: return malformedStub(6, safeLen)

        // Safely traverse IPv6 extension header chain with strict hop limit and monotonic advance
        var extCount = 0
        while (nextHeader in ipv6ExtHeaders) {
            if (extCount >= MAX_IPV6_EXT_HEADERS) {
                isMalformed = true
                break
            }
            extCount++
            val beforePos = payloadCursor.pos
            val nextHdrField = payloadCursor.readU8()
            if (nextHdrField == null) {
                isMalformed = true
                break
            }
            val skipped = when (nextHeader) {
                44 -> payloadCursor.skip(7) // Fragment header is fixed 8 bytes total
                51 -> {
                    // Authentication Header: length in 32-bit words minus 2 => (hdrExtLen + 2) * 4 bytes total
                    val ahLenUnits = payloadCursor.readU8()
                    if (ahLenUnits == null) {
                        false
                    } else {
                        val totalAhBytes = (ahLenUnits + 2) * 4
                        totalAhBytes >= 8 && payloadCursor.skip(totalAhBytes - 2)
                    }
                }
                else -> {
                    // Hop-by-Hop (0), Routing (43), Dest Options (60): (hdrExtLen + 1) * 8 bytes total
                    val extLenUnits = payloadCursor.readU8()
                    if (extLenUnits == null) {
                        false
                    } else {
                        val totalExtBytes = (extLenUnits + 1) * 8
                        totalExtBytes >= 8 && payloadCursor.skip(totalExtBytes - 2)
                    }
                }
            }
            if (!skipped || payloadCursor.pos <= beforePos) {
                isMalformed = true
                break
            }
            nextHeader = nextHdrField
        }

        val proto = TransportProtocol.fromIpProto(nextHeader)
        val transportHeaderStart = payloadCursor.pos
        val transportCursor = SafeByteCursor.of(raw, transportHeaderStart, effectiveLen - transportHeaderStart)
            ?: return malformedStub(6, safeLen)

        return parseTransport(
            raw = raw,
            transportCursor = transportCursor,
            ipVersion = 6,
            ipHeaderLen = transportHeaderStart,
            totalLen = effectiveLen,
            proto = proto,
            srcIp = formatIpv6(srcBytes),
            dstIp = formatIpv6(dstBytes),
            srcBytes = srcBytes,
            dstBytes = dstBytes,
            initialMalformed = isMalformed
        )
    }

    private fun parseTransport(
        raw: ByteArray,
        transportCursor: SafeByteCursor,
        ipVersion: Int,
        ipHeaderLen: Int,
        totalLen: Int,
        proto: TransportProtocol,
        srcIp: String,
        dstIp: String,
        srcBytes: ByteArray,
        dstBytes: ByteArray,
        initialMalformed: Boolean
    ): ParsedPacket {
        var srcPort = 0
        var dstPort = 0
        var tcpFlags = 0
        var tcpSeq = 0L
        var tcpAck = 0L
        var payloadOffset = ipHeaderLen
        var payloadLen = 0
        var malformed = initialMalformed

        when (proto) {
            TransportProtocol.TCP -> {
                if (transportCursor.remaining < 20) {
                    malformed = true
                    payloadOffset = totalLen
                } else {
                    srcPort = transportCursor.readU16BE() ?: 0
                    dstPort = transportCursor.readU16BE() ?: 0
                    tcpSeq = transportCursor.readU32BE() ?: 0L
                    tcpAck = transportCursor.readU32BE() ?: 0L
                    val offsetByte = transportCursor.readU8() ?: 0
                    val flagsByte = transportCursor.readU8() ?: 0
                    transportCursor.skip(6) // Window(2) + Checksum(2) + Urgent(2)

                    val dataOffsetWords = (offsetByte ushr 4) and 0x0F
                    val dataOffsetBytes = dataOffsetWords * 4
                    tcpFlags = flagsByte and 0x3F

                    if (dataOffsetWords < 5 || dataOffsetBytes > (totalLen - ipHeaderLen)) {
                        malformed = true
                        payloadOffset = totalLen
                    } else {
                        val optBytes = dataOffsetBytes - 20
                        if (optBytes > 0) {
                            val optCursor = transportCursor.slice(optBytes)
                            if (optCursor == null || !validateTcpOptions(optCursor)) {
                                malformed = true
                            }
                        }
                        payloadOffset = ipHeaderLen + dataOffsetBytes
                        payloadLen = maxOf(0, totalLen - payloadOffset)
                    }
                }
            }
            TransportProtocol.UDP -> {
                if (transportCursor.remaining < 8) {
                    malformed = true
                    payloadOffset = totalLen
                } else {
                    srcPort = transportCursor.readU16BE() ?: 0
                    dstPort = transportCursor.readU16BE() ?: 0
                    val udpLen = transportCursor.readU16BE() ?: 0
                    transportCursor.skip(2) // UDP Checksum
                    val maxUdpAvailable = totalLen - ipHeaderLen
                    if (udpLen < 8 || udpLen > maxUdpAvailable) {
                        malformed = true
                        payloadOffset = ipHeaderLen + 8
                        payloadLen = maxOf(0, totalLen - payloadOffset)
                    } else {
                        payloadOffset = ipHeaderLen + 8
                        payloadLen = udpLen - 8
                    }
                }
            }
            else -> {
                payloadOffset = minOf(totalLen, ipHeaderLen + 8)
                payloadLen = maxOf(0, totalLen - payloadOffset)
            }
        }

        var dnsDomain: String? = null
        var tlsInfo: TlsClientHelloInfo? = null
        var httpInfo: HttpParsedPayload? = null

        if (!malformed && payloadLen > 0 && payloadOffset >= 0 && payloadOffset + payloadLen <= raw.size) {
            if (proto == TransportProtocol.UDP && (dstPort == 53 || srcPort == 53)) {
                dnsDomain = extractDnsQueryDomain(raw, payloadOffset, payloadLen)
            } else if (proto == TransportProtocol.TCP) {
                val firstPayloadByte = raw[payloadOffset].toInt() and 0xFF
                if (firstPayloadByte == 0x16 && payloadLen > 43) {
                    tlsInfo = extractTlsClientHello(raw, payloadOffset, payloadLen)
                } else {
                    httpInfo = extractHttpPayload(raw, payloadOffset, payloadLen)
                }
            }
        }

        return ParsedPacket(
            ipVersion = ipVersion,
            headerLength = ipHeaderLen,
            totalLength = totalLen,
            protocol = proto,
            srcIp = srcIp,
            dstIp = dstIp,
            srcIpBytes = srcBytes,
            dstIpBytes = dstBytes,
            srcPort = srcPort,
            dstPort = dstPort,
            tcpFlags = tcpFlags,
            tcpSeq = tcpSeq,
            tcpAck = tcpAck,
            payloadOffset = payloadOffset,
            payloadLength = payloadLen,
            dnsQueryDomain = dnsDomain,
            tlsInfo = tlsInfo,
            httpInfo = httpInfo,
            isMalformed = malformed
        )
    }

    private fun validateTcpOptions(optCursor: SafeByteCursor): Boolean {
        var count = 0
        while (!optCursor.isExhausted && count < MAX_TCP_OPTIONS) {
            count++
            val beforePos = optCursor.pos
            val kind = optCursor.readU8() ?: return false
            when (kind) {
                0x00 -> return true // End of Options List
                0x01 -> Unit // NOP (1 byte)
                else -> {
                    val optLen = optCursor.readU8() ?: return false
                    if (optLen < 2 || !optCursor.skip(optLen - 2)) return false
                }
            }
            if (optCursor.pos <= beforePos) return false
        }
        return true
    }

    /**
     * Parses a DNS QNAME from a UDP DNS message with full cycle protection against
     * RFC 1035 0xC0 compression pointer loops.
     */
    fun extractDnsQueryDomain(buf: ByteArray, offset: Int, len: Int): String? {
        val dnsCursor = SafeByteCursor.of(buf, offset, len) ?: return null
        if (dnsCursor.size < 13) return null
        if (!dnsCursor.skip(4)) return null // Transaction ID(2) + Flags(2)
        val qdCount = dnsCursor.readU16BE() ?: return null
        if (qdCount <= 0) return null
        if (!dnsCursor.skip(6)) return null // ANCOUNT + NSCOUNT + ARCOUNT

        val visitedOffsets = HashSet<Int>(16)
        val sb = StringBuilder()
        var labelCount = 0
        var pointerJumps = 0

        while (!dnsCursor.isExhausted && labelCount < MAX_DNS_LABELS) {
            val relOffset = dnsCursor.pos - dnsCursor.start
            if (!visitedOffsets.add(relOffset)) {
                // Detected compression cycle or revisit
                return null
            }

            val labelLen = dnsCursor.readU8() ?: return null
            if (labelLen == 0) break

            val highBits = labelLen and 0xC0
            if (highBits == 0xC0) {
                pointerJumps++
                if (pointerJumps > MAX_DNS_POINTER_JUMPS) return null
                val secondByte = dnsCursor.readU8() ?: return null
                val targetRelOffset = ((labelLen and 0x3F) shl 8) or secondByte
                if (targetRelOffset < 12 || targetRelOffset >= dnsCursor.size || targetRelOffset in visitedOffsets) {
                    return null
                }
                if (!dnsCursor.seekRelative(targetRelOffset)) return null
                continue
            } else if (highBits != 0) {
                // Reserved/invalid RFC 1035 label type bits
                return null
            }

            if (labelLen > 63 || labelLen > dnsCursor.remaining) return null
            val labelText = dnsCursor.readAscii(labelLen) ?: return null
            if (sb.isNotEmpty()) sb.append('.')
            if (sb.length + labelText.length > 253) return null
            for (ch in labelText) {
                val lower = ch.lowercaseChar()
                if (lower !in 'a'..'z' && lower !in '0'..'9' && lower != '-' && lower != '_') {
                    return null
                }
                sb.append(lower)
            }
            labelCount++
        }
        return sb.toString().takeIf { it.contains('.') && it.length in 3..253 }
    }

    /**
     * Bounds-checked TLS ClientHello dissector using zero-copy [SafeByteCursor] sub-slices
     * for every nested record, handshake, cipher, extension, and SNI boundary.
     */
    fun extractTlsClientHello(buf: ByteArray, offset: Int, len: Int): TlsClientHelloInfo? {
        val outer = SafeByteCursor.of(buf, offset, len) ?: return null
        if (outer.size < 48) return null

        val contentType = outer.readU8() ?: return null
        if (contentType != 0x16) return null // TLS Handshake record
        if (!outer.skip(2)) return null // Record protocol version
        val recordLen = outer.readU16BE() ?: return null
        val recordCursor = outer.slice(minOf(recordLen, outer.remaining)) ?: return null

        val handshakeType = recordCursor.readU8() ?: return null
        if (handshakeType != 0x01) return null // ClientHello
        val handshakeLen = recordCursor.readU24BE() ?: return null
        val hsCursor = recordCursor.slice(minOf(handshakeLen, recordCursor.remaining)) ?: return null

        val clientVersion = hsCursor.readU16BE() ?: return null
        if (!hsCursor.skip(32)) return null // Client Random

        val sessionIdLen = hsCursor.readU8() ?: return null
        if (!hsCursor.skip(sessionIdLen)) return null

        val cipherLen = hsCursor.readU16BE() ?: return null
        if (cipherLen % 2 != 0) return null
        val cipherCursor = hsCursor.slice(cipherLen) ?: return null
        val ciphers = ArrayList<Int>(minOf(cipherLen / 2, MAX_TLS_CIPHERS))
        while (cipherCursor.remaining >= 2 && ciphers.size < MAX_TLS_CIPHERS) {
            val cs = cipherCursor.readU16BE() ?: break
            if (!isGreaseValue(cs)) ciphers.add(cs)
        }

        val compLen = hsCursor.readU8() ?: return null
        if (!hsCursor.skip(compLen)) return null

        var sni: String? = null
        val extensions = ArrayList<Int>()
        val groups = ArrayList<Int>()
        val ecFormats = ArrayList<Int>()
        var negotiatedTls13 = false

        if (hsCursor.remaining >= 2) {
            val extTotalLen = hsCursor.readU16BE() ?: return null
            val extListCursor = hsCursor.slice(minOf(extTotalLen, hsCursor.remaining)) ?: return null

            var extCount = 0
            while (extListCursor.remaining >= 4 && extCount < MAX_TLS_EXTENSIONS) {
                extCount++
                val extType = extListCursor.readU16BE() ?: break
                val extLen = extListCursor.readU16BE() ?: break
                val extCursor = extListCursor.slice(extLen) ?: break
                if (!isGreaseValue(extType)) extensions.add(extType)

                when (extType) {
                    0x0000 -> { // SNI
                        val sniListLen = extCursor.readU16BE()
                        if (sniListLen != null) {
                            val sniList = extCursor.slice(sniListLen)
                            if (sniList != null && sniList.remaining >= 3) {
                                val nameType = sniList.readU8()
                                val nameLen = sniList.readU16BE()
                                if (nameType == 0 && nameLen != null && nameLen in 1..253) {
                                    sni = sniList.readAscii(nameLen)?.lowercase()
                                }
                            }
                        }
                    }
                    0x000A -> { // Supported Groups
                        val listLen = extCursor.readU16BE()
                        if (listLen != null && listLen % 2 == 0) {
                            val gCursor = extCursor.slice(listLen)
                            while (gCursor != null && gCursor.remaining >= 2 && groups.size < 64) {
                                val g = gCursor.readU16BE() ?: break
                                if (!isGreaseValue(g)) groups.add(g)
                            }
                        }
                    }
                    0x000B -> { // EC Point Formats
                        val fmtLen = extCursor.readU8()
                        if (fmtLen != null) {
                            val fCursor = extCursor.slice(fmtLen)
                            while (fCursor != null && !fCursor.isExhausted && ecFormats.size < 32) {
                                ecFormats.add(fCursor.readU8() ?: break)
                            }
                        }
                    }
                    0x002B -> { // Supported Versions
                        val vLen = extCursor.readU8()
                        if (vLen != null && vLen % 2 == 0) {
                            val vCursor = extCursor.slice(vLen)
                            while (vCursor != null && vCursor.remaining >= 2) {
                                if (vCursor.readU16BE() == 0x0304) negotiatedTls13 = true
                            }
                        }
                    }
                }
            }
        }

        val ja3Raw = buildString {
            append(clientVersion)
            append(',')
            append(ciphers.joinToString("-"))
            append(',')
            append(extensions.joinToString("-"))
            append(',')
            append(groups.joinToString("-"))
            append(',')
            append(ecFormats.joinToString("-"))
        }
        val ja3Md5 = md5Hex(ja3Raw)
        val versionLabel = when {
            negotiatedTls13 -> "TLS 1.3"
            clientVersion == 0x0303 -> "TLS 1.2"
            clientVersion == 0x0302 -> "TLS 1.1"
            else -> "TLS 0x${clientVersion.toString(16)}"
        }
        return TlsClientHelloInfo(sniHost = sni, ja3Hash = ja3Md5, tlsVersionLabel = versionLabel)
    }

    fun extractHttpPayload(buf: ByteArray, offset: Int, len: Int): HttpParsedPayload? {
        val sampleLen = minOf(len, MAX_HTTP_INSPECT_BYTES)
        if (sampleLen < 12) return null
        val cursor = SafeByteCursor.of(buf, offset, sampleLen) ?: return null
        val text = cursor.readLatin1(sampleLen) ?: return null

        val isResponse = text.startsWith("HTTP/1.") || text.startsWith("HTTP/2")
        val matchedMethod = if (!isResponse) httpMethods.firstOrNull { text.startsWith(it) }?.trim() else null
        if (!isResponse && matchedMethod == null) return null

        val firstLineEnd = text.indexOf("\r\n").takeIf { it > 0 } ?: text.indexOf('\n').takeIf { it > 0 } ?: sampleLen
        val firstLine = text.substring(0, firstLineEnd)
        val parts = firstLine.split(' ')

        val target = if (!isResponse && parts.size >= 2) parts[1] else null
        val status = if (isResponse && parts.size >= 2) parts[1].toIntOrNull() else null
        var hostHeader: String? = null
        val lines = text.split("\r\n", "\n")
        for (i in 1 until minOf(lines.size, 32)) {
            val line = lines[i]
            if (line.isBlank()) break
            if (line.startsWith("Host:", ignoreCase = true)) {
                hostHeader = line.substringAfter(':').trim().substringBefore(':').lowercase()
                    .takeIf { it.length in 1..253 }
                break
            }
        }
        return HttpParsedPayload(
            isRequest = !isResponse,
            method = matchedMethod,
            rawTarget = target,
            statusCode = status,
            hostHeader = hostHeader,
            inspectableText = text
        )
    }

    fun buildIpv4UdpResponse(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        payload: ByteArray,
        payloadLen: Int
    ): ByteArray {
        val totalLen = 20 + 8 + payloadLen
        val out = ByteArray(totalLen)
        out[0] = 0x45
        out[1] = 0x00
        writeU16(out, 2, totalLen)
        writeU16(out, 4, (System.nanoTime() and 0xFFFF).toInt())
        out[6] = 0x40
        out[7] = 0x00
        out[8] = 64
        out[9] = 17 // UDP
        System.arraycopy(srcIp, 0, out, 12, 4)
        System.arraycopy(dstIp, 0, out, 16, 4)
        val ipChecksum = computeChecksum(out, 0, 20)
        writeU16(out, 10, ipChecksum)

        writeU16(out, 20, srcPort)
        writeU16(out, 22, dstPort)
        val udpLen = 8 + payloadLen
        writeU16(out, 24, udpLen)
        System.arraycopy(payload, 0, out, 28, payloadLen)
        val udpChecksum = computeTransportChecksumIpv4(srcIp, dstIp, 17, out, 20, udpLen)
        writeU16(out, 26, if (udpChecksum == 0) 0xFFFF else udpChecksum)
        return out
    }

    fun buildIpv4TcpPacket(
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        window: Int = 65535,
        payload: ByteArray = ByteArray(0),
        payloadLen: Int = payload.size
    ): ByteArray {
        val tcpLen = 20 + payloadLen
        val totalLen = 20 + tcpLen
        val out = ByteArray(totalLen)
        out[0] = 0x45
        writeU16(out, 2, totalLen)
        writeU16(out, 4, (System.nanoTime() and 0xFFFF).toInt())
        out[6] = 0x40
        out[8] = 64
        out[9] = 6 // TCP
        System.arraycopy(srcIp, 0, out, 12, 4)
        System.arraycopy(dstIp, 0, out, 16, 4)
        writeU16(out, 10, computeChecksum(out, 0, 20))

        writeU16(out, 20, srcPort)
        writeU16(out, 22, dstPort)
        writeU32(out, 24, seq)
        writeU32(out, 28, ack)
        out[32] = 0x50 // 5 * 4 = 20 bytes
        out[33] = (flags and 0x3F).toByte()
        writeU16(out, 34, window)
        if (payloadLen > 0) {
            System.arraycopy(payload, 0, out, 40, payloadLen)
        }
        val tcpChecksum = computeTransportChecksumIpv4(srcIp, dstIp, 6, out, 20, tcpLen)
        writeU16(out, 36, tcpChecksum)
        return out
    }

    fun computeChecksum(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = minOf(buf.size, offset + length)
        while (i + 1 < end) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (buf[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }

    private fun computeTransportChecksumIpv4(
        srcIp: ByteArray,
        dstIp: ByteArray,
        proto: Int,
        buf: ByteArray,
        transportOffset: Int,
        transportLen: Int
    ): Int {
        var sum = 0L
        sum += ((srcIp[0].toInt() and 0xFF) shl 8) or (srcIp[1].toInt() and 0xFF)
        sum += ((srcIp[2].toInt() and 0xFF) shl 8) or (srcIp[3].toInt() and 0xFF)
        sum += ((dstIp[0].toInt() and 0xFF) shl 8) or (dstIp[1].toInt() and 0xFF)
        sum += ((dstIp[2].toInt() and 0xFF) shl 8) or (dstIp[3].toInt() and 0xFF)
        sum += proto.toLong()
        sum += transportLen.toLong()

        var i = transportOffset
        val end = minOf(buf.size, transportOffset + transportLen)
        while (i + 1 < end) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (i < end) {
            sum += (buf[i].toInt() and 0xFF) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return (sum.inv() and 0xFFFF).toInt()
    }

    private fun isGreaseValue(v: Int): Boolean =
        (v and 0x0F0F) == 0x0A0A && ((v ushr 8) == (v and 0xFF))

    private val HEX_UPPER = "0123456789ABCDEF".toCharArray()
    private val HEX_LOWER = "0123456789abcdef".toCharArray()

    private fun md5Hex(input: String): String {
        val digest = MessageDigest.getInstance("MD5").digest(input.toByteArray(Charsets.US_ASCII))
        val chars = CharArray(digest.size * 2)
        for (i in digest.indices) {
            val v = digest[i].toInt() and 0xFF
            chars[i * 2] = HEX_LOWER[v ushr 4]
            chars[i * 2 + 1] = HEX_LOWER[v and 0x0F]
        }
        return String(chars)
    }

    private fun formatIpv4(bytes: ByteArray): String =
        "${bytes[0].toInt() and 0xFF}.${bytes[1].toInt() and 0xFF}.${bytes[2].toInt() and 0xFF}.${bytes[3].toInt() and 0xFF}"

    private fun formatIpv6(bytes: ByteArray): String {
        if (bytes.size != 16) return "::"
        val sb = StringBuilder(39)
        for (i in 0 until 8) {
            if (i > 0) sb.append(':')
            val group = ((bytes[i * 2].toInt() and 0xFF) shl 8) or (bytes[i * 2 + 1].toInt() and 0xFF)
            sb.append(group.toString(16))
        }
        return sb.toString()
    }

    private fun writeU16(buf: ByteArray, offset: Int, value: Int) {
        buf[offset] = ((value ushr 8) and 0xFF).toByte()
        buf[offset + 1] = (value and 0xFF).toByte()
    }

    private fun writeU32(buf: ByteArray, offset: Int, value: Long) {
        buf[offset] = ((value ushr 24) and 0xFF).toByte()
        buf[offset + 1] = ((value ushr 16) and 0xFF).toByte()
        buf[offset + 2] = ((value ushr 8) and 0xFF).toByte()
        buf[offset + 3] = (value and 0xFF).toByte()
    }

    private fun malformedStub(version: Int, length: Int): ParsedPacket = ParsedPacket(
        ipVersion = version,
        headerLength = 0,
        totalLength = length,
        protocol = TransportProtocol.OTHER,
        srcIp = "0.0.0.0",
        dstIp = "0.0.0.0",
        srcIpBytes = ByteArray(4),
        dstIpBytes = ByteArray(4),
        srcPort = 0,
        dstPort = 0,
        tcpFlags = 0,
        tcpSeq = 0L,
        tcpAck = 0L,
        payloadOffset = 0,
        payloadLength = 0,
        dnsQueryDomain = null,
        tlsInfo = null,
        httpInfo = null,
        isMalformed = true
    )

    fun toHexPreview(buf: ByteArray, length: Int, maxBytes: Int = 96): String {
        val count = minOf(maxOf(0, length), minOf(buf.size, maxBytes))
        if (count == 0) return ""
        val sb = StringBuilder(count * 3)
        for (i in 0 until count) {
            if (i > 0) sb.append(if (i % 16 == 0) '\n' else ' ')
            val v = buf[i].toInt() and 0xFF
            sb.append(HEX_UPPER[v ushr 4])
            sb.append(HEX_UPPER[v and 0x0F])
        }
        return sb.toString()
    }

    fun writeBufferToByteArray(buffer: ByteBuffer, length: Int): ByteArray {
        val safeLen = length.coerceIn(0, buffer.array().size)
        val out = ByteArray(safeLen)
        System.arraycopy(buffer.array(), 0, out, 0, safeLen)
        return out
    }
}
