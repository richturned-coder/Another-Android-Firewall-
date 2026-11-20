package org.aafw.firewall.engine.network

import java.net.InetAddress
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

object PacketParser {
    private val httpMethods = listOf("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")

    fun parse(raw: ByteArray, length: Int): ParsedPacket? {
        if (length < 20) {
            return malformedStub(4, length)
        }
        val version = (raw[0].toInt() ushr 4) and 0x0F
        return when (version) {
            4 -> parseIpv4(raw, length)
            6 -> parseIpv6(raw, length)
            else -> malformedStub(version, length)
        }
    }

    private fun parseIpv4(raw: ByteArray, length: Int): ParsedPacket {
        val ihl = (raw[0].toInt() and 0x0F) * 4
        if (ihl < 20 || ihl > length) return malformedStub(4, length)
        val totalLen = ((raw[2].toInt() and 0xFF) shl 8) or (raw[3].toInt() and 0xFF)
        val effectiveLen = minOf(length, maxOf(totalLen, ihl))
        val isMalformed = totalLen < ihl || totalLen > length
        val proto = TransportProtocol.fromIpProto(raw[9].toInt() and 0xFF)
        val srcBytes = raw.copyOfRange(12, 16)
        val dstBytes = raw.copyOfRange(16, 20)
        val srcIp = formatIpv4(srcBytes)
        val dstIp = formatIpv4(dstBytes)
        return parseTransport(
            raw = raw,
            ipVersion = 4,
            ipHeaderLen = ihl,
            totalLen = effectiveLen,
            proto = proto,
            srcIp = srcIp,
            dstIp = dstIp,
            srcBytes = srcBytes,
            dstBytes = dstBytes,
            initialMalformed = isMalformed
        )
    }

    private fun parseIpv6(raw: ByteArray, length: Int): ParsedPacket {
        if (length < 40) return malformedStub(6, length)
        val payloadLen = ((raw[4].toInt() and 0xFF) shl 8) or (raw[5].toInt() and 0xFF)
        val nextHeader = raw[6].toInt() and 0xFF
        val proto = TransportProtocol.fromIpProto(nextHeader)
        val srcBytes = raw.copyOfRange(8, 24)
        val dstBytes = raw.copyOfRange(24, 40)
        val srcIp = runCatching { InetAddress.getByAddress(srcBytes).hostAddress ?: "::" }.getOrDefault("::")
        val dstIp = runCatching { InetAddress.getByAddress(dstBytes).hostAddress ?: "::" }.getOrDefault("::")
        val effectiveLen = minOf(length, 40 + payloadLen)
        val isMalformed = 40 + payloadLen > length
        return parseTransport(
            raw = raw,
            ipVersion = 6,
            ipHeaderLen = 40,
            totalLen = effectiveLen,
            proto = proto,
            srcIp = srcIp,
            dstIp = dstIp,
            srcBytes = srcBytes,
            dstBytes = dstBytes,
            initialMalformed = isMalformed
        )
    }

    private fun parseTransport(
        raw: ByteArray,
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
        var malformed = initialMalformed

        when (proto) {
            TransportProtocol.TCP -> {
                if (totalLen < ipHeaderLen + 20) {
                    malformed = true
                } else {
                    srcPort = readU16(raw, ipHeaderLen)
                    dstPort = readU16(raw, ipHeaderLen + 2)
                    tcpSeq = readU32(raw, ipHeaderLen + 4)
                    tcpAck = readU32(raw, ipHeaderLen + 8)
                    val dataOffset = ((raw[ipHeaderLen + 12].toInt() ushr 4) and 0x0F) * 4
                    tcpFlags = raw[ipHeaderLen + 13].toInt() and 0x3F
                    if (dataOffset < 20 || ipHeaderLen + dataOffset > totalLen) {
                        malformed = true
                        payloadOffset = totalLen
                    } else {
                        payloadOffset = ipHeaderLen + dataOffset
                    }
                }
            }
            TransportProtocol.UDP -> {
                if (totalLen < ipHeaderLen + 8) {
                    malformed = true
                } else {
                    srcPort = readU16(raw, ipHeaderLen)
                    dstPort = readU16(raw, ipHeaderLen + 2)
                    val udpLen = readU16(raw, ipHeaderLen + 4)
                    if (udpLen < 8 || ipHeaderLen + udpLen > totalLen) {
                        malformed = true
                    }
                    payloadOffset = ipHeaderLen + 8
                }
            }
            else -> {
                payloadOffset = minOf(totalLen, ipHeaderLen + 8)
            }
        }

        val payloadLen = maxOf(0, totalLen - payloadOffset)
        var dnsDomain: String? = null
        var tlsInfo: TlsClientHelloInfo? = null
        var httpInfo: HttpParsedPayload? = null

        if (!malformed && payloadLen > 0) {
            if (proto == TransportProtocol.UDP && (dstPort == 53 || srcPort == 53)) {
                dnsDomain = extractDnsQueryDomain(raw, payloadOffset, payloadLen)
            } else if (proto == TransportProtocol.TCP) {
                if (raw[payloadOffset].toInt() == 0x16 && payloadLen > 43) {
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

    fun extractDnsQueryDomain(buf: ByteArray, offset: Int, len: Int): String? {
        if (len < 13) return null
        val qdCount = readU16(buf, offset + 4)
        if (qdCount <= 0) return null
        var pos = offset + 12
        val end = offset + len
        val sb = StringBuilder()
        var guard = 0
        while (pos < end && guard < 128) {
            guard++
            val labelLen = buf[pos].toInt() and 0xFF
            if (labelLen == 0) break
            if ((labelLen and 0xC0) == 0xC0) break
            pos++
            if (pos + labelLen > end) return null
            if (sb.isNotEmpty()) sb.append('.')
            for (i in 0 until labelLen) {
                val c = (buf[pos + i].toInt() and 0xFF).toChar()
                sb.append(c.lowercaseChar())
            }
            pos += labelLen
        }
        return sb.toString().takeIf { it.contains('.') && it.length in 3..253 }
    }

    fun extractTlsClientHello(buf: ByteArray, offset: Int, len: Int): TlsClientHelloInfo? {
        if (len < 48) return null
        val end = offset + len
        if ((buf[offset].toInt() and 0xFF) != 0x16) return null
        val handshakeType = buf[offset + 5].toInt() and 0xFF
        if (handshakeType != 0x01) return null // ClientHello only

        val clientVersion = readU16(buf, offset + 9)
        var pos = offset + 11 + 32 // version(2) + random(32)
        if (pos >= end) return null

        val sessionIdLen = buf[pos].toInt() and 0xFF
        pos += 1 + sessionIdLen
        if (pos + 2 > end) return null

        val cipherLen = readU16(buf, pos)
        pos += 2
        if (pos + cipherLen > end) return null

        val ciphers = mutableListOf<Int>()
        var cPos = pos
        while (cPos + 1 < pos + cipherLen) {
            val cs = readU16(buf, cPos)
            if (!isGreaseValue(cs)) ciphers.add(cs)
            cPos += 2
        }
        pos += cipherLen
        if (pos >= end) return null

        val compLen = buf[pos].toInt() and 0xFF
        pos += 1 + compLen
        if (pos + 2 > end) return null

        val extTotalLen = readU16(buf, pos)
        pos += 2
        val extEnd = minOf(end, pos + extTotalLen)

        var sni: String? = null
        val extensions = mutableListOf<Int>()
        val groups = mutableListOf<Int>()
        val ecFormats = mutableListOf<Int>()
        var negotiatedTls13 = false

        while (pos + 4 <= extEnd) {
            val extType = readU16(buf, pos)
            val extLen = readU16(buf, pos + 2)
            pos += 4
            if (pos + extLen > extEnd) break
            if (!isGreaseValue(extType)) extensions.add(extType)

            when (extType) {
                0x0000 -> { // SNI
                    if (extLen >= 5) {
                        val nameType = buf[pos + 2].toInt() and 0xFF
                        val nameLen = readU16(buf, pos + 3)
                        if (nameType == 0 && pos + 5 + nameLen <= extEnd) {
                            sni = String(buf, pos + 5, nameLen, Charsets.US_ASCII).lowercase()
                        }
                    }
                }
                0x000A -> { // Supported Groups
                    if (extLen >= 2) {
                        val listLen = readU16(buf, pos)
                        var gPos = pos + 2
                        while (gPos + 1 < minOf(pos + 2 + listLen, pos + extLen)) {
                            val g = readU16(buf, gPos)
                            if (!isGreaseValue(g)) groups.add(g)
                            gPos += 2
                        }
                    }
                }
                0x000B -> { // EC Point Formats
                    if (extLen >= 1) {
                        val fmtLen = buf[pos].toInt() and 0xFF
                        for (i in 0 until minOf(fmtLen, extLen - 1)) {
                            ecFormats.add(buf[pos + 1 + i].toInt() and 0xFF)
                        }
                    }
                }
                0x002B -> { // Supported Versions (detect TLS 1.3 0x0304)
                    if (extLen >= 3) {
                        val vLen = buf[pos].toInt() and 0xFF
                        var vPos = pos + 1
                        while (vPos + 1 < minOf(pos + 1 + vLen, pos + extLen)) {
                            if (readU16(buf, vPos) == 0x0304) negotiatedTls13 = true
                            vPos += 2
                        }
                    }
                }
            }
            pos += extLen
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
        val sampleLen = minOf(len, 4096)
        if (sampleLen < 12) return null
        val text = String(buf, offset, sampleLen, Charsets.ISO_8859_1)
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
        val end = offset + length
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
        val end = transportOffset + transportLen
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

    private fun md5Hex(input: String): String {
        val digest = MessageDigest.getInstance("MD5").digest(input.toByteArray(Charsets.US_ASCII))
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun formatIpv4(bytes: ByteArray): String =
        "${bytes[0].toInt() and 0xFF}.${bytes[1].toInt() and 0xFF}.${bytes[2].toInt() and 0xFF}.${bytes[3].toInt() and 0xFF}"

    private fun readU16(buf: ByteArray, offset: Int): Int =
        ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)

    private fun readU32(buf: ByteArray, offset: Int): Long =
        ((buf[offset].toLong() and 0xFF) shl 24) or
            ((buf[offset + 1].toLong() and 0xFF) shl 16) or
            ((buf[offset + 2].toLong() and 0xFF) shl 8) or
            (buf[offset + 3].toLong() and 0xFF)

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
        val count = minOf(length, maxBytes)
        val sb = StringBuilder(count * 3)
        for (i in 0 until count) {
            if (i > 0) sb.append(if (i % 16 == 0) '\n' else ' ')
            sb.append("%02X".format(buf[i].toInt() and 0xFF))
        }
        return sb.toString()
    }

    fun writeBufferToByteArray(buffer: ByteBuffer, length: Int): ByteArray {
        val out = ByteArray(length)
        System.arraycopy(buffer.array(), 0, out, 0, length)
        return out
    }
}
