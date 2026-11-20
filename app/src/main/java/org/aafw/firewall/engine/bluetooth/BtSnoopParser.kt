package org.aafw.firewall.engine.bluetooth

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import org.aafw.firewall.engine.SafeByteCursor
import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.zip.ZipInputStream

enum class HciPacketLayer(val label: String) {
    HCI_CMD("HCI CMD"),
    HCI_EVT("HCI EVT"),
    L2CAP("L2CAP"),
    ATT_GATT("ATT / GATT"),
    SMP("SMP"),
    HCI_SCO("HCI SCO"),
    RAW("HCI RAW")
}

data class HciParsedFrame(
    val index: Int,
    val timestampMillis: Long,
    val direction: String, // TX (Host->Ctrl) | RX (Ctrl->Host)
    val layer: HciPacketLayer,
    val summary: String,
    val detail: String,
    val byteLength: Int,
    val rawHex: String
)

data class BtSnoopParseResult(
    val sourceName: String,
    val datalinkType: Int,
    val totalFrames: Int,
    val frames: List<HciParsedFrame>,
    val error: String? = null
)

/**
 * Hardened RFC 1761 BTSnoop v1 + HCI/L2CAP/ATT/BLE-AD parser using [SafeByteCursor].
 *
 * Defends against:
 * - Pre-allocation OOM / NegativeArraySizeException from crafted `includedLength` (`0x7FFFFFFF`, `< 0`)
 * - Unbounded stream / ZIP bomb exhaustion ([MAX_HCI_RECORD_BYTES], [MAX_TOTAL_STREAM_BYTES], [MAX_RECORDS_SCANNED])
 * - Invalid datalink types (strictly validates 1001..1004)
 * - Truncated trailing records (returns all previously parsed valid frames cleanly)
 * - BLE AD TLV zero-length infinite loops inside HCI LE Advertising Reports
 */
object BtSnoopParser {
    private val MAGIC = byteArrayOf(0x62, 0x74, 0x73, 0x6E, 0x6F, 0x6F, 0x70, 0x00) // "btsnoop\0"
    private const val BTSNOOP_EPOCH_DELTA_US = 0x00dcddb30f2f8000L

    const val MAX_HCI_RECORD_BYTES = 65_536
    const val MAX_TOTAL_STREAM_BYTES = 32 * 1024 * 1024
    const val MAX_RECORDS_SCANNED = 100_000
    private const val MAX_ZIP_ENTRIES = 2_048
    private const val READ_CHUNK_SIZE = 4_096

    fun isShizukuInstalled(context: Context): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                context.packageManager.getPackageInfo(
                    "moe.shizuku.privileged.api",
                    PackageManager.PackageInfoFlags.of(0)
                )
            } else {
                @Suppress("DEPRECATION")
                context.packageManager.getPackageInfo("moe.shizuku.privileged.api", 0)
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    fun parse(input: InputStream, sourceName: String = "stream", maxFrames: Int = 2000): BtSnoopParseResult =
        parseBtSnoopStream(input, sourceName, maxFrames)

    suspend fun parseUri(context: Context, uri: Uri, displayName: String): BtSnoopParseResult =
        withContext(Dispatchers.IO) {
            try {
                context.contentResolver.openInputStream(uri)?.use { rawStream ->
                    val buffered = BufferedInputStream(rawStream, 65_536)
                    buffered.mark(8)
                    val probe = ByteArray(4)
                    val read = buffered.read(probe)
                    buffered.reset()

                    // Detect Android bugreport ZIP archive (PK\x03\x04) and extract btsnoop_hci.log automatically
                    if (read == 4 && probe[0] == 0x50.toByte() && probe[1] == 0x4B.toByte() &&
                        probe[2] == 0x03.toByte() && probe[3] == 0x04.toByte()
                    ) {
                        parseFromBugreportZip(buffered, displayName)
                    } else {
                        parseBtSnoopStream(buffered, displayName)
                    }
                } ?: BtSnoopParseResult(displayName, 0, 0, emptyList(), "Unable to open selected file stream.")
            } catch (e: Exception) {
                BtSnoopParseResult(
                    displayName, 0, 0, emptyList(),
                    "Parse error: ${e.message ?: e.javaClass.simpleName}"
                )
            }
        }

    private fun parseFromBugreportZip(input: InputStream, archiveName: String): BtSnoopParseResult {
        ZipInputStream(input).use { zis ->
            var entry = zis.nextEntry
            var inspectedEntries = 0
            while (entry != null && inspectedEntries < MAX_ZIP_ENTRIES) {
                inspectedEntries++
                val lower = entry.name.lowercase()
                if (!entry.isDirectory && (lower.endsWith("btsnoop_hci.log") || lower.contains("btsnoop"))) {
                    return parseBtSnoopStream(zis, "$archiveName -> ${entry.name}")
                }
                entry = zis.nextEntry
            }
        }
        return BtSnoopParseResult(
            archiveName,
            0,
            0,
            emptyList(),
            "No btsnoop_hci.log found inside ZIP bugreport. Enable 'Bluetooth HCI snoop log' in Developer Options first."
        )
    }

    fun parseBtSnoopStream(input: InputStream, sourceName: String, maxFrames: Int = 2000): BtSnoopParseResult {
        val header = readExactBounded(input, 16)
            ?: return BtSnoopParseResult(sourceName, 0, 0, emptyList(), "File too small to be a valid btsnoop log.")

        for (i in 0 until 8) {
            if (header[i] != MAGIC[i]) {
                return BtSnoopParseResult(
                    sourceName, 0, 0, emptyList(),
                    "Invalid magic header (expected RFC 1761 'btsnoop\\0')."
                )
            }
        }
        val hdrCursor = SafeByteCursor(header, 8, 16)
        val version = hdrCursor.readS32BE() ?: return BtSnoopParseResult(sourceName, 0, 0, emptyList(), "Truncated header.")
        val datalink = hdrCursor.readS32BE() ?: return BtSnoopParseResult(sourceName, 0, 0, emptyList(), "Truncated header.")
        if (version != 1) {
            return BtSnoopParseResult(sourceName, datalink, 0, emptyList(), "Unsupported btsnoop version $version.")
        }
        if (datalink !in 1001..1004) {
            return BtSnoopParseResult(sourceName, datalink, 0, emptyList(), "Unsupported btsnoop datalink type $datalink.")
        }

        val safeMaxFrames = maxFrames.coerceIn(1, 20_000)
        val frames = ArrayList<HciParsedFrame>(minOf(safeMaxFrames, 256))
        var total = 0
        var totalBytesRead = 16L

        while (total < MAX_RECORDS_SCANNED && totalBytesRead < MAX_TOTAL_STREAM_BYTES) {
            val recHdr = readExactBounded(input, 24) ?: break // Graceful EOF / truncated trailing header
            totalBytesRead += 24L

            val recCursor = SafeByteCursor(recHdr)
            val origLen = recCursor.readS32BE() ?: break
            val inclLen = recCursor.readS32BE() ?: break
            val flags = recCursor.readS32BE() ?: break
            recCursor.readS32BE() ?: break // cumulative drops
            val tsMicros = recCursor.readS64BE() ?: break

            // Reject negative signed ints, zero-byte empty records, or oversized wire lengths BEFORE allocation
            if (origLen < 0 || inclLen !in 1..MAX_HCI_RECORD_BYTES) break
            if (totalBytesRead + inclLen.toLong() > MAX_TOTAL_STREAM_BYTES) break

            // Read in incremental chunks so a forged inclLen on a short stream never triggers large pre-allocation
            val payload = readExactBounded(input, inclLen) ?: break // Graceful truncated trailing record
            totalBytesRead += inclLen.toLong()

            total++
            if (frames.size < safeMaxFrames) {
                val epochMs = ((tsMicros - BTSNOOP_EPOCH_DELTA_US) / 1000L).coerceAtLeast(0L)
                frames.add(
                    decodeHciFrame(
                        index = total,
                        timestampMillis = epochMs,
                        flags = flags,
                        datalink = datalink,
                        payload = payload,
                        origLen = origLen
                    )
                )
            }
        }

        return BtSnoopParseResult(
            sourceName = sourceName,
            datalinkType = datalink,
            totalFrames = total,
            frames = frames
        )
    }

    /**
     * Streams live RFC 1761 btsnoop records over a local TCP socket (e.g., Android 17+ HCI snoop
     * socket or `adb forward tcp:8872 localabstract:btsnoop` / Shizuku forwarder).
     */
    suspend fun streamLiveSocket(
        host: String,
        port: Int,
        onConnected: (String) -> Unit,
        onFrame: (HciParsedFrame) -> Unit,
        onError: (String) -> Unit
    ) = withContext(Dispatchers.IO) {
        var socket: Socket? = null
        try {
            socket = Socket()
            socket.connect(InetSocketAddress(host, port), 3500)
            val buffered = BufferedInputStream(socket.getInputStream())
            val header = readExactBounded(buffered, 16)
            if (header == null) {
                onError("Peer at $host:$port closed before sending btsnoop header.")
                return@withContext
            }
            for (i in 0 until 8) {
                if (header[i] != MAGIC[i]) {
                    onError("Connected to $host:$port, but peer did not send a btsnoop header.")
                    return@withContext
                }
            }
            val hdrCursor = SafeByteCursor(header, 8, 16)
            val version = hdrCursor.readS32BE() ?: -1
            val datalink = hdrCursor.readS32BE() ?: -1
            if (version != 1 || datalink !in 1001..1004) {
                onError("Unsupported btsnoop header from $host:$port (v=$version, datalink=$datalink).")
                return@withContext
            }
            onConnected("Live btsnoop stream active ($host:$port, datalink=$datalink)")

            var idx = 0
            while (isActive && !socket.isClosed) {
                val recHdr = readExactBounded(buffered, 24) ?: break
                val rc = SafeByteCursor(recHdr)
                val origLen = rc.readS32BE() ?: break
                val inclLen = rc.readS32BE() ?: break
                val flags = rc.readS32BE() ?: break
                rc.readS32BE() ?: break
                val tsMicros = rc.readS64BE() ?: break
                if (origLen < 0 || inclLen !in 1..MAX_HCI_RECORD_BYTES) break
                val payload = readExactBounded(buffered, inclLen) ?: break
                idx++
                val epochMs = ((tsMicros - BTSNOOP_EPOCH_DELTA_US) / 1000L).coerceAtLeast(System.currentTimeMillis())
                onFrame(decodeHciFrame(idx, epochMs, flags, datalink, payload, origLen))
            }
        } catch (e: Exception) {
            onError("Live socket closed/unreachable ($host:$port): ${e.message ?: e.javaClass.simpleName}")
        } finally {
            runCatching { socket?.close() }
        }
    }

    /**
     * Reads exactly [expectedLen] bytes from [input] using bounded chunk transfers so a malicious
     * length header on a short/truncated stream never pre-allocates a huge buffer.
     * Returns `null` on premature EOF or invalid length.
     */
    private fun readExactBounded(input: InputStream, expectedLen: Int): ByteArray? {
        if (expectedLen < 0 || expectedLen > MAX_HCI_RECORD_BYTES) return null
        if (expectedLen == 0) return ByteArray(0)
        if (expectedLen <= READ_CHUNK_SIZE) {
            val buf = ByteArray(expectedLen)
            var off = 0
            while (off < expectedLen) {
                val n = input.read(buf, off, expectedLen - off)
                if (n <= 0) return null
                off += n
            }
            return buf
        }
        val baos = ByteArrayOutputStream(minOf(expectedLen, READ_CHUNK_SIZE))
        val chunk = ByteArray(READ_CHUNK_SIZE)
        var remaining = expectedLen
        while (remaining > 0) {
            val n = input.read(chunk, 0, minOf(chunk.size, remaining))
            if (n <= 0) return null
            baos.write(chunk, 0, n)
            remaining -= n
        }
        return baos.toByteArray()
    }

    fun decodeHciFrame(
        index: Int,
        timestampMillis: Long,
        flags: Int,
        datalink: Int,
        payload: ByteArray,
        origLen: Int
    ): HciParsedFrame {
        val isReceived = (flags and 0x01) != 0
        val direction = if (isReceived) "RX" else "TX"
        val hex = payload.take(48).joinToString(" ") { "%02X".format(it.toInt() and 0xFF) }

        if (payload.isEmpty()) {
            return HciParsedFrame(index, timestampMillis, direction, HciPacketLayer.RAW, "Empty HCI Frame", "", origLen, hex)
        }

        val cursor = SafeByteCursor(payload)
        val firstByte = cursor.peekU8() ?: return HciParsedFrame(index, timestampMillis, direction, HciPacketLayer.RAW, "Empty HCI Frame", "", origLen, hex)
        // Datalink 1002 = HCI UART (H4) where byte 0 is packet indicator (01=CMD, 02=ACL, 03=SCO, 04=EVT)
        val hasH4Prefix = datalink == 1002 || (firstByte in 1..4)
        val h4Type = if (hasH4Prefix) {
            cursor.readU8() ?: 0
        } else {
            val isCmdOrEvt = (flags and 0x02) != 0
            when {
                isCmdOrEvt && !isReceived -> 0x01
                isCmdOrEvt && isReceived -> 0x04
                else -> 0x02
            }
        }

        return when (h4Type) {
            0x01 -> decodeHciCommand(index, timestampMillis, direction, cursor, origLen, hex)
            0x04 -> decodeHciEvent(index, timestampMillis, direction, cursor, origLen, hex)
            0x02 -> decodeAclL2capAtt(index, timestampMillis, direction, cursor, origLen, hex)
            0x03 -> HciParsedFrame(
                index, timestampMillis, direction, HciPacketLayer.HCI_SCO,
                "HCI SCO Audio Frame", "Length=$origLen bytes", origLen, hex
            )
            else -> HciParsedFrame(
                index, timestampMillis, direction, HciPacketLayer.RAW,
                "HCI Raw Packet (type=0x${"%02X".format(h4Type)})", "Length=$origLen bytes", origLen, hex
            )
        }
    }

    private fun decodeHciCommand(
        index: Int,
        ts: Long,
        dir: String,
        cursor: SafeByteCursor,
        origLen: Int,
        hex: String
    ): HciParsedFrame {
        val opcode = cursor.readU16LE()
            ?: return HciParsedFrame(index, ts, dir, HciPacketLayer.HCI_CMD, "Truncated HCI Command", "", origLen, hex)
        val paramLen = cursor.readU8()
            ?: return HciParsedFrame(index, ts, dir, HciPacketLayer.HCI_CMD, "Truncated HCI Command", "", origLen, hex)
        val ogf = (opcode ushr 10) and 0x3F
        val ocf = opcode and 0x3FF
        val name = when (opcode) {
            0x0C03 -> "HCI_Reset"
            0x200B -> "LE_Set_Scan_Parameters"
            0x200C -> "LE_Set_Scan_Enable"
            0x200D -> "LE_Create_Connection"
            0x2006 -> "LE_Set_Advertising_Parameters"
            0x200A -> "LE_Set_Advertise_Enable"
            0x0406 -> "HCI_Disconnect"
            else -> "HCI_Cmd 0x${"%04X".format(opcode)}"
        }
        return HciParsedFrame(
            index, ts, dir, HciPacketLayer.HCI_CMD,
            name,
            "OGF=0x${"%02X".format(ogf)} OCF=0x${"%03X".format(ocf)} ParamLen=$paramLen",
            origLen, hex
        )
    }

    private fun decodeHciEvent(
        index: Int,
        ts: Long,
        dir: String,
        cursor: SafeByteCursor,
        origLen: Int,
        hex: String
    ): HciParsedFrame {
        val evtCode = cursor.readU8()
            ?: return HciParsedFrame(index, ts, dir, HciPacketLayer.HCI_EVT, "Truncated HCI Event", "", origLen, hex)
        val paramLen = cursor.readU8()
            ?: return HciParsedFrame(index, ts, dir, HciPacketLayer.HCI_EVT, "Truncated HCI Event", "", origLen, hex)
        val paramCursor = cursor.slice(minOf(paramLen, cursor.remaining))

        var extraDetail = ""
        val eventName = when (evtCode) {
            0x0E -> "Command Complete"
            0x0F -> "Command Status"
            0x05 -> "Disconnection Complete"
            0x08 -> "Encryption Change"
            0x13 -> "Number Of Completed Packets"
            0x3E -> {
                val sub = paramCursor?.readU8() ?: -1
                when (sub) {
                    0x01 -> "LE Connection Complete"
                    0x02 -> {
                        // Parse first BLE Advertising Report AD TLV structures safely
                        val adCount = parseLeAdvReportAdCount(paramCursor)
                        if (adCount > 0) extraDetail = " AD_Structures=$adCount"
                        "LE Advertising Report"
                    }
                    0x0D -> "LE Extended Advertising Report"
                    else -> "LE Meta Event (sub=0x${"%02X".format(sub and 0xFF)})"
                }
            }
            else -> "HCI Event 0x${"%02X".format(evtCode)}"
        }
        return HciParsedFrame(
            index, ts, dir, HciPacketLayer.HCI_EVT,
            eventName,
            "Event=0x${"%02X".format(evtCode)} ParamLen=$paramLen$extraDetail",
            origLen, hex
        )
    }

    private fun parseLeAdvReportAdCount(paramCursor: SafeByteCursor?): Int {
        if (paramCursor == null) return 0
        val numReports = paramCursor.readU8() ?: return 0
        if (numReports <= 0) return 0
        // EventType(1) + AddrType(1) + Addr(6)
        if (!paramCursor.skip(8)) return 0
        val dataLen = paramCursor.readU8() ?: return 0
        val adBytes = paramCursor.readBytes(dataLen, 64) ?: return 0
        return BleAdParser.parseAdStructures(adBytes).size
    }

    private fun decodeAclL2capAtt(
        index: Int,
        ts: Long,
        dir: String,
        cursor: SafeByteCursor,
        origLen: Int,
        hex: String
    ): HciParsedFrame {
        // ACL Header (4 bytes) + L2CAP Header (4 bytes)
        if (cursor.remaining < 8) {
            return HciParsedFrame(index, ts, dir, HciPacketLayer.L2CAP, "HCI ACL Fragment", "Len=$origLen", origLen, hex)
        }
        val handleFlags = cursor.readU16LE() ?: return HciParsedFrame(index, ts, dir, HciPacketLayer.L2CAP, "HCI ACL Fragment", "Len=$origLen", origLen, hex)
        cursor.readU16LE() ?: return HciParsedFrame(index, ts, dir, HciPacketLayer.L2CAP, "HCI ACL Fragment", "Len=$origLen", origLen, hex) // ACL data total len
        val connHandle = handleFlags and 0x0FFF
        val l2capLen = cursor.readU16LE() ?: return HciParsedFrame(index, ts, dir, HciPacketLayer.L2CAP, "HCI ACL Fragment", "Len=$origLen", origLen, hex)
        val cid = cursor.readU16LE() ?: return HciParsedFrame(index, ts, dir, HciPacketLayer.L2CAP, "HCI ACL Fragment", "Len=$origLen", origLen, hex)
        val l2Payload = cursor.slice(minOf(l2capLen, cursor.remaining)) ?: return HciParsedFrame(index, ts, dir, HciPacketLayer.L2CAP, "HCI ACL Fragment", "Len=$origLen", origLen, hex)

        return when (cid) {
            0x0004 -> { // ATT / GATT
                val attOpcode = l2Payload.readU8() ?: -1
                val attHandle = if (l2Payload.remaining >= 2) l2Payload.readU16LE() else null
                val opName = when (attOpcode) {
                    0x01 -> "ATT Error Response"
                    0x02 -> "ATT Exchange MTU Req"
                    0x03 -> "ATT Exchange MTU Rsp"
                    0x04 -> "ATT Find Info Req"
                    0x08 -> "ATT Read By Type Req"
                    0x09 -> "ATT Read By Type Rsp"
                    0x0A -> "GATT Read Request"
                    0x0B -> "GATT Read Response"
                    0x10 -> "GATT Discover Services (Read By Group Type)"
                    0x11 -> "GATT Read By Group Type Rsp"
                    0x12 -> "GATT Write Request"
                    0x13 -> "GATT Write Response"
                    0x1B -> "GATT Handle Value Notification"
                    0x1D -> "GATT Handle Value Indication"
                    0x52 -> "GATT Write Command"
                    else -> "ATT Opcode 0x${"%02X".format(attOpcode and 0xFF)}"
                }
                val handleStr = attHandle?.let { " Handle=0x${"%04X".format(it)}" } ?: ""
                HciParsedFrame(
                    index, ts, dir, HciPacketLayer.ATT_GATT,
                    opName,
                    "ACL=0x${"%03X".format(connHandle)} CID=0x0004 (ATT) Len=$l2capLen$handleStr",
                    origLen, hex
                )
            }
            0x0006 -> HciParsedFrame(
                index, ts, dir, HciPacketLayer.SMP,
                "BLE Security Manager (SMP)",
                "ACL=0x${"%03X".format(connHandle)} CID=0x0006 Len=$l2capLen",
                origLen, hex
            )
            else -> HciParsedFrame(
                index, ts, dir, HciPacketLayer.L2CAP,
                "L2CAP Channel 0x${"%04X".format(cid)}",
                "ACL=0x${"%03X".format(connHandle)} L2CAP_Len=$l2capLen",
                origLen, hex
            )
        }
    }
}
