package com.example.engine.bluetooth

import android.content.Context
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withContext
import java.io.BufferedInputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
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

object BtSnoopParser {
    private val MAGIC = byteArrayOf(0x62, 0x74, 0x73, 0x6E, 0x6F, 0x6F, 0x70, 0x00) // "btsnoop\0"
    private const val BTSNOOP_EPOCH_DELTA_US = 0x00dcddb30f2f8000L

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
            while (entry != null) {
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
        val dis = DataInputStream(input)
        val header = ByteArray(16)
        try {
            dis.readFully(header)
        } catch (_: EOFException) {
            return BtSnoopParseResult(sourceName, 0, 0, emptyList(), "File too small to be a valid btsnoop log.")
        }

        for (i in 0 until 8) {
            if (header[i] != MAGIC[i]) {
                return BtSnoopParseResult(
                    sourceName, 0, 0, emptyList(),
                    "Invalid magic header (expected RFC 1761 'btsnoop\\0')."
                )
            }
        }
        val hdrBuf = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN)
        hdrBuf.position(8)
        val version = hdrBuf.int
        val datalink = hdrBuf.int
        if (version != 1) {
            return BtSnoopParseResult(sourceName, datalink, 0, emptyList(), "Unsupported btsnoop version $version.")
        }

        val frames = ArrayList<HciParsedFrame>()
        var total = 0
        val recHdr = ByteArray(24)

        while (true) {
            try {
                dis.readFully(recHdr)
            } catch (_: EOFException) {
                break
            }
            val rb = ByteBuffer.wrap(recHdr).order(ByteOrder.BIG_ENDIAN)
            val origLen = rb.int
            val inclLen = rb.int
            val flags = rb.int
            rb.int // cumulative drops
            val tsMicros = rb.long

            if (inclLen <= 0 || inclLen > 65_536) break
            val payload = ByteArray(inclLen)
            try {
                dis.readFully(payload)
            } catch (_: EOFException) {
                break
            }

            total++
            if (frames.size < maxFrames) {
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
            val dis = DataInputStream(BufferedInputStream(socket.getInputStream()))
            val header = ByteArray(16)
            dis.readFully(header)
            for (i in 0 until 8) {
                if (header[i] != MAGIC[i]) {
                    onError("Connected to $host:$port, but peer did not send a btsnoop header.")
                    return@withContext
                }
            }
            val hdrBuf = ByteBuffer.wrap(header).order(ByteOrder.BIG_ENDIAN)
            hdrBuf.position(12)
            val datalink = hdrBuf.int
            onConnected("Live btsnoop stream active ($host:$port, datalink=$datalink)")

            val recHdr = ByteArray(24)
            var idx = 0
            while (isActive && !socket.isClosed) {
                dis.readFully(recHdr)
                val rb = ByteBuffer.wrap(recHdr).order(ByteOrder.BIG_ENDIAN)
                val origLen = rb.int
                val inclLen = rb.int
                val flags = rb.int
                rb.int
                val tsMicros = rb.long
                if (inclLen <= 0 || inclLen > 65_536) continue
                val payload = ByteArray(inclLen)
                dis.readFully(payload)
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

        // Datalink 1002 = HCI UART (H4) where byte 0 is packet indicator (01=CMD, 02=ACL, 03=SCO, 04=EVT)
        val hasH4Prefix = datalink == 1002 || (payload[0].toInt() in 1..4)
        val h4Type = if (hasH4Prefix) payload[0].toInt() and 0xFF else {
            val isCmdOrEvt = (flags and 0x02) != 0
            when {
                isCmdOrEvt && !isReceived -> 0x01
                isCmdOrEvt && isReceived -> 0x04
                else -> 0x02
            }
        }
        val off = if (hasH4Prefix) 1 else 0

        return when (h4Type) {
            0x01 -> decodeHciCommand(index, timestampMillis, direction, payload, off, origLen, hex)
            0x04 -> decodeHciEvent(index, timestampMillis, direction, payload, off, origLen, hex)
            0x02 -> decodeAclL2capAtt(index, timestampMillis, direction, payload, off, origLen, hex)
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
        p: ByteArray,
        off: Int,
        origLen: Int,
        hex: String
    ): HciParsedFrame {
        if (p.size < off + 3) {
            return HciParsedFrame(index, ts, dir, HciPacketLayer.HCI_CMD, "Truncated HCI Command", "", origLen, hex)
        }
        val opcode = (p[off].toInt() and 0xFF) or ((p[off + 1].toInt() and 0xFF) shl 8)
        val ogf = (opcode ushr 10) and 0x3F
        val ocf = opcode and 0x3FF
        val paramLen = p[off + 2].toInt() and 0xFF
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
        p: ByteArray,
        off: Int,
        origLen: Int,
        hex: String
    ): HciParsedFrame {
        if (p.size < off + 2) {
            return HciParsedFrame(index, ts, dir, HciPacketLayer.HCI_EVT, "Truncated HCI Event", "", origLen, hex)
        }
        val evtCode = p[off].toInt() and 0xFF
        val paramLen = p[off + 1].toInt() and 0xFF
        val eventName = when (evtCode) {
            0x0E -> "Command Complete"
            0x0F -> "Command Status"
            0x05 -> "Disconnection Complete"
            0x08 -> "Encryption Change"
            0x13 -> "Number Of Completed Packets"
            0x3E -> {
                val sub = if (p.size > off + 2) p[off + 2].toInt() and 0xFF else -1
                when (sub) {
                    0x01 -> "LE Connection Complete"
                    0x02 -> "LE Advertising Report"
                    0x0D -> "LE Extended Advertising Report"
                    else -> "LE Meta Event (sub=0x${"%02X".format(sub)})"
                }
            }
            else -> "HCI Event 0x${"%02X".format(evtCode)}"
        }
        return HciParsedFrame(
            index, ts, dir, HciPacketLayer.HCI_EVT,
            eventName,
            "Event=0x${"%02X".format(evtCode)} ParamLen=$paramLen",
            origLen, hex
        )
    }

    private fun decodeAclL2capAtt(
        index: Int,
        ts: Long,
        dir: String,
        p: ByteArray,
        off: Int,
        origLen: Int,
        hex: String
    ): HciParsedFrame {
        // ACL Header (4 bytes) + L2CAP Header (4 bytes)
        if (p.size < off + 8) {
            return HciParsedFrame(index, ts, dir, HciPacketLayer.L2CAP, "HCI ACL Fragment", "Len=$origLen", origLen, hex)
        }
        val handleFlags = (p[off].toInt() and 0xFF) or ((p[off + 1].toInt() and 0xFF) shl 8)
        val connHandle = handleFlags and 0x0FFF
        val l2capLen = (p[off + 4].toInt() and 0xFF) or ((p[off + 5].toInt() and 0xFF) shl 8)
        val cid = (p[off + 6].toInt() and 0xFF) or ((p[off + 7].toInt() and 0xFF) shl 8)
        val l2PayloadOff = off + 8

        return when (cid) {
            0x0004 -> { // ATT / GATT
                val attOpcode = if (p.size > l2PayloadOff) p[l2PayloadOff].toInt() and 0xFF else -1
                val attHandle = if (p.size >= l2PayloadOff + 3) {
                    (p[l2PayloadOff + 1].toInt() and 0xFF) or ((p[l2PayloadOff + 2].toInt() and 0xFF) shl 8)
                } else null
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
                    else -> "ATT Opcode 0x${"%02X".format(attOpcode)}"
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
