package org.aafw.firewall.engine.network

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

data class PcapngFrame(
    val timestampMicros: Long,
    val rawBytes: ByteArray,
    val comment: String
)

data class PcapngStats(
    val isRecording: Boolean = false,
    val sessionId: Long? = null,
    val fileName: String? = null,
    val filePath: String? = null,
    val packetsWritten: Long = 0L,
    val bytesWritten: Long = 0L,
    val droppedFrames: Long = 0L,
    val ringCapacity: Int = 2048
)

/**
 * Standards-compliant PCAPNG writer (SHB + IDB LinkType 101 Raw IP + EPB with opt_comment)
 * backed by a bounded ring-buffer Channel (DROP_OLDEST) to prevent memory redlining.
 */
class PcapngWriter(
    private val ringCapacity: Int = 2048,
    private val maxFileBytes: Long = DEFAULT_MAX_FILE_BYTES
) {
    companion object {
        const val DEFAULT_MAX_FILE_BYTES: Long = 100L * 1024L * 1024L // 100 MiB safety ceiling
        private const val MAX_COMMENT_BYTES = 1024
    }

    private val active = AtomicBoolean(false)
    private val packetsWritten = AtomicLong(0L)
    private val bytesWritten = AtomicLong(0L)
    private val droppedFrames = AtomicLong(0L)

    @Volatile
    private var currentFile: File? = null
    @Volatile
    private var currentSessionId: Long? = null
    @Volatile
    private var frameChannel: Channel<PcapngFrame>? = null
    @Volatile
    private var writerJob: Job? = null

    fun isRecording(): Boolean = active.get()

    fun start(
        outputFile: File,
        sessionId: Long,
        scope: CoroutineScope,
        onStatsUpdate: (PcapngStats) -> Unit
    ): Boolean {
        if (!active.compareAndSet(false, true)) return false
        outputFile.parentFile?.mkdirs()
        // Pre-create and lock capture file to owner-only (0600) before writing packet data
        if (!outputFile.exists()) {
            runCatching { outputFile.createNewFile() }
        }
        enforceOwnerOnlyPermissions(outputFile)
        currentFile = outputFile
        currentSessionId = sessionId
        packetsWritten.set(0L)
        bytesWritten.set(0L)
        droppedFrames.set(0L)

        val ch = Channel<PcapngFrame>(
            capacity = ringCapacity,
            onBufferOverflow = BufferOverflow.DROP_OLDEST,
            onUndeliveredElement = { droppedFrames.incrementAndGet() }
        )
        frameChannel = ch

        writerJob = scope.launch(Dispatchers.IO) {
            BufferedOutputStream(FileOutputStream(outputFile), 65_536).use { out ->
                enforceOwnerOnlyPermissions(outputFile)
                val shb = buildSectionHeaderBlock()
                val idb = buildInterfaceDescriptionBlock()
                out.write(shb)
                out.write(idb)
                out.flush()
                bytesWritten.addAndGet((shb.size + idb.size).toLong())
                onStatsUpdate(snapshotStats())

                var flushCounter = 0
                for (frame in ch) {
                    val epb = buildEnhancedPacketBlock(frame)
                    if (maxFileBytes > 0L && bytesWritten.get() + epb.size > maxFileBytes) {
                        droppedFrames.incrementAndGet()
                        continue
                    }
                    out.write(epb)
                    val pktCount = packetsWritten.incrementAndGet()
                    bytesWritten.addAndGet(epb.size.toLong())
                    flushCounter++
                    if (flushCounter >= 16 || pktCount <= 5L) {
                        out.flush()
                        flushCounter = 0
                        onStatsUpdate(snapshotStats())
                    }
                }
                out.flush()
            }
        }
        return true
    }

    private fun enforceOwnerOnlyPermissions(file: File) {
        runCatching {
            file.setReadable(false, false)
            file.setWritable(false, false)
            file.setExecutable(false, false)
            file.setReadable(true, true)
            file.setWritable(true, true)
        }
    }

    fun offerPacket(rawBytes: ByteArray, length: Int, uid: Int, appLabel: String, verdict: String, host: String?) {
        if (!active.get()) return
        val safeLen = length.coerceIn(0, rawBytes.size)
        if (safeLen == 0) return
        val ch = frameChannel ?: return
        val copy = rawBytes.copyOf(safeLen)
        val comment = buildString {
            append("UID=").append(uid)
            append(";APP=").append(appLabel)
            append(";VERDICT=").append(verdict)
            if (!host.isNullOrBlank()) {
                append(";HOST=").append(host)
            }
        }
        val frame = PcapngFrame(
            timestampMicros = System.currentTimeMillis() * 1000L,
            rawBytes = copy,
            comment = comment
        )
        val result = ch.trySend(frame)
        if (!result.isSuccess) {
            droppedFrames.incrementAndGet()
        }
    }

    suspend fun stop(): PcapngStats {
        active.set(false)
        frameChannel?.close()
        writerJob?.join()
        val finalStats = snapshotStats().copy(isRecording = false)
        frameChannel = null
        writerJob = null
        currentFile = null
        currentSessionId = null
        return finalStats
    }

    fun snapshotStats(): PcapngStats = PcapngStats(
        isRecording = active.get(),
        sessionId = currentSessionId,
        fileName = currentFile?.name,
        filePath = currentFile?.absolutePath,
        packetsWritten = packetsWritten.get(),
        bytesWritten = bytesWritten.get(),
        droppedFrames = droppedFrames.get(),
        ringCapacity = ringCapacity
    )

    private fun buildSectionHeaderBlock(): ByteArray {
        val appOpt = "Another Droid Firewall+ Pure-Kotlin Engine".toByteArray(Charsets.UTF_8)
        val optPadded = paddedLength(appOpt.size)
        // Header(24) + Option(4 + optPadded) + EndOfOpt(4) + TrailerLen(4)
        val totalLen = 24 + 4 + optPadded + 4 + 4
        val buf = ByteBuffer.allocate(totalLen).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(0x0A0D0D0A) // Block Type: SHB
        buf.putInt(totalLen)
        buf.putInt(0x1A2B3C4D) // Byte-Order Magic
        buf.putShort(1) // Major Version
        buf.putShort(0) // Minor Version
        buf.putLong(-1L) // Section Length unspecified
        // Option 4: shb_userappl
        buf.putShort(4)
        buf.putShort(appOpt.size.toShort())
        buf.put(appOpt)
        repeat(optPadded - appOpt.size) { buf.put(0) }
        // opt_endofopt
        buf.putShort(0)
        buf.putShort(0)
        buf.putInt(totalLen)
        return buf.array()
    }

    private fun buildInterfaceDescriptionBlock(): ByteArray {
        val ifName = "tun0-adf".toByteArray(Charsets.UTF_8)
        val ifNamePadded = paddedLength(ifName.size)
        // Header(16) + Option if_name(4 + padded) + Option if_tsresol(8) + EndOfOpt(4) + Trailer(4)
        val totalLen = 16 + 4 + ifNamePadded + 8 + 4 + 4
        val buf = ByteBuffer.allocate(totalLen).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(0x00000001) // Block Type: IDB
        buf.putInt(totalLen)
        buf.putShort(101) // LinkType LINKTYPE_RAW (Raw IPv4/IPv6)
        buf.putShort(0) // Reserved
        buf.putInt(65535) // SnapLen
        // Option 2: if_name
        buf.putShort(2)
        buf.putShort(ifName.size.toShort())
        buf.put(ifName)
        repeat(ifNamePadded - ifName.size) { buf.put(0) }
        // Option 9: if_tsresol = 6 (10^-6 microsecond resolution)
        buf.putShort(9)
        buf.putShort(1)
        buf.put(6)
        buf.put(0); buf.put(0); buf.put(0)
        // opt_endofopt
        buf.putShort(0)
        buf.putShort(0)
        buf.putInt(totalLen)
        return buf.array()
    }

    private fun buildEnhancedPacketBlock(frame: PcapngFrame): ByteArray {
        val dataLen = frame.rawBytes.size
        val dataPadded = paddedLength(dataLen)
        val rawCommentBytes = frame.comment.toByteArray(Charsets.UTF_8)
        val commentBytes = if (rawCommentBytes.size > MAX_COMMENT_BYTES) {
            rawCommentBytes.copyOf(MAX_COMMENT_BYTES)
        } else {
            rawCommentBytes
        }
        val commentPadded = paddedLength(commentBytes.size)
        // Header(28) + PacketData(dataPadded) + opt_comment(4 + commentPadded) + opt_endofopt(4) + Trailer(4)
        val totalLen = 28 + dataPadded + 4 + commentPadded + 4 + 4
        val buf = ByteBuffer.allocate(totalLen).order(ByteOrder.LITTLE_ENDIAN)
        buf.putInt(0x00000006) // Block Type: EPB
        buf.putInt(totalLen)
        buf.putInt(0) // Interface ID 0
        buf.putInt((frame.timestampMicros ushr 32).toInt())
        buf.putInt((frame.timestampMicros and 0xFFFFFFFFL).toInt())
        buf.putInt(dataLen) // Captured Len
        buf.putInt(dataLen) // Original Len
        buf.put(frame.rawBytes)
        repeat(dataPadded - dataLen) { buf.put(0) }
        // Option 1: opt_comment (UID, APP, VERDICT, HOST metadata)
        buf.putShort(1)
        buf.putShort(commentBytes.size.toShort())
        buf.put(commentBytes)
        repeat(commentPadded - commentBytes.size) { buf.put(0) }
        // opt_endofopt
        buf.putShort(0)
        buf.putShort(0)
        buf.putInt(totalLen)
        return buf.array()
    }

    private fun paddedLength(len: Int): Int = (len + 3) and 3.inv()
}
