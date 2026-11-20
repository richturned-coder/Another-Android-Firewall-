package org.aafw.firewall.engine

/**
 * Zero-copy, bounds-checked byte cursor for untrusted wire-format parsing.
 *
 * Upholds three strict security invariants:
 * - Zero-crash: read/skip/slice methods return null/false on underflow or negative lengths.
 * - Unsigned safety: all integer reads mask signed Kotlin [Byte] values with `0xFF`.
 * - Bounded allocation: [readBytes] validates `len` against both [remaining] and [maxLen] before allocating.
 */
class SafeByteCursor(
    private val data: ByteArray,
    val start: Int = 0,
    val end: Int = data.size
) {
    var pos: Int = start
        private set

    init {
        require(start in 0..data.size && end in start..data.size) { "Invalid slice bounds" }
    }

    val size: Int get() = end - start
    val remaining: Int get() = end - pos
    val isExhausted: Boolean get() = pos >= end

    fun peekU8(offsetFromPos: Int = 0): Int? {
        if (offsetFromPos < 0 || offsetFromPos >= remaining) return null
        return data[pos + offsetFromPos].toInt() and 0xFF
    }

    fun readU8(): Int? {
        if (remaining < 1) return null
        return data[pos++].toInt() and 0xFF
    }

    fun readU16BE(): Int? {
        if (remaining < 2) return null
        val v = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
        pos += 2
        return v
    }

    fun readU16LE(): Int? {
        if (remaining < 2) return null
        val v = (data[pos].toInt() and 0xFF) or ((data[pos + 1].toInt() and 0xFF) shl 8)
        pos += 2
        return v
    }

    fun readU24BE(): Int? {
        if (remaining < 3) return null
        val v = ((data[pos].toInt() and 0xFF) shl 16) or
            ((data[pos + 1].toInt() and 0xFF) shl 8) or
            (data[pos + 2].toInt() and 0xFF)
        pos += 3
        return v
    }

    fun readU32BE(): Long? {
        if (remaining < 4) return null
        val v = ((data[pos].toLong() and 0xFF) shl 24) or
            ((data[pos + 1].toLong() and 0xFF) shl 16) or
            ((data[pos + 2].toLong() and 0xFF) shl 8) or
            (data[pos + 3].toLong() and 0xFF)
        pos += 4
        return v
    }

    fun readS32BE(): Int? {
        if (remaining < 4) return null
        val v = ((data[pos].toInt() and 0xFF) shl 24) or
            ((data[pos + 1].toInt() and 0xFF) shl 16) or
            ((data[pos + 2].toInt() and 0xFF) shl 8) or
            (data[pos + 3].toInt() and 0xFF)
        pos += 4
        return v
    }

    fun readS64BE(): Long? {
        if (remaining < 8) return null
        var v = 0L
        for (i in 0 until 8) {
            v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        }
        pos += 8
        return v
    }

    fun readBytes(len: Int, maxLen: Int = Int.MAX_VALUE): ByteArray? {
        if (len < 0 || len > maxLen || len > remaining) return null
        val out = data.copyOfRange(pos, pos + len)
        pos += len
        return out
    }

    fun readAscii(len: Int): String? {
        if (len < 0 || len > remaining) return null
        val s = String(data, pos, len, Charsets.US_ASCII)
        pos += len
        return s
    }

    fun readLatin1(len: Int): String? {
        if (len < 0 || len > remaining) return null
        val s = String(data, pos, len, Charsets.ISO_8859_1)
        pos += len
        return s
    }

    fun skip(n: Int): Boolean {
        if (n < 0 || n > remaining) return false
        pos += n
        return true
    }

    fun seekRelative(relativeOffset: Int): Boolean {
        if (relativeOffset < 0 || relativeOffset > size) return false
        pos = start + relativeOffset
        return true
    }

    fun slice(len: Int): SafeByteCursor? {
        if (len < 0 || len > remaining) return null
        val sub = SafeByteCursor(data, pos, pos + len)
        pos += len
        return sub
    }

    fun duplicateAt(relativeOffset: Int): SafeByteCursor? {
        if (relativeOffset < 0 || relativeOffset > size) return null
        val copy = SafeByteCursor(data, start, end)
        copy.pos = start + relativeOffset
        return copy
    }

    companion object {
        fun of(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): SafeByteCursor? {
            if (offset < 0 || length < 0 || offset > data.size) return null
            val safeEnd = minOf(data.size.toLong(), offset.toLong() + length.toLong()).toInt()
            return SafeByteCursor(data, offset, safeEnd)
        }
    }
}
