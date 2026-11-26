package org.aafw.firewall.engine.bluetooth

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import androidx.core.content.ContextCompat
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import org.aafw.firewall.engine.SafeByteCursor
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap

data class BleAdStructure(
    val adType: Int,
    val data: ByteArray
)

/**
 * Zero-crash, O(n) BLE Advertising Data (AD) TLV parser.
 * Explicitly terminates on `len == 0` (end of AD structures) and validates every structure
 * length against remaining bytes to prevent infinite loops and out-of-bounds reads.
 */
object BleAdParser {
    const val MAX_AD_STRUCTURES = 64

    fun parseAdStructures(rawBytes: ByteArray): List<BleAdStructure> {
        if (rawBytes.isEmpty()) return emptyList()
        val cursor = SafeByteCursor(rawBytes)
        val out = ArrayList<BleAdStructure>()
        while (!cursor.isExhausted && out.size < MAX_AD_STRUCTURES) {
            val beforePos = cursor.pos
            val fieldLen = cursor.readU8() ?: break
            if (fieldLen == 0) break // Explicit end-of-AD terminator prevents zero-length TLV loop
            if (fieldLen > cursor.remaining) break
            val adType = cursor.readU8() ?: break
            val payloadLen = fieldLen - 1
            val payload = cursor.readBytes(payloadLen, 255) ?: break
            out.add(BleAdStructure(adType = adType, data = payload))
            if (cursor.pos <= beforePos) break
        }
        return out
    }
}

enum class BleThreatClass {
    NORMAL,
    TRACKER_WATCH,
    TRACKER_PERSISTENT,
    BLE_SPAM_FLOOD
}

data class BleAdvertisingClassification(
    val vendorTag: String,
    val threatClass: BleThreatClass,
    val note: String,
    val isSpamCandidate: Boolean
)

data class BleDeviceSighting(
    val address: String,
    val name: String?,
    val rssi: Int,
    val rssiHistory: List<Int>,
    val vendorTag: String,
    val threatClass: BleThreatClass,
    val threatNote: String,
    val firstSeenAt: Long,
    val lastSeenAt: Long,
    val packetCount: Int,
    val rawAdvHex: String
) {
    val persistenceSeconds: Long get() = ((lastSeenAt - firstSeenAt) / 1000L).coerceAtLeast(0L)
}

data class BleMonitorSnapshot(
    val isScanning: Boolean = false,
    val bluetoothEnabled: Boolean = false,
    val spamAlertActive: Boolean = false,
    val spamSummary: String? = null,
    val packetsPerSecond: Int = 0,
    val trackerCount: Int = 0,
    val devices: List<BleDeviceSighting> = emptyList(),
    val statusMessage: String = "Passive BLE monitor standby"
)

class BleThreatMonitor(private val context: Context) {
    companion object {
        const val MAX_SIGHTINGS = 200
        private const val MAX_RECENT_ALL_PACKETS = 2_000
        private const val MAX_RECENT_FLOOD_EVENTS = 1_000
        private const val MIN_SNAPSHOT_INTERVAL_MS = 250L

        /**
         * Pure-Kotlin BLE AD TLV classifier covering Manufacturer Specific Data (0xFF),
         * 16-bit Service UUID lists (0x02/0x03), and 16-bit Service Data (0x16) used by
         * AirTag/Find My, Tile, Samsung SmartTag, Google Fast Pair/FMD, Swift Pair, and BLE spam payloads.
         */
        fun classifyRawAdPayload(rawBytes: ByteArray): BleAdvertisingClassification? {
            if (rawBytes.isEmpty()) return null
            val structures = BleAdParser.parseAdStructures(rawBytes)
            for (ad in structures) {
                when (ad.adType) {
                    0xFF -> { // Manufacturer Specific Data: 2-byte LE Company ID + payload
                        if (ad.data.size >= 3) {
                            val companyId = (ad.data[0].toInt() and 0xFF) or
                                ((ad.data[1].toInt() and 0xFF) shl 8)
                            val subType = ad.data[2].toInt() and 0xFF
                            classifyManufacturerData(companyId, subType)?.let { return it }
                        }
                    }
                    0x16 -> { // Service Data - 16-bit UUID (2-byte LE UUID + service payload)
                        if (ad.data.size >= 2) {
                            val uuid16 = (ad.data[0].toInt() and 0xFF) or
                                ((ad.data[1].toInt() and 0xFF) shl 8)
                            classifyServiceUuid16(uuid16)?.let { return it }
                        }
                    }
                    0x02, 0x03 -> { // Incomplete / Complete List of 16-bit Service Class UUIDs
                        var i = 0
                        while (i + 1 < ad.data.size) {
                            val uuid16 = (ad.data[i].toInt() and 0xFF) or
                                ((ad.data[i + 1].toInt() and 0xFF) shl 8)
                            classifyServiceUuid16(uuid16)?.let { return it }
                            i += 2
                        }
                    }
                }
            }
            return null
        }

        internal fun classifyManufacturerData(companyId: Int, subType: Int): BleAdvertisingClassification? =
            when (companyId) {
                0x004C -> when (subType) { // Apple Inc.
                    0x12 -> BleAdvertisingClassification(
                        "Apple Find My / AirTag",
                        BleThreatClass.TRACKER_WATCH,
                        "Find My Offline Finding beacon (0x004C type 0x12)",
                        false
                    )
                    0x07, 0x0F -> BleAdvertisingClassification(
                        "Apple Continuity Pop-up",
                        BleThreatClass.NORMAL,
                        "Proximity Pairing / Nearby Action frame (0x004C type 0x${"%02X".format(subType)})",
                        true
                    )
                    else -> BleAdvertisingClassification(
                        "Apple BLE (0x004C)",
                        BleThreatClass.NORMAL,
                        "Continuity frame type 0x${"%02X".format(subType)}",
                        false
                    )
                }
                0x0006 -> if (subType == 0x03) { // Microsoft Swift Pair
                    BleAdvertisingClassification(
                        "Microsoft Swift Pair",
                        BleThreatClass.NORMAL,
                        "Swift Pair beacon (monitored for flood attacks)",
                        true
                    )
                } else null
                0x0075 -> if (subType == 0x42) { // Samsung Easy Setup (Buds / Watch spam target)
                    BleAdvertisingClassification(
                        "Samsung Easy Setup",
                        BleThreatClass.NORMAL,
                        "Samsung BLE Easy Setup frame (monitored for flood attacks)",
                        true
                    )
                } else null
                else -> null
            }

        internal fun classifyServiceUuid16(uuid16: Int): BleAdvertisingClassification? =
            when (uuid16) {
                0xFEED -> BleAdvertisingClassification(
                    "Tile Tracker",
                    BleThreatClass.TRACKER_WATCH,
                    "Tile Bluetooth tracker UUID 0xFEED",
                    false
                )
                0xFD5A -> BleAdvertisingClassification(
                    "Samsung SmartTag",
                    BleThreatClass.TRACKER_WATCH,
                    "SmartThings Find tracker UUID 0xFD5A",
                    false
                )
                0xFE2C -> BleAdvertisingClassification(
                    "Google Fast Pair / FMD",
                    BleThreatClass.TRACKER_WATCH,
                    "Google Fast Pair / Find My Device UUID 0xFE2C",
                    true
                )
                0xFD6F -> BleAdvertisingClassification(
                    "Exposure / Beacon Service",
                    BleThreatClass.NORMAL,
                    "Proximity beacon service UUID 0xFD6F",
                    false
                )
                else -> null
            }

        /**
         * Selects the eviction victim when [sightings] exceeds [MAX_SIGHTINGS].
         * Prefers evicting the oldest NORMAL entry so rotating-MAC BLE spam floods cannot
         * evict active persistent trackers from memory.
         */
        internal fun selectEvictionKey(sightings: Map<String, BleDeviceSighting>): String? {
            val oldestNormal = sightings.entries
                .asSequence()
                .filter { it.value.threatClass == BleThreatClass.NORMAL }
                .minByOrNull { it.value.lastSeenAt }
                ?.key
            if (oldestNormal != null) return oldestNormal
            return sightings.entries.minByOrNull { it.value.lastSeenAt }?.key
        }
    }

    private val bluetoothManager: BluetoothManager? by lazy {
        context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
    }
    private val adapter: BluetoothAdapter? get() = bluetoothManager?.adapter
    private val scanner: BluetoothLeScanner? get() = adapter?.bluetoothLeScanner

    private val sightings = ConcurrentHashMap<String, BleDeviceSighting>()
    private val recentFloodEvents = ArrayDeque<Pair<Long, String>>() // timestamp -> address
    private val recentAllPackets = ArrayDeque<Long>()
    private val lock = Any()
    private var lastSnapshotEmitAt = 0L

    private val _snapshot = MutableStateFlow(BleMonitorSnapshot())
    val snapshot: StateFlow<BleMonitorSnapshot> = _snapshot.asStateFlow()

    @Volatile
    private var activeCallback: ScanCallback? = null

    private var adapterReceiverRegistered = false
    private val adapterStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context?, intent: Intent?) {
            if (intent?.action != BluetoothAdapter.ACTION_STATE_CHANGED) return
            val state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)
            when (state) {
                BluetoothAdapter.STATE_TURNING_OFF, BluetoothAdapter.STATE_OFF -> {
                    stopScanning("Bluetooth adapter turned off.")
                    _snapshot.update { it.copy(bluetoothEnabled = false) }
                }
                BluetoothAdapter.STATE_ON -> {
                    _snapshot.update { it.copy(bluetoothEnabled = true) }
                }
            }
        }
    }

    fun refreshAdapterState() {
        val enabled = runCatching { adapter?.isEnabled == true }.getOrDefault(false)
        _snapshot.update { current ->
            if (!enabled && current.isScanning) {
                activeCallback = null
                unregisterAdapterStateReceiver()
                current.copy(
                    isScanning = false,
                    bluetoothEnabled = false,
                    statusMessage = "Bluetooth adapter is disabled."
                )
            } else {
                current.copy(bluetoothEnabled = enabled)
            }
        }
    }

    @SuppressLint("MissingPermission")
    fun startScanning(): Boolean {
        val btAdapter = adapter
        if (btAdapter == null || !btAdapter.isEnabled) {
            _snapshot.update {
                it.copy(
                    isScanning = false,
                    bluetoothEnabled = false,
                    statusMessage = "Bluetooth adapter is disabled or unavailable on this device."
                )
            }
            return false
        }
        val leScanner = scanner
        if (leScanner == null) {
            _snapshot.update {
                it.copy(
                    isScanning = false,
                    bluetoothEnabled = true,
                    statusMessage = "BLE scanner hardware unavailable."
                )
            }
            return false
        }
        synchronized(lock) {
            if (activeCallback != null) return true
        }

        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .setReportDelay(0L)
            .build()

        val cb = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                processScanResult(result)
            }

            override fun onBatchScanResults(results: MutableList<ScanResult>) {
                for (r in results) processScanResult(r)
            }

            override fun onScanFailed(errorCode: Int) {
                synchronized(lock) {
                    activeCallback = null
                }
                unregisterAdapterStateReceiver()
                _snapshot.update {
                    it.copy(
                        isScanning = false,
                        statusMessage = "BLE scan failed (error code $errorCode)"
                    )
                }
            }
        }

        return try {
            leScanner.startScan(null, settings, cb)
            synchronized(lock) {
                activeCallback = cb
            }
            registerAdapterStateReceiver()
            _snapshot.update {
                it.copy(
                    isScanning = true,
                    bluetoothEnabled = true,
                    statusMessage = "Listening for raw BLE advertising frames (Low-Latency)..."
                )
            }
            true
        } catch (se: SecurityException) {
            _snapshot.update {
                it.copy(
                    isScanning = false,
                    statusMessage = "Missing BLE scan runtime permission."
                )
            }
            false
        } catch (e: Exception) {
            _snapshot.update {
                it.copy(
                    isScanning = false,
                    statusMessage = "Failed to start BLE scan: ${e.message}"
                )
            }
            false
        }
    }

    @SuppressLint("MissingPermission")
    fun stopScanning(reason: String = "Passive BLE monitor stopped.") {
        val cb = synchronized(lock) {
            val current = activeCallback
            activeCallback = null
            current
        }
        unregisterAdapterStateReceiver()
        if (cb != null) {
            runCatching { scanner?.stopScan(cb) }
        }
        _snapshot.update {
            it.copy(
                isScanning = false,
                statusMessage = reason
            )
        }
    }

    fun clearSightings() {
        synchronized(lock) {
            sightings.clear()
            recentFloodEvents.clear()
            recentAllPackets.clear()
            lastSnapshotEmitAt = 0L
        }
        _snapshot.update {
            it.copy(
                spamAlertActive = false,
                spamSummary = null,
                packetsPerSecond = 0,
                trackerCount = 0,
                devices = emptyList()
            )
        }
    }

    private fun registerAdapterStateReceiver() {
        if (adapterReceiverRegistered) return
        runCatching {
            ContextCompat.registerReceiver(
                context,
                adapterStateReceiver,
                IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED),
                ContextCompat.RECEIVER_EXPORTED
            )
            adapterReceiverRegistered = true
        }
    }

    private fun unregisterAdapterStateReceiver() {
        if (!adapterReceiverRegistered) return
        runCatching { context.unregisterReceiver(adapterStateReceiver) }
        adapterReceiverRegistered = false
    }

    @SuppressLint("MissingPermission")
    private fun processScanResult(result: ScanResult) {
        val now = System.currentTimeMillis()
        val address = result.device?.address ?: return
        val record = result.scanRecord
        val rawBytes = record?.bytes ?: ByteArray(0)
        val deviceName = record?.deviceName ?: runCatching { result.device?.name }.getOrNull()
        val rssi = result.rssi

        val classification = classifyAdvertisingFrame(record, rawBytes)

        var pps = 0
        var spamActive = false
        var spamSummary: String? = null
        var sorted: List<BleDeviceSighting>? = null
        var trackerCount = 0

        synchronized(lock) {
            if (activeCallback == null) return

            val existing = sightings[address]
            val firstSeen = existing?.firstSeenAt ?: now
            val persistenceSec = (now - firstSeen) / 1000L
            val rssiHistory = ((existing?.rssiHistory ?: emptyList()) + rssi).takeLast(12)
            val count = (existing?.packetCount ?: 0) + 1

            var finalThreat = classification.threatClass
            var finalNote = classification.note

            if (classification.threatClass == BleThreatClass.TRACKER_WATCH && persistenceSec >= 180L) {
                finalThreat = BleThreatClass.TRACKER_PERSISTENT
                finalNote = "${classification.note} • Persistent >3m (${persistenceSec}s) — potential stalking tag"
            }

            val updated = BleDeviceSighting(
                address = address,
                name = deviceName ?: existing?.name,
                rssi = rssi,
                rssiHistory = rssiHistory,
                vendorTag = classification.vendorTag,
                threatClass = finalThreat,
                threatNote = finalNote,
                firstSeenAt = firstSeen,
                lastSeenAt = now,
                packetCount = count,
                rawAdvHex = rawBytes.take(31).joinToString(" ") { "%02X".format(it.toInt() and 0xFF) }
            )

            sightings[address] = updated
            if (sightings.size > MAX_SIGHTINGS) {
                val victimKey = selectEvictionKey(sightings)
                if (victimKey != null && victimKey != address) {
                    sightings.remove(victimKey)
                }
            }

            if (recentAllPackets.size >= MAX_RECENT_ALL_PACKETS) recentAllPackets.removeFirst()
            recentAllPackets.addLast(now)
            while (recentAllPackets.isNotEmpty() && now - recentAllPackets.first() > 1000L) {
                recentAllPackets.removeFirst()
            }
            pps = recentAllPackets.size

            if (classification.isSpamCandidate) {
                if (recentFloodEvents.size >= MAX_RECENT_FLOOD_EVENTS) recentFloodEvents.removeFirst()
                recentFloodEvents.addLast(now to address)
            }
            while (recentFloodEvents.isNotEmpty() && now - recentFloodEvents.first().first > 5000L) {
                recentFloodEvents.removeFirst()
            }
            val uniqueFloodMacs = recentFloodEvents.map { it.second }.toSet().size
            if (recentFloodEvents.size >= 25 && uniqueFloodMacs >= 6) {
                spamActive = true
                spamSummary = "BLE Advertising Spam Flood detected (${recentFloodEvents.size} frames / $uniqueFloodMacs rotating MACs in 5s — Flipper Zero / Continuity / Fast Pair signature)"
                sightings[address] = updated.copy(
                    threatClass = BleThreatClass.BLE_SPAM_FLOOD,
                    threatNote = "Part of rotating-MAC BLE advertising flood"
                )
            }

            val isUrgentChange = existing == null ||
                existing.threatClass != sightings[address]?.threatClass ||
                spamActive != _snapshot.value.spamAlertActive
            if (isUrgentChange || now - lastSnapshotEmitAt >= MIN_SNAPSHOT_INTERVAL_MS) {
                lastSnapshotEmitAt = now
                val snapshotList = sightings.values.sortedWith(
                    compareByDescending<BleDeviceSighting> { it.threatClass.ordinal }
                        .thenByDescending { it.lastSeenAt }
                )
                trackerCount = snapshotList.count {
                    it.threatClass == BleThreatClass.TRACKER_WATCH || it.threatClass == BleThreatClass.TRACKER_PERSISTENT
                }
                sorted = snapshotList
            }
        }

        val readyDevices = sorted ?: return
        _snapshot.update { current ->
            if (!current.isScanning) return@update current
            current.copy(
                bluetoothEnabled = true,
                spamAlertActive = spamActive,
                spamSummary = spamSummary,
                packetsPerSecond = pps,
                trackerCount = trackerCount,
                devices = readyDevices
            )
        }
    }

    private fun classifyAdvertisingFrame(
        record: android.bluetooth.le.ScanRecord?,
        rawBytes: ByteArray
    ): BleAdvertisingClassification {
        val mfg = record?.manufacturerSpecificData
        if (mfg != null) {
            for (companyId in intArrayOf(0x004C, 0x0006, 0x0075)) {
                val payload = mfg.get(companyId)
                if (payload != null && payload.isNotEmpty()) {
                    val subType = payload[0].toInt() and 0xFF
                    classifyManufacturerData(companyId, subType)?.let { return it }
                }
            }
        }

        val serviceUuids = record?.serviceUuids?.map { it.uuid.toString().uppercase() }.orEmpty()
        for (uuid in serviceUuids) {
            when {
                uuid.startsWith("0000FEED") -> return classifyServiceUuid16(0xFEED)!!
                uuid.startsWith("0000FD5A") -> return classifyServiceUuid16(0xFD5A)!!
                uuid.startsWith("0000FE2C") -> return classifyServiceUuid16(0xFE2C)!!
            }
        }

        // Check Service Data (0x16) and raw AD TLV structures via hardened BleAdParser
        classifyRawAdPayload(rawBytes)?.let { return it }

        val hexStr = rawBytes.take(12).joinToString("") { "%02X".format(it.toInt() and 0xFF) }
        return BleAdvertisingClassification(
            vendorTag = if (hexStr.isNotEmpty()) "BLE Device" else "Unknown BLE",
            threatClass = BleThreatClass.NORMAL,
            note = "Standard BLE advertising packet",
            isSpamCandidate = false
        )
    }
}
