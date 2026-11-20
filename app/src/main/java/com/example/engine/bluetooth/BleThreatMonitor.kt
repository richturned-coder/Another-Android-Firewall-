package com.example.engine.bluetooth

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.ArrayDeque
import java.util.concurrent.ConcurrentHashMap

enum class BleThreatClass {
    NORMAL,
    TRACKER_WATCH,
    TRACKER_PERSISTENT,
    BLE_SPAM_FLOOD
}

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
    private val bluetoothManager: BluetoothManager? =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
    private val adapter: BluetoothAdapter? get() = bluetoothManager?.adapter
    private val scanner: BluetoothLeScanner? get() = adapter?.bluetoothLeScanner

    private val sightings = ConcurrentHashMap<String, BleDeviceSighting>()
    private val recentFloodEvents = ArrayDeque<Pair<Long, String>>() // timestamp -> address
    private val recentAllPackets = ArrayDeque<Long>()
    private val lock = Any()

    private val _snapshot = MutableStateFlow(
        BleMonitorSnapshot(bluetoothEnabled = adapter?.isEnabled == true)
    )
    val snapshot: StateFlow<BleMonitorSnapshot> = _snapshot.asStateFlow()

    private var activeCallback: ScanCallback? = null

    @SuppressLint("MissingPermission")
    fun startScanning(): Boolean {
        val btAdapter = adapter
        if (btAdapter == null || !btAdapter.isEnabled) {
            _snapshot.value = _snapshot.value.copy(
                isScanning = false,
                bluetoothEnabled = false,
                statusMessage = "Bluetooth adapter is disabled or unavailable on this device."
            )
            return false
        }
        val leScanner = scanner
        if (leScanner == null) {
            _snapshot.value = _snapshot.value.copy(
                isScanning = false,
                bluetoothEnabled = true,
                statusMessage = "BLE scanner hardware unavailable."
            )
            return false
        }
        if (activeCallback != null) return true

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
                activeCallback = null
                _snapshot.value = _snapshot.value.copy(
                    isScanning = false,
                    statusMessage = "BLE scan failed (error code $errorCode)"
                )
            }
        }

        return try {
            leScanner.startScan(null, settings, cb)
            activeCallback = cb
            _snapshot.value = _snapshot.value.copy(
                isScanning = true,
                bluetoothEnabled = true,
                statusMessage = "Listening for raw BLE advertising frames (Low-Latency)..."
            )
            true
        } catch (se: SecurityException) {
            _snapshot.value = _snapshot.value.copy(
                isScanning = false,
                statusMessage = "Missing BLUETOOTH_SCAN runtime permission."
            )
            false
        } catch (e: Exception) {
            _snapshot.value = _snapshot.value.copy(
                isScanning = false,
                statusMessage = "Failed to start BLE scan: ${e.message}"
            )
            false
        }
    }

    @SuppressLint("MissingPermission")
    fun stopScanning() {
        val cb = activeCallback
        activeCallback = null
        if (cb != null) {
            runCatching { scanner?.stopScan(cb) }
        }
        _snapshot.value = _snapshot.value.copy(
            isScanning = false,
            statusMessage = "Passive BLE monitor stopped."
        )
    }

    fun clearSightings() {
        synchronized(lock) {
            sightings.clear()
            recentFloodEvents.clear()
            recentAllPackets.clear()
        }
        _snapshot.value = _snapshot.value.copy(
            spamAlertActive = false,
            spamSummary = null,
            packetsPerSecond = 0,
            trackerCount = 0,
            devices = emptyList()
        )
    }

    @SuppressLint("MissingPermission")
    private fun processScanResult(result: ScanResult) {
        val now = System.currentTimeMillis()
        val address = result.device?.address ?: return
        val record = result.scanRecord
        val rawBytes = record?.bytes ?: ByteArray(0)
        val deviceName = record?.deviceName ?: runCatching { result.device?.name }.getOrNull()
        val rssi = result.rssi

        val (vendorTag, baseThreat, baseNote, isSpamCandidate) = classifyAdvertisingFrame(record, rawBytes)

        val existing = sightings[address]
        val firstSeen = existing?.firstSeenAt ?: now
        val persistenceSec = (now - firstSeen) / 1000L
        val rssiHistory = ((existing?.rssiHistory ?: emptyList()) + rssi).takeLast(12)
        val count = (existing?.packetCount ?: 0) + 1

        var finalThreat = baseThreat
        var finalNote = baseNote

        if (baseThreat == BleThreatClass.TRACKER_WATCH && persistenceSec >= 180L) {
            finalThreat = BleThreatClass.TRACKER_PERSISTENT
            finalNote = "$baseNote • Persistent >3m (${persistenceSec}s) — potential stalking tag"
        }

        val updated = BleDeviceSighting(
            address = address,
            name = deviceName ?: existing?.name,
            rssi = rssi,
            rssiHistory = rssiHistory,
            vendorTag = vendorTag,
            threatClass = finalThreat,
            threatNote = finalNote,
            firstSeenAt = firstSeen,
            lastSeenAt = now,
            packetCount = count,
            rawAdvHex = rawBytes.take(31).joinToString(" ") { "%02X".format(it.toInt() and 0xFF) }
        )

        var pps = 0
        var spamActive = false
        var spamSummary: String? = null

        synchronized(lock) {
            sightings[address] = updated
            if (sightings.size > 200) {
                val oldestKey = sightings.entries.minByOrNull { it.value.lastSeenAt }?.key
                if (oldestKey != null) sightings.remove(oldestKey)
            }

            recentAllPackets.addLast(now)
            while (recentAllPackets.isNotEmpty() && now - recentAllPackets.first() > 1000L) {
                recentAllPackets.removeFirst()
            }
            pps = recentAllPackets.size

            if (isSpamCandidate) {
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
        }

        val sorted = sightings.values.sortedWith(
            compareByDescending<BleDeviceSighting> { it.threatClass.ordinal }
                .thenByDescending { it.lastSeenAt }
        )
        val trackerCount = sorted.count {
            it.threatClass == BleThreatClass.TRACKER_WATCH || it.threatClass == BleThreatClass.TRACKER_PERSISTENT
        }

        _snapshot.value = _snapshot.value.copy(
            isScanning = activeCallback != null,
            bluetoothEnabled = true,
            spamAlertActive = spamActive,
            spamSummary = spamSummary,
            packetsPerSecond = pps,
            trackerCount = trackerCount,
            devices = sorted
        )
    }

    private data class Classification(
        val vendorTag: String,
        val threatClass: BleThreatClass,
        val note: String,
        val isSpamCandidate: Boolean
    )

    private fun classifyAdvertisingFrame(
        record: android.bluetooth.le.ScanRecord?,
        rawBytes: ByteArray
    ): Classification {
        val mfg = record?.manufacturerSpecificData
        if (mfg != null) {
            // Apple Inc. (0x004C)
            val appleData = mfg.get(0x004C)
            if (appleData != null && appleData.isNotEmpty()) {
                val subType = appleData[0].toInt() and 0xFF
                return when (subType) {
                    0x12 -> Classification(
                        "Apple Find My / AirTag",
                        BleThreatClass.TRACKER_WATCH,
                        "Find My Offline Finding beacon (0x004C type 0x12)",
                        false
                    )
                    0x07, 0x0F -> Classification(
                        "Apple Continuity Pop-up",
                        BleThreatClass.NORMAL,
                        "Proximity Pairing / Nearby Action frame (0x004C type 0x${"%02X".format(subType)})",
                        true
                    )
                    else -> Classification(
                        "Apple BLE (0x004C)",
                        BleThreatClass.NORMAL,
                        "Continuity frame type 0x${"%02X".format(subType)}",
                        false
                    )
                }
            }
            // Microsoft Swift Pair (0x0006)
            val msData = mfg.get(0x0006)
            if (msData != null && msData.isNotEmpty() && (msData[0].toInt() and 0xFF) == 0x03) {
                return Classification(
                    "Microsoft Swift Pair",
                    BleThreatClass.NORMAL,
                    "Swift Pair beacon (monitored for flood attacks)",
                    true
                )
            }
        }

        val serviceUuids = record?.serviceUuids?.map { it.uuid.toString().uppercase() }.orEmpty()
        for (uuid in serviceUuids) {
            when {
                uuid.startsWith("0000FEED") -> return Classification(
                    "Tile Tracker",
                    BleThreatClass.TRACKER_WATCH,
                    "Tile Bluetooth tracker UUID 0xFEED",
                    false
                )
                uuid.startsWith("0000FD5A") -> return Classification(
                    "Samsung SmartTag",
                    BleThreatClass.TRACKER_WATCH,
                    "SmartThings Find tracker UUID 0xFD5A",
                    false
                )
                uuid.startsWith("0000FE2C") -> return Classification(
                    "Google Fast Pair / FMD",
                    BleThreatClass.TRACKER_WATCH,
                    "Google Fast Pair / Find My Device UUID 0xFE2C",
                    true
                )
            }
        }

        val hexStr = rawBytes.take(12).joinToString("") { "%02X".format(it.toInt() and 0xFF) }
        return Classification(
            vendorTag = if (hexStr.isNotEmpty()) "BLE Device" else "Unknown BLE",
            threatClass = BleThreatClass.NORMAL,
            note = "Standard BLE advertising packet",
            isSpamCandidate = false
        )
    }
}
