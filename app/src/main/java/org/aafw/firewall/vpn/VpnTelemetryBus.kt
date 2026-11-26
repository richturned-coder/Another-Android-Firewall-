package org.aafw.firewall.vpn

import android.os.SystemClock
import org.aafw.firewall.engine.network.PcapngStats
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.ArrayDeque

enum class VpnEngineState {
    STOPPED,
    STARTING,
    RUNNING,
    ERROR
}

data class LivePacketEvent(
    val id: Long,
    val timestamp: Long,
    val direction: String, // TX | RX
    val protocol: String,
    val srcIp: String,
    val srcPort: Int,
    val dstIp: String,
    val dstPort: Int,
    val byteLength: Int,
    val appUid: Int,
    val appLabel: String,
    val allowed: Boolean,
    val ruleReason: String,
    val domainOrSni: String?,
    val tlsSummary: String?,
    val inspectionNote: String,
    val hexPreview: String
)

data class LiveTelemetryCounters(
    val totalPackets: Long = 0L,
    val allowedPackets: Long = 0L,
    val blockedPackets: Long = 0L,
    val totalBytes: Long = 0L,
    val dnsQueries: Long = 0L,
    val tlsHandshakes: Long = 0L,
    val idsAlertHits: Long = 0L
)

class VpnTelemetryBus {
    companion object {
        private const val MAX_RING_SIZE = 400
        private const val MIN_EMIT_INTERVAL_MS = 150L
    }

    private val packetDeque = ArrayDeque<LivePacketEvent>(MAX_RING_SIZE + 1)
    private val lock = Any()

    // Primitive accumulators avoid allocating a LiveTelemetryCounters + 400-item List on every packet
    private var totalPackets = 0L
    private var allowedPackets = 0L
    private var blockedPackets = 0L
    private var totalBytes = 0L
    private var dnsQueries = 0L
    private var tlsHandshakes = 0L
    private var idsAlertHits = 0L
    private var lastEmitElapsedMs = 0L
    private var hasPendingUpdates = false

    private val _vpnState = MutableStateFlow(VpnEngineState.STOPPED)
    val vpnState: StateFlow<VpnEngineState> = _vpnState.asStateFlow()

    private val _lastError = MutableStateFlow<String?>(null)
    val lastError: StateFlow<String?> = _lastError.asStateFlow()

    private val _counters = MutableStateFlow(LiveTelemetryCounters())
    val counters: StateFlow<LiveTelemetryCounters> = _counters.asStateFlow()

    private val _recentPackets = MutableStateFlow<List<LivePacketEvent>>(emptyList())
    val recentPackets: StateFlow<List<LivePacketEvent>> = _recentPackets.asStateFlow()

    private val _pcapStats = MutableStateFlow(PcapngStats())
    val pcapStats: StateFlow<PcapngStats> = _pcapStats.asStateFlow()

    fun setVpnState(state: VpnEngineState, error: String? = null) {
        _vpnState.value = state
        _lastError.value = error
    }

    fun updatePcapStats(stats: PcapngStats) {
        _pcapStats.value = stats
    }

    fun recordPacket(event: LivePacketEvent, isDns: Boolean, isTls: Boolean, newAlerts: Int) {
        var packetSnapshot: List<LivePacketEvent>? = null
        var counterSnapshot: LiveTelemetryCounters? = null

        synchronized(lock) {
            if (packetDeque.size >= MAX_RING_SIZE) {
                packetDeque.removeLast()
            }
            packetDeque.addFirst(event)

            totalPackets++
            if (event.allowed) allowedPackets++ else blockedPackets++
            totalBytes += event.byteLength
            if (isDns) dnsQueries++
            if (isTls) tlsHandshakes++
            idsAlertHits += newAlerts
            hasPendingUpdates = true

            val now = currentMonotonicMs()
            val urgent = !event.allowed || newAlerts > 0 || totalPackets <= 3L
            if (urgent || now - lastEmitElapsedMs >= MIN_EMIT_INTERVAL_MS) {
                lastEmitElapsedMs = now
                hasPendingUpdates = false
                packetSnapshot = ArrayList(packetDeque)
                counterSnapshot = snapshotCountersLocked()
            }
        }

        if (packetSnapshot != null && counterSnapshot != null) {
            _recentPackets.value = packetSnapshot
            _counters.value = counterSnapshot
        }
    }

    /** Flushes any throttled packet/counter snapshots to UI collectors. */
    fun flushPending() {
        var packetSnapshot: List<LivePacketEvent>? = null
        var counterSnapshot: LiveTelemetryCounters? = null

        synchronized(lock) {
            if (!hasPendingUpdates) return
            hasPendingUpdates = false
            lastEmitElapsedMs = currentMonotonicMs()
            packetSnapshot = ArrayList(packetDeque)
            counterSnapshot = snapshotCountersLocked()
        }

        if (packetSnapshot != null && counterSnapshot != null) {
            _recentPackets.value = packetSnapshot
            _counters.value = counterSnapshot
        }
    }

    fun clearLiveStream() {
        synchronized(lock) {
            packetDeque.clear()
            totalPackets = 0L
            allowedPackets = 0L
            blockedPackets = 0L
            totalBytes = 0L
            dnsQueries = 0L
            tlsHandshakes = 0L
            idsAlertHits = 0L
            hasPendingUpdates = false
            lastEmitElapsedMs = 0L
        }
        _recentPackets.value = emptyList()
        _counters.value = LiveTelemetryCounters()
    }

    private fun snapshotCountersLocked(): LiveTelemetryCounters = LiveTelemetryCounters(
        totalPackets = totalPackets,
        allowedPackets = allowedPackets,
        blockedPackets = blockedPackets,
        totalBytes = totalBytes,
        dnsQueries = dnsQueries,
        tlsHandshakes = tlsHandshakes,
        idsAlertHits = idsAlertHits
    )

    private fun currentMonotonicMs(): Long = try {
        SystemClock.elapsedRealtime()
    } catch (_: Throwable) {
        System.nanoTime() / 1_000_000L
    }
}
