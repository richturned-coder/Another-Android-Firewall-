package com.example.vpn

import com.example.engine.network.PcapngStats
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
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
    private val maxRingSize = 400
    private val packetDeque = ArrayDeque<LivePacketEvent>(maxRingSize + 1)
    private val lock = Any()

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
        synchronized(lock) {
            if (packetDeque.size >= maxRingSize) {
                packetDeque.removeLast()
            }
            packetDeque.addFirst(event)
            _recentPackets.value = packetDeque.toList()
        }
        _counters.update { cur ->
            cur.copy(
                totalPackets = cur.totalPackets + 1,
                allowedPackets = cur.allowedPackets + if (event.allowed) 1 else 0,
                blockedPackets = cur.blockedPackets + if (!event.allowed) 1 else 0,
                totalBytes = cur.totalBytes + event.byteLength,
                dnsQueries = cur.dnsQueries + if (isDns) 1 else 0,
                tlsHandshakes = cur.tlsHandshakes + if (isTls) 1 else 0,
                idsAlertHits = cur.idsAlertHits + newAlerts
            )
        }
    }

    fun clearLiveStream() {
        synchronized(lock) {
            packetDeque.clear()
            _recentPackets.value = emptyList()
        }
        _counters.value = LiveTelemetryCounters()
    }
}
