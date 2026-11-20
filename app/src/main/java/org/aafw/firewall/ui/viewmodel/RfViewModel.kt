package org.aafw.firewall.ui.viewmodel

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import org.aafw.firewall.AppContainer
import org.aafw.firewall.data.local.AppSettings
import org.aafw.firewall.data.local.RfAllocationEntity
import org.aafw.firewall.engine.rf.DetectedUsbHardware
import org.aafw.firewall.engine.rf.Radix2FftEngine
import org.aafw.firewall.engine.rf.SpectrumFrame
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class RfUiState(
    val usbDevices: List<DetectedUsbHardware> = emptyList(),
    val isStreaming: Boolean = false,
    val activeSourceLabel: String = "Standby (Attach USB-OTG SDR or Load .cu8 I/Q)",
    val latestSpectrum: SpectrumFrame? = null,
    val waterfallHistory: List<FloatArray> = emptyList()
)

class RfViewModel(
    application: Application,
    private val container: AppContainer
) : AndroidViewModel(application) {

    private val fftEngine by lazy { Radix2FftEngine(fftSize = 1024) }
    private var streamJob: Job? = null

    val settings: StateFlow<AppSettings> = container.preferences.settingsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), AppSettings())

    val allocations: StateFlow<List<RfAllocationEntity>> = container.repository.rfAllocations
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    private val _uiState = MutableStateFlow(RfUiState())
    val uiState: StateFlow<RfUiState> = _uiState.asStateFlow()

    init {
        scanUsbDevices()
    }

    fun scanUsbDevices() {
        viewModelScope.launch(Dispatchers.IO) {
            val devices = container.usbSdrManager.enumerateDevices()
            _uiState.update { it.copy(usbDevices = devices) }
        }
    }

    fun requestUsbPermission(hw: DetectedUsbHardware) {
        container.usbSdrManager.requestUsbPermission(hw.usbDevice)
    }

    fun startUsbSdrStream(hw: DetectedUsbHardware) {
        stopStream()
        val curSettings = settings.value
        _uiState.update {
            it.copy(
                isStreaming = true,
                activeSourceLabel = "Connecting USB-OTG: ${hw.modelLabel}...",
                waterfallHistory = emptyList()
            )
        }
        streamJob = viewModelScope.launch(Dispatchers.Default) {
            container.usbSdrManager.streamRtlSdrBulk(
                device = hw.usbDevice,
                sampleRateHz = curSettings.rfSampleRateHz,
                onStatus = { status ->
                    _uiState.update { it.copy(activeSourceLabel = status) }
                },
                onIqBlock = { bytes, len ->
                    processIqBlock(bytes, len)
                }
            )
            _uiState.update { it.copy(isStreaming = false) }
        }
    }

    fun loadCu8Capture(uri: Uri, label: String) {
        stopStream()
        _uiState.update {
            it.copy(
                isStreaming = true,
                activeSourceLabel = "Loading $label...",
                waterfallHistory = emptyList()
            )
        }
        streamJob = viewModelScope.launch(Dispatchers.Default) {
            container.usbSdrManager.streamCu8File(
                uri = uri,
                onStatus = { status ->
                    _uiState.update { it.copy(activeSourceLabel = status) }
                },
                onIqBlock = { bytes, len ->
                    processIqBlock(bytes, len)
                }
            )
            _uiState.update { it.copy(isStreaming = false) }
        }
    }

    fun stopStream() {
        streamJob?.cancel()
        streamJob = null
        _uiState.update {
            it.copy(
                isStreaming = false,
                activeSourceLabel = "RF Pipeline Stopped"
            )
        }
    }

    fun tuneCenterFreq(freqMhz: Double) {
        viewModelScope.launch(Dispatchers.IO) {
            container.preferences.updateRfSettings(centerFreqMhz = freqMhz.coerceIn(1.0, 6000.0))
        }
    }

    fun setPeakThresholdDb(db: Float) {
        viewModelScope.launch(Dispatchers.IO) {
            container.preferences.updateRfSettings(peakThresholdDb = db.coerceIn(4f, 30f))
        }
    }

    private fun processIqBlock(bytes: ByteArray, len: Int) {
        val cfg = settings.value
        val bands = allocations.value
        val frame = fftEngine.processCu8Block(
            iqBytes = bytes,
            byteLength = len,
            centerFreqMhz = cfg.rfCenterFreqMhz,
            sampleRateHz = cfg.rfSampleRateHz,
            peakThresholdDb = cfg.rfPeakThresholdDb
        ) { freqMhz ->
            val match = bands.firstOrNull { freqMhz >= it.startFreqMhz && freqMhz <= it.endFreqMhz }
            if (match != null) {
                match.bandName to match.commonProtocols
            } else {
                "Unallocated / Custom Band" to "Raw Spectral Carrier"
            }
        }
        _uiState.update { cur ->
            // Downsample 1024 bins -> 128 bins for fast 60fps Canvas waterfall rendering
            val compactRow = FloatArray(128) { idx ->
                val start = idx * 8
                var peak = -120f
                for (k in start until minOf(start + 8, frame.binsDb.size)) {
                    if (frame.binsDb[k] > peak) peak = frame.binsDb[k]
                }
                peak
            }
            val nextWaterfall = (listOf(compactRow) + cur.waterfallHistory).take(48)
            cur.copy(
                latestSpectrum = frame,
                waterfallHistory = nextWaterfall
            )
        }
    }

    override fun onCleared() {
        stopStream()
        super.onCleared()
    }
}
