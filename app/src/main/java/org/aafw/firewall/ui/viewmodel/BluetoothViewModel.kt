package org.aafw.firewall.ui.viewmodel

import android.app.Application
import android.net.Uri
import android.os.Build
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import org.aafw.firewall.AppContainer
import org.aafw.firewall.engine.bluetooth.BleMonitorSnapshot
import org.aafw.firewall.engine.bluetooth.BtSnoopParser
import org.aafw.firewall.engine.bluetooth.HciPacketLayer
import org.aafw.firewall.engine.bluetooth.HciParsedFrame
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class HciCaptureUiState(
    val sourceLabel: String = "No HCI log or live socket attached",
    val isLiveStreaming: Boolean = false,
    val totalFrames: Int = 0,
    val frames: List<HciParsedFrame> = emptyList(),
    val errorMessage: String? = null,
    val shizukuInstalled: Boolean = false,
    val androidApiLevel: Int = Build.VERSION.SDK_INT,
    val selectedLayer: HciPacketLayer? = null
)

class BluetoothViewModel(
    application: Application,
    private val container: AppContainer
) : AndroidViewModel(application) {

    val bleSnapshot: StateFlow<BleMonitorSnapshot> = container.bleMonitor.snapshot

    private val _hciState = MutableStateFlow(HciCaptureUiState())
    val hciState: StateFlow<HciCaptureUiState> = _hciState.asStateFlow()

    private var liveSocketJob: Job? = null

    init {
        viewModelScope.launch(Dispatchers.IO) {
            container.bleMonitor.refreshAdapterState()
            val hasShizuku = BtSnoopParser.isShizukuInstalled(getApplication())
            _hciState.update { it.copy(shizukuInstalled = hasShizuku) }
        }
    }

    fun startBleScan() {
        container.bleMonitor.startScanning()
    }

    fun stopBleScan() {
        container.bleMonitor.stopScanning()
    }

    fun refreshAdapterState() {
        container.bleMonitor.refreshAdapterState()
    }

    fun clearBleSightings() {
        container.bleMonitor.clearSightings()
    }

    fun setHciLayerFilter(layer: HciPacketLayer?) {
        _hciState.update { it.copy(selectedLayer = layer) }
    }

    fun importBtSnoopFile(uri: Uri, displayName: String) {
        disconnectLiveSocket()
        viewModelScope.launch {
            _hciState.update {
                it.copy(
                    sourceLabel = "Parsing $displayName...",
                    errorMessage = null
                )
            }
            val result = BtSnoopParser.parseUri(getApplication(), uri, displayName)
            _hciState.update {
                it.copy(
                    sourceLabel = result.sourceName,
                    totalFrames = result.totalFrames,
                    frames = result.frames,
                    errorMessage = result.error
                )
            }
        }
    }

    fun connectLiveBtSnoopSocket(host: String = "127.0.0.1", port: Int = 8872) {
        disconnectLiveSocket()
        _hciState.update {
            it.copy(
                isLiveStreaming = true,
                sourceLabel = "Connecting to btsnoop socket $host:$port...",
                errorMessage = null,
                frames = emptyList(),
                totalFrames = 0
            )
        }
        liveSocketJob = viewModelScope.launch {
            BtSnoopParser.streamLiveSocket(
                host = host,
                port = port,
                onConnected = { msg ->
                    _hciState.update { it.copy(sourceLabel = msg, errorMessage = null) }
                },
                onFrame = { frame ->
                    _hciState.update { cur ->
                        val updated = (listOf(frame) + cur.frames).take(800)
                        cur.copy(frames = updated, totalFrames = cur.totalFrames + 1)
                    }
                },
                onError = { err ->
                    _hciState.update {
                        it.copy(
                            isLiveStreaming = false,
                            errorMessage = err
                        )
                    }
                }
            )
            _hciState.update { it.copy(isLiveStreaming = false) }
        }
    }

    fun disconnectLiveSocket() {
        liveSocketJob?.cancel()
        liveSocketJob = null
        _hciState.update { it.copy(isLiveStreaming = false) }
    }

    override fun onCleared() {
        disconnectLiveSocket()
        container.bleMonitor.stopScanning()
        super.onCleared()
    }
}
