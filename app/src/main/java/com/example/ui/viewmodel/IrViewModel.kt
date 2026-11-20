package com.example.ui.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.AppContainer
import com.example.data.local.AppSettings
import com.example.engine.ir.IrAnalysisFrame
import com.example.engine.rf.DetectedUsbHardware
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

data class IrUiState(
    val latestFrame: IrAnalysisFrame = IrAnalysisFrame(),
    val isFrozen: Boolean = false,
    val totalDetections: Int = 0,
    val usbIrDevices: List<DetectedUsbHardware> = emptyList()
)

class IrViewModel(
    application: Application,
    private val container: AppContainer
) : AndroidViewModel(application) {

    val settings: StateFlow<AppSettings> = container.preferences.settingsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), AppSettings())

    private val _uiState = MutableStateFlow(IrUiState())
    val uiState: StateFlow<IrUiState> = _uiState.asStateFlow()

    init {
        refreshUsbIrHardware()
    }

    fun onFrameAnalyzed(frame: IrAnalysisFrame) {
        if (_uiState.value.isFrozen) return
        _uiState.update { cur ->
            cur.copy(
                latestFrame = frame,
                totalDetections = if (frame.hotspots.isNotEmpty()) cur.totalDetections + 1 else cur.totalDetections
            )
        }
    }

    fun toggleFreeze() {
        _uiState.update { it.copy(isFrozen = !it.isFrozen) }
    }

    fun toggleCameraFacing() {
        viewModelScope.launch(Dispatchers.IO) {
            container.preferences.updateIrSettings(useFrontCamera = !settings.value.irUseFrontCamera)
        }
    }

    fun setLumaThreshold(value: Int) {
        viewModelScope.launch(Dispatchers.IO) {
            container.preferences.updateIrSettings(lumaThreshold = value.coerceIn(150, 252))
        }
    }

    fun setChromaBias(value: Float) {
        viewModelScope.launch(Dispatchers.IO) {
            container.preferences.updateIrSettings(chromaBias = value.coerceIn(0.05f, 0.85f))
        }
    }

    fun refreshUsbIrHardware() {
        viewModelScope.launch(Dispatchers.IO) {
            val irBridges = container.usbSdrManager.enumerateDevices().filter { it.isIrSerialBridge }
            _uiState.update { it.copy(usbIrDevices = irBridges) }
        }
    }
}
