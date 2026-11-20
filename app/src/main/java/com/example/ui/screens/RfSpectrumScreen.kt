package com.example.ui.screens

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.GraphicEq
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Sensors
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Usb
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.R
import com.example.data.local.RfAllocationEntity
import com.example.engine.rf.DetectedRfPeak
import com.example.engine.rf.DetectedUsbHardware
import com.example.engine.rf.SpectrumFrame
import com.example.ui.components.MetricTile
import com.example.ui.components.PulsingStatusBadge
import com.example.ui.components.TacticalEmptyState
import com.example.ui.components.TacticalPanel
import com.example.ui.theme.AlertCrimson
import com.example.ui.theme.HairlineBorder
import com.example.ui.theme.ObsidianBlack
import com.example.ui.theme.PhosphorCyan
import com.example.ui.theme.TacticalAmber
import com.example.ui.theme.TelemetryMonoLarge
import com.example.ui.theme.TelemetryMonoMedium
import com.example.ui.theme.TelemetryMonoSmall
import com.example.ui.viewmodel.RfViewModel

private val rfPresets = listOf(
    "315 ISM" to 315.0,
    "433.92 ISM" to 433.92,
    "868 SRD" to 868.3,
    "915 ISM" to 915.0,
    "162.55 NOAA" to 162.55,
    "1090 ADS-B" to 1090.0,
    "100.1 FM" to 100.1
)

@Composable
fun RfSpectrumScreen(
    viewModel: RfViewModel
) {
    val ui by viewModel.uiState.collectAsStateWithLifecycle()
    val settings by viewModel.settings.collectAsStateWithLifecycle()
    val allocations by viewModel.allocations.collectAsStateWithLifecycle()

    val cu8Launcher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            val name = uri.lastPathSegment?.substringAfterLast('/') ?: "capture.cu8"
            viewModel.loadCu8Capture(uri, name)
        }
    }

    val spectrum = ui.latestSpectrum

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Header & Hardware Actions
        item(key = "rf_header") {
            TacticalPanel(
                accentColor = if (ui.isStreaming) MaterialTheme.colorScheme.primary
                else MaterialTheme.colorScheme.secondary
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.rf_title),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = "${"%.3f".format(settings.rfCenterFreqMhz)} MHz",
                            style = TelemetryMonoLarge,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    PulsingStatusBadge(
                        label = if (ui.isStreaming) "FFT LIVE" else "STANDBY",
                        color = if (ui.isStreaming) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
                        isPulsing = ui.isStreaming
                    )
                }

                Spacer(Modifier.height(6.dp))
                Text(
                    text = ui.activeSourceLabel,
                    style = TelemetryMonoSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Spacer(Modifier.height(10.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(
                        onClick = { viewModel.scanUsbDevices() },
                        modifier = Modifier
                            .weight(1f)
                            .heightIn(min = 48.dp)
                            .testTag("rf_scan_usb_button"),
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary)
                    ) {
                        Icon(Icons.Default.Refresh, contentDescription = null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(stringResource(R.string.action_scan_usb), color = MaterialTheme.colorScheme.primary)
                    }

                    if (ui.isStreaming) {
                        Button(
                            onClick = { viewModel.stopStream() },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .testTag("rf_stop_button"),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = MaterialTheme.colorScheme.errorContainer,
                                contentColor = MaterialTheme.colorScheme.error
                            )
                        ) {
                            Icon(Icons.Default.Stop, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(stringResource(R.string.action_stop_sdr))
                        }
                    } else {
                        Button(
                            onClick = { cu8Launcher.launch(arrayOf("*/*")) },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .testTag("rf_load_cu8_button")
                        ) {
                            Icon(Icons.Default.FileOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(stringResource(R.string.action_load_cu8))
                        }
                    }
                }

                Spacer(Modifier.height(10.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    rfPresets.forEach { (label, freq) ->
                        FilterChip(
                            selected = kotlin.math.abs(settings.rfCenterFreqMhz - freq) < 0.05,
                            onClick = { viewModel.tuneCenterFreq(freq) },
                            label = { Text(label, style = MaterialTheme.typography.labelSmall) }
                        )
                    }
                }
            }
        }

        // Dual FFT + Waterfall Oscilloscope Canvas
        item(key = "rf_oscilloscope") {
            TacticalPanel(accentColor = MaterialTheme.colorScheme.primary) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "RADIX-2 FFT (1024-PT) & WATERFALL",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        text = "Span: ${"%.2f".format(settings.rfSampleRateHz / 1_000_000.0)} MHz",
                        style = TelemetryMonoSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Spacer(Modifier.height(8.dp))
                SpectrumAndWaterfallCanvas(
                    spectrum = spectrum,
                    waterfallRows = ui.waterfallHistory,
                    peakThresholdDb = settings.rfPeakThresholdDb,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(230.dp)
                        .clip(RoundedCornerShape(6.dp))
                        .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(6.dp))
                )
                Spacer(Modifier.height(10.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    MetricTile(
                        label = "Noise Floor",
                        value = spectrum?.let { "${"%.1f".format(it.noiseFloorDb)} dB" } ?: "-- dB",
                        accent = MaterialTheme.colorScheme.secondary,
                        modifier = Modifier.weight(1f)
                    )
                    MetricTile(
                        label = "Peak Power",
                        value = spectrum?.let { "${"%.1f".format(it.peakPowerDb)} dB" } ?: "-- dB",
                        accent = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.weight(1f)
                    )
                    MetricTile(
                        label = "Signals",
                        value = (spectrum?.peaks?.size ?: 0).toString(),
                        accent = MaterialTheme.colorScheme.tertiary,
                        modifier = Modifier.weight(1f)
                    )
                }

                Spacer(Modifier.height(8.dp))
                Text(
                    text = "Peak SNR Detection Threshold: +${"%.0f".format(settings.rfPeakThresholdDb)} dB above floor",
                    style = TelemetryMonoSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Slider(
                    value = settings.rfPeakThresholdDb,
                    onValueChange = { viewModel.setPeakThresholdDb(it) },
                    valueRange = 4f..28f
                )

                spectrum?.ookPulseSummary?.let { ook ->
                    Spacer(Modifier.height(6.dp))
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .clip(RoundedCornerShape(6.dp))
                            .background(MaterialTheme.colorScheme.secondaryContainer)
                            .padding(10.dp)
                    ) {
                        Text(
                            text = ook,
                            style = TelemetryMonoSmall,
                            color = MaterialTheme.colorScheme.secondary
                        )
                    }
                }
            }
        }

        // Attached USB-OTG Hardware Devices
        item(key = "usb_hardware_section") {
            Text(
                text = "ATTACHED USB-OTG HARDWARE (${ui.usbDevices.size})",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        if (ui.usbDevices.isEmpty()) {
            item(key = "empty_usb") {
                TacticalEmptyState(
                    icon = Icons.Default.Usb,
                    title = stringResource(R.string.empty_rf_title),
                    subtitle = stringResource(R.string.empty_rf_subtitle),
                    actionLabel = stringResource(R.string.action_load_cu8),
                    onAction = { cu8Launcher.launch(arrayOf("*/*")) }
                )
            }
        } else {
            items(ui.usbDevices, key = { it.deviceName }) { hw ->
                UsbHardwareCard(
                    hw = hw,
                    onRequestPerm = { viewModel.requestUsbPermission(hw) },
                    onStream = { viewModel.startUsbSdrStream(hw) }
                )
            }
        }

        // Detected Signal Peaks
        if (spectrum != null && spectrum.peaks.isNotEmpty()) {
            item(key = "peaks_header") {
                Text(
                    text = "IDENTIFIED SIGNAL PEAKS (${spectrum.peaks.size})",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.secondary
                )
            }
            items(spectrum.peaks, key = { "${it.frequencyMhz}_${it.powerDb}" }) { peak ->
                DetectedPeakCard(peak = peak)
            }
        }

        // On-Device ITU/FCC RF Frequency Allocation Table
        item(key = "rf_db_header") {
            Text(
                text = "ON-DEVICE RF ALLOCATION DATABASE (${allocations.size} BANDS)",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary
            )
        }
        items(allocations, key = { it.id }) { band ->
            RfAllocationRow(band = band, onTune = { viewModel.tuneCenterFreq((band.startFreqMhz + band.endFreqMhz) / 2.0) })
        }
    }
}

@Composable
private fun SpectrumAndWaterfallCanvas(
    spectrum: SpectrumFrame?,
    waterfallRows: List<FloatArray>,
    peakThresholdDb: Float,
    modifier: Modifier = Modifier
) {
    Canvas(modifier = modifier.background(ObsidianBlack)) {
        val w = size.width
        val h = size.height
        val fftH = h * 0.56f
        val wfTop = fftH + 4f
        val wfH = (h - wfTop).coerceAtLeast(10f)

        // Precision oscilloscope grid
        for (i in 1..3) {
            val y = fftH * i / 4f
            drawLine(HairlineBorder, Offset(0f, y), Offset(w, y), strokeWidth = 1f)
        }
        for (i in 1..7) {
            val x = w * i / 8f
            drawLine(HairlineBorder, Offset(x, 0f), Offset(x, fftH), strokeWidth = 1f)
        }

        if (spectrum != null && spectrum.binsDb.isNotEmpty()) {
            val bins = spectrum.binsDb
            val minDb = -105f
            val maxDb = -5f
            fun dbToY(db: Float): Float {
                val norm = ((db - minDb) / (maxDb - minDb)).coerceIn(0f, 1f)
                return fftH - norm * (fftH - 12f) - 4f
            }

            // Noise floor + threshold lines
            val floorY = dbToY(spectrum.noiseFloorDb)
            val threshY = dbToY(spectrum.noiseFloorDb + peakThresholdDb)
            drawLine(
                color = TacticalAmber.copy(alpha = 0.45f),
                start = Offset(0f, floorY),
                end = Offset(w, floorY),
                strokeWidth = 1.5f
            )
            drawLine(
                color = AlertCrimson.copy(alpha = 0.4f),
                start = Offset(0f, threshY),
                end = Offset(w, threshY),
                strokeWidth = 1f
            )

            // FFT Trace + gradient fill
            val step = maxOf(1, bins.size / 256)
            val tracePath = Path()
            val fillPath = Path()
            var first = true
            var xIdx = 0
            while (xIdx < bins.size) {
                val x = (xIdx.toFloat() / (bins.size - 1)) * w
                val y = dbToY(bins[xIdx])
                if (first) {
                    tracePath.moveTo(x, y)
                    fillPath.moveTo(x, fftH)
                    fillPath.lineTo(x, y)
                    first = false
                } else {
                    tracePath.lineTo(x, y)
                    fillPath.lineTo(x, y)
                }
                xIdx += step
            }
            fillPath.lineTo(w, fftH)
            fillPath.close()

            drawPath(
                path = fillPath,
                brush = Brush.verticalGradient(
                    colors = listOf(PhosphorCyan.copy(alpha = 0.28f), Color.Transparent),
                    startY = 0f,
                    endY = fftH
                )
            )
            drawPath(
                path = tracePath,
                color = PhosphorCyan,
                style = Stroke(width = 2.2f, cap = StrokeCap.Round)
            )
        } else {
            // Center baseline when idle
            drawLine(
                color = PhosphorCyan.copy(alpha = 0.35f),
                start = Offset(0f, fftH * 0.78f),
                end = Offset(w, fftH * 0.78f),
                strokeWidth = 1.5f
            )
        }

        // Divider between FFT & Waterfall
        drawLine(PhosphorCyan.copy(alpha = 0.35f), Offset(0f, fftH + 2f), Offset(w, fftH + 2f), strokeWidth = 1.5f)

        // Scrolling Waterfall Spectrogram
        if (waterfallRows.isNotEmpty()) {
            val rowH = wfH / 48f
            waterfallRows.forEachIndexed { rowIdx, rowBins ->
                val y = wfTop + rowIdx * rowH
                if (y > h) return@forEachIndexed
                val colW = w / rowBins.size.toFloat()
                for (c in rowBins.indices) {
                    val norm = ((rowBins[c] + 100f) / 85f).coerceIn(0f, 1f)
                    val color = when {
                        norm < 0.25f -> Color(0xFF05070A).copy(alpha = 1f)
                        norm < 0.55f -> PhosphorCyan.copy(alpha = (norm - 0.2f) * 1.4f)
                        norm < 0.80f -> TacticalAmber.copy(alpha = 0.85f)
                        else -> AlertCrimson
                    }
                    drawRect(
                        color = color,
                        topLeft = Offset(c * colW, y),
                        size = Size(colW + 0.5f, rowH + 0.5f)
                    )
                }
            }
        }
    }
}

@Composable
private fun UsbHardwareCard(
    hw: DetectedUsbHardware,
    onRequestPerm: () -> Unit,
    onStream: () -> Unit
) {
    TacticalPanel(accentColor = if (hw.isSupportedSdr) MaterialTheme.colorScheme.tertiary else null) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = hw.modelLabel, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    text = "VID:PID ${"%04X:%04X".format(hw.vendorId, hw.productId)} • ${hw.deviceName}",
                    style = TelemetryMonoSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            if (hw.isSupportedSdr) {
                Button(
                    onClick = if (hw.hasPermission) onStream else onRequestPerm,
                    modifier = Modifier.heightIn(min = 48.dp)
                ) {
                    Icon(Icons.Default.PlayArrow, contentDescription = null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(4.dp))
                    Text(if (hw.hasPermission) "Stream" else "Grant USB")
                }
            }
        }
    }
}

@Composable
private fun DetectedPeakCard(peak: DetectedRfPeak) {
    TacticalPanel(accentColor = MaterialTheme.colorScheme.secondary) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Icon(Icons.Default.GraphicEq, contentDescription = null, tint = MaterialTheme.colorScheme.secondary, modifier = Modifier.size(18.dp))
                Text(
                    text = "${"%.4f".format(peak.frequencyMhz)} MHz",
                    style = TelemetryMonoMedium,
                    color = MaterialTheme.colorScheme.primary
                )
            }
            Text(
                text = "SNR +${"%.1f".format(peak.snrDb)} dB • BW ${"%.1f".format(peak.bandwidthKhz)} kHz",
                style = TelemetryMonoSmall,
                color = MaterialTheme.colorScheme.secondary
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(text = "${peak.bandLabel} — ${peak.estimatedModulation}", style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurface)
        Text(text = peak.protocolHint, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

@Composable
private fun RfAllocationRow(band: RfAllocationEntity, onTune: () -> Unit) {
    TacticalPanel {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = "${band.bandName} (${band.startFreqMhz}–${band.endFreqMhz} MHz)",
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = "${band.commonProtocols} • ${band.typicalModulation}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Spacer(Modifier.width(8.dp))
            OutlinedButton(
                onClick = onTune,
                modifier = Modifier.heightIn(min = 48.dp)
            ) {
                Icon(Icons.Default.Sensors, contentDescription = "Tune to ${band.bandName}", modifier = Modifier.size(16.dp))
                Spacer(Modifier.width(4.dp))
                Text("Tune")
            }
        }
    }
}
