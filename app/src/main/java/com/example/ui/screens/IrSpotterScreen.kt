package com.example.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.aspectRatio
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cameraswitch
import androidx.compose.material.icons.filled.Pause
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Usb
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.R
import com.example.engine.ir.IrHotspot
import com.example.engine.ir.NearIrAnalyzer
import com.example.ui.components.MetricTile
import com.example.ui.components.PulsingStatusBadge
import com.example.ui.components.TacticalEmptyState
import com.example.ui.components.TacticalPanel
import com.example.ui.theme.AlertCrimson
import com.example.ui.theme.PhosphorCyan
import com.example.ui.theme.TacticalAmber
import com.example.ui.theme.TelemetryMonoSmall
import com.example.ui.viewmodel.IrViewModel
import java.util.concurrent.Executors

@Composable
fun IrSpotterScreen(
    viewModel: IrViewModel,
    onShowMessage: (String) -> Unit
) {
    val context = LocalContext.current
    val ui by viewModel.uiState.collectAsStateWithLifecycle()
    val settings by viewModel.settings.collectAsStateWithLifecycle()

    var hasCameraPerm by remember {
        mutableStateOf(
            ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
        )
    }

    val camPermLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { granted ->
        hasCameraPerm = granted
        if (!granted) {
            onShowMessage("Camera permission is required for Near-IR optical detection.")
        }
    }

    val frame = ui.latestFrame
    val hotspotDetected = frame.hotspots.isNotEmpty()

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item(key = "ir_header") {
            TacticalPanel(
                accentColor = if (hotspotDetected) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.ir_title),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = "850–940 nm Near-IR & Laser HUD",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    PulsingStatusBadge(
                        label = when {
                            !hasCameraPerm -> "NO CAM"
                            ui.isFrozen -> "FROZEN"
                            hotspotDetected -> "IR LOCK (${frame.hotspots.size})"
                            else -> "SCANNING"
                        },
                        color = when {
                            hotspotDetected -> MaterialTheme.colorScheme.error
                            hasCameraPerm && !ui.isFrozen -> MaterialTheme.colorScheme.primary
                            else -> MaterialTheme.colorScheme.secondary
                        },
                        isPulsing = hasCameraPerm && !ui.isFrozen
                    )
                }

                Spacer(Modifier.height(8.dp))
                Text(
                    text = "Front-facing cameras typically have weaker IR-cut filters than rear lenses. Sweep dark corners to spot violet/white near-IR security LEDs, IR blasters, and lasers.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }

        if (!hasCameraPerm) {
            item(key = "ir_perm_empty") {
                TacticalEmptyState(
                    icon = Icons.Default.Visibility,
                    title = stringResource(R.string.empty_ir_title),
                    subtitle = stringResource(R.string.empty_ir_subtitle),
                    actionLabel = stringResource(R.string.action_grant_camera),
                    actionTestTag = "grant_camera_button",
                    onAction = { camPermLauncher.launch(Manifest.permission.CAMERA) }
                )
            }
        } else {
            item(key = "ir_viewport") {
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .aspectRatio(4f / 3f)
                        .clip(RoundedCornerShape(10.dp))
                        .background(MaterialTheme.colorScheme.background)
                        .border(
                            1.5.dp,
                            if (hotspotDetected) AlertCrimson else PhosphorCyan.copy(alpha = 0.6f),
                            RoundedCornerShape(10.dp)
                        )
                ) {
                    CameraXIrPreview(
                        useFrontCamera = settings.irUseFrontCamera,
                        lumaThreshold = settings.irLuminanceThreshold,
                        chromaBiasThreshold = settings.irChromaBiasThreshold,
                        isFrozen = ui.isFrozen,
                        onFrame = { viewModel.onFrameAnalyzed(it) },
                        modifier = Modifier.fillMaxSize()
                    )

                    IrReticleHudOverlay(
                        hotspots = frame.hotspots,
                        mirrorX = settings.irUseFrontCamera,
                        modifier = Modifier.fillMaxSize()
                    )

                    Row(
                        modifier = Modifier
                            .align(Alignment.TopStart)
                            .padding(10.dp),
                        horizontalArrangement = Arrangement.spacedBy(6.dp)
                    ) {
                        PulsingStatusBadge(
                            label = if (settings.irUseFrontCamera) "FRONT CMOS (WEAK IR-CUT)" else "REAR CMOS",
                            color = PhosphorCyan,
                            isPulsing = false
                        )
                    }
                }
            }

            item(key = "ir_controls") {
                TacticalPanel {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = { viewModel.toggleCameraFacing() },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .testTag("ir_switch_camera_button")
                        ) {
                            Icon(Icons.Default.Cameraswitch, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(stringResource(R.string.action_flip_camera))
                        }

                        OutlinedButton(
                            onClick = { viewModel.toggleFreeze() },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .testTag("ir_freeze_button"),
                            border = BorderStroke(1.dp, MaterialTheme.colorScheme.secondary)
                        ) {
                            Icon(
                                if (ui.isFrozen) Icons.Default.PlayArrow else Icons.Default.Pause,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.secondary,
                                modifier = Modifier.size(18.dp)
                            )
                            Spacer(Modifier.width(6.dp))
                            Text(
                                if (ui.isFrozen) stringResource(R.string.action_resume_frame)
                                else stringResource(R.string.action_freeze_frame),
                                color = MaterialTheme.colorScheme.secondary
                            )
                        }
                    }

                    Spacer(Modifier.height(10.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        MetricTile("Ambient Y", "${frame.ambientLuma}/255", MaterialTheme.colorScheme.primary, Modifier.weight(1f))
                        MetricTile("Peak Y", "${frame.peakLuma}/255", MaterialTheme.colorScheme.secondary, Modifier.weight(1f))
                        MetricTile("Locks", frame.hotspots.size.toString(), if (hotspotDetected) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.tertiary, Modifier.weight(1f))
                    }

                    Spacer(Modifier.height(10.dp))
                    Text(
                        text = "Luminance Gate: ${settings.irLuminanceThreshold} / 255",
                        style = TelemetryMonoSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Slider(
                        value = settings.irLuminanceThreshold.toFloat(),
                        onValueChange = { viewModel.setLumaThreshold(it.toInt()) },
                        valueRange = 160f..252f
                    )

                    Text(
                        text = "Violet/Magenta Chroma Sensitivity: ${"%.2f".format(settings.irChromaBiasThreshold)}",
                        style = TelemetryMonoSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Slider(
                        value = settings.irChromaBiasThreshold,
                        onValueChange = { viewModel.setChromaBias(it) },
                        valueRange = 0.08f..0.75f
                    )
                }
            }
        }

        // USB-C External 38kHz IR Transceiver / Photodiode Sensor Status
        item(key = "usb_ir_bridge") {
            TacticalPanel {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Icon(Icons.Default.Usb, contentDescription = null, tint = MaterialTheme.colorScheme.secondary)
                        Column {
                            Text(
                                text = "USB-OTG IR Transceiver / Photodiode",
                                style = MaterialTheme.typography.titleSmall,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Text(
                                text = if (ui.usbIrDevices.isEmpty())
                                    "No USB-C IR bridge attached (needed for 38 kHz remote waveform or far-IR thermal analysis)"
                                else
                                    "${ui.usbIrDevices.size} USB serial/IR bridge(s): ${ui.usbIrDevices.joinToString { it.modelLabel }}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                    OutlinedButton(
                        onClick = { viewModel.refreshUsbIrHardware() },
                        modifier = Modifier.heightIn(min = 48.dp)
                    ) {
                        Icon(Icons.Default.Refresh, contentDescription = "Scan USB IR hardware", modifier = Modifier.size(16.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun CameraXIrPreview(
    useFrontCamera: Boolean,
    lumaThreshold: Int,
    chromaBiasThreshold: Float,
    isFrozen: Boolean,
    onFrame: (com.example.engine.ir.IrAnalysisFrame) -> Unit,
    modifier: Modifier = Modifier
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val analyzerExecutor = remember { Executors.newSingleThreadExecutor() }

    val latestLuma by rememberUpdatedState(lumaThreshold)
    val latestChroma by rememberUpdatedState(chromaBiasThreshold)
    val latestFrozen by rememberUpdatedState(isFrozen)
    val latestCallback by rememberUpdatedState(onFrame)

    val previewView = remember {
        PreviewView(context).apply {
            implementationMode = PreviewView.ImplementationMode.COMPATIBLE
            scaleType = PreviewView.ScaleType.FILL_CENTER
        }
    }

    DisposableEffect(useFrontCamera, lifecycleOwner) {
        val providerFuture = ProcessCameraProvider.getInstance(context)
        val listener = Runnable {
            runCatching {
                val cameraProvider = providerFuture.get()
                val preview = Preview.Builder().build().also {
                    it.surfaceProvider = previewView.surfaceProvider
                }
                val analysis = ImageAnalysis.Builder()
                    .setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST)
                    .setOutputImageFormat(ImageAnalysis.OUTPUT_IMAGE_FORMAT_YUV_420_888)
                    .build()
                    .also {
                        it.setAnalyzer(
                            analyzerExecutor,
                            NearIrAnalyzer(
                                getLumaThreshold = { latestLuma },
                                getChromaBiasThreshold = { latestChroma },
                                isFrozen = { latestFrozen },
                                onResult = { frame -> latestCallback(frame) }
                            )
                        )
                    }

                val preferredSelector = if (useFrontCamera) {
                    CameraSelector.DEFAULT_FRONT_CAMERA
                } else {
                    CameraSelector.DEFAULT_BACK_CAMERA
                }
                val selector = if (cameraProvider.hasCamera(preferredSelector)) {
                    preferredSelector
                } else {
                    CameraSelector.DEFAULT_BACK_CAMERA
                }
                cameraProvider.unbindAll()
                cameraProvider.bindToLifecycle(lifecycleOwner, selector, preview, analysis)
            }
        }
        providerFuture.addListener(listener, ContextCompat.getMainExecutor(context))

        onDispose {
            runCatching {
                if (providerFuture.isDone) {
                    providerFuture.get().unbindAll()
                }
            }
        }
    }

    DisposableEffect(Unit) {
        onDispose { analyzerExecutor.shutdown() }
    }

    AndroidView(factory = { previewView }, modifier = modifier)
}

@Composable
private fun IrReticleHudOverlay(
    hotspots: List<IrHotspot>,
    mirrorX: Boolean,
    modifier: Modifier = Modifier
) {
    Canvas(modifier = modifier) {
        val w = size.width
        val h = size.height
        val cx = w / 2f
        val cy = h / 2f

        // Subtle center optical crosshair
        drawLine(PhosphorCyan.copy(alpha = 0.3f), Offset(cx - 28f, cy), Offset(cx + 28f, cy), strokeWidth = 1.5f)
        drawLine(PhosphorCyan.copy(alpha = 0.3f), Offset(cx, cy - 28f), Offset(cx, cy + 28f), strokeWidth = 1.5f)

        // Corner brackets
        val b = 22f
        val pad = 16f
        val bracketColor = PhosphorCyan.copy(alpha = 0.65f)
        drawLine(bracketColor, Offset(pad, pad), Offset(pad + b, pad), 2.5f)
        drawLine(bracketColor, Offset(pad, pad), Offset(pad, pad + b), 2.5f)
        drawLine(bracketColor, Offset(w - pad, pad), Offset(w - pad - b, pad), 2.5f)
        drawLine(bracketColor, Offset(w - pad, pad), Offset(w - pad, pad + b), 2.5f)
        drawLine(bracketColor, Offset(pad, h - pad), Offset(pad + b, h - pad), 2.5f)
        drawLine(bracketColor, Offset(pad, h - pad), Offset(pad, h - pad - b), 2.5f)
        drawLine(bracketColor, Offset(w - pad, h - pad), Offset(w - pad - b, h - pad), 2.5f)
        drawLine(bracketColor, Offset(w - pad, h - pad), Offset(w - pad, h - pad - b), 2.5f)

        // Detected Near-IR Hotspot Lock Reticles
        for (spot in hotspots) {
            val sx = (if (mirrorX) 1f - spot.normX else spot.normX) * w
            val sy = spot.normY * h
            val ringColor = if (spot.chromaSignature == "NEAR_IR_VIOLET") AlertCrimson else TacticalAmber
            val radius = 18f + spot.intensityScore * 16f
            drawCircle(
                color = ringColor.copy(alpha = 0.2f),
                radius = radius,
                center = Offset(sx, sy)
            )
            drawCircle(
                color = ringColor,
                radius = radius,
                center = Offset(sx, sy),
                style = Stroke(width = 2.5f)
            )
            drawLine(ringColor, Offset(sx - radius - 8f, sy), Offset(sx - radius + 4f, sy), 2f)
            drawLine(ringColor, Offset(sx + radius - 4f, sy), Offset(sx + radius + 8f, sy), 2f)
            drawLine(ringColor, Offset(sx, sy - radius - 8f), Offset(sx, sy - radius + 4f), 2f)
            drawLine(ringColor, Offset(sx, sy + radius - 4f), Offset(sx, sy + radius + 8f), 2f)
        }
    }
}
