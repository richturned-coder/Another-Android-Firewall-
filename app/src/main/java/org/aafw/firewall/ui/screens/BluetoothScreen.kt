package org.aafw.firewall.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.material.icons.automirrored.filled.BluetoothSearching
import androidx.compose.material.icons.filled.Cable
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.Radar
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.aafw.firewall.R
import org.aafw.firewall.engine.bluetooth.BleDeviceSighting
import org.aafw.firewall.engine.bluetooth.BleThreatClass
import org.aafw.firewall.engine.bluetooth.HciPacketLayer
import org.aafw.firewall.engine.bluetooth.HciParsedFrame
import org.aafw.firewall.ui.components.KeyValueRow
import org.aafw.firewall.ui.components.MetricTile
import org.aafw.firewall.ui.components.PulsingStatusBadge
import org.aafw.firewall.ui.components.SegmentedTacticalBar
import org.aafw.firewall.ui.components.TacticalEmptyState
import org.aafw.firewall.ui.components.TacticalPanel
import org.aafw.firewall.ui.components.formatClockMillis
import org.aafw.firewall.ui.theme.TelemetryMonoMedium
import org.aafw.firewall.ui.theme.TelemetryMonoSmall
import org.aafw.firewall.ui.viewmodel.BluetoothViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun BluetoothScreen(
    viewModel: BluetoothViewModel,
    onShowMessage: (String) -> Unit
) {
    val context = LocalContext.current
    val ble by viewModel.bleSnapshot.collectAsStateWithLifecycle()
    val hci by viewModel.hciState.collectAsStateWithLifecycle()

    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    var inspectedBle by remember { mutableStateOf<BleDeviceSighting?>(null) }
    var inspectedHci by remember { mutableStateOf<HciParsedFrame?>(null) }
    var showSocketDialog by remember { mutableStateOf(false) }
    var showAdbGuide by rememberSaveable { mutableStateOf(false) }

    val requiredBlePermissions = remember {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
        } else {
            arrayOf(Manifest.permission.ACCESS_COARSE_LOCATION)
        }
    }

    val blePermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        if (results.values.all { it }) {
            viewModel.startBleScan()
        } else {
            onShowMessage("Bluetooth scan permission denied.")
        }
    }

    val hciFileLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        if (uri != null) {
            val name = uri.lastPathSegment?.substringAfterLast('/') ?: "btsnoop_hci.log"
            viewModel.importBtSnoopFile(uri, name)
        }
    }

    fun requestOrStartBle() {
        if (ble.isScanning) {
            viewModel.stopBleScan()
            return
        }
        val allGranted = requiredBlePermissions.all {
            ContextCompat.checkSelfPermission(context, it) == PackageManager.PERMISSION_GRANTED
        }
        if (allGranted) {
            viewModel.startBleScan()
        } else {
            blePermissionLauncher.launch(requiredBlePermissions)
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item(key = "bt_header") {
            TacticalPanel(
                accentColor = when {
                    ble.spamAlertActive -> MaterialTheme.colorScheme.error
                    ble.isScanning || hci.isLiveStreaming -> MaterialTheme.colorScheme.primary
                    else -> MaterialTheme.colorScheme.outlineVariant
                }
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.bt_title),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = "Passive BLE & HCI Snoop Forensics",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    PulsingStatusBadge(
                        label = when {
                            ble.spamAlertActive -> "SPAM FLOOD"
                            ble.isScanning -> "BLE LIVE"
                            hci.isLiveStreaming -> "HCI LIVE"
                            else -> "IDLE"
                        },
                        color = when {
                            ble.spamAlertActive -> MaterialTheme.colorScheme.error
                            ble.isScanning || hci.isLiveStreaming -> MaterialTheme.colorScheme.primary
                            else -> MaterialTheme.colorScheme.onSurfaceVariant
                        },
                        isPulsing = ble.isScanning || hci.isLiveStreaming || ble.spamAlertActive
                    )
                }
                Spacer(Modifier.height(10.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    MetricTile("BLE Rate", "${ble.packetsPerSecond}/s", MaterialTheme.colorScheme.primary, Modifier.weight(1f))
                    MetricTile("Trackers", ble.trackerCount.toString(), MaterialTheme.colorScheme.secondary, Modifier.weight(1f))
                    MetricTile("HCI Frames", hci.totalFrames.toString(), MaterialTheme.colorScheme.tertiary, Modifier.weight(1f))
                }
            }
        }

        item(key = "bt_tabs") {
            SegmentedTacticalBar(
                tabs = listOf(
                    stringResource(R.string.tab_ble_monitor),
                    stringResource(R.string.tab_hci_capture)
                ),
                selectedIndex = selectedTab,
                onSelect = { selectedTab = it },
                testTagPrefix = "bt"
            )
        }

        if (selectedTab == 0) {
            item(key = "ble_controls") {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Button(
                        onClick = ::requestOrStartBle,
                        modifier = Modifier
                            .weight(1f)
                            .heightIn(min = 48.dp)
                            .testTag("ble_scan_toggle_button"),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (ble.isScanning) MaterialTheme.colorScheme.errorContainer
                            else MaterialTheme.colorScheme.primary,
                            contentColor = if (ble.isScanning) MaterialTheme.colorScheme.error
                            else MaterialTheme.colorScheme.onPrimary
                        )
                    ) {
                        Icon(
                            if (ble.isScanning) Icons.Default.Stop else Icons.AutoMirrored.Filled.BluetoothSearching,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            if (ble.isScanning) stringResource(R.string.action_stop_ble)
                            else stringResource(R.string.action_start_ble)
                        )
                    }
                    IconButton(
                        onClick = { viewModel.clearBleSightings() },
                        modifier = Modifier.size(48.dp)
                    ) {
                        Icon(Icons.Default.Delete, contentDescription = "Clear BLE sightings")
                    }
                }
            }

            val spamSummary = ble.spamSummary
            if (ble.spamAlertActive && spamSummary != null) {
                item(key = "ble_spam_banner") {
                    TacticalPanel(accentColor = MaterialTheme.colorScheme.error) {
                        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Icon(Icons.Default.Warning, contentDescription = null, tint = MaterialTheme.colorScheme.error)
                            Text(
                                text = spamSummary,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error
                            )
                        }
                    }
                }
            }

            if (ble.devices.isEmpty()) {
                item(key = "empty_ble") {
                    TacticalEmptyState(
                        icon = Icons.Default.Radar,
                        title = stringResource(R.string.empty_ble_title),
                        subtitle = ble.statusMessage.ifBlank { stringResource(R.string.empty_ble_subtitle) },
                        actionLabel = if (!ble.isScanning) stringResource(R.string.action_start_ble) else null,
                        onAction = if (!ble.isScanning) ::requestOrStartBle else null
                    )
                }
            } else {
                items(ble.devices, key = { it.address }) { dev ->
                    BleDeviceCard(device = dev, onClick = { inspectedBle = dev })
                }
            }
        } else {
            // TAB 1: HCI Snoop Capture (Shizuku / ADB Live Socket + btsnoop_hci.log / Bugreport ZIP Parser)
            item(key = "hci_controls") {
                TacticalPanel(accentColor = MaterialTheme.colorScheme.secondary) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Shizuku: ${if (hci.shizukuInstalled) "INSTALLED" else "NOT DETECTED"} • API ${hci.androidApiLevel}",
                            style = TelemetryMonoSmall,
                            color = if (hci.shizukuInstalled) MaterialTheme.colorScheme.tertiary
                            else MaterialTheme.colorScheme.secondary
                        )
                        TextButton(onClick = { showAdbGuide = !showAdbGuide }) {
                            Icon(Icons.Default.Terminal, contentDescription = null, modifier = Modifier.size(16.dp))
                            Spacer(Modifier.width(4.dp))
                            Text(if (showAdbGuide) "Hide ADB" else "ADB/Shizuku")
                        }
                    }

                    if (showAdbGuide) {
                        Spacer(Modifier.height(6.dp))
                        Box(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(6.dp))
                                .background(MaterialTheme.colorScheme.background)
                                .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(6.dp))
                                .padding(10.dp)
                        ) {
                            Text(
                                text = "1. Developer Options -> Enable Bluetooth HCI snoop log\n" +
                                    "   (Android 17+: also toggle 'HCI snoop log socket')\n" +
                                    "2. Live ADB/Shizuku Socket Forward:\n" +
                                    "   adb forward tcp:8872 localabstract:btsnoop\n" +
                                    "3. Or Extract Bugreport Archive:\n" +
                                    "   adb bugreport bt_dump.zip -> Import below",
                                style = TelemetryMonoSmall,
                                color = MaterialTheme.colorScheme.primary
                            )
                        }
                    }

                    Spacer(Modifier.height(10.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = {
                                if (hci.isLiveStreaming) viewModel.disconnectLiveSocket()
                                else showSocketDialog = true
                            },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .testTag("hci_socket_button"),
                            colors = ButtonDefaults.buttonColors(
                                containerColor = if (hci.isLiveStreaming) MaterialTheme.colorScheme.errorContainer
                                else MaterialTheme.colorScheme.primary,
                                contentColor = if (hci.isLiveStreaming) MaterialTheme.colorScheme.error
                                else MaterialTheme.colorScheme.onPrimary
                            )
                        ) {
                            Icon(Icons.Default.Cable, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(
                                if (hci.isLiveStreaming) "Disconnect"
                                else stringResource(R.string.action_connect_btsnoop_socket),
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }

                        OutlinedButton(
                            onClick = { hciFileLauncher.launch(arrayOf("*/*")) },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .testTag("hci_import_file_button"),
                            border = BorderStroke(1.dp, MaterialTheme.colorScheme.secondary)
                        ) {
                            Icon(Icons.Default.FileOpen, contentDescription = null, tint = MaterialTheme.colorScheme.secondary, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text("Import Log/.zip", color = MaterialTheme.colorScheme.secondary)
                        }
                    }

                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = hci.sourceLabel,
                        style = TelemetryMonoSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    hci.errorMessage?.let { err ->
                        Spacer(Modifier.height(4.dp))
                        Text(text = err, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                }
            }

            item(key = "hci_layer_filters") {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    FilterChip(
                        selected = hci.selectedLayer == null,
                        onClick = { viewModel.setHciLayerFilter(null) },
                        label = { Text("ALL") }
                    )
                    listOf(
                        HciPacketLayer.ATT_GATT,
                        HciPacketLayer.L2CAP,
                        HciPacketLayer.HCI_CMD,
                        HciPacketLayer.HCI_EVT,
                        HciPacketLayer.SMP
                    ).forEach { layer ->
                        FilterChip(
                            selected = hci.selectedLayer == layer,
                            onClick = { viewModel.setHciLayerFilter(layer) },
                            label = { Text(layer.label) }
                        )
                    }
                }
            }

            val filteredHci = if (hci.selectedLayer == null) hci.frames
            else hci.frames.filter { it.layer == hci.selectedLayer }

            if (filteredHci.isEmpty()) {
                item(key = "empty_hci") {
                    TacticalEmptyState(
                        icon = Icons.Default.Cable,
                        title = stringResource(R.string.empty_hci_title),
                        subtitle = stringResource(R.string.empty_hci_subtitle),
                        actionLabel = stringResource(R.string.action_import_btsnoop),
                        onAction = { hciFileLauncher.launch(arrayOf("*/*")) }
                    )
                }
            } else {
                items(filteredHci, key = { "${it.index}_${it.timestampMillis}" }) { frame ->
                    HciFrameCard(frame = frame, onClick = { inspectedHci = frame })
                }
            }
        }
    }

    inspectedBle?.let { dev ->
        ModalBottomSheet(
            onDismissRequest = { inspectedBle = null },
            containerColor = MaterialTheme.colorScheme.surface
        ) {
            Column(modifier = Modifier.padding(horizontal = 18.dp, vertical = 10.dp)) {
                Text(dev.vendorTag, style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.height(8.dp))
                KeyValueRow("MAC Address", dev.address)
                KeyValueRow("Name", dev.name ?: "(Advertised Anonymous)")
                KeyValueRow("RSSI", "${dev.rssi} dBm (Trend: ${dev.rssiHistory.joinToString(",")})")
                KeyValueRow("Persistence", "${dev.persistenceSeconds}s (${dev.packetCount} adv frames)")
                KeyValueRow("Assessment", dev.threatNote, MaterialTheme.colorScheme.secondary)
                Spacer(Modifier.height(10.dp))
                Text("RAW BLE AD RECORD HEX", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(4.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(6.dp))
                        .background(MaterialTheme.colorScheme.background)
                        .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(6.dp))
                        .padding(10.dp)
                ) {
                    Text(dev.rawAdvHex.ifBlank { "(Empty AD payload)" }, style = TelemetryMonoSmall, color = MaterialTheme.colorScheme.primary)
                }
                Spacer(Modifier.height(22.dp))
            }
        }
    }

    inspectedHci?.let { frame ->
        ModalBottomSheet(
            onDismissRequest = { inspectedHci = null },
            containerColor = MaterialTheme.colorScheme.surface
        ) {
            Column(modifier = Modifier.padding(horizontal = 18.dp, vertical = 10.dp)) {
                Text("${frame.layer.label} FRAME #${frame.index}", style = MaterialTheme.typography.titleMedium, color = MaterialTheme.colorScheme.primary)
                Spacer(Modifier.height(8.dp))
                KeyValueRow("Summary", frame.summary, MaterialTheme.colorScheme.secondary)
                KeyValueRow("Direction", frame.direction)
                KeyValueRow("Timestamp", formatClockMillis(frame.timestampMillis))
                KeyValueRow("Decoded Headers", frame.detail)
                KeyValueRow("Length", "${frame.byteLength} bytes")
                Spacer(Modifier.height(10.dp))
                Text("RAW HCI / L2CAP / ATT HEX", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Spacer(Modifier.height(4.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(6.dp))
                        .background(MaterialTheme.colorScheme.background)
                        .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(6.dp))
                        .padding(10.dp)
                ) {
                    Text(frame.rawHex, style = TelemetryMonoSmall, color = MaterialTheme.colorScheme.primary)
                }
                Spacer(Modifier.height(22.dp))
            }
        }
    }

    if (showSocketDialog) {
        var host by remember { mutableStateOf("127.0.0.1") }
        var port by remember { mutableStateOf("8872") }
        AlertDialog(
            onDismissRequest = { showSocketDialog = false },
            containerColor = MaterialTheme.colorScheme.surface,
            title = { Text("Connect Live BTSnoop Socket") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    Text(
                        text = "Connects to local ADB/Shizuku-forwarded btsnoop TCP stream (Android 17+ HCI snoop socket or `adb forward tcp:8872 localabstract:btsnoop`).",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    OutlinedTextField(value = host, onValueChange = { host = it }, label = { Text("Host") }, singleLine = true)
                    OutlinedTextField(value = port, onValueChange = { port = it }, label = { Text("Port") }, singleLine = true)
                }
            },
            confirmButton = {
                Button(onClick = {
                    val p = port.toIntOrNull() ?: 8872
                    viewModel.connectLiveBtSnoopSocket(host.trim().ifEmpty { "127.0.0.1" }, p)
                    showSocketDialog = false
                }) { Text("Connect") }
            },
            dismissButton = {
                TextButton(onClick = { showSocketDialog = false }) { Text("Cancel") }
            }
        )
    }
}

@Composable
private fun BleDeviceCard(device: BleDeviceSighting, onClick: () -> Unit) {
    val accent = when (device.threatClass) {
        BleThreatClass.BLE_SPAM_FLOOD, BleThreatClass.TRACKER_PERSISTENT -> MaterialTheme.colorScheme.error
        BleThreatClass.TRACKER_WATCH -> MaterialTheme.colorScheme.secondary
        BleThreatClass.NORMAL -> null
    }
    TacticalPanel(
        modifier = Modifier.clickable(onClick = onClick),
        accentColor = accent
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = device.name?.let { "$it • ${device.vendorTag}" } ?: device.vendorTag,
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "${device.address} • ${device.packetCount} adv • ${device.persistenceSeconds}s",
                    style = TelemetryMonoSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Text(
                text = "${device.rssi} dBm",
                style = TelemetryMonoMedium,
                color = if (device.rssi > -60) MaterialTheme.colorScheme.secondary else MaterialTheme.colorScheme.primary
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(
            text = device.threatNote,
            style = MaterialTheme.typography.bodySmall,
            color = accent ?: MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun HciFrameCard(frame: HciParsedFrame, onClick: () -> Unit) {
    val accent = when (frame.layer) {
        HciPacketLayer.ATT_GATT -> MaterialTheme.colorScheme.primary
        HciPacketLayer.SMP -> MaterialTheme.colorScheme.error
        HciPacketLayer.L2CAP -> MaterialTheme.colorScheme.secondary
        else -> null
    }
    TacticalPanel(
        modifier = Modifier.clickable(onClick = onClick),
        accentColor = accent
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "#${frame.index}",
                    style = TelemetryMonoSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Text(
                    text = frame.layer.label,
                    style = MaterialTheme.typography.labelSmall,
                    color = accent ?: MaterialTheme.colorScheme.tertiary
                )
                Text(
                    text = frame.direction,
                    style = TelemetryMonoSmall,
                    color = MaterialTheme.colorScheme.secondary
                )
            }
            Text(text = "${frame.byteLength}B", style = TelemetryMonoSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.height(3.dp))
        Text(text = frame.summary, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurface)
        Text(text = frame.detail, style = TelemetryMonoSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
