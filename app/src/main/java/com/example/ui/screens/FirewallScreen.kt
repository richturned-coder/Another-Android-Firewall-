package com.example.ui.screens

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Block
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Download
import androidx.compose.material.icons.filled.FiberManualRecord
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.Stop
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
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.example.R
import com.example.data.local.CaptureSessionEntity
import com.example.data.local.FirewallRuleEntity
import com.example.data.local.RuleAction
import com.example.data.local.RuleType
import com.example.ui.components.KeyValueRow
import com.example.ui.components.MetricTile
import com.example.ui.components.PulsingStatusBadge
import com.example.ui.components.SegmentedTacticalBar
import com.example.ui.components.TacticalEmptyState
import com.example.ui.components.TacticalPanel
import com.example.ui.components.formatBytesCompact
import com.example.ui.components.formatClockMillis
import com.example.ui.theme.TelemetryMonoMedium
import com.example.ui.theme.TelemetryMonoSmall
import com.example.ui.viewmodel.FirewallViewModel
import com.example.ui.viewmodel.InstalledAppEntry
import com.example.vpn.FirewallVpnService
import com.example.vpn.LivePacketEvent
import com.example.vpn.VpnEngineState

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FirewallScreen(
    viewModel: FirewallViewModel,
    onShowMessage: (String) -> Unit
) {
    val context = LocalContext.current
    val vpnState by viewModel.vpnState.collectAsStateWithLifecycle()
    val vpnError by viewModel.vpnError.collectAsStateWithLifecycle()
    val counters by viewModel.counters.collectAsStateWithLifecycle()
    val livePackets by viewModel.livePackets.collectAsStateWithLifecycle()
    val pcapStats by viewModel.pcapStats.collectAsStateWithLifecycle()
    val allRules by viewModel.allRules.collectAsStateWithLifecycle()
    val installedApps by viewModel.installedApps.collectAsStateWithLifecycle()
    val captureSessions by viewModel.captureSessions.collectAsStateWithLifecycle()
    val settings by viewModel.settings.collectAsStateWithLifecycle()
    val toastMsg by viewModel.toastMessage.collectAsStateWithLifecycle()

    LaunchedEffect(toastMsg) {
        toastMsg?.let {
            onShowMessage(it)
            viewModel.consumeToast()
        }
    }

    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    LaunchedEffect(selectedTab) {
        if (selectedTab == 1) {
            viewModel.ensureInstalledAppsLoaded()
        }
    }
    var searchQuery by rememberSaveable { mutableStateOf("") }
    var selectedPacket by remember { mutableStateOf<LivePacketEvent?>(null) }
    var showAddRuleDialog by remember { mutableStateOf(false) }
    var pendingExportSession by remember { mutableStateOf<CaptureSessionEntity?>(null) }

    val vpnConsentLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val intent = Intent(context, FirewallVpnService::class.java).apply {
                action = FirewallVpnService.ACTION_START
            }
            ContextCompat.startForegroundService(context, intent)
        } else {
            onShowMessage("VPN permission denied by user.")
        }
    }

    val exportPcapLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/vnd.tcpdump.pcap")
    ) { uri ->
        val session = pendingExportSession
        pendingExportSession = null
        if (uri != null && session != null) {
            viewModel.exportCaptureToUri(session, uri)
        }
    }

    fun toggleVpnShield() {
        if (vpnState == VpnEngineState.RUNNING || vpnState == VpnEngineState.STARTING) {
            val stopIntent = Intent(context, FirewallVpnService::class.java).apply {
                action = FirewallVpnService.ACTION_STOP
            }
            context.startService(stopIntent)
        } else {
            val prepareIntent = VpnService.prepare(context)
            if (prepareIntent != null) {
                vpnConsentLauncher.launch(prepareIntent)
            } else {
                val startIntent = Intent(context, FirewallVpnService::class.java).apply {
                    action = FirewallVpnService.ACTION_START
                }
                ContextCompat.startForegroundService(context, startIntent)
            }
        }
    }

    fun togglePcapRecording() {
        if (vpnState != VpnEngineState.RUNNING) {
            onShowMessage("Arm the VPN firewall first to record simultaneous PCAPNG.")
            return
        }
        val action = if (pcapStats.isRecording) {
            FirewallVpnService.ACTION_STOP_PCAP
        } else {
            FirewallVpnService.ACTION_START_PCAP
        }
        context.startService(Intent(context, FirewallVpnService::class.java).apply {
            this.action = action
        })
    }

    val appRuleByUid = remember(allRules) {
        allRules
            .filter { it.ruleType == RuleType.APP_UID.name && it.enabled }
            .associateBy { it.targetValue.toIntOrNull() ?: -1 }
    }
    val customRules = remember(allRules) {
        allRules.filter { it.ruleType != RuleType.APP_UID.name }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // Master Tactical Shield Panel
        item(key = "shield_header") {
            val isArmed = vpnState == VpnEngineState.RUNNING
            val statusColor = when (vpnState) {
                VpnEngineState.RUNNING -> MaterialTheme.colorScheme.primary
                VpnEngineState.STARTING -> MaterialTheme.colorScheme.secondary
                VpnEngineState.ERROR -> MaterialTheme.colorScheme.error
                VpnEngineState.STOPPED -> MaterialTheme.colorScheme.onSurfaceVariant
            }
            TacticalPanel(accentColor = statusColor) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.firewall_title),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.primary
                        )
                        Text(
                            text = stringResource(R.string.app_name),
                            style = MaterialTheme.typography.headlineSmall,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    PulsingStatusBadge(
                        label = when (vpnState) {
                            VpnEngineState.RUNNING -> stringResource(R.string.vpn_status_armed)
                            VpnEngineState.STARTING -> stringResource(R.string.vpn_status_starting)
                            VpnEngineState.ERROR -> "FAULT"
                            VpnEngineState.STOPPED -> stringResource(R.string.vpn_status_standby)
                        },
                        color = statusColor,
                        isPulsing = isArmed || vpnState == VpnEngineState.STARTING
                    )
                }

                vpnError?.let { err ->
                    Spacer(Modifier.height(8.dp))
                    Text(
                        text = err,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error
                    )
                }

                Spacer(Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Button(
                        onClick = ::toggleVpnShield,
                        modifier = Modifier
                            .weight(1.35f)
                            .heightIn(min = 48.dp)
                            .testTag("vpn_toggle_button"),
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (isArmed) MaterialTheme.colorScheme.errorContainer
                            else MaterialTheme.colorScheme.primary,
                            contentColor = if (isArmed) MaterialTheme.colorScheme.error
                            else MaterialTheme.colorScheme.onPrimary
                        )
                    ) {
                        Icon(
                            imageVector = if (isArmed) Icons.Default.Stop else Icons.Default.Shield,
                            contentDescription = stringResource(R.string.cd_vpn_shield),
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(Modifier.width(8.dp))
                        Text(
                            text = if (isArmed) stringResource(R.string.action_disarm_vpn)
                            else stringResource(R.string.action_arm_vpn)
                        )
                    }

                    OutlinedButton(
                        onClick = ::togglePcapRecording,
                        modifier = Modifier
                            .weight(1f)
                            .heightIn(min = 48.dp)
                            .testTag("pcap_toggle_button"),
                        border = BorderStroke(
                            1.dp,
                            if (pcapStats.isRecording) MaterialTheme.colorScheme.error
                            else MaterialTheme.colorScheme.secondary
                        )
                    ) {
                        Icon(
                            imageVector = Icons.Default.FiberManualRecord,
                            contentDescription = stringResource(R.string.cd_pcap_record),
                            tint = if (pcapStats.isRecording) MaterialTheme.colorScheme.error
                            else MaterialTheme.colorScheme.secondary,
                            modifier = Modifier.size(14.dp)
                        )
                        Spacer(Modifier.width(6.dp))
                        Text(
                            text = if (pcapStats.isRecording) "STOP PCAP" else "PCAPNG",
                            color = if (pcapStats.isRecording) MaterialTheme.colorScheme.error
                            else MaterialTheme.colorScheme.secondary
                        )
                    }
                }

                Spacer(Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    MetricTile(
                        label = "Packets",
                        value = counters.totalPackets.toString(),
                        accent = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.weight(1f)
                    )
                    MetricTile(
                        label = "Blocked",
                        value = counters.blockedPackets.toString(),
                        accent = MaterialTheme.colorScheme.error,
                        modifier = Modifier.weight(1f)
                    )
                    MetricTile(
                        label = "Volume",
                        value = formatBytesCompact(counters.totalBytes),
                        accent = MaterialTheme.colorScheme.tertiary,
                        modifier = Modifier.weight(1f)
                    )
                }
            }
        }

        // Sub-tab Navigation
        item(key = "firewall_subtabs") {
            SegmentedTacticalBar(
                tabs = listOf(
                    stringResource(R.string.tab_live_stream),
                    stringResource(R.string.tab_app_rules),
                    stringResource(R.string.tab_custom_rules),
                    stringResource(R.string.tab_captures)
                ),
                selectedIndex = selectedTab,
                onSelect = { selectedTab = it },
                testTagPrefix = "firewall"
            )
        }

        when (selectedTab) {
            // TAB 0: Live 5-Tuple Packet Stream
            0 -> {
                item(key = "stream_controls") {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = searchQuery,
                            onValueChange = { searchQuery = it },
                            modifier = Modifier
                                .weight(1f)
                                .testTag("packet_search_input"),
                            placeholder = { Text("Filter IP, port, UID, app, SNI...") },
                            leadingIcon = { Icon(Icons.Default.Search, contentDescription = stringResource(R.string.cd_search)) },
                            singleLine = true
                        )
                        IconButton(
                            onClick = { viewModel.clearLiveStream() },
                            modifier = Modifier
                                .size(48.dp)
                                .testTag("clear_stream_button")
                        ) {
                            Icon(
                                Icons.Default.Delete,
                                contentDescription = "Clear live packet stream",
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }

                val filteredPackets = if (searchQuery.isBlank()) {
                    livePackets
                } else {
                    val q = searchQuery.lowercase()
                    livePackets.filter {
                        it.appLabel.lowercase().contains(q) ||
                            it.dstIp.contains(q) ||
                            it.dstPort.toString().contains(q) ||
                            it.appUid.toString().contains(q) ||
                            (it.domainOrSni?.lowercase()?.contains(q) == true)
                    }
                }

                if (filteredPackets.isEmpty()) {
                    item(key = "empty_stream") {
                        TacticalEmptyState(
                            icon = Icons.Default.NetworkCheck,
                            title = stringResource(R.string.empty_stream_title),
                            subtitle = stringResource(R.string.empty_stream_subtitle),
                            actionLabel = if (vpnState != VpnEngineState.RUNNING) stringResource(R.string.action_arm_vpn) else null,
                            actionTestTag = "empty_arm_vpn_btn",
                            onAction = if (vpnState != VpnEngineState.RUNNING) ::toggleVpnShield else null
                        )
                    }
                } else {
                    items(filteredPackets, key = { it.id }) { pkt ->
                        PacketStreamRow(
                            packet = pkt,
                            onClick = { selectedPacket = pkt }
                        )
                    }
                }
            }

            // TAB 1: Per-App AFWall+ Rules Matrix
            1 -> {
                item(key = "afwall_posture") {
                    TacticalPanel(
                        accentColor = if (settings.defaultBlockAllMode) MaterialTheme.colorScheme.secondary
                        else MaterialTheme.colorScheme.tertiary
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = if (settings.defaultBlockAllMode) "AFWall+ Allowlist Mode (Default BLOCK)"
                                    else "Denylist Mode (Default ALLOW)",
                                    style = MaterialTheme.typography.titleSmall,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                Text(
                                    text = "Android 10+ UID resolution via ConnectivityManager.getConnectionOwnerUid()",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            Switch(
                                checked = settings.defaultBlockAllMode,
                                onCheckedChange = { viewModel.setDefaultBlockAll(it) },
                                modifier = Modifier.testTag("default_block_all_switch")
                            )
                        }
                        Spacer(Modifier.height(10.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            OutlinedTextField(
                                value = searchQuery,
                                onValueChange = { searchQuery = it },
                                modifier = Modifier
                                    .weight(1f)
                                    .testTag("app_search_input"),
                                placeholder = { Text("Search installed apps or UID...") },
                                leadingIcon = { Icon(Icons.Default.Search, contentDescription = null) },
                                singleLine = true
                            )
                            IconButton(
                                onClick = { viewModel.refreshInstalledApps() },
                                modifier = Modifier.size(48.dp)
                            ) {
                                Icon(Icons.Default.Refresh, contentDescription = "Refresh app list")
                            }
                        }
                    }
                }

                val filteredApps = if (searchQuery.isBlank()) {
                    installedApps
                } else {
                    val q = searchQuery.lowercase()
                    installedApps.filter {
                        it.appLabel.lowercase().contains(q) ||
                            it.packageName.lowercase().contains(q) ||
                            it.uid.toString().contains(q)
                    }
                }

                items(filteredApps, key = { it.uid }) { app ->
                    val existing = appRuleByUid[app.uid]
                    AppFirewallRuleCard(
                        app = app,
                        rule = existing,
                        defaultBlockAll = settings.defaultBlockAllMode,
                        onAllow = { viewModel.setAppRule(app, RuleAction.ALLOW) },
                        onBlock = { viewModel.setAppRule(app, RuleAction.BLOCK) },
                        onClear = { viewModel.clearAppRule(app.uid) }
                    )
                }
            }

            // TAB 2: IP / CIDR / Port / Domain Rules
            2 -> {
                item(key = "custom_rule_bar") {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "IP, CIDR, Port & Domain Rules (${customRules.size})",
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Button(
                            onClick = { showAddRuleDialog = true },
                            modifier = Modifier
                                .heightIn(min = 48.dp)
                                .testTag("add_custom_rule_button")
                        ) {
                            Icon(Icons.Default.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(stringResource(R.string.action_add_rule))
                        }
                    }
                }

                if (customRules.isEmpty()) {
                    item(key = "empty_custom_rules") {
                        TacticalEmptyState(
                            icon = Icons.Default.FilterList,
                            title = "No Custom IP/Port/Host Rules",
                            subtitle = "Add rules targeting specific IPv4/IPv6 CIDR subnets (e.g. 192.168.1.0/24), ports (TCP:443, UDP:53), or domain suffixes.",
                            actionLabel = stringResource(R.string.action_add_rule),
                            actionTestTag = "empty_add_rule_btn",
                            onAction = { showAddRuleDialog = true }
                        )
                    }
                } else {
                    items(customRules, key = { it.id }) { rule ->
                        CustomRuleCard(
                            rule = rule,
                            onDelete = { viewModel.deleteRule(rule.id) }
                        )
                    }
                }
            }

            // TAB 3: Simultaneous PCAPNG Recorder & Saved Captures
            3 -> {
                item(key = "pcap_status_panel") {
                    TacticalPanel(
                        accentColor = if (pcapStats.isRecording) MaterialTheme.colorScheme.error
                        else MaterialTheme.colorScheme.primary
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "Ring-Buffer PCAPNG Engine",
                                    style = MaterialTheme.typography.titleMedium,
                                    color = MaterialTheme.colorScheme.onSurface
                                )
                                Text(
                                    text = pcapStats.fileName ?: "LinkType 101 Raw IP • UID/Verdict EPB Comments",
                                    style = TelemetryMonoSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            PulsingStatusBadge(
                                label = if (pcapStats.isRecording) "REC LIVE" else "IDLE",
                                color = if (pcapStats.isRecording) MaterialTheme.colorScheme.error
                                else MaterialTheme.colorScheme.onSurfaceVariant,
                                isPulsing = pcapStats.isRecording
                            )
                        }
                        Spacer(Modifier.height(10.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            MetricTile(
                                label = "Written",
                                value = pcapStats.packetsWritten.toString(),
                                accent = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.weight(1f)
                            )
                            MetricTile(
                                label = "Size",
                                value = formatBytesCompact(pcapStats.bytesWritten),
                                accent = MaterialTheme.colorScheme.tertiary,
                                modifier = Modifier.weight(1f)
                            )
                            MetricTile(
                                label = "Dropped",
                                value = pcapStats.droppedFrames.toString(),
                                accent = if (pcapStats.droppedFrames > 0) MaterialTheme.colorScheme.error
                                else MaterialTheme.colorScheme.secondary,
                                modifier = Modifier.weight(1f)
                            )
                        }
                        Spacer(Modifier.height(10.dp))
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "Auto-record PCAPNG when VPN arms",
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                            Switch(
                                checked = settings.autoRecordPcapOnVpnStart,
                                onCheckedChange = { viewModel.setAutoRecordPcap(it) },
                                modifier = Modifier.testTag("auto_pcap_switch")
                            )
                        }
                    }
                }

                if (captureSessions.isEmpty()) {
                    item(key = "empty_captures") {
                        TacticalEmptyState(
                            icon = Icons.Default.Security,
                            title = stringResource(R.string.empty_captures_title),
                            subtitle = stringResource(R.string.empty_captures_subtitle)
                        )
                    }
                } else {
                    items(captureSessions, key = { it.id }) { session ->
                        CaptureSessionCard(
                            session = session,
                            onExport = {
                                pendingExportSession = session
                                exportPcapLauncher.launch(session.fileName)
                            },
                            onDelete = { viewModel.deleteCaptureSession(session) }
                        )
                    }
                }
            }
        }
    }

    // Packet Forensic Detail Bottom Sheet
    selectedPacket?.let { pkt ->
        ModalBottomSheet(
            onDismissRequest = { selectedPacket = null },
            containerColor = MaterialTheme.colorScheme.surface
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 18.dp, vertical = 8.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = "${pkt.protocol} PACKET #${pkt.id}",
                        style = MaterialTheme.typography.titleMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    PulsingStatusBadge(
                        label = if (pkt.allowed) "ALLOWED" else "BLOCKED",
                        color = if (pkt.allowed) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.error,
                        isPulsing = false
                    )
                }
                Spacer(Modifier.height(10.dp))
                KeyValueRow("Timestamp", formatClockMillis(pkt.timestamp))
                KeyValueRow("App / UID", "${pkt.appLabel} (UID ${pkt.appUid})")
                KeyValueRow("Source", "${pkt.srcIp}:${pkt.srcPort}")
                KeyValueRow("Destination", "${pkt.dstIp}:${pkt.dstPort}")
                KeyValueRow("Size", "${pkt.byteLength} bytes")
                pkt.domainOrSni?.let { KeyValueRow("DNS / SNI Host", it, MaterialTheme.colorScheme.secondary) }
                pkt.tlsSummary?.let { KeyValueRow("TLS Metadata", it, MaterialTheme.colorScheme.primary) }
                KeyValueRow("Verdict", pkt.ruleReason)
                KeyValueRow("Inspection", pkt.inspectionNote)

                Spacer(Modifier.height(10.dp))
                Text(
                    text = "RAW PAYLOAD HEX PREVIEW",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(4.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(6.dp))
                        .background(MaterialTheme.colorScheme.background)
                        .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(6.dp))
                        .padding(10.dp)
                ) {
                    Text(
                        text = pkt.hexPreview.ifBlank { "(No raw bytes)" },
                        style = TelemetryMonoSmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                }

                Spacer(Modifier.height(14.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    if (pkt.appUid >= 0) {
                        OutlinedButton(
                            onClick = {
                                viewModel.addCustomRule(RuleType.APP_UID, pkt.appUid.toString(), pkt.appLabel, RuleAction.BLOCK)
                                selectedPacket = null
                            },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                        ) {
                            Text("Block App", color = MaterialTheme.colorScheme.error)
                        }
                    }
                    OutlinedButton(
                        onClick = {
                            viewModel.addCustomRule(RuleType.IP_CIDR, pkt.dstIp, pkt.dstIp, RuleAction.BLOCK)
                            selectedPacket = null
                        },
                        modifier = Modifier
                            .weight(1f)
                            .heightIn(min = 48.dp)
                    ) {
                        Text("Block IP", color = MaterialTheme.colorScheme.error)
                    }
                    if (!pkt.domainOrSni.isNullOrBlank()) {
                        OutlinedButton(
                            onClick = {
                                viewModel.addCustomRule(RuleType.DOMAIN, pkt.domainOrSni, pkt.domainOrSni, RuleAction.BLOCK)
                                selectedPacket = null
                            },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                        ) {
                            Text("Block Host", color = MaterialTheme.colorScheme.secondary)
                        }
                    }
                }
                Spacer(Modifier.height(20.dp))
            }
        }
    }

    if (showAddRuleDialog) {
        AddCustomRuleDialog(
            onDismiss = { showAddRuleDialog = false },
            onConfirm = { type, target, label, action ->
                viewModel.addCustomRule(type, target, label, action)
                showAddRuleDialog = false
            }
        )
    }
}

@Composable
private fun PacketStreamRow(packet: LivePacketEvent, onClick: () -> Unit) {
    val verdictColor = if (packet.allowed) MaterialTheme.colorScheme.tertiary else MaterialTheme.colorScheme.error
    TacticalPanel(
        modifier = Modifier
            .clickable(onClick = onClick)
            .testTag("packet_item_${packet.id}"),
        accentColor = if (!packet.allowed) MaterialTheme.colorScheme.error else null
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    text = packet.protocol,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = packet.appLabel,
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "UID:${packet.appUid}",
                    style = TelemetryMonoSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Text(
                text = if (packet.allowed) "ALLOW" else "BLOCK",
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                color = verdictColor
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(
            text = "${packet.dstIp}:${packet.dstPort}" + (packet.domainOrSni?.let { "  •  $it" } ?: ""),
            style = TelemetryMonoMedium,
            color = if (packet.domainOrSni != null) MaterialTheme.colorScheme.secondary
            else MaterialTheme.colorScheme.onSurface,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Spacer(Modifier.height(3.dp))
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Text(
                text = packet.inspectionNote,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )
            Spacer(Modifier.width(8.dp))
            Text(
                text = "${packet.byteLength}B",
                style = TelemetryMonoSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun AppFirewallRuleCard(
    app: InstalledAppEntry,
    rule: FirewallRuleEntity?,
    defaultBlockAll: Boolean,
    onAllow: () -> Unit,
    onBlock: () -> Unit,
    onClear: () -> Unit
) {
    val effectiveAllow = when (rule?.action) {
        RuleAction.ALLOW.name -> true
        RuleAction.BLOCK.name -> false
        else -> !defaultBlockAll
    }
    TacticalPanel(
        accentColor = if (!effectiveAllow) MaterialTheme.colorScheme.error else null
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = app.appLabel,
                    style = MaterialTheme.typography.titleSmall,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "UID ${app.uid} • ${app.packageName}",
                    style = TelemetryMonoSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }
            Spacer(Modifier.width(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                FilterChip(
                    selected = rule?.action == RuleAction.ALLOW.name,
                    onClick = { if (rule?.action == RuleAction.ALLOW.name) onClear() else onAllow() },
                    label = { Text("ALLOW", style = MaterialTheme.typography.labelSmall) },
                    leadingIcon = {
                        Icon(
                            Icons.Default.CheckCircle,
                            contentDescription = "Allow ${app.appLabel}",
                            tint = MaterialTheme.colorScheme.tertiary,
                            modifier = Modifier.size(15.dp)
                        )
                    }
                )
                FilterChip(
                    selected = rule?.action == RuleAction.BLOCK.name,
                    onClick = { if (rule?.action == RuleAction.BLOCK.name) onClear() else onBlock() },
                    label = { Text("BLOCK", style = MaterialTheme.typography.labelSmall) },
                    leadingIcon = {
                        Icon(
                            Icons.Default.Block,
                            contentDescription = "Block ${app.appLabel}",
                            tint = MaterialTheme.colorScheme.error,
                            modifier = Modifier.size(15.dp)
                        )
                    }
                )
            }
        }
    }
}

@Composable
private fun CustomRuleCard(rule: FirewallRuleEntity, onDelete: () -> Unit) {
    val isBlock = rule.action == RuleAction.BLOCK.name
    TacticalPanel(accentColor = if (isBlock) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.tertiary) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        text = rule.ruleType,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        text = rule.action,
                        style = MaterialTheme.typography.labelSmall,
                        color = if (isBlock) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.tertiary
                    )
                    Text(
                        text = "Hits: ${rule.hitCount}",
                        style = TelemetryMonoSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Spacer(Modifier.height(3.dp))
                Text(
                    text = rule.targetValue,
                    style = TelemetryMonoMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
                if (rule.displayLabel != rule.targetValue) {
                    Text(
                        text = rule.displayLabel,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            IconButton(
                onClick = onDelete,
                modifier = Modifier.size(48.dp)
            ) {
                Icon(
                    Icons.Default.Delete,
                    contentDescription = "Delete rule ${rule.targetValue}",
                    tint = MaterialTheme.colorScheme.error
                )
            }
        }
    }
}

@Composable
private fun CaptureSessionCard(
    session: CaptureSessionEntity,
    onExport: () -> Unit,
    onDelete: () -> Unit
) {
    TacticalPanel {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = session.fileName,
                    style = TelemetryMonoMedium,
                    color = MaterialTheme.colorScheme.primary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Text(
                    text = "${session.packetCount} pkts • ${formatBytesCompact(session.byteCount)} • Dropped: ${session.droppedCount}",
                    style = TelemetryMonoSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Row {
                IconButton(onClick = onExport, modifier = Modifier.size(48.dp)) {
                    Icon(
                        Icons.Default.Download,
                        contentDescription = stringResource(R.string.action_export_pcap),
                        tint = MaterialTheme.colorScheme.primary
                    )
                }
                IconButton(onClick = onDelete, modifier = Modifier.size(48.dp)) {
                    Icon(
                        Icons.Default.Delete,
                        contentDescription = stringResource(R.string.action_delete),
                        tint = MaterialTheme.colorScheme.error
                    )
                }
            }
        }
    }
}

@Composable
private fun AddCustomRuleDialog(
    onDismiss: () -> Unit,
    onConfirm: (RuleType, String, String, RuleAction) -> Unit
) {
    var selectedType by remember { mutableStateOf(RuleType.IP_CIDR) }
    var selectedAction by remember { mutableStateOf(RuleAction.BLOCK) }
    var targetText by remember { mutableStateOf("") }
    var labelText by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = MaterialTheme.colorScheme.surface,
        title = { Text("Add Firewall Rule", style = MaterialTheme.typography.titleMedium) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    listOf(RuleType.IP_CIDR to "IP/CIDR", RuleType.PORT to "Port", RuleType.DOMAIN to "Domain").forEach { (type, lbl) ->
                        FilterChip(
                            selected = selectedType == type,
                            onClick = { selectedType = type },
                            label = { Text(lbl) }
                        )
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FilterChip(
                        selected = selectedAction == RuleAction.BLOCK,
                        onClick = { selectedAction = RuleAction.BLOCK },
                        label = { Text("BLOCK") }
                    )
                    FilterChip(
                        selected = selectedAction == RuleAction.ALLOW,
                        onClick = { selectedAction = RuleAction.ALLOW },
                        label = { Text("ALLOW") }
                    )
                }
                OutlinedTextField(
                    value = targetText,
                    onValueChange = { targetText = it },
                    label = {
                        Text(
                            when (selectedType) {
                                RuleType.IP_CIDR -> "IP or CIDR (e.g. 198.51.100.0/24)"
                                RuleType.PORT -> "Port or Proto:Port (e.g. TCP:443 or 53)"
                                RuleType.DOMAIN -> "Domain suffix (e.g. tracker.example.com)"
                                RuleType.APP_UID -> "App UID"
                            }
                        )
                    },
                    singleLine = true,
                    modifier = Modifier.testTag("custom_rule_target_input")
                )
                OutlinedTextField(
                    value = labelText,
                    onValueChange = { labelText = it },
                    label = { Text("Optional Note / Label") },
                    singleLine = true
                )
            }
        },
        confirmButton = {
            Button(
                onClick = { onConfirm(selectedType, targetText, labelText, selectedAction) },
                modifier = Modifier.testTag("confirm_custom_rule_button")
            ) {
                Text("Save Rule")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        }
    )
}
