package org.aafw.firewall.ui.screens

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
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.FileOpen
import androidx.compose.material.icons.filled.GppGood
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import org.aafw.firewall.R
import org.aafw.firewall.data.local.AlertSeverity
import org.aafw.firewall.data.local.IdsAlertEntity
import org.aafw.firewall.data.local.ThreatFeedEntryEntity
import org.aafw.firewall.ui.components.KeyValueRow
import org.aafw.firewall.ui.components.MetricTile
import org.aafw.firewall.ui.components.PulsingStatusBadge
import org.aafw.firewall.ui.components.SegmentedTacticalBar
import org.aafw.firewall.ui.components.TacticalEmptyState
import org.aafw.firewall.ui.components.TacticalPanel
import org.aafw.firewall.ui.components.formatClockMillis
import org.aafw.firewall.ui.theme.TelemetryMonoMedium
import org.aafw.firewall.ui.theme.TelemetryMonoSmall
import org.aafw.firewall.ui.viewmodel.IdsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun IdsScreen(
    viewModel: IdsViewModel,
    onShowMessage: (String) -> Unit
) {
    val alerts by viewModel.alerts.collectAsStateWithLifecycle()
    val threatFeed by viewModel.threatFeedEntries.collectAsStateWithLifecycle()
    val settings by viewModel.settings.collectAsStateWithLifecycle()
    val statusMsg by viewModel.statusMessage.collectAsStateWithLifecycle()

    LaunchedEffect(statusMsg) {
        statusMsg?.let {
            onShowMessage(it)
            viewModel.consumeStatus()
        }
    }

    var selectedTab by rememberSaveable { mutableIntStateOf(0) }
    var severityFilter by rememberSaveable { mutableStateOf<String?>(null) }
    var inspectedAlert by remember { mutableStateOf<IdsAlertEntity?>(null) }
    var showAddIndicatorDialog by remember { mutableStateOf(false) }

    val importFeedLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri ->
        uri?.let { viewModel.importThreatFeedUri(it) }
    }

    val criticalCount = remember(alerts) { alerts.count { it.severity == AlertSeverity.CRITICAL.name } }
    val highCount = remember(alerts) { alerts.count { it.severity == AlertSeverity.HIGH.name } }
    val mediumCount = remember(alerts) { alerts.count { it.severity == AlertSeverity.MEDIUM.name } }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(14.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item(key = "ids_header") {
            TacticalPanel(
                accentColor = if (criticalCount > 0) MaterialTheme.colorScheme.error
                else MaterialTheme.colorScheme.secondary
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(R.string.ids_title),
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.secondary
                        )
                        Text(
                            text = "Inline Deep Packet & Metadata IDS",
                            style = MaterialTheme.typography.titleMedium,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    PulsingStatusBadge(
                        label = "${threatFeed.count { it.enabled }} IOCs",
                        color = MaterialTheme.colorScheme.primary,
                        isPulsing = false
                    )
                }
                Spacer(Modifier.height(10.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    MetricTile("Critical", criticalCount.toString(), MaterialTheme.colorScheme.error, Modifier.weight(1f))
                    MetricTile("High", highCount.toString(), MaterialTheme.colorScheme.secondary, Modifier.weight(1f))
                    MetricTile("Medium", mediumCount.toString(), MaterialTheme.colorScheme.primary, Modifier.weight(1f))
                }
                Spacer(Modifier.height(10.dp))
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(6.dp))
                        .background(MaterialTheme.colorScheme.surfaceContainer)
                        .padding(8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(
                        Icons.Default.Lock,
                        contentDescription = "TLS inspection boundary",
                        tint = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.size(16.dp)
                    )
                    Text(
                        text = "TLS 1.3 Boundary: Cleartext HTTP gets full Aho-Corasick/regex SQLi, XSS & CMDi DPI. Pinned HTTPS/TLS flows are inspected via DNS, SNI, JA3 fingerprints & timing bursts without breaking TLS.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }

        item(key = "ids_subtabs") {
            SegmentedTacticalBar(
                tabs = listOf(
                    stringResource(R.string.tab_ids_alerts),
                    stringResource(R.string.tab_ids_engines),
                    stringResource(R.string.tab_ids_feeds)
                ),
                selectedIndex = selectedTab,
                onSelect = { selectedTab = it },
                testTagPrefix = "ids"
            )
        }

        when (selectedTab) {
            0 -> {
                item(key = "alert_filters") {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                            listOf(null to "ALL", "CRITICAL" to "CRIT", "HIGH" to "HIGH", "MEDIUM" to "MED").forEach { (sev, label) ->
                                FilterChip(
                                    selected = severityFilter == sev,
                                    onClick = { severityFilter = sev },
                                    label = { Text(label, style = MaterialTheme.typography.labelSmall) }
                                )
                            }
                        }
                        if (alerts.isNotEmpty()) {
                            IconButton(
                                onClick = { viewModel.clearAllAlerts() },
                                modifier = Modifier
                                    .size(48.dp)
                                    .testTag("clear_ids_alerts_button")
                            ) {
                                Icon(
                                    Icons.Default.Delete,
                                    contentDescription = stringResource(R.string.action_clear_alerts),
                                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                        }
                    }
                }

                val filtered = if (severityFilter == null) alerts else alerts.filter { it.severity == severityFilter }
                if (filtered.isEmpty()) {
                    item(key = "empty_ids") {
                        TacticalEmptyState(
                            icon = Icons.Default.GppGood,
                            title = stringResource(R.string.empty_ids_title),
                            subtitle = stringResource(R.string.empty_ids_subtitle)
                        )
                    }
                } else {
                    items(filtered, key = { it.id }) { alert ->
                        IdsAlertCard(
                            alert = alert,
                            onClick = { inspectedAlert = alert }
                        )
                    }
                }
            }

            1 -> {
                item(key = "ids_engine_toggles") {
                    TacticalPanel(accentColor = MaterialTheme.colorScheme.primary) {
                        IdsEngineToggleRow(
                            title = "DNS & TLS SNI Phishing Feed",
                            subtitle = "Matches UDP/53 DNS queries & TLS ClientHello SNI against local OpenPhish/URLhaus/PhishTank feeds.",
                            checked = settings.idsDnsPhishingEnabled,
                            tag = "toggle_ids_phishing",
                            onChange = { viewModel.toggleIdsEngine(dnsPhishing = it) }
                        )
                        Spacer(Modifier.height(10.dp))
                        IdsEngineToggleRow(
                            title = "Punycode / Homograph & DGA Entropy",
                            subtitle = "Flags xn-- IDN lookalikes, brand Levenshtein typosquatting, and >3.85-bit high-entropy DNS labels.",
                            checked = settings.idsHeuristicsEnabled,
                            tag = "toggle_ids_heuristics",
                            onChange = { viewModel.toggleIdsEngine(heuristics = it) }
                        )
                        Spacer(Modifier.height(10.dp))
                        IdsEngineToggleRow(
                            title = "Behavioral Port-Scan & Fuzzing Window",
                            subtitle = "10s sliding-window detector for sequential port sweeps, malformed packet spikes, and HTTP 4xx/5xx floods.",
                            checked = settings.idsBehavioralScanEnabled,
                            tag = "toggle_ids_behavioral",
                            onChange = { viewModel.toggleIdsEngine(behavioral = it) }
                        )
                        Spacer(Modifier.height(10.dp))
                        IdsEngineToggleRow(
                            title = "HTTP DPI (SQLi / XSS / CMDi / Traversal)",
                            subtitle = "Compiled Aho-Corasick + OWASP CRS regex engine scanning URLs, query parameters, headers & bodies.",
                            checked = settings.idsHttpDpiEnabled,
                            tag = "toggle_ids_http_dpi",
                            onChange = { viewModel.toggleIdsEngine(httpDpi = it) }
                        )
                    }
                }
            }

            2 -> {
                item(key = "feed_actions") {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Button(
                            onClick = { importFeedLauncher.launch(arrayOf("text/*", "*/*")) },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                                .testTag("import_threat_feed_button")
                        ) {
                            Icon(Icons.Default.FileOpen, contentDescription = null, modifier = Modifier.size(18.dp))
                            Spacer(Modifier.width(6.dp))
                            Text(stringResource(R.string.action_import_feed))
                        }
                        OutlinedButton(
                            onClick = { showAddIndicatorDialog = true },
                            modifier = Modifier
                                .heightIn(min = 48.dp)
                                .testTag("add_indicator_button"),
                            border = BorderStroke(1.dp, MaterialTheme.colorScheme.primary)
                        ) {
                            Icon(Icons.Default.Add, contentDescription = "Add indicator", tint = MaterialTheme.colorScheme.primary)
                        }
                    }
                }

                items(threatFeed, key = { it.id }) { entry ->
                    ThreatFeedCard(
                        entry = entry,
                        onToggle = { viewModel.toggleThreatIndicator(entry.id, it) },
                        onDelete = { viewModel.deleteThreatIndicator(entry.id) }
                    )
                }
            }
        }
    }

    inspectedAlert?.let { alert ->
        ModalBottomSheet(
            onDismissRequest = { inspectedAlert = null },
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
                        text = "${alert.ruleId} • ${alert.category}",
                        style = MaterialTheme.typography.labelLarge,
                        color = severityColor(alert.severity)
                    )
                    PulsingStatusBadge(
                        label = alert.severity,
                        color = severityColor(alert.severity),
                        isPulsing = alert.severity == AlertSeverity.CRITICAL.name
                    )
                }
                Spacer(Modifier.height(6.dp))
                Text(
                    text = alert.title,
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = alert.description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(10.dp))
                KeyValueRow("Timestamp", formatClockMillis(alert.timestamp))
                KeyValueRow("App / UID", "${alert.appLabel} (UID ${alert.appUid})")
                KeyValueRow("Layer", alert.inspectionLayer, MaterialTheme.colorScheme.primary)
                KeyValueRow("Flow", "${alert.srcEndpoint} → ${alert.dstEndpoint}")
                alert.domainOrSni?.let { KeyValueRow("Host / SNI", it, MaterialTheme.colorScheme.secondary) }

                Spacer(Modifier.height(10.dp))
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(6.dp))
                        .background(MaterialTheme.colorScheme.background)
                        .border(1.dp, MaterialTheme.colorScheme.outlineVariant, RoundedCornerShape(6.dp))
                        .padding(10.dp)
                ) {
                    Text(
                        text = alert.payloadExcerpt,
                        style = TelemetryMonoSmall,
                        color = MaterialTheme.colorScheme.secondary
                    )
                }
                Spacer(Modifier.height(14.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    if (alert.appUid >= 0) {
                        Button(
                            onClick = {
                                viewModel.blockAppFromAlert(alert.appUid, alert.appLabel)
                                inspectedAlert = null
                            },
                            modifier = Modifier
                                .weight(1f)
                                .heightIn(min = 48.dp)
                        ) {
                            Text("Block App")
                        }
                    }
                    OutlinedButton(
                        onClick = {
                            viewModel.blockIpFromAlert(alert.dstEndpoint)
                            inspectedAlert = null
                        },
                        modifier = Modifier
                            .weight(1f)
                            .heightIn(min = 48.dp)
                    ) {
                        Text("Block IP", color = MaterialTheme.colorScheme.error)
                    }
                    alert.domainOrSni?.let { dom ->
                        OutlinedButton(
                            onClick = {
                                viewModel.blockDomainFromAlert(dom)
                                inspectedAlert = null
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

    if (showAddIndicatorDialog) {
        var host by remember { mutableStateOf("") }
        var cat by remember { mutableStateOf("PHISHING") }
        AlertDialog(
            onDismissRequest = { showAddIndicatorDialog = false },
            containerColor = MaterialTheme.colorScheme.surface,
            title = { Text("Add Local Threat Indicator") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    OutlinedTextField(
                        value = host,
                        onValueChange = { host = it },
                        label = { Text("Domain / Hostname") },
                        singleLine = true
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                        listOf("PHISHING", "MALWARE_C2", "SCAM").forEach { c ->
                            FilterChip(
                                selected = cat == c,
                                onClick = { cat = c },
                                label = { Text(c, style = MaterialTheme.typography.labelSmall) }
                            )
                        }
                    }
                }
            },
            confirmButton = {
                Button(onClick = {
                    viewModel.addThreatIndicator(host, cat)
                    showAddIndicatorDialog = false
                }) { Text("Add") }
            },
            dismissButton = {
                TextButton(onClick = { showAddIndicatorDialog = false }) { Text("Cancel") }
            }
        )
    }
}

@Composable
private fun severityColor(severity: String): Color = when (severity) {
    AlertSeverity.CRITICAL.name -> MaterialTheme.colorScheme.error
    AlertSeverity.HIGH.name -> MaterialTheme.colorScheme.secondary
    AlertSeverity.MEDIUM.name -> MaterialTheme.colorScheme.primary
    else -> MaterialTheme.colorScheme.tertiary
}

@Composable
private fun IdsAlertCard(alert: IdsAlertEntity, onClick: () -> Unit) {
    val accent = severityColor(alert.severity)
    TacticalPanel(
        modifier = Modifier
            .clickable(onClick = onClick)
            .testTag("ids_alert_${alert.id}"),
        accentColor = accent
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                Icon(Icons.Default.Warning, contentDescription = null, tint = accent, modifier = Modifier.size(16.dp))
                Text(text = alert.ruleId, style = MaterialTheme.typography.labelSmall, color = accent)
                Text(text = alert.inspectionLayer, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Text(text = formatClockMillis(alert.timestamp), style = TelemetryMonoSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.height(4.dp))
        Text(
            text = alert.title,
            style = MaterialTheme.typography.titleSmall,
            color = MaterialTheme.colorScheme.onSurface,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
        Text(
            text = "${alert.appLabel} (UID ${alert.appUid}) → ${alert.dstEndpoint}",
            style = TelemetryMonoSmall,
            color = MaterialTheme.colorScheme.primary,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis
        )
    }
}

@Composable
private fun IdsEngineToggleRow(
    title: String,
    subtitle: String,
    checked: Boolean,
    tag: String,
    onChange: (Boolean) -> Unit
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(text = title, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.onSurface)
            Text(text = subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Spacer(Modifier.width(10.dp))
        Switch(
            checked = checked,
            onCheckedChange = onChange,
            modifier = Modifier.testTag(tag)
        )
    }
}

@Composable
private fun ThreatFeedCard(
    entry: ThreatFeedEntryEntity,
    onToggle: (Boolean) -> Unit,
    onDelete: () -> Unit
) {
    TacticalPanel {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(text = entry.indicator, style = TelemetryMonoMedium, color = MaterialTheme.colorScheme.onSurface)
                Text(
                    text = "${entry.source} • ${entry.category}",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.secondary
                )
            }
            Switch(checked = entry.enabled, onCheckedChange = onToggle)
            IconButton(onClick = onDelete, modifier = Modifier.size(48.dp)) {
                Icon(Icons.Default.Delete, contentDescription = "Delete indicator", tint = MaterialTheme.colorScheme.error)
            }
        }
    }
}
