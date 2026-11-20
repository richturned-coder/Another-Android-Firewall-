package org.aafw.firewall.ui.viewmodel

import android.app.Application
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import org.aafw.firewall.AppContainer
import org.aafw.firewall.data.local.AppSettings
import org.aafw.firewall.data.local.CaptureSessionEntity
import org.aafw.firewall.data.local.FirewallRuleEntity
import org.aafw.firewall.data.local.RuleAction
import org.aafw.firewall.data.local.RuleType
import org.aafw.firewall.engine.network.AppLabelResolver
import org.aafw.firewall.engine.network.PcapngStats
import org.aafw.firewall.vpn.FirewallVpnService
import org.aafw.firewall.vpn.LivePacketEvent
import org.aafw.firewall.vpn.LiveTelemetryCounters
import org.aafw.firewall.vpn.VpnEngineState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

data class InstalledAppEntry(
    val uid: Int,
    val packageName: String,
    val appLabel: String,
    val isSystemApp: Boolean
)

class FirewallViewModel(
    application: Application,
    private val container: AppContainer
) : AndroidViewModel(application) {

    val vpnState: StateFlow<VpnEngineState> = container.telemetryBus.vpnState
    val vpnError: StateFlow<String?> = container.telemetryBus.lastError
    val counters: StateFlow<LiveTelemetryCounters> = container.telemetryBus.counters
    val livePackets: StateFlow<List<LivePacketEvent>> = container.telemetryBus.recentPackets
    val pcapStats: StateFlow<PcapngStats> = container.telemetryBus.pcapStats

    val allRules: StateFlow<List<FirewallRuleEntity>> = container.repository.allRules
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val captureSessions: StateFlow<List<CaptureSessionEntity>> = container.repository.captureSessions
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val settings: StateFlow<AppSettings> = container.preferences.settingsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), AppSettings())

    private val _installedApps = MutableStateFlow<List<InstalledAppEntry>>(emptyList())
    val installedApps: StateFlow<List<InstalledAppEntry>> = _installedApps.asStateFlow()

    private val _toastMessage = MutableStateFlow<String?>(null)
    val toastMessage: StateFlow<String?> = _toastMessage.asStateFlow()

    @Volatile
    private var appsLoaded = false

    fun ensureInstalledAppsLoaded() {
        if (!appsLoaded) {
            refreshInstalledApps()
        }
    }

    fun consumeToast() {
        _toastMessage.value = null
    }

    fun refreshInstalledApps() {
        appsLoaded = true
        viewModelScope.launch(Dispatchers.IO) {
            val pm = getApplication<Application>().packageManager
            val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            val resolved = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.queryIntentActivities(launcherIntent, PackageManager.ResolveInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.queryIntentActivities(launcherIntent, 0)
            }

            val byUid = LinkedHashMap<Int, InstalledAppEntry>()
            val selfPkg = getApplication<Application>().packageName
            for (ri in resolved) {
                val ai = ri.activityInfo?.applicationInfo ?: continue
                if (ai.packageName == selfPkg) continue
                val uid = ai.uid
                if (!byUid.containsKey(uid)) {
                    val label = AppLabelResolver.resolve(ri, ai)
                    val isSys = (ai.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                    byUid[uid] = InstalledAppEntry(
                        uid = uid,
                        packageName = ai.packageName,
                        appLabel = label,
                        isSystemApp = isSys
                    )
                }
            }
            _installedApps.value = byUid.values.sortedBy { it.appLabel.lowercase() }
        }
    }

    fun setAppRule(app: InstalledAppEntry, action: RuleAction) {
        viewModelScope.launch(Dispatchers.IO) {
            container.repository.upsertRule(
                FirewallRuleEntity(
                    ruleType = RuleType.APP_UID.name,
                    targetValue = app.uid.toString(),
                    displayLabel = app.appLabel,
                    packageName = app.packageName,
                    action = action.name,
                    enabled = true
                )
            )
            syncServiceRules()
        }
    }

    fun clearAppRule(uid: Int) {
        viewModelScope.launch(Dispatchers.IO) {
            container.repository.deleteRuleByTarget(RuleType.APP_UID, uid.toString())
            syncServiceRules()
        }
    }

    fun addCustomRule(ruleType: RuleType, targetRaw: String, label: String, action: RuleAction) {
        val cleaned = targetRaw.trim()
        if (cleaned.isEmpty()) {
            _toastMessage.value = "Rule target cannot be empty."
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            container.repository.upsertRule(
                FirewallRuleEntity(
                    ruleType = ruleType.name,
                    targetValue = cleaned,
                    displayLabel = label.ifBlank { cleaned },
                    action = action.name,
                    enabled = true
                )
            )
            syncServiceRules()
            _toastMessage.value = "${action.name} rule added for $cleaned"
        }
    }

    fun deleteRule(id: Long) {
        viewModelScope.launch(Dispatchers.IO) {
            container.repository.deleteRule(id)
            syncServiceRules()
        }
    }

    fun setDefaultBlockAll(enabled: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            container.preferences.setDefaultBlockAllMode(enabled)
            syncServiceRules()
        }
    }

    fun setAutoRecordPcap(enabled: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            container.preferences.setAutoRecordPcap(enabled)
        }
    }

    fun clearLiveStream() {
        container.telemetryBus.clearLiveStream()
    }

    fun deleteCaptureSession(session: CaptureSessionEntity) {
        viewModelScope.launch(Dispatchers.IO) {
            runCatching { File(session.filePath).delete() }
            container.repository.deleteCaptureSession(session.id)
            _toastMessage.value = "Deleted ${session.fileName}"
        }
    }

    fun exportCaptureToUri(session: CaptureSessionEntity, targetUri: Uri) {
        viewModelScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val src = File(session.filePath)
                    if (!src.exists()) error("Capture file not found on disk.")
                    getApplication<Application>().contentResolver.openOutputStream(targetUri)?.use { out ->
                        src.inputStream().use { input -> input.copyTo(out) }
                    } ?: error("Unable to write to chosen destination.")
                }
            }
            _toastMessage.value = if (result.isSuccess) {
                "Exported ${session.fileName}"
            } else {
                "Export failed: ${result.exceptionOrNull()?.message}"
            }
        }
    }

    private fun syncServiceRules() {
        if (vpnState.value == VpnEngineState.RUNNING) {
            val ctx = getApplication<Application>()
            val intent = Intent(ctx, FirewallVpnService::class.java).apply {
                action = FirewallVpnService.ACTION_REFRESH_RULES
            }
            runCatching { ctx.startService(intent) }
        }
    }
}
