package org.aafw.firewall.ui.viewmodel

import android.app.Application
import android.content.Intent
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import org.aafw.firewall.AppContainer
import org.aafw.firewall.data.local.AppSettings
import org.aafw.firewall.data.local.FirewallRuleEntity
import org.aafw.firewall.data.local.IdsAlertEntity
import org.aafw.firewall.data.local.RuleAction
import org.aafw.firewall.data.local.RuleType
import org.aafw.firewall.data.local.ThreatFeedEntryEntity
import org.aafw.firewall.vpn.FirewallVpnService
import org.aafw.firewall.vpn.VpnEngineState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import java.io.BufferedReader
import java.io.InputStreamReader

class IdsViewModel(
    application: Application,
    private val container: AppContainer
) : AndroidViewModel(application) {

    val alerts: StateFlow<List<IdsAlertEntity>> = container.repository.recentAlerts
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val threatFeedEntries: StateFlow<List<ThreatFeedEntryEntity>> = container.repository.threatFeedEntries
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val settings: StateFlow<AppSettings> = container.preferences.settingsFlow
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), AppSettings())

    private val _statusMessage = MutableStateFlow<String?>(null)
    val statusMessage: StateFlow<String?> = _statusMessage.asStateFlow()

    fun consumeStatus() {
        _statusMessage.value = null
    }

    fun toggleIdsEngine(
        dnsPhishing: Boolean? = null,
        heuristics: Boolean? = null,
        behavioral: Boolean? = null,
        httpDpi: Boolean? = null
    ) {
        viewModelScope.launch(Dispatchers.IO) {
            container.preferences.updateIdsToggle(
                dnsPhishing = dnsPhishing,
                heuristics = heuristics,
                behavioral = behavioral,
                httpDpi = httpDpi
            )
        }
    }

    fun clearAllAlerts() {
        viewModelScope.launch(Dispatchers.IO) {
            container.repository.clearAlerts()
            _statusMessage.value = "Cleared all IDS alert logs."
        }
    }

    fun deleteAlert(id: Long) {
        viewModelScope.launch(Dispatchers.IO) {
            container.repository.deleteAlert(id)
        }
    }

    fun blockAppFromAlert(uid: Int, appLabel: String) {
        if (uid < 0) {
            _statusMessage.value = "Cannot create UID rule for unattributed packet."
            return
        }
        viewModelScope.launch(Dispatchers.IO) {
            container.repository.upsertRule(
                FirewallRuleEntity(
                    ruleType = RuleType.APP_UID.name,
                    targetValue = uid.toString(),
                    displayLabel = appLabel,
                    action = RuleAction.BLOCK.name
                )
            )
            refreshServiceRules()
            _statusMessage.value = "Blocked app $appLabel (UID $uid)."
        }
    }

    fun blockDomainFromAlert(domain: String) {
        val clean = domain.trim().lowercase()
        if (clean.isEmpty()) return
        viewModelScope.launch(Dispatchers.IO) {
            container.repository.upsertRule(
                FirewallRuleEntity(
                    ruleType = RuleType.DOMAIN.name,
                    targetValue = clean,
                    displayLabel = clean,
                    action = RuleAction.BLOCK.name
                )
            )
            refreshServiceRules()
            _statusMessage.value = "Blocked domain $clean."
        }
    }

    fun blockIpFromAlert(ipEndpoint: String) {
        val ip = ipEndpoint.substringBeforeLast(':').trim('[', ']')
        if (ip.isBlank()) return
        viewModelScope.launch(Dispatchers.IO) {
            container.repository.upsertRule(
                FirewallRuleEntity(
                    ruleType = RuleType.IP_CIDR.name,
                    targetValue = ip,
                    displayLabel = ip,
                    action = RuleAction.BLOCK.name
                )
            )
            refreshServiceRules()
            _statusMessage.value = "Blocked destination IP $ip."
        }
    }

    fun addThreatIndicator(domain: String, category: String) {
        val clean = domain.trim().lowercase()
        if (clean.isEmpty()) return
        viewModelScope.launch(Dispatchers.IO) {
            container.repository.addThreatIndicators(
                listOf(
                    ThreatFeedEntryEntity(
                        indicator = clean,
                        source = "Manual-Local",
                        category = category
                    )
                )
            )
            _statusMessage.value = "Added $clean to on-device threat feed."
        }
    }

    fun toggleThreatIndicator(id: Long, enabled: Boolean) {
        viewModelScope.launch(Dispatchers.IO) {
            container.repository.toggleThreatIndicator(id, enabled)
        }
    }

    fun deleteThreatIndicator(id: Long) {
        viewModelScope.launch(Dispatchers.IO) {
            container.repository.deleteThreatIndicator(id)
        }
    }

    fun importThreatFeedUri(uri: Uri) {
        viewModelScope.launch(Dispatchers.IO) {
            val imported = ArrayList<ThreatFeedEntryEntity>()
            runCatching {
                getApplication<Application>().contentResolver.openInputStream(uri)?.use { stream ->
                    BufferedReader(InputStreamReader(stream)).useLines { lines ->
                        lines.forEach { raw ->
                            val line = raw.trim().lowercase()
                            if (line.isEmpty() || line.startsWith("#")) return@forEach
                            val host = line
                                .removePrefix("0.0.0.0 ")
                                .removePrefix("127.0.0.1 ")
                                .removePrefix("https://")
                                .removePrefix("http://")
                                .substringBefore('/')
                                .substringBefore(':')
                                .trim()
                            if (host.contains('.') && host.length in 4..253 && imported.size < 5000) {
                                imported.add(
                                    ThreatFeedEntryEntity(
                                        indicator = host,
                                        source = "Custom-SAF",
                                        category = "PHISHING"
                                    )
                                )
                            }
                        }
                    }
                }
            }
            if (imported.isNotEmpty()) {
                container.repository.addThreatIndicators(imported)
                _statusMessage.value = "Imported ${imported.size} local threat indicators."
            } else {
                _statusMessage.value = "No valid domains found in selected file."
            }
        }
    }

    private fun refreshServiceRules() {
        if (container.telemetryBus.vpnState.value == VpnEngineState.RUNNING) {
            val ctx = getApplication<Application>()
            runCatching {
                ctx.startService(
                    Intent(ctx, FirewallVpnService::class.java).apply {
                        action = FirewallVpnService.ACTION_REFRESH_RULES
                    }
                )
            }
        }
    }
}
