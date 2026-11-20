package com.example

import android.app.Application
import com.example.data.local.FirewallDatabase
import com.example.data.local.FirewallRepository
import com.example.data.local.PreferencesRepository
import com.example.engine.bluetooth.BleThreatMonitor
import com.example.engine.network.FirewallRuleEngine
import com.example.engine.network.IdsEngine
import com.example.engine.rf.RtlSdrUsbManager
import com.example.vpn.VpnTelemetryBus
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean

class AppContainer(private val application: Application) {
    private val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    val database: FirewallDatabase by lazy { FirewallDatabase.getInstance(application) }
    val repository: FirewallRepository by lazy {
        FirewallRepository(
            ruleDao = database.firewallRuleDao(),
            alertDao = database.idsAlertDao(),
            threatFeedDao = database.threatFeedDao(),
            captureSessionDao = database.captureSessionDao(),
            rfAllocationDao = database.rfAllocationDao()
        )
    }
    val preferences: PreferencesRepository by lazy { PreferencesRepository(application) }
    val ruleEngine: FirewallRuleEngine by lazy { FirewallRuleEngine() }
    val idsEngine: IdsEngine by lazy { IdsEngine() }
    val telemetryBus: VpnTelemetryBus by lazy { VpnTelemetryBus() }
    val bleMonitor: BleThreatMonitor by lazy { BleThreatMonitor(application) }
    val usbSdrManager: RtlSdrUsbManager by lazy { RtlSdrUsbManager(application) }
    val latestDefaultBlockAll: AtomicBoolean = AtomicBoolean(false)

    init {
        appScope.launch {
            repository.ensureSeeded()
            preferences.settingsFlow.collect { settings ->
                latestDefaultBlockAll.set(settings.defaultBlockAllMode)
            }
        }
    }
}

class FirewallApplication : Application() {
    lateinit var container: AppContainer
        private set

    override fun onCreate() {
        super.onCreate()
        container = AppContainer(this)
    }
}
