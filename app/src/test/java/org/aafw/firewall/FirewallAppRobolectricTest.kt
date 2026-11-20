package org.aafw.firewall

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.test.runTest
import org.aafw.firewall.data.local.FirewallDatabase
import org.aafw.firewall.data.local.FirewallRuleEntity
import org.aafw.firewall.data.local.RuleAction
import org.aafw.firewall.data.local.RuleType
import org.aafw.firewall.engine.rf.RtlSdrUsbManager
import org.aafw.firewall.vpn.FirewallVpnService
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class FirewallAppRobolectricTest {

    @Test
    fun appResourcesAndApplicationIdMatchHardenedNamespace() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        assertEquals("Another Droid Firewall+", context.getString(R.string.app_name))
        assertEquals(BuildConfig.APPLICATION_ID, context.packageName)
        assertEquals("org.aafw.firewall", BuildConfig.APPLICATION_ID.removeSuffix(".debug"))
    }

    @Test
    fun dynamicIntentActionsUseApplicationIdPrefix() {
        val prefix = BuildConfig.APPLICATION_ID
        assertEquals("$prefix.vpn.ACTION_START", FirewallVpnService.ACTION_START)
        assertEquals("$prefix.vpn.ACTION_STOP", FirewallVpnService.ACTION_STOP)
        assertEquals("$prefix.vpn.ACTION_START_PCAP", FirewallVpnService.ACTION_START_PCAP)
        assertEquals("$prefix.vpn.ACTION_STOP_PCAP", FirewallVpnService.ACTION_STOP_PCAP)
        assertEquals("$prefix.vpn.ACTION_REFRESH_RULES", FirewallVpnService.ACTION_REFRESH_RULES)
        assertEquals("$prefix.USB_SDR_PERMISSION", RtlSdrUsbManager.ACTION_USB_PERMISSION)
    }

    @Test
    fun inMemoryFirewallDatabasePersistsAndQueriesRules() = runTest {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val db = Room.inMemoryDatabaseBuilder(context, FirewallDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        try {
            val dao = db.firewallRuleDao()
            dao.upsertRule(
                FirewallRuleEntity(
                    ruleType = RuleType.DOMAIN.name,
                    targetValue = "telemetry.invalid",
                    displayLabel = "Telemetry Block",
                    action = RuleAction.BLOCK.name
                )
            )
            val active = dao.getActiveRulesSnapshot()
            assertEquals(1, active.size)
            assertEquals("telemetry.invalid", active.first().targetValue)
        } finally {
            db.close()
        }
    }
}
