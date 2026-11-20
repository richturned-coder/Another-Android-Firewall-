package org.aafw.firewall

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.test.runTest
import org.aafw.firewall.data.local.FirewallDatabase
import org.aafw.firewall.data.local.FirewallRuleEntity
import org.aafw.firewall.data.local.RuleAction
import org.aafw.firewall.data.local.RuleType
import org.aafw.firewall.engine.bluetooth.BleThreatClass
import org.aafw.firewall.engine.bluetooth.BleThreatMonitor
import org.aafw.firewall.engine.rf.RtlSdrUsbManager
import org.aafw.firewall.vpn.FirewallVpnService
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
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

    @Test
    fun bleThreatMonitorStaysStrictlyBoundedUnderHighRateRotatingMacFlood() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val monitor = BleThreatMonitor(context)
        val baseTime = 1_700_000_000_000L
        val payload = byteArrayOf(0x02, 0x01, 0x1A, 0x03, 0xFF.toByte(), 0x4C, 0x00)

        for (i in 0 until 5_000) {
            val mac = "AA:BB:CC:%02X:%02X:%02X".format((i ushr 16) and 0xFF, (i ushr 8) and 0xFF, i and 0xFF)
            monitor.ingestFrame(
                address = mac,
                deviceName = null,
                rssi = -60,
                rawBytes = payload,
                vendorTag = "Apple Continuity Pop-up",
                baseThreat = BleThreatClass.NORMAL,
                baseNote = "Flood test",
                isSpamCandidate = true,
                now = baseTime + (i % 500)
            )
        }

        val (sightingsSize, recentPacketsSize, recentFloodSize) = monitor.trackedStateSizes()
        assertTrue("sightings=$sightingsSize exceeded cap", sightingsSize <= BleThreatMonitor.MAX_SIGHTINGS)
        assertTrue("recentPackets=$recentPacketsSize exceeded cap", recentPacketsSize <= BleThreatMonitor.MAX_RECENT_PACKETS)
        assertTrue("recentFlood=$recentFloodSize exceeded cap", recentFloodSize <= BleThreatMonitor.MAX_RECENT_FLOOD_EVENTS)
        assertTrue("Expected spamAlertActive=true under flood", monitor.snapshot.value.spamAlertActive)
    }
}
