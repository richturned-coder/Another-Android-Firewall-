package org.aafw.firewall

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.aafw.firewall.data.crypto.DatabaseKeyManager
import org.aafw.firewall.data.crypto.TinkKeystoreProvider
import org.aafw.firewall.data.local.AppSettings
import org.aafw.firewall.data.local.FirewallDatabase
import org.aafw.firewall.data.local.FirewallRuleEntity
import org.aafw.firewall.data.local.PreferencesRepository
import org.aafw.firewall.data.local.RuleAction
import org.aafw.firewall.data.local.RuleType
import org.aafw.firewall.engine.rf.RtlSdrUsbManager
import org.aafw.firewall.vpn.FirewallVpnService
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

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
    fun databaseKeyManagerWrapsReloadsRecoversAndScrubsLegacyPlaintextDb() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val aead = TinkKeystoreProvider.createInMemoryForTest()
        val testKeyFileName = "test_room_db_key_v1.enc"

        val key1 = DatabaseKeyManager.getOrCreatePassphrase(context, aead, keyFileName = testKeyFileName)
        assertEquals(32, key1.size)

        val keyFile = File(File(context.filesDir, "crypto"), testKeyFileName)
        assertTrue("Wrapped key file must exist", keyFile.exists())
        val wrappedBytes = keyFile.readBytes()
        assertTrue("Wrapped key ciphertext must be larger than raw key", wrappedBytes.size > key1.size)
        assertFalse("Wrapped key file must not equal raw passphrase", wrappedBytes.contentEquals(key1))

        val key2 = DatabaseKeyManager.getOrCreatePassphrase(context, aead, keyFileName = testKeyFileName)
        assertTrue("Subsequent retrieval must return identical unwrapped passphrase", key1.contentEquals(key2))

        // Simulate corrupted key blob + stale encrypted DB: must wipe undecryptable DB and rotate cleanly
        val staleEncDb = context.getDatabasePath(DatabaseKeyManager.ENCRYPTED_DB_NAME)
        staleEncDb.parentFile?.mkdirs()
        staleEncDb.writeBytes(byteArrayOf(1, 2, 3, 4))
        keyFile.writeBytes(byteArrayOf(0x00, 0x11, 0x22, 0x33, 0x44))

        val key3 = DatabaseKeyManager.getOrCreatePassphrase(context, aead, keyFileName = testKeyFileName)
        assertEquals(32, key3.size)
        assertFalse("Recovered passphrase must be freshly generated", key1.contentEquals(key3))
        assertFalse("Undecryptable DB file must be wiped on key corruption", staleEncDb.exists())

        // Verify legacy unencrypted Room SQLite family is scrubbed
        val legacyDb = context.getDatabasePath(DatabaseKeyManager.LEGACY_PLAINTEXT_DB_NAME)
        legacyDb.parentFile?.mkdirs()
        val legacyWal = File("${legacyDb.absolutePath}-wal")
        val legacyShm = File("${legacyDb.absolutePath}-shm")
        legacyDb.writeText("SQLite format 3\u0000plaintext-leak")
        legacyWal.writeText("wal-data")
        legacyShm.writeText("shm-data")

        DatabaseKeyManager.scrubLegacyPlaintextDatabase(context)
        assertFalse(legacyDb.exists())
        assertFalse(legacyWal.exists())
        assertFalse(legacyShm.exists())
    }

    @Test
    fun preferencesRepositoryEncryptsAtRestRecoversCorruptionAndScrubsLegacyFile() = runBlocking {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val aead = TinkKeystoreProvider.createInMemoryForTest()
        val storeScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        val corruptScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        try {
            val encFile = File(File(context.filesDir, "datastore"), "test_adf_settings.enc")
            val repo = PreferencesRepository.createForTest(encFile, aead, storeScope)

            repo.setDefaultBlockAllMode(true)
            repo.setAutoRecordPcap(true)
            repo.updateIdsToggle(dnsPhishing = false, httpDpi = false)
            repo.updateRfSettings(centerFreqMhz = 868.3, sampleRateHz = 1_024_000, peakThresholdDb = 12.5f)

            val saved = repo.settingsFlow.first()
            assertTrue(saved.defaultBlockAllMode)
            assertTrue(saved.autoRecordPcapOnVpnStart)
            assertFalse(saved.idsDnsPhishingEnabled)
            assertFalse(saved.idsHttpDpiEnabled)
            assertEquals(868.3, saved.rfCenterFreqMhz, 0.0001)
            assertEquals(1_024_000, saved.rfSampleRateHz)
            assertEquals(12.5f, saved.rfPeakThresholdDb, 0.0001f)

            assertTrue("Encrypted settings file must exist on disk", encFile.exists())
            val rawDiskBytes = encFile.readBytes()
            assertTrue(rawDiskBytes.isNotEmpty())
            val rawLatin1 = String(rawDiskBytes, Charsets.ISO_8859_1)
            assertFalse("On-disk DataStore must not expose plaintext magic header", rawLatin1.contains("ADFS"))
            assertFalse("On-disk DataStore must not expose plaintext key names", rawLatin1.contains("default_block_all"))

            // Tampered/corrupted DataStore file must recover cleanly to default AppSettings
            val corruptFile = File(File(context.filesDir, "datastore"), "test_corrupt_settings.enc")
            corruptFile.parentFile?.mkdirs()
            corruptFile.writeBytes(byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte(), 7, 8, 9))
            val corruptRepo = PreferencesRepository.createForTest(corruptFile, aead, corruptScope)
            assertEquals(AppSettings(), corruptRepo.settingsFlow.first())

            // Constructing production PreferencesRepository(context) scrubs legacy plaintext preferences_pb
            val legacyPrefs = File(File(context.filesDir, "datastore"), "adf_preferences.preferences_pb")
            legacyPrefs.parentFile?.mkdirs()
            legacyPrefs.writeText("legacy_plaintext_prefs")
            PreferencesRepository(context)
            assertFalse("Legacy plaintext preferences_pb must be scrubbed", legacyPrefs.exists())
        } finally {
            storeScope.cancel()
            corruptScope.cancel()
        }
    }
}
