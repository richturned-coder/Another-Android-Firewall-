package org.aafw.firewall.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import org.aafw.firewall.data.crypto.DatabaseKeyManager
import org.aafw.firewall.data.crypto.TinkKeystoreProvider
import java.util.Arrays

@Database(
    entities = [
        FirewallRuleEntity::class,
        IdsAlertEntity::class,
        ThreatFeedEntryEntity::class,
        CaptureSessionEntity::class,
        RfAllocationEntity::class
    ],
    version = 1,
    exportSchema = false
)
abstract class FirewallDatabase : RoomDatabase() {
    abstract fun firewallRuleDao(): FirewallRuleDao
    abstract fun idsAlertDao(): IdsAlertDao
    abstract fun threatFeedDao(): ThreatFeedDao
    abstract fun captureSessionDao(): CaptureSessionDao
    abstract fun rfAllocationDao(): RfAllocationDao

    companion object {
        @Volatile
        private var instance: FirewallDatabase? = null

        fun getInstance(context: Context): FirewallDatabase {
            return instance ?: synchronized(this) {
                instance ?: buildEncryptedDatabase(context.applicationContext).also { instance = it }
            }
        }

        private fun buildEncryptedDatabase(appContext: Context): FirewallDatabase {
            // Wipe legacy unencrypted Room SQLite files so historical plaintext telemetry does not linger.
            DatabaseKeyManager.scrubLegacyPlaintextDatabase(appContext)

            val passphrase = DatabaseKeyManager.getOrCreatePassphrase(appContext)
            return try {
                System.loadLibrary("sqlcipher")
                // Note: Do NOT zero `passphrase` here — SupportOpenHelperFactory holds the reference
                // until Room lazily opens the database and clears it internally.
                val factory = SupportOpenHelperFactory(passphrase)
                Room.databaseBuilder(
                    appContext,
                    FirewallDatabase::class.java,
                    DatabaseKeyManager.ENCRYPTED_DB_NAME
                )
                    .openHelperFactory(factory)
                    .build()
            } catch (e: UnsatisfiedLinkError) {
                Arrays.fill(passphrase, 0)
                // Only fall back to host SQLite under Robolectric JVM tests where Android ABIs
                // for libsqlcipher.so cannot load. Real Android devices always fail closed.
                if (!TinkKeystoreProvider.isRobolectricHost()) {
                    throw e
                }
                Room.databaseBuilder(
                    appContext,
                    FirewallDatabase::class.java,
                    "another_droid_firewall_robolectric.db"
                ).build()
            }
        }
    }
}

object SeedDatabaseCatalog {
    fun defaultThreatIndicators(): List<ThreatFeedEntryEntity> = listOf(
        ThreatFeedEntryEntity(indicator = "login-secure-verify-account.xyz", source = "OpenPhish-Local", category = "PHISHING"),
        ThreatFeedEntryEntity(indicator = "auth-wallet-recovery.top", source = "OpenPhish-Local", category = "PHISHING"),
        ThreatFeedEntryEntity(indicator = "update-banking-session.click", source = "PhishTank-Local", category = "PHISHING"),
        ThreatFeedEntryEntity(indicator = "signin-cloud-verify.icu", source = "PhishTank-Local", category = "PHISHING"),
        ThreatFeedEntryEntity(indicator = "secure-paypa1-support.com", source = "PhishTank-Local", category = "PHISHING"),
        ThreatFeedEntryEntity(indicator = "g00gle-account-alert.net", source = "OpenPhish-Local", category = "PHISHING"),
        ThreatFeedEntryEntity(indicator = "micr0soft-365-login.org", source = "OpenPhish-Local", category = "PHISHING"),
        ThreatFeedEntryEntity(indicator = "dropper-payload-cdn.ru", source = "URLhaus-Local", category = "MALWARE_C2"),
        ThreatFeedEntryEntity(indicator = "botnet-gate-panel.cc", source = "URLhaus-Local", category = "MALWARE_C2"),
        ThreatFeedEntryEntity(indicator = "stealer-exfil-api.pw", source = "URLhaus-Local", category = "MALWARE_C2"),
        ThreatFeedEntryEntity(indicator = "eicar-test-phish.invalid", source = "Local-Test-Vector", category = "PHISHING")
    )

    fun defaultRfAllocations(): List<RfAllocationEntity> = listOf(
        RfAllocationEntity(startFreqMhz = 26.965, endFreqMhz = 27.405, bandName = "CB Radio 11m", serviceCategory = "Citizens Band", commonProtocols = "AM / SSB Voice", typicalModulation = "AM / SSB"),
        RfAllocationEntity(startFreqMhz = 87.5, endFreqMhz = 108.0, bandName = "FM Broadcast", serviceCategory = "Broadcast Radio", commonProtocols = "WFM Stereo + RDS", typicalModulation = "WFM"),
        RfAllocationEntity(startFreqMhz = 108.0, endFreqMhz = 137.0, bandName = "VHF Airband", serviceCategory = "Aeronautical", commonProtocols = "ATC Voice, ACARS, VOR/ILS", typicalModulation = "AM"),
        RfAllocationEntity(startFreqMhz = 137.0, endFreqMhz = 138.0, bandName = "Weather Satellites", serviceCategory = "Meteorological", commonProtocols = "NOAA APT, Meteor-M LRPT", typicalModulation = "FM / QPSK"),
        RfAllocationEntity(startFreqMhz = 144.0, endFreqMhz = 148.0, bandName = "2m Amateur Band", serviceCategory = "Amateur Radio", commonProtocols = "NFM Voice, APRS (144.39 MHz)", typicalModulation = "NFM / AFSK"),
        RfAllocationEntity(startFreqMhz = 156.0, endFreqMhz = 162.025, bandName = "Marine VHF", serviceCategory = "Maritime", commonProtocols = "Marine Voice, AIS (161.975/162.025)", typicalModulation = "NFM / GMSK"),
        RfAllocationEntity(startFreqMhz = 162.4, endFreqMhz = 162.55, bandName = "NOAA Weather Radio", serviceCategory = "Public Safety", commonProtocols = "SAME Weather Broadcast", typicalModulation = "NFM"),
        RfAllocationEntity(startFreqMhz = 314.8, endFreqMhz = 315.2, bandName = "315 MHz ISM", serviceCategory = "Short-Range Devices", commonProtocols = "TPMS, Key Fobs, Garage Remotes (US/JP)", typicalModulation = "OOK / ASK / FSK"),
        RfAllocationEntity(startFreqMhz = 420.0, endFreqMhz = 450.0, bandName = "70cm Amateur Band", serviceCategory = "Amateur Radio", commonProtocols = "Repeaters, DMR, LoRa HAM", typicalModulation = "NFM / FSK"),
        RfAllocationEntity(startFreqMhz = 433.05, endFreqMhz = 434.79, bandName = "433 MHz ISM (LPD433)", serviceCategory = "ISM / IoT Sensors", commonProtocols = "Weather Stations, TPMS, Alarm Sensors, Key Fobs", typicalModulation = "OOK / ASK / FSK"),
        RfAllocationEntity(startFreqMhz = 462.55, endFreqMhz = 467.725, bandName = "FRS / GMRS", serviceCategory = "Two-Way Radio", commonProtocols = "Personal Radio Channels", typicalModulation = "NFM"),
        RfAllocationEntity(startFreqMhz = 863.0, endFreqMhz = 870.0, bandName = "868 MHz SRD (EU)", serviceCategory = "ISM / LPWAN", commonProtocols = "LoRaWAN EU868, Smart Meters, Alarms", typicalModulation = "CSS / FSK / OOK"),
        RfAllocationEntity(startFreqMhz = 902.0, endFreqMhz = 928.0, bandName = "915 MHz ISM (US)", serviceCategory = "ISM / LPWAN", commonProtocols = "LoRaWAN US915, AMR Meters, RFID, Z-Wave", typicalModulation = "CSS / FSK / FHSS"),
        RfAllocationEntity(startFreqMhz = 1090.0, endFreqMhz = 1090.5, bandName = "1090 MHz ADS-B", serviceCategory = "Aviation Surveillance", commonProtocols = "Mode-S / Extended Squitter Transponder", typicalModulation = "PPM (Pulse)"),
        RfAllocationEntity(startFreqMhz = 1574.42, endFreqMhz = 1576.42, bandName = "GPS L1", serviceCategory = "Radionavigation", commonProtocols = "GPS C/A, Galileo E1", typicalModulation = "BPSK / DSSS"),
        RfAllocationEntity(startFreqMhz = 2400.0, endFreqMhz = 2483.5, bandName = "2.4 GHz ISM", serviceCategory = "WLAN / WPAN", commonProtocols = "Wi-Fi 802.11b/g/n, Bluetooth/BLE, Zigbee", typicalModulation = "OFDM / GFSK / DSSS"),
        RfAllocationEntity(startFreqMhz = 5150.0, endFreqMhz = 5850.0, bandName = "5 GHz UNII / ISM", serviceCategory = "WLAN / FPV", commonProtocols = "Wi-Fi 802.11a/n/ac/ax, Drone Video", typicalModulation = "OFDM / Analog FM")
    )
}
