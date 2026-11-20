package org.aafw.firewall.data.local

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.doublePreferencesKey
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.floatPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

private val Context.firewallDataStore: DataStore<Preferences> by preferencesDataStore(
    name = "adf_preferences"
)

data class AppSettings(
    val defaultBlockAllMode: Boolean = false, // false = Denylist (Allow by default), true = Allowlist (AFWall+ Block by default)
    val autoRecordPcapOnVpnStart: Boolean = false,
    val idsDnsPhishingEnabled: Boolean = true,
    val idsHeuristicsEnabled: Boolean = true,
    val idsBehavioralScanEnabled: Boolean = true,
    val idsHttpDpiEnabled: Boolean = true,
    val irLuminanceThreshold: Int = 225,
    val irChromaBiasThreshold: Float = 0.28f,
    val irUseFrontCamera: Boolean = true,
    val rfCenterFreqMhz: Double = 433.92,
    val rfSampleRateHz: Int = 2_048_000,
    val rfPeakThresholdDb: Float = 10f
)

class PreferencesRepository(private val context: Context) {
    private object Keys {
        val DEFAULT_BLOCK_ALL = booleanPreferencesKey("default_block_all")
        val AUTO_RECORD_PCAP = booleanPreferencesKey("auto_record_pcap")
        val IDS_DNS_PHISHING = booleanPreferencesKey("ids_dns_phishing")
        val IDS_HEURISTICS = booleanPreferencesKey("ids_heuristics")
        val IDS_BEHAVIORAL = booleanPreferencesKey("ids_behavioral")
        val IDS_HTTP_DPI = booleanPreferencesKey("ids_http_dpi")
        val IR_LUMA_THRESHOLD = intPreferencesKey("ir_luma_threshold")
        val IR_CHROMA_BIAS = floatPreferencesKey("ir_chroma_bias")
        val IR_FRONT_CAM = booleanPreferencesKey("ir_front_cam")
        val RF_CENTER_FREQ = doublePreferencesKey("rf_center_freq_mhz")
        val RF_SAMPLE_RATE = intPreferencesKey("rf_sample_rate_hz")
        val RF_PEAK_THRESHOLD = floatPreferencesKey("rf_peak_threshold_db")
    }

    val settingsFlow: Flow<AppSettings> = context.firewallDataStore.data.map { prefs ->
        AppSettings(
            defaultBlockAllMode = prefs[Keys.DEFAULT_BLOCK_ALL] ?: false,
            autoRecordPcapOnVpnStart = prefs[Keys.AUTO_RECORD_PCAP] ?: false,
            idsDnsPhishingEnabled = prefs[Keys.IDS_DNS_PHISHING] ?: true,
            idsHeuristicsEnabled = prefs[Keys.IDS_HEURISTICS] ?: true,
            idsBehavioralScanEnabled = prefs[Keys.IDS_BEHAVIORAL] ?: true,
            idsHttpDpiEnabled = prefs[Keys.IDS_HTTP_DPI] ?: true,
            irLuminanceThreshold = prefs[Keys.IR_LUMA_THRESHOLD] ?: 225,
            irChromaBiasThreshold = prefs[Keys.IR_CHROMA_BIAS] ?: 0.28f,
            irUseFrontCamera = prefs[Keys.IR_FRONT_CAM] ?: true,
            rfCenterFreqMhz = prefs[Keys.RF_CENTER_FREQ] ?: 433.92,
            rfSampleRateHz = prefs[Keys.RF_SAMPLE_RATE] ?: 2_048_000,
            rfPeakThresholdDb = prefs[Keys.RF_PEAK_THRESHOLD] ?: 10f
        )
    }

    suspend fun setDefaultBlockAllMode(enabled: Boolean) {
        context.firewallDataStore.edit { it[Keys.DEFAULT_BLOCK_ALL] = enabled }
    }

    suspend fun setAutoRecordPcap(enabled: Boolean) {
        context.firewallDataStore.edit { it[Keys.AUTO_RECORD_PCAP] = enabled }
    }

    suspend fun updateIdsToggle(
        dnsPhishing: Boolean? = null,
        heuristics: Boolean? = null,
        behavioral: Boolean? = null,
        httpDpi: Boolean? = null
    ) {
        context.firewallDataStore.edit { prefs ->
            dnsPhishing?.let { prefs[Keys.IDS_DNS_PHISHING] = it }
            heuristics?.let { prefs[Keys.IDS_HEURISTICS] = it }
            behavioral?.let { prefs[Keys.IDS_BEHAVIORAL] = it }
            httpDpi?.let { prefs[Keys.IDS_HTTP_DPI] = it }
        }
    }

    suspend fun updateIrSettings(
        lumaThreshold: Int? = null,
        chromaBias: Float? = null,
        useFrontCamera: Boolean? = null
    ) {
        context.firewallDataStore.edit { prefs ->
            lumaThreshold?.let { prefs[Keys.IR_LUMA_THRESHOLD] = it }
            chromaBias?.let { prefs[Keys.IR_CHROMA_BIAS] = it }
            useFrontCamera?.let { prefs[Keys.IR_FRONT_CAM] = it }
        }
    }

    suspend fun updateRfSettings(
        centerFreqMhz: Double? = null,
        sampleRateHz: Int? = null,
        peakThresholdDb: Float? = null
    ) {
        context.firewallDataStore.edit { prefs ->
            centerFreqMhz?.let { prefs[Keys.RF_CENTER_FREQ] = it }
            sampleRateHz?.let { prefs[Keys.RF_SAMPLE_RATE] = it }
            peakThresholdDb?.let { prefs[Keys.RF_PEAK_THRESHOLD] = it }
        }
    }
}
