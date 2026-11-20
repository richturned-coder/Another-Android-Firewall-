package org.aafw.firewall.data.local

import android.content.Context
import androidx.datastore.core.CorruptionException
import androidx.datastore.core.DataStore
import androidx.datastore.core.DataStoreFactory
import androidx.datastore.core.Serializer
import androidx.datastore.core.handlers.ReplaceFileCorruptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import org.aafw.firewall.data.crypto.AeadCipher
import org.aafw.firewall.data.crypto.DatabaseKeyManager
import org.aafw.firewall.data.crypto.TinkKeystoreProvider
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.security.GeneralSecurityException

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

/**
 * Typed [Serializer] that authenticates and encrypts [AppSettings] with Tink AES-256-GCM
 * using a fixed AAD namespace. Any tampering, truncation, or wrong-key decryption raises
 * [CorruptionException] so DataStore's [ReplaceFileCorruptionHandler] resets cleanly.
 */
internal class EncryptedAppSettingsSerializer(
    private val aead: AeadCipher
) : Serializer<AppSettings> {

    override val defaultValue: AppSettings = AppSettings()

    override suspend fun readFrom(input: InputStream): AppSettings {
        val ciphertext = readBounded(input, MAX_CIPHERTEXT_BYTES)
        if (ciphertext.isEmpty()) return defaultValue

        val plaintext = try {
            aead.decrypt(ciphertext, SETTINGS_AAD)
        } catch (e: GeneralSecurityException) {
            throw CorruptionException("Failed to decrypt encrypted app settings", e)
        }

        return try {
            DataInputStream(ByteArrayInputStream(plaintext)).use { dis ->
                val magic = dis.readInt()
                if (magic != MAGIC_HEADER) {
                    throw CorruptionException("Invalid app settings magic header: 0x${magic.toString(16)}")
                }
                val version = dis.readInt()
                if (version != SCHEMA_VERSION) {
                    throw CorruptionException("Unsupported app settings schema version: $version")
                }
                val settings = AppSettings(
                    defaultBlockAllMode = dis.readBoolean(),
                    autoRecordPcapOnVpnStart = dis.readBoolean(),
                    idsDnsPhishingEnabled = dis.readBoolean(),
                    idsHeuristicsEnabled = dis.readBoolean(),
                    idsBehavioralScanEnabled = dis.readBoolean(),
                    idsHttpDpiEnabled = dis.readBoolean(),
                    irLuminanceThreshold = dis.readInt(),
                    irChromaBiasThreshold = dis.readFloat(),
                    irUseFrontCamera = dis.readBoolean(),
                    rfCenterFreqMhz = dis.readDouble(),
                    rfSampleRateHz = dis.readInt(),
                    rfPeakThresholdDb = dis.readFloat()
                )
                if (dis.available() != 0) {
                    throw CorruptionException("Unexpected trailing bytes in app settings payload")
                }
                settings
            }
        } catch (e: EOFException) {
            throw CorruptionException("Truncated app settings payload", e)
        }
    }

    override suspend fun writeTo(t: AppSettings, output: OutputStream) {
        val baos = ByteArrayOutputStream(64)
        DataOutputStream(baos).use { dos ->
            dos.writeInt(MAGIC_HEADER)
            dos.writeInt(SCHEMA_VERSION)
            dos.writeBoolean(t.defaultBlockAllMode)
            dos.writeBoolean(t.autoRecordPcapOnVpnStart)
            dos.writeBoolean(t.idsDnsPhishingEnabled)
            dos.writeBoolean(t.idsHeuristicsEnabled)
            dos.writeBoolean(t.idsBehavioralScanEnabled)
            dos.writeBoolean(t.idsHttpDpiEnabled)
            dos.writeInt(t.irLuminanceThreshold)
            dos.writeFloat(t.irChromaBiasThreshold)
            dos.writeBoolean(t.irUseFrontCamera)
            dos.writeDouble(t.rfCenterFreqMhz)
            dos.writeInt(t.rfSampleRateHz)
            dos.writeFloat(t.rfPeakThresholdDb)
            dos.flush()
        }
        val ciphertext = aead.encrypt(baos.toByteArray(), SETTINGS_AAD)
        output.write(ciphertext)
        output.flush()
    }

    private fun readBounded(input: InputStream, maxBytes: Int): ByteArray {
        val baos = ByteArrayOutputStream()
        val buffer = ByteArray(4096)
        var total = 0
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read
            if (total > maxBytes) {
                throw CorruptionException("Encrypted app settings exceeded maximum size ($maxBytes bytes)")
            }
            baos.write(buffer, 0, read)
        }
        return baos.toByteArray()
    }

    companion object {
        private const val MAGIC_HEADER = 0x41444653 // "ADFS"
        private const val SCHEMA_VERSION = 1
        private const val MAX_CIPHERTEXT_BYTES = 64 * 1024
        private val SETTINGS_AAD = "org.aafw.firewall:app_settings:v1".toByteArray(Charsets.UTF_8)
    }
}

class PreferencesRepository internal constructor(
    private val dataStore: DataStore<AppSettings>,
    private val settingsFile: File? = null
) {
    constructor(context: Context) : this(
        dataStore = getOrCreateSharedDataStore(context.applicationContext),
        settingsFile = encryptedSettingsFile(context.applicationContext)
    )

    val settingsFlow: Flow<AppSettings> = dataStore.data

    private suspend fun updateSettings(transform: (AppSettings) -> AppSettings) {
        dataStore.updateData(transform)
        settingsFile?.let { DatabaseKeyManager.enforceOwnerOnlyFile(it) }
    }

    suspend fun setDefaultBlockAllMode(enabled: Boolean) {
        updateSettings { it.copy(defaultBlockAllMode = enabled) }
    }

    suspend fun setAutoRecordPcap(enabled: Boolean) {
        updateSettings { it.copy(autoRecordPcapOnVpnStart = enabled) }
    }

    suspend fun updateIdsToggle(
        dnsPhishing: Boolean? = null,
        heuristics: Boolean? = null,
        behavioral: Boolean? = null,
        httpDpi: Boolean? = null
    ) {
        updateSettings { current ->
            current.copy(
                idsDnsPhishingEnabled = dnsPhishing ?: current.idsDnsPhishingEnabled,
                idsHeuristicsEnabled = heuristics ?: current.idsHeuristicsEnabled,
                idsBehavioralScanEnabled = behavioral ?: current.idsBehavioralScanEnabled,
                idsHttpDpiEnabled = httpDpi ?: current.idsHttpDpiEnabled
            )
        }
    }

    suspend fun updateIrSettings(
        lumaThreshold: Int? = null,
        chromaBias: Float? = null,
        useFrontCamera: Boolean? = null
    ) {
        updateSettings { current ->
            current.copy(
                irLuminanceThreshold = lumaThreshold ?: current.irLuminanceThreshold,
                irChromaBiasThreshold = chromaBias ?: current.irChromaBiasThreshold,
                irUseFrontCamera = useFrontCamera ?: current.irUseFrontCamera
            )
        }
    }

    suspend fun updateRfSettings(
        centerFreqMhz: Double? = null,
        sampleRateHz: Int? = null,
        peakThresholdDb: Float? = null
    ) {
        updateSettings { current ->
            current.copy(
                rfCenterFreqMhz = centerFreqMhz ?: current.rfCenterFreqMhz,
                rfSampleRateHz = sampleRateHz ?: current.rfSampleRateHz,
                rfPeakThresholdDb = peakThresholdDb ?: current.rfPeakThresholdDb
            )
        }
    }

    companion object {
        private const val DATASTORE_DIR_NAME = "datastore"
        private const val ENCRYPTED_SETTINGS_FILE = "adf_settings.enc"
        private const val LEGACY_PLAINTEXT_PREFS_FILE = "adf_preferences.preferences_pb"

        private val storeLock = Any()

        @Volatile
        private var cachedStorePath: String? = null

        @Volatile
        private var cachedDataStore: DataStore<AppSettings>? = null

        private fun encryptedSettingsFile(appContext: Context): File {
            val dir = File(appContext.filesDir, DATASTORE_DIR_NAME).apply {
                mkdirs()
                DatabaseKeyManager.enforceOwnerOnlyDir(this)
            }
            return File(dir, ENCRYPTED_SETTINGS_FILE)
        }

        internal fun scrubLegacyPlaintextPreferences(appContext: Context) {
            val legacyFile = File(File(appContext.filesDir, DATASTORE_DIR_NAME), LEGACY_PLAINTEXT_PREFS_FILE)
            if (legacyFile.exists()) {
                DatabaseKeyManager.wipeAndDeleteFile(legacyFile)
            }
        }

        private fun getOrCreateSharedDataStore(appContext: Context): DataStore<AppSettings> {
            scrubLegacyPlaintextPreferences(appContext)
            val targetFile = encryptedSettingsFile(appContext)
            val canonicalPath = targetFile.canonicalPath
            if (cachedStorePath == canonicalPath) {
                cachedDataStore?.let { return it }
            }
            return synchronized(storeLock) {
                if (cachedStorePath == canonicalPath) {
                    cachedDataStore?.let { return@synchronized it }
                }
                if (targetFile.exists()) {
                    DatabaseKeyManager.enforceOwnerOnlyFile(targetFile)
                }

                val aead = TinkKeystoreProvider.getOrCreateAead(appContext)
                val store = DataStoreFactory.create(
                    serializer = EncryptedAppSettingsSerializer(aead),
                    corruptionHandler = ReplaceFileCorruptionHandler { AppSettings() },
                    scope = CoroutineScope(Dispatchers.IO + SupervisorJob()),
                    produceFile = { targetFile }
                )
                cachedStorePath = canonicalPath
                cachedDataStore = store
                store
            }
        }

        internal fun createForTest(
            file: File,
            aead: AeadCipher,
            scope: CoroutineScope
        ): PreferencesRepository {
            file.parentFile?.let { parent ->
                parent.mkdirs()
                DatabaseKeyManager.enforceOwnerOnlyDir(parent)
            }
            val store = DataStoreFactory.create(
                serializer = EncryptedAppSettingsSerializer(aead),
                corruptionHandler = ReplaceFileCorruptionHandler { AppSettings() },
                scope = scope,
                produceFile = { file }
            )
            return PreferencesRepository(dataStore = store, settingsFile = file)
        }
    }
}
