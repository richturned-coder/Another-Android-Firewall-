package org.aafw.firewall.data.crypto

import android.annotation.SuppressLint
import android.content.Context
import android.os.Build
import com.google.crypto.tink.Aead
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.RegistryConfiguration
import com.google.crypto.tink.aead.AeadConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import java.io.IOException
import java.security.GeneralSecurityException

/**
 * Authenticated encryption (AEAD) abstraction for data-at-rest protection.
 * Backed by Google Tink AES-256-GCM wrapped with an Android Keystore master key on devices.
 */
interface AeadCipher {
    @Throws(GeneralSecurityException::class)
    fun encrypt(plaintext: ByteArray, associatedData: ByteArray): ByteArray

    @Throws(GeneralSecurityException::class)
    fun decrypt(ciphertext: ByteArray, associatedData: ByteArray): ByteArray
}

class TinkAeadCipher(private val aead: Aead) : AeadCipher {
    override fun encrypt(plaintext: ByteArray, associatedData: ByteArray): ByteArray =
        aead.encrypt(plaintext, associatedData)

    override fun decrypt(ciphertext: ByteArray, associatedData: ByteArray): ByteArray =
        aead.decrypt(ciphertext, associatedData)
}

object TinkKeystoreProvider {
    private const val MASTER_KEY_ALIAS = "org_aafw_firewall_master_key_v1"
    private const val KEYSET_NAME = "org_aafw_firewall_aead_keyset_v1"
    private const val KEYSET_PREF_FILE = "org_aafw_firewall_tink_keyset_prefs"
    private const val KEY_TEMPLATE_NAME = "AES256_GCM"

    private val lock = Any()

    @Volatile
    private var tinkRegistered = false

    @Volatile
    private var cachedAead: AeadCipher? = null

    private fun ensureTinkRegistered() {
        if (!tinkRegistered) {
            synchronized(lock) {
                if (!tinkRegistered) {
                    AeadConfig.register()
                    tinkRegistered = true
                }
            }
        }
    }

    internal fun isRobolectricHost(): Boolean =
        Build.FINGERPRINT.equals("robolectric", ignoreCase = true)

    /**
     * Returns a process-wide Tink AES-256-GCM [AeadCipher] wrapped by Android Keystore.
     *
     * On real Android devices, fails closed if Keystore-backed keyset creation cannot succeed
     * (never falls back to unencrypted storage). Under Robolectric JVM tests where
     * AndroidKeyStore is absent, uses a real in-memory Tink AES-256-GCM keyset.
     */
    fun getOrCreateAead(context: Context): AeadCipher {
        cachedAead?.let { return it }
        synchronized(lock) {
            cachedAead?.let { return it }
            ensureTinkRegistered()

            val cipher = if (isRobolectricHost()) {
                createInMemoryForTest()
            } else {
                createAndroidKeystoreAead(context.applicationContext)
            }
            cachedAead = cipher
            return cipher
        }
    }

    @SuppressLint("ApplySharedPref")
    private fun createAndroidKeystoreAead(appContext: Context): AeadCipher {
        val masterKeyUri = "android-keystore://$MASTER_KEY_ALIAS"
        val keysetHandle = try {
            buildKeysetManager(appContext, masterKeyUri).keysetHandle
        } catch (_: GeneralSecurityException) {
            // Keystore key invalidated or orphaned keyset restored from backup: reset keyset prefs and regenerate
            appContext.getSharedPreferences(KEYSET_PREF_FILE, Context.MODE_PRIVATE)
                .edit()
                .clear()
                .commit()
            buildKeysetManager(appContext, masterKeyUri).keysetHandle
        } catch (_: IOException) {
            appContext.getSharedPreferences(KEYSET_PREF_FILE, Context.MODE_PRIVATE)
                .edit()
                .clear()
                .commit()
            buildKeysetManager(appContext, masterKeyUri).keysetHandle
        }
        val aead = keysetHandle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
        return TinkAeadCipher(aead)
    }

    private fun buildKeysetManager(appContext: Context, masterKeyUri: String): AndroidKeysetManager {
        return AndroidKeysetManager.Builder()
            .withSharedPref(appContext, KEYSET_NAME, KEYSET_PREF_FILE)
            .withKeyTemplate(KeyTemplates.get(KEY_TEMPLATE_NAME))
            .withMasterKeyUri(masterKeyUri)
            .build()
    }

    /**
     * Creates a fresh real Tink AES-256-GCM [AeadCipher] in memory for unit/Robolectric tests.
     */
    internal fun createInMemoryForTest(): AeadCipher {
        ensureTinkRegistered()
        val handle = KeysetHandle.generateNew(KeyTemplates.get(KEY_TEMPLATE_NAME))
        val aead = handle.getPrimitive(RegistryConfiguration.get(), Aead::class.java)
        return TinkAeadCipher(aead)
    }
}
