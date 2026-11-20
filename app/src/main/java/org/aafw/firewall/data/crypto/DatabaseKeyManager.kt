package org.aafw.firewall.data.crypto

import android.content.Context
import java.io.File
import java.security.GeneralSecurityException
import java.security.SecureRandom
import java.util.Arrays

/**
 * Generates, wraps, and retrieves the 256-bit random SQLCipher database passphrase
 * using Tink AES-256-GCM + Android Keystore with purpose-bound Associated Data (AAD).
 */
object DatabaseKeyManager {
    const val ENCRYPTED_DB_NAME = "another_droid_firewall_enc.db"
    const val LEGACY_PLAINTEXT_DB_NAME = "another_droid_firewall.db"

    private const val CRYPTO_DIR_NAME = "crypto"
    private const val KEY_FILE_NAME = "room_db_key_v1.enc"
    private const val PASSPHRASE_LENGTH_BYTES = 32
    private val DB_KEY_AAD = "org.aafw.firewall:sqlcipher_passphrase:v1".toByteArray(Charsets.UTF_8)

    private val lock = Any()
    private val secureRandom = SecureRandom()

    fun getOrCreatePassphrase(
        context: Context,
        aead: AeadCipher = TinkKeystoreProvider.getOrCreateAead(context)
    ): ByteArray = synchronized(lock) {
        val appContext = context.applicationContext
        val cryptoDir = File(appContext.filesDir, CRYPTO_DIR_NAME).apply {
            mkdirs()
            enforceOwnerOnlyDir(this)
        }
        val keyFile = File(cryptoDir, KEY_FILE_NAME)

        if (keyFile.exists() && keyFile.length() > 0L) {
            try {
                val ciphertext = keyFile.readBytes()
                val plaintext = aead.decrypt(ciphertext, DB_KEY_AAD)
                if (plaintext.size == PASSPHRASE_LENGTH_BYTES) {
                    return@synchronized plaintext
                }
                Arrays.fill(plaintext, 0)
            } catch (_: GeneralSecurityException) {
                // Wrapped key cannot be decrypted (e.g. Keystore invalidated).
                // Remove unreadable key and undecryptable DB so fresh encrypted storage can be initialized.
                wipeAndDeleteFile(keyFile)
                deleteDatabaseFamily(appContext, ENCRYPTED_DB_NAME)
            } catch (_: Exception) {
                wipeAndDeleteFile(keyFile)
                deleteDatabaseFamily(appContext, ENCRYPTED_DB_NAME)
            }
        }

        val rawPassphrase = ByteArray(PASSPHRASE_LENGTH_BYTES)
        secureRandom.nextBytes(rawPassphrase)
        val encrypted = aead.encrypt(rawPassphrase, DB_KEY_AAD)

        val tempFile = File(cryptoDir, "$KEY_FILE_NAME.tmp")
        try {
            if (!tempFile.exists()) {
                tempFile.createNewFile()
            }
            enforceOwnerOnlyFile(tempFile)
            tempFile.writeBytes(encrypted)
            enforceOwnerOnlyFile(tempFile)
            if (!tempFile.renameTo(keyFile)) {
                keyFile.writeBytes(encrypted)
            }
            enforceOwnerOnlyFile(keyFile)
        } finally {
            if (tempFile.exists()) {
                wipeAndDeleteFile(tempFile)
            }
        }

        return@synchronized rawPassphrase
    }

    /**
     * Overwrites and removes legacy unencrypted Room SQLite files (`.db`, `-wal`, `-shm`, `-journal`)
     * so historical plaintext telemetry/alerts do not linger on disk after upgrading to SQLCipher.
     */
    fun scrubLegacyPlaintextDatabase(
        context: Context,
        legacyDbName: String = LEGACY_PLAINTEXT_DB_NAME
    ) {
        deleteDatabaseFamily(context.applicationContext, legacyDbName)
    }

    private fun deleteDatabaseFamily(context: Context, dbName: String) {
        val baseDb = context.getDatabasePath(dbName) ?: return
        val candidates = listOf(
            baseDb,
            File("${baseDb.absolutePath}-wal"),
            File("${baseDb.absolutePath}-shm"),
            File("${baseDb.absolutePath}-journal")
        )
        for (file in candidates) {
            if (file.exists()) {
                wipeAndDeleteFile(file)
            }
        }
    }

    internal fun wipeAndDeleteFile(file: File) {
        runCatching {
            if (file.isFile) {
                val len = file.length()
                if (len in 1L..(16L * 1024L * 1024L)) {
                    val zeros = ByteArray(minOf(len.toInt(), 8192))
                    file.outputStream().use { out ->
                        var remaining = len
                        while (remaining > 0L) {
                            val chunk = minOf(remaining, zeros.size.toLong()).toInt()
                            out.write(zeros, 0, chunk)
                            remaining -= chunk
                        }
                        out.flush()
                    }
                }
            }
            file.delete()
        }
    }

    internal fun enforceOwnerOnlyFile(file: File) {
        runCatching {
            file.setReadable(false, false)
            file.setWritable(false, false)
            file.setExecutable(false, false)
            file.setReadable(true, true)
            file.setWritable(true, true)
        }
    }

    internal fun enforceOwnerOnlyDir(dir: File) {
        runCatching {
            dir.setReadable(false, false)
            dir.setWritable(false, false)
            dir.setExecutable(false, false)
            dir.setReadable(true, true)
            dir.setWritable(true, true)
            dir.setExecutable(true, true)
        }
    }
}
