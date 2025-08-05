package cn.lc6464.fileencryptor

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.core.content.edit
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * 这是一个辅助类，负责所有与 Android Keystore 交互的加密和解密操作。
 * 它将密钥安全地存储在硬件支持的 Keystore 中。
 */
private class CryptoHelper {

    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    private fun getSecretKey(alias: String): SecretKey {
        return (keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.secretKey
            ?: generateSecretKey(alias)
    }

    private fun generateSecretKey(alias: String): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        val parameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        keyGenerator.init(parameterSpec)
        return keyGenerator.generateKey()
    }

    fun encrypt(data: String, keyAlias: String): Pair<ByteArray, ByteArray> {
        val key = getSecretKey(keyAlias)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val encryptedData = cipher.doFinal(data.toByteArray(StandardCharsets.UTF_8))
        return Pair(cipher.iv, encryptedData)
    }

    fun decrypt(iv: ByteArray, encryptedData: ByteArray, keyAlias: String): String {
        val key = getSecretKey(keyAlias)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, iv) // GCM 认证标签长度为 128 位
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        val decryptedData = cipher.doFinal(encryptedData)
        return String(decryptedData, StandardCharsets.UTF_8)
    }
}


/**
 * 使用平台原生 API (AndroidKeyStore 和 SharedPreferences) 来安全地存储密码。
 * 这取代了已弃用的 EncryptedSharedPreferences。
 */
class PasswordStorageManager(context: Context) {

    private val cryptoHelper = CryptoHelper()
    private val sharedPreferences =
        context.getSharedPreferences("secure_prefs", Context.MODE_PRIVATE)

    companion object {
        private const val KEY_ALIAS_PASSWORD = "password_key_alias"
        private const val PREF_KEY_ENCRYPTED_PASSWORD = "encrypted_password"
        private const val PREF_KEY_PASSWORD_IV = "password_iv"
    }

    fun savePassword(password: String) {
        try {
            val (iv, encryptedPassword) = cryptoHelper.encrypt(password, KEY_ALIAS_PASSWORD)
            sharedPreferences.edit {
                putString(
                    PREF_KEY_PASSWORD_IV,
                    android.util.Base64.encodeToString(iv, android.util.Base64.NO_WRAP)
                )
                putString(
                    PREF_KEY_ENCRYPTED_PASSWORD,
                    android.util.Base64.encodeToString(
                        encryptedPassword,
                        android.util.Base64.NO_WRAP
                    )
                )
            }
        } catch (e: Exception) {
            // 在这里处理加密失败的异常，例如记录日志
            e.printStackTrace()
        }
    }

    fun getPassword(): String? {
        return try {
            val ivString = sharedPreferences.getString(PREF_KEY_PASSWORD_IV, null)
            val encryptedPasswordString =
                sharedPreferences.getString(PREF_KEY_ENCRYPTED_PASSWORD, null)

            if (ivString != null && encryptedPasswordString != null) {
                val iv = android.util.Base64.decode(ivString, android.util.Base64.NO_WRAP)
                val encryptedPassword =
                    android.util.Base64.decode(encryptedPasswordString, android.util.Base64.NO_WRAP)
                cryptoHelper.decrypt(iv, encryptedPassword, KEY_ALIAS_PASSWORD)
            } else {
                null
            }
        } catch (e: Exception) {
            // 在这里处理解密失败的异常
            e.printStackTrace()
            // 如果解密失败（例如密钥已更改或数据损坏），最好清除旧数据
            sharedPreferences.edit {
                remove(PREF_KEY_PASSWORD_IV)
                remove(PREF_KEY_ENCRYPTED_PASSWORD)
            }
            null
        }
    }
}