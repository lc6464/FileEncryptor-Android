package cn.lc6464.fileencryptor

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.core.content.edit

class PasswordStorageManager(context: Context) {

    // 使用 MasterKey.Builder 替换已弃用的 MasterKeys.getOrCreate
    // 这是 Android Security 库推荐的现代方法。
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    // 使用接受 MasterKey 对象的 create 方法重载
    // 注意参数顺序也发生了变化 (context 现在是第一个参数)。
    private val sharedPreferences = EncryptedSharedPreferences.create(
        context, // 第一个参数是 Context
        "secret_shared_prefs", // 第二个参数是文件名
        masterKey, // 第三个参数是 MasterKey 对象
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    companion object {
        private const val KEY_PASSWORD = "password"
    }

    fun savePassword(password: String) {
        sharedPreferences.edit { putString(KEY_PASSWORD, password) }
    }

    fun getPassword(): String? {
        return sharedPreferences.getString(KEY_PASSWORD, null)
    }
}