package cn.lc6464.fileencryptor

import android.net.Uri
import android.os.Bundle
import android.provider.OpenableColumns
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.WindowCompat
import androidx.lifecycle.lifecycleScope
import cn.lc6464.fileencryptor.databinding.ActivityMainBinding
import kotlinx.coroutines.*
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.InputStream
import java.io.OutputStream

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var passwordStorageManager: PasswordStorageManager

    // 临时文件处理阈值：64 MB
    private val TEMP_FILE_THRESHOLD_BYTES = 64 * 1024 * 1024
    private val TEMP_FILE_PREFIX = "crypt_temp_"

    // --- State Holders ---
    private var encryptionJob: Deferred<CryptoResult>? = null
    private var decryptionJob: Deferred<CryptoResult>? = null

    // --- Result Classes ---
    // 定义一个密封类来封装加解密操作的结果
    sealed class CryptoResult {
        // 成功时，携带临时文件或内存流
        data class Success(
            val tempFile: File?,
            val tempBytes: ByteArrayOutputStream?
        ) : CryptoResult()

        // 失败时，携带异常信息
        data class Failure(val error: Throwable) : CryptoResult()
    }

    // --- Activity Result Launchers ---
    private val pickFileLauncher =
        registerForActivityResult(ActivityResultContracts.GetContent()) { uri: Uri? ->
            uri?.let { onInputFileSelected(it) }
        }

    private val createFileLauncher =
        registerForActivityResult(ActivityResultContracts.CreateDocument("*/*")) { uri: Uri? ->
            if (uri != null) {
                // 根据哪个 job 不为空，来处理对应的结果
                when {
                    encryptionJob != null -> handleEncryptionResult(uri)
                    decryptionJob != null -> handleDecryptionResult(uri)
                }
            } else {
                // 用户取消了文件保存，取消所有可能正在进行的任务
                showToast("操作已取消")
                encryptionJob?.cancel()
                decryptionJob?.cancel()
                showLoading(false)
            }
        }

    // --- Lifecycle & Setup ---
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowCompat.setDecorFitsSystemWindows(window, false)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        passwordStorageManager = PasswordStorageManager(applicationContext)
        setupUIListeners()
        cleanupLeftoverTempFiles()
    }

    private fun setupUIListeners() {
        binding.savePasswordButton.setOnClickListener { handleSavePassword() }
        binding.getPasswordButton.setOnClickListener { handleGetPassword() }
        binding.processFileButton.setOnClickListener { handleProcessFile() }
    }

    private fun handleSavePassword() {
        val password = binding.passwordEditText.text.toString()
        if (password.isEmpty()) {
            showToast("请输入要保存的密码")
            return
        }
        passwordStorageManager.savePassword(password)
        showFeedbackOnButton(
            binding.savePasswordButton,
            getString(R.string.save_password_success),
            getString(R.string.save_password)
        )
    }

    private fun handleGetPassword() {
        val savedPassword = passwordStorageManager.getPassword()
        if (savedPassword != null) {
            binding.passwordEditText.setText(savedPassword)
            showFeedbackOnButton(
                binding.getPasswordButton,
                getString(R.string.get_password_success),
                getString(R.string.get_password)
            )
        } else {
            showFeedbackOnButton(
                binding.getPasswordButton,
                getString(R.string.get_password_notfound),
                getString(R.string.get_password)
            )
        }
    }

    private fun handleProcessFile() {
        val password = binding.passwordEditText.text.toString()
        if (password.isEmpty()) {
            showToast("请输入密码！")
            return
        }
        pickFileLauncher.launch("*/*")
    }

    private fun onInputFileSelected(inputUri: Uri) {
        val password = binding.passwordEditText.text.toString()
        if (password.isEmpty()) {
            showToast("请输入密码！")
            return
        }
        val inputFileName = getFileNameFromUri(inputUri) ?: "file"

        // 清理上一次操作可能遗留的状态
        encryptionJob = null
        decryptionJob = null

        if (!inputFileName.endsWith(".lcenc", ignoreCase = true)) {
            initiateEncryptionFlow(inputUri, password, inputFileName)
        } else {
            initiateDecryptionFlow(inputUri, password, inputFileName)
        }
    }

    // --- Encryption Flow ---
    private fun initiateEncryptionFlow(inputUri: Uri, password: String, inputFileName: String) {
        showLoading(true)
        // 1. 立即开始后台加密任务
        encryptionJob = startEncryptionAsync(inputUri, password, inputFileName)
        // 2. 同时弹出文件保存对话框
        val defaultOutputName = "${inputFileName.substringBeforeLast('.')}.lcenc"
        createFileLauncher.launch(defaultOutputName)
    }

    private fun startEncryptionAsync(
        inputUri: Uri,
        password: String,
        fileName: String
    ): Deferred<CryptoResult> {
        return lifecycleScope.async(Dispatchers.IO) {
            try {
                val result = processStream(inputUri) { inputStream, outputStream ->
                    CryptoManager.encrypt(inputStream, outputStream, password, fileName)
                }
                CryptoResult.Success(result.first, result.second)
            } catch (e: Exception) {
                CryptoResult.Failure(e)
            }
        }
    }

    private fun handleEncryptionResult(outputUri: Uri) {
        lifecycleScope.launch(Dispatchers.Main) {
            val result = encryptionJob?.await()
            writeResultToUri(result, outputUri)
        }
    }

    // --- Decryption Flow ---
    private fun initiateDecryptionFlow(inputUri: Uri, password: String, inputFileName: String) {
        showLoading(true)
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // 1. 预读取文件头信息，这是一个快速操作
                val info = contentResolver.openInputStream(inputUri)?.use {
                    CryptoManager.peekDecryptionInfo(it)
                } ?: throw Exception("无法打开输入文件进行预读取")

                // 2. 立即开始后台完整解密任务
                decryptionJob = startDecryptionAsync(inputUri, password)

                // 3. 使用预读取到的扩展名，在主线程弹出文件保存对话框
                val defaultOutputName =
                    "${inputFileName.removeSuffix(".lcenc")}.${info.extension}".trimEnd('.')
                withContext(Dispatchers.Main) {
                    createFileLauncher.launch(defaultOutputName)
                }

            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    showToast("解密准备失败: ${e.message}")
                    showLoading(false)
                }
            }
        }
    }

    private fun startDecryptionAsync(inputUri: Uri, password: String): Deferred<CryptoResult> {
        return lifecycleScope.async(Dispatchers.IO) {
            try {
                // 这里的 processor 函数体现在了 lambda 表达式中
                val result = processStream(inputUri) { inStream, outStream ->
                    CryptoManager.decrypt(inStream, outStream, password)
                }
                CryptoResult.Success(result.first, result.second)
            } catch (e: Exception) {
                CryptoResult.Failure(e)
            }
        }
    }

    private fun handleDecryptionResult(outputUri: Uri) {
        lifecycleScope.launch(Dispatchers.Main) {
            val result = decryptionJob?.await()
            writeResultToUri(result, outputUri)
        }
    }

    // --- Helper & Utility Functions ---

    /**
     * 通用的流处理函数，根据大小决定使用内存还是文件
     */
    private suspend fun processStream(
        inputUri: Uri,
        processor: (InputStream, OutputStream) -> Unit
    ): Pair<File?, ByteArrayOutputStream?> {
        return withContext(Dispatchers.IO) {
            val inputFileSize =
                contentResolver.openFileDescriptor(inputUri, "r")?.use { f -> f.statSize } ?: -1
            val inputStream =
                contentResolver.openInputStream(inputUri) ?: throw Exception("无法打开输入文件")

            var tempFile: File? = null
            var tempBytes: ByteArrayOutputStream? = null

            if (inputFileSize > TEMP_FILE_THRESHOLD_BYTES || inputFileSize == -1L) {
                tempFile = File.createTempFile(TEMP_FILE_PREFIX, ".tmp", cacheDir)
                FileOutputStream(tempFile).use { outStream ->
                    inputStream.use { inStream ->
                        processor(inStream, outStream)
                    }
                }
            } else {
                tempBytes = ByteArrayOutputStream()
                tempBytes.use { outStream ->
                    inputStream.use { inStream ->
                        processor(inStream, outStream)
                    }
                }
            }
            Pair(tempFile, tempBytes)
        }
    }

    /**
     * 将 CryptoResult 的内容写入目标 Uri
     */
    private suspend fun writeResultToUri(result: CryptoResult?, outputUri: Uri) {
        // 注意：这里的 coroutine context 已经是 Main dispatcher，
        // 但文件操作应该在 IO dispatcher 中进行，所以我们切换一下
        withContext(Dispatchers.IO) {
            when (result) {
                is CryptoResult.Success -> {
                    try {
                        contentResolver.openOutputStream(outputUri)?.use { outputStream ->
                            result.tempFile?.inputStream()?.use { it.copyTo(outputStream) }
                            result.tempBytes?.writeTo(outputStream)
                        }
                        withContext(Dispatchers.Main) { showToast("操作成功，文件已保存！") }
                    } catch (e: Exception) {
                        withContext(Dispatchers.Main) { showToast("保存文件失败: ${e.message}") }
                    } finally {
                        result.tempFile?.delete()
                    }
                }

                is CryptoResult.Failure -> {
                    val errorMessage = when (result.error) {
                        is SecurityException -> "处理失败：密码错误或文件已损坏。"
                        is IllegalArgumentException -> "处理失败：无效的文件格式。"
                        else -> "处理失败: ${result.error.message}"
                    }
                    withContext(Dispatchers.Main) { showToast(errorMessage) }
                }

                null -> withContext(Dispatchers.Main) { showToast("发生未知错误") }
            }
        }
        withContext(Dispatchers.Main) { showLoading(false) }
    }


    private fun getFileNameFromUri(uri: Uri): String? {
        var fileName: String? = null
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            if (cursor.moveToFirst()) {
                val displayNameIndex = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (displayNameIndex != -1) {
                    fileName = cursor.getString(displayNameIndex)
                }
            }
        }
        return fileName
    }

    private fun cleanupLeftoverTempFiles() {
        val tempFiles = cacheDir.listFiles { _, name -> name.startsWith(TEMP_FILE_PREFIX) }
        tempFiles?.forEach { it.delete() }
    }

    private fun showLoading(isLoading: Boolean) {
        binding.progressBar.visibility = if (isLoading) View.VISIBLE else View.GONE
        binding.processFileButton.isEnabled = !isLoading
        binding.savePasswordButton.isEnabled = !isLoading
        binding.getPasswordButton.isEnabled = !isLoading
    }

    private fun showToast(message: String) {
        Toast.makeText(this@MainActivity, message, Toast.LENGTH_LONG).show()
    }

    private fun showFeedbackOnButton(button: View, feedbackText: String, originalText: String) {
        val originalButton = button as? android.widget.Button
        originalButton?.text = feedbackText
        lifecycleScope.launch {
            delay(1500)
            originalButton?.text = originalText
        }
    }
}