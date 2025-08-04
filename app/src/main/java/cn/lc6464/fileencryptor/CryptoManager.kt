package cn.lc6464.fileencryptor

import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.text.Charsets.UTF_8

object CryptoManager {

    private const val ALGORITHM = "AES"
    private const val TRANSFORMATION = "AES/CBC/PKCS7Padding"
    private const val HMAC_ALGORITHM = "HmacSHA256"
    private const val IV_LENGTH_BYTES = 16
    private const val FILE_MAGIC_NUMBER = "LCEN"

    data class DecryptionInfo(val extension: String, val iv: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as DecryptionInfo

            if (extension != other.extension) return false
            if (!iv.contentEquals(other.iv)) return false

            return true
        }

        override fun hashCode(): Int {
            var result = extension.hashCode()
            result = 31 * result + iv.contentHashCode()
            return result
        }
    }

    // 生成一个随机的16字节IV
    private fun generateIv(): ByteArray {
        val iv = ByteArray(IV_LENGTH_BYTES)
        SecureRandom().nextBytes(iv)
        return iv
    }

    /**
     * 这部分是与 .NET 实现兼容的关键。
     * 使用 IV 作为 HMAC-SHA256 的密钥来哈希密码。
     */
    private fun hashPasswordWithIv(password: String, iv: ByteArray): SecretKeySpec {
        val hmac = Mac.getInstance(HMAC_ALGORITHM)
        // HMAC的密钥是IV
        val hmacKey = SecretKeySpec(iv, HMAC_ALGORITHM)
        hmac.init(hmacKey)
        // HMAC计算的数据是密码
        val keyBytes = hmac.doFinal(password.toByteArray(UTF_8))
        // 返回一个用于AES的密钥
        return SecretKeySpec(keyBytes, ALGORITHM)
    }

    /**
     * 预读取解密信息。
     * 只读取文件头，获取扩展名和IV，然后将流关闭。
     * 用于在解密整个文件前获取必要信息。
     * @throws Exception 如果文件格式不正确或已损坏。
     */
    fun peekDecryptionInfo(inputStream: InputStream): DecryptionInfo {
        inputStream.use { // use 会确保流在结束时被关闭
            val headerBuffer = ByteArray(4)
            if (it.read(headerBuffer) != 4 || String(headerBuffer, UTF_8) != FILE_MAGIC_NUMBER) {
                throw IllegalArgumentException("无效的文件格式。")
            }

            val extensionLength = it.read()
            if (extensionLength == -1) throw IllegalArgumentException("文件已损坏：无法读取扩展名长度。")

            val extension = if (extensionLength > 0) {
                val extensionBytes = ByteArray(extensionLength)
                if (it.read(extensionBytes) != extensionLength) throw IllegalArgumentException("文件已损坏：扩展名数据不完整。")
                String(extensionBytes, UTF_8)
            } else {
                ""
            }

            val iv = ByteArray(IV_LENGTH_BYTES)
            if (it.read(iv) != IV_LENGTH_BYTES) throw IllegalArgumentException("文件已损坏：IV数据不完整。")

            return DecryptionInfo(extension, iv)
        }
    }

    /**
     * 加密文件
     */
    fun encrypt(
        inputStream: InputStream,
        outputStream: OutputStream,
        password: String,
        originalFileName: String
    ) {
        val iv = generateIv()
        val keySpec = hashPasswordWithIv(password, iv)
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, keySpec, IvParameterSpec(iv))
        }

        // 写入文件头
        val extension = File(originalFileName).extension
        val extensionBytes = extension.toByteArray(UTF_8)

        outputStream.write(FILE_MAGIC_NUMBER.toByteArray(UTF_8)) // 4字节魔法数
        outputStream.write(extensionBytes.size) // 1字节扩展名长度
        outputStream.write(extensionBytes) // 扩展名
        outputStream.write(iv) // 16字节IV

        // 使用 CipherOutputStream 进行流式加密
        val cipherOut = CipherOutputStream(outputStream, cipher)
        inputStream.copyTo(cipherOut)
        cipherOut.flush()
        cipherOut.close() // 非常重要：会写入最后的padding
    }

    /**
     * 解密文件
     * @return 返回原始文件扩展名
     */
    @Throws(Exception::class)
    fun decrypt(inputStream: InputStream, outputStream: OutputStream, password: String): String {
        val headerBuffer = ByteArray(4)
        inputStream.read(headerBuffer)

        // 验证魔法数
        if (String(headerBuffer, UTF_8) != FILE_MAGIC_NUMBER) {
            throw IllegalArgumentException("无效的文件格式。")
        }

        // 读取扩展名
        val extensionLength = inputStream.read()
        if (extensionLength == -1) throw IllegalArgumentException("文件已损坏：无法读取扩展名长度。")
        val extension = if (extensionLength > 0) {
            val extensionBytes = ByteArray(extensionLength)
            inputStream.read(extensionBytes)
            String(extensionBytes, UTF_8)
        } else {
            ""
        }

        // 读取IV并生成密钥
        val iv = ByteArray(IV_LENGTH_BYTES)
        inputStream.read(iv)
        val keySpec = hashPasswordWithIv(password, iv)

        // 初始化Cipher进行解密
        val cipher = Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, keySpec, IvParameterSpec(iv))
        }

        // 使用 CipherInputStream 进行流式解密
        // 如果密码错误，在读取数据时会抛出 BadPaddingException
        try {
            val cipherIn = CipherInputStream(inputStream, cipher)
            cipherIn.copyTo(outputStream)
            cipherIn.close()
        } catch (e: Exception) {
            // 将 javax.crypto.BadPaddingException 等异常统一包装
            throw SecurityException("解密失败，可能是密码错误或文件已损坏。", e)
        }

        return extension
    }
}