package com.sshproxy.vpn.importer

import org.json.JSONObject
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/** الاستثناء الوحيد اللي كيطلع من MlConfigFile.parse - بلا تفاصيل داخلية. */
class MlConfigParseException(message: String) : Exception(message)

/**
 * تنسيق ملف .ml (كونفيغ قابل للمشاركة/الحفظ فـ Downloads):
 *
 *  بلا كلمة سر (FLAG_PLAIN):
 *   [0..3]  magic "MVCP"
 *   [4]     format version = 0x01
 *   [5]     flag = 0x00
 *   [6..]   JSON UTF-8 خام (بلا تشفير)
 *
 *  بكلمة سر (FLAG_ENCRYPTED):
 *   [0..3]  magic "MVCP"
 *   [4]     format version = 0x01
 *   [5]     flag = 0x01
 *   [6..21] salt (16 بايت، عشوائي)
 *   [22..33] IV ديال AES-GCM (12 بايت)
 *   [34..]  ciphertext (AES-256-GCM، GCM tag مزاد فالآخر تلقائيا)
 *
 * المفتاح فحالة التشفير: PBKDF2WithHmacSHA256(password, salt, 210000 iterations, 256-bit) -
 * أقوى من مفتاح ثابت لأنه مربوط بكلمة السر ديال المستخدم، وماشي مربوط
 * بالجهاز (بخلاف SecureConfigStore) حيت الملف خاصو يتفتح من جهاز آخر.
 */
internal object MlConfigFile {

    private val MAGIC = byteArrayOf('M'.code.toByte(), 'V'.code.toByte(), 'C'.code.toByte(), 'P'.code.toByte())
    private const val FORMAT_VERSION: Byte = 0x01
    private const val FLAG_PLAIN: Byte = 0x00
    private const val FLAG_ENCRYPTED: Byte = 0x01
    private const val PBKDF2_ITERATIONS = 210_000
    private const val SALT_LEN = 16
    private const val GCM_IV_LEN = 12
    private const val GCM_TAG_BITS = 128
    private const val HEADER_LEN = 6

    const val EXTENSION = "ml"

    data class Parsed(val name: String, val serverMessage: String, val fields: Map<String, Any?>)

    /** كيبني bytes ديال الملف. password فارغة/null = بلا تشفير. */
    fun build(name: String, serverMessage: String, fields: Map<String, Any?>, password: String?): ByteArray {
        val payload = JSONObject()
        payload.put("name", name)
        payload.put("msg", serverMessage)
        payload.put("t", System.currentTimeMillis())
        val fieldsJson = JSONObject()
        for ((k, v) in fields) {
            when (v) {
                null -> {}
                else -> fieldsJson.put(k, v)
            }
        }
        payload.put("fields", fieldsJson)
        val plaintext = payload.toString().toByteArray(Charsets.UTF_8)

        val header = ByteArray(HEADER_LEN)
        System.arraycopy(MAGIC, 0, header, 0, 4)
        header[4] = FORMAT_VERSION

        return if (password.isNullOrEmpty()) {
            header[5] = FLAG_PLAIN
            header + plaintext
        } else {
            header[5] = FLAG_ENCRYPTED
            val salt = ByteArray(SALT_LEN).also { SecureRandom().nextBytes(it) }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, deriveKey(password, salt))
            val iv = cipher.iv // 12 بايت، مولّدة عشوائيا
            val ciphertext = cipher.doFinal(plaintext)
            header + salt + iv + ciphertext
        }
    }

    fun isEncrypted(bytes: ByteArray): Boolean {
        validateHeader(bytes)
        return bytes[5] == FLAG_ENCRYPTED
    }

    /** password مطلوبة غير إلا كان isEncrypted(bytes) == true. */
    fun parse(bytes: ByteArray, password: String? = null): Parsed {
        validateHeader(bytes)
        val plaintext: ByteArray = if (bytes[5] == FLAG_PLAIN) {
            bytes.copyOfRange(HEADER_LEN, bytes.size)
        } else {
            if (password.isNullOrEmpty()) throw MlConfigParseException("password required")
            if (bytes.size < HEADER_LEN + SALT_LEN + GCM_IV_LEN) throw MlConfigParseException("truncated")
            val salt = bytes.copyOfRange(HEADER_LEN, HEADER_LEN + SALT_LEN)
            val iv = bytes.copyOfRange(HEADER_LEN + SALT_LEN, HEADER_LEN + SALT_LEN + GCM_IV_LEN)
            val ciphertext = bytes.copyOfRange(HEADER_LEN + SALT_LEN + GCM_IV_LEN, bytes.size)
            try {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, deriveKey(password, salt), GCMParameterSpec(GCM_TAG_BITS, iv))
                cipher.doFinal(ciphertext)
            } catch (_: Throwable) {
                // كلمة سر غالطة أو ملف متلاعب بيه - نفس الرسالة فالحالتين (fail-closed)
                throw MlConfigParseException("wrong password")
            }
        }
        return try {
            val json = JSONObject(String(plaintext, Charsets.UTF_8))
            val fieldsJson = json.optJSONObject("fields") ?: JSONObject()
            val fields = mutableMapOf<String, Any?>()
            val keys = fieldsJson.keys()
            while (keys.hasNext()) {
                val k = keys.next()
                fields[k] = fieldsJson.get(k)
            }
            Parsed(
                name = json.optString("name", ""),
                serverMessage = json.optString("msg", ""),
                fields = fields
            )
        } catch (_: Throwable) {
            throw MlConfigParseException("corrupt file")
        }
    }

    private fun validateHeader(bytes: ByteArray) {
        if (bytes.size < HEADER_LEN) throw MlConfigParseException("too short")
        if (!bytes.copyOfRange(0, 4).contentEquals(MAGIC)) throw MlConfigParseException("not a MR VPN TUNNEL config")
        if (bytes[4] != FORMAT_VERSION) throw MlConfigParseException("unsupported version")
    }

    private fun deriveKey(password: String, salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, 256)
        val skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val keyBytes = skf.generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, "AES")
    }
}

