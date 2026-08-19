package com.sshproxy.vpn.importer

import org.json.JSONObject
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/** الاستثناء الوحيد اللي كيطلع من MlConfigFile.parse - بلا تفاصيل داخلية. */
class MlConfigParseException(message: String) : Exception(message)

/** كيطلع من MlConfigFile.build() إلا كانت password أقصر من MIN_PASSWORD_LENGTH. */
class MlConfigWeakPasswordException(message: String) : Exception(message)

/**
 * تنسيق ملف .ml (كونفيغ قابل للمشاركة/الحفظ فـ Downloads):
 *
 *  بلا كلمة سر ديال المستخدم (FLAG_PLAIN):
 *   [0..3]  magic "MVCP"
 *   [4]     format version = 0x01
 *   [5]     flag = 0x00
 *   [6..17] IV ديال AES-GCM (12 بايت)
 *   [18..]  ciphertext (AES-256-GCM بمفتاح ثابت مدمج فالتطبيق - staticKey())
 *
 *   ملاحظة: "Unprotected" فالواجهة كيعني بلا طلب password من المستخدم
 *   جوا التطبيق - ماشي بلا تشفير خالص. المفتاح ثابت (نفسو لكل نسخة من
 *   التطبيق)، فالهدف هو منع الملف من كونو قابل للقراءة مباشرة فـFile
 *   Manager/محرر نصوص عادي (Server/UUID/Domain الحقيقيين)، ماشي حماية
 *   من reverse-engineering ديال التطبيق نفسو. الفك كيوقع بصمت جوا
 *   التطبيق بلا ما يطلب من المستخدم أي حاجة.
 *
 *  بكلمة سر ديال المستخدم (FLAG_ENCRYPTED):
 *   [0..3]  magic "MVCP"
 *   [4]     format version = 0x01
 *   [5]     flag = 0x01
 *   [6..21] salt (16 بايت، عشوائي)
 *   [22..33] IV ديال AES-GCM (12 بايت)
 *   [34..]  ciphertext (AES-256-GCM، GCM tag مزاد فالآخر تلقائيا)
 *
 * المفتاح فحالة التشفير بـpassword: PBKDF2WithHmacSHA256(password, salt,
 * 600000 iterations, 256-bit) - توصية OWASP 2023 لـPBKDF2-SHA256 (كانت
 * 210000 قبل هاد التعديل - شوف PBKDF2_ITERATIONS_LEGACY تحت للتوافق مع
 * الملفات المحمية القديمة). أقوى من مفتاح ثابت لأنه مربوط بكلمة السر
 * ديال المستخدم، وماشي مربوط بالجهاز (بخلاف SecureConfigStore) حيت
 * الملف خاصو يتفتح من جهاز آخر. الحد الأدنى لطول الـpassword (8 أحرف)
 * مفروض عند build() - أقوى تشفير مايفيدش حتى password ضعيفة يقدر
 * يتخمن بسرعة.
 *
 * توافق مع الملفات القديمة (بلا password، FLAG_PLAIN): قبل هاد التعديل،
 * FLAG_PLAIN كانت كتكتب JSON خام بلا أي تشفير (header + plaintext
 * مباشرة، بلا IV). parse() تحت كتجرب أولا الفك بـstaticKey() (الفورمات
 * الجديد)، وإلا فشل (طول الملف قصير بزاف، أو فشل AES-GCM tag) كترجع
 * للفورمات القديم (JSON خام) باش الملفات المحفوظة قبل هاد التعديل يبقاو
 * خدامين.
 *
 * توافق مع الملفات المحمية القديمة (بـpassword، FLAG_ENCRYPTED): الملفات
 * المتصاوبة قبل رفع الـiterations كانت مبنية بـ210000 - عدد الـ
 * iterations ماشي مخزن جوا الملف نفسو، فparse() كتجرب PBKDF2_ITERATIONS
 * الجديد (600000) أولا، وإلا فشل الفك (AES-GCM tag) كتعاود بـ
 * PBKDF2_ITERATIONS_LEGACY (210000) قبل ما تقول "password غالطة".
 */
internal object MlConfigFile {

    private val MAGIC = byteArrayOf('M'.code.toByte(), 'V'.code.toByte(), 'C'.code.toByte(), 'P'.code.toByte())
    private const val FORMAT_VERSION: Byte = 0x01
    private const val FLAG_PLAIN: Byte = 0x00
    private const val FLAG_ENCRYPTED: Byte = 0x01
    private const val PBKDF2_ITERATIONS = 600_000
    private const val PBKDF2_ITERATIONS_LEGACY = 210_000
    // الحد الأدنى لطول password عند إنشاء كونفيغ محمي - بلا هادشي، AES-256
    // مايفيدش حتى password قصيرة/سهلة التخمين (بحال "1234").
    const val MIN_PASSWORD_LENGTH = 8
    private const val SALT_LEN = 16
    private const val GCM_IV_LEN = 12
    private const val GCM_TAG_BITS = 128
    private const val HEADER_LEN = 6

    const val EXTENSION = "ml"

    // مفتاح ثابت مدمج فالتطبيق - كيتحسب من SHA-256 ديال جملة ثابتة (ماشي
    // مخزن كـbytes خام مباشرة، بلا فايدة أمنية حقيقية زايدة، غير باش
    // ماشي أول حاجة بانة فـstrings ديال الـAPK). Static فكل نسخة من
    // التطبيق - أي ملف "Unprotected" مبني من أي جهاز يتفك من أي جهاز
    // آخر فيه نفس التطبيق، بلا ما يحتاج password.
    private val STATIC_KEY_PASSPHRASE = "MRVPNTUNNEL_UNPROTECTED_CONFIG_STATIC_KEY_V1"

    private fun staticKey(): SecretKeySpec {
        val digest = MessageDigest.getInstance("SHA-256").digest(STATIC_KEY_PASSPHRASE.toByteArray(Charsets.UTF_8))
        return SecretKeySpec(digest, "AES")
    }

    data class Parsed(val name: String, val serverMessage: String, val fields: Map<String, Any?>)

    /**
     * كيبني bytes ديال الملف. password فارغة/null = بلا password ديال
     * المستخدم (مشفرة بمفتاح ثابت، بلا طلب password جوا التطبيق).
     * إلا كانت password غير فارغة لكن أقصر من MIN_PASSWORD_LENGTH،
     * كيطلع MlConfigWeakPasswordException - أقوى تشفير (AES-256) ماخصوش
     * يبني على password ضعيفة سهلة التخمين.
     */
    fun build(name: String, serverMessage: String, fields: Map<String, Any?>, password: String?): ByteArray {
        if (!password.isNullOrEmpty() && password.length < MIN_PASSWORD_LENGTH) {
            throw MlConfigWeakPasswordException("password must be at least $MIN_PASSWORD_LENGTH characters")
        }
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
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, staticKey())
            val iv = cipher.iv
            val ciphertext = cipher.doFinal(plaintext)
            header + iv + ciphertext
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
            decryptPlainFlagged(bytes)
        } else {
            if (password.isNullOrEmpty()) throw MlConfigParseException("password required")
            if (bytes.size < HEADER_LEN + SALT_LEN + GCM_IV_LEN) throw MlConfigParseException("truncated")
            val salt = bytes.copyOfRange(HEADER_LEN, HEADER_LEN + SALT_LEN)
            val iv = bytes.copyOfRange(HEADER_LEN + SALT_LEN, HEADER_LEN + SALT_LEN + GCM_IV_LEN)
            val ciphertext = bytes.copyOfRange(HEADER_LEN + SALT_LEN + GCM_IV_LEN, bytes.size)
            // كنجربو عدد iterations الجديد (600000) أولا - كل الملفات
            // المتصاوبة من دابا مبنية بيه. إلا فشل (ملف قديم مبني بـ210000
            // قبل هاد التعديل)، كنعاودو بالرقم القديم قبل ما نقولو
            // "password غالطة" - عدد الـiterations ماشي مخزن جوا الملف
            // نفسو، فماكاين حتى طريقة نعرفو أي واحد فيهم غير بالتجربة.
            try {
                decryptWithIterations(ciphertext, password, salt, iv, PBKDF2_ITERATIONS)
            } catch (_: Throwable) {
                try {
                    decryptWithIterations(ciphertext, password, salt, iv, PBKDF2_ITERATIONS_LEGACY)
                } catch (_: Throwable) {
                    // كلمة سر غالطة أو ملف متلاعب بيه - نفس الرسالة فالحالتين (fail-closed)
                    throw MlConfigParseException("wrong password")
                }
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

    /**
     * FLAG_PLAIN: تجرب الفورمات الجديد أولا (IV + AES-GCM بمفتاح ثابت) -
     * إلا فشلت (ملف قديم محفوظ قبل هاد التعديل: JSON خام بلا IV/تشفير)،
     * كترجع لبالفورمات القديم مباشرة. هادشي كيضمن ملفات "Unprotected"
     * القديمة تبقى خدامة بلا ما يحتاج المستخدم يعاود يصاوبهم.
     */
    private fun decryptPlainFlagged(bytes: ByteArray): ByteArray {
        if (bytes.size >= HEADER_LEN + GCM_IV_LEN) {
            try {
                val iv = bytes.copyOfRange(HEADER_LEN, HEADER_LEN + GCM_IV_LEN)
                val ciphertext = bytes.copyOfRange(HEADER_LEN + GCM_IV_LEN, bytes.size)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, staticKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
                val result = cipher.doFinal(ciphertext)
                // تحقق إضافي: النتيجة خاصها تكون JSON صحيح، وإلا فهاد
                // الملف كان قديم (JSON خام) وصادف طولو كافي لهاد الفرع
                // بلا ما يكون فعلا مشفر - نرجعو لبالفورمات القديم تحت.
                JSONObject(String(result, Charsets.UTF_8))
                return result
            } catch (_: Throwable) {
                // مشيش - نجربو الفورمات القديم تحت
            }
        }
        // الفورمات القديم: JSON خام مباشرة من بعد الـheader
        return bytes.copyOfRange(HEADER_LEN, bytes.size)
    }

    private fun validateHeader(bytes: ByteArray) {
        if (bytes.size < HEADER_LEN) throw MlConfigParseException("too short")
        if (!bytes.copyOfRange(0, 4).contentEquals(MAGIC)) throw MlConfigParseException("not a MR VPN TUNNEL config")
        if (bytes[4] != FORMAT_VERSION) throw MlConfigParseException("unsupported version")
    }

    /** كيفك AES-GCM بعدد iterations محدد - مستعملة من parse() باش تجرب PBKDF2_ITERATIONS ثم PBKDF2_ITERATIONS_LEGACY. */
    private fun decryptWithIterations(ciphertext: ByteArray, password: String, salt: ByteArray, iv: ByteArray, iterations: Int): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(password, salt, iterations), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ciphertext)
    }

    /** build() ديما كيستعمل PBKDF2_ITERATIONS (الجديد) - iterations هنا كـparameter غير باش parse() تقدر تجرب القديم. */
    private fun deriveKey(password: String, salt: ByteArray, iterations: Int = PBKDF2_ITERATIONS): SecretKeySpec {
        val spec = PBEKeySpec(password.toCharArray(), salt, iterations, 256)
        val skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val keyBytes = skf.generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, "AES")
    }
}
