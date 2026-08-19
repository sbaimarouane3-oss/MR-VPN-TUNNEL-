package com.sshproxy.vpn.importer

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
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
 * تنسيق .ml مع ملكية مرتبطة بالجهاز:
 * - الإصدار 2: المحتوى مشفر كما قبل، وفوق ذلك كيتوقع بواسطة Private Key
 *   الموجود في Android Keystore. الـPrivate Key ما كيدخلش للملف نهائيا.
 * - الإصدار 1: ملفات قديمة تبقى قابلة للقراءة للتوافق، ولكن ما كتعتبرش
 *   Owner Config وبالتالي ما عندهاش صلاحية Edit على النظام الجديد.
 */
internal object MlConfigFile {

    private val MAGIC = byteArrayOf('M'.code.toByte(), 'V'.code.toByte(), 'C'.code.toByte(), 'P'.code.toByte())
    private const val FORMAT_VERSION_LEGACY: Byte = 0x01
    private const val FORMAT_VERSION: Byte = 0x02
    private const val FLAG_PLAIN: Byte = 0x00
    private const val FLAG_ENCRYPTED: Byte = 0x01
    private const val PBKDF2_ITERATIONS = 600_000
    private const val PBKDF2_ITERATIONS_LEGACY = 210_000
    const val MIN_PASSWORD_LENGTH = 8
    private const val SALT_LEN = 16
    private const val GCM_IV_LEN = 12
    private const val GCM_TAG_BITS = 128
    private const val HEADER_LEN = 6
    private const val KEY_ALIAS = "mr_vpn_tunnel_ml_owner_v1"
    private const val SIG_ALGORITHM = "SHA256withECDSA"
    private const val EC_CURVE = "secp256r1"

    const val EXTENSION = "ml"

    private val STATIC_KEY_PASSPHRASE = "MRVPNTUNNEL_UNPROTECTED_CONFIG_STATIC_KEY_V1"

    data class Parsed(
        val name: String,
        val serverMessage: String,
        val fields: Map<String, Any?>,
        /** true فقط إذا كان الملف من فورمات الملكية الجديد وفيه توقيع صالح. */
        val isSigned: Boolean = false,
        /** بصرف النظر عن الجهاز: true إذا كان توقيع الملف صالحاً. */
        val signatureValid: Boolean = false,
        /** true فقط إذا كان Public Key ديال الملف مطابق للمفتاح المحلي في Keystore. */
        val ownerPublicKey: String? = null
    )

    private fun staticKey(): SecretKeySpec {
        val digest = MessageDigest.getInstance("SHA-256").digest(STATIC_KEY_PASSPHRASE.toByteArray(Charsets.UTF_8))
        return SecretKeySpec(digest, "AES")
    }

    /**
     * كينشئ/يضمن مفتاح الملكية داخل Android Keystore. المفتاح الخاص
     * non-exportable وكيستعمل غير للتوقيع.
     */
    private fun ensureOwnerKeyPair(context: Context): KeyStore {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
            val spec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec(EC_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(false)
                .build()
            generator.initialize(spec)
            generator.generateKeyPair()
        }
        return keyStore
    }

    private fun localPublicKeyBase64(context: Context): String {
        val ks = ensureOwnerKeyPair(context)
        val cert = ks.getCertificate(KEY_ALIAS) ?: throw IllegalStateException("owner key unavailable")
        return Base64.encodeToString(cert.publicKey.encoded, Base64.NO_WRAP)
    }

    private fun sign(context: Context, data: ByteArray): String {
        val ks = ensureOwnerKeyPair(context)
        val privateKey = ks.getKey(KEY_ALIAS, null) as? java.security.PrivateKey
            ?: throw IllegalStateException("owner private key unavailable")
        val signature = Signature.getInstance(SIG_ALGORITHM)
        signature.initSign(privateKey)
        signature.update(data)
        return Base64.encodeToString(signature.sign(), Base64.NO_WRAP)
    }

    private fun verifySignature(publicKeyBase64: String, signatureBase64: String, data: ByteArray): Boolean {
        return try {
            val publicKeyBytes = Base64.decode(publicKeyBase64, Base64.DEFAULT)
            val signatureBytes = Base64.decode(signatureBase64, Base64.DEFAULT)
            val keyFactory = java.security.KeyFactory.getInstance("EC")
            val publicKey = keyFactory.generatePublic(X509EncodedKeySpec(publicKeyBytes))
            val verifier = Signature.getInstance(SIG_ALGORITHM)
            verifier.initVerify(publicKey)
            verifier.update(data)
            verifier.verify(signatureBytes)
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * true = هذا الجهاز هو Owner الحقيقي للملف.
     * لا نعتمد على Android ID/IMEI/MAC؛ المقارنة مبنية على Public Key المقابل
     * لـPrivate Key الموجود في Android Keystore.
     */
    fun isOwner(context: Context, parsed: Parsed): Boolean {
        if (!parsed.isSigned || !parsed.signatureValid || parsed.ownerPublicKey.isNullOrBlank()) return false
        return try {
            MessageDigest.isEqual(
                Base64.decode(parsed.ownerPublicKey, Base64.DEFAULT),
                Base64.decode(localPublicKeyBase64(context), Base64.DEFAULT)
            )
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * يبني ملف .ml جديد وموقع بملكية الجهاز الحالي.
     */
    fun build(context: Context, name: String, serverMessage: String, fields: Map<String, Any?>, password: String?): ByteArray {
        if (!password.isNullOrEmpty() && password.length < MIN_PASSWORD_LENGTH) {
            throw MlConfigWeakPasswordException("password must be at least $MIN_PASSWORD_LENGTH characters")
        }

        val data = JSONObject()
        data.put("name", name)
        data.put("msg", serverMessage)
        data.put("t", System.currentTimeMillis())
        val fieldsJson = JSONObject()
        for ((k, v) in fields) {
            if (v != null) fieldsJson.put(k, v)
        }
        data.put("fields", fieldsJson)

        val signedData = data.toString().toByteArray(Charsets.UTF_8)
        val wrapper = JSONObject()
            .put("data", data.toString())
            .put("ownerPublicKey", localPublicKeyBase64(context))
            .put("signature", sign(context, signedData))
        val plaintext = wrapper.toString().toByteArray(Charsets.UTF_8)

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
            val iv = cipher.iv
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
            try {
                decryptWithIterations(ciphertext, password, salt, iv, PBKDF2_ITERATIONS)
            } catch (_: Throwable) {
                try {
                    decryptWithIterations(ciphertext, password, salt, iv, PBKDF2_ITERATIONS_LEGACY)
                } catch (_: Throwable) {
                    throw MlConfigParseException("wrong password")
                }
            }
        }

        return try {
            val json = JSONObject(String(plaintext, Charsets.UTF_8))
            val isV2 = bytes[4] == FORMAT_VERSION
            if (!isV2) {
                parseLegacyPayload(json)
            } else {
                val dataString = json.optString("data", "")
                val ownerPublicKey = json.optString("ownerPublicKey", "")
                val signature = json.optString("signature", "")
                if (dataString.isBlank() || ownerPublicKey.isBlank() || signature.isBlank()) {
                    throw MlConfigParseException("unsigned config")
                }
                val valid = verifySignature(
                    ownerPublicKey,
                    signature,
                    dataString.toByteArray(Charsets.UTF_8)
                )
                val data = JSONObject(dataString)
                val parsed = parseDataObject(data)
                Parsed(
                    name = parsed.name,
                    serverMessage = parsed.serverMessage,
                    fields = parsed.fields,
                    isSigned = true,
                    signatureValid = valid,
                    ownerPublicKey = ownerPublicKey
                )
            }
        } catch (e: MlConfigParseException) {
            throw e
        } catch (_: Throwable) {
            throw MlConfigParseException("corrupt file")
        }
    }

    private fun parseLegacyPayload(json: JSONObject): Parsed {
        val parsed = parseDataObject(json)
        return Parsed(
            name = parsed.name,
            serverMessage = parsed.serverMessage,
            fields = parsed.fields,
            isSigned = false,
            signatureValid = false,
            ownerPublicKey = null
        )
    }

    private fun parseDataObject(json: JSONObject): Parsed {
        val fieldsJson = json.optJSONObject("fields") ?: JSONObject()
        val fields = mutableMapOf<String, Any?>()
        val keys = fieldsJson.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            fields[k] = fieldsJson.get(k)
        }
        return Parsed(
            name = json.optString("name", ""),
            serverMessage = json.optString("msg", ""),
            fields = fields
        )
    }

    private fun decryptPlainFlagged(bytes: ByteArray): ByteArray {
        if (bytes[4] == FORMAT_VERSION && bytes.size >= HEADER_LEN + GCM_IV_LEN) {
            try {
                val iv = bytes.copyOfRange(HEADER_LEN, HEADER_LEN + GCM_IV_LEN)
                val ciphertext = bytes.copyOfRange(HEADER_LEN + GCM_IV_LEN, bytes.size)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, staticKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
                val result = cipher.doFinal(ciphertext)
                JSONObject(String(result, Charsets.UTF_8))
                return result
            } catch (_: Throwable) {
                // fallback below for old v1 unprotected files
            }
        } else if (bytes.size >= HEADER_LEN + GCM_IV_LEN) {
            try {
                val iv = bytes.copyOfRange(HEADER_LEN, HEADER_LEN + GCM_IV_LEN)
                val ciphertext = bytes.copyOfRange(HEADER_LEN + GCM_IV_LEN, bytes.size)
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, staticKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
                val result = cipher.doFinal(ciphertext)
                JSONObject(String(result, Charsets.UTF_8))
                return result
            } catch (_: Throwable) {
                // old v1 plaintext fallback
            }
        }
        return bytes.copyOfRange(HEADER_LEN, bytes.size)
    }

    private fun validateHeader(bytes: ByteArray) {
        if (bytes.size < HEADER_LEN) throw MlConfigParseException("too short")
        if (!bytes.copyOfRange(0, 4).contentEquals(MAGIC)) throw MlConfigParseException("not a MR VPN TUNNEL config")
        if (bytes[4] != FORMAT_VERSION && bytes[4] != FORMAT_VERSION_LEGACY) {
            throw MlConfigParseException("unsupported version")
        }
        if (bytes[5] != FLAG_PLAIN && bytes[5] != FLAG_ENCRYPTED) {
            throw MlConfigParseException("invalid flags")
        }
    }

    private fun decryptWithIterations(ciphertext: ByteArray, password: String, salt: ByteArray, iv: ByteArray, iterations: Int): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, deriveKey(password, salt, iterations), GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ciphertext)
    }

    private fun deriveKey(password: String, salt: ByteArray, iterations: Int = PBKDF2_ITERATIONS): SecretKeySpec {
        val spec = PBEKeySpec(password.toCharArray(), salt, iterations, 256)
        val skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val keyBytes = skf.generateSecret(spec).encoded
        return SecretKeySpec(keyBytes, "AES")
    }
}
