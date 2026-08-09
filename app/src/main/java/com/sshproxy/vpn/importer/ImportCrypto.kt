package com.sshproxy.vpn.importer

import android.util.Base64
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** الاستثناء الوحيد اللي كيطلع من verifyAndDecrypt، بلا تفاصيل داخلية للمستخدم. */
class InvalidImportCodeException(message: String) : Exception(message)

/**
 * تنسيق كود الاستيراد (بعد نزع بادئة MRVPN://، وقبل ترميز Base62):
 *
 *  [0]          version (1 بايت) = 0x01
 *  [1..2]       طول الـciphertext (uint16 big-endian)
 *  [3..14]      IV ديال AES-GCM (12 بايت)
 *  [15..]       ciphertext (فيه الـGCM tag مزاد فالآخر تلقائيا)
 *  [..+2]       طول التوقيع (uint16 big-endian)
 *  [..]         توقيع ECDSA (SHA256withECDSA) فوق [0 .. نهاية ciphertext]
 *
 * الترتيب المهم: **التحقق من التوقيع يجي قبل فك التشفير** (fail-closed).
 * أي حرف واحد يتبدل فالكود → التوقيع كيفشل → رفض فوري بلا ما نحاولو
 * حتى نفكو التشفير.
 */
internal object ImportCrypto {

    private const val PREFIX = "MRVPN://"
    private const val VERSION: Byte = 0x01
    private const val GCM_TAG_BITS = 128
    private const val GCM_IV_LEN = 12

    fun isImportCode(text: String): Boolean = text.trim().startsWith(PREFIX)

    /**
     * كنتحققو من التوقيع أولا، وملي التوقيع صحيح، كنفكو التشفير.
     * كنطلقو InvalidImportCodeException برسالة موحدة فأي حالة فشل
     * (كود ماشي صالح، تلاعب، تشفير فاسد...) — بلا ما نبينو تفاصيل
     * داخلية ممكن تفيد مهاجم (زي "signature failed" مقابل "bad json").
     */
    fun verifyAndDecrypt(rawCode: String): ImportedConfig {
        try {
            val code = rawCode.trim()
            if (!code.startsWith(PREFIX)) {
                throw InvalidImportCodeException("bad prefix")
            }
            val body = code.substring(PREFIX.length)
            val blob = Base62.decode(body)

            if (blob.size < 1 + 2 + GCM_IV_LEN + 2) {
                throw InvalidImportCodeException("too short")
            }

            val buf = ByteBuffer.wrap(blob)
            val version = buf.get()
            if (version != VERSION) throw InvalidImportCodeException("bad version")

            val ctLen = buf.short.toInt() and 0xFFFF
            val iv = ByteArray(GCM_IV_LEN)
            buf.get(iv)

            if (buf.remaining() < ctLen + 2) throw InvalidImportCodeException("truncated")
            val ciphertext = ByteArray(ctLen)
            buf.get(ciphertext)

            val sigLen = buf.short.toInt() and 0xFFFF
            if (buf.remaining() < sigLen) throw InvalidImportCodeException("truncated sig")
            val signature = ByteArray(sigLen)
            buf.get(signature)

            // الجزء الموقّع = من البداية لحد نهاية الـciphertext (بلا طول التوقيع أو التوقيع نفسو)
            val signedPartLen = 1 + 2 + GCM_IV_LEN + ctLen
            val signedPart = blob.copyOfRange(0, signedPartLen)

            // 1) التحقق من التوقيع الرقمي (fail-closed)
            if (!verifySignature(signedPart, signature)) {
                throw InvalidImportCodeException("signature mismatch")
            }

            // 2) فك التشفير AES-256-GCM (الـGCM tag كيتحقق من التكامل زيادة على التوقيع)
            val plaintext = decryptAesGcm(ciphertext, iv)

            return ImportedConfig.fromJson(String(plaintext, Charsets.UTF_8))
        } catch (e: InvalidImportCodeException) {
            throw e
        } catch (e: Throwable) {
            // أي خطأ آخر (JSON فاسد، base62 غير صالح، GCM tag ماطابقش...)
            // كنعتبروه نفس حالة "كود غير صالح"
            throw InvalidImportCodeException("invalid: ${e.javaClass.simpleName}")
        }
    }

    private fun verifySignature(signedPart: ByteArray, signature: ByteArray): Boolean {
        return try {
            val pubKeyBytes = Base64.decode(ImportKeyMaterial.SIGN_PUBLIC_KEY_B64, Base64.DEFAULT)
            val keyFactory = KeyFactory.getInstance("EC")
            val publicKey: PublicKey = keyFactory.generatePublic(X509EncodedKeySpec(pubKeyBytes))

            val sig = Signature.getInstance("SHA256withECDSA")
            sig.initVerify(publicKey)
            sig.update(signedPart)
            sig.verify(signature)
        } catch (_: Throwable) {
            false
        }
    }

    private fun decryptAesGcm(ciphertext: ByteArray, iv: ByteArray): ByteArray {
        val key = ImportKeyMaterial.aesKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(GCM_TAG_BITS, iv)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), spec)
        return cipher.doFinal(ciphertext)
    }
}
