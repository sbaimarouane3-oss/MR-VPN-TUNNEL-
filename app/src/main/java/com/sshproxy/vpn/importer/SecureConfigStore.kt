package com.sshproxy.vpn.importer

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * تخزين الكونفيغ المستورد "at rest" (على القرص) بعد فك تشفيره من كود
 * الاستيراد. هذا تشفير مختلف تماما عن تشفير كود الاستيراد نفسو:
 *
 * - تشفير كود الاستيراد (ImportCrypto): مفتاح ثابت مشترك (نفسو فكل
 *   نسخة من التطبيق)، لازم يكون هكذا باش الكود يخدم على أي جهاز.
 * - تخزين at-rest (هنا): مفتاح AES مولّد ومخزّن **داخل Android Keystore**
 *   (hardware-backed إلا الجهاز كيدعمها)، خاص بهاد الجهاز/التطبيق فقط،
 *   عمرو ما كيخرج كـbytes واضحة حتى للتطبيق نفسو — هادي أقوى حماية
 *   ممكنة للتخزين المحلي، بلا ما نحتاجو نكتبو ولا نخزنو أي مفتاح يدويا.
 */
internal object SecureConfigStore {

    private const val KEYSTORE_ALIAS = "sshproxy_vpn_config_key"
    private const val FILE_NAME = "secure_config.bin"
    private const val GCM_TAG_BITS = 128
    private const val GCM_IV_LEN = 12

    fun hasConfig(ctx: Context): Boolean = configFile(ctx).exists()

    fun save(ctx: Context, config: ImportedConfig) {
        val key = getOrCreateKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv // 12 بايت، مولّدة عشوائيا من طرف الـprovider
        val ciphertext = cipher.doFinal(config.toJson().toByteArray(Charsets.UTF_8))

        val out = ByteArray(iv.size + ciphertext.size)
        System.arraycopy(iv, 0, out, 0, iv.size)
        System.arraycopy(ciphertext, 0, out, iv.size, ciphertext.size)

        // كونفيغ واحد فقط: كنكتبو (نبدلو) نفس الملف، القديم كيتمحى تلقائيا
        configFile(ctx).writeBytes(out)
    }

    fun load(ctx: Context): ImportedConfig? {
        val f = configFile(ctx)
        if (!f.exists()) return null
        return try {
            val data = f.readBytes()
            if (data.size < GCM_IV_LEN) return null
            val iv = data.copyOfRange(0, GCM_IV_LEN)
            val ciphertext = data.copyOfRange(GCM_IV_LEN, data.size)

            val key = getOrCreateKey()
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            val plaintext = cipher.doFinal(ciphertext)
            ImportedConfig.fromJson(String(plaintext, Charsets.UTF_8))
        } catch (_: Throwable) {
            // ملف فاسد أو مفتاح الـKeystore تبدل (مثلا reset ديال التطبيق) → كنعتبروه ماكاينش
            null
        }
    }

    fun clear(ctx: Context) {
        val f = configFile(ctx)
        if (f.exists()) f.delete()
    }

    private fun configFile(ctx: Context): File = File(ctx.filesDir, FILE_NAME)

    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore")
        ks.load(null)

        val existing = ks.getKey(KEYSTORE_ALIAS, null) as? SecretKey
        if (existing != null) return existing

        val keyGen = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
        )
        val spec = KeyGenParameterSpec.Builder(
            KEYSTORE_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        keyGen.init(spec)
        return keyGen.generateKey()
    }
}
