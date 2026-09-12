package com.sshproxy.vpn.importer

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.sshproxy.vpn.xray.ParsedProxyConfig
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * نفس فكرة SecureConfigStore بالضبط (نفس نوع التشفير AES/GCM +
 * Android Keystore) لكن لكونفيغ V2Ray/Xray (ParsedProxyConfig) - ملف
 * ومفتاح Keystore منفصلين تماماً عن SecureConfigStore، بلا ما نمس فيه.
 */
internal object XraySecureConfigStore {

    private const val KEYSTORE_ALIAS = "sshproxy_vpn_xray_config_key"
    private const val FILE_NAME = "secure_xray_config.bin"
    private const val GCM_TAG_BITS = 128
    private const val GCM_IV_LEN = 12

    fun hasConfig(ctx: Context): Boolean = configFile(ctx).exists()

    fun save(ctx: Context, config: ParsedProxyConfig) {
        val key = getOrCreateKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(config.toJson().toByteArray(Charsets.UTF_8))

        val out = ByteArray(iv.size + ciphertext.size)
        System.arraycopy(iv, 0, out, 0, iv.size)
        System.arraycopy(ciphertext, 0, out, iv.size, ciphertext.size)

        configFile(ctx).writeBytes(out)
    }

    fun load(ctx: Context): ParsedProxyConfig? {
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
            ParsedProxyConfig.fromJson(String(plaintext, Charsets.UTF_8))
        } catch (_: Throwable) {
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
