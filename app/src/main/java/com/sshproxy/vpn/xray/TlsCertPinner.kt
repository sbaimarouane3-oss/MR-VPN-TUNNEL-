package com.sshproxy.vpn.xray

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * بديل صحيح لـallowInsecure=true فـXray الحديث (لي حيدها نهائيا): بدل
 * ما نخمّنو شنو اسم نتحقق بيه (address ولا SNI - التخمين هادا كان
 * السبب فمشكلتين مختلفتين سابقتين، كل وحدة عكس الأخرى)، كندارو TLS
 * handshake حقيقي مرة وحدة قبل الاتصال، كنجيبو الشهادة الحقيقية لي
 * السيرفر رجّعها بالضبط (بلا أي تحقق - نفس سلوك allowInsecure
 * القديم)، كنحسبو SHA-256 ديالها، ونثبتوها (pin) فـ
 * "pinnedPeerCertSha256". هادشي كيخدم بلا معرفة مسبقة بأي اسم
 * (address ولا SNI) هو الصحيح، حيت كنقبلو أي شهادة ترجع فهاد الاحتمال
 * الوحيد (بحال TOFU)، وبعدها Xray كيتأكد ديما أنها نفس الشهادة بالضبط.
 */
object TlsCertPinner {

    /** كيرجع hex SHA-256 (lowercase) ديال الشهادة، ولا null إلا فشل الاتصال/التحقق. */
    suspend fun fetchLeafCertSha256Hex(host: String, port: Int, sni: String, timeoutMs: Long = 6000): String? {
        return withContext(Dispatchers.IO) {
            withTimeoutOrNull(timeoutMs) {
                try {
                    val trustAll = object : X509TrustManager {
                        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
                        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
                    }
                    val sslContext = SSLContext.getInstance("TLS")
                    sslContext.init(null, arrayOf(trustAll), java.security.SecureRandom())

                    Socket().use { raw ->
                        raw.connect(InetSocketAddress(host, port), timeoutMs.toInt().coerceAtMost(Int.MAX_VALUE))
                        (sslContext.socketFactory.createSocket(raw, host, port, true) as SSLSocket).use { ssl ->
                            if (sni.isNotBlank()) {
                                val params: SSLParameters = ssl.sslParameters
                                params.serverNames = listOf(SNIHostName(sni))
                                ssl.sslParameters = params
                            }
                            ssl.startHandshake()
                            val cert = ssl.session.peerCertificates.firstOrNull() as? X509Certificate
                                ?: return@withTimeoutOrNull null
                            val digest = MessageDigest.getInstance("SHA-256").digest(cert.encoded)
                            digest.joinToString("") { "%02x".format(it) }
                        }
                    }
                } catch (_: Throwable) {
                    null
                }
            }
        }
    }
}
