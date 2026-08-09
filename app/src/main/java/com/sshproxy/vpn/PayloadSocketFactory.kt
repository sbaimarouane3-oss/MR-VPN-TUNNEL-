package com.sshproxy.vpn

import com.jcraft.jsch.SocketFactory
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * كيدير Socket عادي، كيبعث Payload (HTTP GET/websocket upgrade) قبل ما يبدا SSH handshake.
 * هادشي هو نفس المبدأ ديال HTTP Custom / SSH-PROXY-PAYLOAD.
 *
 * إلا كان useSsl مفعّل، كنلفو التواصل بـ TLS (SNI قابل للتخصيص) قبل ما نبداو أي
 * Payload أو SSH handshake - هادشي هو بروتوكول "SSH-SSL" بحال SSL checkbox
 * فـ HTTP Custom / NPV Tunnel. Payload والـ SSL مستقلين عن بعضياتهم بالضبط
 * بحال فالتطبيقات الأخرى: يمكن تفعّل واحد منهما، بجوج، ولا حتى واحد.
 */
class PayloadSocketFactory(
    private val proxyHost: String,
    private val proxyPort: Int,
    private val payloadTemplate: String,
    private val sniHost: String,
    private val usePayload: Boolean,
    private val useSsl: Boolean = false,
    private val sslSni: String = "",
    private val onLog: (String) -> Unit
) : SocketFactory {

    // السوكيت "الفعلي" لي كيتقرا/يتكتب منو فعلا - سوكيت TLS إلا كان useSsl
    // مفعّل، أو نفس السوكيت الخام إلا لا. جيتش كيسول getInputStream/
    // getOutputStream بالسوكيت الأصلي اللي رجّعناه من createSocket، ماشي
    // بالضرورة بالسوكيت المستعمل فعليا - فكنخزنو مرجع ليه هنا.
    private var activeSocket: Socket? = null

    /** TrustManager بلا تحقق من الشهادة - نفس المبدأ ديال StrictHostKeyChecking=no فالكود الحالي. */
    private object TrustAllManager : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    override fun createSocket(host: String, port: Int): Socket {
        var socket: Socket = Socket()
        try {
            // TCP-level KeepAlive as a second line of defense under the
            // SSH-level ServerAlive settings: lets the OS detect a truly dead
            // link (e.g. NAT/carrier silently drops the mapping) without
            // waiting on the SSH layer alone. TcpNoDelay avoids Nagle-related
            // latency spikes on the small, frequent SSH/SOCKS packets.
            socket.keepAlive = true
            socket.tcpNoDelay = true
            socket.setPerformancePreferences(0, 2, 1) // prioritize low latency over bandwidth/connect-time
        } catch (_: Throwable) { }
        socket.connect(InetSocketAddress(proxyHost, proxyPort), 6000)
        onLog("TCP Socket Connected.")

        if (useSsl) {
            socket = wrapWithSsl(socket, sslSni.ifBlank { sniHost })
            onLog("SSL Handshake Successful.")
        }

        if (usePayload && payloadTemplate.isNotBlank()) {
            val payload = payloadTemplate
                .replace("[crlf]", "\r\n")
                .replace("[lf]", "\n")
                .replace("[host]", sniHost)
                .replace("[split]", "")

            socket.getOutputStream().write(payload.toByteArray(Charsets.ISO_8859_1))
            socket.getOutputStream().flush()
            onLog("Sending Payload...")

            // السيرفر يقدر يرجع بزاف ديال الاستجابات (301, 200, 101 Switching...) قبل ما يفتح التونيل.
            // كنقراو الهيدرز غير باش نعرفو فين توقف الـ HTTP response، بلا ما نبدلو أي منطق اتصال —
            // النتيجة ماكتأثرش على قرار المتابعة، السوكيت كيرجع فكل الحالات بحال قبل.
            for (i in 0 until 5) {
                val status = readHttpHeaders(socket) ?: break
                if (status.contains("101") || status.contains("Connection Established")) break
            }
            onLog("Payload Accepted.")
        }

        activeSocket = socket
        return socket
    }

    /** كيلف سوكيت TCP خام بـ TLS (SNI قابل للتخصيص)، بلا تحقق من الشهادة. */
    private fun wrapWithSsl(plain: Socket, sniName: String): SSLSocket {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(TrustAllManager), SecureRandom())
        val sslSocket = sslContext.socketFactory.createSocket(
            plain, sniName, plain.port, true
        ) as SSLSocket

        try {
            val params = sslSocket.sslParameters
            params.serverNames = listOf(SNIHostName(sniName))
            sslSocket.sslParameters = params
        } catch (_: Throwable) {
            // SNI setting best-effort only - some devices/older TLS stacks
            // don't support it; the handshake below still proceeds normally.
        }

        sslSocket.startHandshake()
        return sslSocket
    }

    /** كتقرا هيدرز الـ HTTP response بلا ما تسجل محتواها الخام (يقدر يحتوي على host/proxy معلومات). */
    private fun readHttpHeaders(socket: Socket): String? {
        val input = socket.getInputStream()
        val buf = StringBuilder()
        while (true) {
            val b = input.read()
            if (b == -1) break
            buf.append(b.toChar())
            if (buf.length >= 4 && buf.substring(buf.length - 4) == "\r\n\r\n") break
            if (buf.length > 8192) break // حماية من infinite loop
        }
        return buf.toString().lineSequence().firstOrNull()?.trim()
    }

    override fun getInputStream(socket: Socket): InputStream = (activeSocket ?: socket).getInputStream()
    override fun getOutputStream(socket: Socket): OutputStream = (activeSocket ?: socket).getOutputStream()
}
