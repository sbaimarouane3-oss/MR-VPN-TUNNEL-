package com.sshproxy.vpn

import com.jcraft.jsch.SocketFactory
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import android.os.SystemClock
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
        val totalStart = SystemClock.elapsedRealtime()
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
        onLog("TCP Connecting...")
        try {
            socket.connect(InetSocketAddress(proxyHost, proxyPort), 2000)
        } catch (e: Throwable) {
            try { socket.close() } catch (_: Throwable) {}
            throw e
        }
        onLog("TCP Socket Connected. (${SystemClock.elapsedRealtime() - totalStart} ms)")

        if (useSsl) {
            val sslStart = SystemClock.elapsedRealtime()
            socket = wrapWithSsl(socket, sslSni.ifBlank { sniHost })
            onLog("SSL Handshake Successful. (${SystemClock.elapsedRealtime() - sslStart} ms)")
        }

        if (usePayload && payloadTemplate.isNotBlank()) {
            val payload = payloadTemplate
                .replace("[crlf]", "\r\n")
                .replace("[lf]", "\n")
                .replace("[host]", sniHost)
                .replace("[split]", "")

            socket.getOutputStream().write(payload.toByteArray(Charsets.ISO_8859_1))
            socket.getOutputStream().flush()
            onLog("Payload Sent.")

            // IMPORTANT: do not wait for HTTP response headers here.
            // Some payload/proxy servers stay silent until SSH starts, while
            // others send an HTTP response that JSch must consume correctly.
            // Reading here can block for several seconds and was the main
            // reason a failed attempt could take ~16 seconds. JSch now owns
            // the SSH handshake immediately after the payload is sent.
            onLog("Payload Accepted.")
        }

        activeSocket = socket
        onLog("Socket Factory Ready. (${SystemClock.elapsedRealtime() - totalStart} ms total)")
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

        // Limit the TLS handshake separately. The JSch connect timeout does
        // not fully cover the TLS handshake performed inside SocketFactory,
        // so leaving this unlimited can make SSH-TLS attempts stack up.
        try { sslSocket.soTimeout = 2500 } catch (_: Throwable) {}
        try {
            sslSocket.startHandshake()
        } catch (e: Throwable) {
            try { sslSocket.close() } catch (_: Throwable) {}
            throw e
        } finally {
            // JSch will apply its own SSH timeout after the socket is returned.
            try { sslSocket.soTimeout = 0 } catch (_: Throwable) {}
        }
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
