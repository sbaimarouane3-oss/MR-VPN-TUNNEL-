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

    private var activeSocket: Socket? = null

    private object TrustAllManager : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    override fun createSocket(host: String, port: Int): Socket {
        // ===== DEBUG: اطبع في Logcat مباشرة =====
        android.util.Log.d("PSF", "===== createSocket() START for $host:$port =====")
        
        val totalStart = SystemClock.elapsedRealtime()
        var socket: Socket = Socket()
        
        android.util.Log.d("PSF", "TCP Connecting to $proxyHost:$proxyPort...")
        onLog("TCP Connecting to $proxyHost:$proxyPort...")
        
        try {
            socket.keepAlive = true
            socket.tcpNoDelay = true
            socket.setPerformancePreferences(0, 2, 1)
        } catch (_: Throwable) { }
        
        val connectStart = SystemClock.elapsedRealtime()
        try {
            socket.connect(InetSocketAddress(proxyHost, proxyPort), 1500)
            android.util.Log.d("PSF", "TCP Connected in ${SystemClock.elapsedRealtime() - connectStart} ms")
            onLog("TCP Socket Connected. (${SystemClock.elapsedRealtime() - connectStart} ms)")
        } catch (e: Throwable) {
            android.util.Log.d("PSF", "TCP Connect FAILED: ${e.javaClass.simpleName}: ${e.message}")
            onLog("TCP Connect Failed. (${SystemClock.elapsedRealtime() - connectStart} ms)")
            try { socket.close() } catch (_: Throwable) {}
            throw e
        }

        if (useSsl) {
            android.util.Log.d("PSF", "SSL Handshake Starting...")
            val sslStart = SystemClock.elapsedRealtime()
            try {
                socket = wrapWithSsl(socket, sslSni.ifBlank { sniHost })
                android.util.Log.d("PSF", "SSL Handshake OK in ${SystemClock.elapsedRealtime() - sslStart} ms")
                onLog("SSL Handshake Successful. (${SystemClock.elapsedRealtime() - sslStart} ms)")
            } catch (e: Throwable) {
                android.util.Log.d("PSF", "SSL Handshake FAILED: ${e.javaClass.simpleName}: ${e.message}")
                onLog("SSL Handshake Failed. (${SystemClock.elapsedRealtime() - sslStart} ms)")
                throw e
            }
        }

        if (usePayload && payloadTemplate.isNotBlank()) {
            android.util.Log.d("PSF", "Sending Payload...")
            val payloadStart = SystemClock.elapsedRealtime()
            
            val payload = payloadTemplate
                .replace("[crlf]", "\r\n")
                .replace("[lf]", "\n")
                .replace("[host]", sniHost)
                .replace("[split]", "")

            try {
                socket.getOutputStream().write(payload.toByteArray(Charsets.ISO_8859_1))
                socket.getOutputStream().flush()
                android.util.Log.d("PSF", "Payload Sent in ${SystemClock.elapsedRealtime() - payloadStart} ms")
                onLog("Payload Sent. (${SystemClock.elapsedRealtime() - payloadStart} ms)")
                onLog("Payload Accepted.")
            } catch (e: Throwable) {
                android.util.Log.d("PSF", "Payload Send FAILED: ${e.javaClass.simpleName}: ${e.message}")
                onLog("Payload Send Failed.")
                throw e
            }
        }

        activeSocket = socket
        android.util.Log.d("PSF", "===== createSocket() END in ${SystemClock.elapsedRealtime() - totalStart} ms =====")
        onLog("Socket Factory Ready. (${SystemClock.elapsedRealtime() - totalStart} ms total)")
        return socket
    }

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
        } catch (_: Throwable) { }

        try { sslSocket.soTimeout = 1500 } catch (_: Throwable) {}
        try {
            sslSocket.startHandshake()
        } catch (e: Throwable) {
            try { sslSocket.close() } catch (_: Throwable) {}
            throw e
        } finally {
            try { sslSocket.soTimeout = 0 } catch (_: Throwable) {}
        }
        return sslSocket
    }

    override fun getInputStream(socket: Socket): InputStream = (activeSocket ?: socket).getInputStream()
    override fun getOutputStream(socket: Socket): OutputStream = (activeSocket ?: socket).getOutputStream()
}
