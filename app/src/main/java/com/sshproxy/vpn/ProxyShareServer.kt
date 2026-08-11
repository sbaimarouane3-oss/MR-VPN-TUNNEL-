package com.sshproxy.vpn

import java.io.IOException
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors

/**
 * كيشارك تونيل الـVPN الحالي (سواء SSH أو Xray/V2Ray/Shadowsocks) مع
 * أجهزة أخرى فنفس الشبكة (WiFi/Hotspot) - عبر relay خام كيسمع على
 * 0.0.0.0:listenPort وكيربط كل اتصال جاي مباشرة بـ127.0.0.1:targetPort
 * (نفس البورت ديال الـSOCKS5 المحلي اللي كايستعملو hev-tunnel/Xray
 * جوايا التيليفون فعلا).
 *
 * relay خام بلا أي فهم لبروتوكول SOCKS5 - غير bytes pipe فالجوج
 * الاتجاهات، فماكاينش أي مساس بمنطق الاتصال الأصلي (JSch/Xray/hev).
 * الأجهزة الأخرى خاصها غير يضيفو SOCKS5 proxy بـIP ديال التيليفون على
 * الشبكة + listenPort.
 */
class ProxyShareServer(
    private val listenPort: Int,
    private val targetPortProvider: () -> Int,
    private val onLog: (String) -> Unit
) {
    @Volatile private var running = false
    private var serverSocket: ServerSocket? = null
    private val pool = Executors.newCachedThreadPool()

    fun isRunning(): Boolean = running && serverSocket?.isClosed == false

    fun start(): Boolean {
        return try {
            val ss = ServerSocket()
            ss.reuseAddress = true
            ss.bind(InetSocketAddress("0.0.0.0", listenPort))
            serverSocket = ss
            running = true
            pool.execute {
                while (running) {
                    try {
                        val client = ss.accept()
                        pool.execute { handleClient(client) }
                    } catch (e: IOException) {
                        if (running) onLog("WARN: Proxy Share Accept Error.")
                    }
                }
            }
            val ip = localLanIp()
            if (ip != null) {
                onLog("Proxy Share: SOCKS5 على $ip:$listenPort (زيدو ذاك الـIP فالأجهزة لي بغيتي تشاركهم)")
            } else {
                onLog("Proxy Share: SOCKS5 فعّال على البورت $listenPort")
            }
            true
        } catch (e: Throwable) {
            running = false
            onLog("ERROR: Proxy Share تعذر تشغيلو (البورت $listenPort خدام؟).")
            false
        }
    }

    fun stop() {
        running = false
        try { serverSocket?.close() } catch (_: Exception) { }
        pool.shutdownNow()
    }

    private fun handleClient(client: Socket) {
        var upstream: Socket? = null
        try {
            client.tcpNoDelay = true
            upstream = Socket()
            upstream.tcpNoDelay = true
            upstream.connect(InetSocketAddress("127.0.0.1", targetPortProvider()), 8000)

            val f1 = pool.submit { pipe(client, upstream) }
            val f2 = pool.submit { pipe(upstream, client) }
            try { f1.get() } catch (_: Exception) { }
            try { f2.get() } catch (_: Exception) { }
        } catch (_: Exception) {
            // صامت - نفس منطق MiniSocks5Server، الاتصالات كتنقطع بشكل طبيعي
        } finally {
            try { client.close() } catch (_: Exception) { }
            try { upstream?.close() } catch (_: Exception) { }
        }
    }

    private fun pipe(from: Socket, to: Socket) {
        val buffer = ByteArray(8192)
        try {
            val input = from.getInputStream()
            val output = to.getOutputStream()
            while (true) {
                val n = input.read(buffer)
                if (n == -1) break
                output.write(buffer, 0, n)
                output.flush()
            }
        } catch (_: Exception) {
        } finally {
            try { to.shutdownOutput() } catch (_: Exception) { }
        }
    }

    /** كيقلب على IP ديال التيليفون فشبكة الـWiFi/Hotspot (غير للعرض فـlog، ماشي حرج للاتصال). */
    private fun localLanIp(): String? {
        return try {
            NetworkInterface.getNetworkInterfaces().asSequence()
                .filter { it.isUp && !it.isLoopback }
                .flatMap { it.inetAddresses.asSequence() }
                .filter { !it.isLoopbackAddress && it.hostAddress?.contains(":") == false }
                .map { it.hostAddress }
                .firstOrNull { it != null && (it.startsWith("192.168.") || it.startsWith("10.") || it.startsWith("172.")) }
        } catch (_: Throwable) {
            null
        }
    }
}
