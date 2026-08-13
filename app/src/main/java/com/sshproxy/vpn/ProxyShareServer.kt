package com.sshproxy.vpn

import java.io.IOException
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors

/**
 * Shares whatever local proxy endpoint (SOCKS5) a connected backend exposes
 * (SSH, Xray/V2Ray/VLESS/VMess/Trojan/Shadowsocks, or any future protocol)
 * with other devices on the same network (WiFi/Hotspot) via a raw relay.
 * It listens on 0.0.0.0:listenPort and forwards every incoming connection
 * directly to 127.0.0.1:targetPort (whatever local SOCKS5 port the current
 * backend is using - see targetPortProvider).
 *
 * This is a raw byte relay with no understanding of the SOCKS5 protocol,
 * and no knowledge of which backend/protocol is behind it - it just pipes
 * bytes in both directions. All protocol-aware logging/formatting lives one
 * layer up, in [UnifiedProxySharingManager], which is what makes this class
 * reusable across every protocol without any per-protocol copy.
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

    /** Returns the resolved LAN IP on success, or null if binding the listen port failed. */
    fun start(): String? {
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
                        if (running) onLog("[PROXY] WARN: Accept error.")
                    }
                }
            }
            localLanIp() ?: "0.0.0.0"
        } catch (e: Throwable) {
            running = false
            null
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
            // Silent - same behavior as MiniSocks5Server, connections drop naturally
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

    /** Looks up the phone's LAN IP on WiFi/Hotspot (display only, not critical for the relay itself). */
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
