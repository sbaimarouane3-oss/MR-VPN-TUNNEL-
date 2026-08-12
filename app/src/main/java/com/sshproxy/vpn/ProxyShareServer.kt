package com.sshproxy.vpn

import java.io.IOException
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors

/**
 * Shares the currently active VPN tunnel (SSH or Xray/V2Ray/Shadowsocks)
 * with other devices on the same network (WiFi/Hotspot) via a raw relay.
 * It listens on 0.0.0.0:listenPort and forwards every incoming connection
 * directly to 127.0.0.1:targetPort (the same local SOCKS5 port already
 * used internally by hev-tunnel/Xray on this phone).
 *
 * This is a raw byte relay with no understanding of the SOCKS5 protocol
 * itself - it just pipes bytes in both directions, so it does not touch
 * the original connection logic (JSch/Xray/hev) in any way.
 * Other devices only need to add a SOCKS5 proxy pointing to this phone's
 * IP on the local network + listenPort.
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
                        if (running) onLog("WARN: Proxy Share accept error.")
                    }
                }
            }
            val ip = localLanIp()
            if (ip != null) {
                onLog("Proxy Share: SOCKS5 on $ip:$listenPort (use this IP on the devices you want to share with)")
            } else {
                onLog("Proxy Share: SOCKS5 active on port $listenPort")
            }
            true
        } catch (e: Throwable) {
            running = false
            onLog("ERROR: Proxy Share failed to start (is port $listenPort already in use?).")
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
