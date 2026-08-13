package com.sshproxy.vpn

import android.content.Context

/**
 * Unified, protocol-agnostic Proxy Sharing layer:
 *
 *   Protocol Backend -> Local Proxy Endpoint -> UnifiedProxySharingManager -> Hotspot Client
 *
 * Any backend (SSH, Xray/V2Ray/VLESS/VMess/Trojan/Shadowsocks, or any future
 * protocol) only ever needs to provide ONE thing: a local SOCKS5 endpoint on
 * 127.0.0.1 (a host + a port). This object takes that endpoint and exposes
 * it to other devices on the same WiFi/Hotspot via [ProxyShareServer] (a
 * pure, protocol-unaware byte relay). Nothing about protocol/backend
 * details ever leaks into ProxyShareServer, and nothing about this feature
 * lives inside any single protocol's own code (e.g. Xray's) - this is the
 * one and only place it's implemented.
 *
 * Lifecycle contract for callers (SshVpnService):
 *  - Call [startIfEnabled] any time a backend reaches READY (initial
 *    connect OR reconnect) - it is fully idempotent: if sharing is already
 *    running, it does nothing (never creates a second listener), so it's
 *    always safe to call unconditionally.
 *  - Call [stop] on disconnect/cleanup.
 *  - [localPortProvider] is a live lookup (not a snapshot) so if a
 *    reconnect changes the backend's local port, already-open sharing
 *    keeps working against the *current* value without needing a restart.
 */
object UnifiedProxySharingManager {

    private const val PREFS_NAME = "proxy_share_prefs"
    private const val KEY_ENABLED = "enabled"
    private const val KEY_PORT = "port"
    const val DEFAULT_PORT = 8388

    private var server: ProxyShareServer? = null

    fun isRunning(): Boolean = server?.isRunning() == true

    /**
     * @param backendName human-readable backend label for the log, e.g.
     *   "SSH SOCKS5", "VLESS SOCKS5", "VMESS SOCKS5", "TROJAN SOCKS5",
     *   "SHADOWSOCKS SOCKS5" - whatever the currently connected backend is.
     * @param localHost the backend's local proxy host - always "127.0.0.1"
     *   in this app, but passed explicitly rather than hardcoded here so a
     *   future backend isn't forced into that assumption.
     * @param localPortProvider live lookup of the backend's local proxy
     *   port (e.g. `{ socksPort }`) - read fresh on every forwarded
     *   connection, not just once at start().
     */
    fun startIfEnabled(
        context: Context,
        backendName: String,
        localHost: String,
        localPortProvider: () -> Int,
        onLog: (String) -> Unit
    ) {
        try {
            val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            if (!prefs.getBoolean(KEY_ENABLED, false)) return
            if (isRunning()) return // already sharing - never open a second listener on reconnect

            val listenPort = prefs.getInt(KEY_PORT, DEFAULT_PORT)
            val relay = ProxyShareServer(listenPort, localPortProvider) { msg -> onLog(msg) }
            val lanIp = relay.start()
            if (lanIp == null) {
                onLog("[PROXY] ERROR: Sharing failed to start (is port $listenPort already in use?).")
                return
            }
            server = relay

            onLog("[PROXY] Sharing Started")
            onLog("[PROXY] Listen: 0.0.0.0:$listenPort")
            onLog("[PROXY] Backend: $backendName")
            onLog("[PROXY] Local Endpoint: $localHost:${localPortProvider()}")
            onLog("[PROXY] Proxy IP: $lanIp")
            onLog("[PROXY] Proxy Port: $listenPort")
            onLog("[PROXY] Ready for Hotspot Clients")
        } catch (_: Throwable) { }
    }

    fun stop() {
        try { server?.stop() } catch (_: Throwable) { }
        server = null
    }
}
