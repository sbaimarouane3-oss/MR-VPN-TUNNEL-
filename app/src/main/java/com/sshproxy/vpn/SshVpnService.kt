package com.sshproxy.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.TrafficStats
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import com.jcraft.jsch.JSch
import com.jcraft.jsch.Session
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import com.sshproxy.vpn.xray.ParsedProxyConfig
import com.sshproxy.vpn.xray.XrayConfigBuilder
import com.sshproxy.vpn.xray.XrayCoreManager

class SshVpnService : VpnService() {

    companion object {
        const val ACTION_CONNECT = "com.sshproxy.vpn.CONNECT"
        const val ACTION_DISCONNECT = "com.sshproxy.vpn.DISCONNECT"
        const val ACTION_LOG = "com.sshproxy.vpn.LOG"
        const val EXTRA_LOG_MESSAGE = "message"

        const val ACTION_STATUS = "com.sshproxy.vpn.STATUS"
        const val EXTRA_STATE = "state"
        const val STATE_CONNECTING = "CONNECTING"
        const val STATE_READY = "READY"
        const val STATE_RECONNECTING = "RECONNECTING"
        const val STATE_WAITING_NETWORK = "WAITING_NETWORK"
        const val STATE_DISCONNECTED = "DISCONNECTED"
        const val STATE_FAILED = "FAILED"
        const val STATE_WAITING_USER_ACTION = "WAITING_USER_ACTION"

        const val EXTRA_MODE = "mode"
        const val MODE_SSH = "SSH"
        const val MODE_XRAY = "XRAY"
        const val EXTRA_XRAY_CONFIG = "xrayParsedConfigJson"

        private const val MAX_AUTO_RECONNECT_WINDOW_MS = 60 * 60 * 1000L
        private const val XRAY_PING_INTERVAL_MS = 5000L

        private const val CHANNEL_ID = "vpn_status"
        private const val NOTIF_ID = 1

        @Volatile private var nativeLoaded = false
        @Volatile private var nativeLoadError: String? = null

        fun ensureNativeLoaded(ctx: Context): Boolean {
            if (nativeLoaded) return true
            synchronized(this) {
                if (nativeLoaded) return true
                return try {
                    System.loadLibrary("hev-socks5-tunnel")
                    System.loadLibrary("hev-socks5-tunnel-jni")
                    nativeLoaded = true
                    true
                } catch (e: Throwable) {
                    nativeLoadError = e.javaClass.simpleName
                    false
                }
            }
        }
    }

    private external fun nativeStartTunnel(
        fd: Int, socksHost: String, socksPort: Int, mtu: Int,
        udpMode: String, udpgwHost: String, udpgwPort: Int
    ): Int
    private external fun nativeStopTunnel()

    private var session: Session? = null
    private var tunFd: ParcelFileDescriptor? = null
    private var socksServer: MiniSocks5Server? = null
    @Volatile private var backendProtocolName: String = "SOCKS5"
    private var speedMonitorJob: Job? = null
    private var xrayPingMonitorJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    @Volatile private var socksPort: Int = 10808
    @Volatile private var mode: String = MODE_SSH
    private var lastXrayParsedJson: String = ""
    @Volatile private var logTag: String = ""

    private var lastHost = ""
    private var lastPort = 443
    private var lastUser = ""
    private var lastPass = ""
    private var lastProxyHost = ""
    private var lastProxyPort = 443
    private var lastPayload = ""
    private var lastUsePayload = true
    private var lastUseSsl = false
    private var lastSni = ""
    private var lastUdpgwEnabled = false
    private var lastUdpgwPort = 0
    private var udpgwLocalPort = 0
    private var lastMaskLogs = false

    @Volatile private var vpnActive = false
    @Volatile private var vpnStopped = false
    @Volatile private var reconnecting = false
    @Volatile private var stopRequested = false
    @Volatile private var networkAvailable = true
    @Volatile private var reconnectGeneration = 0
    @Volatile private var autoReconnectSuspended = false
    @Volatile private var firstReconnectFailureAt: Long = 0L

    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var reconnectDebounceJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        try {
            connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onLost(network: Network) {
                    if (isVpnTransport(network)) return
                    networkAvailable = false
                    if (vpnActive) {
                        broadcastStatus(STATE_WAITING_NETWORK)
                    }
                }

                override fun onAvailable(network: Network) {
                    if (isVpnTransport(network)) return
                    networkAvailable = true
                    if (vpnActive) {
                        tryResumeSession("network-available")
                    }
                }

                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
                    val validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                    if (validated && !networkAvailable) {
                        networkAvailable = true
                        if (vpnActive) {
                            tryResumeSession("network-validated")
                        }
                    }
                }
            }
            connectivityManager?.registerDefaultNetworkCallback(networkCallback!!)
        } catch (_: Throwable) { }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            stopRequested = true
            stopVpn()
            return START_NOT_STICKY
        }

        stopRequested = false
        autoReconnectSuspended = false
        firstReconnectFailureAt = 0L
        socksPort = (20000..59000).random()

        if (session != null || tunFd != null || socksServer != null) {
            cleanupResources()
        }

        mode = intent?.getStringExtra(EXTRA_MODE) ?: MODE_SSH

        if (mode == MODE_XRAY) {
            val parsedJson = intent?.getStringExtra(EXTRA_XRAY_CONFIG)
            if (parsedJson.isNullOrBlank()) {
                log("ERROR: Invalid Configuration.")
                return START_NOT_STICKY
            }
            lastXrayParsedJson = parsedJson
            logTag = "XRAY"

            log("Starting Service...")
            broadcastStatus(STATE_CONNECTING)

            try {
                startForegroundNotif()
            } catch (e: Throwable) {
                log("ERROR: ${e.javaClass.simpleName}: ${realDetail(e)}")
                stopSelf()
                return START_NOT_STICKY
            }

            scope.launch {
                var attempt = 0
                while (isActive) {
                    try {
                        log("Preparing VPN Engine...")
                        if (!ensureNativeLoaded(applicationContext)) {
                            log("ERROR: Native Library Load Failed. (${nativeLoadError ?: "unknown"})")
                            broadcastStatus(STATE_FAILED)
                            stopVpn()
                            return@launch
                        }
                        connectXray(parsedJson)
                        break
                    } catch (e: Throwable) {
                        log(classifyConnectError(e))

                        if (stopRequested) {
                            stopVpn()
                            return@launch
                        }

                        cleanupResources()
                        attempt++
                        val waitMs = backoffDelayMs(attempt - 1)
                        log("Retrying Connection (attempt $attempt)...")
                        delay(waitMs)
                    }
                }
            }
            return START_STICKY
        }

        val host = intent?.getStringExtra("host") ?: return START_NOT_STICKY
        val port = intent.getIntExtra("port", 443)
        val user = intent.getStringExtra("user") ?: ""
        val pass = intent.getStringExtra("pass") ?: ""
        val proxyHost = intent.getStringExtra("proxyHost") ?: host
        val proxyPort = intent.getIntExtra("proxyPort", port)
        val payload = intent.getStringExtra("payload") ?: ""
        val usePayload = intent.getBooleanExtra("usePayload", true)
        val useSsl = intent.getBooleanExtra("useSsl", false)
        val sni = intent.getStringExtra("sni") ?: ""
        val udpgwEnabled = intent.getBooleanExtra("udpgwEnabled", false)
        val udpgwPort = intent.getIntExtra("udpgwPort", 7300)
        val maskLogs = intent.getBooleanExtra("maskLogs", false)

        val usesProxyForTag = proxyHost.isNotBlank() && (proxyHost != host || proxyPort != port)
        logTag = StringBuilder("SSH").apply {
            if (useSsl) append("-TLS")
            if (usesProxyForTag) append("-PROXY")
            if (usePayload) append("-PAYLOAD")
        }.toString().let { if (it == "SSH") "SSH-DIRECT" else it }

        log("Starting Service...")
        broadcastStatus(STATE_CONNECTING)

        lastHost = host; lastPort = port; lastUser = user; lastPass = pass
        lastProxyHost = proxyHost; lastProxyPort = proxyPort
        lastPayload = payload; lastUsePayload = usePayload
        lastUseSsl = useSsl; lastSni = sni
        lastUdpgwEnabled = udpgwEnabled; lastUdpgwPort = udpgwPort; lastMaskLogs = maskLogs

        try {
            startForegroundNotif()
        } catch (e: Throwable) {
            log("ERROR: ${e.javaClass.simpleName}: ${realDetail(e)}")
            stopSelf()
            return START_NOT_STICKY
        }

        scope.launch {
            var attempt = 0
            while (isActive) {
                try {
                    log("Preparing VPN Engine...")
                    if (!ensureNativeLoaded(applicationContext)) {
                        log("ERROR: Native Library Load Failed. (${nativeLoadError ?: "unknown"})")
                        broadcastStatus(STATE_FAILED)
                        stopVpn()
                        return@launch
                    }
                    connect(host, port, user, pass, proxyHost, proxyPort, payload, usePayload, useSsl, sni, udpgwEnabled, udpgwPort, maskLogs)
                    break
                } catch (e: Throwable) {
                    log(classifyConnectError(e))

                    if (stopRequested) {
                        stopVpn()
                        return@launch
                    }

                    cleanupResources()
                    attempt++
                    val waitMs = 500L
                    log("Retrying Connection (attempt $attempt) in ${waitMs} ms...")
                    delay(waitMs)
                }
            }
        }
        return START_STICKY
    }

    private fun connect(
        host: String, port: Int, user: String, pass: String,
        proxyHost: String, proxyPort: Int, payload: String, usePayload: Boolean,
        useSsl: Boolean = false, sni: String = "",
        udpgwEnabled: Boolean = false, udpgwPort: Int = 7300,
        maskLogs: Boolean = false
    ) {
        val usesProxy = proxyHost.isNotBlank() && (proxyHost != host || proxyPort != port)
        val protocolLabel = StringBuilder("SSH").apply {
            if (useSsl) append("-TLS")
            if (usesProxy) append("-Proxy")
            if (usePayload) append("-Payload")
        }.toString().let { if (it == "SSH") "SSH-Direct" else it }
        log("Protocol: $protocolLabel")
        log("Resolving Server...")
        val connectTotalStart = SystemClock.elapsedRealtime()

        SecurityCheck.quickScan()?.let { log(it) }
        log("Connection Setup Started.")

        val jsch = JSch()
        val sessionStart = SystemClock.elapsedRealtime()
        val s = jsch.getSession(user, host, port)
        log("SSH Session Created. (${SystemClock.elapsedRealtime() - sessionStart} ms)")
        s.setPassword(pass)
        s.setConfig("StrictHostKeyChecking", "no")
        s.setConfig("kex", "diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256," +
            "ecdh-sha2-nistp256,curve25519-sha256,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1")
        applyKeepAlive(s)

        log("Creating Socket Factory...")
        val socketFactory = PayloadSocketFactory(proxyHost, proxyPort, payload, host, usePayload, useSsl, sni) { msg ->
            log(msg)
        }
        s.setSocketFactory(socketFactory)
        log("Socket Factory Created.")

        log("SSH Handshake Starting...")
        val sshStart = SystemClock.elapsedRealtime()
        try {
            s.connect(10000)
            log("SSH Handshake Successful. (${SystemClock.elapsedRealtime() - sshStart} ms)")
        } catch (e: Throwable) {
            log("SSH Handshake Failed after ${SystemClock.elapsedRealtime() - sshStart} ms")
            throw e
        }
        session = s
        log("SSH Authentication Successful. (total ${SystemClock.elapsedRealtime() - connectTotalStart} ms)")

        socksServer = MiniSocks5Server(s, "127.0.0.1", socksPort) { msg -> log(msg) }
        socksServer?.start()
        backendProtocolName = "SSH SOCKS5"
        log("SOCKS5 Proxy Ready.")

        if (udpgwEnabled && udpgwPort > 0) {
            if (udpgwLocalPort == 0) udpgwLocalPort = (60001..64999).random()
            try {
                s.setPortForwardingL(udpgwLocalPort, "127.0.0.1", udpgwPort)
                log("UDPGW Forward Ready.")
            } catch (e: Throwable) {
                log("WARN: UDPGW Forward Failed.")
                udpgwLocalPort = 0
            }
        } else {
            udpgwLocalPort = 0
        }

        log("Creating VPN Interface...")
        val builder = Builder()
            .setSession("SSH-Proxy-Payload")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("1.1.1.1")
            .addDnsServer("9.9.9.9")
            .addDnsServer("8.8.4.4")
            .setMtu(1500)
            .setBlocking(true)

        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) { }

        tunFd = builder.establish()
        val fd = tunFd?.fd ?: throw IllegalStateException("VPN Interface establish() returned null")

        log("VPN Interface Created.")
        vpnActive = true
        networkAvailable = true

        scope.launch(Dispatchers.IO) {
            var firstRun = true
            while (vpnActive) {
                val rc = nativeStartTunnel(
                    fd, "127.0.0.1", socksPort, 1500,
                    if (udpgwLocalPort > 0) "gw" else "udp",
                    "127.0.0.1", udpgwLocalPort
                )
                if (!vpnActive) break
                if (!firstRun || rc != 0) {
                    log("ERROR: Native Tunnel Failed (rc=$rc).")
                }
                firstRun = false
                delay(500)
            }
        }

        log("Tunnel Started Successfully.")
        log("Connection Established.")
        broadcastStatus(STATE_READY)

        scope.launch(Dispatchers.IO) {
            var consecutiveFailures = 0
            while (vpnActive) {
                delay(6000)
                if (!vpnActive) break
                if (reconnecting) continue

                val sessionAlive = try { session?.isConnected == true } catch (_: Throwable) { false }
                if (!sessionAlive) {
                    log("ERROR: SSH Session Closed.")
                    consecutiveFailures = 0
                    scheduleSmartReconnect("session-closed", debounceMs = 0)
                    continue
                }

                val pingMs = checkTunnelLatencyMs(6000)
                if (pingMs != null) {
                    log("Ping: ${pingMs}ms OK.")
                    consecutiveFailures = 0
                    if (!networkAvailable) {
                        networkAvailable = true
                        broadcastStatus(STATE_READY)
                    }
                } else {
                    consecutiveFailures++
                    if (!hasUsableNetwork()) {
                        if (networkAvailable) networkAvailable = false
                        broadcastStatus(STATE_WAITING_NETWORK)
                    }
                    if (consecutiveFailures >= 8) {
                        consecutiveFailures = 0
                        val stillAlive = try { session?.isConnected == true } catch (_: Throwable) { false }
                        if (!stillAlive) {
                            log("ERROR: SSH Session Closed.")
                            scheduleSmartReconnect("session-closed", debounceMs = 0)
                        }
                    }
                }
            }
        }
    }

    private suspend fun connectXray(parsedConfigJson: String) {
        log("Protocol: V2Ray/Xray")
        log("Parsing Config...")

        val cfg = try {
            ParsedProxyConfig.fromJson(parsedConfigJson)
        } catch (e: Throwable) {
            throw IllegalArgumentException("ERROR: ${e.javaClass.simpleName}: ${realDetail(e)}", e)
        }
        backendProtocolName = "${cfg.protocol.name} SOCKS5"

        SecurityCheck.quickScan()?.let { log(it) }

        log("Generating Xray Config...")
        val xrayJson = try {
            XrayConfigBuilder.build(cfg, socksPort)
        } catch (e: Throwable) {
            throw IllegalArgumentException("ERROR: ${e.javaClass.simpleName}: ${realDetail(e)}", e)
        }

        log("Connecting...")
        val started = XrayCoreManager.start(
            context = applicationContext,
            configJson = xrayJson,
            localSocksPort = socksPort,
            listener = object : XrayCoreManager.Listener {
                override fun onXrayLog(message: String) { log(message) }
                override fun onXrayCrashed(reason: String) {
                    log("ERROR: Native Tunnel Failed. ($reason)")
                    if (vpnActive && !stopRequested) scheduleSmartReconnect("xray-crashed", debounceMs = 0)
                }
            }
        )
        if (!started) {
            throw java.io.IOException("Xray core failed to start / SOCKS5 not ready")
        }
        log("SOCKS5 Proxy Ready.")

        log("Creating VPN Interface...")
        val builder = Builder()
            .setSession("V2Ray-Xray")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("1.1.1.1")
            .addDnsServer("9.9.9.9")
            .addDnsServer("8.8.4.4")
            .setMtu(1500)
            .setBlocking(true)

        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) { }

        tunFd = builder.establish()
        val fd = tunFd?.fd ?: throw IllegalStateException("VPN Interface establish() returned null")

        log("VPN Interface Created.")
        vpnActive = true
        networkAvailable = true

        scope.launch(Dispatchers.IO) {
            var firstRun = true
            while (vpnActive) {
                val rc = nativeStartTunnel(
                    fd, "127.0.0.1", socksPort, 1500,
                    "udp", "127.0.0.1", 0
                )
                if (!vpnActive) break
                if (!firstRun || rc != 0) {
                    log("ERROR: Native Tunnel Failed (rc=$rc).")
                }
                firstRun = false
                delay(500)
            }
        }

        log("Tunnel Started Successfully.")

        var networkOk = hasUsableNetwork()
        var networkCheckAttempt = 0
        while (!networkOk && networkCheckAttempt < 6) {
            delay(300)
            networkOk = hasUsableNetwork()
            networkCheckAttempt++
        }
        if (!networkOk) {
            log("ERROR: No Network Available.")
            broadcastStatus(STATE_WAITING_NETWORK)
            throw java.io.IOException("No usable network")
        }

        log("Verifying Internet Connectivity...")
        if (!verifyTunnelConnectivity(8000)) {
            log("ERROR: Server Unreachable.")
            broadcastStatus(STATE_RECONNECTING)
            log("Reconnecting...")
            scheduleSmartReconnect("initial-server-unreachable", debounceMs = 0)
            return
        }

        log("Connection Established.")
        broadcastStatus(STATE_READY)
        startXrayPingMonitor()
    }

    private fun startXrayPingMonitor() {
        if (xrayPingMonitorJob?.isActive == true) return
        xrayPingMonitorJob = scope.launch(Dispatchers.IO) {
            var consecutiveFailures = 0
            while (vpnActive) {
                delay(XRAY_PING_INTERVAL_MS)
                if (!vpnActive) break
                if (reconnecting) continue
                if (mode != MODE_XRAY) break

                if (!XrayCoreManager.isRunning()) {
                    log("ERROR: Native Tunnel Failed.")
                    consecutiveFailures = 0
                    scheduleSmartReconnect("xray-not-running", debounceMs = 0)
                    continue
                }

                val pingMs = checkTunnelLatencyMs(6000)
                if (pingMs != null) {
                    log("Ping: ${pingMs}ms OK.")
                    consecutiveFailures = 0
                    if (!networkAvailable) {
                        networkAvailable = true
                        broadcastStatus(STATE_READY)
                    }
                } else {
                    consecutiveFailures++
                    if (!hasUsableNetwork()) {
                        if (networkAvailable) networkAvailable = false
                        broadcastStatus(STATE_WAITING_NETWORK)
                    }
                    if (consecutiveFailures >= 6) {
                        if (!XrayCoreManager.isRunning()) {
                            log("ERROR: Native Tunnel Failed.")
                            consecutiveFailures = 0
                            scheduleSmartReconnect("xray-not-running", debounceMs = 0)
                        }
                    }
                }
            }
        }
    }

    private fun isVpnTransport(network: Network): Boolean {
        return try {
            val caps = connectivityManager?.getNetworkCapabilities(network) ?: return false
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        } catch (_: Throwable) {
            false
        }
    }

    private fun hasUsableNetwork(): Boolean {
        return try {
            val cm = connectivityManager ?: return true
            val networks = cm.allNetworks
            if (networks.isEmpty()) return false
            networks.any { net ->
                val caps = cm.getNetworkCapabilities(net) ?: return@any false
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            }
        } catch (_: Throwable) {
            true
        }
    }

    private fun tryResumeSession(reason: String) {
        if (!vpnActive || stopRequested || autoReconnectSuspended) return
        if (reconnecting) return
        scope.launch {
            delay(600)
            if (!vpnActive || stopRequested || reconnecting) return@launch

            val sessionAlive = if (mode == MODE_XRAY) {
                XrayCoreManager.isRunning()
            } else {
                try { session?.isConnected == true } catch (_: Throwable) { false }
            }
            if (sessionAlive && verifyTunnelConnectivity(4000)) {
                log("Connection Established.")
                broadcastStatus(STATE_READY)
            } else {
                scheduleSmartReconnect(reason)
            }
        }
    }

    private fun scheduleSmartReconnect(reason: String, debounceMs: Long = 800) {
        if (!vpnActive || stopRequested || autoReconnectSuspended) return
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = scope.launch {
            if (debounceMs > 0) delay(debounceMs)
            smartReconnect(reason)
        }
    }

    private suspend fun smartReconnect(reason: String) {
        if (mode == MODE_XRAY) {
            smartReconnectXray(reason)
            return
        }
        if (!vpnActive || stopRequested) return
        if (autoReconnectSuspended) return
        if (reconnecting) return
        reconnecting = true
        val myGeneration = ++reconnectGeneration
        if (firstReconnectFailureAt == 0L) firstReconnectFailureAt = System.currentTimeMillis()
        broadcastStatus(STATE_RECONNECTING)
        log("Reconnecting...")

        try {
            try { socksServer?.stop() } catch (_: Throwable) { }
            try { session?.disconnect() } catch (_: Throwable) { }
            socksServer = null
            session = null

            var attempt = 0
            val maxAttempts = 6
            var success = false

            while (attempt < maxAttempts && vpnActive && !stopRequested && myGeneration == reconnectGeneration) {
                if (!networkAvailable) {
                    broadcastStatus(STATE_WAITING_NETWORK)
                    return
                }

                delay(if (attempt == 0) 0L else 500L)

                try {
                    log("Creating Socket Factory...")
                    val jsch = JSch()
                    val s = jsch.getSession(lastUser, lastHost, lastPort)
                    s.setPassword(lastPass)
                    s.setConfig("StrictHostKeyChecking", "no")
                    s.setConfig("kex", "diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256," +
                        "ecdh-sha2-nistp256,curve25519-sha256,diffie-hellman-group1-sha1,diffie-hellman-group14-sha1")
                    applyKeepAlive(s)
                    
                    val socketFactory = PayloadSocketFactory(lastProxyHost, lastProxyPort, lastPayload, lastHost, lastUsePayload, lastUseSsl, lastSni) { msg ->
                        log(msg)
                    }
                    s.setSocketFactory(socketFactory)
                    log("Socket Factory Created.")
                    
                    log("SSH Handshake Starting...")
                    s.connect(10000)
                    session = s
                    log("SSH Authentication Successful.")

                    val newSocks = MiniSocks5Server(s, "127.0.0.1", socksPort) { msg -> log(msg) }
                    newSocks.start()
                    socksServer = newSocks
                    log("SOCKS5 Proxy Ready.")

                    if (lastUdpgwEnabled && udpgwLocalPort > 0) {
                        try {
                            s.setPortForwardingL(udpgwLocalPort, "127.0.0.1", lastUdpgwPort)
                            log("UDPGW Forward Ready.")
                        } catch (e: Throwable) {
                            log("WARN: UDPGW Forward Failed.")
                        }
                    }

                    delay(400)
                    if (verifyTunnelConnectivity()) {
                        log("Connection Established.")
                        success = true
                    } else {
                        throw java.io.IOException("post-reconnect connectivity check failed")
                    }
                } catch (e: Throwable) {
                    attempt++
                    log(classifyConnectError(e))
                    try { socksServer?.stop() } catch (_: Throwable) { }
                    try { session?.disconnect() } catch (_: Throwable) { }
                    socksServer = null
                    session = null
                }

                if (success) break
            }

            if (success) {
                firstReconnectFailureAt = 0L
                broadcastStatus(STATE_READY)
            } else if (vpnActive && !stopRequested && myGeneration == reconnectGeneration) {
                val elapsed = System.currentTimeMillis() - firstReconnectFailureAt
                if (elapsed >= MAX_AUTO_RECONNECT_WINDOW_MS) {
                    autoReconnectSuspended = true
                    log("Waiting User Action...")
                    broadcastStatus(STATE_WAITING_USER_ACTION)
                } else {
                    broadcastStatus(STATE_WAITING_NETWORK)
                }
            }
        } finally {
            reconnecting = false
        }
    }

    private suspend fun smartReconnectXray(reason: String) {
        if (!vpnActive || stopRequested) return
        if (autoReconnectSuspended) return
        if (reconnecting) return
        reconnecting = true
        val myGeneration = ++reconnectGeneration
        if (firstReconnectFailureAt == 0L) firstReconnectFailureAt = System.currentTimeMillis()
        broadcastStatus(STATE_RECONNECTING)
        log("Reconnecting...")

        try {
            XrayCoreManager.stop()

            var attempt = 0
            val maxAttempts = 6
            var success = false

            while (attempt < maxAttempts && vpnActive && !stopRequested && myGeneration == reconnectGeneration) {
                if (!networkAvailable) {
                    broadcastStatus(STATE_WAITING_NETWORK)
                    return
                }
                delay(if (attempt == 0) 800 else backoffDelayMs(attempt))

                try {
                    val cfg = ParsedProxyConfig.fromJson(lastXrayParsedJson)
                    backendProtocolName = "${cfg.protocol.name} SOCKS5"
                    val xrayJson = XrayConfigBuilder.build(cfg, socksPort)
                    val started = XrayCoreManager.start(
                        context = applicationContext,
                        configJson = xrayJson,
                        localSocksPort = socksPort,
                        listener = object : XrayCoreManager.Listener {
                            override fun onXrayLog(message: String) { log(message) }
                            override fun onXrayCrashed(reason: String) {
                                if (vpnActive && !stopRequested) scheduleSmartReconnect("xray-crashed", debounceMs = 0)
                            }
                        }
                    )
                    if (!started) throw java.io.IOException("Xray restart failed")
                    log("SOCKS5 Proxy Ready.")

                    delay(400)
                    if (verifyTunnelConnectivity()) {
                        log("Connection Established.")
                        success = true
                    } else {
                        throw java.io.IOException("post-reconnect connectivity check failed")
                    }
                } catch (e: Throwable) {
                    attempt++
                    log(classifyConnectError(e))
                    XrayCoreManager.stop()
                }

                if (success) break
            }

            if (success) {
                firstReconnectFailureAt = 0L
                broadcastStatus(STATE_READY)
                startXrayPingMonitor()
            } else if (vpnActive && !stopRequested && myGeneration == reconnectGeneration) {
                val elapsed = System.currentTimeMillis() - firstReconnectFailureAt
                if (elapsed >= MAX_AUTO_RECONNECT_WINDOW_MS) {
                    autoReconnectSuspended = true
                    log("Waiting User Action...")
                    broadcastStatus(STATE_WAITING_USER_ACTION)
                } else {
                    broadcastStatus(STATE_WAITING_NETWORK)
                }
            }
        } finally {
            reconnecting = false
        }
    }

    private fun applyKeepAlive(s: Session) {
        try {
            s.serverAliveInterval = 30000
            s.serverAliveCountMax = 4
            s.timeout = 0
        } catch (_: Throwable) { }
    }

    private fun verifyTunnelConnectivity(timeoutMs: Int = 5000): Boolean {
        return checkTunnelLatencyMs(timeoutMs) != null
    }

    private val connectivityProbeUrls = listOf(
        "http://www.gstatic.com/generate_204",
        "http://cp.cloudflare.com/generate_204",
        "http://www.msftconnecttest.com/connecttest.txt"
    )

    private fun checkTunnelLatencyMs(timeoutMs: Int = 5000): Int? {
        val start = System.currentTimeMillis()
        val proxy = java.net.Proxy(java.net.Proxy.Type.SOCKS, java.net.InetSocketAddress("127.0.0.1", socksPort))
        val executor = java.util.concurrent.Executors.newFixedThreadPool(connectivityProbeUrls.size)
        try {
            val futures = connectivityProbeUrls.map { probe ->
                executor.submit<Boolean> {
                    try {
                        val url = java.net.URL(probe)
                        val conn = url.openConnection(proxy) as java.net.HttpURLConnection
                        conn.connectTimeout = timeoutMs
                        conn.readTimeout = timeoutMs
                        val code = conn.responseCode
                        conn.disconnect()
                        code in 200..299
                    } catch (_: Throwable) {
                        false
                    }
                }
            }
            val deadline = start + timeoutMs + 500
            while (System.currentTimeMillis() < deadline) {
                if (futures.any { it.isDone && it.get() == true }) {
                    return (System.currentTimeMillis() - start).toInt()
                }
                if (futures.all { it.isDone }) break
                Thread.sleep(20)
            }
            return null
        } finally {
            executor.shutdownNow()
        }
    }

    private fun realDetail(e: Throwable): String {
        val text = e.message?.takeIf { it.isNotBlank() } ?: e.cause?.message ?: "no detail"
        return text.take(160)
    }

    private fun classifyConnectError(e: Throwable): String {
        val msg = e.message ?: ""
        val cause = e.cause
        return when {
            e is java.net.UnknownHostException || cause is java.net.UnknownHostException ->
                "ERROR: DNS Resolution Failed."

            msg.contains("proxy", ignoreCase = true) &&
                (e is java.net.ConnectException || cause is java.net.ConnectException ||
                    msg.contains("timeout", ignoreCase = true)) ->
                "ERROR: Proxy Connection Failed."

            e is java.net.ConnectException || cause is java.net.ConnectException ||
                msg.contains("Connection refused", ignoreCase = true) ->
                "ERROR: Connection Refused."

            msg.contains("Connection reset", ignoreCase = true) ->
                "ERROR: TCP Connection Reset."

            e is java.net.SocketTimeoutException || cause is java.net.SocketTimeoutException ||
                msg.contains("timeout", ignoreCase = true) ->
                "ERROR: Connection Timeout."

            msg.contains("Auth fail", ignoreCase = true) ||
                msg.contains("Auth cancel", ignoreCase = true) ->
                "ERROR: Authentication Failed."

            msg.contains("session is down", ignoreCase = true) ||
                msg.contains("session is not open", ignoreCase = true) ||
                msg.contains("SessionClosed", ignoreCase = true) ->
                "ERROR: SSH Session Closed."

            msg.contains("UnknownHostKey", ignoreCase = true) ||
                msg.contains("HostKey", ignoreCase = true) ->
                "ERROR: Host Key Rejected."

            msg.contains("SSLHandshake", ignoreCase = true) ||
                msg.contains("SSLException", ignoreCase = true) ||
                e is javax.net.ssl.SSLException ->
                "ERROR: SSL/TLS Handshake Failed."

            msg.contains("VPN Interface", ignoreCase = true) ||
                e is IllegalStateException ->
                "ERROR: VPN Interface Failed."

            msg.contains("native", ignoreCase = true) || msg.contains("tunnel", ignoreCase = true) ->
                "ERROR: Native Tunnel Failed."

            msg.contains("301") || msg.contains("302") ||
                msg.contains("400") || msg.contains("403") || msg.contains("404") || msg.contains("500") ->
                "ERROR: Payload Rejected."

            msg.contains("payload", ignoreCase = true) ->
                "ERROR: Payload Rejected."

            else -> "ERROR: ${e.javaClass.simpleName}"
        }
    }

    private fun backoffDelayMs(attempt: Int): Long {
        val base = (800L * (1 shl attempt.coerceAtMost(4))).coerceAtMost(8000L)
        val jitter = (0..400).random()
        return base + jitter
    }

    private fun startProxyShareIfEnabled() {
        UnifiedProxySharingManager.startIfEnabled(
            context = applicationContext,
            backendName = backendProtocolName,
            localHost = "127.0.0.1",
            localPortProvider = { socksPort },
            onLog = { msg -> log(msg) }
        )
    }

    private fun cleanupResources() {
        vpnActive = false
        try { if (nativeLoaded) nativeStopTunnel() } catch (_: Throwable) { }
        try { socksServer?.stop() } catch (_: Throwable) { }
        try { session?.disconnect() } catch (_: Throwable) { }
        try { XrayCoreManager.stop() } catch (_: Throwable) { }
        try { UnifiedProxySharingManager.stop() } catch (_: Throwable) { }
        stopSpeedMonitor()
        try { tunFd?.close() } catch (_: Throwable) { }
        socksServer = null
        session = null
        tunFd = null
        log("Cleanup Completed.")
    }

    private fun stopVpn(finalState: String = STATE_DISCONNECTED) {
        if (vpnStopped) return
        vpnStopped = true

        vpnActive = false
        reconnectDebounceJob?.cancel()
        cleanupResources()
        if (finalState == STATE_FAILED) {
            // Error already logged
        } else {
            log("Disconnected.")
        }
        broadcastStatus(finalState)
        try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Throwable) { }

        Handler(Looper.getMainLooper()).postDelayed({
            Process.killProcess(Process.myPid())
        }, 300)
    }

    private fun log(msg: String) {
        val tagged = if (logTag.isNotEmpty() && !msg.startsWith("[PROXY]")) "[$logTag] $msg" else msg
        LogManager.add(applicationContext, tagged)
        try {
            val i = Intent(ACTION_LOG)
            i.putExtra(EXTRA_LOG_MESSAGE, tagged)
            sendBroadcast(i)
        } catch (_: Throwable) { }
    }

    private fun broadcastStatus(state: String) {
        StateStore.write(applicationContext, state)
        updateNotification(state)
        if (state == STATE_READY) {
            UpdateManager.checkOnceAsync(applicationContext)
            startProxyShareIfEnabled()
            startSpeedMonitor()
        } else {
            stopSpeedMonitor()
        }
        try {
            val i = Intent(ACTION_STATUS)
            i.putExtra(EXTRA_STATE, state)
            sendBroadcast(i)
        } catch (_: Throwable) { }
    }

    private fun notificationTextFor(state: String): String = when (state) {
        STATE_CONNECTING -> "Connecting..."
        STATE_READY -> "Connected"
        STATE_RECONNECTING -> "Reconnecting..."
        STATE_WAITING_NETWORK -> "Waiting Network..."
        STATE_WAITING_USER_ACTION -> "Waiting User Action..."
        STATE_FAILED -> "Connection Failed"
        else -> "Disconnected"
    }

    private fun buildContentIntent(): PendingIntent {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        return PendingIntent.getActivity(this, 0, intent, flags)
    }

    private fun formatSpeed(bytesPerSec: Long): String {
        if (bytesPerSec < 1024) return "${bytesPerSec}B/s"
        val kb = bytesPerSec / 1024.0
        if (kb < 1024) return String.format("%.0fKB/s", kb)
        val mb = kb / 1024.0
        return String.format("%.1fMB/s", mb)
    }

    private fun formatSize(bytes: Long): String {
        if (bytes < 1024) return "${bytes}B"
        val kb = bytes / 1024.0
        if (kb < 1024) return String.format("%.0fKB", kb)
        val mb = kb / 1024.0
        if (mb < 1024) return String.format("%.1fMB", mb)
        val gb = mb / 1024.0
        return String.format("%.2fGB", gb)
    }

    private fun startSpeedMonitor() {
        if (speedMonitorJob?.isActive == true) return
        val uid = Process.myUid()
        var lastRx = TrafficStats.getUidRxBytes(uid)
        var lastTx = TrafficStats.getUidTxBytes(uid)
        var lastTime = System.currentTimeMillis()
        val sessionStartRx = lastRx
        val sessionStartTx = lastTx

        speedMonitorJob = scope.launch {
            while (isActive) {
                delay(1000)
                val now = System.currentTimeMillis()
                val rx = TrafficStats.getUidRxBytes(uid)
                val tx = TrafficStats.getUidTxBytes(uid)
                val elapsedSec = ((now - lastTime).coerceAtLeast(1)) / 1000.0

                val rxSpeed = if (rx >= 0 && lastRx >= 0) ((rx - lastRx) / elapsedSec).toLong().coerceAtLeast(0) else 0L
                val txSpeed = if (tx >= 0 && lastTx >= 0) ((tx - lastTx) / elapsedSec).toLong().coerceAtLeast(0) else 0L

                val totalUsed = if (rx >= 0 && tx >= 0 && sessionStartRx >= 0 && sessionStartTx >= 0) {
                    ((rx - sessionStartRx) + (tx - sessionStartTx)).coerceAtLeast(0)
                } else 0L

                lastRx = rx
                lastTx = tx
                lastTime = now

                updateNotification(
                    STATE_READY,
                    "\u2193 ${formatSpeed(rxSpeed)}  \u2191 ${formatSpeed(txSpeed)}  \u2022  ${formatSize(totalUsed)}"
                )
            }
        }
    }

    private fun stopSpeedMonitor() {
        speedMonitorJob?.cancel()
        speedMonitorJob = null
    }

    private fun updateNotification(state: String, speedText: String? = null) {
        if (state == STATE_DISCONNECTED) return
        try {
            val text = if (state == STATE_READY && speedText != null) {
                "${notificationTextFor(state)}   $speedText"
            } else {
                notificationTextFor(state)
            }
            val notif = NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("MR VPN TUNNEL")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentIntent(buildContentIntent())
                .setOngoing(true)
                .build()
            val nm = getSystemService(NotificationManager::class.java)
            nm?.notify(NOTIF_ID, notif)
        } catch (_: Throwable) { }
    }

    private fun startForegroundNotif() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(CHANNEL_ID, "VPN Status", NotificationManager.IMPORTANCE_LOW)
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
        val notif = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("MR VPN TUNNEL")
            .setContentText(notificationTextFor(STATE_CONNECTING))
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(buildContentIntent())
            .setOngoing(true)
            .build()
        startForeground(NOTIF_ID, notif)
    }

    override fun onDestroy() {
        try { cleanupResources() } catch (_: Throwable) { }
        try { networkCallback?.let { connectivityManager?.unregisterNetworkCallback(it) } } catch (_: Throwable) { }
        reconnectDebounceJob?.cancel()
        scope.cancel()
        super.onDestroy()
    }

    override fun onRevoke() {
        stopRequested = true
        log("VPN Permission Revoked.")
        try { stopVpn() } catch (_: Throwable) { }
        super.onRevoke()
    }
}
