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

        // Connection-state broadcast (independent from the text log) so the
        // UI (MainActivity) can show CONNECTING / READY / RECONNECTING /
        // WAITING_NETWORK without parsing log text.
        const val ACTION_STATUS = "com.sshproxy.vpn.STATUS"
        const val EXTRA_STATE = "state"
        const val STATE_CONNECTING = "CONNECTING"
        const val STATE_READY = "READY"
        const val STATE_RECONNECTING = "RECONNECTING"
        const val STATE_WAITING_NETWORK = "WAITING_NETWORK"
        const val STATE_DISCONNECTED = "DISCONNECTED"
        const val STATE_FAILED = "FAILED"
        // Reached only after auto-reconnect has kept failing continuously for
        // MAX_AUTO_RECONNECT_WINDOW_MS - stops silently retrying forever and
        // asks the user to tap Connect again themselves.
        const val STATE_WAITING_USER_ACTION = "WAITING_USER_ACTION"

        // نوع الاتصال - إضافة جديدة بلا ما تمس السلوك الافتراضي (SSH يبقى
        // الافتراضي إذا الـextra ماجاش، بحال كان الوضع قبل هاد التعديل).
        const val EXTRA_MODE = "mode"
        const val MODE_SSH = "SSH"
        const val MODE_XRAY = "XRAY"
        // JSON ديال ParsedProxyConfig.toJson() - مبني من طرف MainActivity/
        // الاستيراد قبل ما يبدا الـservice.
        const val EXTRA_XRAY_CONFIG = "xrayParsedConfigJson"

        private const val MAX_AUTO_RECONNECT_WINDOW_MS = 60 * 60 * 1000L // 1 hour

        // Shares the VPN's internet connection with other devices on the same
        // network via a SOCKS5 proxy - a standalone addition, does not touch
        // the original connection logic. The port is fixed (not random like
        // the internal socksPort) since the user has to type it manually on
        // the other devices.
        private const val PROXY_SHARE_PREFS = "proxy_share_prefs"
        private const val PROXY_SHARE_ENABLED_KEY = "enabled"
        private const val PROXY_SHARE_PORT_KEY = "port"
        private const val PROXY_SHARE_DEFAULT_PORT = 8388

        private const val CHANNEL_ID = "vpn_status"
        private const val NOTIF_ID = 1

        @Volatile private var nativeLoaded = false
        @Volatile private var nativeLoadError: String? = null

        fun ensureNativeLoaded(ctx: Context): Boolean {
            if (nativeLoaded) return true
            synchronized(this) {
                if (nativeLoaded) return true
                return try {
                    // hev-socks5-tunnel كيتبنى بـ ndk-build (Android.mk) كـ
                    // .so منفصلة (شوف app/src/main/jni/CMakeLists.txt)،
                    // وhev-socks5-tunnel-jni.so كيربط معاها ديناميكيًا -
                    // فخاص الجوج يتحملو بهاد الترتيب.
                    System.loadLibrary("hev-socks5-tunnel")
                    System.loadLibrary("hev-socks5-tunnel-jni")
                    nativeLoaded = true
                    true
                } catch (e: Throwable) {
                    // Internal diagnostic only - never surfaced to the log (no
                    // library paths / exception text shown to the user).
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
    private var proxyShareServer: ProxyShareServer? = null
    private var speedMonitorJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Random local SOCKS5 port chosen once per service run (instead of a
    // fixed, hardcoded port) so a static analysis of the APK/traffic can't
    // rely on a known constant port. Every reconnect within the same run
    // reuses this same value, since the native tunnel (started once and
    // never restarted - see connect()) is already bound to it.
    @Volatile private var socksPort: Int = 10808

    // نوع الاتصال الحالي - SSH (الافتراضي، السلوك القديم بحالو) أو XRAY.
    @Volatile private var mode: String = MODE_SSH
    private var lastXrayParsedJson: String = ""

    // تاگ الجلسة الحالية (SSH-DIRECT / SSH-PROXY / SSH-PAYLOAD /
    // SSH-PROXY-PAYLOAD / SSH-TLS-PAYLOAD... / XRAY) - كيتحدد مرة وحدة فـ
    // onStartCommand() قبل ما يبدا أي log، وكل الأسطر التابعة لنفس الجلسة
    // (بما فيهم reconnect/tryResumeSession) كتستعمل نفس التاگ. هادشي كيمنع
    // اختلاط logs ديال SSH-PROXY مع SSH-PROXY-PAYLOAD فنفس الشاشة.
    @Volatile private var logTag: String = ""

    // Last successful connection parameters, kept in memory only, so we can
    // reconnect automatically (like HTTP Custom) when the network drops and
    // comes back, without the user tapping CONNECT again. The TUN interface
    // itself is never touched here - only the SSH session gets recreated.
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
    // البورت المحلي لي كيتوجه ليه setPortForwardingL - كيتحدد مرة وحدة عند
    // أول اتصال وكيتعاود استعمالو بحاله فكل smartReconnect، حيت hev-socks5-tunnel
    // (نفسو ماكيتوقفش عند reconnect) خدام عليه من البداية.
    private var udpgwLocalPort = 0
    private var lastMaskLogs = false

    @Volatile private var vpnActive = false      // true from establish() success until stopVpn()
    @Volatile private var reconnecting = false
    @Volatile private var stopRequested = false  // true once the user taps Disconnect manually (even mid-CONNECTING)
    @Volatile private var networkAvailable = true
    @Volatile private var reconnectGeneration = 0 // invalidates stale reconnect attempts when a newer trigger arrives
    @Volatile private var autoReconnectSuspended = false // true once the 1-hour retry ceiling is hit
    @Volatile private var firstReconnectFailureAt: Long = 0L

    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var reconnectDebounceJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        // We watch the default network: once it becomes available again after
        // being lost (Wi-Fi/mobile data toggled or switched) while VPN was
        // active, we run a full "smart reconnect" (Payload + SSH + SOCKS)
        // automatically, without the user tapping CONNECT again - exactly
        // like HTTP Custom.
        //
        // Important: the TUN interface (tunFd) and nativeStartTunnel() are
        // never touched here. The hev-socks5-tunnel library keeps global C
        // state that is not safe to start/stop repeatedly within the same
        // process (this was the cause of an earlier native crash). The
        // native tunnel keeps running at all times and simply talks to the
        // local SOCKS5 proxy - only the SSH session and SOCKS server
        // underneath get swapped when the network changes.
        try {
            connectivityManager = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onLost(network: Network) {
                    // Ignore our own VPN network going away - that just means
                    // stopVpn() tore it down deliberately, it is not the
                    // underlying Wi-Fi/mobile connection dropping.
                    if (isVpnTransport(network)) return
                    networkAvailable = false
                    if (vpnActive) {
                        broadcastStatus(STATE_WAITING_NETWORK)
                    }
                }

                override fun onAvailable(network: Network) {
                    // The system reports OUR OWN VPN interface as the new
                    // "default network" the instant establish() succeeds -
                    // that would otherwise immediately trigger a redundant
                    // tryResumeSession() right after we just connected,
                    // producing a duplicate "Connection Established." log
                    // line a few seconds into every session. Only real
                    // underlying-network changes (Wi-Fi/mobile) should ever
                    // reach tryResumeSession.
                    if (isVpnTransport(network)) return
                    networkAvailable = true
                    if (vpnActive) {
                        tryResumeSession("network-available")
                    }
                }

                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                    if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
                    // "onAvailable" can arrive before the network is actually
                    // validated (captive portal, SIM switch, etc). We use this
                    // callback to retry once the network becomes validated
                    // again after having been unavailable.
                    val validated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                    if (validated && !networkAvailable) {
                        networkAvailable = true
                        if (vpnActive) {
                            tryResumeSession("network-validated")
                        }
                    }
                }
            }
            // registerDefaultNetworkCallback tracks the device's single
            // "default" network (the one actual traffic would use) rather
            // than every network matching a capability filter. That is a
            // much more reliable signal for "did my connectivity really go
            // away" than registerNetworkCallback(request, ...), which can
            // fire onLost/onAvailable for secondary networks that aren't
            // actually the one we care about, or miss the real default
            // network dropping entirely on some OEM network stacks.
            connectivityManager?.registerDefaultNetworkCallback(networkCallback!!)
        } catch (_: Throwable) {
            // Network monitoring unavailable on this device/OS version; the
            // periodic tunnel connectivity check still provides a fallback.
        }
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

        // ===== V2Ray / Xray path - مستقل كامل عن كود SSH تحت =====
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
                log("ERROR: Invalid Configuration.")
                stopSelf()
                return START_NOT_STICKY
            }

            scope.launch {
                var attempt = 0
                while (isActive) {
                    try {
                        log("Preparing VPN Engine...")
                        if (!ensureNativeLoaded(applicationContext)) {
                            log("ERROR: Invalid Configuration.")
                            broadcastStatus(STATE_FAILED)
                            stopVpn()
                            return@launch
                        }
                        connectXray(parsedJson)
                        break // وصلنا لـ"Connection Established" بلا مشاكل
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
        // ===== نهاية V2Ray/Xray path - كود SSH الأصلي كيبدا هنا بلا تبديل =====

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

        // تحديد تاگ الجلسة قبل أي log - بحال طلب المستخدم (نقطة 7): SSH-PROXY
        // وSSH-PROXY-PAYLOAD ماخصهمش يختلطو. نفس الحساب لي كان قبل فـ connect()
        // (protocolLabel) - غير أننا كنديروه هنا بكري باش يغطي حتى "Starting
        // Service..." و"Preparing VPN Engine..." لي كيجيو قبل connect().
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
            log("ERROR: Invalid Configuration.")
            stopSelf()
            return START_NOT_STICKY
        }

        scope.launch {
            var attempt = 0
            while (isActive) {
                try {
                    log("Preparing VPN Engine...")
                    if (!ensureNativeLoaded(applicationContext)) {
                        log("ERROR: Invalid Configuration.")
                        broadcastStatus(STATE_FAILED)
                        stopVpn()
                        return@launch
                    }
                    connect(host, port, user, pass, proxyHost, proxyPort, payload, usePayload, useSsl, sni, udpgwEnabled, udpgwPort, maskLogs)
                    break // reached "Connection Established" with no issues
                } catch (e: Throwable) {
                    log(classifyConnectError(e))

                    if (stopRequested) {
                        // User tapped Disconnect manually mid-attempt - stop, no retry
                        stopVpn()
                        return@launch
                    }

                    // Like HTTP Custom: any error during the initial setup
                    // stage (before the tunnel is up) retries automatically
                    // from scratch, without killing the app. This is the
                    // initial setup stage only (SSH+TUN not yet built) - not
                    // the same path as "smart reconnect" (see smartReconnect),
                    // which only runs once the tunnel is already up.
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

        SecurityCheck.quickScan()?.let { log(it) }

        val jsch = JSch()
        val s = jsch.getSession(user, host, port)
        s.setPassword(pass)
        s.setConfig("StrictHostKeyChecking", "no")
        s.setConfig("kex", "diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256," +
            "ecdh-sha2-nistp256,curve25519-sha256")
        applyKeepAlive(s)

        s.setSocketFactory(PayloadSocketFactory(proxyHost, proxyPort, payload, host, usePayload, useSsl, sni) { msg ->
            log(msg)
        })

        log("Connecting...")
        try {
            s.connect(12000)
        } catch (e: Throwable) {
            log(classifyConnectError(e))
            throw e
        }
        session = s
        log("SSH Authentication Successful.")

        socksServer = MiniSocks5Server(s, "127.0.0.1", socksPort) { msg -> log(msg) }
        socksServer?.start()
        log("SOCKS5 Proxy Ready.")

        // UDPGW: SOCKS5 المحلي ديالنا كيدير غير CONNECT (TCP) وكيرفض UDP
        // ASSOCIATE، فـ hev-socks5-tunnel ماقدرش يمرر UDP عبرو. الحل: نفتحو
        // Local Port Forward جديد عبر SSH (setPortForwardingL) نحو udpgwPort
        // على 127.0.0.1 ديال السيرفر البعيد (فين خدام badvpn-udpgw)، ونعطيو
        // hev-socks5-tunnel هاذ البورت باش يمرر عليه UDP مباشرة (udp mode
        // "gw")، بدل ما يمر عبر السوكس5 لي مايدعمش UDP.
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

        // nativeStartTunnel is a blocking call (runs its own event loop) and
        // only returns once the tunnel stops or fails. Occasionally it can
        // return early even though the connection is expected to stay active
        // - this silently stops packet forwarding (internet stops while SSH
        // still looks "connected"). We keep relaunching it automatically as
        // long as vpnActive stays true (i.e. the user hasn't disconnected).
        //
        // This loop is the only place allowed to call
        // nativeStartTunnel/nativeStopTunnel after the initial connection -
        // smartReconnect() never touches it.
        scope.launch(Dispatchers.IO) {
            var firstRun = true
            while (vpnActive) {
                val rc = nativeStartTunnel(
                    fd, "127.0.0.1", socksPort, 1500,
                    if (udpgwLocalPort > 0) "gw" else "udp",
                    "127.0.0.1", udpgwLocalPort
                )
                if (!vpnActive) break
                // The native loop returning while vpnActive is still true
                // means it exited unexpectedly (not because the user
                // disconnected) - surface that instead of silently retrying
                // forever with no explanation in the log.
                if (!firstRun || rc != 0) {
                    log("ERROR: Native Tunnel Failed.")
                }
                firstRun = false
                delay(500)
            }
        }

        log("Tunnel Started Successfully.")
        log("Connection Established.")
        broadcastStatus(STATE_READY)

        // SSH can report "connected" even though real internet isn't passing
        // through the tunnel. Like HTTP Custom's 200 OK ping, we run a real
        // periodic check through SOCKS5 itself, logging the latency so the
        // user can see the connection speed - after enough consecutive
        // failures we treat the connection as effectively down and run
        // smartReconnect() (without touching TUN/native tunnel and without
        // Process.killProcess), instead of leaving the user staring at
        // "DISCONNECT" while the internet doesn't actually work.
        scope.launch(Dispatchers.IO) {
            var consecutiveFailures = 0
            while (vpnActive) {
                delay(6000)
                if (!vpnActive) break
                if (reconnecting) continue // a reconnect is already running

                // Ping is only a quality indicator here, never a trigger on
                // its own - exactly like HTTP Custom. A weak network can miss
                // several pings in a row while the SSH session itself is
                // still perfectly alive; we only ever reconnect once the SSH
                // session is confirmed dead.
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
                        // Network/tunnel recovered on its own between ping
                        // cycles (e.g. the NetworkCallback's onAvailable
                        // never fired on this device) - flip the UI back
                        // from "RECONNECTING..." to normal without a full
                        // reconnect, since the ping already proves traffic
                        // is flowing again.
                        networkAvailable = true
                        broadcastStatus(STATE_READY)
                    }
                } else {
                    consecutiveFailures++
                    // Second, independent check for "no real network" beyond
                    // the NetworkCallback: some OEM network stacks are slow
                    // or unreliable about delivering onLost, which would
                    // otherwise leave the button stuck showing "DISCONNECT"
                    // instead of "RECONNECTING..." while the network is
                    // actually down. Cheap and idempotent - only updates the
                    // UI-facing status, never touches the SSH session.
                    if (!hasUsableNetwork()) {
                        if (networkAvailable) networkAvailable = false
                        broadcastStatus(STATE_WAITING_NETWORK)
                    }
                    // Allow a long run of consecutive ping timeouts (like
                    // HTTP Custom) before even re-checking the session -
                    // a ping timeout alone never proves the tunnel is down.
                    if (consecutiveFailures >= 8) {
                        consecutiveFailures = 0
                        val stillAlive = try { session?.isConnected == true } catch (_: Throwable) { false }
                        if (!stillAlive) {
                            log("ERROR: SSH Session Closed.")
                            scheduleSmartReconnect("session-closed", debounceMs = 0)
                        }
                        // else: SSH still reports alive - network is just
                        // degraded, the session is left untouched.
                    }
                }
            }
        }
    }

    /**
     * نفس دور connect() بالضبط لكن بـXray-core بدل JSch/MiniSocks5Server.
     * TUN interface وnativeStartTunnel كيبقاو بحالهم بلا تبديل - Xray غير
     * كيعوض الجزء اللي كان كيبني الـSOCKS5 المحلي (SSH session + MiniSocks5Server).
     */
    private suspend fun connectXray(parsedConfigJson: String) {
        log("Protocol: V2Ray/Xray")
        log("Parsing Config...")

        val cfg = try {
            ParsedProxyConfig.fromJson(parsedConfigJson)
        } catch (e: Throwable) {
            throw IllegalArgumentException("ERROR: Invalid Configuration.")
        }

        SecurityCheck.quickScan()?.let { log(it) }

        log("Generating Xray Config...")
        val xrayJson = try {
            XrayConfigBuilder.build(cfg, socksPort)
        } catch (e: Throwable) {
            throw IllegalArgumentException("ERROR: Invalid Configuration.")
        }

        log("Connecting...")
        val started = XrayCoreManager.start(
            context = applicationContext,
            configJson = xrayJson,
            localSocksPort = socksPort,
            listener = object : XrayCoreManager.Listener {
                override fun onXrayLog(message: String) { log(message) }
                override fun onXrayCrashed(reason: String) {
                    log("ERROR: Native Tunnel Failed.")
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

        // نفس منطق connect(): nativeStartTunnel blocking، وكنعاودو نشغلوه
        // إلا رجع بلا ما vpnActive تكون false (خروج غير متوقع).
        scope.launch(Dispatchers.IO) {
            var firstRun = true
            while (vpnActive) {
                val rc = nativeStartTunnel(
                    fd, "127.0.0.1", socksPort, 1500,
                    "udp", "127.0.0.1", 0
                )
                if (!vpnActive) break
                if (!firstRun || rc != 0) {
                    log("ERROR: Native Tunnel Failed.")
                }
                firstRun = false
                delay(500)
            }
        }

        log("Tunnel Started Successfully.")

        // ===== تحقق حقيقي قبل أي إعلان CONNECTED =====
        // XrayCoreManager.start() كيرجع true غير ملي الـSOCKS5 المحلي بدا
        // كيخدم - هادشي كيوقع حتى لو Server خاطئ، معطل، أو مافيهش Internet
        // خالص (الـoutbound الحقيقي عند Xray مايتفحصش هنا). خصنا نتأكدو من
        // الشبكة أولا، ومن بعد نديرو probe حقيقي عبر التونيل نفسو - نفس
        // verifyTunnelConnectivity() المستعملة فمسار SSH - قبل ما نبدلو
        // الحالة لـSTATE_READY (كيبانلها فالواجهة "CONNECTED").
        //
        // مهلة قصيرة قبل الحكم النهائي: مباشرة بعد establish() (إنشاء
        // واجهة VPN)، بعض الأجهزة كيبقى ConnectivityManager ديالها فمرحلة
        // انتقالية وكيرجع مؤقتا hasUsableNetwork()=false رغم أن 4G/WiFi
        // فعليا خدامة (race condition) - عاودنا الفحص لبضع مرات بفواصل
        // قصيرة قبل ما نعلن WAITING_NETWORK فعلا، بدل فحص واحد فوري.
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
            // Server خاطئ/منتهي (الشبكة موجودة وتخدم - hasUsableNetwork()
            // نجحت فوق - لكن ماكاين حتى probe نجح عبر التونيل). هادي
            // حالة نهائية (permanent) ماشي حالة "الشبكة راه غادي ترجع" -
            // فماخصنا نخليوها تدخل لنفس حلقة الـretry اللانهائية لي
            // كاينة فـonStartCommand (لي كانت هي السبب ديال الـcrash: كل
            // محاولة كتعاود تشغل Xray core من جديد بزربة كبيرة بلا ما
            // القديمة توقف مزيان). هنا كنوقفو الـengine وVPN بشكل آمن
            // وكامل (stopVpn عبر cleanupResources) ونعلنو STATE_FAILED
            // مرة وحدة، بلا retry - المستخدم كيقدر يبدل Server ويعاود
            // CONNECT بيدو. return (ماشي throw) باش onStartCommand
            // مايعاودش يحاول من جديد.
            log("ERROR: Server Unreachable.")
            stopVpn(STATE_FAILED)
            return
        }

        log("Connection Established.")
        broadcastStatus(STATE_READY)
        // مراقبة دورية: Xray core مازال خدام + SOCKS5 مازال كيرد (نفس فكرة
        // ping loop ديال SSH، لكن بلا session SSH - كنعتمدو غير على
        // XrayCoreManager.isRunning() وping حقيقي عبر checkTunnelLatencyMs).
        scope.launch(Dispatchers.IO) {
            var consecutiveFailures = 0
            while (vpnActive) {
                delay(6000)
                if (!vpnActive) break
                if (reconnecting) continue
                if (mode != MODE_XRAY) break // احتياط: reconnect بدلات الوضع

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
                    if (consecutiveFailures >= 3 && networkAvailable) {
                        log("ERROR: Native Tunnel Failed.")
                        consecutiveFailures = 0
                        scheduleSmartReconnect("xray-ping-failed", debounceMs = 0)
                    }
                }
            }
        }
    }

    /** True if the given network is our own VPN tunnel rather than the real underlying connection. */
    private fun isVpnTransport(network: Network): Boolean {
        return try {
            val caps = connectivityManager?.getNetworkCapabilities(network) ?: return false
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        } catch (_: Throwable) {
            false
        }
    }

    /** True if the device currently reports an active *non-VPN* network capable of carrying real internet traffic. */
    private fun hasUsableNetwork(): Boolean {
        return try {
            val cm = connectivityManager ?: return true // unknown -> don't assume the worst
            val networks = cm.allNetworks
            if (networks.isEmpty()) return false
            networks.any { net ->
                val caps = cm.getNetworkCapabilities(net) ?: return@any false
                !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                    caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            }
        } catch (_: Throwable) {
            true // unknown -> don't assume the worst
        }
    }

    /**
     * Called whenever the underlying network comes back (Wi-Fi/data switch,
     * brief drop, captive portal cleared, etc). Per the "HTTP Custom
     * behaviour" requirement, a network blip must NOT force a fresh
     * Payload + SSH re-authentication if the existing SSH session actually
     * survived it (JSch/TCP can often keep the socket alive across a short
     * gap). We only pay the full smartReconnect cost when the session is
     * genuinely gone.
     */
    private fun tryResumeSession(reason: String) {
        if (!vpnActive || stopRequested || autoReconnectSuspended) return
        if (reconnecting) return
        scope.launch {
            // Give the OS a brief moment to finish settling routes/DNS after
            // a network switch before probing.
            delay(600)
            if (!vpnActive || stopRequested || reconnecting) return@launch

            val sessionAlive = if (mode == MODE_XRAY) {
                XrayCoreManager.isRunning()
            } else {
                try { session?.isConnected == true } catch (_: Throwable) { false }
            }
            if (sessionAlive && verifyTunnelConnectivity(4000)) {
                // The existing SSH session survived the network change - no
                // re-authentication, no Payload resend, nothing torn down.
                log("Connection Established.")
                broadcastStatus(STATE_READY)
            } else {
                // Session is genuinely gone (or unreachable) - only now do we
                // pay for a full reconnect.
                scheduleSmartReconnect(reason)
            }
        }
    }

    /**
     * Schedules smartReconnect() with a small debounce so we don't run
     * multiple attempts at once (e.g. onAvailable and onCapabilitiesChanged
     * can both fire close together during a network switch). Each new call
     * cancels the previous one.
     */
    private fun scheduleSmartReconnect(reason: String, debounceMs: Long = 800) {
        if (!vpnActive || stopRequested || autoReconnectSuspended) return
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = scope.launch {
            if (debounceMs > 0) delay(debounceMs)
            smartReconnect(reason)
        }
    }

    /**
     * Full application-level smart reconnect: stop the old SSH session,
     * resend the payload, open a new SSH session, and restart the SOCKS5
     * server - without touching the TUN interface (tunFd) or
     * nativeStartTunnel/nativeStopTunnel, and without Process.killProcess.
     *
     * Reason: hev-socks5-tunnel keeps global C state, and stopping/starting
     * it repeatedly within the same process (without killing the process)
     * causes a crash. The original tunnel (TUN + native loop) keeps running
     * at all times and talks to the local SOCKS5 proxy - so it's enough to
     * swap out what's underneath (SSH+SOCKS) to bring the internet back,
     * exactly like professional VPN apps that never flicker the system's
     * VPN icon during a reconnect.
     */
    private suspend fun smartReconnect(reason: String) {
        if (mode == MODE_XRAY) {
            smartReconnectXray(reason)
            return
        }
        if (!vpnActive || stopRequested) return
        if (autoReconnectSuspended) return // ceiling already hit - wait for the user to tap Connect
        if (reconnecting) return
        reconnecting = true
        val myGeneration = ++reconnectGeneration
        if (firstReconnectFailureAt == 0L) firstReconnectFailureAt = System.currentTimeMillis()
        broadcastStatus(STATE_RECONNECTING)
        log("Reconnecting...")

        try {
            // 1) Stop the old SSH session + old SOCKS server (TUN untouched)
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

                // Network "available" doesn't mean the system's DNS/routing is
                // 100% ready at that exact instant (especially switching
                // between Wi-Fi/mobile data) - we give it a short grace period
                // and retry a few times before giving up.
                delay(if (attempt == 0) 800 else backoffDelayMs(attempt))

                try {
                    // 2) + 3) Resend the payload and open a new SSH session
                    val jsch = JSch()
                    val s = jsch.getSession(lastUser, lastHost, lastPort)
                    s.setPassword(lastPass)
                    s.setConfig("StrictHostKeyChecking", "no")
                    s.setConfig("kex", "diffie-hellman-group-exchange-sha256,diffie-hellman-group14-sha256," +
                        "ecdh-sha2-nistp256,curve25519-sha256")
                    applyKeepAlive(s)
                    s.setSocketFactory(PayloadSocketFactory(lastProxyHost, lastProxyPort, lastPayload, lastHost, lastUsePayload, lastUseSsl, lastSni) { msg ->
                        log(msg)
                    })
                    s.connect(15000)
                    session = s
                    log("SSH Authentication Successful.")

                    // 4) Restart SOCKS5 on the same port - nativeStartTunnel
                    // keeps working transparently since the original tunnel
                    // is still running
                    val newSocks = MiniSocks5Server(s, "127.0.0.1", socksPort) { msg -> log(msg) }
                    newSocks.start()
                    socksServer = newSocks
                    log("SOCKS5 Proxy Ready.")

                    // إعادة فتح Local Port Forward ديال UDPGW بنفس البورت
                    // المحلي القديم (udpgwLocalPort) - hev-socks5-tunnel
                    // نفسو ماتوقفش (التونيل الأصلي باقي خدام)، فخاصو يلقى
                    // نفس البورت شغال من جديد بعد كل reconnect.
                    if (lastUdpgwEnabled && udpgwLocalPort > 0) {
                        try {
                            s.setPortForwardingL(udpgwLocalPort, "127.0.0.1", lastUdpgwPort)
                            log("UDPGW Forward Ready.")
                        } catch (e: Throwable) {
                            log("WARN: UDPGW Forward Failed.")
                        }
                    }

                    // Real check: confirm the internet is actually passing
                    // through the tunnel before declaring success (like HTTP
                    // Custom's 200 OK ping)
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
                    // Stop retrying silently forever - after a full hour of
                    // continuous failure this is very unlikely to fix itself,
                    // and endless retries just drain the battery. The user
                    // has to tap Connect again to try a truly fresh start.
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

    /**
     * نسخة Xray ديال smartReconnect(): كيوقف Xray core القديم ويشغل واحد
     * جديد بنفس الكونفيغ (lastXrayParsedJson) على نفس socksPort - TUN
     * interface وnativeStartTunnel بلا مساس، نفس مبدأ smartReconnect() ديال SSH.
     */
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

    /**
     * SSH-level KeepAlive tuning, applied to every session (initial connect
     * and every smart reconnect). A server-alive packet is sent whenever the
     * link has been silent for [ServerAliveInterval]; the session is only
     * declared dead after [ServerAliveCountMax] consecutive packets go
     * unanswered. Using a longer interval and a higher count (instead of
     * JSch's aggressive defaults) gives weak/flaky mobile networks enough
     * room to recover on their own - mirroring HTTP Custom's tolerance -
     * instead of tearing the session down on the first hiccup.
     */
    private fun applyKeepAlive(s: Session) {
        try {
            s.serverAliveInterval = 30000  // ping the server every 30s of silence (lower battery cost)
            s.serverAliveCountMax = 4      // allow 4 misses (~2 min) before JSch itself gives up
            s.timeout = 0                  // no hard session I/O timeout; KeepAlive governs liveness instead
        } catch (_: Throwable) { }
    }

    /** Real check that internet is passing through the tunnel via the local SOCKS5 proxy. */
    private fun verifyTunnelConnectivity(timeoutMs: Int = 5000): Boolean {
        return checkTunnelLatencyMs(timeoutMs) != null
    }

    // Several independent "204 No Content"-style probes instead of only
    // Google's. Some countries/carriers block gstatic.com specifically while
    // the tunnel itself is perfectly fine - trying a short list and taking
    // the first success avoids a false "connection down" verdict.
    private val connectivityProbeUrls = listOf(
        "http://www.gstatic.com/generate_204",
        "http://cp.cloudflare.com/generate_204",
        "http://www.msftconnecttest.com/connecttest.txt"
    )

    /** Same check as [verifyTunnelConnectivity] but returns the round-trip time in ms (null on failure), so the user can see connection speed in the log. Runs all probes in parallel and returns as soon as the first one succeeds, instead of waiting on each sequentially (which could take up to timeoutMs * probe count). */
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
            // Bounded overall by ~timeoutMs (all probes run at once), not
            // timeoutMs * number of probes like a sequential loop would be.
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

    /**
     * Maps any connection error to one of a small set of clean, English,
     * non-sensitive log lines. The raw exception (class name, message,
     * stack trace) and any host/IP/port it might contain are never logged -
     * only this fixed, safe phrase is shown to the user.
     */
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
                "ERROR: Invalid Configuration."

            msg.contains("SSLHandshake", ignoreCase = true) ||
                msg.contains("SSLException", ignoreCase = true) ||
                e is javax.net.ssl.SSLException ->
                "ERROR: Invalid Configuration."

            msg.contains("VPN Interface", ignoreCase = true) ||
                e is IllegalStateException ->
                "ERROR: VPN Interface Failed."

            msg.contains("native", ignoreCase = true) || msg.contains("tunnel", ignoreCase = true) ->
                "ERROR: Native Tunnel Failed."

            msg.contains("301") || msg.contains("302") ->
                "ERROR: Payload Rejected."

            msg.contains("400") || msg.contains("403") || msg.contains("404") || msg.contains("500") ->
                "ERROR: Payload Rejected."

            msg.contains("payload", ignoreCase = true) ->
                "ERROR: Payload Rejected."

            else -> "ERROR: Network Unreachable."
        }
    }

    /** Exponential backoff + random jitter between reconnect attempts. */
    private fun backoffDelayMs(attempt: Int): Long {
        val base = (800L * (1 shl attempt.coerceAtMost(4))).coerceAtMost(8000L) // 800,1600,3200,6400,8000...
        val jitter = (0..400).random()
        return base + jitter
    }

    /**
     * Reads the setting (enabled + port) from SharedPreferences
     * ("proxy_share_prefs") and starts ProxyShareServer if enabled and not
     * already running. The targetPortProvider = { socksPort } always points
     * to whatever the current internal port is (SSH or Xray) - without
     * touching socksPort itself or the original tunnel-building logic.
     */
    private fun startProxyShareIfEnabled() {
        try {
            val prefs = applicationContext.getSharedPreferences(PROXY_SHARE_PREFS, Context.MODE_PRIVATE)
            val enabled = prefs.getBoolean(PROXY_SHARE_ENABLED_KEY, false)
            if (!enabled) return
            if (proxyShareServer?.isRunning() == true) return

            val port = prefs.getInt(PROXY_SHARE_PORT_KEY, PROXY_SHARE_DEFAULT_PORT)
            val server = ProxyShareServer(port, { socksPort }) { msg -> log(msg) }
            if (server.start()) {
                proxyShareServer = server
            }
        } catch (_: Throwable) { }
    }

    private fun cleanupResources() {
        // مهم: قبل هاد السطر، vpnActive كان ماكيتبدلش هنا خالص - هادشي
        // كان كيخلي حلقة إعادة تشغيل التونيل الأصلي (scope.launch { while
        // (vpnActive) { nativeStartTunnel... } }) خدامة فالخلفية بلا ما
        // تتوقف حقيقة بين كل محاولة اتصال فاشلة (retry)، وكتعاود تنادي
        // nativeStartTunnel() بـfd تسد بعدها مباشرة (tunFd?.close() تحت) -
        // هادشي كيسبب حلقات متوازية فوق بعضياتهم، وhev-socks5-tunnel (كيحتفظ
        // بحالة C عامة) ماشي آمن يتصاوب فيه start/stop متوازيين - غادي
        // يسبب native crash حقيقي (كيطيح التطبيق كاملو بلا Exception
        // ديال Kotlin). هادشي كيبان بسرعة أكبر ملي مافيهش شبكة خالص، حيت
        // كل محاولة كتفشل وتعاود بزربة (بلا الوقت الكافي باش القديمة
        // توقف). تبديل vpnActive لـfalse هنا (قبل nativeStopTunnel وقبل
        // إغلاق tunFd) كيضمن أن الحلقة توقف نهائيا قبل ما نسد الـfd.
        vpnActive = false
        try { if (nativeLoaded) nativeStopTunnel() } catch (_: Throwable) { }
        try { socksServer?.stop() } catch (_: Throwable) { }
        try { session?.disconnect() } catch (_: Throwable) { }
        try { XrayCoreManager.stop() } catch (_: Throwable) { }
        try { proxyShareServer?.stop() } catch (_: Throwable) { }
        stopSpeedMonitor()
        try { tunFd?.close() } catch (_: Throwable) { }
        socksServer = null
        session = null
        proxyShareServer = null
        tunFd = null
        log("Cleanup Completed.")
    }

    /**
     * Important: hev-socks5-tunnel keeps internal global state and is not
     * designed to run twice within the same process. Rather than trying to
     * clean it up manually (fragile and complex), we kill the whole process
     * (a separate process ":vpnproc", not the main app) so the next
     * connection always starts perfectly clean, without needing to clear
     * app data manually each time.
     *
     * This function is only called when the user taps Disconnect manually,
     * or when the very first connection (native lib / first TUN) fails
     * terminally. Automatic reconnects triggered by network changes
     * (smartReconnect) never call this - VPN stays active at all times
     * without Process.killProcess.
     */
    /**
     * finalState: الحالة اللي كتبعث قبل التوقف النهائي - STATE_DISCONNECTED
     * (الافتراضي، ديسكونيكت يدوي عادي) أو STATE_FAILED (Server خاطئ/منتهي
     * ديال V2Ray/Xray/Shadowsocks - نفس التنظيف الآمن والكامل، غير الحالة
     * المبعوثة كتبقى FAILED باش المستخدم يعرف بلي كاين مشكل فالكونفيغ،
     * ماشي ديسكونيكت عادي). الـkill process فكلتا الحالتين ضروري - نفس
     * السبب المذكور فوق: hev-socks5-tunnel/Xray core ماشي آمنين يعاودو
     * start/stop بزاف داخل نفس الـprocess.
     */
    private fun stopVpn(finalState: String = STATE_DISCONNECTED) {
        vpnActive = false
        reconnectDebounceJob?.cancel()
        cleanupResources()
        if (finalState == STATE_FAILED) {
            // سطر log الخطأ الحقيقي (Server Unreachable...) اتسجل ديجا قبل
            // ما نوصلو لهنا - "Disconnected." هنا يقدر يخلط المستخدم أنو
            // هو لي دس على Disconnect.
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
        val tagged = if (logTag.isNotEmpty()) "[$logTag] $msg" else msg
        FileLogger.append(applicationContext, tagged)
        try {
            val i = Intent(ACTION_LOG)
            i.putExtra(EXTRA_LOG_MESSAGE, tagged)
            sendBroadcast(i)
        } catch (_: Throwable) { }
    }

    private fun broadcastStatus(state: String) {
        // Persisted first (cross-process, survives the activity being
        // recreated / the app being backgrounded) so MainActivity always has
        // a real, current source of truth to sync against - never just the
        // last value it happened to hold in memory.
        StateStore.write(applicationContext, state)
        updateNotification(state)
        if (state == STATE_READY) {
            // Fire the (at most once per process) update check only once we
            // have a real, working connection - never on cold start, since
            // most users have no usable internet before the VPN comes up.
            // Fully async, fully independent of the VPN itself; see
            // UpdateManager for the "never affects the tunnel" guarantees.
            UpdateManager.checkOnceAsync(applicationContext)
            startProxyShareIfEnabled()
            startSpeedMonitor()
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

    /**
     * Tapping the notification opens MainActivity directly - standard
     * behavior in every other VPN app. FLAG_IMMUTABLE is required on
     * Android 12+ for PendingIntents that don't need to be mutated.
     */
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

    /**
     * Samples TrafficStats for this app's UID once a second and rebuilds the
     * notification with a live download/upload speed line, same idea as
     * HTTP Custom / other VPN apps. Only runs while the tunnel is READY -
     * started from broadcastStatus(), stopped from cleanupResources(), so it
     * never touches the actual connection/tunnel logic.
     */
    private fun startSpeedMonitor() {
        if (speedMonitorJob?.isActive == true) return
        val uid = Process.myUid()
        var lastRx = TrafficStats.getUidRxBytes(uid)
        var lastTx = TrafficStats.getUidTxBytes(uid)
        var lastTime = System.currentTimeMillis()

        speedMonitorJob = scope.launch {
            while (isActive) {
                delay(1000)
                val now = System.currentTimeMillis()
                val rx = TrafficStats.getUidRxBytes(uid)
                val tx = TrafficStats.getUidTxBytes(uid)
                val elapsedSec = ((now - lastTime).coerceAtLeast(1)) / 1000.0

                // getUidRxBytes/TxBytes can return -1 on some devices/ROMs
                // if per-uid stats aren't available - fall back to "0" speed
                // instead of a garbage negative number.
                val rxSpeed = if (rx >= 0 && lastRx >= 0) ((rx - lastRx) / elapsedSec).toLong().coerceAtLeast(0) else 0L
                val txSpeed = if (tx >= 0 && lastTx >= 0) ((tx - lastTx) / elapsedSec).toLong().coerceAtLeast(0) else 0L

                lastRx = rx
                lastTx = tx
                lastTime = now

                updateNotification(STATE_READY, "\u2193 ${formatSpeed(rxSpeed)}  \u2191 ${formatSpeed(txSpeed)}")
            }
        }
    }

    private fun stopSpeedMonitor() {
        speedMonitorJob?.cancel()
        speedMonitorJob = null
    }

    private fun updateNotification(state: String, speedText: String? = null) {
        // DISCONNECTED means the foreground notification is about to be
        // removed anyway (stopVpn already calls stopForeground) - no need to
        // rebuild it for that transition.
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
        // The system calls this when our VPN permission is taken away -
        // almost always because the user started a different VPN app (e.g.
        // HTTP Custom), which forces Android to revoke whichever VPN was
        // previously active. The TUN interface is already gone at this
        // point, so this is a real, final disconnect: run the exact same
        // full shutdown as a manual Disconnect (stop everything, persist
        // DISCONNECTED, notify the UI, stop the foreground notification,
        // end the process) instead of only freeing resources silently.
        // Without this, vpnActive stayed true forever, so the ping loop and
        // the native-tunnel relaunch loop kept spinning uselessly on a dead
        // TUN fd, and the button stayed stuck on DISCONNECT.
        stopRequested = true
        log("VPN Permission Revoked.")
        try { stopVpn() } catch (_: Throwable) { }
        super.onRevoke()
    }
}
