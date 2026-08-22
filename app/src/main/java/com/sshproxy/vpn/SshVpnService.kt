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
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
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
        const val EXTRA_REQUEST_ID = "requestId"

        private const val MAX_AUTO_RECONNECT_WINDOW_MS = 60 * 60 * 1000L // 1 hour

        // Proxy Sharing settings (enabled flag, port, prefs key/name) now
        // live in UnifiedProxySharingManager - the single, protocol-agnostic
        // place this feature is implemented. See that class.

        // Xray connection-health probe interval, per explicit request: was
        // 6000ms, now 1000ms for much faster failure detection and a live
        // per-second ping in the log. Trade-off worth knowing: this fires a
        // real network probe (checkTunnelLatencyMs, up to 3 parallel HTTP
        // requests) every second for as long as the VPN is connected -
        // noticeably more data/battery use than the previous 6s interval.
        // If that turns out to be too aggressive, raising this back up
        // (e.g. 3000-5000ms) is the only line that needs to change.
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
    @Volatile private var backendProtocolName: String = "SOCKS5" // for UnifiedProxySharingManager's log ("SSH SOCKS5", "VLESS SOCKS5", ...)
    private var speedMonitorJob: Job? = null
    private var xrayPingMonitorJob: Job? = null
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
    @Volatile private var vpnStopped = false     // guards stopVpn() against running its body twice (see stopVpn)
    @Volatile private var requestId: Long = 0L // identifies the current connection/config session
    @Volatile private var reconnecting = false
    @Volatile private var stopRequested = false  // true once the user taps Disconnect manually (even mid-CONNECTING)
    @Volatile private var networkAvailable = true

    // === Session epoch (race-condition fix: Stop vs Reconnect) ===
    // Bumped (1) at the very start of every fresh ACTION_CONNECT in
    // onStartCommand, and (2) at the very start of stopVpn(). Every
    // long-running/async connect or reconnect coroutine captures the
    // epoch value that was current when IT started ("myEpoch"/"epoch")
    // and re-checks it against the live `sessionEpoch` field after every
    // suspend point (delay, blocking I/O, network calls) before doing
    // anything that touches shared state (session/socksServer/tunFd/
    // vpnActive) or emits CONNECTING / RECONNECTING / READY.
    //
    // Because it is a plain @Volatile Long compared with `!=`, a stale
    // coroutine started before the bump can NEVER be confused for the
    // current one again, no matter how many Stop/Start cycles race with
    // it - this is what makes old reconnect attempts unable to affect a
    // newer session, and guarantees a Stop tap invalidates everything
    // in flight immediately (the bump itself is a single synchronous
    // field write, visible to every other thread right away).
    @Volatile private var sessionEpoch: Long = 0L

    /** Thrown internally to unwind a connect()/connectXray() attempt that discovered mid-flight it is no longer the current session (Stop was pressed, or a newer Start superseded it). Never logged as an error and never triggers a retry - the owning epoch is already gone. */
    private class StaleSessionException : Exception()
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
        requestId = intent?.getLongExtra(EXTRA_REQUEST_ID, requestId) ?: requestId
        if (intent?.action == ACTION_DISCONNECT) {
            // stopVpn() itself bumps sessionEpoch as its very first
            // statement - this immediately invalidates every in-flight
            // connect/reconnect attempt (see the epoch checks throughout
            // this file) before anything else in stopVpn() even runs.
            stopRequested = true
            stopVpn()
            return START_NOT_STICKY
        }

        // Fresh, clean start: bump the session epoch BEFORE touching
        // anything else. This does two things at once - (1) it makes this
        // the new "current" session so every broadcast/state-mutation below
        // is allowed through the epoch checks, and (2) it immediately
        // invalidates any coroutine left over from a previous session that
        // is still mid-flight (e.g. a reconnect attempt that raced with a
        // Stop and is still executing, or one that simply hadn't noticed
        // stopRequested yet) - it can never again touch vpnActive/session/
        // socksServer/tunFd or emit CONNECTING/RECONNECTING/READY, no
        // matter what it does after this point.
        val myEpoch = ++sessionEpoch

        stopRequested = false
        autoReconnectSuspended = false
        firstReconnectFailureAt = 0L
        socksPort = (20000..59000).random()

        if (session != null || tunFd != null || socksServer != null) {
            cleanupResources()
        }
        vpnStopped = false

        // بلا تاگ برتوكول (logTag مازال ماتحددش لهاد الجلسة الجديدة) -
        // بحال HTTP Custom لي كيبين معلومات الجهاز/الشبكة مرة وحدة فبداية
        // كل محاولة اتصال، قبل أي log مرتبط بالبروتوكول.
        logTag = ""
        logDeviceAndNetworkInfo()

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
            emitState(myEpoch, STATE_CONNECTING)

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
                    // A newer Connect or a Stop has already superseded this
                    // whole loop - stop immediately, no log spam, no retry.
                    if (myEpoch != sessionEpoch) return@launch
                    try {
                        log("Preparing VPN Engine...")
                        if (!ensureNativeLoaded(applicationContext)) {
                            log("ERROR: Native Library Load Failed. (${nativeLoadError ?: "unknown"})")
                            if (myEpoch == sessionEpoch) {
                                broadcastStatus(STATE_FAILED)
                                stopVpn()
                            }
                            return@launch
                        }
                        connectXray(parsedJson, myEpoch)
                        break // وصلنا لـ"Connection Established" بلا مشاكل
                    } catch (e: StaleSessionException) {
                        // This attempt discovered mid-flight that it's no
                        // longer current (Stop pressed, or a newer Connect
                        // started) - already torn down inside connectXray(),
                        // nothing more to do here.
                        return@launch
                    } catch (e: Throwable) {
                        if (myEpoch != sessionEpoch) return@launch
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
        emitState(myEpoch, STATE_CONNECTING)

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

        // كيتحسب مرة وحدة هنا (ماشي فكل محاولة داخل connect()) - شوف
        // التعليق فـ connect() على securityNotice.
        val securityNotice = SecurityCheck.quickScan()

        scope.launch {
            var attempt = 0
            while (isActive) {
                // A newer Connect or a Stop has already superseded this
                // whole loop - stop immediately, no log spam, no retry.
                if (myEpoch != sessionEpoch) return@launch
                try {
                    log("Preparing VPN Engine...")
                    if (!ensureNativeLoaded(applicationContext)) {
                        log("ERROR: Native Library Load Failed. (${nativeLoadError ?: "unknown"})")
                        if (myEpoch == sessionEpoch) {
                            broadcastStatus(STATE_FAILED)
                            stopVpn()
                        }
                        return@launch
                    }
                    connect(host, port, user, pass, proxyHost, proxyPort, payload, usePayload, useSsl, sni, udpgwEnabled, udpgwPort, maskLogs, securityNotice, myEpoch)
                    break // reached "Connection Established" with no issues
                } catch (e: StaleSessionException) {
                    // Already torn down inside connect() - this attempt is
                    // no longer current, nothing more to do here.
                    return@launch
                } catch (e: Throwable) {
                    if (myEpoch != sessionEpoch) return@launch
                    log(classifyConnectError(e))

                    // Full teardown before any retry: disconnects the failed
                    // JSch session (belt-and-suspenders on top of the
                    // explicit disconnect() already done in connect()'s own
                    // catch), stops the local SOCKS server if it was
                    // somehow started, and clears every reference so the
                    // next attempt below starts from a clean slate - no
                    // previous attempt's Session/socket stays reachable or
                    // running in the background.
                    cleanupResources()

                    if (stopRequested) {
                        // User tapped Disconnect manually mid-attempt - stop, no retry
                        stopVpn()
                        return@launch
                    }

                    attempt++

                    // Same "stop hammering a dead server forever" ceiling
                    // already used by smartReconnect() for post-connect
                    // drops (MAX_AUTO_RECONNECT_WINDOW_MS = 1h), now also
                    // applied to the very first connection attempt. Before
                    // this fix, an invalid/expired server made this loop
                    // retry every 500ms forever - each attempt doing a full
                    // JSch session + crypto handshake - with nothing to ever
                    // stop it. This is the real fix for the CPU/RAM/battery
                    // drain: an unbounded loop of real work, not a resource
                    // leak inside a single attempt.
                    if (firstReconnectFailureAt == 0L) firstReconnectFailureAt = System.currentTimeMillis()
                    val elapsedSinceFirstFailure = System.currentTimeMillis() - firstReconnectFailureAt
                    if (elapsedSinceFirstFailure >= MAX_AUTO_RECONNECT_WINDOW_MS) {
                        // Unlike smartReconnect's ceiling (where a TUN
                        // interface is already up and worth keeping alive
                        // idle), the initial connect never got that far here
                        // - there is nothing to keep running. Full teardown
                        // (same stopVpn() path used everywhere else in this
                        // service) removes the foreground notification and
                        // ends the process cleanly instead of leaving an
                        // idle foreground service behind. The UI treats
                        // STATE_WAITING_USER_ACTION the same as
                        // STATE_FAILED - button resets, user can tap
                        // Connect again for a fresh attempt.
                        log("Waiting User Action...")
                        autoReconnectSuspended = true
                        stopVpn(STATE_WAITING_USER_ACTION)
                        return@launch
                    }

                    // Exponential backoff + jitter (800ms -> 8s ceiling,
                    // same helper smartReconnect/Xray already use) instead
                    // of a fixed 500ms hammer. A truly dead/invalid server
                    // now backs off instead of retrying at full speed
                    // forever; a server that's briefly unreachable still
                    // recovers quickly on the early, short attempts.
                    val waitMs = backoffDelayMs(attempt - 1)
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
        maskLogs: Boolean = false,
        // كيتحسب مرة وحدة قبل ما تبدا حلقة الـretry (شوف onStartCommand) -
        // ماشي فكل محاولة. نتيجة SecurityCheck.quickScan() (root/emulator/
        // debugger) ماغاديش تتبدل بين محاولة ومحاولة كل بضع مئات ديال الـms،
        // فإعادة فحص 10 ملفات + Build.FINGERPRINT فكل محاولة (بلا فايدة
        // حقيقية) هي واحد من الأسباب لي كانت كتخلي سيرفر خاطئ/منتهي يستهلك
        // CPU بزاف بلا داعي.
        securityNotice: String? = null,
        // Session epoch this attempt was launched under - see the
        // sessionEpoch field. Re-checked after every suspend point below;
        // if it no longer matches the live sessionEpoch, a Stop (or a
        // newer Connect) has superseded this attempt and it must unwind
        // via StaleSessionException without touching shared state or
        // emitting CONNECTING/RECONNECTING/READY.
        epoch: Long = sessionEpoch
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

        securityNotice?.let { log(it) }
        log("Connection Setup Started.")

        val jsch = JSch()
        val sessionStart = SystemClock.elapsedRealtime()
        val s = jsch.getSession(user, host, port)
        log("SSH Session Created. (${SystemClock.elapsedRealtime() - sessionStart} ms)")
        // مهم لتنظيف الموارد: نربطو `session` بالجلسة هنا مباشرة (قبل حتى
        // s.connect())، ماشي غير بعد النجاح. هكذا، إلا فشلت s.connect() أو
        // أي خطوة بعدها، cleanupResources() لي كتنادى عليها حلقة الـretry
        // فـ onStartCommand غادي تلقى `session` غير null وتقدر تدير عليها
        // disconnect() فعلا (كتسد الـsocket/streams الداخليين ديال JSch) -
        // قبل هاد التعديل، `session` كان كيتبدل غير بعد النجاح، فأي جلسة
        // فشلات كانت كتضيع بلا ما cleanupResources() توصل ليها.
        session = s
        s.setPassword(pass)
        s.setConfig("StrictHostKeyChecking", "no")
        // diffie-hellman-group14-sha1 مزيدة فالأول: هي لي كيفضلها هاد
        // السيرفر (شفناها فـ HTTP Custom: "Key exchange algorithm:
        // diffie-hellman-group14-sha1") - fixed group، بلا round-trip
        // زايد. بلا هاد الخوارزمية، JSch كان مجبور يهبط لـ
        // group-exchange-sha256 لي كتحتاج round-trip إضافي باش تتفاوض
        // على حجم الـmodulus، وهادشي كان كيخلي الـhandshake يتجاوز
        // المؤقت ديال 4.5s بانتظام.
        s.setConfig("kex", "diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256," +
            "diffie-hellman-group14-sha256,ecdh-sha2-nistp256,curve25519-sha256")
        applyKeepAlive(s)

        s.setSocketFactory(PayloadSocketFactory(proxyHost, proxyPort, payload, host, usePayload, useSsl, sni) { msg ->
            log(msg)
        })

        log("Connecting...")
        val sshStart = SystemClock.elapsedRealtime()
        try {
            // 8s كافية للـhandshake حتى مع round-trip زايد (group-exchange)
            // على شبكة بطيئة، وفنفس الوقت مازالت قصيرة باش ما تخليش
            // سيرفر ميت يعطل الـretry loop بزاف.
            s.connect(8000)
            log("SSH Connect Completed. (${SystemClock.elapsedRealtime() - sshStart} ms)")
        } catch (e: Throwable) {
            log("SSH Connect Failed after ${SystemClock.elapsedRealtime() - sshStart} ms")
            // Defense in depth: JSch's own connect() already closes its
            // socket/streams internally when it throws, but calling
            // disconnect() here too is cheap, idempotent, and guarantees
            // this exact Session object (channels, io) is fully released
            // even in edge cases JSch's own catch doesn't cover (e.g. an
            // Error, not an Exception). The outer retry loop's
            // cleanupResources() will also call session?.disconnect() on
            // this same object right after - safe to call twice.
            try { s.disconnect() } catch (_: Throwable) { }
            // The outer retry loop logs the classified error once. Avoid
            // printing the same ERROR twice for every failed attempt.
            throw e
        }
        log("SSH Authentication Successful. (total ${SystemClock.elapsedRealtime() - connectTotalStart} ms)")

        // s.connect(8000) above is a real blocking network call, easily the
        // slowest step in this whole function - a Stop tap (or a fresh
        // Connect superseding this one) is very likely to land exactly
        // during it. Check right away: if this attempt is no longer
        // current, tear the just-authenticated session down ourselves and
        // unwind quietly instead of going on to build SOCKS5/TUN for a
        // session nobody wants anymore.
        if (epoch != sessionEpoch) {
            try { s.disconnect() } catch (_: Throwable) { }
            throw StaleSessionException()
        }

        socksServer = MiniSocks5Server(s, "127.0.0.1", socksPort) { msg -> log(msg) }
        socksServer?.start()
        backendProtocolName = "SSH SOCKS5"
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

        // Same reasoning as above - UDPGW setup and everything since the
        // last check took real time (SSH round-trips). Re-check before
        // spending an establish() call (creates a real system VPN
        // interface) on an attempt nobody wants anymore.
        if (epoch != sessionEpoch) {
            try { socksServer?.stop() } catch (_: Throwable) { }
            try { s.disconnect() } catch (_: Throwable) { }
            socksServer = null
            throw StaleSessionException()
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

        val establishedFd = builder.establish()

        // Final gate, right before this attempt would flip vpnActive to
        // true and become "the" active connection. establish() itself can
        // briefly block, so this is checked one last time immediately
        // after it returns - if we lost the race, close everything we just
        // built (TUN interface included) instead of letting a stale
        // attempt resurrect the tunnel out from under a Stop that already
        // completed.
        if (epoch != sessionEpoch) {
            try { establishedFd?.close() } catch (_: Throwable) { }
            try { socksServer?.stop() } catch (_: Throwable) { }
            try { s.disconnect() } catch (_: Throwable) { }
            socksServer = null
            throw StaleSessionException()
        }

        tunFd = establishedFd
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
                    log("ERROR: Native Tunnel Failed (rc=$rc).")
                }
                firstRun = false
                delay(500)
            }
        }

        log("Tunnel Started Successfully.")
        log("Connection Established.")
        emitState(epoch, STATE_READY)

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
            while (vpnActive && epoch == sessionEpoch) {
                delay(6000)
                if (!vpnActive || epoch != sessionEpoch) break
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
                        emitState(epoch, STATE_READY)
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
                        emitState(epoch, STATE_WAITING_NETWORK)
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
    private suspend fun connectXray(parsedConfigJson: String, epoch: Long = sessionEpoch) {
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

        // فحص الشبكة قبل أي محاولة اتصال حقيقية - Xray Core (libv2ray عبر
        // JNI/native) ما مصمّمش يتعامل بأمان مع "بلا شبكة خالص" (مثلا DNS
        // resolution أو فتح socket بلا أي interface متاح) - هادشي وارد
        // يسبب native crash (SIGSEGV/Go panic) كيقتل الـprocess مباشرة،
        // بلا ما يتلقط بـtry/catch ديال Kotlin هنا فوق. بفحص الشبكة قبل ما
        // نديرو XrayCoreManager.start()، كنولّيو "No Network" غلطة عادية
        // كتنكتب فاللوگ وتعاود تحاول بـbackoff - بحال أي غلطة أخرى - بدل
        // كراش صامت كيسد التطبيق كامل.
        if (!hasUsableNetwork()) {
            throw java.io.IOException("No network connection available.")
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

        // XrayCoreManager.start() above can take real time - re-check
        // before spending an establish() call on an attempt nobody wants
        // anymore.
        if (epoch != sessionEpoch) {
            try { XrayCoreManager.stop() } catch (_: Throwable) { }
            throw StaleSessionException()
        }

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

        val establishedFd = builder.establish()

        // Final gate, right before this attempt would flip vpnActive to
        // true. Checked once more immediately after establish() returns -
        // if we lost the race, close everything we just built instead of
        // resurrecting a tunnel a completed Stop already tore down.
        if (epoch != sessionEpoch) {
            try { establishedFd?.close() } catch (_: Throwable) { }
            try { XrayCoreManager.stop() } catch (_: Throwable) { }
            throw StaleSessionException()
        }

        tunFd = establishedFd
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
                    log("ERROR: Native Tunnel Failed (rc=$rc).")
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
            emitState(epoch, STATE_WAITING_NETWORK)
            throw java.io.IOException("No usable network")
        }

        log("Verifying Internet Connectivity...")
        if (!verifyTunnelConnectivity(8000)) {
            // Server خاطئ/منتهي (الشبكة موجودة وتخدم - hasUsableNetwork()
            // نجحت فوق - لكن ماكاين حتى probe نجح عبر التونيل). قبل، هادي
            // الحالة كانت كتوقف كلشي (stopVpn) وتعلن STATE_FAILED مباشرة.
            // دابا، بحال أي انقطاع كيوقع من بعد ما الاتصال يكون READY،
            // كنعتمدو على smartReconnectXray() اللي كاينة ديجا: كتوقف
            // Xray core بشكل آمن (نفس السبب المذكور فوق - بلا ما تعاود
            // تشغلو بزربة فوق نفسو)، وتعاود تحاول من جديد بـbackoff، بلا
            // ما تلمس TUN interface (tunFd) ولا nativeStartTunnel/
            // nativeStopTunnel خالص - غير بعد ساعة كاملة من الفشل
            // المتواصل كتوقف (STATE_WAITING_USER_ACTION)، ماشي فورا.
            // vpnActive/tunFd already established above - VPN interface
            // stays up, Xray core stays alive until smartReconnectXray
            // itself decides to restart it.
            log("ERROR: Server Unreachable.")
            emitState(epoch, STATE_RECONNECTING)
            // ملاحظة: log("Reconnecting...") اتشال من هنا - كان كيتكرر
            // مرتين حدة حدة فالـLog. scheduleSmartReconnect(debounceMs=0)
            // تحت كينادي مباشرة smartReconnect() -> smartReconnectXray()،
            // ولي هي بحالها كتبدا بـ log("Reconnecting...") (شوف تحت) -
            // فهاد السطر هنا كان زايد، نفس الرسالة كتتكتب مرتين لنفس
            // الحدث. broadcastStatus(STATE_RECONNECTING) خليناها كيفما
            // هي باش الواجهة تتبدل فورا بلا ما تستنى.
            scheduleSmartReconnect("initial-server-unreachable", debounceMs = 0)
            return
        }

        log("Connection Established.")
        emitState(epoch, STATE_READY)
        startXrayPingMonitor(epoch)
    }

    /**
     * Periodic Xray connection monitor: Xray core still running + SOCKS5
     * still responding (same idea as the SSH ping loop, but relying only on
     * XrayCoreManager.isRunning() and a real probe through the tunnel via
     * checkTunnelLatencyMs). Guarded so it only ever runs once per
     * connection - safe to call after ANY path that reaches STATE_READY for
     * the first time (direct success, or success after retrying from an
     * initial "Server Unreachable"), whether or not it was already running.
     */
    private fun startXrayPingMonitor(epoch: Long = sessionEpoch) {
        if (xrayPingMonitorJob?.isActive == true) return
        xrayPingMonitorJob = scope.launch(Dispatchers.IO) {
            var consecutiveFailures = 0
            while (vpnActive && epoch == sessionEpoch) {
                delay(XRAY_PING_INTERVAL_MS)
                if (!vpnActive || epoch != sessionEpoch) break
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
                        emitState(epoch, STATE_READY)
                    }
                } else {
                    consecutiveFailures++
                    if (!hasUsableNetwork()) {
                        if (networkAvailable) networkAvailable = false
                        emitState(epoch, STATE_WAITING_NETWORK)
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
        // Snapshot the epoch of the session this probe belongs to. If a
        // Stop (or a fresh Connect) supersedes it while the 600ms grace
        // delay below is running, the epoch check after the delay catches
        // it and this probe unwinds without touching anything.
        val myEpoch = sessionEpoch
        scope.launch {
            // Give the OS a brief moment to finish settling routes/DNS after
            // a network switch before probing.
            delay(600)
            if (!vpnActive || stopRequested || reconnecting || myEpoch != sessionEpoch) return@launch

            val sessionAlive = if (mode == MODE_XRAY) {
                XrayCoreManager.isRunning()
            } else {
                try { session?.isConnected == true } catch (_: Throwable) { false }
            }
            if (sessionAlive && verifyTunnelConnectivity(4000)) {
                // The existing SSH session survived the network change - no
                // re-authentication, no Payload resend, nothing torn down.
                // Re-check once more right before announcing READY: the
                // connectivity probe itself takes real time too.
                if (myEpoch != sessionEpoch) return@launch
                log("Connection Established.")
                emitState(myEpoch, STATE_READY)
            } else {
                // Session is genuinely gone (or unreachable) - only now do we
                // pay for a full reconnect.
                scheduleSmartReconnect(reason, epoch = myEpoch)
            }
        }
    }

    /**
     * Schedules smartReconnect() with a small debounce so we don't run
     * multiple attempts at once (e.g. onAvailable and onCapabilitiesChanged
     * can both fire close together during a network switch). Each new call
     * cancels the previous one.
     */
    private fun scheduleSmartReconnect(reason: String, debounceMs: Long = 800, epoch: Long = sessionEpoch) {
        if (!vpnActive || stopRequested || autoReconnectSuspended) return
        reconnectDebounceJob?.cancel()
        reconnectDebounceJob = scope.launch {
            if (debounceMs > 0) delay(debounceMs)
            if (epoch != sessionEpoch || stopRequested) return@launch
            smartReconnect(reason, epoch)
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
    private suspend fun smartReconnect(reason: String, epoch: Long = sessionEpoch) {
        if (epoch != sessionEpoch || stopRequested) return // already superseded before we even started
        if (mode == MODE_XRAY) {
            smartReconnectXray(reason, epoch)
            return
        }
        if (!vpnActive || stopRequested) return
        if (autoReconnectSuspended) return // ceiling already hit - wait for the user to tap Connect
        if (reconnecting) return
        reconnecting = true
        val myGeneration = ++reconnectGeneration
        if (firstReconnectFailureAt == 0L) firstReconnectFailureAt = System.currentTimeMillis()
        emitState(epoch, STATE_RECONNECTING)
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
            // Track the exact objects THIS attempt creates, separately from
            // the shared `session`/`socksServer` fields. If we later find
            // out we're stale, we must only tear down our own objects - by
            // then a newer, legitimate connect/reconnect may already have
            // replaced the shared fields with a good session, and we must
            // never touch that one.
            var attemptSession: Session? = null
            var attemptSocks: MiniSocks5Server? = null

            while (attempt < maxAttempts && vpnActive && !stopRequested && myGeneration == reconnectGeneration && epoch == sessionEpoch) {
                if (!networkAvailable) {
                    emitState(epoch, STATE_WAITING_NETWORK)
                    return
                }

                // Network "available" doesn't mean the system's DNS/routing is
                // 100% ready at that exact instant (especially switching
                // between Wi-Fi/mobile data) - we give it a short grace period
                // and retry a few times before giving up.
                delay(if (attempt == 0) 0L else 500L)
                if (epoch != sessionEpoch || stopRequested) break // Stop landed during the grace delay

                try {
                    // 2) + 3) Resend the payload and open a new SSH session
                    val jsch = JSch()
                    val s = jsch.getSession(lastUser, lastHost, lastPort)
                    s.setPassword(lastPass)
                    s.setConfig("StrictHostKeyChecking", "no")
                    s.setConfig("kex", "diffie-hellman-group14-sha1,diffie-hellman-group-exchange-sha256," +
                        "diffie-hellman-group14-sha256,ecdh-sha2-nistp256,curve25519-sha256")
                    applyKeepAlive(s)
                    s.setSocketFactory(PayloadSocketFactory(lastProxyHost, lastProxyPort, lastPayload, lastHost, lastUsePayload, lastUseSsl, lastSni) { msg ->
                        log(msg)
                    })
                    s.connect(8000)

                    // s.connect(8000) is a real blocking handshake - the
                    // most likely place for a Stop tap to land. Check right
                    // away, before this reconnect attempt claims the shared
                    // `session`/`socksServer` fields or reports any state.
                    if (epoch != sessionEpoch || stopRequested) {
                        try { s.disconnect() } catch (_: Throwable) { }
                        break
                    }

                    attemptSession = s
                    session = s
                    log("SSH Authentication Successful.")

                    // 4) Restart SOCKS5 on the same port - nativeStartTunnel
                    // keeps working transparently since the original tunnel
                    // is still running
                    val newSocks = MiniSocks5Server(s, "127.0.0.1", socksPort) { msg -> log(msg) }
                    newSocks.start()
                    attemptSocks = newSocks
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
                    attemptSession = null
                    attemptSocks = null
                }

                if (success) break
            }

            // Final gate before this attempt is allowed to surface as the
            // active connection: everything above (JSch handshake, SOCKS5
            // start, the 400ms connectivity probe) is real time during
            // which a Stop could have landed - or, in a fast Stop-then-
            // Start-again sequence, a newer connect() could already be the
            // one holding `session`/`socksServer` by now. Either way, this
            // attempt must not be allowed to announce
            // READY/CONNECTING/RECONNECTING. We only ever tear down and
            // clear OUR OWN objects (attemptSession/attemptSocks), and only
            // clear the shared fields if they still point at exactly those
            // objects - never at whatever a newer, legitimate session may
            // have since put there.
            if (epoch != sessionEpoch || stopRequested) {
                if (success) {
                    try { attemptSocks?.stop() } catch (_: Throwable) { }
                    try { attemptSession?.disconnect() } catch (_: Throwable) { }
                    if (session === attemptSession) session = null
                    if (socksServer === attemptSocks) socksServer = null
                }
                return
            }

            if (success) {
                firstReconnectFailureAt = 0L
                emitState(epoch, STATE_READY)
            } else if (vpnActive && !stopRequested && myGeneration == reconnectGeneration) {
                val elapsed = System.currentTimeMillis() - firstReconnectFailureAt
                if (elapsed >= MAX_AUTO_RECONNECT_WINDOW_MS) {
                    // Stop retrying silently forever - after a full hour of
                    // continuous failure this is very unlikely to fix itself,
                    // and endless retries just drain the battery. The user
                    // has to tap Connect again to try a truly fresh start.
                    autoReconnectSuspended = true
                    log("Waiting User Action...")
                    emitState(epoch, STATE_WAITING_USER_ACTION)
                } else {
                    emitState(epoch, STATE_WAITING_NETWORK)
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
    private suspend fun smartReconnectXray(reason: String, epoch: Long = sessionEpoch) {
        if (epoch != sessionEpoch || stopRequested) return // already superseded before we even started
        if (!vpnActive || stopRequested) return
        if (autoReconnectSuspended) return
        if (reconnecting) return
        reconnecting = true
        val myGeneration = ++reconnectGeneration
        if (firstReconnectFailureAt == 0L) firstReconnectFailureAt = System.currentTimeMillis()
        emitState(epoch, STATE_RECONNECTING)
        log("Reconnecting...")

        try {
            XrayCoreManager.stop()

            var attempt = 0
            val maxAttempts = 6
            var success = false

            while (attempt < maxAttempts && vpnActive && !stopRequested && myGeneration == reconnectGeneration && epoch == sessionEpoch) {
                if (!networkAvailable) {
                    emitState(epoch, STATE_WAITING_NETWORK)
                    return
                }
                delay(if (attempt == 0) 800 else backoffDelayMs(attempt))
                if (epoch != sessionEpoch || stopRequested) break // Stop landed during the grace delay

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

                    // XrayCoreManager.start() above is real, blocking native
                    // work - re-check right away, before spending the extra
                    // 400ms probe delay and before this attempt is treated
                    // as having claimed the (singleton) Xray core.
                    if (epoch != sessionEpoch || stopRequested) {
                        XrayCoreManager.stop()
                        break
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
                    XrayCoreManager.stop()
                }

                if (success) break
            }

            // Same reasoning as smartReconnect()'s final gate: a Stop (or a
            // newer Connect) may have landed during the native start / probe
            // delay above. XrayCoreManager is a process-global singleton
            // (unlike JSch Sessions there is no separate "our own instance"
            // to distinguish) - stopping it here mirrors exactly what
            // cleanupResources() already does on Stop, and is a no-op/safe
            // if it's already stopped.
            if (epoch != sessionEpoch || stopRequested) {
                if (success) {
                    try { XrayCoreManager.stop() } catch (_: Throwable) { }
                }
                return
            }

            if (success) {
                firstReconnectFailureAt = 0L
                emitState(epoch, STATE_READY)
                startXrayPingMonitor(epoch)
            } else if (vpnActive && !stopRequested && myGeneration == reconnectGeneration) {
                val elapsed = System.currentTimeMillis() - firstReconnectFailureAt
                if (elapsed >= MAX_AUTO_RECONNECT_WINDOW_MS) {
                    autoReconnectSuspended = true
                    log("Waiting User Action...")
                    emitState(epoch, STATE_WAITING_USER_ACTION)
                } else {
                    emitState(epoch, STATE_WAITING_NETWORK)
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

    // شير executor واحد لكل الـpings (بدل ما نخلقو thread pool جديد ونمُوّتو
    // فكل نداء لـcheckTunnelLatencyMs). هاد الدالة كتندادى كل 5-6 ثواني بلا
    // ماتوقف طول ما الـVPN شغال - كانت كتخلق 3 threads جداد وتسدهم فكل
    // مرة (churn تقيل على GC/CPU باستمرار). داباهي threads ثابتين، كيتبنيو
    // مرة وحدة وكيتقادو غير عند stopVpn/onDestroy.
    private val latencyProbeExecutor by lazy {
        java.util.concurrent.Executors.newFixedThreadPool(connectivityProbeUrls.size)
    }

    /** Same check as [verifyTunnelConnectivity] but returns the round-trip time in ms (null on failure), so the user can see connection speed in the log. Runs all probes in parallel and returns as soon as the first one succeeds, instead of waiting on each sequentially (which could take up to timeoutMs * probe count). */
    private fun checkTunnelLatencyMs(timeoutMs: Int = 5000): Int? {
        val start = System.currentTimeMillis()
        val proxy = java.net.Proxy(java.net.Proxy.Type.SOCKS, java.net.InetSocketAddress("127.0.0.1", socksPort))
        // completionService كيعطينا get() اللي كيبلوكي (real wait، ماشي
        // busy-poll) حتى يكمل أول probe - بلا ماندوزو بالـThread.sleep(20)
        // فـwhile loop اللي كان كيفيق الـCPU مرارًا طول مدة الـtimeout.
        val completionService = java.util.concurrent.ExecutorCompletionService<Boolean>(latencyProbeExecutor)
        val submitted = connectivityProbeUrls.map { probe ->
            completionService.submit {
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
        try {
            var remaining = submitted.size
            val deadline = start + timeoutMs + 500
            while (remaining > 0) {
                val waitMs = deadline - System.currentTimeMillis()
                if (waitMs <= 0) break
                val done = completionService.poll(waitMs, java.util.concurrent.TimeUnit.MILLISECONDS) ?: break
                remaining--
                val ok = try { done.get() == true } catch (_: Exception) { false }
                if (ok) return (System.currentTimeMillis() - start).toInt()
            }
            return null
        } finally {
            // ماكنسدوش الـexecutor هنا - غير الطلبات الفاضية اللي بقاو
            // معلقين (probe ماكملش قبل الـdeadline)؛ الـexecutor بحالو
            // شير و باقي خدام للـpings الجايين.
            submitted.forEach { if (!it.isDone) it.cancel(true) }
        }
    }

    /**
     * Maps any connection error to one of a small set of clean, English,
     * non-sensitive log lines. The raw exception (class name, message,
     * stack trace) and any host/IP/port it might contain are never logged -
     * only this fixed, safe phrase is shown to the user.
     */
    /** Real exception detail for log messages - message first, falls back to the cause's, bounded so one log line can't blow up. */
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
                "ERROR: Host Key Rejected. (${e.javaClass.simpleName}: ${realDetail(e)})"

            msg.contains("SSLHandshake", ignoreCase = true) ||
                msg.contains("SSLException", ignoreCase = true) ||
                e is javax.net.ssl.SSLException ->
                "ERROR: SSL/TLS Handshake Failed. (${e.javaClass.simpleName}: ${realDetail(e)})"

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

            else -> "ERROR: ${e.javaClass.simpleName}: ${realDetail(e)}"
        }
    }

    /** Exponential backoff + random jitter between reconnect attempts. */
    private fun backoffDelayMs(attempt: Int): Long {
        val base = (800L * (1 shl attempt.coerceAtMost(4))).coerceAtMost(8000L) // 800,1600,3200,6400,8000...
        val jitter = (0..400).random()
        return base + jitter
    }

    /**
     * Delegates to [UnifiedProxySharingManager] - the single, shared,
     * protocol-agnostic Proxy Sharing layer (see its class doc). This
     * service's only job is to say WHICH backend is currently live and
     * WHERE its local proxy endpoint is; the manager owns everything about
     * whether sharing is enabled, the listen port, idempotency, and the
     * log output. Safe to call on every STATE_READY (initial connect or
     * any reconnect, any protocol) - it never opens a second listener.
     */
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
        try { UnifiedProxySharingManager.stop() } catch (_: Throwable) { }
        stopSpeedMonitor()
        try { tunFd?.close() } catch (_: Throwable) { }
        socksServer = null
        session = null
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
        // Bump the session epoch FIRST, unconditionally, before the
        // idempotency guard below and before anything else runs. This is
        // the actual fix for the Stop/Reconnect race: the instant Stop is
        // requested, every in-flight connect()/connectXray()/smartReconnect
        // attempt anywhere in the service - no matter which coroutine or
        // network callback started it - captured an older epoch value and
        // will now fail its next `epoch == sessionEpoch` check, so it can
        // no longer flip vpnActive back to true, reassign session/
        // socksServer/tunFd, or emit CONNECTING/RECONNECTING/READY. A
        // single @Volatile field write is visible to every other thread
        // immediately, so this takes effect before any other statement in
        // this function even runs.
        sessionEpoch++
        stopRequested = true

        // Idempotency guard: stopVpn() can legitimately be reached from two
        // places almost simultaneously - (1) the user tapping Disconnect
        // (ACTION_DISCONNECT in onStartCommand) and (2) the connect retry
        // loop's own catch block, which also calls stopVpn() once it
        // observes stopRequested == true after its in-flight attempt throws
        // (because cleanupResources() from path 1 tore down the session/
        // socks/tunFd out from under it). Without this guard both paths ran
        // the full body - double "Disconnected." log lines, double
        // Cleanup Completed., and two competing killProcess schedules.
        if (vpnStopped) return
        vpnStopped = true

        reconnectDebounceJob?.cancel()
        vpnActive = false
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

    /**
     * نفس getActiveDataCarrierName() ديال MainActivity.kt - كيرجع اسم
     * الأوبراتور الصحيح ديال الـSIM اللي فعلا كيدير بيانات الهاتف (dual-SIM)
     * بدل ما يبقى دايما يرجع لـSIM الافتراضي. كترجع null إلا ماكانش
     * ممكن (permission، جهاز SIM واحد، إلخ) - فهاد الحالة الكود كيرجع
     * تلقائيا للطريقة القديمة.
     */
    private fun getActiveDataCarrierName(baseTm: TelephonyManager?): String? {
        if (baseTm == null) return null
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return null
        return try {
            @Suppress("DEPRECATION")
            val subId = SubscriptionManager.getDefaultDataSubscriptionId()
            if (subId == SubscriptionManager.INVALID_SUBSCRIPTION_ID) return null
            baseTm.createForSubscriptionId(subId).networkOperatorName?.takeIf { it.isNotBlank() }
        } catch (_: SecurityException) {
            null
        } catch (_: Throwable) {
            null
        }
    }

    /**
     * كيبين معلومات الجهاز والشبكة مرة وحدة فبداية كل محاولة اتصال -
     * بحال HTTP Custom (اسم/موديل الجهاز، نسخة Android، اسم الشبكة/الـ
     * IP المحلي). Best-effort بحتة: أي خطأ هنا ماخصوش يوقف الاتصال.
     */
    private fun logDeviceAndNetworkInfo() {
        try {
            val versionName = try { BuildConfig.VERSION_NAME } catch (_: Throwable) { "" }
            val versionCode = try { BuildConfig.VERSION_CODE } catch (_: Throwable) { 0 }
            log("MR VPN TUNNEL v$versionName ($versionCode)")
            log("running on ${Build.MANUFACTURER} (${Build.MODEL})")
            val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown"
            log("Android ${Build.VERSION.RELEASE} API-${Build.VERSION.SDK_INT} ($abi)")

            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val activeNetwork = cm?.activeNetwork
            val caps = activeNetwork?.let { cm.getNetworkCapabilities(it) }
            val connLabel = when {
                caps == null -> "Unknown Network"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> {
                    // getNetworkOperatorName() ماخصهاش أي permission خاص -
                    // كتعطي اسم الشبكة (بحال "Maroc Telecom") من الـSIM.
                    // كنجربو أولا نجيبو اسم الأوبراتور ديال الـSIM اللي
                    // فعلا كيدير Data (dual-SIM) - وإلا ما قدرناش، نرجعو
                    // للطريقة القديمة (SIM الافتراضي).
                    val tm = getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
                    val carrier = getActiveDataCarrierName(tm)
                        ?: tm?.networkOperatorName?.takeIf { it.isNotBlank() }
                        ?: "Mobile"
                    "$carrier / Mobile Data"
                }
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
                else -> "Unknown Network"
            }
            log(connLabel)

            val localIp = try {
                java.net.NetworkInterface.getNetworkInterfaces().asSequence()
                    .flatMap { it.inetAddresses.asSequence() }
                    .firstOrNull { !it.isLoopbackAddress && it is java.net.Inet4Address }
                    ?.hostAddress
            } catch (_: Throwable) { null }
            if (!localIp.isNullOrBlank()) {
                log("Local IP $localIp")
            }
        } catch (_: Throwable) {
            // best-effort - ماخصهاش توقف/تعطل بداية الاتصال
        }
    }

    private fun log(msg: String) {
        // Proxy Sharing lines already carry their own [PROXY] tag and are
        // protocol-agnostic by design (see UnifiedProxySharingManager) -
        // they should never also get stamped with the current protocol's
        // [SSH]/[XRAY] tag, which would make them look backend-specific.
        val tagged = if (logTag.isNotEmpty() && !msg.startsWith("[PROXY]")) "[$logTag] $msg" else msg
        LogManager.add(applicationContext, tagged)
        try {
            val i = Intent(ACTION_LOG)
            i.putExtra(EXTRA_LOG_MESSAGE, tagged)
            sendBroadcast(i)
        } catch (_: Throwable) { }
    }

    /**
     * Guarded status emitter for every state that a session-scoped
     * coroutine (initial connect, retry loop, smartReconnect,
     * tryResumeSession, ping monitors...) can produce: CONNECTING,
     * RECONNECTING, READY, WAITING_NETWORK, WAITING_USER_ACTION.
     *
     * [epoch] must be the sessionEpoch value that was current when the
     * calling coroutine/attempt started. If a newer epoch has since
     * started (a fresh Connect) or the user tapped Stop, this is a
     * stale/superseded attempt and the call is dropped silently - it
     * must never be allowed to move the UI/notification backwards.
     *
     * DISCONNECTED and FAILED are terminal states owned exclusively by
     * stopVpn(), which calls broadcastStatus() directly (never through
     * this guard), so they are always delivered.
     */
    private fun emitState(epoch: Long, state: String) {
        if (epoch != sessionEpoch || stopRequested) return
        broadcastStatus(state)
    }

    private fun broadcastStatus(state: String) {
        // Persisted first (cross-process, survives the activity being
        // recreated / the app being backgrounded) so MainActivity always has
        // a real, current source of truth to sync against - never just the
        // last value it happened to hold in memory.
        StateStore.write(applicationContext, state, requestId)
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
        } else {
            // Any state other than READY (RECONNECTING, WAITING_NETWORK,
            // FAILED, DISCONNECTED...) must stop the speed monitor - it was
            // previously left running across state changes, which kept
            // overwriting the notification back to "Connected + speed"
            // every second even while the app itself showed
            // "Reconnecting...", making the two disagree.
            stopSpeedMonitor()
        }
        try {
            val i = Intent(ACTION_STATUS)
            i.putExtra(EXTRA_STATE, state)
            i.putExtra(EXTRA_REQUEST_ID, requestId)
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

    private fun formatSize(bytes: Long): String {
        if (bytes < 1024) return "${bytes}B"
        val kb = bytes / 1024.0
        if (kb < 1024) return String.format("%.0fKB", kb)
        val mb = kb / 1024.0
        if (mb < 1024) return String.format("%.1fMB", mb)
        val gb = mb / 1024.0
        return String.format("%.2fGB", gb)
    }

    /**
     * Samples TrafficStats for this app's UID once a second and rebuilds the
     * notification with a live download/upload speed line plus the total
     * data used since this connection came up, same idea as HTTP Custom /
     * other VPN apps. Only runs while the tunnel is READY - started from
     * broadcastStatus(), stopped from cleanupResources() and on any
     * non-READY state change, so it never touches the actual
     * connection/tunnel logic.
     *
     * The total resets each time a new READY session starts (i.e. it counts
     * "usage since the last (re)connect", not lifetime usage across the
     * whole app install) - that mirrors what most VPN apps show as their
     * live session counter.
     */
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
                // بدلات من 1000 لـ3000: خصنا نبنيو Notification جديدة (allocation)
                // ونديرو IPC (binder) لـNotificationManager كل مرة - مرة فالثانية
                // طول مدة الاتصال كانت كتحرق باتري بلا فائدة كبيرة، حيت سرعة
                // التحميل ماخاصهاش تتبدل بهاد السرعة باش تبان للمستخدم.
                delay(3000)
                val now = System.currentTimeMillis()
                val rx = TrafficStats.getUidRxBytes(uid)
                val tx = TrafficStats.getUidTxBytes(uid)
                val elapsedSec = ((now - lastTime).coerceAtLeast(1)) / 1000.0

                // getUidRxBytes/TxBytes can return -1 on some devices/ROMs
                // if per-uid stats aren't available - fall back to "0" speed
                // instead of a garbage negative number.
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

    private var lastNotifText: String? = null

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
            // ماكنبنيوش Notification جديدة ولا كنديرو notify() (binder IPC)
            // إلا كان النص فعلا تبدل - كنجنبو allocation + IPC بلا فائدة
            // ملي السرعة كتبقى صفر (بلا تصفح) أو نفس القيمة.
            if (text == lastNotifText) return
            lastNotifText = text
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
        val initialText = notificationTextFor(STATE_CONNECTING)
        lastNotifText = initialText
        val notif = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("MR VPN TUNNEL")
            .setContentText(initialText)
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
        try { latencyProbeExecutor.shutdownNow() } catch (_: Throwable) { }
        try { FileLogger.close() } catch (_: Throwable) { }
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
