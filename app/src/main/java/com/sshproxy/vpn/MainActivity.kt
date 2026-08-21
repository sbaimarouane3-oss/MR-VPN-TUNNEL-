package com.sshproxy.vpn

import android.animation.ValueAnimator
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.res.ColorStateList
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.telephony.SubscriptionManager
import android.telephony.TelephonyManager
import android.view.View
import android.view.animation.LinearInterpolator
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.widget.SwitchCompat
import com.google.android.material.button.MaterialButton
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.updatePadding
import androidx.drawerlayout.widget.DrawerLayout
import androidx.lifecycle.lifecycleScope
import androidx.viewpager2.widget.ViewPager2
import com.google.android.material.navigation.NavigationView
import com.google.android.material.tabs.TabLayout
import com.google.android.material.tabs.TabLayoutMediator
import com.sshproxy.vpn.importer.ImportCrypto
import com.sshproxy.vpn.importer.ImportedConfig
import com.sshproxy.vpn.importer.InvalidImportCodeException
import com.sshproxy.vpn.importer.MlConfigFile
import com.sshproxy.vpn.importer.MlConfigParseException
import com.sshproxy.vpn.importer.MlConfigWeakPasswordException
import com.sshproxy.vpn.importer.SecureConfigStore
import com.sshproxy.vpn.importer.XraySecureConfigStore
import com.sshproxy.vpn.xray.ParsedProxyConfig
import com.sshproxy.vpn.xray.XrayConfigParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job
import kotlinx.coroutines.withContext
import java.io.File

/**
 * الـ Activity ماعندهاش views مباشرة ديال الحقول/اللوگ — هادوك كاينين
 * فـ SshFragment و LogFragment (يمكن السحب بينهم عبر ViewPager2 بحال
 * HTTP Custom). كل منطق الاتصال، الاستيراد، وحفظ الحقول باقي هنا
 * مركزي، والفراگمنتات كتسجل الـ views ديالها عبر onSshFragmentReady /
 * onLogFragmentReady.
 */
/**
 * تعريف كل بروتوكول قابل للاختيار من "Choose Protocol": الاسم اللي
 * كيبان فالـdialog وفـ Protocol row، والأعلام اللي كيتبناو عليهم
 * الحقول اللي كتبان (useSsl->SNI, usePayload->Payload, useProxy->
 * Remote Proxy). isXtra كيوجه startVpnService لمسار Xray (VLESS)
 * اليدوي بدل المسار العادي ديال SSH.
 */
private data class ProtocolOption(
    val label: String,
    val usePayload: Boolean,
    val useSsl: Boolean,
    val useProxy: Boolean,
    val isXtra: Boolean = false,
    // V2Ray: كيبين حقل JSON كبير بدل حقول SSH (Host/User/Pass/Payload/SSL).
    val isV2Ray: Boolean = false,
    // Shadowsocks: كيبين حقول Server/Port/Method/Password/UDP بدل حقول SSH.
    val isShadowsocks: Boolean = false,
    // وصف قصير كيبان تحت الاسم فـ"Choose Protocol" dialog (UI فقط، ماعندوش
    // تأثير على منطق الاتصال).
    val description: String = "",
    // أيقونة الصف فـ"Choose Protocol" dialog (UI فقط). إلا زدنا بروتوكول
    // جديد بلا أيقونة خاصة، كيرجع تلقائيا لقفل بسيط (ic_protocol_lock).
    val iconRes: Int = R.drawable.ic_protocol_lock
)

/**
 * مصدر وحيد للحقيقة ديال كل بروتوكول قابل للاختيار - "Choose Protocol"
 * dialog (showProtocolPicker) كيبني القائمة ديالو ديناميكيا مباشرة من هاد
 * اللائحة (صف واحد لكل عنصر)، فبروتوكول جديد يتزاد هنا فقط (label + أعلام
 * المنطق + description + iconRes اختياريين) كافي باش يبان تلقائيا فالـUI
 * بلا أي تعديل آخر فـdialog_choose_protocol.xml ولا فـshowProtocolPicker().
 */
private val PROTOCOL_OPTIONS = listOf(
    ProtocolOption(
        "SSH-Direct", usePayload = false, useSsl = false, useProxy = false,
        description = "Direct SSH connection", iconRes = R.drawable.ic_protocol_lock
    ),
    ProtocolOption(
        "SSH-Proxy", usePayload = false, useSsl = false, useProxy = true,
        description = "SSH via proxy", iconRes = R.drawable.ic_protocol_lock
    ),
    ProtocolOption(
        "SSH-Payload", usePayload = true, useSsl = false, useProxy = false,
        description = "SSH with payload", iconRes = R.drawable.ic_protocol_lock
    ),
    ProtocolOption(
        "SSH-Proxy-Payload", usePayload = true, useSsl = false, useProxy = true,
        description = "SSH via proxy with payload", iconRes = R.drawable.ic_protocol_lock
    ),
    ProtocolOption(
        "SSH-TLS", usePayload = false, useSsl = true, useProxy = false,
        description = "SSH over TLS", iconRes = R.drawable.ic_protocol_lock_shield
    ),
    ProtocolOption(
        "SSH-TLS-Proxy", usePayload = false, useSsl = true, useProxy = true,
        description = "SSH over TLS via proxy", iconRes = R.drawable.ic_protocol_lock_shield
    ),
    ProtocolOption(
        "SSH-TLS-Payload", usePayload = true, useSsl = true, useProxy = false,
        description = "SSH over TLS with payload", iconRes = R.drawable.ic_protocol_lock_shield
    ),
    ProtocolOption(
        "SSH-TLS-Proxy-Payload", usePayload = true, useSsl = true, useProxy = true,
        description = "SSH over TLS via proxy with payload", iconRes = R.drawable.ic_protocol_lock_shield
    ),
    // XTRA: يدوي لـ VLESS+TCP (+TLS إلا تعمرت SNI) - نفس حقول SSH-TLS
    // بالضبط (Host:Port, Username/UUID, Password, SNI)، بلا Payload
    // وبلا Proxy. ماشي عبر Import - القيم كتبنى مباشرة فـstartVpnService.
    ProtocolOption(
        "XTRA", usePayload = false, useSsl = true, useProxy = false, isXtra = true,
        description = "High performance protocol", iconRes = R.drawable.ic_protocol_bolt
    ),
    // V2Ray: حقل JSON كامل (V2Ray/Xray config) - كيتبنى مباشرة فـ
    // startVpnService عبر XrayConfigParser.parse بلا Import.
    ProtocolOption(
        "V2Ray", usePayload = false, useSsl = false, useProxy = false, isV2Ray = true,
        description = "V2Ray core protocol", iconRes = R.drawable.ic_protocol_v2ray
    ),
    // Shadowsocks: حقول Server/Port/Method/Password/UDP يدوية - كيتبنى
    // ParsedProxyConfig مباشرة فـstartVpnService بلا Import.
    ProtocolOption(
        "Shadowsocks", usePayload = false, useSsl = false, useProxy = false, isShadowsocks = true,
        description = "Secure SOCKS5 proxy", iconRes = R.drawable.ic_protocol_globe
    )
)

private val DEFAULT_PROTOCOL = PROTOCOL_OPTIONS[0]

/**
 * مصدر الكونفيغ "المخفي" النشط حاليا (activeImportedConfig/activeXrayConfig) -
 * باش updateImportUiState() يقدر يفرق بين حالتين كيستعملو نفس التخزين
 * تحت لكن خاصهم واجهة مختلفة تماما:
 * - IMPORTED: جاي من Import Code / Add (نفس التصميم القديم - "Config
 *   imported" + زر REMOVE IMPORTED CONFIG).
 * - SAVED_CONFIG: جاي من تشغيل ملف .ml محفوظ من CONFIG tab (File/
 *   Protocol/Server/Port فقط - بلا "Config imported" وبلا زر الحذف).
 */
private enum class ConfigSource { NONE, IMPORTED, SAVED_CONFIG }

class MainActivity : AppCompatActivity() {

    private var connected = false
    private var connecting = false
    // true ملي VPN كيعاود الاتصال تلقائيا (تبديل شبكة / انقطاع مؤقت)
    // بلا ما المستخدم يحتاج يدوس شي حاجة — كنبينوها فالزر بحال HTTP Custom.
    private var reconnectingUi = false
    // true غير وقت STATE_FAILED / STATE_WAITING_USER_ACTION - باش الزر
    // الدائري يبين أحمر بدل الرمادي العادي ديال DISCONNECTED. كيتصفى
    // (false) فأول CONNECTING جديدة أو DISCONNECT يدوي.
    private var failedUi = false

    private var sshFragment: SshFragment? = null
    private var logFragment: LogFragment? = null
    private var configFragment: ConfigFragment? = null

    // اسم الملف .ml اللي هو "النشط" حاليا (متصل ولا فطور الاتصال) عبر
    // زر ★/■ فـCONFIG tab أو عبر ملف جاي من تلغرام/واتساب - null معناه
    // مافيهش ملف نشط (اتصال يدوي عادي من SSH SETTINGS). كنستعملوه باش
    // ConfigFragment يعرف أي صف يلون بالأخضر ويبين ■ بدل ★.
    private var activeConfigFileName: String? = null
    // ملي المستخدم كيدوس "Edit" على ملف .ml بلا كلمة سر: كنسجلو اسمو
    // هنا باش لما يعاود يحفظ بنفس الاسم من "+ NEW CONFIG" نديرو Overwrite
    // بلا خطأ "الاسم مستعمل ديجا" (التكرار ممنوع غير للأسماء المختلفة).
    private var editingConfigOriginalName: String? = null
    // true فقط بعد ما نتحقق أن الملف الأصلي موقع بمفتاح الملكية الموجود في هذا الجهاز.
    private var editingConfigOwnerVerified: Boolean = false
    // .ml ملف جاي من نية VIEW خارجية (تلغرام/واتساب...) وصل قبل ما
    // SshFragment يكون جاهز - كنأخروه لحد onSshFragmentReady.
    private var pendingIncomingUri: Uri? = null

    private var drawerLayout: DrawerLayout? = null

    private var lastLogContent = ""
    private var hadRealNativeCrashThisLaunch = false // gates Share Log's crash diagnostics section - see shareLog()
    // Ensures the device/network info block below is only written once per
    // app launch (onCreate can run again after process recreation) - it is
    // NOT a replacement for the same block SshVpnService writes at the
    // start of every connection attempt, just an earlier, one-time copy so
    // it's visible even before the user taps Connect.
    private var deviceInfoLoggedThisLaunch = false
    private var activeImportedConfig: ImportedConfig? = null
    private var activeXrayConfig: ParsedProxyConfig? = null
    private var configSource: ConfigSource = ConfigSource.NONE

    // Animator ديال النبض (pulse) حول الزر الدائري - واحد فقط، ماكيتبداش
    // من جديد كل مرة UI كترفرش (applyConnectButtonState كيتصاوب فوقها
    // بزاف)، غير ملي الحالة تبدل فعليا (بحال connecting/reconnecting).
    private var pulseAnimator: ValueAnimator? = null
    private var lastButtonVisualState: String? = null
    // طلب تبديل Config المعلّق؛ كنلغي الطلب السابق باش آخر ضغطة هي اللي تربح.
    private var pendingConfigConnectJob: Job? = null
    // Unique id for the currently selected VPN service session. Status/state
    // messages from an older :vpnproc instance are ignored after a Config
    // switch, so the old DISCONNECTED/READY event cannot cancel the new one.
    private var serviceRequestId: Long = 0L
    private var pendingServiceRequestId: Long? = null

    private val vpnPrepareLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            startVpnService()
        } else {
            appendLog("ERROR: VPN Permission Denied.")
        }
    }

    private val notifPermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { }

    // باش نعرفو اسم الأوبراتور الصحيح ديال الـSIM اللي فعلا كيدير بيانات
    // الهاتف (dual-SIM) بدل ما نبقاو دايما نرجعو لـSIM الافتراضي - نفس
    // أسلوب notifPermLauncher: كنطلبوها مرة واحدة عند فتح التطبيق، وإلا
    // رفضها المستخدم، getActiveDataCarrierName() كترجع null والكود
    // كيرجع تلقائيا للطريقة القديمة (tm.networkOperatorName) بلا مشكل.
    private val phoneStatePermLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { }

    private val logReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            lifecycleScope.launch { refreshLogIfChanged() }
        }
    }

    // كيستقبل حالة الاتصال المباشرة من SshVpnService (CONNECTING / READY /
    // RECONNECTING / WAITING_NETWORK / DISCONNECTED / FAILED) باش الزر
    // يبين "RECONNECTING..." تلقائيا وقت تبديل/انقطاع الشبكة، بلا ما
    // نعتمدو غير على تحليل نص اللوگ.
    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val incomingRequestId = intent.getLongExtra(SshVpnService.EXTRA_REQUEST_ID, -1L)
            // Old vpnproc instances can still finish cleanup and broadcast
            // DISCONNECTED after a new Config has already been selected.
            // Never let such a stale event overwrite the new Config state.
            if (incomingRequestId >= 0L && serviceRequestId == 0L) {
                serviceRequestId = incomingRequestId
            } else if (incomingRequestId >= 0L && incomingRequestId != serviceRequestId) {
                return
            }

            when (intent.getStringExtra(SshVpnService.EXTRA_STATE)) {
                SshVpnService.STATE_CONNECTING -> {
                    connecting = true; connected = false; reconnectingUi = false; failedUi = false
                }
                SshVpnService.STATE_READY -> {
                    connecting = false; connected = true; reconnectingUi = false; failedUi = false
                }
                SshVpnService.STATE_RECONNECTING, SshVpnService.STATE_WAITING_NETWORK -> {
                    // WAITING_NETWORK is NOT a successful connection.
                    // Keep the UI in reconnecting/waiting state instead of
                    // leaving connected=true (which made the button green).
                    connecting = false; connected = false; reconnectingUi = true; failedUi = false
                }
                SshVpnService.STATE_DISCONNECTED -> {
                    connecting = false; connected = false; reconnectingUi = false; failedUi = false
                }
                SshVpnService.STATE_FAILED, SshVpnService.STATE_WAITING_USER_ACTION -> {
                    connecting = false; connected = false; reconnectingUi = false; failedUi = true
                }
            }
            applyConnectButtonState()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // ===== إصلاح "أيقونة تلغرام/واتساب عالقة فوق التطبيق فـ Recents" =====
        // ملي تلغرام/واتساب كيفتحو ملف .ml بـACTION_VIEW/ACTION_SEND بلا
        // FLAG_ACTIVITY_NEW_TASK، Android بعض المرات كيلصق هاد الـ Activity
        // فنفس الـ task ديال التطبيق المصدر بدل ما يخلق task جديدة خاصة
        // بيها - رغم launchMode="singleTask". isTaskRoot=false هو العلامة
        // على هاد الحالة بالضبط. الحل: نسدو هاد الـ instance ونعاودو نطلقو
        // نفس الـ Intent من جديد - هادشي كيجبر Android يبدا task جديدة
        // نظيفة (هي لي غادي تولي isTaskRoot=true فالمرة الجاية) بلا أي
        // ارتباط بـtask ديال تلغرام/واتساب، فتختفي الأيقونة العالقة فـ
        // Recents. onCreate غادي يتعاود من جديد تلقائيا مع الـ instance
        // الجديدة، فـhandleIntentUriIfPresent(intent) تحت غادي تخدم بحالها
        // ديما.
        //
        // حارس ضد loop لا نهائي: إلا كان هاد الـ intent نفسو سبق وتعاود
        // إطلاقو من هنا (EXTRA_RELAUNCHED=true) وبقات isTaskRoot=false
        // حتى بعد المحاولة، نوقفو ونكملو عادي بدل ما نلفو للأبد - بعض
        // الأجهزة/اللانشرات النادرة يمكن ما تعطيش isTaskRoot=true حتى
        // بعد finish()+startActivity().
        val isReentryFileIntent = (intent?.action == Intent.ACTION_VIEW || intent?.action == Intent.ACTION_SEND)
        if (isReentryFileIntent && !isTaskRoot && intent?.getBooleanExtra(EXTRA_RELAUNCHED, false) != true) {
            val relaunch = Intent(intent).putExtra(EXTRA_RELAUNCHED, true)
            finish()
            startActivity(relaunch)
            return
        }

        handleIntentUriIfPresent(intent)

        val root = findViewById<View>(android.R.id.content)
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            // مهم: targetSdk 35 كيفعّل edge-to-edge تلقائيا، وفهاد الحالة
            // النظام ما كيقلّصش الـ Window بحال قبل حتى مع adjustResize فـ
            // Manifest. خاصنا نزيدو bottom padding يدويا بقد ارتفاع الكيبورد
            // (ime.bottom) باش الـ ScrollView تقدر تدفع الحقول (بحال Payload)
            // للفوق وتبقى ظاهرة فوق الكيبورد بدل ما يغطيها.
            view.updatePadding(
                top = bars.top,
                bottom = if (ime.bottom > 0) ime.bottom else bars.bottom
            )
            insets
        }

        val crashLogPath = File(applicationContext.filesDir, "vpn_native_crash.txt").absolutePath
        // FIX: خاصنا نقراو أي كراش باقي من الجلسة السابقة قبل ما نديرو
        // installIfPossible() ديال الجلسة الحالية - حيت install() (فالجزء
        // native) كيكتب سطر تأكيد ("crash guard installed successfully")
        // فنفس هاد الملف بمجرد ما يتركب الـguard. قبل هاد التصحيح، كنا
        // كنديرو install() أولا ثم كنقراو الملف - فكنا كنلقاو دايما محتوى
        // (السطر لي هو ذاتو كتب install() منذ شوية)، وكنفسروه غلط كأنه
        // كراش حقيقي فكل فتح للتطبيق. دابا: نقراو وننظفو الملف أولا (أي
        // حاجة فيه جاية من كراش حقيقي فالجلسة اللي فاتت)، وبعد ذلك غير
        // نركبو الـguard ديال هاد الجلسة الجديدة.
        try {
            val crashFile = File(crashLogPath)
            if (crashFile.exists() && crashFile.length() > 0) {
                hadRealNativeCrashThisLaunch = true
                appendStartupDiag("--- Native Crash saved ---")
                appendStartupDiag(crashFile.readText())
                appendStartupDiag("--- End Native Crash ---")
                // Consume it: without this, the same (ever-growing) crash
                // file gets re-appended into the diag log on every single
                // app launch, so old crash reports pile up and duplicate
                // endlessly in Share Log. Deleting it here means each crash
                // is recorded exactly once.
                crashFile.delete()
            }
        } catch (_: Throwable) { }
        CrashGuard.installIfPossible(crashLogPath)

        Thread.setDefaultUncaughtExceptionHandler { _, e ->
            LogManager.add(applicationContext, "FATAL (uncaught): ${e.javaClass.simpleName}: ${e.message}")
        }

        logDeviceAndNetworkInfoOnce()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notifPermLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }
        if (ContextCompat.checkSelfPermission(this, android.Manifest.permission.READ_PHONE_STATE)
            != PackageManager.PERMISSION_GRANTED
        ) {
            phoneStatePermLauncher.launch(android.Manifest.permission.READ_PHONE_STATE)
        }

        val filter = IntentFilter(SshVpnService.ACTION_LOG)
        val statusFilter = IntentFilter(SshVpnService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(logReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
            registerReceiver(statusReceiver, statusFilter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(logReceiver, filter)
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(statusReceiver, statusFilter)
        }

        activeImportedConfig = SecureConfigStore.load(applicationContext)
        activeXrayConfig = XraySecureConfigStore.load(applicationContext)
        // إعادة استرجاع هوية Saved Config (اسم الملف) بعد إعادة فتح
        // التطبيق - غير إلا كان فعلا كاين كونفيغ محمل (Import Code كيستعمل
        // نفس التخزين لكن كيمسح هاد المفتاح عند الحفظ - شوف saveXrayConfig/
        // saveImportedConfig)، باش مانرجعوش اسم ملف قديم فوق كونفيغ Import
        // Code جديد.
        if (activeImportedConfig != null || activeXrayConfig != null) {
            val savedFileName = connectionStatePrefs().getString(KEY_LAST_SAVED_CONFIG_FILE, null)
            if (savedFileName != null) {
                activeConfigFileName = savedFileName
                configSource = ConfigSource.SAVED_CONFIG
            } else if (connectionStatePrefs().getBoolean(KEY_LAST_CONFIG_WAS_IMPORTED, false)) {
                // نفس المبدأ لـImported Config: كونفيغ محمل + العلامة
                // محفوظة = كان جاي من Import Code - رجّع Config imported ✓
                // + REMOVE IMPORTED CONFIG بدل ما يهبط لـ+ NEW CONFIG.
                configSource = ConfigSource.IMPORTED
            }
        }

        setupDrawer()

        val viewPager = findViewById<ViewPager2>(R.id.viewPager)
        val tabLayout = findViewById<TabLayout>(R.id.tabLayout)
        viewPager.offscreenPageLimit = 1
        viewPager.adapter = MainPagerAdapter(this)
        TabLayoutMediator(tabLayout, viewPager) { tab, position ->
            tab.text = when (position) {
                0 -> "SSH SETTINGS"
                1 -> "CONFIG"
                else -> "LOG"
            }
        }.attach()

        startLogPolling()
        showUpdateDialogIfNeeded()
    }

    /**
     * كيربط القائمة الجانبية (DrawerLayout + NavigationView). فتحها
     * بالسحب من طرف الشاشة سلوك افتراضي ديال DrawerLayout مع درور
     * layout_gravity="start" — ماكيحتاجش أي كود إضافي.
     */
    private fun setupDrawer() {
        val drawer = findViewById<DrawerLayout>(R.id.drawerLayout)
        drawerLayout = drawer
        val navView = findViewById<NavigationView>(R.id.navigationView)

        // إصلاح: NavigationView كيطبق تلوين (tint) أوتوماتيكي على الأيقونات
        // كيبان بحال دوائر بلون واحد فقط. تعطيل التلوين هنا (بالكود) هو
        // الطريقة الأكيدة باش الأيقونات الأصلية (تليجرام الأزرق، واتساب
        // الأخضر...) تبان بألوانها الحقيقية.
        navView.itemIconTintList = null

        findViewById<View>(R.id.btnMenu).setOnClickListener {
            drawer.openDrawer(androidx.core.view.GravityCompat.START)
        }

        // أول جيب لروابط Telegram/WhatsApp (links.json من GitHub)، وكل مرة
        // كتحل القائمة نعاودو الجيب فالخلفية باش الروابط تبقى دايما محدثة
        // بلا ما نحتاجو تحديث جديد للتطبيق.
        LinksManager.refreshAsync(applicationContext)
        drawer.addDrawerListener(object : DrawerLayout.SimpleDrawerListener() {
            override fun onDrawerOpened(drawerView: View) {
                LinksManager.refreshAsync(applicationContext)
            }
        })

        navView.setNavigationItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_add -> showImportDialog()
                R.id.nav_share_proxy -> showProxyShareDialog()
                R.id.nav_clear -> confirmClearAllData()
                R.id.nav_telegram -> openUrl(LinksManager.getCached(applicationContext).telegramUrl)
                R.id.nav_whatsapp -> openUrl(LinksManager.getCached(applicationContext).whatsappUrl)
                R.id.nav_sharelog -> shareLog()
            }
            drawer.closeDrawer(navView)
            true
        }
    }

    /**
     * Share Proxy dialog: an on/off switch plus a port field. Reads/writes
     * directly to SharedPreferences "proxy_share_prefs" (same name and keys
     * used in SshVpnService.startProxyShareIfEnabled) - without touching
     * the connection logic at all. The service only reads these values once
     * the state reaches READY, so a change here applies starting from the
     * next connection (or a disconnect/reconnect if the VPN is already up).
     */
    private fun showProxyShareDialog() {
        val prefs = getSharedPreferences("proxy_share_prefs", MODE_PRIVATE)
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val pad = (16 * resources.displayMetrics.density).toInt()
            setPadding(pad, pad, pad, pad)
        }

        val switchEnabled = SwitchCompat(this).apply {
            text = "Enable Internet Sharing (Proxy)"
            isChecked = prefs.getBoolean("enabled", false)
        }
        val edtPort = EditText(this).apply {
            hint = "Port (default 8388)"
            inputType = android.text.InputType.TYPE_CLASS_NUMBER
            setText(prefs.getInt("port", 8388).toString())
        }
        val txtHint = TextView(this).apply {
            text = "Once enabled, any other device on the same WiFi can add a SOCKS5 proxy using this phone's IP + the port (it will appear in Share Log). The VPN must be Connected."
            val pad = (8 * resources.displayMetrics.density).toInt()
            setPadding(0, pad, 0, 0)
            alpha = 0.7f
            textSize = 12f
        }

        container.addView(switchEnabled)
        container.addView(edtPort)
        container.addView(txtHint)

        AlertDialog.Builder(this)
            .setTitle("Share Proxy")
            .setView(container)
            .setPositiveButton("Save") { _, _ ->
                val port = edtPort.text?.toString()?.trim()?.toIntOrNull()
                if (port == null || port !in 1024..65535) {
                    Toast.makeText(this, "Invalid port (1024-65535)", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                prefs.edit()
                    .putBoolean("enabled", switchEnabled.isChecked)
                    .putInt("port", port)
                    .apply()
                Toast.makeText(
                    this,
                    if (switchEnabled.isChecked) "Enabled - will start on the next connection" else "Disabled",
                    Toast.LENGTH_SHORT
                ).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    /**
     * "Clear" فالقائمة الجانبية (تحت Share Proxy) - كيمسح كل حاجة محفوظة
     * فالتطبيق ويرجعو لحالة أول تشغيل. Delete/Cancel، بلا رجعة (irreversible).
     */
    private fun confirmClearAllData() {
        AlertDialog.Builder(this)
            .setTitle("Clear All Data")
            .setMessage("This will permanently delete all saved configs, imported config, manual fields, and share-proxy settings, and disconnect if connected. This cannot be undone.")
            .setPositiveButton("Delete") { _, _ -> clearAllAppDataAndResetToFirstLaunch() }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun clearAllAppDataAndResetToFirstLaunch() {
        // 1) قطع الاتصال إلا كان خدام أو فطور الاتصال.
        if (connected || connecting) disconnect()

        // 2) الكونفيغ "المخفي" النشط (Saved Config أو Import Code) - نفس
        // التخزين لي كيستعملو activeImportedConfig/activeXrayConfig.
        SecureConfigStore.clear(applicationContext)
        XraySecureConfigStore.clear(applicationContext)
        activeImportedConfig = null
        activeXrayConfig = null

        // 3) هوية الملف/المصدر (Saved Config identity + persistence ديالها).
        activeConfigFileName = null
        editingConfigOriginalName = null
        editingConfigOwnerVerified = false
        configSource = ConfigSource.NONE
        persistLastSavedConfigFileName(null)
        persistImportedConfigActive(false)

        // 4) الحقول اليدوية (SSH/V2Ray/Shadowsocks) + Share Proxy settings.
        manualFieldsPrefs().edit().clear().apply()
        connectionStatePrefs().edit().clear().apply()
        getSharedPreferences("proxy_share_prefs", MODE_PRIVATE).edit().clear().apply()

        // 5) مسح Connection Log أيضاً، وتصفير الكاش ديال الواجهة.
        // مهم: Clear All Data خاصو يمسح حتى السجل، ماشي غير الـconfigs.
        LogManager.clear(applicationContext)
        lastLogContent = ""
        logFragment?.txtLog?.text = ""

        // مسح نسخة Share Log التي تم إنشاؤها سابقاً داخل cache.
        // LogManager.clear() يمسح Connection Log، لكنه لا يمسح ملف
        // vpn_log_share.txt الذي يتم إنشاؤه فقط عند الضغط على Share Log.
        try {
            File(cacheDir, "vpn_log_share.txt").delete()
        } catch (_: Throwable) { }

        // مسح vpn_startup_diag.txt (ملف الـcrash guard) أيضاً - هذا الملف
        // كان كيتزاد فيه سطر جديد فـappendStartupDiag() كل launch، وعمرو
        // ماكان كيتمسح لا هنا ولا فأي بلاصة أخرى، فكان كيتراكم من بداية
        // استعمال التطبيق. النتيجة: أي كراش حقيقي جديد كان كيجيب معاه
        // كامل التاريخ ديال "crash guard installed successfully" السابقين
        // فـShare Log، وهذا اللي كان كيبان بحال كراش كيتكرر بزاف.
        try {
            File(applicationContext.filesDir, "vpn_startup_diag.txt").delete()
        } catch (_: Throwable) { }

        // 6) واجهة فورية (بلا ما نستنى الحذف ديال الملفات، لي كيدير IO):
        // الحقول ترجع افتراضية، الكارد ديال Saved Config/Imported يختفي.
        restoreManualFields()
        updateImportUiState()
        configFragment?.updateActiveVisuals(null, false, false)
        applyConnectButtonState()

        // 7) مسح كل ملفات Saved Config (.ml) فـDownloads/MR VPN TUNNEL -
        // list()/delete() كيديرو MediaStore/File IO، خاصهم Dispatchers.IO
        // (نفس القاعدة ديال saveNewConfig فوق). configFragment?.refreshList()
        // هنا كيرجع يقرا اللائحة (خاوية دابا) من نفس المصدر.
        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                val entries = ConfigStorageManager.list(applicationContext)
                entries.forEach { entry ->
                    ConfigStorageManager.delete(applicationContext, entry)
                    UnlockedConfigCache.remove(entry.displayName)
                }
            }
            configFragment?.refreshList()
            Toast.makeText(this@MainActivity, "All data cleared", Toast.LENGTH_SHORT).show()
        }
    }

    private fun openUrl(url: String) {
        if (url.isBlank()) return
        try {
            startActivity(Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url)))
        } catch (_: Throwable) {
            Toast.makeText(this, "Could not open link.", Toast.LENGTH_SHORT).show()
        }
    }

    private var updateDialogShowing = false

    /**
     * Single source of truth call for whether to prompt the user to update -
     * cheap, synchronous, purely local (see UpdateManager.getPendingUpdate).
     * Called on every onCreate/onStart so the prompt reliably reappears on
     * every app launch (including after a reboot) until the app is actually
     * updated, exactly as required - independent of whether the device has
     * internet right now.
     */
    private fun showUpdateDialogIfNeeded() {
        if (updateDialogShowing) return
        if (isFinishing || isDestroyed) return
        val update = UpdateManager.getPendingUpdate(applicationContext) ?: return

        // إذا كان VPN متصل (أو فطور الاتصال) ملي طلع "New Version Available"،
        // نقطعو الاتصال تلقائيا - المستخدم خاصو يحدث التطبيق، وما بغيناش
        // يبقى Tunnel شغال بنسخة قديمة فالخلفية بلا ما المستخدم يعرف.
        if (connected || connecting) {
            disconnect()
            // رسالة تنبيه بلون الزيون فقط - بلا ما نمس أي حاجة فمنطق
            // الاتصال/الـprofile ديال VPN. الهدف غير نعلمو المستخدم أن
            // الحماية طاحت بسبب الانقطاع التلقائي.
            Toast.makeText(
                this,
                "⚠️ VPN disconnected — update required. Your traffic is not protected.",
                Toast.LENGTH_LONG
            ).apply {
                view?.findViewById<TextView>(android.R.id.message)
                    ?.setTextColor(android.graphics.Color.parseColor("#FFD700"))
            }.show()
        }

        val view = layoutInflater.inflate(R.layout.dialog_update, null)
        val txtTitle = view.findViewById<TextView>(R.id.txtUpdateTitle)
        val txtVersion = view.findViewById<TextView>(R.id.txtUpdateVersion)
        val txtMessage = view.findViewById<TextView>(R.id.txtUpdateMessage)
        val btnLater = view.findViewById<TextView>(R.id.btnUpdateLater)
        val btnDownload = view.findViewById<TextView>(R.id.btnUpdateDownload)

        txtTitle.text = update.title.ifBlank { "New Version Available" }
        txtVersion.text = if (update.versionName.isNotBlank()) "Version ${update.versionName}" else ""
        txtVersion.visibility = if (update.versionName.isNotBlank()) View.VISIBLE else View.GONE
        txtMessage.text = update.message
        txtMessage.visibility = if (update.message.isNotBlank()) View.VISIBLE else View.GONE

        // The dialog must never be dismissed by tapping outside it or by the
        // back button - regardless of forceUpdate - it can only be closed via
        // the LATER or DOWNLOAD buttons below.
        val dialog = AlertDialog.Builder(this)
            .setView(view)
            .setCancelable(false)
            .create()
        dialog.setCanceledOnTouchOutside(false)

        // force_update = true: no way to dismiss without tapping Download -
        // no Later button, no outside-tap dismiss, no back-press dismiss.
        btnLater.visibility = if (update.forceUpdate) View.GONE else View.VISIBLE
        btnLater.setOnClickListener { dialog.dismiss() }

        btnDownload.setOnClickListener {
            openDownloadUrl(update.downloadUrl)
            // Deliberately never dismissed here, even on success - per the
            // requirement, the dialog only ever goes away once
            // BuildConfig.VERSION_CODE actually reaches latest_version
            // (i.e. after the user installs the new build and relaunches).
        }

        dialog.setOnDismissListener { updateDialogShowing = false }
        updateDialogShowing = true
        dialog.show()
    }

    private fun openDownloadUrl(url: String) {
        if (url.isBlank()) return
        try {
            startActivity(Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url)))
        } catch (_: Throwable) {
            Toast.makeText(this, "Could not open download link.", Toast.LENGTH_SHORT).show()
        }
    }

    fun onSshFragmentReady(fragment: SshFragment) {
        sshFragment = fragment

        fragment.btnConnect.setOnClickListener {
            try {
                if (connected || connecting) disconnect() else tryConnect()
            } catch (e: Throwable) {
                appendLog("ERROR: ${e.javaClass.simpleName}: ${e.message ?: "Unknown error"}")
                android.util.Log.e("MainActivity", "Connection error", e)
            }
        }
        fragment.btnShareLog.setOnClickListener { shareLog() }
        fragment.btnImportConfig.setOnClickListener { showImportDialog() }
        fragment.btnRemoveImported.setOnClickListener { confirmRemoveImportedConfig() }
        fragment.rowProtocol.setOnClickListener { showProtocolPicker() }
        fragment.btnNewConfig.setOnClickListener { showNewConfigNameDialog() }

        restoreManualFields()
        wireManualFieldPersistence()
        updateImportUiState()
        syncStateFromService()
        processPendingFileIntentIfAny()
    }

    /**
     * Reads the real, current state from SshVpnService (persisted via
     * StateStore, since the service runs in a separate process and cannot be
     * queried directly) and applies it to the button. Called on cold start
     * and every time the app becomes visible again, so the UI is always
     * driven by the service's actual state rather than an assumption or a
     * stale in-memory value left over from before the app was backgrounded.
     */
    private fun syncStateFromService() {
        lifecycleScope.launch {
            // readReconciled (not read): if the persisted state claims an
            // active connection but the ":vpnproc" process is actually dead
            // (Force Stop / system kill wiped it out without ever writing
            // DISCONNECTED), this treats it as DISCONNECTED and heals the
            // file - so the button always resets itself to CONNECT on its
            // own the next time the app is opened, instead of staying stuck
            // on CONNECTING.../DISCONNECT forever.
            val snapshot = withContext(Dispatchers.IO) { StateStore.readSnapshot(applicationContext) }
            if (serviceRequestId == 0L && snapshot.requestId >= 0L) {
                serviceRequestId = snapshot.requestId
            } else if (snapshot.requestId >= 0L && snapshot.requestId != serviceRequestId) {
                return@launch
            }
            val state = withContext(Dispatchers.IO) { StateStore.readReconciled(applicationContext) }
            when (state) {
                SshVpnService.STATE_CONNECTING -> {
                    connecting = true; connected = false; reconnectingUi = false
                }
                SshVpnService.STATE_READY -> {
                    connecting = false; connected = true; reconnectingUi = false
                }
                SshVpnService.STATE_RECONNECTING, SshVpnService.STATE_WAITING_NETWORK -> {
                    // WAITING_NETWORK must never be rendered as CONNECTED.
                    connecting = false; connected = false; reconnectingUi = true
                }
                else -> { // DISCONNECTED, FAILED, or nothing ever recorded
                    connecting = false; connected = false; reconnectingUi = false
                }
            }
            applyConnectButtonState()
        }
    }

    fun onLogFragmentReady(fragment: LogFragment) {
        logFragment = fragment
        fragment.txtLog.text = LogManager.formatForUi(lastLogContent)
        fragment.logScroll.post { fragment.logScroll.fullScroll(View.FOCUS_DOWN) }
    }

    fun onConfigFragmentReady(fragment: ConfigFragment) {
        configFragment = fragment
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntentUriIfPresent(intent)
        processPendingFileIntentIfAny()
    }

    private fun handleIntentUriIfPresent(intent: Intent?) {
        if (intent == null) return
        val uri = when (intent.action) {
            Intent.ACTION_VIEW -> intent.data
            Intent.ACTION_SEND -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_STREAM)
                }
            }
            else -> null
        }
        if (uri != null) pendingIncomingUri = uri
    }

    /** Called once sshFragment (and its fields) actually exist - see onSshFragmentReady. */
    private fun processPendingFileIntentIfAny() {
        val uri = pendingIncomingUri ?: return
        if (sshFragment == null) return
        pendingIncomingUri = null
        handleIncomingConfigFile(uri)
    }

    /**
     * كينظف الـ Intent الحالي ديال هاد الـ Activity من أي أثر ديال
     * ACTION_VIEW/ACTION_SEND الجاي من تلغرام/واتساب (action, data,
     * extras) ويعوضو بـ Intent عادي بحال ما يكون التطبيق تحل من
     * اللانشر مباشرة. بلا هاد الخطوة، getIntent() كيبقى شاد فبالو
     * نية المصدر (تلغرام/واتساب) طول ما الـ Activity حية - وهو اللي
     * كان كيخلي أيقونة تلغرام/واتساب تبقى بادية عالقة فوق التطبيق فـ
     * Recents، وكيخلي أي إعادة قراءة لـintent (بحال بعد rotation) تعاود
     * تفتح نفس الملف من جديد بلا داعي.
     */
    private fun clearIncomingIntentLinkage() {
        val cleanIntent = Intent(Intent.ACTION_MAIN).apply {
            addCategory(Intent.CATEGORY_LAUNCHER)
            setClass(this@MainActivity, MainActivity::class.java)
        }
        setIntent(cleanIntent)
    }

    /**
     * كيقرا ملف .ml جاي من نية VIEW خارجية (تلغرام/واتساب/أي مدير ملفات) -
     * كيحفظ نسخة منو فـCONFIG tab (بلا ما يبدل شي ملف بنفس الاسم - كيزيد
     * "(1)" إلا تكرر)، يبدل لتبويب CONFIG (ماشي SSH SETTINGS)، ويتصل من
     * تما - إلا محمي بكلمة سر كنطلبوها (مرة وحدة فهاد الجلسة، شوف
     * UnlockedConfigCache). بلا ما نمسو أي حاجة فمنطق الاتصال نفسو.
     */
    private fun handleIncomingConfigFile(uri: Uri) {
        lifecycleScope.launch {
            val bytes = withContext(Dispatchers.IO) { ConfigStorageManager.readBytes(applicationContext, uri) }
            // كيف ما كانت النتيجة (نجحات القراءة أو لا)، خاص الـ Intent
            // يتنظف مباشرة هنا - الملف تقرا ديجا (bytes) ولا خاصنا ما
            // خصناش نبقاو مرتبطين بنية تلغرام/واتساب.
            clearIncomingIntentLinkage()
            if (bytes == null) {
                Toast.makeText(this@MainActivity, "Could not read config file.", Toast.LENGTH_SHORT).show()
                return@launch
            }
            if (!looksLikeMlConfig(bytes)) {
                Toast.makeText(this@MainActivity, "Invalid or corrupted MR VPN TUNNEL config file.", Toast.LENGTH_SHORT).show()
                return@launch
            }

            // اسم الـURI الخارجي (تلغرام/واتساب) - fallback أخير غير إلا ما
            // قدرناش نجيبو الاسم الحقيقي من جوا الملف. تطبيقات بحال تلغرام
            // كيرجعو أحيانا معرف داخلي رقمي (مثلا "4_5769215511841743645")
            // بدل الاسم الأصلي عبر OpenableColumns.DISPLAY_NAME - فهاد
            // الحالة الاسم من جوا محتوى .ml نفسو (MlConfigFile.Parsed.name)
            // هو المصدر الموثوق، تماما بحال match.name فتطبيق LiveTV.
            val fallbackName = withContext(Dispatchers.IO) {
                ConfigStorageManager.queryDisplayName(applicationContext, uri)
            } ?: "config_${System.currentTimeMillis()}"

            try {
                if (MlConfigFile.isEncrypted(bytes)) {
                    // الاسم مشفر جوا الملف - ماخصناش نحفظو تحت اسم غالط ثم
                    // نبدلوه؛ نطلبو كلمة السر قبل الحفظ باش نعرفو الاسم
                    // الحقيقي من أول مرة.
                    promptPasswordForIncomingFile(bytes, fallbackName)
                } else {
                    val parsed = MlConfigFile.parse(bytes, null)
                    val realName = parsed.name.trim().ifBlank { fallbackName }
                    val saved = withContext(Dispatchers.IO) {
                        ConfigStorageManager.saveDeduped(applicationContext, realName, bytes)
                    }
                    if (saved == null) {
                        Toast.makeText(this@MainActivity, "Could not save config.", Toast.LENGTH_SHORT).show()
                        return@launch
                    }
                    // saved.first = Uri, saved.second = اسم الملف المحفوظ - ماخصناش
                    // حتى واحد منهم هنا، الحفظ كافي.
                    findViewById<ViewPager2>(R.id.viewPager).currentItem = 1
                    configFragment?.refreshList()
                    // نحفظو الملف فقط - بلا اتصال تلقائي. المستخدم خاصو
                    // يضغط Connect بيدو (من CONFIG tab ولا SSH SETTINGS)،
                    // بحال بالضبط الملفات لي كتنحفظ من "+ NEW CONFIG".
                }
            } catch (_: Throwable) {
                Toast.makeText(this@MainActivity, "Invalid or corrupted MR VPN TUNNEL config file.", Toast.LENGTH_SHORT).show()
            }
        }
    }

    /** فحص خفيف بلا فك تشفير - غير باش نأكدو أن الملف MR VPN TUNNEL فعلا قبل ما نحفظوه فـCONFIG tab. */
    private fun looksLikeMlConfig(bytes: ByteArray): Boolean {
        return try { MlConfigFile.isEncrypted(bytes); true } catch (_: Throwable) { false }
    }

    /**
     * كلمة السر كتطلب قبل أي حفظ - الاسم الحقيقي (parsed.name) ماكيبانش
     * إلا بعد فك التشفير، فكنحفظو الملف بيه مباشرة (fallbackName كيتستعمل
     * غير إلا كان الاسم الداخلي فارغ لسبب ما).
     */
    private fun promptPasswordForIncomingFile(bytes: ByteArray, fallbackName: String) {
        val input = EditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = "Password"
        }
        AlertDialog.Builder(this)
            .setTitle("Protected Config")
            .setMessage("This config is password protected. Enter the password to save it (you'll only need to enter it once this session).")
            .setView(input)
            .setPositiveButton("Open") { _, _ ->
                val password = input.text.toString()
                lifecycleScope.launch {
                    try {
                        val parsed = withContext(Dispatchers.Default) { MlConfigFile.parse(bytes, password) }
                        val realName = parsed.name.trim().ifBlank { fallbackName }
                        val saved = withContext(Dispatchers.IO) {
                            ConfigStorageManager.saveDeduped(applicationContext, realName, bytes)
                        }
                        if (saved == null) {
                            Toast.makeText(this@MainActivity, "Could not save config.", Toast.LENGTH_SHORT).show()
                            return@launch
                        }
                        val (_, savedName) = saved
                        UnlockedConfigCache.put(savedName, parsed.fields)
                        findViewById<ViewPager2>(R.id.viewPager).currentItem = 1
                        configFragment?.refreshList()
                        // نحفظو الملف فقط - بلا اتصال تلقائي. كلمة السر
                        // بقات محفوظة فـUnlockedConfigCache لهاد الجلسة
                        // (بحال ما كان موعود فالـdialog) - ملي المستخدم
                        // يضغط على الملف من CONFIG tab باش يتصل، ماغاديش
                        // يطلب منو كلمة السر مرة ثانية.
                    } catch (_: MlConfigParseException) {
                        Toast.makeText(this@MainActivity, "Wrong password.", Toast.LENGTH_SHORT).show()
                    } catch (_: Throwable) {
                        Toast.makeText(this@MainActivity, "Wrong password.", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    /** Snapshot of whatever protocol/fields are currently set in SSH SETTINGS - used to build a new .ml config. */
    fun currentManualFieldsSnapshot(): Map<String, Any?> {
        val p = manualFieldsPrefs()
        return linkedMapOf(
            "protocol" to (p.getString("protocol", DEFAULT_PROTOCOL.label) ?: DEFAULT_PROTOCOL.label),
            "host" to (p.getString("host", "") ?: ""),
            "user" to (p.getString("user", "") ?: ""),
            "pass" to (p.getString("pass", "") ?: ""),
            "proxy" to (p.getString("proxy", "") ?: ""),
            "payload" to (p.getString("payload", "") ?: ""),
            "usePayload" to p.getBoolean("usePayload", DEFAULT_PROTOCOL.usePayload),
            "sni" to (p.getString("sni", "") ?: ""),
            "useSsl" to p.getBoolean("useSsl", DEFAULT_PROTOCOL.useSsl),
            "udpgwEnabled" to p.getBoolean("udpgwEnabled", false),
            "udpgwPort" to (p.getString("udpgwPort", "7300") ?: "7300"),
            "v2rayJson" to (p.getString("v2rayJson", "") ?: ""),
            "ssServer" to (p.getString("ssServer", "") ?: ""),
            "ssPort" to (p.getString("ssPort", "") ?: ""),
            "ssMethod" to (p.getString("ssMethod", "") ?: ""),
            "ssPassword" to (p.getString("ssPassword", "") ?: ""),
            "ssUdp" to p.getBoolean("ssUdp", true)
        )
    }

    // ===== إنشاء كونفيغ .ml جديد (زر "+ NEW CONFIG" فـSSH SETTINGS) =====
    // اسم -> كلمة سر اختيارية -> حفظ. بلا خطوة سيرفر مساج (تحيدات).

    private fun showNewConfigNameDialog() {
        val isEditing = editingConfigOriginalName != null
        val prefillName = if (isEditing) {
            editingConfigOriginalName!!.removeSuffix(".${MlConfigFile.EXTENSION}")
        } else ""
        val nameInput = EditText(this).apply {
            hint = "Config name"
            if (prefillName.isNotEmpty()) {
                setText(prefillName)
                setSelection(prefillName.length)
            }
        }
        AlertDialog.Builder(this)
            .setTitle(if (isEditing) "Edit Config" else "New Config")
            .setMessage(
                if (isEditing) "Update your changes, then save them back into this same config file."
                else "Name this config. It will be created from your current SSH SETTINGS."
            )
            .setView(nameInput)
            .setPositiveButton(if (isEditing) "Save" else "Next") { _, _ ->
                val name = nameInput.text.toString().trim()
                if (name.isEmpty()) {
                    Toast.makeText(this, "Please enter a name.", Toast.LENGTH_SHORT).show()
                    return@setPositiveButton
                }
                if (isEditing) {
                    // Password إجباري دابا على كل حفظ (جديد ولا Edit) - نفس
                    // dialog password (showNewConfigPasswordDialog) لي
                    // كيدير الحفظ In-Place عبر editingConfigOriginalName
                    // (شوف saveNewConfig()).
                    showNewConfigPasswordDialog(name)
                } else {
                    lifecycleScope.launch {
                        val fileName = ConfigStorageManager.finalFileName(name)
                        val existing = withContext(Dispatchers.IO) { ConfigStorageManager.list(applicationContext) }
                            .firstOrNull { it.displayName.equals(fileName, ignoreCase = true) }
                        if (existing != null) {
                            // ممنوع تكرار نفس اسم الملف - كنطلبو اسم آخر بدل
                            // ما نبدلو الملف بصمت.
                            Toast.makeText(
                                this@MainActivity,
                                "\"$fileName\" already exists. Please choose a different name.",
                                Toast.LENGTH_LONG
                            ).show()
                            showNewConfigNameDialog()
                        } else {
                            showNewConfigPasswordDialog(name)
                        }
                    }
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showNewConfigPasswordDialog(name: String) {
        val passInput = EditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = "Password (required, min ${MlConfigFile.MIN_PASSWORD_LENGTH} characters)"
        }
        AlertDialog.Builder(this)
            .setTitle("Set a Password")
            .setMessage("Every config must be protected with a password. It will be strongly encrypted (AES-256) - no one can read the server info inside without it.")
            .setView(passInput)
            .setPositiveButton("Save") { _, _ ->
                val password = passInput.text.toString()
                if (password.isEmpty()) {
                    Toast.makeText(this, "A password is required.", Toast.LENGTH_SHORT).show()
                    showNewConfigPasswordDialog(name)
                    return@setPositiveButton
                }
                if (password.length < MlConfigFile.MIN_PASSWORD_LENGTH) {
                    Toast.makeText(
                        this,
                        "Password must be at least ${MlConfigFile.MIN_PASSWORD_LENGTH} characters.",
                        Toast.LENGTH_LONG
                    ).show()
                    showNewConfigPasswordDialog(name)
                    return@setPositiveButton
                }
                saveNewConfig(name, password)
            }
            .setNegativeButton("Back") { _, _ -> showNewConfigNameDialog() }
            .show()
    }

    /**
     * كيحفظ الكونفيغ - جديد أو تعديل. فحالة التعديل (editingConfigOriginalName
     * != null) كيدير الحفظ In-Place: كيستهدف نفس الملف الأصلي مباشرة عبر
     * editingConfigOriginalName (بلا أي مقارنة مع الاسم لي كتب المستخدم فـ
     * الديالوغ)، ويبدل محتواه بـConfigStorageManager.overwrite() - نفس الـURI،
     * نفس اسم الملف على القرص، بلا نسخة ثانية. إذا الملف الأصلي ماكاينش
     * (تحيد بطريقة ما)، كنرجعو نديرو ملف جديد باش ماتضيعش التعديلات.
     */
    private fun saveNewConfig(name: String, password: String) {
        val fields = currentManualFieldsSnapshot()
        val bytes = try {
            MlConfigFile.build(applicationContext, name, "", fields, password.ifBlank { null })
        } catch (e: MlConfigWeakPasswordException) {
            Toast.makeText(this, "Password must be at least ${MlConfigFile.MIN_PASSWORD_LENGTH} characters.", Toast.LENGTH_LONG).show()
            return
        }

        val editingOriginal = editingConfigOriginalName
        if (editingOriginal != null && !editingConfigOwnerVerified) {
            Toast.makeText(this, "This config belongs to another device. Create a new config instead.", Toast.LENGTH_LONG).show()
            editingConfigOriginalName = null
            editingConfigOwnerVerified = false
            return
        }

        lifecycleScope.launch {
            val allEntries = withContext(Dispatchers.IO) { ConfigStorageManager.list(applicationContext) }
            var ok = false
            var savedFileName: String? = null

            if (editingOriginal != null) {
                val target = allEntries.firstOrNull { it.displayName.equals(editingOriginal, ignoreCase = true) }
                if (target != null) {
                    val newFileName = ConfigStorageManager.finalFileName(name)
                    val sameName = newFileName.equals(target.displayName, ignoreCase = true)

                    if (sameName) {
                        // نفس الاسم: نكتب فوق الملف نفسه.
                        ok = withContext(Dispatchers.IO) {
                            ConfigStorageManager.overwrite(applicationContext, target, bytes)
                        }
                        savedFileName = target.displayName
                    } else {
                        // الاسم تبدل: overwrite() وحدها كتبدل المحتوى فقط وما كتبدلش
                        // اسم الملف. لذلك نحفظ نسخة جديدة بالاسم الجديد ثم نحذف القديم.
                        val collision = allEntries.firstOrNull {
                            it.displayName.equals(newFileName, ignoreCase = true)
                        }

                        if (collision != null) {
                            Toast.makeText(
                                this@MainActivity,
                                "\"$newFileName\" already exists. Please choose a different name.",
                                Toast.LENGTH_LONG
                            ).show()
                            return@launch
                        }

                        val savedNew = withContext(Dispatchers.IO) {
                            ConfigStorageManager.save(applicationContext, name, bytes)
                        }

                        if (savedNew != null) {
                            // ما نمسحوش الملف القديم إلا بعد نجاح إنشاء الملف الجديد.
                            val deletedOld = withContext(Dispatchers.IO) {
                                ConfigStorageManager.delete(applicationContext, target)
                            }
                            if (deletedOld) {
                                UnlockedConfigCache.remove(target.displayName)
                                ok = true
                                savedFileName = newFileName
                            } else {
                                // فشل حذف القديم: نحاول نحافظ على سلامة البيانات.
                                // الملف الجديد بقى محفوظ، لكن ما نعتبرش العملية مكتملة.
                                ok = false
                                savedFileName = newFileName
                            }
                        }
                    }
                } else {
                    // الملف الأصلي تحيد من قبل: ننشئ ملف جديد بالاسم المطلوب.
                    val saved = withContext(Dispatchers.IO) {
                        ConfigStorageManager.save(applicationContext, name, bytes)
                    }
                    ok = saved != null
                    savedFileName = ConfigStorageManager.finalFileName(name)
                }
            } else {
                val fileName = ConfigStorageManager.finalFileName(name)
                val existing = allEntries.firstOrNull { it.displayName.equals(fileName, ignoreCase = true) }
                if (existing != null) {
                    ok = withContext(Dispatchers.IO) {
                        ConfigStorageManager.overwrite(applicationContext, existing, bytes)
                    }
                } else {
                    ok = withContext(Dispatchers.IO) {
                        ConfigStorageManager.save(applicationContext, name, bytes) != null
                    }
                }
                savedFileName = fileName
            }

            if (ok && savedFileName != null) {
                // FIX (مشكلة 2): قبل هاد التصحيح، أي CREATE CONFIG (حتى
                // ملي كون الاتصال الحقيقي الجاري هو Manual/Choose Protocol
                // ولا Import Code) كان كيبدل activeConfigFileName/
                // configSource لـSAVED_CONFIG مباشرة - فيبان الملف الجديد
                // فـCONFIG tab وكأنه هو الاتصال النشط/RUNNING، رغم أن
                // الـtunnel الحقيقي مازال خدام بمصدر آخر بالكامل (mismatch
                // بين Connection Source و Config Source).
                //
                // الحل: نبدلو activeConfigFileName/configSource للملف
                // الجديد غير فحالتين:
                // 1) ما كاين حتى اتصال/محاولة اتصال جارية دابا (السلوك
                //    القديم بلا تغيير).
                // 2) هاد الحفظ هو تعديل In-Place (Edit/Rename) لنفس
                //    الملف لي هو ديجا الـSAVED_CONFIG النشط - فهاد الحالة
                //    فعلا بقات نفس الاتصال، غير الاسم/المحتوى تبدل.
                //
                // فكل حالة أخرى (مثلا: متصل بـManual من SSH SETTINGS ثم
                // CREATE CONFIG لملف جديد، أو Edit لملف آخر ماشي النشط)،
                // الملف كيتحفظ عادي فـDownloads لكن بلا ما "يسرق" حالة
                // Active/Running - الاتصال الحقيقي كيبقى واضح أن مصدره
                // Manual/Import Code بحالو.
                val wasEditingActiveConfig = editingOriginal != null &&
                    configSource == ConfigSource.SAVED_CONFIG &&
                    activeConfigFileName == editingOriginal
                val liveConnectionFromOtherSource = (connected || connecting) && !wasEditingActiveConfig
                if (!liveConnectionFromOtherSource) {
                    // حدّث هوية الملف النشط حتى يبان الاسم الجديد مباشرة في SSH SETTINGS
                    // وما يبقاش activeConfigFileName مربوط بالاسم القديم.
                    activeConfigFileName = savedFileName
                    configSource = ConfigSource.SAVED_CONFIG
                    persistLastSavedConfigFileName(savedFileName)
                }

                Toast.makeText(
                    this@MainActivity,
                    "Config saved to Download/MR VPN TUNNEL",
                    Toast.LENGTH_SHORT
                ).show()
                editingConfigOriginalName = null
                editingConfigOwnerVerified = false
                UnlockedConfigCache.remove(savedFileName)
                configFragment?.refreshList()
                updateConnectionSummary()
            } else if (editingOriginal != null) {
                Toast.makeText(this@MainActivity, "Could not rename/save config. The original file was kept.", Toast.LENGTH_LONG).show()
                configFragment?.refreshList()
            } else {
                Toast.makeText(this@MainActivity, "Could not save config.", Toast.LENGTH_SHORT).show()
                configFragment?.refreshList()
            }
        }
    }

    /** كيكتب فـ manual_fields prefs غير المفاتيح الموجودة فـ fields - بلا ما يمس أي حاجة أخرى. */
    private fun applyFieldsToManualPrefs(fields: Map<String, Any?>) {
        val editor = manualFieldsPrefs().edit()
        (fields["protocol"] as? String)?.let { editor.putString("protocol", it) }
        (fields["host"] as? String)?.let { editor.putString("host", it) }
        (fields["user"] as? String)?.let { editor.putString("user", it) }
        (fields["pass"] as? String)?.let { editor.putString("pass", it) }
        (fields["proxy"] as? String)?.let { editor.putString("proxy", it) }
        (fields["payload"] as? String)?.let { editor.putString("payload", it) }
        (fields["usePayload"] as? Boolean)?.let { editor.putBoolean("usePayload", it) }
        (fields["sni"] as? String)?.let { editor.putString("sni", it) }
        (fields["useSsl"] as? Boolean)?.let { editor.putBoolean("useSsl", it) }
        (fields["udpgwEnabled"] as? Boolean)?.let { editor.putBoolean("udpgwEnabled", it) }
        fields["udpgwPort"]?.toString()?.let { editor.putString("udpgwPort", it) }
        (fields["v2rayJson"] as? String)?.let { editor.putString("v2rayJson", it) }
        (fields["ssServer"] as? String)?.let { editor.putString("ssServer", it) }
        fields["ssPort"]?.toString()?.let { editor.putString("ssPort", it) }
        (fields["ssMethod"] as? String)?.let { editor.putString("ssMethod", it) }
        (fields["ssPassword"] as? String)?.let { editor.putString("ssPassword", it) }
        (fields["ssUdp"] as? Boolean)?.let { editor.putBoolean("ssUdp", it) }
        editor.apply()
    }

    /** Edit flow (ConfigFragment "Edit", بلا كلمة سر فقط): يعمر الحقول ويرجع لتبويب SSH SETTINGS بلا اتصال تلقائي. */
    fun loadFieldsForEditing(originalName: String, fields: Map<String, Any?>, ownerVerified: Boolean = false) {
        if (!ownerVerified) {
            Toast.makeText(this, "Only the device that created this config can edit it.", Toast.LENGTH_LONG).show()
            return
        }
        clearActiveImportedConfigSilently()
        activeConfigFileName = null
        persistLastSavedConfigFileName(null)
        persistImportedConfigActive(false)
        configFragment?.updateActiveVisuals(null, false, false)
        editingConfigOriginalName = originalName
        editingConfigOwnerVerified = true
        applyFieldsToManualPrefs(fields)
        restoreManualFields()
        updateImportUiState()
        findViewById<ViewPager2>(R.id.viewPager).currentItem = 0
    }

    /**
     * كيتصل بملف .ml محدد بلا ما يبدل تبويب - كيبقى المستخدم فـCONFIG
     * tab وكيشوف الصف كيتلون بالأخضر وزر ★ يتبدل لـ■. بلا ما يمس
     * tryConnect/startVpnService/بروتوكول الاتصال نفسو، غير كيستدعيهم
     * بحال ما يدير المستخدم بيدو من SSH SETTINGS.
     *
     * دايما كيبني كونفيغ "مخفي" (ImportedConfig/ParsedProxyConfig)،
     * محمي بكلمة سر ولا لا - وكيبين غير ملخص (File/Protocol/Server/Port)
     * فـSSH SETTINGS، ماشي "Config imported" (هادشي خاص فقط بـImport
     * Code - شوف ConfigSource فوق).
     */
    fun connectConfigFile(displayName: String, fields: Map<String, Any?>, isProtected: Boolean) {
        // Config واحد فقط مسموح فنفس الوقت: إلا كان فيه اتصال/محاولة اتصال
        // جارية بملف آخر، نقطعوها أولا قبل ما نبداو هاد الملف الجديد.
        //
        // SshVpnService كتخدم فـprocess منفصل (:vpnproc)، وstopVpn() كتدير
        // Process.killProcess() بـdelay ديال 300ms (باش Xray/hev-socks5
        // يتنظفو بأمان قبل القتل - شوف SshVpnService.stopVpn()). إلا
        // درنا tryConnect() مباشرة بعد disconnect() بلا نستناو، الاتصال
        // الجديد كيبدا فنفس الـprocess القديمة، وملي توصل الـ300ms،
        // killProcess() (المجدولة من الـdisconnect القديم) كتقتل الاتصال
        // الجديد معاها. هادشي كان كيخلي أول ضغطة تدير غير قطع الاتصال
        // القديم بلا ما تكمل تتصل بالجديد - وخصنا ضغطة ثانية باش يخدم.
        // الحل: نستناو أكثر من 300ms (400ms) قبل ما نبداو tryConnect().
        val needsDisconnectFirst = (connected || connecting) && activeConfigFileName != displayName
        val oldServiceRequestId = serviceRequestId
        if (needsDisconnectFirst) {
            // Invalidate every event belonging to the old VPN session before
            // asking that session to stop. The UI can switch to B immediately,
            // while the old process finishes cleanup in the background.
            serviceRequestId = System.nanoTime()
            pendingServiceRequestId = serviceRequestId
        }
        // إلا كان كاين تبديل سابق مازال كيتسنى، نلغيوه فوراً.
        // هكذا مايمكنش طلب قديم يرجع من بعد ويشغل Config آخر.
        pendingConfigConnectJob?.cancel()
        pendingConfigConnectJob = null

        if (needsDisconnectFirst) {
            disconnect(oldServiceRequestId)
        }

        val ok = applyFieldsAsHiddenImportedConfig(fields)
        if (!ok) return

        configSource = ConfigSource.SAVED_CONFIG
        activeConfigFileName = displayName
        persistLastSavedConfigFileName(displayName)
        persistImportedConfigActive(false)
        updateImportUiState()
        if (needsDisconnectFirst) {
            // الواجهة خاصها تبدل مباشرة مع الضغطة، ماشي من بعد ما تسالي مهلة
            // إيقاف الـVPN القديم. كنعتبر Config الجديد في حالة CONNECTING
            // بصرياً فوراً، بينما الخدمة القديمة كتكمّل الإيقاف في الخلفية.
            connecting = true
            connected = false
            reconnectingUi = false
            failedUi = false
            applyConnectButtonState()
            configFragment?.updateActiveVisuals(activeConfigFileName, connected, connecting)

            pendingConfigConnectJob = lifecycleScope.launch {
                delay(400)
                try {
                    // إلا المستخدم ضغط Config آخر، هاد الطلب مايبقاش صالح.
                    if (activeConfigFileName != displayName) return@launch
                    // دابا فقط نطلق الخدمة الجديدة؛ مدة الانتظار ماكتبانش للمستخدم.
                    connecting = false
                    tryConnect()
                } catch (e: Throwable) {
                    connecting = false
                    appendLog("ERROR: ${e.javaClass.simpleName}: ${e.message ?: "Unknown error"}")
                    applyConnectButtonState()
                }
            }
            return
        }
        try {
            if (!connected && !connecting) tryConnect()
        } catch (e: Throwable) {
            appendLog("ERROR: ${e.javaClass.simpleName}: ${e.message ?: "Unknown error"}")
        }
        configFragment?.updateActiveVisuals(activeConfigFileName, connected, connecting)
    }

    /**
     * إلا كان هاد الملف بالضبط هو ديجا activeConfigFileName/SAVED_CONFIG
     * المحمل حاليا (سواء بقا محمل من نفس الجلسة، أو تسترجع من
     * SecureConfigStore/XraySecureConfigStore عند onCreate بعد ما التطبيق
     * تقتل بالكامل وتعاود يتفتح - شوف التعليق فـonCreate) - كنشغلوه
     * مباشرة بنفس الحقول المفكوكة ديجا، بلا ما نحتاجو نعاودو نقرا/نفكو
     * الملف من القرص ولا نطلبو password ثانية. هادشي كيحل الحالة لي كان
     * فيها ConfigFragment.onActionTapped() كيشوف غير فـUnlockedConfigCache
     * (فارغة دايما بعد process kill) وكيتجاهل كليا أن MainActivity ديجا
     * عندها نفس الكونفيغ محمل من التخزين الدائم.
     */
    fun startIfAlreadyLoaded(displayName: String): Boolean {
        if (activeConfigFileName != displayName || configSource != ConfigSource.SAVED_CONFIG) return false
        if (activeImportedConfig == null && activeXrayConfig == null) return false
        updateImportUiState()
        try {
            if (!connected && !connecting) tryConnect()
        } catch (e: Throwable) {
            appendLog("ERROR: ${e.javaClass.simpleName}: ${e.message ?: "Unknown error"}")
        }
        configFragment?.updateActiveVisuals(activeConfigFileName, connected, connecting)
        return true
    }

    /** زر ■ فـCONFIG tab: نفس disconnect() ديال SSH SETTINGS (لي كيمسح activeConfigFileName بحالو - سلوك قديم بلا تغيير) + تحديث لائحة CONFIG. */
    fun disconnectConfigFile() {
        disconnect()
        configFragment?.updateActiveVisuals(null, false, false)
    }

    /**
     * كيتصل بيه ConfigFragment ملي المستخدم يمسح ملف .ml من CONFIG tab.
     * إلا كان هو نفسو الكونفيغ النشط دابا (سواء متصل ولا لا)، كنمسحو
     * بالكامل: نوقفو الاتصال إلا كان خدام، نمسحو الكونفيغ المخفي، ونرجعو
     * SSH SETTINGS لحالة "بلا كونفيغ" - بلا Config imported وبلا ملخص
     * Saved Config. إلا كان ملف آخر (ماشي هو النشط)، ماكنمسوش حتى حاجة
     * هنا. الحذف الفعلي ديال الملف (بالإضافة لأي كلمة سر) كيبقى بلا
     * تغيير - هادي غير مزامنة الحالة فـSSH SETTINGS.
     */
    fun handleConfigFileDeleted(displayName: String) {
        if (activeConfigFileName != displayName) return
        if (connected || connecting) disconnect()
        SecureConfigStore.clear(applicationContext)
        XraySecureConfigStore.clear(applicationContext)
        activeImportedConfig = null
        activeXrayConfig = null
        activeConfigFileName = null
        persistLastSavedConfigFileName(null)
        persistImportedConfigActive(false)
        configSource = ConfigSource.NONE
        updateImportUiState()
        configFragment?.updateActiveVisuals(null, false, false)
    }

    fun isConfigFileActive(displayName: String): Boolean = activeConfigFileName == displayName
    fun activeConfigFileNameOrNull(): String? = activeConfigFileName
    fun isConnectedNow(): Boolean = connected
    fun isConnectingNow(): Boolean = connecting

    /** بلا Toast/ديالوغ "Replace؟" ديال saveImportedConfig/saveXrayConfig - كنمسحو بصمت قبل ما نرجعو لحقول يدوية. */
    private fun clearActiveImportedConfigSilently() {
        if (activeImportedConfig != null || activeXrayConfig != null) {
            SecureConfigStore.clear(applicationContext)
            XraySecureConfigStore.clear(applicationContext)
            activeImportedConfig = null
            activeXrayConfig = null
        }
        configSource = ConfigSource.NONE
    }

    /**
     * كيبني كونفيغ مخفي (ImportedConfig للبروتوكولات ديال SSH، أو
     * ParsedProxyConfig لـXTRA/V2Ray/Shadowsocks) من fields ديال ملف .ml
     * محمي، ويحفظو بنفس الطريقة ديال استيراد كود عادي - الحقول الخام
     * (host/user/pass/...) ماكيتكتبوش لا فـmanual_fields ولا فـEditText.
     * كيرجع false إلا كان الكونفيغ ناقص/غالط.
     */
    private fun applyFieldsAsHiddenImportedConfig(fields: Map<String, Any?>): Boolean {
        val protocol = (fields["protocol"] as? String) ?: DEFAULT_PROTOCOL.label
        return when (protocol) {
            "V2Ray" -> {
                val json = (fields["v2rayJson"] as? String)?.trim().orEmpty()
                try {
                    val cfg = XrayConfigParser.parse(json)
                    storeXrayConfigSilently(cfg)
                    true
                } catch (e: Throwable) {
                    Toast.makeText(this, "Invalid V2Ray/Xray JSON in this config.", Toast.LENGTH_SHORT).show()
                    false
                }
            }
            "XTRA" -> {
                val hostPort = (fields["host"] as? String)?.trim().orEmpty()
                if (!hostPort.contains(":")) {
                    Toast.makeText(this, "Invalid config: missing host:port.", Toast.LENGTH_SHORT).show()
                    return false
                }
                val host = hostPort.substringBeforeLast(":")
                val port = hostPort.substringAfterLast(":").toIntOrNull() ?: 443
                val id = (fields["user"] as? String)?.trim().orEmpty()
                val sni = (fields["sni"] as? String)?.trim().orEmpty()
                val cfg = ParsedProxyConfig(
                    protocol = ParsedProxyConfig.ProxyProtocol.VLESS,
                    remark = "XTRA",
                    address = host,
                    port = port,
                    id = id,
                    encryption = "none",
                    network = "tcp",
                    security = if (sni.isNotBlank()) "tls" else "none",
                    sni = sni
                )
                storeXrayConfigSilently(cfg)
                true
            }
            "Shadowsocks" -> {
                val server = (fields["ssServer"] as? String)?.trim().orEmpty()
                val port = fields["ssPort"]?.toString()?.trim()?.toIntOrNull() ?: 0
                val method = (fields["ssMethod"] as? String)?.trim().orEmpty()
                val password = (fields["ssPassword"] as? String).orEmpty()
                val udp = (fields["ssUdp"] as? Boolean) ?: true
                if (server.isEmpty() || port <= 0 || method.isEmpty() || password.isEmpty()) {
                    Toast.makeText(this, "Invalid config: missing Shadowsocks fields.", Toast.LENGTH_SHORT).show()
                    return false
                }
                val cfg = ParsedProxyConfig(
                    protocol = ParsedProxyConfig.ProxyProtocol.SHADOWSOCKS,
                    remark = "Shadowsocks",
                    address = server,
                    port = port,
                    ssMethod = method,
                    ssPassword = password,
                    ssUdp = udp,
                    network = "tcp",
                    security = "none"
                )
                storeXrayConfigSilently(cfg)
                true
            }
            else -> {
                // SSH-style (SSH-Direct / SSH-TLS / SSH-Payload / ...)
                val hostPort = (fields["host"] as? String)?.trim().orEmpty()
                if (!hostPort.contains(":")) {
                    Toast.makeText(this, "Invalid config: missing host:port.", Toast.LENGTH_SHORT).show()
                    return false
                }
                val host = hostPort.substringBeforeLast(":")
                val port = hostPort.substringAfterLast(":").toIntOrNull() ?: 443
                val proxyText = (fields["proxy"] as? String)?.trim().orEmpty()
                val proxyHost = if (proxyText.contains(":")) proxyText.substringBeforeLast(":") else host
                val proxyPort = if (proxyText.contains(":")) proxyText.substringAfterLast(":").toIntOrNull() ?: port else port
                val cfg = ImportedConfig(
                    host = host,
                    port = port,
                    user = (fields["user"] as? String).orEmpty(),
                    pass = (fields["pass"] as? String).orEmpty(),
                    proxyHost = proxyHost,
                    proxyPort = proxyPort,
                    payload = (fields["payload"] as? String).orEmpty(),
                    usePayload = (fields["usePayload"] as? Boolean) ?: true,
                    useSsl = (fields["useSsl"] as? Boolean) ?: false,
                    sni = (fields["sni"] as? String).orEmpty(),
                    udpgwEnabled = (fields["udpgwEnabled"] as? Boolean) ?: false,
                    udpgwPort = fields["udpgwPort"]?.toString()?.toIntOrNull() ?: 7300
                )
                storeImportedConfigSilently(cfg)
                true
            }
        }
    }

    private fun manualFieldsPrefs() = getSharedPreferences("manual_fields", Context.MODE_PRIVATE)

    // تخزين دائم لهوية Saved Config النشط (اسم الملف فقط) - مستقل عن
    // activeConfigFileName الحالي فالذاكرة، لي كان كيتصفى عند disconnect()
    // القديم ولا عند إعادة تشغيل التطبيق. هادشي كيسمح لينا نفرقو بين
    // "هوية الملف" (دائمة) و"حالة الاتصال" (مؤقتة)، ونرجعو الهوية بعد
    // إعادة فتح التطبيق فـonCreate.
    private fun connectionStatePrefs() = getSharedPreferences("connection_state", Context.MODE_PRIVATE)

    private fun persistLastSavedConfigFileName(name: String?) {
        val editor = connectionStatePrefs().edit()
        if (name == null) editor.remove(KEY_LAST_SAVED_CONFIG_FILE) else editor.putString(KEY_LAST_SAVED_CONFIG_FILE, name)
        editor.apply()
    }

    // نفس المبدأ ديال persistLastSavedConfigFileName لكن لـImported Config:
    // كنسجلو غير "كان هذا الكونفيغ جاي من Import Code" (بلا اسم ملف - ماشي
    // Saved Config). كيتقرا فـonCreate باش يرجع configSource = IMPORTED
    // (Config imported ✓ + REMOVE IMPORTED CONFIG) بدل ما يهبط لـNONE
    // (+ NEW CONFIG) بعد إعادة فتح التطبيق.
    private fun persistImportedConfigActive(active: Boolean) {
        val editor = connectionStatePrefs().edit()
        if (active) editor.putBoolean(KEY_LAST_CONFIG_WAS_IMPORTED, true) else editor.remove(KEY_LAST_CONFIG_WAS_IMPORTED)
        editor.apply()
    }

    private fun restoreManualFields() {
        val f = sshFragment ?: return
        val p = manualFieldsPrefs()
        f.edtHost.setText(p.getString("host", ""))
        f.edtUser.setText(p.getString("user", ""))
        f.edtPass.setText(p.getString("pass", ""))
        f.edtProxy.setText(p.getString("proxy", ""))
        // Always restore Payload, even when the preference key was removed by Clear.
        // Previously this field was only updated when "payload" existed, so Clear
        // could leave the old Payload visible in the UI.
        f.edtPayload.setText(p.getString("payload", ""))
        val opt = PROTOCOL_OPTIONS.find { it.label == p.getString("protocol", DEFAULT_PROTOCOL.label) }
            ?: DEFAULT_PROTOCOL
        f.chkUsePayload.isChecked = p.getBoolean("usePayload", opt.usePayload)
        f.chkUseSsl.isChecked = p.getBoolean("useSsl", opt.useSsl)
        f.edtSni.setText(p.getString("sni", ""))
        f.chkUdpgw.isChecked = p.getBoolean("udpgwEnabled", false)
        f.edtUdpgwPort.setText(p.getString("udpgwPort", "7300"))
        f.edtV2rayJson.setText(p.getString("v2rayJson", ""))
        f.edtSsServer.setText(p.getString("ssServer", ""))
        f.edtSsPort.setText(p.getString("ssPort", ""))
        f.edtSsMethod.setText(p.getString("ssMethod", ""))
        f.edtSsPassword.setText(p.getString("ssPassword", ""))
        f.chkSsUdp.isChecked = p.getBoolean("ssUdp", true)
        applyProtocolFieldVisibility(f, opt)
    }

    /**
     * كتبين/كتخبي غير الحقول اللي عندها علاقة بالبروتوكول المختار:
     * SNI (SSH-TLS.. أو XTRA)، Payload (*-Payload)، Remote Proxy (*-Proxy).
     * Host/User/Pass وUDPGW كيبقاو بانين مع بروتوكولات SSH/XTRA، وكيتخبيو
     * كاملين مع V2Ray/Shadowsocks لي عندهم حقول ديالهم بحالهم (v2raySection/
     * shadowsocksSection).
     */
    private fun applyProtocolFieldVisibility(f: SshFragment, opt: ProtocolOption) {
        f.sshCoreFieldsSection.visibility = if (opt.isV2Ray || opt.isShadowsocks) View.GONE else View.VISIBLE
        f.udpgwSection.visibility = if (opt.isV2Ray || opt.isShadowsocks) View.GONE else View.VISIBLE
        f.sniSection.visibility = if (opt.useSsl && !opt.isV2Ray && !opt.isShadowsocks) View.VISIBLE else View.GONE
        f.payloadSection.visibility = if (opt.usePayload && !opt.isV2Ray && !opt.isShadowsocks) View.VISIBLE else View.GONE
        f.proxySection.visibility = if (opt.useProxy && !opt.isV2Ray && !opt.isShadowsocks) View.VISIBLE else View.GONE
        f.v2raySection.visibility = if (opt.isV2Ray) View.VISIBLE else View.GONE
        f.shadowsocksSection.visibility = if (opt.isShadowsocks) View.VISIBLE else View.GONE
    }

    private fun wireManualFieldPersistence() {
        val f = sshFragment ?: return
        fun watcher(save: (String) -> Unit) = object : android.text.TextWatcher {
            override fun afterTextChanged(s: android.text.Editable?) { save(s?.toString() ?: "") }
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
        }
        f.edtHost.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("host", it).apply() })
        f.edtUser.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("user", it).apply() })
        f.edtPass.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("pass", it).apply() })
        f.edtProxy.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("proxy", it).apply() })
        f.edtPayload.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("payload", it).apply() })
        f.chkUsePayload.setOnCheckedChangeListener { _, checked ->
            manualFieldsPrefs().edit().putBoolean("usePayload", checked).apply()
        }
        f.edtSni.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("sni", it).apply() })
        f.chkUseSsl.setOnCheckedChangeListener { _, checked ->
            manualFieldsPrefs().edit().putBoolean("useSsl", checked).apply()
        }
        f.chkUdpgw.setOnCheckedChangeListener { _, checked ->
            manualFieldsPrefs().edit().putBoolean("udpgwEnabled", checked).apply()
        }
        f.edtUdpgwPort.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("udpgwPort", it).apply() })

        // V2Ray: كيبقى الـJSON محفوظ ومعروض عند رجوع المستخدم لتبويب SSH
        // Settings (بحال Edit) - نفس مبدأ باقي الحقول اليدوية.
        f.edtV2rayJson.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("v2rayJson", it).apply() })

        // Shadowsocks: كل حقل كيتحفظ لوحدو باش يبقى قابل للتعديل عند رجوع
        // المستخدم لنفس البروتوكول.
        f.edtSsServer.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("ssServer", it).apply() })
        f.edtSsPort.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("ssPort", it).apply() })
        f.edtSsMethod.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("ssMethod", it).apply() })
        f.edtSsPassword.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("ssPassword", it).apply() })
        f.chkSsUdp.setOnCheckedChangeListener { _, checked ->
            manualFieldsPrefs().edit().putBoolean("ssUdp", checked).apply()
        }
    }

    /**
     * مختار البروتوكول: كيبان ملي المستخدم كيدوس على "Protocol" فكارد
     * Connection Details. بلا ما نبنيو منطق اتصال جديد - غير كيوجه
     * المستخدم إما للحقول اليدوية ديال SSH (الموجودة ديجا)، أو لنفس
     * dialog الاستيراد (showImportDialog) اللي كيقبل ديجا VLESS/VMess/
     * Trojan/Shadowsocks/Xray JSON كامل (XrayConfigParser.parse كيتعرف
     * عليهم تلقائيا) - بلا أي تعديل فمنطق البارس أو الاتصال.
     */
    private fun showProtocolPicker() {
        val currentProtocol = manualFieldsPrefs().getString("protocol", DEFAULT_PROTOCOL.label)
            ?: DEFAULT_PROTOCOL.label

        // Dialog مخصص (نفس أسلوب dialog_import.xml: Card بحواف مدورة +
        // خلفية نافذة شفافة) بدل AlertDialog.Builder().setAdapter() القديم.
        val view = layoutInflater.inflate(R.layout.dialog_choose_protocol, null)
        val llList = view.findViewById<LinearLayout>(R.id.llProtocolList)
        val btnClose = view.findViewById<View>(R.id.btnProtocolClose)
        val btnCancel = view.findViewById<View>(R.id.btnProtocolCancel)

        val dialog = AlertDialog.Builder(this)
            .setView(view)
            .create()
        dialog.window?.setBackgroundDrawableResource(android.R.color.transparent)
        dialog.setCancelable(true)
        dialog.setCanceledOnTouchOutside(false)

        // كل عنصر فـPROTOCOL_OPTIONS كيولد صف واحد تلقائيا (Dynamic list) -
        // بروتوكول جديد يتزاد فاللائحة فوق كافي باش يبان هنا بلا أي تعديل
        // فهاد الدالة. اختيار الصف (onClick) بقا بالضبط نفس السلوك القديم:
        // switchToManualProtocol().
        PROTOCOL_OPTIONS.forEach { opt ->
            val row = layoutInflater.inflate(R.layout.item_protocol_choice, llList, false)
            val img = row.findViewById<android.widget.ImageView>(R.id.imgProtocolIcon)
            val txtName = row.findViewById<TextView>(R.id.txtProtocolName)
            val txtDesc = row.findViewById<TextView>(R.id.txtProtocolDesc)
            val radio = row.findViewById<android.widget.ImageView>(R.id.imgProtocolRadio)

            val isSelected = opt.label == currentProtocol
            img.setImageResource(opt.iconRes)
            txtName.text = opt.label
            txtDesc.text = opt.description
            radio.setImageResource(if (isSelected) R.drawable.ic_radio_checked else R.drawable.ic_radio_unchecked)
            row.background = androidx.core.content.ContextCompat.getDrawable(
                this, if (isSelected) R.drawable.shape_card_active else R.drawable.shape_card_alt
            )
            row.setOnClickListener {
                dialog.dismiss()
                switchToManualProtocol(opt)
            }
            llList.addView(row)
        }

        btnClose.setOnClickListener { dialog.dismiss() }
        btnCancel.setOnClickListener { dialog.dismiss() }

        dialog.show()
    }

    /** كيرجع لوضع الحقول اليدوية (SSH أو XTRA)، وكيعمر usePayload/useSsl/
     *  useProxy ويبين/يخبي الحقول تلقائيا حسب البروتوكول لي ختار
     *  المستخدم من "Choose Protocol" - بلا ما يحتاج يدوس على أي checkbox
     *  بيدو (الـcheckboxes بقاو خدامين فالكود، غير مخبيين من الواجهة). */
    private fun switchToManualProtocol(opt: ProtocolOption) {
        // إلا كان فيه اتصال/محاولة اتصال جارية (بملف محفوظ ولا Import
        // Code) ملي المستخدم يختار بروتوكول جديد من "Choose Protocol"،
        // خصنا نقطعوه أولا - قبل هاد الفيكس، الـtunnel كان يبقى خدام
        // فعليا بالسيرفر القديم بينما الواجهة كتبدل لحقول يدوية فارغة
        // (تناقض: SSH SETTINGS تبان "Disconnected"/فارغة، والاتصال
        // الحقيقي مازال شغال فالخلفية بكونفيغ آخر).
        if (connected || connecting) disconnect()

        if (activeImportedConfig != null || activeXrayConfig != null) {
            SecureConfigStore.clear(applicationContext)
            activeImportedConfig = null
            XraySecureConfigStore.clear(applicationContext)
            activeXrayConfig = null
        }
        configSource = ConfigSource.NONE
        activeConfigFileName = null
        persistLastSavedConfigFileName(null)
        persistImportedConfigActive(false)
        editingConfigOriginalName = null
        editingConfigOwnerVerified = false
        configFragment?.updateActiveVisuals(null, connected, connecting)
        val f = sshFragment
        if (f != null) {
            f.chkUsePayload.isChecked = opt.usePayload
            f.chkUseSsl.isChecked = opt.useSsl
            manualFieldsPrefs().edit()
                .putString("protocol", opt.label)
                .putBoolean("usePayload", opt.usePayload)
                .putBoolean("useSsl", opt.useSsl)
                .putBoolean("useProxy", opt.useProxy)
                .apply()
            applyProtocolFieldVisibility(f, opt)
        }
        updateImportUiState()
        updateConnectionSummary()
    }

    private fun showImportDialog() {
        // نفس المنطق بالضبط (handleImportCode على نص الحقل) - غير الشكل
        // البصري تبدل من AlertDialog القياسي لـ layout مخصص عصري
        // (dialog_import.xml) بزوايا مدورة وأزرار CANCEL / IMPORT.
        val view = layoutInflater.inflate(R.layout.dialog_import, null)
        val input = view.findViewById<EditText>(R.id.edtImportCode)
        val btnCancel = view.findViewById<View>(R.id.btnImportCancel)
        val btnConfirm = view.findViewById<View>(R.id.btnImportConfirm)

        val dialog = AlertDialog.Builder(this)
            .setView(view)
            .setCancelable(true)
            .create()
        dialog.window?.setBackgroundDrawableResource(android.R.color.transparent)

        // The field above already has a fixed height, but we still tell the
        // dialog window to RESIZE (not just pan) when the keyboard shows, so
        // the whole dialog shrinks to fit above it and Import/Cancel are
        // never hidden underneath.
        dialog.window?.setSoftInputMode(android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        dialog.setCanceledOnTouchOutside(false)

        btnCancel.setOnClickListener { dialog.dismiss() }
        btnConfirm.setOnClickListener {
            handleImportCode(input.text.toString())
            dialog.dismiss()
        }

        dialog.show()
    }

    private fun handleImportCode(rawCode: String) {
        val code = rawCode.trim()
        if (code.isEmpty()) {
            Toast.makeText(this, "Please paste the import code first", Toast.LENGTH_SHORT).show()
            return
        }

        // ===== V2Ray/Xray link - مسار مستقل كامل عن MRVPN تحت =====
        val lower = code.lowercase()
        val looksLikeXray = lower.startsWith("vless://") || lower.startsWith("vmess://") ||
            lower.startsWith("trojan://") || lower.startsWith("ss://") || code.trimStart().startsWith("{")
        if (looksLikeXray) {
            appendLog("Import Code Detected.")
            appendLog("Parsing Config...")
            val parsed = try {
                XrayConfigParser.parse(code)
            } catch (e: IllegalArgumentException) {
                appendLog("ERROR: Invalid Configuration.")
                showInvalidCodeDialog(e.message ?: "Import file or code is invalid or has been modified.")
                return
            } catch (e: Throwable) {
                appendLog("ERROR: Invalid Configuration.")
                showInvalidCodeDialog("Import file or code is invalid or has been modified.")
                return
            }

            if (SecureConfigStore.hasConfig(applicationContext) || XraySecureConfigStore.hasConfig(applicationContext)) {
                AlertDialog.Builder(this)
                    .setTitle("Replace current config?")
                    .setMessage("A config is already saved in the app. Only one config is allowed — importing a new one will permanently delete the old one and replace it with this new one.")
                    .setPositiveButton("Replace") { _, _ -> saveXrayConfig(parsed) }
                    .setNegativeButton("Cancel", null)
                    .show()
            } else {
                saveXrayConfig(parsed)
            }
            return
        }
        // ===== نهاية V2Ray/Xray - كود MRVPN الأصلي كيبدا هنا بلا تبديل =====

        appendLog("Import Code Detected.")
        appendLog("Decrypting Configuration...")

        val parsed: ImportedConfig
        try {
            parsed = ImportCrypto.verifyAndDecrypt(code)
        } catch (e: InvalidImportCodeException) {
            appendLog("ERROR: Invalid Configuration.")
            showInvalidCodeDialog()
            return
        } catch (e: Throwable) {
            appendLog("ERROR: Invalid Configuration.")
            showInvalidCodeDialog()
            return
        }

        if (SecureConfigStore.hasConfig(applicationContext) || XraySecureConfigStore.hasConfig(applicationContext)) {
            AlertDialog.Builder(this)
                .setTitle("Replace current config?")
                .setMessage("A config is already saved in the app. Only one config is allowed — importing a new code will permanently delete the old one and replace it with this new one.")
                .setPositiveButton("Replace") { _, _ -> saveImportedConfig(parsed) }
                .setNegativeButton("Cancel", null)
                .show()
        } else {
            saveImportedConfig(parsed)
        }
    }

    /** تخزين بلا أي Toast/log/UI - كتستعمل غير من applyFieldsAsHiddenImportedConfig (مسار Saved Config)، ماشي من Import Code. */
    private fun storeXrayConfigSilently(cfg: ParsedProxyConfig) {
        SecureConfigStore.clear(applicationContext)
        activeImportedConfig = null
        XraySecureConfigStore.save(applicationContext, cfg)
        activeXrayConfig = cfg
    }

    /** تخزين بلا أي Toast/log/UI - كتستعمل غير من applyFieldsAsHiddenImportedConfig (مسار Saved Config)، ماشي من Import Code. */
    private fun storeImportedConfigSilently(cfg: ImportedConfig) {
        XraySecureConfigStore.clear(applicationContext)
        activeXrayConfig = null
        SecureConfigStore.save(applicationContext, cfg)
        activeImportedConfig = cfg
    }

    private fun saveXrayConfig(cfg: ParsedProxyConfig) {
        // FIX (مشكلة 1): Import Code كان كيبدل الكونفيغ المخزن (Xray/SSH)
        // بلا ما يوقف الاتصال/التunnel القديم لي كان مازال خدام فعليا فـ
        // SshVpnService (:vpnproc) - نفس الطريقة لي كتستعملها
        // connectConfigFile() فوق: نبطلو serviceRequestId القديم قبل ما
        // نطلبو disconnect، باش أي broadcast قديم (READY/RECONNECTING...)
        // مايقدرش يرجع يفعّل الاتصال القديم من بعد ما تبدل المصدر (race
        // condition). disconnect() كتبدل connected/connecting لـfalse
        // مباشرة وبشكل متزامن (sync)، فالكود لي تحت كيقرا القيمة الصحيحة.
        // بعد الحفظ، الاتصال كيبقى Disconnected - المستخدم خاصو يدوس
        // START من جديد باش يشغل الـImport الجديد فقط.
        if (connected || connecting) {
            val oldServiceRequestId = serviceRequestId
            serviceRequestId = System.nanoTime()
            pendingServiceRequestId = null
            pendingConfigConnectJob?.cancel()
            pendingConfigConnectJob = null
            disconnect(oldServiceRequestId)
        }

        // كونفيغ واحد فقط مسموح - إلا كان SSH config محفوظ نمحيوه (نفس
        // القاعدة "config واحد" ديال SecureConfigStore القديمة).
        configSource = ConfigSource.IMPORTED
        // Import Code ماشي Saved Config: خاصنا نمسحو اسم الملف القديم
        // من الذاكرة حتى CONFIG tab مايبقاش يبين ملف .zrr قديم على أنه نشط.
        activeConfigFileName = null
        persistLastSavedConfigFileName(null)
        persistImportedConfigActive(true)
        configFragment?.updateActiveVisuals(null, connected, connecting)
        SecureConfigStore.clear(applicationContext)
        activeImportedConfig = null

        XraySecureConfigStore.save(applicationContext, cfg)
        activeXrayConfig = cfg
        updateImportUiState()
        appendLog("Configuration Loaded Successfully.")
        Toast.makeText(this, "Config imported successfully \u2705", Toast.LENGTH_SHORT).show()
    }

    private fun saveImportedConfig(cfg: ImportedConfig) {
        // FIX (مشكلة 1): نفس التصحيح ديال saveXrayConfig فوق - شوف
        // التعليق هناك للتفاصيل الكاملة.
        if (connected || connecting) {
            val oldServiceRequestId = serviceRequestId
            serviceRequestId = System.nanoTime()
            pendingServiceRequestId = null
            pendingConfigConnectJob?.cancel()
            pendingConfigConnectJob = null
            disconnect(oldServiceRequestId)
        }

        configSource = ConfigSource.IMPORTED
        // Import Code ماشي Saved Config: خاصنا نمسحو اسم الملف القديم
        // من الذاكرة حتى CONFIG tab مايبقاش يبين ملف .zrr قديم على أنه نشط.
        activeConfigFileName = null
        persistLastSavedConfigFileName(null)
        persistImportedConfigActive(true)
        configFragment?.updateActiveVisuals(null, connected, connecting)
        XraySecureConfigStore.clear(applicationContext)
        activeXrayConfig = null

        SecureConfigStore.save(applicationContext, cfg)
        activeImportedConfig = cfg
        updateImportUiState()
        appendLog("Configuration Loaded Successfully.")
        Toast.makeText(this, "Config imported successfully \u2705", Toast.LENGTH_SHORT).show()
    }

    private fun confirmRemoveImportedConfig() {
        AlertDialog.Builder(this)
            .setTitle("Remove imported config?")
            .setMessage("You'll be able to enter server details manually again.")
            .setPositiveButton("Remove") { _, _ ->
                SecureConfigStore.clear(applicationContext)
                activeImportedConfig = null
                XraySecureConfigStore.clear(applicationContext)
                activeXrayConfig = null
                configSource = ConfigSource.NONE
                activeConfigFileName = null
                persistLastSavedConfigFileName(null)
                persistImportedConfigActive(false)
                editingConfigOriginalName = null
                editingConfigOwnerVerified = false
                configFragment?.updateActiveVisuals(null, connected, connecting)
                updateImportUiState()
                Toast.makeText(this, "Imported config removed", Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton("Cancel", null)
            .show()
    }

    private fun showInvalidCodeDialog(message: String = "Import file or code is invalid or has been modified.") {
        AlertDialog.Builder(this)
            .setTitle("Error")
            .setMessage(message)
            .setPositiveButton("OK", null)
            .show()
    }

    private fun updateImportUiState() {
        val f = sshFragment ?: return
        when (configSource) {
            ConfigSource.IMPORTED -> {
                val ssh = activeImportedConfig
                val xray = activeXrayConfig
                f.importedStatusContainer.visibility = View.VISIBLE
                f.txtImportedStatus.text = xray?.summary() ?: ssh?.maskedSummary() ?: ""
                f.manualFieldsContainer.visibility = View.GONE
                // + NEW CONFIG كيخبى ما دام Imported Config هو المستعمل
                // حاليا - نفس المنطق ديال SAVED_CONFIG تحت. الطريق باش
                // يخرج منها هو REMOVE IMPORTED CONFIG، ماشي + NEW CONFIG.
                f.btnNewConfig.visibility = View.GONE
            }
            ConfigSource.SAVED_CONFIG -> {
                // بلا بطاقة "USING SAVED CONFIG" منفصلة - اسم الملف كيبان
                // دابا كسطر "File" جوا كارد Connection Details نفسها
                // (شوف updateConnectionSummary()). + NEW CONFIG كيخبى ما
                // دام Config محفوظة هي المستعملة حاليا.
                f.importedStatusContainer.visibility = View.GONE
                f.manualFieldsContainer.visibility = View.GONE
                f.btnNewConfig.visibility = View.GONE
            }
            ConfigSource.NONE -> {
                f.importedStatusContainer.visibility = View.GONE
                f.manualFieldsContainer.visibility = View.VISIBLE
                f.btnNewConfig.visibility = View.VISIBLE
            }
        }
        // تحديث فوري لـ Card ديال Server/Protocol/Port/File بعد أي تغيير فـ
        // الكونفيغ المستورد (عرض فقط - نفس الأعلام لي كايستعملهم
        // applyConnectButtonState() بلا ما نمس منطق الاستيراد فوق).
        updateConnectionSummary()
    }

    private fun startLogPolling() {
        lifecycleScope.launch {
            while (isActive) {
                refreshLogIfChanged()
                // Same "don't rely on broadcasts alone" reasoning as the log
                // polling above: some devices delay/drop background
                // broadcasts, which previously meant a RECONNECTING status
                // that arrived via broadcast could be silently missed, and
                // the button would stay stuck on "DISCONNECT" until the user
                // left and returned to the app. Polling the persisted state
                // on the same 400ms cadence, while the app is actually
                // visible, closes that gap.
                syncStateFromService()
                // Same reasoning again for the update prompt: UpdateManager
                // saves its result to disk from the (separate-process)
                // SshVpnService the moment it detects a newer version, but
                // showUpdateDialogIfNeeded() previously only ran in
                // onCreate/onStart - so if the user stayed on this screen
                // through the whole "connect -> STATE_READY -> background
                // update check finishes" sequence without ever leaving and
                // returning to the app, the dialog would silently never
                // appear during that session. Polling it here means it
                // shows up within ~400ms of the check actually finishing.
                showUpdateDialogIfNeeded()
                delay(400)
            }
        }
    }

    private suspend fun refreshLogIfChanged() {
        val content = withContext(Dispatchers.IO) { LogManager.readRaw(applicationContext) }
        if (content != lastLogContent) {
            val newlyAdded = if (content.startsWith(lastLogContent)) content.removePrefix(lastLogContent) else content
            lastLogContent = content
            logFragment?.let { lf ->
                lf.txtLog.text = LogManager.formatForUi(content)
                lf.logScroll.post { lf.logScroll.fullScroll(View.FOCUS_DOWN) }
            }

            // احتياط: بحال ماوصلش بث الحالة (STATE_READY) لأي سبب (بعض
            // الأجهزة كتقيد الـ broadcasts فالخلفية)، كنبقاو كنراقبو نص
            // اللوگ ديال "Connection Established." باش الزر يتبدل لـ
            // DISCONNECT فكل الحالات، ماشي غير عبر statusReceiver.
            if ((connecting || reconnectingUi) && newlyAdded.contains("Connection Established.")) {
                connecting = false
                connected = true
                reconnectingUi = false
                applyConnectButtonState()
            }
        }
    }

    private fun applyConnectButtonState() {
        configFragment?.updateActiveVisuals(activeConfigFileName, connected, connecting)
        val f = sshFragment ?: return
        f.btnConnect.isEnabled = true
        // الزر دائري وفيه نص START/STOP (بدل الأيقونة القديمة) - بطلب
        // المستخدم. CONNECTING/RECONNECTING كيبقاو نص مؤقت وسط الزر
        // بحالو، بلا ما يمس منطق الضغط عليه.
        val buttonText = when {
            connecting -> "..."
            reconnectingUi -> "..."
            connected -> "STOP"
            else -> "START"
        }
        f.btnConnect.text = buttonText
        f.btnConnect.contentDescription = when {
            connecting -> "Connecting"
            reconnectingUi -> "Reconnecting"
            connected -> "Disconnect"
            else -> "Connect"
        }

        // ===== واجهة جديدة فقط (Status ديال الكارد فقط - الاسم/الدائرة =====
        // اللي كانو تحت الزر تحيدو، Status دابا كاين غير هنا). بلا أي
        // تأثير على منطق الاتصال أعلاه.
        val statusLabel = when {
            connecting -> "CONNECTING..."
            reconnectingUi -> "RECONNECTING..."
            connected -> "CONNECTED"
            failedUi -> "CONNECTION FAILED"
            else -> "DISCONNECTED"
        }
        val statusColorRes = when {
            connecting || reconnectingUi -> R.color.state_connecting
            connected -> R.color.state_success
            failedUi -> R.color.state_error
            else -> R.color.state_idle
        }
        val statusColor = androidx.core.content.ContextCompat.getColor(this, statusColorRes)
        f.txtStatusCardValue.text = statusLabel.lowercase()
            .replaceFirstChar { it.uppercase() }
        f.txtStatusCardValue.setTextColor(statusColor)

        updateConnectButtonVisual(statusColorRes)
        updateConnectionSummary()
    }

    /**
     * كيلون الزر الدائري حسب الحالة، وكيتحكم فـ pulse ring حوليه:
     * - Connecting/Reconnecting: لون برتقالي + نبض خفيف (animator وحيد،
     *   ماكيتبداش من جديد إلا كانت الحالة السابقة ماشي نفسها).
     * - Connected: أخضر، بلا نبض مستمر (fade-in وحيد وقت الدخول للحالة).
     * - Failed: أحمر، بلا animation.
     * - Disconnected: رمادي.
     */
    private fun updateConnectButtonVisual(statusColorRes: Int) {
        val f = sshFragment ?: return
        val button = f.btnConnect as? MaterialButton ?: return
        val ring = f.viewConnectPulseRing

        val visualState = when {
            connecting -> "CONNECTING"
            reconnectingUi -> "RECONNECTING"
            connected -> "CONNECTED"
            failedUi -> "FAILED"
            else -> "IDLE"
        }
        if (visualState == lastButtonVisualState) return
        lastButtonVisualState = visualState

        val color = androidx.core.content.ContextCompat.getColor(this, statusColorRes)
        button.backgroundTintList = ColorStateList.valueOf(color)

        val isPulsing = visualState == "CONNECTING" || visualState == "RECONNECTING"
        if (isPulsing) {
            ring.backgroundTintList = ColorStateList.valueOf(color)
            ring.visibility = View.VISIBLE
            if (pulseAnimator == null) {
                pulseAnimator = ValueAnimator.ofFloat(0.55f, 1f, 0.55f).apply {
                    duration = 1400
                    repeatCount = ValueAnimator.INFINITE
                    interpolator = LinearInterpolator()
                    addUpdateListener { anim ->
                        val v = anim.animatedValue as Float
                        ring.alpha = v
                        val scale = 0.9f + (1f - v) * 0.25f
                        ring.scaleX = scale
                        ring.scaleY = scale
                    }
                    start()
                }
            }
        } else {
            pulseAnimator?.cancel()
            pulseAnimator = null
            ring.visibility = View.INVISIBLE
            ring.alpha = 1f
            ring.scaleX = 1f
            ring.scaleY = 1f

            if (visualState == "CONNECTED") {
                // نبضة واحدة خفيفة وقت الوصول لـCONNECTED فقط - ماشي متكررة.
                button.animate().cancel()
                button.scaleX = 0.9f
                button.scaleY = 0.9f
                button.animate().scaleX(1f).scaleY(1f).setDuration(220).start()
            }
        }
    }

    /**
     * كيحدث Card ديال "Connection Details" (Server/Protocol/Port) - عرض
     * فقط، بلا أي قراءة/كتابة جديدة لأي حاجة كتأثر على الاتصال الفعلي.
     * كيتقرا نفس المصادر لي كايستعملهم startVpnService() ديجا
     * (activeXrayConfig / activeImportedConfig / حقول SSH اليدوية).
     */
    private fun updateConnectionSummary() {
        val f = sshFragment ?: return
        val xray = activeXrayConfig
        val ssh = activeImportedConfig

        val server: String
        val protocol: String
        val port: String

        when {
            xray != null -> {
                server = maskForDisplay(xray.address)
                protocol = xray.protocol.name + if (xray.security != "none") " • ${xray.security.uppercase()}" else ""
                port = if (xray.port > 0) xray.port.toString() else "—"
            }
            ssh != null -> {
                server = maskForDisplay(ssh.host)
                protocol = ssh.protocolLabel()
                port = ssh.port.toString()
            }
            else -> {
                // البروتوكول كيتقرا مباشرة من الاختيار المخزن (Choose Protocol)
                // بدل ما يتبنى من محتوى الحقول - كيضمن توافق تام بين الكارد
                // وبين الحقول المبينة فعليا فالواجهة.
                val manualProtocol = manualFieldsPrefs().getString("protocol", DEFAULT_PROTOCOL.label)
                    ?: DEFAULT_PROTOCOL.label
                protocol = manualProtocol

                when (manualProtocol) {
                    "V2Ray" -> {
                        // كنحاولو نستخرجو address:port غير للعرض من الـJSON
                        // المدخل - بلا ما يأثر على أي حاجة أخرى، وبلا ما
                        // نوقفو الواجهة إذا كان الـJSON ماشي كامل بازال.
                        val json = f.edtV2rayJson.text?.toString()?.trim().orEmpty()
                        val parsed = if (json.isNotEmpty()) {
                            try { XrayConfigParser.parse(json) } catch (_: Throwable) { null }
                        } else null
                        server = if (parsed != null && parsed.address.isNotBlank()) maskForDisplay(parsed.address) else "—"
                        port = if (parsed != null && parsed.port > 0) parsed.port.toString() else "—"
                    }
                    "Shadowsocks" -> {
                        val host = f.edtSsServer.text?.toString()?.trim().orEmpty()
                        server = if (host.isBlank()) "—" else maskForDisplay(host)
                        port = f.edtSsPort.text?.toString()?.trim()?.ifBlank { "—" } ?: "—"
                    }
                    else -> {
                        val hostPort = f.edtHost.text?.toString()?.trim().orEmpty()
                        val host = if (hostPort.contains(":")) hostPort.substringBeforeLast(":") else hostPort
                        port = if (hostPort.contains(":")) hostPort.substringAfterLast(":") else "—"
                        server = if (host.isBlank()) "—" else maskForDisplay(host)
                    }
                }
            }
        }

        f.txtServerValue.text = server
        f.txtProtocolValue.text = protocol
        f.txtPortValue.text = port

        // File: كيبان غير ملي Config محفوظة هي المستعملة حاليا (configSource
        // == SAVED_CONFIG)، بلا علاقة بحالة الاتصال (Connected/Disconnected).
        // ما دام ماشي Saved Config (Import Code أو حقول يدوية)، السطر كيخبى
        // بالكامل. اسم الملف كيتزامن مباشرة مع activeConfigFileName الحالي.
        if (configSource == ConfigSource.SAVED_CONFIG && activeConfigFileName != null) {
            f.dividerFile.visibility = View.VISIBLE
            f.rowFile.visibility = View.VISIBLE
            f.txtFileValue.text = activeConfigFileName!!.removeSuffix(".${MlConfigFile.EXTENSION}")
        } else {
            f.dividerFile.visibility = View.GONE
            f.rowFile.visibility = View.GONE
        }
    }

    /** كيخبي جزء من عنوان السيرفر فالعرض فقط (مثلا za**********) - بلا
     *  ما يمس القيمة الحقيقية المخزنة أو المستعملة فالاتصال. */
    private fun maskForDisplay(host: String): String {
        if (host.isBlank()) return "—"
        if (host.length <= 4) return "****"
        return host.take(2) + "*".repeat((host.length - 2).coerceAtMost(10))
    }

    private fun appendStartupDiag(text: String) {
        try {
            val f = File(applicationContext.filesDir, "vpn_startup_diag.txt")
            f.appendText("$text\n")
        } catch (_: Throwable) { }
    }

    private fun shareLog() {
        try {
            // Fresh read, not the polling-cached lastLogContent: that cache
            // updates on a 400ms cadence, so tapping Share Log right after
            // Disconnect could previously export a snapshot that was
            // missing the very last lines (e.g. the final Ping or
            // Disconnected. itself) - exactly the "some messages don't
            // appear in export" symptom. Reading fresh here closes that gap
            // entirely, and running it through the SAME filter as the UI
            // (formatForExport = formatForUi's twin, see LogManager) means
            // the exported file always matches Connection Log line for line.
            val rawNow = LogManager.readRaw(applicationContext)
            val sessionLog = LogManager.formatForExport(rawNow)

            val fullLog = buildString {
                append(sessionLog)
                // Native crash diagnostics only if a REAL crash was recorded
                // THIS launch (see hadRealNativeCrashThisLaunch) - not the
                // routine "crash guard OK" install confirmation, which used
                // to get glued onto every single export regardless of
                // whether anything ever crashed.
                if (hadRealNativeCrashThisLaunch) {
                    val diagFile = File(applicationContext.filesDir, "vpn_startup_diag.txt")
                    val diag = if (diagFile.exists()) diagFile.readText() else ""
                    if (diag.isNotBlank()) {
                        append("\n\n--- Native Crash Diagnostics ---\n")
                        append(diag)
                    }
                }
            }
            val file = File(cacheDir, "vpn_log_share.txt")
            file.writeText(fullLog)

            val uri = FileProvider.getUriForFile(
                this, "$packageName.fileprovider", file
            )
            val intent = Intent(Intent.ACTION_SEND).apply {
                type = "text/plain"
                putExtra(Intent.EXTRA_STREAM, uri)
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            }
            startActivity(Intent.createChooser(intent, "Share Log"))
        } catch (e: Throwable) {
            appendLog("ERROR: Unable to Share Log.")
        }
    }

    private fun tryConnect() {
        logFragment?.txtLog?.text = ""
        LogManager.clear(applicationContext)
        lastLogContent = ""

        if (activeImportedConfig == null && activeXrayConfig == null) {
            val manualProtocol = manualFieldsPrefs().getString("protocol", DEFAULT_PROTOCOL.label)
                ?: DEFAULT_PROTOCOL.label
            when (manualProtocol) {
                "V2Ray" -> {
                    val json = sshFragment?.edtV2rayJson?.text?.toString()?.trim() ?: ""
                    if (json.isEmpty()) {
                        appendLog("ERROR: Invalid Configuration.")
                        showInvalidCodeDialog("Please paste a V2Ray/Xray JSON config first.")
                        return
                    }
                    // التحقق من صحة JSON قبل أي محاولة اتصال (قبل حتى طلب
                    // إذن VPN) - نفس منطق XrayConfigParser.parse لي كيتستعمل
                    // فمسار Import.
                    try {
                        XrayConfigParser.parse(json)
                    } catch (e: Throwable) {
                        appendLog("ERROR: ${e.javaClass.simpleName}: ${e.message ?: "Unknown error"}")
                        android.util.Log.e("MainActivity", "Connection error", e)
                        showInvalidCodeDialog(e.message ?: "Invalid V2Ray/Xray JSON config.")
                        return
                    }
                }
                "Shadowsocks" -> {
                    val f = sshFragment
                    val server = f?.edtSsServer?.text?.toString()?.trim() ?: ""
                    val port = f?.edtSsPort?.text?.toString()?.trim()?.toIntOrNull()
                    val method = f?.edtSsMethod?.text?.toString()?.trim() ?: ""
                    val password = f?.edtSsPassword?.text?.toString() ?: ""
                    if (server.isEmpty() || port == null || port <= 0 || method.isEmpty() || password.isEmpty()) {
                        appendLog("ERROR: Invalid Configuration.")
                        showInvalidCodeDialog("Please fill Server, Port, Method and Password.")
                        return
                    }
                }
                else -> {
                    val hostPort = sshFragment?.edtHost?.text?.toString()?.trim() ?: ""
                    if (!hostPort.contains(":")) {
                        appendLog("ERROR: Invalid Configuration.")
                        return
                    }
                }
            }
        }

        try {
            val prepareIntent = VpnService.prepare(this)
            if (prepareIntent != null) {
                vpnPrepareLauncher.launch(prepareIntent)
            } else {
                startVpnService()
            }
        } catch (e: Throwable) {
            appendLog("ERROR: ${e.javaClass.simpleName}: ${e.message ?: "Unknown error"}")
            android.util.Log.e("MainActivity", "Connection error", e)
        }
    }

    private fun startVpnService() {
        try {
            val requestId = pendingServiceRequestId ?: System.nanoTime()
            serviceRequestId = requestId
            pendingServiceRequestId = null
            val xray = activeXrayConfig
            val imported = activeImportedConfig
            val f = sshFragment

            val intent = Intent(this, SshVpnService::class.java).apply {
                putExtra(SshVpnService.EXTRA_REQUEST_ID, requestId)
            }

            // ===== V2Ray/Xray - مسار مستقل كامل، بلا مساس بـSSH تحت =====
            if (xray != null) {
                intent.putExtra(SshVpnService.EXTRA_MODE, SshVpnService.MODE_XRAY)
                intent.putExtra(SshVpnService.EXTRA_XRAY_CONFIG, xray.toJson())

                StateStore.write(applicationContext, SshVpnService.STATE_CONNECTING, requestId)
                startService(intent)
                connecting = true
                connected = false
                reconnectingUi = false
                failedUi = false
                applyConnectButtonState()
                // "Starting Service..." كيتسجل من SshVpnService نفسها
                // (onStartCommand) - ماكنسجلوهش هنا زيادة باش مايتكررش
                // نفس السطر جوج مرات فـ log واحد.
                return
            }
            // ===== نهاية V2Ray/Xray - كود SSH الأصلي كيبدا هنا بلا تبديل =====

            val manualProtocol = manualFieldsPrefs().getString("protocol", DEFAULT_PROTOCOL.label)
                ?: DEFAULT_PROTOCOL.label

            if (imported != null) {
                intent.putExtra("host", imported.host)
                intent.putExtra("port", imported.port)
                intent.putExtra("user", imported.user)
                intent.putExtra("pass", imported.pass)
                intent.putExtra("proxyHost", imported.proxyHost)
                intent.putExtra("proxyPort", imported.proxyPort)
                intent.putExtra("payload", imported.payload)
                intent.putExtra("usePayload", imported.usePayload)
                intent.putExtra("useSsl", imported.useSsl)
                intent.putExtra("sni", imported.sni)
                intent.putExtra("udpgwEnabled", imported.udpgwEnabled)
                intent.putExtra("udpgwPort", imported.udpgwPort)
                intent.putExtra("maskLogs", true)
            } else if (manualProtocol == "XTRA") {
                // ===== XTRA - VLESS يدوي مبني مباشرة من نفس حقول SSH-TLS =====
                // (Host:Port, Username->UUID, SNI). TLS كيتفعل تلقائيا إلا
                // تعمرت SNI. بلا Import، بلا مساس بمسار SSH تحت.
                val hostPort = f?.edtHost?.text?.toString()?.trim() ?: ""
                val host = hostPort.substringBeforeLast(":")
                val port = hostPort.substringAfterLast(":").toIntOrNull() ?: 443
                val id = f?.edtUser?.text?.toString()?.trim() ?: ""
                val sni = f?.edtSni?.text?.toString()?.trim() ?: ""

                val cfg = ParsedProxyConfig(
                    protocol = ParsedProxyConfig.ProxyProtocol.VLESS,
                    remark = "XTRA",
                    address = host,
                    port = port,
                    id = id,
                    encryption = "none",
                    network = "tcp",
                    security = if (sni.isNotBlank()) "tls" else "none",
                    sni = sni
                )

                intent.putExtra(SshVpnService.EXTRA_MODE, SshVpnService.MODE_XRAY)
                intent.putExtra(SshVpnService.EXTRA_XRAY_CONFIG, cfg.toJson())

                StateStore.write(applicationContext, SshVpnService.STATE_CONNECTING, requestId)
                startService(intent)
                connecting = true
                connected = false
                reconnectingUi = false
                failedUi = false
                applyConnectButtonState()
                return
            } else if (manualProtocol == "V2Ray") {
                // ===== V2Ray - JSON كامل مدخل يدويا، بلا Import =====
                // الصحة اتفحصت ديجا فـtryConnect() قبل طلب إذن VPN. هنا
                // كنبنيو ParsedProxyConfig (rawOutboundJson) بنفس الآلية
                // اللي كيستعملها مسار Import ديال Xray JSON، ونديرو
                // MODE_XRAY - بلا Mock، Xray الحقيقي (XrayCoreManager) هو
                // اللي غادي يخدم الكونفيغ.
                val json = f?.edtV2rayJson?.text?.toString()?.trim() ?: ""
                val cfg = try {
                    XrayConfigParser.parse(json)
                } catch (e: Throwable) {
                    appendLog("ERROR: ${e.javaClass.simpleName}: ${e.message ?: "Unknown error"}")
                    android.util.Log.e("MainActivity", "Connection error", e)
                    return
                }

                intent.putExtra(SshVpnService.EXTRA_MODE, SshVpnService.MODE_XRAY)
                intent.putExtra(SshVpnService.EXTRA_XRAY_CONFIG, cfg.toJson())

                StateStore.write(applicationContext, SshVpnService.STATE_CONNECTING, requestId)
                startService(intent)
                connecting = true
                connected = false
                reconnectingUi = false
                failedUi = false
                applyConnectButtonState()
                return
            } else if (manualProtocol == "Shadowsocks") {
                // ===== Shadowsocks - حقول يدوية مباشرة، بلا Import =====
                val server = f?.edtSsServer?.text?.toString()?.trim() ?: ""
                val port = f?.edtSsPort?.text?.toString()?.trim()?.toIntOrNull() ?: 0
                val method = f?.edtSsMethod?.text?.toString()?.trim() ?: ""
                val password = f?.edtSsPassword?.text?.toString() ?: ""
                val udp = f?.chkSsUdp?.isChecked ?: true

                val cfg = ParsedProxyConfig(
                    protocol = ParsedProxyConfig.ProxyProtocol.SHADOWSOCKS,
                    remark = "Shadowsocks",
                    address = server,
                    port = port,
                    ssMethod = method,
                    ssPassword = password,
                    ssUdp = udp,
                    network = "tcp",
                    security = "none"
                )

                intent.putExtra(SshVpnService.EXTRA_MODE, SshVpnService.MODE_XRAY)
                intent.putExtra(SshVpnService.EXTRA_XRAY_CONFIG, cfg.toJson())

                StateStore.write(applicationContext, SshVpnService.STATE_CONNECTING, requestId)
                startService(intent)
                connecting = true
                connected = false
                reconnectingUi = false
                failedUi = false
                applyConnectButtonState()
                return
            } else {
                val hostPort = f?.edtHost?.text?.toString()?.trim() ?: ""
                val host = hostPort.substringBeforeLast(":")
                val port = hostPort.substringAfterLast(":").toIntOrNull() ?: 443
                // useProxy كيتقرا من الاختيار المخزن ديال Choose Protocol -
                // ماشي بالتخمين من محتوى الحقل، حيت الحقل يمكن يبقى فيه
                // نص قديم مخبي (SSH-Direct/Payload/TLS) وماخصوش يتقرا.
                val useProxy = manualFieldsPrefs().getBoolean("useProxy", false)
                val proxyText = f?.edtProxy?.text?.toString()?.trim() ?: ""
                val proxyHost = if (useProxy && proxyText.contains(":")) {
                    proxyText.substringBeforeLast(":")
                } else host
                val proxyPort = if (useProxy && proxyText.contains(":")) {
                    proxyText.substringAfterLast(":").toIntOrNull() ?: port
                } else port

                intent.putExtra("host", host)
                intent.putExtra("port", port)
                intent.putExtra("user", f?.edtUser?.text?.toString() ?: "")
                intent.putExtra("pass", f?.edtPass?.text?.toString() ?: "")
                intent.putExtra("proxyHost", proxyHost)
                intent.putExtra("proxyPort", proxyPort)
                intent.putExtra("payload", f?.edtPayload?.text?.toString() ?: "")
                intent.putExtra("usePayload", f?.chkUsePayload?.isChecked ?: true)
                intent.putExtra("useSsl", f?.chkUseSsl?.isChecked ?: false)
                intent.putExtra("sni", f?.edtSni?.text?.toString()?.trim() ?: "")
                intent.putExtra("udpgwEnabled", f?.chkUdpgw?.isChecked ?: false)
                intent.putExtra("udpgwPort", f?.edtUdpgwPort?.text?.toString()?.trim()?.toIntOrNull() ?: 7300)
                intent.putExtra("maskLogs", false)
            }

            // Write CONNECTING to StateStore BEFORE starting the service and
            // BEFORE flipping the local UI flag. The background poll loop
            // (syncStateFromService, every 400ms) reads this same file - if
            // we only set the in-memory `connecting` flag here, there's a
            // race: the poll can fire before the ":vpnproc" process has
            // actually started and called broadcastStatus(STATE_CONNECTING),
            // sees the stale leftover DISCONNECTED value still on disk, and
            // snaps the button straight back to CONNECT for one tick -
            // causing the CONNECTING... -> CONNECT -> CONNECTING... flicker.
            // Writing it here first closes that window entirely.
            StateStore.write(applicationContext, SshVpnService.STATE_CONNECTING, requestId)
            startService(intent)
            connecting = true
            connected = false
            reconnectingUi = false
            failedUi = false
            applyConnectButtonState()
            // نفس الشيء هنا: السطر "Starting Service..." كيجي من الـservice
            // ماشي من الواجهة، باش يبان مرة وحدة بوحدة فـ log لكل محاولة حقيقية.
        } catch (e: Throwable) {
            appendLog("ERROR: ${e.javaClass.simpleName}: ${e.message ?: "Unknown error"}")
            android.util.Log.e("MainActivity", "Connection error", e)
        }
    }

    private fun disconnect(requestId: Long = serviceRequestId) {
        pendingConfigConnectJob?.cancel()
        pendingConfigConnectJob = null
        try {
            val intent = Intent(this, SshVpnService::class.java).apply {
                action = SshVpnService.ACTION_DISCONNECT
                putExtra(SshVpnService.EXTRA_REQUEST_ID, requestId)
            }
            startService(intent)
            connected = false
            connecting = false
            reconnectingUi = false
            // ملاحظة: activeConfigFileName ماكيتمسحش هنا من بعد - كان
            // هادشي هو السبب الرئيسي فاختفاء اسم الملف بعد STOP رغم أن
            // نفس Saved Config بقات هي المستعملة. الهوية (اسم الملف) خاصها
            // تبقى، غير حالة الاتصال (connected/connecting) هي لي كتبدل.
            // applyConnectButtonState() تحت غادي يزامن CONFIG tab
            // بـactiveConfigFileName الحالي (ماشي null).
            applyConnectButtonState()
            // "Disconnected." كيجي من SshVpnService.stopVpn() فقط - ماشي من
            // هنا. كان هادي بالضبط سبب "Disconnected." مرتين فـ Connection
            // Log: هاد الدالة كانت كتكتب نسخة ديالها مباشرة (bypass كامل
            // للـ service)، والـ service كيكتب نسخة ثانية ملي كيوصل
            // لـ ACTION_DISCONNECT. نفس المبدأ لي متبع ديجا مع
            // "Starting Service..." (شوف tryConnect فوق) - الحالة الحقيقية
            // للاتصال (بداية، نهاية، إعادة اتصال) خاصها تجي من مصدر واحد:
            // الـservice، ماشي الواجهة.
        } catch (e: Throwable) {
            appendLog("ERROR: Disconnect Failed.")
        }
    }

    private fun appendLog(msg: String) {
        LogManager.add(applicationContext, msg)
        lifecycleScope.launch { refreshLogIfChanged() }
    }

    /**
     * كيرجع اسم الأوبراتور الصحيح ديال الـSIM اللي فعلا كيدير بيانات
     * الهاتف (Mobile Data) - ماشي الـSIM الافتراضي/الأول. فهاتف بـ2 SIM
     * (dual-SIM)، الطريقة العادية tm.networkOperatorName كترجع دايما
     * اسم الأوبراتور ديال SIM1 حتى إلا كان SIM2 هو المفعل عليه Data -
     * هاد الدالة كتصحح هاد المشكل عبر SubscriptionManager.getActiveDataSubscriptionId()
     * (API 30+) أو SubscriptionManager.getDefaultDataSubscriptionId()
     * (كـfallback فـAPI 24-29)، وبعدين TelephonyManager.createForSubscriptionId()
     * باش نجيبو اسم الأوبراتور المرتبط فعلا بهاد الـSIM.
     * كترجع null إلا: الجهاز SIM واحد فقط، الـpermission (READ_PHONE_STATE)
     * ماعطاهاش المستخدم، ولا أي خطأ آخر - فهاد الحالة الكود لي كيستدعيها
     * كيرجع تلقائيا للطريقة القديمة (tm.networkOperatorName) بلا مشكل.
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
     * كيبين معلومات الجهاز والشبكة مرة وحدة عند فتح التطبيق (بحال
     * SshVpnService.logDeviceAndNetworkInfo() لي كيدير نفسها عند كل
     * محاولة اتصال) - باش تبان فاللوق حتى قبل ما المستخدم يدوس Connect،
     * بحال HTTP Custom. Best-effort بحتة: أي خطأ هنا ماخصوش يوقف فتح
     * التطبيق. الصيغة ديال الأسطر خاصها تبقى مطابقة بالضبط لهاديك اللي
     * كيكتب SshVpnService باش LogFormatter.isDeviceNetworkInfoLine()
     * تعرفها وما تفلترهاش.
     */
    private fun logDeviceAndNetworkInfoOnce() {
        if (deviceInfoLoggedThisLaunch) return
        deviceInfoLoggedThisLaunch = true
        try {
            val versionName = try { BuildConfig.VERSION_NAME } catch (_: Throwable) { "" }
            val versionCode = try { BuildConfig.VERSION_CODE } catch (_: Throwable) { 0 }
            appendLog("MR VPN TUNNEL v$versionName ($versionCode)")
            appendLog("running on ${Build.MANUFACTURER} (${Build.MODEL})")
            val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "unknown"
            appendLog("Android ${Build.VERSION.RELEASE} API-${Build.VERSION.SDK_INT} ($abi)")

            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            val activeNetwork = cm?.activeNetwork
            val caps = activeNetwork?.let { cm.getNetworkCapabilities(it) }
            val connLabel = when {
                caps == null -> "Unknown Network"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> {
                    val tm = getSystemService(Context.TELEPHONY_SERVICE) as? TelephonyManager
                    val carrier = getActiveDataCarrierName(tm)
                        ?: tm?.networkOperatorName?.takeIf { it.isNotBlank() }
                        ?: "Mobile"
                    "$carrier / Mobile Data"
                }
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "Ethernet"
                else -> "Unknown Network"
            }
            appendLog(connLabel)

            val localIp = try {
                java.net.NetworkInterface.getNetworkInterfaces().asSequence()
                    .flatMap { it.inetAddresses.asSequence() }
                    .firstOrNull { !it.isLoopbackAddress && it is java.net.Inet4Address }
                    ?.hostAddress
            } catch (_: Throwable) { null }
            if (!localIp.isNullOrBlank()) {
                appendLog("Local IP $localIp")
            }
        } catch (_: Throwable) {
            // best-effort - ماخصهاش توقف/تعطل فتح التطبيق
        }
    }

    override fun onStart() {
        super.onStart()
        // The user may have left the app (Home button, switched apps) while
        // the service kept running/reconnecting in the background, or the
        // Activity may have been recreated from scratch. Either way, re-sync
        // with the service's real state now rather than trusting whatever
        // this instance's fields happened to hold.
        syncStateFromService()
        // Also re-check for a pending update here, not just onCreate: the
        // VPN may have connected (and discovered an update) while this
        // Activity was backgrounded, in which case onCreate never ran again.
        showUpdateDialogIfNeeded()
    }

    @Suppress("DEPRECATION")
    override fun onBackPressed() {
        val drawer = drawerLayout
        if (drawer != null && drawer.isDrawerOpen(androidx.core.view.GravityCompat.START)) {
            drawer.closeDrawer(androidx.core.view.GravityCompat.START)
        } else {
            super.onBackPressed()
        }
    }

    override fun onDestroy() {
        try { unregisterReceiver(logReceiver) } catch (_: Throwable) { }
        try { unregisterReceiver(statusReceiver) } catch (_: Throwable) { }
        pulseAnimator?.cancel()
        pulseAnimator = null
        super.onDestroy()
    }

    companion object {
        private const val EXTRA_RELAUNCHED = "com.sshproxy.vpn.EXTRA_RELAUNCHED"
        private const val KEY_LAST_SAVED_CONFIG_FILE = "lastLoadedConfigFileName"
        private const val KEY_LAST_CONFIG_WAS_IMPORTED = "lastConfigWasImported"
    }
}
