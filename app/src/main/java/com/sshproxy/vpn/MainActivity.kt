package com.sshproxy.vpn

import android.animation.ValueAnimator
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.res.ColorStateList
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.LinearInterpolator
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.widget.SwitchCompat
import com.google.android.material.button.MaterialButton
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
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
import com.sshproxy.vpn.importer.SecureConfigStore
import com.sshproxy.vpn.importer.XraySecureConfigStore
import com.sshproxy.vpn.xray.ParsedProxyConfig
import com.sshproxy.vpn.xray.XrayConfigParser
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

private data class ProtocolOption(
    val label: String,
    val usePayload: Boolean,
    val useSsl: Boolean,
    val useProxy: Boolean,
    val isXtra: Boolean = false,
    val isV2Ray: Boolean = false,
    val isShadowsocks: Boolean = false
)

private val PROTOCOL_OPTIONS = listOf(
    ProtocolOption("SSH-Direct", usePayload = false, useSsl = false, useProxy = false),
    ProtocolOption("SSH-Proxy", usePayload = false, useSsl = false, useProxy = true),
    ProtocolOption("SSH-Payload", usePayload = true, useSsl = false, useProxy = false),
    ProtocolOption("SSH-Proxy-Payload", usePayload = true, useSsl = false, useProxy = true),
    ProtocolOption("SSH-TLS", usePayload = false, useSsl = true, useProxy = false),
    ProtocolOption("SSH-TLS-Proxy", usePayload = false, useSsl = true, useProxy = true),
    ProtocolOption("SSH-TLS-Payload", usePayload = true, useSsl = true, useProxy = false),
    ProtocolOption("SSH-TLS-Proxy-Payload", usePayload = true, useSsl = true, useProxy = true),
    ProtocolOption("XTRA", usePayload = false, useSsl = true, useProxy = false, isXtra = true),
    ProtocolOption("V2Ray", usePayload = false, useSsl = false, useProxy = false, isV2Ray = true),
    ProtocolOption("Shadowsocks", usePayload = false, useSsl = false, useProxy = false, isShadowsocks = true)
)

private val DEFAULT_PROTOCOL = PROTOCOL_OPTIONS[0]

class MainActivity : AppCompatActivity() {

    private var connected = false
    private var connecting = false
    private var reconnectingUi = false
    private var failedUi = false

    private var sshFragment: SshFragment? = null
    private var logFragment: LogFragment? = null

    private var drawerLayout: DrawerLayout? = null

    private var lastLogContent = ""
    private var hadRealNativeCrashThisLaunch = false
    private var activeImportedConfig: ImportedConfig? = null
    private var activeXrayConfig: ParsedProxyConfig? = null

    private var pulseAnimator: ValueAnimator? = null
    private var lastButtonVisualState: String? = null

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

    private val logReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            lifecycleScope.launch { refreshLogIfChanged() }
        }
    }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            when (intent.getStringExtra(SshVpnService.EXTRA_STATE)) {
                SshVpnService.STATE_CONNECTING -> {
                    connecting = true; connected = false; reconnectingUi = false; failedUi = false
                }
                SshVpnService.STATE_READY -> {
                    connecting = false; connected = true; reconnectingUi = false; failedUi = false
                }
                SshVpnService.STATE_RECONNECTING, SshVpnService.STATE_WAITING_NETWORK -> {
                    reconnectingUi = true; failedUi = false
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

        val root = findViewById<View>(android.R.id.content)
        ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
            val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            val ime = insets.getInsets(WindowInsetsCompat.Type.ime())
            view.updatePadding(
                top = bars.top,
                bottom = if (ime.bottom > 0) ime.bottom else bars.bottom
            )
            insets
        }

        val crashLogPath = File(applicationContext.filesDir, "vpn_native_crash.txt").absolutePath
        val guardStatus = CrashGuard.installIfPossible(crashLogPath)
        appendStartupDiag(guardStatus)
        try {
            val crashFile = File(crashLogPath)
            if (crashFile.exists() && crashFile.length() > 0) {
                hadRealNativeCrashThisLaunch = true
                appendStartupDiag("--- Native Crash saved ---")
                appendStartupDiag(crashFile.readText())
                appendStartupDiag("--- End Native Crash ---")
                crashFile.delete()
            }
        } catch (_: Throwable) { }

        Thread.setDefaultUncaughtExceptionHandler { _, e ->
            LogManager.add(applicationContext, "FATAL (uncaught): ${e.javaClass.simpleName}: ${e.message}")
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            notifPermLauncher.launch(android.Manifest.permission.POST_NOTIFICATIONS)
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

        setupDrawer()

        val viewPager = findViewById<ViewPager2>(R.id.viewPager)
        val tabLayout = findViewById<TabLayout>(R.id.tabLayout)
        viewPager.offscreenPageLimit = 1
        viewPager.adapter = MainPagerAdapter(this)
        TabLayoutMediator(tabLayout, viewPager) { tab, position ->
            tab.text = if (position == 0) "SSH SETTINGS" else "LOG"
        }.attach()

        startLogPolling()
        showUpdateDialogIfNeeded()
    }

    private fun setupDrawer() {
        val drawer = findViewById<DrawerLayout>(R.id.drawerLayout)
        drawerLayout = drawer
        val navView = findViewById<NavigationView>(R.id.navigationView)
        navView.itemIconTintList = null

        findViewById<View>(R.id.btnMenu).setOnClickListener {
            drawer.openDrawer(androidx.core.view.GravityCompat.START)
        }

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
                R.id.nav_telegram -> openUrl(LinksManager.getCached(applicationContext).telegramUrl)
                R.id.nav_whatsapp -> openUrl(LinksManager.getCached(applicationContext).whatsappUrl)
                R.id.nav_sharelog -> shareLog()
            }
            drawer.closeDrawer(navView)
            true
        }
    }

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

    private fun openUrl(url: String) {
        if (url.isBlank()) return
        try {
            startActivity(Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url)))
        } catch (_: Throwable) {
            Toast.makeText(this, "Could not open link.", Toast.LENGTH_SHORT).show()
        }
    }

    private var updateDialogShowing = false

    private fun showUpdateDialogIfNeeded() {
        if (updateDialogShowing) return
        if (isFinishing || isDestroyed) return
        val update = UpdateManager.getPendingUpdate(applicationContext) ?: return

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

        val dialog = AlertDialog.Builder(this)
            .setView(view)
            .setCancelable(false)
            .create()
        dialog.setCanceledOnTouchOutside(false)

        btnLater.visibility = if (update.forceUpdate) View.GONE else View.VISIBLE
        btnLater.setOnClickListener { dialog.dismiss() }

        btnDownload.setOnClickListener {
            openDownloadUrl(update.downloadUrl)
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

        restoreManualFields()
        wireManualFieldPersistence()
        updateImportUiState()
        syncStateFromService()
    }

    private fun syncStateFromService() {
        lifecycleScope.launch {
            val state = withContext(Dispatchers.IO) { StateStore.readReconciled(applicationContext) }
            when (state) {
                SshVpnService.STATE_CONNECTING -> {
                    connecting = true; connected = false; reconnectingUi = false
                }
                SshVpnService.STATE_READY -> {
                    connecting = false; connected = true; reconnectingUi = false
                }
                SshVpnService.STATE_RECONNECTING, SshVpnService.STATE_WAITING_NETWORK -> {
                    connecting = false; connected = true; reconnectingUi = true
                }
                else -> {
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

    private fun manualFieldsPrefs() = getSharedPreferences("manual_fields", Context.MODE_PRIVATE)

    private fun restoreManualFields() {
        val f = sshFragment ?: return
        val p = manualFieldsPrefs()
        f.edtHost.setText(p.getString("host", ""))
        f.edtUser.setText(p.getString("user", ""))
        f.edtPass.setText(p.getString("pass", ""))
        f.edtProxy.setText(p.getString("proxy", ""))
        if (p.contains("payload")) f.edtPayload.setText(p.getString("payload", ""))
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
        f.edtV2rayJson.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("v2rayJson", it).apply() })
        f.edtSsServer.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("ssServer", it).apply() })
        f.edtSsPort.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("ssPort", it).apply() })
        f.edtSsMethod.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("ssMethod", it).apply() })
        f.edtSsPassword.addTextChangedListener(watcher { manualFieldsPrefs().edit().putString("ssPassword", it).apply() })
        f.chkSsUdp.setOnCheckedChangeListener { _, checked ->
            manualFieldsPrefs().edit().putBoolean("ssUdp", checked).apply()
        }
    }

    private fun showProtocolPicker() {
        val currentProtocol = manualFieldsPrefs().getString("protocol", DEFAULT_PROTOCOL.label)
            ?: DEFAULT_PROTOCOL.label
        val labels = PROTOCOL_OPTIONS.map { it.label }

        val adapter = object : ArrayAdapter<String>(this, R.layout.item_protocol_choice, R.id.txtProtocolName, labels) {
            override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                val row = convertView ?: LayoutInflater.from(context)
                    .inflate(R.layout.item_protocol_choice, parent, false)
                val txt = row.findViewById<TextView>(R.id.txtProtocolName)
                val divider = row.findViewById<View>(R.id.dividerProtocol)

                val label = labels[position]
                txt.text = label
                txt.setTextColor(
                    androidx.core.content.ContextCompat.getColor(
                        this@MainActivity,
                        if (label == currentProtocol) R.color.accent_green else R.color.text_primary
                    )
                )
                divider.visibility = if (position == labels.lastIndex) View.GONE else View.VISIBLE
                return row
            }
        }

        AlertDialog.Builder(this)
            .setTitle("Choose Protocol")
            .setAdapter(adapter) { _, which ->
                switchToManualProtocol(PROTOCOL_OPTIONS[which])
            }
            .show()
    }

    private fun switchToManualProtocol(opt: ProtocolOption) {
        if (activeImportedConfig != null || activeXrayConfig != null) {
            SecureConfigStore.clear(applicationContext)
            activeImportedConfig = null
            XraySecureConfigStore.clear(applicationContext)
            activeXrayConfig = null
        }
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
        val view = layoutInflater.inflate(R.layout.dialog_import, null)
        val input = view.findViewById<EditText>(R.id.edtImportCode)
        val btnCancel = view.findViewById<View>(R.id.btnImportCancel)
        val btnConfirm = view.findViewById<View>(R.id.btnImportConfirm)

        val dialog = AlertDialog.Builder(this)
            .setView(view)
            .setCancelable(true)
            .create()
        dialog.window?.setBackgroundDrawableResource(android.R.color.transparent)
        dialog.window?.setSoftInputMode(android.view.WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)

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

    private fun saveXrayConfig(cfg: ParsedProxyConfig) {
        SecureConfigStore.clear(applicationContext)
        activeImportedConfig = null

        XraySecureConfigStore.save(applicationContext, cfg)
        activeXrayConfig = cfg
        updateImportUiState()
        appendLog("Configuration Loaded Successfully.")
        Toast.makeText(this, "Config imported successfully \u2705", Toast.LENGTH_SHORT).show()
    }

    private fun saveImportedConfig(cfg: ImportedConfig) {
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
        val ssh = activeImportedConfig
        val xray = activeXrayConfig
        if (xray != null) {
            f.importedStatusContainer.visibility = View.VISIBLE
            f.txtImportedStatus.text = xray.summary()
            f.manualFieldsContainer.visibility = View.GONE
        } else if (ssh != null) {
            f.importedStatusContainer.visibility = View.VISIBLE
            f.txtImportedStatus.text = ssh.maskedSummary()
            f.manualFieldsContainer.visibility = View.GONE
        } else {
            f.importedStatusContainer.visibility = View.GONE
            f.manualFieldsContainer.visibility = View.VISIBLE
        }
        updateConnectionSummary()
    }

    private fun startLogPolling() {
        lifecycleScope.launch {
            while (isActive) {
                refreshLogIfChanged()
                syncStateFromService()
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

            if ((connecting || reconnectingUi) && newlyAdded.contains("Connection Established.")) {
                connecting = false
                connected = true
                reconnectingUi = false
                applyConnectButtonState()
            }
        }
    }

    private fun applyConnectButtonState() {
        val f = sshFragment ?: return
        f.btnConnect.isEnabled = true
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
                button.animate().cancel()
                button.scaleX = 0.9f
                button.scaleY = 0.9f
                button.animate().scaleX(1f).scaleY(1f).setDuration(220).start()
            }
        }
    }

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
                val manualProtocol = manualFieldsPrefs().getString("protocol", DEFAULT_PROTOCOL.label)
                    ?: DEFAULT_PROTOCOL.label
                protocol = manualProtocol

                when (manualProtocol) {
                    "V2Ray" -> {
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
    }

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
            val rawNow = LogManager.readRaw(applicationContext)
            val sessionLog = LogManager.formatForExport(rawNow)

            val fullLog = buildString {
                append(sessionLog)
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
            val xray = activeXrayConfig
            val imported = activeImportedConfig
            val f = sshFragment

            val intent = Intent(this, SshVpnService::class.java)

            if (xray != null) {
                intent.putExtra(SshVpnService.EXTRA_MODE, SshVpnService.MODE_XRAY)
                intent.putExtra(SshVpnService.EXTRA_XRAY_CONFIG, xray.toJson())

                StateStore.write(applicationContext, SshVpnService.STATE_CONNECTING)
                startService(intent)
                connecting = true
                connected = false
                reconnectingUi = false
                failedUi = false
                applyConnectButtonState()
                return
            }

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

                StateStore.write(applicationContext, SshVpnService.STATE_CONNECTING)
                startService(intent)
                connecting = true
                connected = false
                reconnectingUi = false
                failedUi = false
                applyConnectButtonState()
                return
            } else if (manualProtocol == "V2Ray") {
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

                StateStore.write(applicationContext, SshVpnService.STATE_CONNECTING)
                startService(intent)
                connecting = true
                connected = false
                reconnectingUi = false
                failedUi = false
                applyConnectButtonState()
                return
            } else if (manualProtocol == "Shadowsocks") {
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

                StateStore.write(applicationContext, SshVpnService.STATE_CONNECTING)
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

            StateStore.write(applicationContext, SshVpnService.STATE_CONNECTING)
            startService(intent)
            connecting = true
            connected = false
            reconnectingUi = false
            failedUi = false
            applyConnectButtonState()
        } catch (e: Throwable) {
            appendLog("ERROR: ${e.javaClass.simpleName}: ${e.message ?: "Unknown error"}")
            android.util.Log.e("MainActivity", "Connection error", e)
        }
    }

    private fun disconnect() {
        try {
            val intent = Intent(this, SshVpnService::class.java).apply {
                action = SshVpnService.ACTION_DISCONNECT
            }
            startService(intent)
            connected = false
            connecting = false
            reconnectingUi = false
            applyConnectButtonState()
        } catch (e: Throwable) {
            appendLog("ERROR: Disconnect Failed.")
        }
    }

    private fun appendLog(msg: String) {
        LogManager.add(applicationContext, msg)
        lifecycleScope.launch { refreshLogIfChanged() }
    }

    override fun onStart() {
        super.onStart()
        syncStateFromService()
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
}
