package com.sshproxy.vpn

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.io.File

/**
 * Orchestrates the whole update-check feature. This is the only class
 * SshVpnService and MainActivity should ever talk to directly - it owns:
 *
 *  - WHEN a check runs: [checkOnceAsync], fired once per successful VPN
 *    connection (once per app-process lifetime, guarded internally), never
 *    on cold start.
 *  - Persisting the result so it survives the app being closed or the
 *    phone being rebooted.
 *  - [getPendingUpdate], the single, cheap, synchronous, network-free
 *    source of truth the UI reads on every launch to decide whether to
 *    show the update dialog.
 *
 * IMPORTANT: this deliberately uses a plain JSON file (via [File], same
 * pattern as [StateStore]) instead of SharedPreferences. SshVpnService runs
 * in a separate process (android:process=":vpnproc") from MainActivity.
 * SharedPreferencesImpl caches its content in memory per-process and only
 * refreshes on writes made through that *same* cached instance - a write
 * from the service's process is invisible to a SharedPreferences instance
 * MainActivity's process already loaded, even though both point at the same
 * underlying file. A plain File read has no such cache and always reflects
 * the latest write from either process.
 *
 * Completely independent of SshVpnService: nothing in here can throw back
 * into the caller, block the VPN threads, or otherwise affect the tunnel.
 */
object UpdateManager {

    private const val FILE_NAME = "update_state.json"

    private const val KEY_LATEST_VERSION_CODE = "latest_version_code"
    private const val KEY_VERSION_NAME = "version_name"
    private const val KEY_TITLE = "title"
    private const val KEY_MESSAGE = "message"
    private const val KEY_DOWNLOAD_URL = "download_url"
    private const val KEY_FORCE_UPDATE = "force_update"

    // Runs at most once per process lifetime. SshVpnService may reach
    // STATE_READY many times in one run (reconnects) - we only want the
    // very first one to trigger a network call.
    @Volatile private var checkedThisProcess = false

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    /**
     * Fire-and-forget: launches the check on a background coroutine and
     * returns immediately. Safe to call from SshVpnService right after
     * broadcasting STATE_READY - it never touches the VPN, never throws,
     * and does nothing at all after the first successful call in this
     * process.
     *
     * [onLog], if given, receives a single neutral line once the check has
     * actually run and completed (either "found a new version" or "already
     * up to date") - never on network/parse failure, which stays silent by
     * design.
     */
    fun checkOnceAsync(context: Context, socksPort: Int? = null, onLog: ((String) -> Unit)? = null) {
        if (checkedThisProcess) return
        checkedThisProcess = true
        val appContext = context.applicationContext
        scope.launch {
            try {
                // نجربو أولاً عبر التنل (إلا كان socksPort معطى) - هادشي
                // كيتفادى بلوكاج/بطء الشبكة الحقيقية ديال الأوبراتور
                // (بحال Orange على بيانات الهاتف) حيت التطبيق مستثنى من
                // الـVPN أصلاً. إلا فشلات (تنل بطيء/سيرفر ماشي جاهز بعد)،
                // كنرجعو نجربو مباشرة عبر الشبكة الحقيقية كـfallback.
                val info = (socksPort?.let { UpdateChecker.fetch(it) } ?: UpdateChecker.fetch())
                    ?: UpdateChecker.fetch()
                    ?: return@launch
                if (info.latestVersionCode > BuildConfig.VERSION_CODE) {
                    save(appContext, info)
                    onLog?.invoke("Update Check: New Version Available.")
                } else {
                    // We're already on latest (or newer) as of this fresh
                    // check - e.g. the user updated already, or reinstalled
                    // an old build but latest_version was lowered/removed.
                    // Clear any stale pending record so the dialog stops.
                    clear(appContext)
                    onLog?.invoke("Update Check: Up To Date.")
                }
            } catch (_: Throwable) {
                // Belt-and-suspenders: UpdateChecker.fetch() already never
                // throws, but nothing about this feature is allowed to ever
                // surface an error or crash the app.
            }
        }
    }

    @Synchronized
    private fun save(context: Context, info: UpdateInfo) {
        try {
            val json = JSONObject()
                .put(KEY_LATEST_VERSION_CODE, info.latestVersionCode)
                .put(KEY_VERSION_NAME, info.versionName)
                .put(KEY_TITLE, info.title)
                .put(KEY_MESSAGE, info.message)
                .put(KEY_DOWNLOAD_URL, info.downloadUrl)
                .put(KEY_FORCE_UPDATE, info.forceUpdate)
            File(context.filesDir, FILE_NAME).writeText(json.toString())
        } catch (_: Throwable) {
            // Persistence must never crash the caller.
        }
    }

    /** Clears any stored pending-update record. */
    @Synchronized
    fun clear(context: Context) {
        try {
            File(context.filesDir, FILE_NAME).delete()
        } catch (_: Throwable) { }
    }

    /**
     * Cheap, synchronous, local-only read - safe to call on every app
     * launch and on every UI poll tick. Returns the update to prompt the
     * user about, or null if there is nothing pending: either no check has
     * ever found a newer version, or the installed build
     * (BuildConfig.VERSION_CODE) has already caught up to what was last
     * recorded - which is exactly the "disappears once actually updated"
     * requirement, re-evaluated fresh on every call rather than baked in at
     * save() time. Always reads the file fresh from disk - see the class
     * doc for why this can't use SharedPreferences.
     */
    @Synchronized
    fun getPendingUpdate(context: Context): UpdateInfo? {
        return try {
            val file = File(context.applicationContext.filesDir, FILE_NAME)
            if (!file.exists()) return null
            val json = JSONObject(file.readText())
            val latest = json.optInt(KEY_LATEST_VERSION_CODE, -1)
            if (latest <= 0) return null
            if (BuildConfig.VERSION_CODE >= latest) return null
            UpdateInfo(
                latestVersionCode = latest,
                versionName = json.optString(KEY_VERSION_NAME, ""),
                title = json.optString(KEY_TITLE, ""),
                message = json.optString(KEY_MESSAGE, ""),
                downloadUrl = json.optString(KEY_DOWNLOAD_URL, ""),
                forceUpdate = json.optBoolean(KEY_FORCE_UPDATE, false)
            )
        } catch (_: Throwable) {
            null
        }
    }
}
