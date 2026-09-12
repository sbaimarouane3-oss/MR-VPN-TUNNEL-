package com.sshproxy.vpn

/**
 * Parsed contents of update.json. Nothing here touches the network or
 * SharedPreferences - it's a pure data holder shared between
 * [UpdateChecker] (fetches it), [UpdateManager] (persists/reads it), and
 * the UI (displays it).
 */
data class UpdateInfo(
    val latestVersionCode: Int,
    val versionName: String,
    val title: String,
    val message: String,
    val downloadUrl: String,
    val forceUpdate: Boolean
)
