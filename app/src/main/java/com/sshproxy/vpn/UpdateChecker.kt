package com.sshproxy.vpn

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Downloads and parses update.json. This class does exactly one job -
 * fetch the manifest and turn it into an [UpdateInfo] - and nothing else.
 * It knows nothing about SharedPreferences, BuildConfig, or the UI; that
 * orchestration lives in [UpdateManager]. It has no Android Context
 * dependency at all, so it's trivially safe to call from any background
 * thread.
 *
 * update.json format (hosted on GitHub or any static host):
 * {
 *   "latest_version": 5,
 *   "version_name": "2.0",
 *   "update_title": "New Version Available",
 *   "update_message": "Improvements and fixes",
 *   "download_url": "https://...",
 *   "force_update": false
 * }
 */
object UpdateChecker {

    // Points at marouanegerman5-hue/update.json on GitHub - a small, public,
    // standalone repo containing only update.json (kept separate from the
    // app's own, private source-code repo). Pushing a new version, a new
    // download link, or flipping force_update later only ever means editing
    // that one JSON file on GitHub - never touching or rebuilding the app.
    private const val UPDATE_JSON_URL =
        "https://raw.githubusercontent.com/marouanegerman5-hue/update.json/refs/heads/main/update.json"

    private const val TIMEOUT_MS = 8000

    /**
     * Fetches and parses update.json. Returns null on absolutely any
     * failure - no network, DNS failure, GitHub down, malformed JSON,
     * missing/invalid "latest_version" - this method never throws and the
     * caller never needs a try/catch around it.
     */
    fun fetch(): UpdateInfo? {
        var conn: HttpURLConnection? = null
        return try {
            val url = URL(UPDATE_JSON_URL)
            conn = url.openConnection() as HttpURLConnection
            conn.connectTimeout = TIMEOUT_MS
            conn.readTimeout = TIMEOUT_MS
            conn.requestMethod = "GET"
            if (conn.responseCode !in 200..299) return null

            val body = conn.inputStream.bufferedReader().use { it.readText() }
            val json = JSONObject(body)

            val latestVersion = json.optInt("latest_version", -1)
            if (latestVersion <= 0) return null

            UpdateInfo(
                latestVersionCode = latestVersion,
                versionName = json.optString("version_name", ""),
                title = json.optString("update_title", "New Version Available"),
                message = json.optString("update_message", ""),
                downloadUrl = json.optString("download_url", ""),
                forceUpdate = json.optBoolean("force_update", false)
            )
        } catch (_: Throwable) {
            null
        } finally {
            try { conn?.disconnect() } catch (_: Throwable) { }
        }
    }
}
