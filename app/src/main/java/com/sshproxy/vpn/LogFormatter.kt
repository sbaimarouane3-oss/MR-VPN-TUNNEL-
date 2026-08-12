package com.sshproxy.vpn

import android.graphics.Color
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.graphics.Typeface

/**
 * Turns the raw log file content (every single event, unfiltered, written
 * by SshVpnService.log()) into a clean, colored, filtered log for display
 * in the LOG tab - similar in spirit to HTTP Custom's connection log.
 *
 * This is a pure display-layer transform: it reads the same raw text that
 * was always being read (FileLogger.readAll), and only changes how it is
 * rendered in the TextView. It never writes back to the log file and never
 * touches SshVpnService, the connection logic, or Share Log's raw export -
 * so nothing about the underlying connection/monitoring code is affected.
 */
object LogFormatter {

    // Colors
    private const val COLOR_TIME = 0xFF6B7280.toInt()      // gray
    private const val COLOR_WHITE = 0xFFFFFFFF.toInt()
    private const val COLOR_YELLOW = 0xFFFFC107.toInt()
    private const val COLOR_GREEN = 0xFF4CAF50.toInt()
    private const val COLOR_RED = 0xFFFF5252.toInt()
    private const val COLOR_ORANGE = 0xFFFFA726.toInt()

    private const val PING_THROTTLE_SECONDS = 30

    private val LINE_REGEX =
        Regex("""^\[(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?]\s*(?:\[\w+]\s*)?(.*)$""")
    private val PROXY_SHARE_REGEX =
        Regex("""Proxy Share:\s*(\S+)\s+on\s+([0-9.]+):(\d+)""", RegexOption.IGNORE_CASE)
    private val PING_REGEX =
        Regex("""^Ping:\s*(\d+)ms\s*(OK|FAILED)\.?""", RegexOption.IGNORE_CASE)

    // Internal/debug noise the user never needs to see in the live log.
    private val HIDE_CONTAINS = listOf(
        "crash guard",
        "native crash",
        "generating xray config",
        "generating config",
        "parsing config",
        "preparing vpn engine",
        "verifying internet connectivity",
        "socks5 proxy ready",
        "vpn interface created",
        "tunnel started successfully",
        "debug"
    )

    // Always shown even if not in the "important" whitelist below - these
    // are operational states the user needs to see to understand problems.
    private fun isAlwaysVisible(body: String): Boolean {
        val l = body.lowercase()
        return l.contains("error") || l.contains("fatal") || l.contains("warn") ||
            l.contains("disconnected") || l.contains("reconnecting") ||
            l.contains("waiting for network") || l.contains("failed")
    }

    private fun isWhitelisted(body: String): Boolean {
        val l = body.lowercase()
        return l.startsWith("starting service") ||
            l.startsWith("protocol:") ||
            l.contains("creating vpn interface") ||
            l.contains("connection established") ||
            l.startsWith("proxy share:") ||
            l.startsWith("ping:")
    }

    /**
     * @param raw the full raw content of the log file (as returned by FileLogger.readAll)
     */
    fun format(raw: String): SpannableStringBuilder {
        val out = SpannableStringBuilder()
        var lastPingSeconds: Int? = null
        var lastPingWasOk: Boolean? = null
        var firstLine = true

        for (rawLine in raw.lineSequence()) {
            val line = rawLine.trim()
            if (line.isEmpty()) continue

            val match = LINE_REGEX.find(line)
            val timeText: String
            val body: String
            val totalSeconds: Int
            if (match != null) {
                val h = match.groupValues[1]
                val m = match.groupValues[2]
                val s = match.groupValues[3]
                timeText = "$h:$m:$s"
                totalSeconds = h.toInt() * 3600 + m.toInt() * 60 + s.toInt()
                body = match.groupValues[4].trim()
            } else {
                timeText = ""
                totalSeconds = -1
                body = line
            }

            if (HIDE_CONTAINS.any { body.contains(it, ignoreCase = true) }) continue
            if (!isWhitelisted(body) && !isAlwaysVisible(body)) continue

            // Throttle Ping lines: only once every 30s, or immediately if
            // the OK/FAILED outcome flips (a real state change).
            val pingMatch = PING_REGEX.find(body)
            if (pingMatch != null) {
                val isOk = pingMatch.groupValues[2].equals("OK", ignoreCase = true)
                val show = lastPingSeconds == null ||
                    lastPingWasOk != isOk ||
                    (totalSeconds >= 0 && totalSeconds - lastPingSeconds!! >= PING_THROTTLE_SECONDS)
                lastPingSeconds = if (totalSeconds >= 0) totalSeconds else lastPingSeconds
                lastPingWasOk = isOk
                if (!show) continue
            }

            if (!firstLine) out.append("\n")
            firstLine = false

            appendLine(out, timeText, body)
        }

        return out
    }

    private fun appendLine(out: SpannableStringBuilder, timeText: String, body: String) {
        val start = out.length
        if (timeText.isNotEmpty()) {
            out.append("[$timeText] ")
        }
        val afterTime = out.length

        val proxyMatch = PROXY_SHARE_REGEX.find(body)
        when {
            proxyMatch != null -> {
                val protocol = proxyMatch.groupValues[1]
                val ip = proxyMatch.groupValues[2]
                val port = proxyMatch.groupValues[3]

                appendColored(out, "Proxy Share: $protocol\n", COLOR_WHITE)
                appendColored(out, "  IP: ", COLOR_WHITE)
                appendColored(out, ip, COLOR_YELLOW)
                out.append("\n")
                appendColored(out, "  Port: ", COLOR_WHITE)
                appendColored(out, port, COLOR_YELLOW)
            }
            body.contains("Connection Established", ignoreCase = true) -> {
                appendColored(out, "Connected \u2713", COLOR_GREEN, bold = true)
            }
            body.contains("error", ignoreCase = true) || body.contains("fatal", ignoreCase = true) -> {
                appendColored(out, body, COLOR_RED, bold = true)
            }
            body.contains("warn", ignoreCase = true) || body.contains("reconnecting", ignoreCase = true) ||
                body.contains("waiting for network", ignoreCase = true) -> {
                appendColored(out, body, COLOR_ORANGE)
            }
            body.contains("disconnected", ignoreCase = true) -> {
                appendColored(out, body, COLOR_RED)
            }
            else -> {
                out.append(body) // default TextView color (terminal green)
            }
        }

        if (timeText.isNotEmpty()) {
            out.setSpan(
                ForegroundColorSpan(COLOR_TIME),
                start, afterTime,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
            )
        }
    }

    private fun appendColored(out: SpannableStringBuilder, text: String, color: Int, bold: Boolean = false) {
        val start = out.length
        out.append(text)
        val end = out.length
        out.setSpan(ForegroundColorSpan(color), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        if (bold) {
            out.setSpan(StyleSpan(Typeface.BOLD), start, end, Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        }
    }
}
