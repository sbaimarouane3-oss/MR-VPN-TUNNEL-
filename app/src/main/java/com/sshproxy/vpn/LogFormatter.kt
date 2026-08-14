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
        Regex("""^\[(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?]\s*(?:\[(\w+)]\s*)?(.*)$""")
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
            l.contains("retrying") ||
            l.contains("waiting for network") || l.contains("failed")
    }

    private fun isWhitelisted(body: String): Boolean {
        val l = body.lowercase()
        return l.startsWith("starting service") ||
            l.startsWith("protocol:") ||
            l.contains("creating vpn interface") ||
            l.contains("connection established") ||
            l.startsWith("ping:")
    }

    /**
     * Core selection logic - the ONE place that decides which raw log lines
     * are visible and in what order. Both [format] (Connection Log UI,
     * colored) and [formatPlain] (Export TXT, plain text) call this and
     * only differ in how they render the result - so the two outputs can
     * never diverge in *content*, only in styling.
     *
     * @return list of (timeText, body, isProxyLine) for every visible line, in order.
     */
    private fun selectVisibleLines(raw: String): List<Triple<String, String, Boolean>> {
        val result = mutableListOf<Triple<String, String, Boolean>>()
        var lastPingSeconds: Int? = null
        var lastPingWasOk: Boolean? = null

        for (rawLine in raw.lineSequence()) {
            val line = rawLine.trim()
            if (line.isEmpty()) continue

            val match = LINE_REGEX.find(line)
            val timeText: String
            val tag: String
            val body: String
            val totalSeconds: Int
            if (match != null) {
                val h = match.groupValues[1]
                val m = match.groupValues[2]
                val s = match.groupValues[3]
                timeText = "$h:$m:$s"
                totalSeconds = h.toInt() * 3600 + m.toInt() * 60 + s.toInt()
                tag = match.groupValues[4]
                body = match.groupValues[5].trim()
            } else {
                timeText = ""
                tag = ""
                totalSeconds = -1
                body = line
            }

            // Proxy Sharing lines are protocol-agnostic by design (see
            // UnifiedProxySharingManager) - always shown, regardless of
            // which backend (SSH/Xray/VLESS/...) is currently active.
            val isProxyLine = tag.equals("PROXY", ignoreCase = true)

            if (!isProxyLine) {
                if (HIDE_CONTAINS.any { body.contains(it, ignoreCase = true) }) continue
                if (!isWhitelisted(body) && !isAlwaysVisible(body)) continue
            }

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

            result.add(Triple(timeText, body, isProxyLine))
        }

        return result
    }

    /**
     * @param raw the full raw content of the log file (as returned by FileLogger.readAll)
     */
    fun format(raw: String): SpannableStringBuilder {
        val out = SpannableStringBuilder()
        var firstLine = true
        for ((timeText, body, isProxyLine) in selectVisibleLines(raw)) {
            if (!firstLine) out.append("\n")
            firstLine = false
            appendLine(out, timeText, body, isProxyLine)
        }
        return out
    }

    /**
     * Plain-text equivalent of [format], for Export TXT - same selection,
     * same order, same lines, just without color spans. This is what makes
     * the exported file guaranteed to match what the user sees in the
     * Connection Log tab.
     */
    fun formatPlain(raw: String): String {
        val lines = selectVisibleLines(raw).map { (timeText, body, _) ->
            val displayBody = if (body.contains("Connection Established", ignoreCase = true)) {
                "Connected \u2713"
            } else {
                body
            }
            if (timeText.isNotEmpty()) "[$timeText] $displayBody" else displayBody
        }
        return lines.joinToString("\n")
    }

    private fun appendLine(out: SpannableStringBuilder, timeText: String, body: String, isProxyLine: Boolean) {
        val start = out.length
        if (timeText.isNotEmpty()) {
            out.append("[$timeText] ")
        }
        val afterTime = out.length

        when {
            isProxyLine -> appendProxyLine(out, body)
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

    /**
     * Formats one line of the [PROXY] block. Every line from
     * UnifiedProxySharingManager is either "Label: value" (label in white,
     * value in yellow) or a plain status phrase ("Sharing Started",
     * "Ready for Hotspot Clients" - shown in white/green respectively).
     */
    private fun appendProxyLine(out: SpannableStringBuilder, body: String) {
        val colonIndex = body.indexOf(':')
        when {
            body.contains("Ready for Hotspot Clients", ignoreCase = true) -> {
                appendColored(out, body, COLOR_GREEN, bold = true)
            }
            body.startsWith("ERROR", ignoreCase = true) || body.startsWith("WARN", ignoreCase = true) -> {
                appendColored(out, body, COLOR_RED)
            }
            colonIndex > 0 -> {
                val label = body.substring(0, colonIndex + 1) // includes ":"
                val value = body.substring(colonIndex + 1).trim()
                appendColored(out, "$label ", COLOR_WHITE)
                appendColored(out, value, COLOR_YELLOW)
            }
            else -> {
                appendColored(out, body, COLOR_WHITE, bold = true)
            }
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
