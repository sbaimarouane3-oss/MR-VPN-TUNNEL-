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
 */
object LogFormatter {

    // Colors
    private const val COLOR_TIME = 0xFF6B7280.toInt()
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

    // Internal/debug noise - completely hidden
    private val HIDE_CONTAINS = listOf(
        "crash guard",
        "native crash",
        "generating xray config",
        "generating config",
        "parsing config",
        "verifying internet connectivity",
        "debug",
        "payloadsocketfactory"  // hide the internal debug line
    )

    private fun isAlwaysVisible(body: String): Boolean {
        val l = body.lowercase()
        return l.contains("error") || l.contains("fatal") || l.contains("warn") ||
            l.contains("disconnected") || l.contains("reconnecting") ||
            l.contains("retrying") ||
            l.contains("waiting for network") || l.contains("failed")
    }

    /**
     * ============================================================
     * IMPORTANT: This is the ONLY place that decides which log
     * lines appear in the UI. Add ANY new log message here.
     * ============================================================
     */
    private fun isWhitelisted(body: String): Boolean {
        val l = body.lowercase()
        
        // ===== SERVICE LIFECYCLE =====
        if (l.startsWith("starting service")) return true
        if (l.startsWith("preparing vpn engine")) return true
        
        // ===== PROTOCOL =====
        if (l.startsWith("protocol:")) return true
        if (l.startsWith("resolving server")) return true
        if (l.startsWith("connection setup started")) return true
        
        // ===== SSH SESSION =====
        if (l.startsWith("ssh session created")) return true
        
        // ===== SOCKET FACTORY =====
        if (l.startsWith("creating socket factory")) return true
        if (l.startsWith("socket factory created")) return true
        
        // ===== TCP CONNECTION =====
        if (l.startsWith("tcp connecting")) return true
        if (l.startsWith("creating tcp socket")) return true
        if (l.startsWith("tcp socket connected")) return true
        if (l.startsWith("tcp connect failed")) return true
        
        // ===== SSL/TLS =====
        if (l.startsWith("ssl handshake")) return true
        
        // ===== PAYLOAD =====
        if (l.startsWith("sending payload")) return true
        if (l.startsWith("payload sent")) return true
        if (l.startsWith("payload accepted")) return true
        if (l.startsWith("payload send failed")) return true
        
        // ===== SOCKET FACTORY READY =====
        if (l.startsWith("socket factory ready")) return true
        
        // ===== SSH HANDSHAKE =====
        if (l.startsWith("ssh handshake")) return true
        if (l.startsWith("ssh connect")) return true
        
        // ===== SSH AUTHENTICATION =====
        if (l.startsWith("ssh authentication")) return true
        
        // ===== SOCKS5 =====
        if (l.startsWith("socks5 proxy ready")) return true
        
        // ===== VPN INTERFACE =====
        if (l.startsWith("creating vpn interface")) return true
        if (l.startsWith("vpn interface created")) return true
        
        // ===== TUNNEL =====
        if (l.startsWith("tunnel started successfully")) return true
        
        // ===== CONNECTION ESTABLISHED =====
        if (l.contains("connection established")) return true
        
        // ===== PING =====
        if (l.startsWith("ping:")) return true
        
        // ===== RECONNECT =====
        if (l.startsWith("reconnecting")) return true
        
        // ===== UDPGW =====
        if (l.startsWith("udpgw forward ready")) return true
        if (l.startsWith("warn: udpgw")) return true
        
        // ===== XRAY =====
        if (l.startsWith("xray:")) return true
        
        return false
    }

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

            val isProxyLine = tag.equals("PROXY", ignoreCase = true)

            if (!isProxyLine) {
                if (HIDE_CONTAINS.any { body.contains(it, ignoreCase = true) }) continue
                if (!isWhitelisted(body) && !isAlwaysVisible(body)) continue
            }

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
                out.append(body)
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
                val label = body.substring(0, colonIndex + 1)
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
