package com.sshproxy.vpn

import android.content.Context
import android.text.SpannableStringBuilder

/**
 * Single centralized Log Manager:
 *
 *   LogManager.add(...)
 *        |
 *        v
 *   FileLogger (one raw file, one writer path)
 *        |
 *        +--> formatForUi()     -> Connection Log (colored, filtered)
 *        +--> formatForExport() -> Export TXT      (plain,   filtered)
 *
 * Both consumers run through the exact same selection/filter/throttle
 * logic in [LogFormatter] - they can never show different content because
 * there is only one code path that decides "is this line visible". The
 * only difference between the two is the final rendering (Spannable with
 * colors vs plain text), never which lines get included.
 *
 * This does not replace [FileLogger] (still the actual on-disk storage) or
 * [LogFormatter] (still the actual filtering rules) - it is the one place
 * every other class should go through instead of calling either directly,
 * so there is a single source of truth for "what the log contains" and
 * "what the user is allowed to see".
 */
object LogManager {

    /** Every log line in the app - service or UI-originated - should go through this. */
    fun add(context: Context, msg: String) {
        FileLogger.append(context, msg)
    }

    /** Always reads fresh from disk - never a cached/stale snapshot, so export can never lag behind the UI. */
    fun readRaw(context: Context): String = FileLogger.readAll(context)

    /** Connection Log tab: colored, filtered. */
    fun formatForUi(raw: String): SpannableStringBuilder = LogFormatter.format(raw)

    /** Export TXT: plain text, filtered with the EXACT SAME rules as the UI - guaranteed to match, line for line. */
    fun formatForExport(raw: String): String = LogFormatter.formatPlain(raw)

    fun clear(context: Context) = FileLogger.clear(context)
}

