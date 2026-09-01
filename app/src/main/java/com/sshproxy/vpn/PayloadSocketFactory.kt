package com.sshproxy.vpn

import com.jcraft.jsch.SocketFactory
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import android.os.SystemClock
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.X509TrustManager

/**
 * كيدير Socket عادي، كيبعث Payload (HTTP GET/websocket upgrade) قبل ما يبدا SSH handshake.
 * هادشي هو نفس المبدأ ديال HTTP Custom / SSH-PROXY-PAYLOAD.
 *
 * إلا كان useSsl مفعّل، كنلفو التواصل بـ TLS (SNI قابل للتخصيص) قبل ما نبداو أي
 * Payload أو SSH handshake - هادشي هو بروتوكول "SSH-SSL" بحال SSL checkbox
 * فـ HTTP Custom / NPV Tunnel. Payload والـ SSL مستقلين عن بعضياتهم بالضبط
 * بحال فالتطبيقات الأخرى: يمكن تفعّل واحد منهما، بجوج، ولا حتى واحد.
 */
class PayloadSocketFactory(
    private val proxyHost: String,
    private val proxyPort: Int,
    private val payloadTemplate: String,
    private val sniHost: String,
    private val usePayload: Boolean,
    private val useSsl: Boolean = false,
    private val sslSni: String = "",
    private val onLog: (String) -> Unit
) : SocketFactory {

    // السوكيت "الفعلي" لي كيتقرا/يتكتب منو فعلا - سوكيت TLS إلا كان useSsl
    // مفعّل، أو نفس السوكيت الخام إلا لا. جيتش كيسول getInputStream/
    // getOutputStream بالسوكيت الأصلي اللي رجّعناه من createSocket، ماشي
    // بالضرورة بالسوكيت المستعمل فعليا - فكنخزنو مرجع ليه هنا.
    private var activeSocket: Socket? = null

    // إلا كان السيرفر أكد WebSocket upgrade حقيقي (101 + احتاج framing)،
    // هاد الستريمز كتبدل الستريمز الخام ديال activeSocket فـ
    // getInputStream/getOutputStream تحت.
    private var wsInput: InputStream? = null
    private var wsOutput: OutputStream? = null

    /** TrustManager بلا تحقق من الشهادة - نفس المبدأ ديال StrictHostKeyChecking=no فالكود الحالي. */
    private object TrustAllManager : X509TrustManager {
        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
    }

    override fun createSocket(host: String, port: Int): Socket {
        val totalStart = SystemClock.elapsedRealtime()
        var socket: Socket = Socket()
        try {
            // TCP-level KeepAlive as a second line of defense under the
            // SSH-level ServerAlive settings: lets the OS detect a truly dead
            // link (e.g. NAT/carrier silently drops the mapping) without
            // waiting on the SSH layer alone. TcpNoDelay avoids Nagle-related
            // latency spikes on the small, frequent SSH/SOCKS packets.
            socket.keepAlive = true
            socket.tcpNoDelay = true
            socket.setPerformancePreferences(0, 2, 1) // prioritize low latency over bandwidth/connect-time
            // كبرنا الـTCP send/receive buffers (256KB) من القيمة الافتراضية
            // ديال الأندرويد (غالبا 64KB أو أقل). هاد السوكيت هو الوحيد لي
            // كيحمل كل حركة الـSSH (كل الـchannels multiplexed فوقو)، وحجم
            // البفر هو لي كيحدد قداش من بيانات يمكن تكون "فالطريق" قبل ما
            // تنتظر تأكيد - على شبكة فيها latency حقيقية (موبايل، سيرفر
            // بعيد)، بفر صغير كيولي هو السقف الحقيقي ديال السرعة حتى لو
            // كانت البندويث الفعلية أكبر بزاف. هاد التعديل ماكيغيّرش
            // البروتوكول ولا الإعدادات لي كيدخلها المستخدم - غير حجم
            // الذاكرة المحجوزة للسوكيت.
            socket.receiveBufferSize = 256 * 1024
            socket.sendBufferSize = 256 * 1024
        } catch (_: Throwable) { }
        onLog("TCP Connecting...")
        try {
            socket.connect(InetSocketAddress(proxyHost, proxyPort), 2000)
        } catch (e: Throwable) {
            try { socket.close() } catch (_: Throwable) {}
            throw e
        }
        onLog("TCP Socket Connected. (${SystemClock.elapsedRealtime() - totalStart} ms)")

        if (useSsl) {
            val sslStart = SystemClock.elapsedRealtime()
            socket = wrapWithSsl(socket, sslSni.ifBlank { sniHost })
            onLog("SSL Handshake Successful. (${SystemClock.elapsedRealtime() - sslStart} ms)")
        }

        if (usePayload && payloadTemplate.isNotBlank()) {
            // [rotate=host1;host2;...] - مستعملة فـconfigs مستوردة من
            // تطبيقات أخرى (HTTP Custom / HTTP Tweak) باش تبدل الـHost
            // header بين بزاف ديال الدومينات فكل محاولة اتصال، عوض واحد
            // ثابت (كيصعب على الـDPI يبلوكيه). كنختارو واحد عشوائي من
            // اللائحة فكل نداء ليهاد الدالة (يعني كل محاولة/reconnect).
            var payload = ROTATE_REGEX.replace(payloadTemplate) { m ->
                val options = m.groupValues[1].split(";").map { it.trim() }.filter { it.isNotEmpty() }
                if (options.isEmpty()) "" else options.random()
            }
                .replace("[crlf]", "\r\n")
                .replace("[lf]", "\n")
                .replace("[host]", sniHost)
                .replace("[split]", "")

            // بعض السيرفرات (بحال Google Cloud Run وأي reverse proxy وراه)
            // كتاخد "Upgrade: websocket" على محمل الجد حقيقي - عندها كتقبل
            // الـHTTP request الأولي (101) ولكن كتسد الكونكسيون فورا إلا
            // ماكانتش البيانات الجاية بعدها مؤطرة بشكل WebSocket frame
            // حقيقي (RFC 6455)، ماشي bytes خام بحال SSH-PROXY-PAYLOAD
            // العادي. كنكتشفو هاد الحالة من الهيدر نفسو، ونزيدو
            // Sec-WebSocket-Key/Version إلا كانا ناقصين فـpayload
            // المستخدم (خاصين للـhandshake يكون صحيح فنظر السيرفر).
            val isWebSocketUpgrade = WS_UPGRADE_HEADER_REGEX.containsMatchIn(payload)
            if (isWebSocketUpgrade && !payload.contains("Sec-WebSocket-Key", ignoreCase = true)) {
                val keyBytes = ByteArray(16)
                SecureRandom().nextBytes(keyBytes)
                val wsKey = android.util.Base64.encodeToString(keyBytes, android.util.Base64.NO_WRAP)
                val extraHeaders = "Sec-WebSocket-Key: $wsKey\r\nSec-WebSocket-Version: 13\r\n"
                val blankLineIdx = payload.lastIndexOf("\r\n\r\n")
                payload = if (blankLineIdx >= 0) {
                    payload.substring(0, blankLineIdx + 2) + extraHeaders + "\r\n"
                } else {
                    payload + extraHeaders + "\r\n"
                }
            }

            socket.getOutputStream().write(payload.toByteArray(Charsets.ISO_8859_1))
            socket.getOutputStream().flush()
            onLog("Payload Sent.")

            // Some payload/proxy servers (e.g. classic SSH-PROXY-PAYLOAD /
            // HTTP Custom style servers) reply with an HTTP status line
            // (e.g. "HTTP/1.1 101 Switching Protocols") before they open the
            // raw tunnel. If we hand the socket to JSch without consuming
            // that response first, JSch reads those HTTP bytes as if they
            // were the SSH banner and the handshake fails immediately -
            // this is the main cause of SSH-PROXY-PAYLOAD breaking.
            //
            // Other servers stay completely silent until SSH starts, so we
            // bound this read with a short timeout instead of blocking
            // indefinitely (that unbounded block was the ~16s issue this
            // code originally tried to avoid).
            val previousTimeout = try { socket.soTimeout } catch (_: Throwable) { 0 }
            var statusLine: String? = null
            try {
                socket.soTimeout = 2500
                statusLine = readHttpHeaders(socket)
                if (!statusLine.isNullOrBlank()) onLog(statusLine)
            } catch (_: Throwable) {
                // Timeout or read error: server is likely silent-until-SSH,
                // proceed and let JSch take over below.
            } finally {
                try { socket.soTimeout = previousTimeout } catch (_: Throwable) {}
            }
            onLog("Payload Accepted.")

            // السيرفر أكد الـWebSocket upgrade (101) - من هنا الاتصال
            // الخام ماخصوش يتقرا/يتكتب مباشرة، خاصو يتأطر بشكل WebSocket
            // frame حقيقي فكل الاتجاهين، وإلا reverse proxy السيرفر غادي
            // يسد الكونكسيون بمجرد ما يوصلو bytes SSH خام مو مؤطرين.
            if (isWebSocketUpgrade && statusLine?.contains("101") == true) {
                onLog("WebSocket Framing Active.")
                val rawIn = socket.getInputStream()
                val rawOut = socket.getOutputStream()
                wsInput = WebSocketInputStream(rawIn, rawOut)
                wsOutput = WebSocketOutputStream(rawOut)
            }
        }

        activeSocket = socket
        onLog("Socket Factory Ready. (${SystemClock.elapsedRealtime() - totalStart} ms total)")
        return socket
    }

    /** كيلف سوكيت TCP خام بـ TLS (SNI قابل للتخصيص)، بلا تحقق من الشهادة. */
    private fun wrapWithSsl(plain: Socket, sniName: String): SSLSocket {
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(TrustAllManager), SecureRandom())
        val sslSocket = sslContext.socketFactory.createSocket(
            plain, sniName, plain.port, true
        ) as SSLSocket

        try {
            val params = sslSocket.sslParameters
            params.serverNames = listOf(SNIHostName(sniName))
            sslSocket.sslParameters = params
        } catch (_: Throwable) {
            // SNI setting best-effort only - some devices/older TLS stacks
            // don't support it; the handshake below still proceeds normally.
        }

        // Limit the TLS handshake separately. The JSch connect timeout does
        // not fully cover the TLS handshake performed inside SocketFactory,
        // so leaving this unlimited can make SSH-TLS attempts stack up.
        try { sslSocket.soTimeout = 2500 } catch (_: Throwable) {}
        try {
            sslSocket.startHandshake()
        } catch (e: Throwable) {
            try { sslSocket.close() } catch (_: Throwable) {}
            throw e
        } finally {
            // JSch will apply its own SSH timeout after the socket is returned.
            try { sslSocket.soTimeout = 0 } catch (_: Throwable) {}
        }
        return sslSocket
    }

    /** كتقرا هيدرز الـ HTTP response بلا ما تسجل محتواها الخام (يقدر يحتوي على host/proxy معلومات). */
    private fun readHttpHeaders(socket: Socket): String? {
        val input = socket.getInputStream()
        val buf = StringBuilder()
        while (true) {
            val b = input.read()
            if (b == -1) break
            buf.append(b.toChar())
            if (buf.length >= 4 && buf.substring(buf.length - 4) == "\r\n\r\n") break
            if (buf.length > 8192) break // حماية من infinite loop
        }
        return buf.toString().lineSequence().firstOrNull()?.trim()
    }

    override fun getInputStream(socket: Socket): InputStream = wsInput ?: (activeSocket ?: socket).getInputStream()
    override fun getOutputStream(socket: Socket): OutputStream = wsOutput ?: (activeSocket ?: socket).getOutputStream()

    companion object {
        private val ROTATE_REGEX = Regex("""\[rotate=([^\]]*)]""", RegexOption.IGNORE_CASE)
        private val WS_UPGRADE_HEADER_REGEX = Regex("""upgrade\s*:\s*websocket""", RegexOption.IGNORE_CASE)
    }
}

/**
 * كتأطر كل write() فـWebSocket binary frame حقيقي (RFC 6455), ماسكة
 * بحال ما كيلزم لكل frame جاي من client. JSch كيدير write() بأحجام
 * عشوائية (حسب حجم كل SSH packet) - كل واحدة كتولي frame واحدة، بلا ما
 * تحتاج توافق مع "حدود رسالة" أي جهة أخرى، حيت الطرف الآخر (JSch فالجهة
 * التانية) كيقرا bytes متتالية بلا وعي بحدود الفريمات أصلا.
 */
private class WebSocketOutputStream(private val out: OutputStream) : OutputStream() {
    private val random = SecureRandom()
    private val lock = Any()

    override fun write(b: Int) {
        write(byteArrayOf(b.toByte()), 0, 1)
    }

    override fun write(b: ByteArray, off: Int, len: Int) {
        if (len <= 0) return
        val header = java.io.ByteArrayOutputStream()
        header.write(0x82) // FIN=1, opcode=0x2 (binary)
        val maskBit = 0x80
        when {
            len < 126 -> header.write(maskBit or len)
            len <= 0xFFFF -> {
                header.write(maskBit or 126)
                header.write((len shr 8) and 0xFF)
                header.write(len and 0xFF)
            }
            else -> {
                header.write(maskBit or 127)
                for (i in 7 downTo 0) header.write(((len.toLong() shr (i * 8)) and 0xFF).toInt())
            }
        }
        val maskKey = ByteArray(4)
        random.nextBytes(maskKey)
        header.write(maskKey)
        val masked = ByteArray(len)
        for (i in 0 until len) masked[i] = (b[off + i].toInt() xor maskKey[i % 4].toInt()).toByte()
        synchronized(lock) {
            out.write(header.toByteArray())
            out.write(masked)
            out.flush()
        }
    }

    override fun flush() {
        out.flush()
    }

    override fun close() {
        out.close()
    }
}

/**
 * كتفك كل WebSocket frame جاي من السيرفر (RFC 6455) وترجع غير الـpayload
 * bytes ديالها لـJSch - بلا ما تفرق بين text/binary/continuation (SSH
 * ماعندهاش حدود رسائل، غير stream متواصل ديال bytes). كتجاوب تلقائيا على
 * ping بـpong، وكتعتبر close frame نهاية الستريم (EOF عادي، ماشي error).
 */
private class WebSocketInputStream(
    private val input: InputStream,
    private val output: OutputStream
) : InputStream() {
    private var pending: ByteArray = ByteArray(0)
    private var pendingPos = 0
    private var streamClosed = false

    override fun read(): Int {
        val b = ByteArray(1)
        val n = read(b, 0, 1)
        return if (n <= 0) -1 else (b[0].toInt() and 0xFF)
    }

    override fun read(b: ByteArray, off: Int, len: Int): Int {
        if (len <= 0) return 0
        if (pendingPos >= pending.size) {
            if (!fillNextFrame()) return -1
        }
        val available = pending.size - pendingPos
        val toCopy = minOf(available, len)
        System.arraycopy(pending, pendingPos, b, off, toCopy)
        pendingPos += toCopy
        return toCopy
    }

    override fun available(): Int = (pending.size - pendingPos).coerceAtLeast(0)

    override fun close() {
        streamClosed = true
        input.close()
    }

    private fun readExact(n: Int): ByteArray {
        val buf = ByteArray(n)
        var read = 0
        while (read < n) {
            val r = input.read(buf, read, n - read)
            if (r == -1) throw java.io.EOFException("WebSocket stream closed by server")
            read += r
        }
        return buf
    }

    /** كتقرا frame واحدة كاملة وتحطها فـ[pending]. ترجع false غير عند close frame حقيقي (EOF عادي). */
    private fun fillNextFrame(): Boolean {
        if (streamClosed) return false
        while (true) {
            val first2 = readExact(2)
            val opcode = first2[0].toInt() and 0x0F
            val masked = (first2[1].toInt() and 0x80) != 0
            var length = (first2[1].toInt() and 0x7F).toLong()
            if (length == 126L) {
                val ext = readExact(2)
                length = (((ext[0].toInt() and 0xFF) shl 8) or (ext[1].toInt() and 0xFF)).toLong()
            } else if (length == 127L) {
                val ext = readExact(8)
                length = 0L
                for (i in 0 until 8) length = (length shl 8) or (ext[i].toInt() and 0xFF).toLong()
            }
            val maskKey = if (masked) readExact(4) else null
            val payload = if (length > 0) readExact(length.toInt()) else ByteArray(0)
            if (maskKey != null) {
                for (i in payload.indices) payload[i] = (payload[i].toInt() xor maskKey[i % 4].toInt()).toByte()
            }
            when (opcode) {
                0x0, 0x1, 0x2 -> {
                    // continuation/text/binary - كلهم كنعتبروهم غير bytes
                    // تابعة لنفس الستريم، بلا تمييز (شوف تعليق الكلاس).
                    pending = payload
                    pendingPos = 0
                    return true
                }
                0x8 -> { // close
                    streamClosed = true
                    return false
                }
                0x9 -> { // ping - نجاوبو pong ونكملو نقراو
                    sendPong(payload)
                    continue
                }
                else -> continue // pong (0xA) أو opcode غير معروف - كنتجاهلوه
            }
        }
    }

    private fun sendPong(payload: ByteArray) {
        try {
            val header = java.io.ByteArrayOutputStream()
            header.write(0x8A) // FIN=1, opcode=0xA (pong)
            val len = payload.size
            val maskBit = 0x80
            if (len < 126) {
                header.write(maskBit or len)
            } else {
                header.write(maskBit or 126)
                header.write((len shr 8) and 0xFF)
                header.write(len and 0xFF)
            }
            val maskKey = ByteArray(4)
            SecureRandom().nextBytes(maskKey)
            header.write(maskKey)
            val masked = ByteArray(len)
            for (i in payload.indices) masked[i] = (payload[i].toInt() xor maskKey[i % 4].toInt()).toByte()
            output.write(header.toByteArray())
            output.write(masked)
            output.flush()
        } catch (_: Throwable) {
            // best-effort - إلا فشل الـpong، السيرفر غادي يقفل الكونكسيون
            // بروحو (timeout) وJSch غادي يشوف EOF عادي.
        }
    }
}
