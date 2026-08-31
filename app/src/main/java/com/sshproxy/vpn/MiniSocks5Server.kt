package com.sshproxy.vpn

import com.jcraft.jsch.ChannelDirectTCPIP
import com.jcraft.jsch.Session
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors

// 64KB بدل 8KB: تقليل عدد قراءات/كتابات النظام (syscalls) لكل ميغابايت
// منقول - كل read()/write() كيكلف context switch، فبكبر البفر كنقصو
// العدد ديالهم بزاف من غير ما نبدلو أي منطق. هادشي كيربح خصوصا فـ
// التحميل/الرفع الكبير فين البوتلنيك هو عدد الـsyscalls ماشي البندويث
// نفسها.
private const val PIPE_BUFFER_SIZE = 64 * 1024

/**
 * SOCKS5 server صغير وخفيف كيخدم فوق JSch Session.
 * JSch مافيهاش دعم native ديال "-D" (dynamic port forwarding بحال ssh command)،
 * فهاد الكلاس كيعوضها: كيقبل اتصالات SOCKS5 محلية، وكل اتصال كيفتحلو
 * "direct-tcpip" channel عبر SSH session، وكيربط البيانات فالجوج اتجاهات.
 */
class MiniSocks5Server(
    private val session: Session,
    private val bindHost: String,
    private val port: Int,
    private val onLog: (String) -> Unit
) {
    @Volatile private var running = false
    private var serverSocket: ServerSocket? = null
    private val pool = Executors.newCachedThreadPool()
    private val forwardFailCount = java.util.concurrent.atomic.AtomicInteger(0)

    /** True only while the accept loop is alive AND the bound socket is still open - used by the connection monitor. */
    fun isRunning(): Boolean = running && serverSocket?.isClosed == false

    fun start() {
        running = true
        val ss = ServerSocket()
        ss.reuseAddress = true
        ss.bind(InetSocketAddress(bindHost, port))
        serverSocket = ss
        pool.execute {
            while (running) {
                try {
                    val client = ss.accept()
                    pool.execute { handleClient(client) }
                } catch (e: IOException) {
                    if (running) onLog("WARN: SOCKS5 Accept Error.")
                }
            }
        }
    }

    fun stop() {
        running = false
        try { serverSocket?.close() } catch (_: Exception) { }
        pool.shutdownNow()
    }

    private fun handleClient(client: Socket) {
        var channel: ChannelDirectTCPIP? = null
        try {
            client.tcpNoDelay = true
            val input = client.getInputStream()
            val output = client.getOutputStream()

            // --- SOCKS5 greeting ---
            val ver = input.read()
            if (ver != 0x05) { client.close(); return }
            val nMethods = input.read()
            val methods = ByteArray(nMethods)
            readFully(input, methods)
            // بلا auth (0x00) - كافي هنا حيت الـSOCKS5 محلي فقط (127.0.0.1)
            output.write(byteArrayOf(0x05, 0x00))
            output.flush()

            // --- SOCKS5 request ---
            val reqVer = input.read()
            val cmd = input.read()
            input.read() // reserved
            val atyp = input.read()
            if (reqVer != 0x05 || cmd != 0x01) { // كنديرو غير CONNECT
                sendReply(output, 0x07) // command not supported
                client.close()
                return
            }

            val targetHost: String
            when (atyp) {
                0x01 -> { // IPv4
                    val addr = ByteArray(4)
                    readFully(input, addr)
                    targetHost = "${addr[0].toInt() and 0xFF}.${addr[1].toInt() and 0xFF}." +
                        "${addr[2].toInt() and 0xFF}.${addr[3].toInt() and 0xFF}"
                }
                0x03 -> { // domain name
                    val len = input.read()
                    val domain = ByteArray(len)
                    readFully(input, domain)
                    targetHost = String(domain, Charsets.US_ASCII)
                }
                else -> { // IPv6 وأنواع أخرى - ماشي مدعومين هنا
                    sendReply(output, 0x08)
                    client.close()
                    return
                }
            }
            val portHi = input.read()
            val portLo = input.read()
            val targetPort = (portHi shl 8) or portLo

            // --- فتح direct-tcpip channel عبر SSH ---
            channel = session.openChannel("direct-tcpip") as ChannelDirectTCPIP
            channel.setHost(targetHost)
            channel.setPort(targetPort)
            try {
                channel.connect(10000)
            } catch (e: Exception) {
                // مهم: خاصنا نبعتو رد فشل SOCKS5 صريح هنا (ماشي نسكتو)
                // - بلا هادشي، العميل (hev-socks5-tunnel/المتصفح) كيبقى
                // معلق كيستنى جواب ماغاديش يجي (بحال DNS_PROBE_STARTED
                // بلا نهاية فالمتصفح)، بدل ما يفشل بسرعة برسالة واضحة.
                // هادشي وارد بزاف مع سيرفرات كتقيد الـforwarding نحو
                // بعض الوجهات (بحال DNS servers) بحال ماكانش خدام مع
                // الداتا العادية.
                //
                // تسجيل محدود (أول 5 مرات غير) باش يبين للمستخدم علاش
                // "متصل" ولكن الإنترنت ماخدامش - بلا ما نغرقو اللوگ إلا
                // كانت بزاف الاتصالات كتفشل بسرعة (بحال إعلانات محجوبة
                // أو بورتات مرفوضة، شي عادي فأي تصفح).
                if (forwardFailCount.incrementAndGet() <= 5) {
                    onLog("WARN: Forwarding to $targetHost:$targetPort refused by server (${e.javaClass.simpleName}: ${e.message}).")
                }
                sendReply(output, 0x05) // Connection refused
                client.close()
                return
            }

            sendReply(output, 0x00) // success

            val chIn = channel.inputStream
            val chOut = channel.outputStream

            // Reuse the existing cached thread pool for both pipe directions
            // instead of spawning two brand-new raw Thread objects per
            // connection - fewer threads created/torn down overall, which
            // matters since a browsing session opens many short-lived
            // connections.
            val f1 = pool.submit { pipe(input, chOut) }
            val f2 = pool.submit { pipe(chIn, output) }
            try { f1.get() } catch (_: Exception) { }
            try { f2.get() } catch (_: Exception) { }

        } catch (_: Exception) {
            // صامت - الاتصالات كتنقطع بشكل طبيعي بزاف، ماخاصناش نعمرو الـlog
        } finally {
            try { channel?.disconnect() } catch (_: Exception) { }
            try { client.close() } catch (_: Exception) { }
        }
    }

    private fun sendReply(output: OutputStream, code: Int) {
        output.write(byteArrayOf(0x05, code.toByte(), 0x00, 0x01, 0, 0, 0, 0, 0, 0))
        output.flush()
    }

    private fun readFully(input: InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n == -1) throw IOException("stream closed")
            off += n
        }
    }

    private fun pipe(from: InputStream, to: OutputStream) {
        val buffer = ByteArray(PIPE_BUFFER_SIZE)
        try {
            while (true) {
                val n = from.read(buffer)
                if (n == -1) break
                to.write(buffer, 0, n)
                // flush() بعد كل قراءة باقية ضرورية هنا: الـSOCKS client
                // socket خام (بلا buffering) فـflush() عليه no-op وما
                // كيكلفش والو، أما الـchannel.outputStream ديال JSch
                // فكيبفر داخليا - flush() هو لي كيدفعها تتبعث كـSSH
                // packet مباشرة بدل ما تبقى واقفة. حذفها كانت غادي تزيد
                // latency (خصوصا فالتصفح العادي) باش نربحو throughput
                // زهيد جدا - التبديل ماشي مستاهل.
                to.flush()
            }
        } catch (_: Exception) {
        } finally {
            try { to.close() } catch (_: Exception) { }
        }
    }
}
