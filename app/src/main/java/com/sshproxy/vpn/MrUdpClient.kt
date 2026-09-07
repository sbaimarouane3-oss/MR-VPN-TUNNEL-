package com.sshproxy.vpn

import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * MR-UDP v1 client.
 *
 * It exposes a local SOCKS5 listener. TCP streams are multiplexed over one
 * encrypted UDP socket. UDP ASSOCIATE is also supported for datagrams.
 * The matching server is mr_udp_server.py supplied with this project.
 */
class MrUdpClient(
    private val serverHost: String,
    private val serverPort: Int,
    private val username: String,
    private val password: String,
    private val onLog: (String) -> Unit,
    private val requestedLocalPort: Int = 0
) : Closeable {
    companion object {
        private const val MAGIC = 0x4D525550 // MRUP
        private const val VERSION: Byte = 1
        private const val HELLO: Byte = 1
        private const val HELLO_OK: Byte = 2
        private const val OPEN: Byte = 3
        private const val OPEN_OK: Byte = 4
        private const val DATA: Byte = 5
        private const val ACK: Byte = 6
        private const val CLOSE: Byte = 7
        private const val UDP: Byte = 8
        private const val PING: Byte = 9
        private const val MAX_PAYLOAD = 1100
        private const val ACK_TIMEOUT_MS = 1800
        private const val MAX_RETRIES = 5
    }

    private val random = SecureRandom()
    private val socket = DatagramSocket()
    private val remote = InetSocketAddress(serverHost, serverPort)
    private val pool = Executors.newCachedThreadPool()
    private val streams = ConcurrentHashMap<Int, MrStream>()
    private val udpWaiters = ConcurrentHashMap<Int, (ByteArray) -> Unit>()
    private val udpLastSeen = ConcurrentHashMap<Int, Long>()
    private val lock = Any()
    private val key = SecretKeySpec(sha256(password.toByteArray(Charsets.UTF_8)), "AES")
    private var nextStreamId = random.nextInt().let { if (it == 0) 1 else it }
    @Volatile private var running = false
    @Volatile private var authenticated = false
    private var socksServer: ServerSocket? = null

    val localPort: Int get() = socksServer?.localPort ?: 0

    fun start(): Int {
        if (running) return localPort
        running = true
        socket.soTimeout = 1000
        pool.execute { receiveLoop() }
        authenticate()
        val ss = ServerSocket()
        ss.reuseAddress = true
        ss.bind(InetSocketAddress("127.0.0.1", requestedLocalPort))
        socksServer = ss
        pool.execute {
            while (running) {
                try {
                    val client = ss.accept()
                    pool.execute { handleSocks(client) }
                } catch (_: IOException) {
                    if (running) onLog("WARN: MR-UDP SOCKS listener stopped.")
                }
            }
        }
        onLog("MR-UDP SOCKS5 Ready on 127.0.0.1:${ss.localPort}")
        return ss.localPort
    }

    private fun authenticate() {
        val payload = ByteArrayOutputStreamCompat()
        payload.writeUtf8(username)
        payload.writeUtf8(password)
        send(HELLO, 0, 0, payload.toByteArray())
        val deadline = System.currentTimeMillis() + 10000
        while (running && !authenticated && System.currentTimeMillis() < deadline) Thread.sleep(50)
        if (!authenticated) throw IOException("MR-UDP authentication failed")
        onLog("MR-UDP authenticated.")
    }

    private fun handleSocks(client: Socket) {
        try {
            client.tcpNoDelay = true
            client.soTimeout = 0
            val input = client.getInputStream()
            val output = client.getOutputStream()
            if (input.read() != 5) return
            val n = input.read()
            if (n < 0) return
            val methods = ByteArray(n)
            readFully(input, methods)
            output.write(byteArrayOf(5, 0)); output.flush()
            if (input.read() != 5) return
            val cmd = input.read()
            input.read()
            val atyp = input.read()
            val host = when (atyp) {
                1 -> { val b = ByteArray(4); readFully(input, b); b.joinToString(".") { (it.toInt() and 255).toString() } }
                3 -> { val l = input.read(); val b = ByteArray(l); readFully(input, b); String(b, Charsets.US_ASCII) }
                4 -> { val b = ByteArray(16); readFully(input, b); java.net.InetAddress.getByAddress(b).hostAddress }
                else -> return
            }
            val hi = input.read(); val lo = input.read()
            val port = (hi shl 8) or lo
            when (cmd) {
                1 -> {
                    val stream = openStream(host, port)
                    output.write(byteArrayOf(5, 0, 0, 1, 0, 0, 0, 0, 0, 0)); output.flush()
                    pool.execute { pipeSocketToStream(input, stream) }
                    pool.execute { pipeStreamToSocket(stream, output) }
                    while (!stream.closed && !client.isClosed) Thread.sleep(200)
                }
                3 -> handleUdpAssociate(client, output)
                else -> output.write(byteArrayOf(5, 7, 0, 1, 0, 0, 0, 0, 0, 0))
            }
        } catch (_: Throwable) {
        } finally { try { client.close() } catch (_: Throwable) {} }
    }

    private fun handleUdpAssociate(tcp: Socket, output: java.io.OutputStream) {
        val udpSock = DatagramSocket(0, java.net.InetAddress.getByName("127.0.0.1"))
        udpSock.soTimeout = 1000
        val p = udpSock.localPort
        output.write(byteArrayOf(5, 0, 0, 1, 127, 0, 0, 1, (p ushr 8).toByte(), p.toByte())); output.flush()
        pool.execute {
            val buf = ByteArray(65535)
            while (running && !tcp.isClosed) {
                try {
                    val dp = DatagramPacket(buf, buf.size); udpSock.receive(dp)
                    if (dp.length < 10 || buf[0].toInt() != 0 || buf[1].toInt() != 0) continue
                    val frag = buf[2].toInt(); if (frag != 0) continue
                    var off = 3
                    val atyp = buf[off++].toInt() and 255
                    val host = when (atyp) {
                        1 -> { val h = "${buf[off].toInt() and 255}.${buf[off+1].toInt() and 255}.${buf[off+2].toInt() and 255}.${buf[off+3].toInt() and 255}"; off += 4; h }
                        3 -> { val l = buf[off++].toInt() and 255; val h = String(buf, off, l, Charsets.US_ASCII); off += l; h }
                        else -> continue
                    }
                    val port = ((buf[off++].toInt() and 255) shl 8) or (buf[off++].toInt() and 255)
                    val data = buf.copyOfRange(off, dp.length)
                    sendUdp(host, port, data) { response ->
                        try {
                            val hb = java.net.InetAddress.getByName(host).address
                            val out = ByteArray(10 + response.size)
                            out[0]=0; out[1]=0; out[2]=0; out[3]=1
                            if (hb.size == 4) System.arraycopy(hb,0,out,4,4) else return@sendUdp
                            out[8]=(port ushr 8).toByte(); out[9]=port.toByte(); System.arraycopy(response,0,out,10,response.size)
                            udpSock.send(DatagramPacket(out,out.size,dp.address,dp.port))
                        } catch (_: Throwable) {}
                    }
                } catch (_: SocketTimeoutException) {}
                catch (_: Throwable) { break }
            }
            udpSock.close()
        }
    }

    private fun openStream(host: String, port: Int): MrStream {
        val id = synchronized(lock) { nextStreamId += 2; nextStreamId }
        val s = MrStream(id)
        streams[id] = s
        val target = ByteArrayOutputStreamCompat()
        target.writeUtf8(host); target.writeShort(port)
        send(OPEN, id, 0, target.toByteArray())
        if (!s.openLatch.await(10, TimeUnit.SECONDS)) { streams.remove(id); throw IOException("MR-UDP OPEN timeout") }
        if (!s.openAccepted) { streams.remove(id); throw IOException("MR-UDP remote connect failed") }
        return s
    }

    private fun sendUdp(host: String, port: Int, data: ByteArray, callback: (ByteArray)->Unit) {
        val id = synchronized(lock) { nextStreamId += 2; nextStreamId }
        udpWaiters[id] = callback
        udpLastSeen[id] = System.currentTimeMillis()
        val b = ByteArrayOutputStreamCompat(); b.writeUtf8(host); b.writeShort(port); b.write(data)
        send(UDP, id, 0, b.toByteArray())
        pool.execute {
            try {
                while (running) {
                    Thread.sleep(30_000)
                    val last = udpLastSeen[id] ?: break
                    if (System.currentTimeMillis() - last >= 30_000) {
                        udpWaiters.remove(id)
                        udpLastSeen.remove(id)
                        break
                    }
                }
            } catch (_: InterruptedException) {
            }
        }
    }

    private fun pipeSocketToStream(input: java.io.InputStream, s: MrStream) {
        val buf = ByteArray(MAX_PAYLOAD)
        try { while (running && !s.closed) { val n=input.read(buf); if(n<0) break; s.write(buf,0,n) } } catch (_:Throwable) {} finally { s.close() }
    }
    private fun pipeStreamToSocket(s: MrStream, out: java.io.OutputStream) {
        try { while (running && !s.closed) { val data=s.read(); if(data==null) break; out.write(data); out.flush() } } catch (_:Throwable) {} finally { try{out.close()}catch(_:Throwable){}; s.close() }
    }

    private fun receiveLoop() {
        val buf = ByteArray(65535)
        while (running) {
            try {
                val dp = DatagramPacket(buf, buf.size); socket.receive(dp)
                val packet = decrypt(buf.copyOfRange(0, dp.length)) ?: continue
                if (packet.size < 13) continue
                val type=packet[0]; val id=ByteBuffer.wrap(packet,1,4).int; val seq=ByteBuffer.wrap(packet,5,4).int
                val payload=packet.copyOfRange(13,packet.size)
                when(type) {
                    HELLO_OK -> authenticated=true
                    OPEN_OK -> streams[id]?.let { it.markOpen(payload.isNotEmpty() && payload[0].toInt()==1); it.openLatch.countDown() }
                    DATA -> { streams[id]?.onData(seq,payload); send(ACK,id,seq,ByteArray(0)) }
                    ACK -> streams[id]?.onAck(seq)
                    CLOSE -> streams.remove(id)?.remoteClose()
                    UDP -> {
                        udpLastSeen[id] = System.currentTimeMillis()
                        udpWaiters[id]?.invoke(payload)
                    }
                    PING -> send(PING,0,seq,ByteArray(0))
                }
            } catch (_:SocketTimeoutException) {} catch (_:Throwable) { if(running) onLog("WARN: MR-UDP transport stopped."); break }
        }
    }

    private fun send(type: Byte, id: Int, seq: Int, payload: ByteArray) {
        if (!running) return
        val plain = ByteBuffer.allocate(13 + payload.size).apply { put(type); putInt(id); putInt(seq); putInt(payload.size); put(payload) }.array()
        val encrypted = encrypt(plain)
        socket.send(DatagramPacket(encrypted, encrypted.size, remote))
    }

    private fun encrypt(plain: ByteArray): ByteArray {
        val nonce=ByteArray(12); random.nextBytes(nonce); val c=Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.ENCRYPT_MODE,key,GCMParameterSpec(128,nonce)); val ct=c.doFinal(plain); return nonce+ct
    }
    private fun decrypt(data:ByteArray):ByteArray? { if(data.size<28)return null; return try { val nonce=data.copyOfRange(0,12); val ct=data.copyOfRange(12,data.size); val c=Cipher.getInstance("AES/GCM/NoPadding"); c.init(Cipher.DECRYPT_MODE,key,GCMParameterSpec(128,nonce)); c.doFinal(ct) } catch(_:Throwable){null} }
    private fun readFully(input: java.io.InputStream,b:ByteArray){var o=0;while(o<b.size){val n=input.read(b,o,b.size-o);if(n<0)throw IOException("closed");o+=n}}

    override fun close() {
        running=false; authenticated=false
        try{socksServer?.close()}catch(_:Throwable){}
        streams.values.forEach{it.close()}; streams.clear(); udpWaiters.clear(); udpLastSeen.clear()
        try{socket.close()}catch(_:Throwable){}
        pool.shutdownNow()
    }

    inner class MrStream(val id:Int) {
        val openLatch=java.util.concurrent.CountDownLatch(1)
        @Volatile var openAccepted=false; @Volatile var closed=false
        private var sendSeq=0; private var recvSeq=0
        private val queue=java.util.concurrent.LinkedBlockingQueue<ByteArray>()
        private val ackLock=Object(); private var lastAck=-1
        fun markOpen(ok:Boolean){openAccepted=ok}
        fun write(src:ByteArray,off:Int,len:Int){var p=off;val end=off+len;while(p<end&&!closed){val n=minOf(MAX_PAYLOAD,end-p);val chunk=src.copyOfRange(p,p+n);sendReliable(chunk);p+=n}}
        private fun sendReliable(data:ByteArray){val seq= synchronized(ackLock){sendSeq++}; var tries=0; while(running&&!closed&&tries++<MAX_RETRIES){send(DATA,id,seq,data);synchronized(ackLock){if(lastAck>=seq)return;ackLock.wait(ACK_TIMEOUT_MS.toLong())}};if(tries>=MAX_RETRIES)close()}
        fun onAck(seq:Int){synchronized(ackLock){if(seq>lastAck)lastAck=seq;ackLock.notifyAll()}}
        fun onData(seq:Int,data:ByteArray){if(seq==recvSeq){queue.offer(data);recvSeq++} }
        fun read():ByteArray?{while(running&&!closed){val x=queue.poll(1,TimeUnit.SECONDS);if(x!=null)return x};return null}
        fun remoteClose(){closed=true;queue.offer(ByteArray(0))}
        fun close(){if(!closed){closed=true;send(CLOSE,id,0,ByteArray(0));streams.remove(id)}}
    }

    private class ByteArrayOutputStreamCompat {
        private val out=java.io.ByteArrayOutputStream()
        fun writeUtf8(s:String){val b=s.toByteArray(Charsets.UTF_8);writeShort(b.size);out.write(b)}
        fun writeShort(v:Int){out.write((v ushr 8) and 255);out.write(v and 255)}
        fun write(b:ByteArray){out.write(b)}
        fun toByteArray()=out.toByteArray()
    }
    private fun sha256(b:ByteArray)=MessageDigest.getInstance("SHA-256").digest(b)
}
