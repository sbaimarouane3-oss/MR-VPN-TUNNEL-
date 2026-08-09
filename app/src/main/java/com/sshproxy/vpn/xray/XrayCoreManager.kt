package com.sshproxy.vpn.xray

import android.content.Context
import java.io.File
import java.net.InetSocketAddress
import java.net.Socket

object XrayCoreManager {

    interface Listener {
        fun onXrayLog(message: String)
        fun onXrayCrashed(reason: String)
    }

    @Volatile private var controller: Any? = null
    @Volatile private var running = false
    private var listener: Listener? = null

    @Synchronized
    fun start(
        context: Context,
        configJson: String,
        localSocksPort: Int,
        listener: Listener,
        timeoutMs: Long = 15000
    ): Boolean {
        this.listener = listener
        stopInternal()

        try {
            val handler = buildCallbackHandler()
            val ctrl = newCoreController(handler)
            controller = ctrl

            setCoreEnv(context.filesDir.absolutePath)

            startLoop(ctrl, configJson)
        } catch (e: Throwable) {
            listener.onXrayLog("ERROR: Xray start failed - ${e.javaClass.simpleName}: ${e.message}")
            stopInternal()
            return false
        }

        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (isSocksReady(localSocksPort)) {
                running = true
                return true
            }
            if (!isCoreRunning()) {
                break
            }
            Thread.sleep(200)
        }

        listener.onXrayLog("ERROR: Xray SOCKS5 Proxy Not Ready.")
        stopInternal()
        return false
    }

    @Synchronized
    fun stop() {
        stopInternal()
    }

    private fun stopInternal() {
        running = false
        val ctrl = controller
        controller = null
        if (ctrl != null) {
            try {
                stopLoop(ctrl)
            } catch (_: Throwable) { }
        }
    }

    fun isRunning(): Boolean = running && isCoreRunning()

    private fun isSocksReady(port: Int): Boolean {
        return try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress("127.0.0.1", port), 500)
                socket.getOutputStream().write(byteArrayOf(0x05, 0x01, 0x00))
                socket.getOutputStream().flush()
                socket.soTimeout = 800
                val resp = ByteArray(2)
                val read = socket.getInputStream().read(resp)
                read == 2 && resp[0] == 0x05.toByte()
            }
        } catch (_: Throwable) {
            false
        }
    }

    private fun buildCallbackHandler(): libv2ray.CoreCallbackHandler {
        return object : libv2ray.CoreCallbackHandler {
            override fun startup(): Long = 0
            override fun shutdown(): Long {
                if (running) {
                    running = false
                    listener?.onXrayCrashed("Xray core stopped unexpectedly")
                }
                return 0
            }
            override fun onEmitStatus(p0: Long, p1: String?): Long {
                if (!p1.isNullOrBlank()) listener?.onXrayLog("Xray: $p1")
                return 0
            }
        }
    }

    private fun newCoreController(handler: libv2ray.CoreCallbackHandler): libv2ray.CoreController {
        return libv2ray.Libv2ray.newCoreController(handler)
    }

    private fun setCoreEnv(path: String) {
        try {
            libv2ray.Libv2ray.initCoreEnv(path, "")
        } catch (_: Throwable) { }
    }

    private fun startLoop(ctrl: Any, configJson: String) {
        (ctrl as libv2ray.CoreController).startLoop(configJson, 0)
    }

    private fun stopLoop(ctrl: Any) {
        (ctrl as libv2ray.CoreController).stopLoop()
    }

    private fun isCoreRunning(): Boolean {
        val ctrl = controller as? libv2ray.CoreController ?: return false
        return try { ctrl.isRunning } catch (_: Throwable) { false }
    }
}
