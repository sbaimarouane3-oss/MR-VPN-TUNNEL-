package com.sshproxy.vpn

object CrashGuard {
    @Volatile private var loaded = false
    @Volatile private var installed = false

    fun installIfPossible(logPath: String): String {
        return try {
            if (!loaded) {
                System.loadLibrary("crash-guard")
                loaded = true
            }
            if (!installed) {
                install(logPath)
                installed = true
            }
            "crash guard OK"
        } catch (e: Throwable) {
            "crash guard FAILED: ${e.javaClass.simpleName}: ${e.message}"
        }
    }

    @JvmStatic
    external fun install(logPath: String)
}
