package com.sshproxy.vpn.importer

import org.json.JSONObject

/**
 * كونفيغ مستورد ومفكوك التشفير. المفاتيح مختصرة (h, p, u...) باش
 * الكود المشفر يبقى أقصر ما يمكن.
 */
data class ImportedConfig(
    val host: String,
    val port: Int,
    val user: String,
    val pass: String,
    val proxyHost: String,
    val proxyPort: Int,
    val payload: String,
    val usePayload: Boolean,
    val useSsl: Boolean = false,
    val sni: String = "",
    val udpgwEnabled: Boolean = false,
    val udpgwPort: Int = 7300,
    val importedAt: Long = System.currentTimeMillis()
) {
    fun toJson(): String {
        val o = JSONObject()
        o.put("h", host)
        o.put("p", port)
        o.put("u", user)
        o.put("w", pass)
        o.put("ph", proxyHost)
        o.put("pp", proxyPort)
        o.put("pl", payload)
        o.put("up", usePayload)
        o.put("us", useSsl)
        o.put("sn", sni)
        o.put("ug", udpgwEnabled)
        o.put("gp", udpgwPort)
        o.put("t", importedAt)
        return o.toString()
    }

    /** كنعرضو غير معلومة ماسكة فالواجهة، بلا ما نبينو host/user/pass الحقيقيين. */
    /** كتحدد اسم البروتوكول المفعّل حسب useSsl/usePayload/Proxy، بنفس التسمية القياسية
     *  المستعملة فتطبيقات بحال NPV Tunnel / HTTP Custom (SSH-Direct, SSH-Proxy,
     *  SSH-Payload, SSH-Proxy-Payload, SSH-TLS, SSH-TLS-Proxy, SSH-TLS-Payload,
     *  SSH-TLS-Proxy-Payload). الـ Proxy كيتحسب تلقائيًا: مفعّل إلا كان
     *  Remote Proxy Host/Port مختلفين عن SSH Host/Port. */
    fun protocolLabel(): String {
        val usesProxy = proxyHost.isNotBlank() && (proxyHost != host || proxyPort != port)
        val parts = StringBuilder("SSH")
        if (useSsl) parts.append("-TLS")
        if (usesProxy) parts.append("-Proxy")
        if (usePayload) parts.append("-Payload")
        return if (parts.toString() == "SSH") "SSH-Direct" else parts.toString()
    }

    fun maskedSummary(): String {
        val hostMasked = maskHost(host)
        return "Config imported ✓  (Server: $hostMasked)  •  Protocol: ${protocolLabel()}"
    }

    private fun maskHost(h: String): String {
        if (h.length <= 4) return "****"
        val visible = h.take(2)
        return "$visible${"*".repeat((h.length - 2).coerceAtMost(10))}"
    }

    companion object {
        fun fromJson(json: String): ImportedConfig {
            val o = JSONObject(json)
            return ImportedConfig(
                host = o.getString("h"),
                port = o.getInt("p"),
                user = o.getString("u"),
                pass = o.getString("w"),
                proxyHost = o.getString("ph"),
                proxyPort = o.getInt("pp"),
                payload = o.optString("pl", ""),
                usePayload = o.optBoolean("up", true),
                useSsl = o.optBoolean("us", false),
                sni = o.optString("sn", ""),
                udpgwEnabled = o.optBoolean("ug", false),
                udpgwPort = o.optInt("gp", 7300),
                importedAt = o.optLong("t", System.currentTimeMillis())
            )
        }
    }
}
