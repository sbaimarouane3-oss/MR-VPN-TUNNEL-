package com.sshproxy.vpn.xray

import org.json.JSONObject

/**
 * تمثيل موحّد لأي config V2Ray/Xray بعد الـparse، كيفما كان مصدرو
 * (vless:// / vmess:// / trojan:// / ss:// / Xray JSON). هاد الشكل
 * هو اللي كيدخل لـ XrayConfigBuilder باش يبني الـoutbound الصالح لـXray.
 *
 * ملاحظة: rawOutboundJson (إذا كان موجود، أي جا من "Xray JSON" import)
 * كيتاخد بحالو مباشرة بدون إعادة بناء - الحقول الأخرى فهاد الحالة
 * كيبقاو غير للعرض فالواجهة (اسم، سيرفر، بورت...).
 */
data class ParsedProxyConfig(
    val protocol: ProxyProtocol,
    val remark: String = "",
    val address: String = "",
    val port: Int = 0,

    // VLESS / VMess
    val id: String = "",              // UUID
    val encryption: String = "none",  // VLESS: عادة "none"
    val alterId: Int = 0,             // VMess فقط (legacy، غالباً 0)
    val vmessSecurity: String = "auto", // VMess: auto/aes-128-gcm/chacha20-poly1305/none
    val flow: String = "",            // VLESS: "" أو "xtls-rprx-vision"

    // Trojan
    val password: String = "",

    // Shadowsocks
    val ssMethod: String = "",        // مثلاً aes-256-gcm, chacha20-ietf-poly1305
    val ssPassword: String = "",

    // Transport (network)
    val network: String = "tcp",      // tcp | ws | grpc | http (h2) | xhttp
    val path: String = "",            // WS / XHTTP path
    val hostHeader: String = "",      // WS / H2 Host header
    val serviceName: String = "",     // gRPC serviceName
    val headerType: String = "none",  // tcp header type (none/http)

    // TLS / Reality
    val security: String = "none",    // none | tls | reality
    val sni: String = "",
    val fingerprint: String = "chrome", // uTLS fingerprint
    val alpn: String = "",            // مفصولة بفواصل: "h2,http/1.1"
    val allowInsecure: Boolean = false,
    val publicKey: String = "",       // Reality pbk
    val shortId: String = "",         // Reality sid
    val spiderX: String = "",         // Reality spx

    // إذا الاستيراد كان بصيغة Xray JSON كاملة، كنخزنو الـoutbound
    // بحالو، وXrayConfigBuilder غادي يستعملو مباشرة بلا إعادة بناء.
    val rawOutboundJson: String? = null
) {
    enum class ProxyProtocol { VLESS, VMESS, TROJAN, SHADOWSOCKS }

    fun summary(): String {
        val host = if (address.length <= 4) "****" else address.take(2) + "*".repeat((address.length - 2).coerceAtMost(10))
        val label = "${protocol.name} • $network${if (security != "none") "+$security" else ""}"
        return "Config imported ✓  (Server: $host:$port)  •  $label"
    }

    /** كنستعملوه باش نديرو pass لهاد الكونفيغ عبر Intent extra وحدة لـ SshVpnService. */
    fun toJson(): String {
        val o = JSONObject()
        o.put("protocol", protocol.name)
        o.put("remark", remark)
        o.put("address", address)
        o.put("port", port)
        o.put("id", id)
        o.put("encryption", encryption)
        o.put("alterId", alterId)
        o.put("vmessSecurity", vmessSecurity)
        o.put("flow", flow)
        o.put("password", password)
        o.put("ssMethod", ssMethod)
        o.put("ssPassword", ssPassword)
        o.put("network", network)
        o.put("path", path)
        o.put("hostHeader", hostHeader)
        o.put("serviceName", serviceName)
        o.put("headerType", headerType)
        o.put("security", security)
        o.put("sni", sni)
        o.put("fingerprint", fingerprint)
        o.put("alpn", alpn)
        o.put("allowInsecure", allowInsecure)
        o.put("publicKey", publicKey)
        o.put("shortId", shortId)
        o.put("spiderX", spiderX)
        if (rawOutboundJson != null) o.put("rawOutboundJson", rawOutboundJson)
        return o.toString()
    }

    companion object {
        fun fromJson(json: String): ParsedProxyConfig {
            val o = JSONObject(json)
            return ParsedProxyConfig(
                protocol = ProxyProtocol.valueOf(o.getString("protocol")),
                remark = o.optString("remark", ""),
                address = o.optString("address", ""),
                port = o.optInt("port", 0),
                id = o.optString("id", ""),
                encryption = o.optString("encryption", "none"),
                alterId = o.optInt("alterId", 0),
                vmessSecurity = o.optString("vmessSecurity", "auto"),
                flow = o.optString("flow", ""),
                password = o.optString("password", ""),
                ssMethod = o.optString("ssMethod", ""),
                ssPassword = o.optString("ssPassword", ""),
                network = o.optString("network", "tcp"),
                path = o.optString("path", ""),
                hostHeader = o.optString("hostHeader", ""),
                serviceName = o.optString("serviceName", ""),
                headerType = o.optString("headerType", "none"),
                security = o.optString("security", "none"),
                sni = o.optString("sni", ""),
                fingerprint = o.optString("fingerprint", "chrome"),
                alpn = o.optString("alpn", ""),
                allowInsecure = o.optBoolean("allowInsecure", false),
                publicKey = o.optString("publicKey", ""),
                shortId = o.optString("shortId", ""),
                spiderX = o.optString("spiderX", ""),
                rawOutboundJson = if (o.has("rawOutboundJson")) o.getString("rawOutboundJson") else null
            )
        }
    }
}
