package com.sshproxy.vpn.xray

import android.util.Base64
import org.json.JSONException
import org.json.JSONObject
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * كيقرا أي config V2Ray/Xray (vless:// vmess:// trojan:// ss:// أو Xray
 * JSON كامل) وكيرجع ParsedProxyConfig موحّد. أي خطأ فالصيغة كيطلع
 * IllegalArgumentException برسالة واضحة (باش تتعرض للمستخدم كيفما هي).
 *
 * هاد الملف جديد بالكامل - ماكيمسش والو من importer/ الموجود لي خاص
 * بـMRVPN:// (SSH). الاثنين خدامين جنب بعضياتهم.
 */
object XrayConfigParser {

    /** كيتعرف تلقائياً على نوع الرابط/الكونفيغ ويرجّع ParsedProxyConfig. */
    fun parse(raw: String): ParsedProxyConfig {
        val input = raw.trim()
        if (input.isEmpty()) throw IllegalArgumentException("Config فارغ")

        return when {
            input.startsWith("vless://", ignoreCase = true) -> parseVless(input)
            input.startsWith("vmess://", ignoreCase = true) -> parseVmess(input)
            input.startsWith("trojan://", ignoreCase = true) -> parseTrojan(input)
            input.startsWith("ss://", ignoreCase = true) -> parseShadowsocks(input)
            input.trimStart().startsWith("{") -> parseXrayJson(input)
            else -> throw IllegalArgumentException(
                "صيغة غير معروفة. المدعومة: vless:// vmess:// trojan:// ss:// أو Xray JSON"
            )
        }
    }

    // ---------------------------------------------------------------
    // VLESS: vless://uuid@host:port?params...#remark
    // ---------------------------------------------------------------
    private fun parseVless(input: String): ParsedProxyConfig {
        val uri = safeUri(input, "vless")
        val userInfo = uri.userInfo ?: throw IllegalArgumentException("VLESS: ناقص UUID")
        val id = userInfo.trim()
        if (id.isEmpty()) throw IllegalArgumentException("VLESS: UUID فارغ")

        val host = uri.host ?: throw IllegalArgumentException("VLESS: ناقص السيرفر (host)")
        val port = requirePort(uri, "VLESS")
        val q = queryMap(input)

        return ParsedProxyConfig(
            protocol = ParsedProxyConfig.ProxyProtocol.VLESS,
            remark = fragmentOf(input),
            address = host,
            port = port,
            id = id,
            encryption = q["encryption"] ?: "none",
            flow = q["flow"] ?: "",
            network = normalizeNetwork(q["type"] ?: q["network"] ?: "tcp"),
            path = decodeOrEmpty(q["path"]),
            hostHeader = decodeOrEmpty(q["host"]),
            serviceName = decodeOrEmpty(q["serviceName"]),
            headerType = q["headerType"] ?: "none",
            security = normalizeSecurity(q["security"]),
            sni = q["sni"] ?: q["peer"] ?: host,
            fingerprint = q["fp"] ?: "chrome",
            alpn = decodeOrEmpty(q["alpn"]),
            allowInsecure = (q["allowInsecure"] == "1" || q["allowInsecure"] == "true"),
            publicKey = q["pbk"] ?: "",
            shortId = q["sid"] ?: "",
            spiderX = decodeOrEmpty(q["spx"])
        )
    }

    // ---------------------------------------------------------------
    // VMess: vmess://base64(JSON)   -- الصيغة القياسية (v2rayN style)
    // ---------------------------------------------------------------
    private fun parseVmess(input: String): ParsedProxyConfig {
        val b64 = input.removePrefix("vmess://").substringBefore("#").trim()
        val jsonText = try {
            String(decodeBase64(b64), StandardCharsets.UTF_8)
        } catch (e: Exception) {
            throw IllegalArgumentException("VMess: تعذّر فك التشفير (base64 غير صالح)")
        }

        val o = try {
            JSONObject(jsonText)
        } catch (e: JSONException) {
            throw IllegalArgumentException("VMess: JSON غير صالح داخل الرابط")
        }

        val host = o.optString("add").trim()
        if (host.isEmpty()) throw IllegalArgumentException("VMess: ناقص السيرفر (add)")
        val port = o.optString("port").toIntOrNull() ?: o.optInt("port", 0)
        if (port <= 0) throw IllegalArgumentException("VMess: بورت غير صالح")
        val id = o.optString("id").trim()
        if (id.isEmpty()) throw IllegalArgumentException("VMess: ناقص UUID (id)")

        val net = normalizeNetwork(o.optString("net", "tcp"))
        val tlsRaw = o.optString("tls", "")
        val alpn = o.optString("alpn", "")

        return ParsedProxyConfig(
            protocol = ParsedProxyConfig.ProxyProtocol.VMESS,
            remark = o.optString("ps", ""),
            address = host,
            port = port,
            id = id,
            alterId = o.optString("aid").toIntOrNull() ?: o.optInt("aid", 0),
            vmessSecurity = o.optString("scy", "auto").ifBlank { "auto" },
            network = net,
            path = o.optString("path", ""),
            hostHeader = o.optString("host", ""),
            serviceName = o.optString("path", ""), // فـVMess gRPC، serviceName كتنحط فـ"path"
            headerType = o.optString("type", "none").ifBlank { "none" },
            security = normalizeSecurity(tlsRaw),
            sni = o.optString("sni", "").ifBlank { host },
            fingerprint = o.optString("fp", "chrome").ifBlank { "chrome" },
            alpn = alpn,
            allowInsecure = false
        )
    }

    // ---------------------------------------------------------------
    // Trojan: trojan://password@host:port?params...#remark
    // ---------------------------------------------------------------
    private fun parseTrojan(input: String): ParsedProxyConfig {
        val uri = safeUri(input, "trojan")
        val password = uri.userInfo?.trim()
            ?: throw IllegalArgumentException("Trojan: ناقص Password")
        if (password.isEmpty()) throw IllegalArgumentException("Trojan: Password فارغ")

        val host = uri.host ?: throw IllegalArgumentException("Trojan: ناقص السيرفر (host)")
        val port = requirePort(uri, "Trojan")
        val q = queryMap(input)

        return ParsedProxyConfig(
            protocol = ParsedProxyConfig.ProxyProtocol.TROJAN,
            remark = fragmentOf(input),
            address = host,
            port = port,
            password = password,
            network = normalizeNetwork(q["type"] ?: q["network"] ?: "tcp"),
            path = decodeOrEmpty(q["path"]),
            hostHeader = decodeOrEmpty(q["host"]),
            serviceName = decodeOrEmpty(q["serviceName"]),
            headerType = q["headerType"] ?: "none",
            // Trojan ديما TLS إلا إذا تحدد security=none بوضوح
            security = if (q["security"] == "none") "none" else normalizeSecurity(q["security"] ?: "tls"),
            sni = q["sni"] ?: q["peer"] ?: host,
            fingerprint = q["fp"] ?: "chrome",
            alpn = decodeOrEmpty(q["alpn"]),
            allowInsecure = (q["allowInsecure"] == "1" || q["allowInsecure"] == "true"),
            publicKey = q["pbk"] ?: "",
            shortId = q["sid"] ?: "",
            spiderX = decodeOrEmpty(q["spx"])
        )
    }

    // ---------------------------------------------------------------
    // Shadowsocks: ss://base64(method:password)@host:port#remark
    //           أو ss://base64(method:password@host:port)#remark (قديمة)
    //           أو ss://method:password@host:port#remark (بلا تشفير)
    // ---------------------------------------------------------------
    private fun parseShadowsocks(input: String): ParsedProxyConfig {
        val body = input.removePrefix("ss://").substringBefore("#")

        // شكل قديم: كلشي مشفر بـbase64 (فيه @ بعد الفك)
        if (!body.contains("@")) {
            val decoded = try {
                String(decodeBase64(body), StandardCharsets.UTF_8)
            } catch (e: Exception) {
                throw IllegalArgumentException("Shadowsocks: صيغة غير صالحة")
            }
            return parseSsMethodPassAtHost(decoded, fragmentOf(input))
        }

        // شكل SIP002: base64(method:password)@host:port
        val at = body.lastIndexOf("@")
        val userPart = body.substring(0, at)
        val hostPart = body.substring(at + 1)

        val methodPass = try {
            String(decodeBase64(userPart), StandardCharsets.UTF_8)
        } catch (e: Exception) {
            // بعض الروابط كيخليو method:password بلا تشفير
            userPart
        }

        return parseSsMethodPassAtHost("$methodPass@$hostPart", fragmentOf(input))
    }

    private fun parseSsMethodPassAtHost(decoded: String, remark: String): ParsedProxyConfig {
        // الصيغة: method:password@host:port
        val at = decoded.lastIndexOf("@")
        if (at < 0) throw IllegalArgumentException("Shadowsocks: صيغة ناقصة (بلا @)")
        val methodPass = decoded.substring(0, at)
        val hostPort = decoded.substring(at + 1)

        val colonMp = methodPass.indexOf(":")
        if (colonMp < 0) throw IllegalArgumentException("Shadowsocks: ناقص method:password")
        val method = methodPass.substring(0, colonMp)
        val password = methodPass.substring(colonMp + 1)
        if (method.isBlank() || password.isBlank()) {
            throw IllegalArgumentException("Shadowsocks: method أو password فارغين")
        }

        val colonHp = hostPort.lastIndexOf(":")
        if (colonHp < 0) throw IllegalArgumentException("Shadowsocks: ناقص host:port")
        val host = hostPort.substring(0, colonHp)
        val port = hostPort.substring(colonHp + 1).toIntOrNull()
            ?: throw IllegalArgumentException("Shadowsocks: بورت غير صالح")

        return ParsedProxyConfig(
            protocol = ParsedProxyConfig.ProxyProtocol.SHADOWSOCKS,
            remark = remark,
            address = host,
            port = port,
            ssMethod = method,
            ssPassword = password,
            network = "tcp",
            security = "none"
        )
    }

    // ---------------------------------------------------------------
    // Xray JSON خام: إما config كامل {"outbounds":[...]}, إما outbound
    // واحد {"protocol":"vless","settings":{...},"streamSettings":{...}}
    // ---------------------------------------------------------------
    private fun parseXrayJson(input: String): ParsedProxyConfig {
        val root = try {
            JSONObject(input)
        } catch (e: JSONException) {
            throw IllegalArgumentException("Xray JSON: صيغة JSON غير صالحة")
        }

        val outbound: JSONObject = when {
            root.has("outbounds") -> {
                val arr = root.getJSONArray("outbounds")
                var chosen: JSONObject? = null
                for (i in 0 until arr.length()) {
                    val ob = arr.getJSONObject(i)
                    val proto = ob.optString("protocol")
                    if (proto in listOf("vless", "vmess", "trojan", "shadowsocks")) {
                        chosen = ob
                        break
                    }
                }
                chosen ?: throw IllegalArgumentException("Xray JSON: ماكاينش outbound صالح (vless/vmess/trojan/shadowsocks)")
            }
            root.has("protocol") -> root
            else -> throw IllegalArgumentException("Xray JSON: بنية غير معروفة")
        }

        val protocolName = outbound.optString("protocol")
        val protocol = when (protocolName) {
            "vless" -> ParsedProxyConfig.ProxyProtocol.VLESS
            "vmess" -> ParsedProxyConfig.ProxyProtocol.VMESS
            "trojan" -> ParsedProxyConfig.ProxyProtocol.TROJAN
            "shadowsocks" -> ParsedProxyConfig.ProxyProtocol.SHADOWSOCKS
            else -> throw IllegalArgumentException("Xray JSON: protocol غير مدعوم ($protocolName)")
        }

        // كنخزنو الـoutbound الخام بحالو - XrayConfigBuilder غادي يستعملو
        // مباشرة بلا إعادة بناء، هادشي كيضمن دعم كامل لأي parameter زائد
        // اللي مكاينش فالموديل الموحّد ديالنا.
        var address = ""
        var port = 0
        try {
            val settings = outbound.optJSONObject("settings")
            val vnextOrServers = settings?.optJSONArray("vnext") ?: settings?.optJSONArray("servers")
            val first = vnextOrServers?.optJSONObject(0)
            address = first?.optString("address", "") ?: ""
            port = first?.optInt("port", 0) ?: 0
        } catch (_: Exception) { /* غير للعرض، ماشي حرج */ }

        return ParsedProxyConfig(
            protocol = protocol,
            remark = outbound.optString("tag", "Imported"),
            address = address,
            port = port,
            rawOutboundJson = outbound.toString()
        )
    }

    // ================== Helpers ==================

    private fun safeUri(input: String, label: String): URI {
        return try {
            URI(input)
        } catch (e: Exception) {
            throw IllegalArgumentException("$label: رابط غير صالح")
        }
    }

    private fun requirePort(uri: URI, label: String): Int {
        val p = uri.port
        if (p <= 0) throw IllegalArgumentException("$label: بورت غير صالح")
        return p
    }

    private fun fragmentOf(input: String): String {
        val idx = input.indexOf('#')
        if (idx < 0 || idx == input.length - 1) return ""
        return try {
            URLDecoder.decode(input.substring(idx + 1), "UTF-8")
        } catch (_: Exception) {
            input.substring(idx + 1)
        }
    }

    /** كيقرا query parameters يدوياً (URI.getQuery كيهرب بعض الرموز بطريقة كتخربق الـpath). */
    private fun queryMap(input: String): Map<String, String> {
        val qStart = input.indexOf('?')
        if (qStart < 0) return emptyMap()
        var qEnd = input.indexOf('#', qStart)
        if (qEnd < 0) qEnd = input.length
        val query = input.substring(qStart + 1, qEnd)
        if (query.isBlank()) return emptyMap()

        return query.split("&").mapNotNull { pair ->
            if (pair.isBlank()) return@mapNotNull null
            val eq = pair.indexOf('=')
            if (eq < 0) return@mapNotNull pair to ""
            val key = pair.substring(0, eq)
            val value = try {
                URLDecoder.decode(pair.substring(eq + 1), "UTF-8")
            } catch (_: Exception) {
                pair.substring(eq + 1)
            }
            key to value
        }.toMap()
    }

    private fun decodeOrEmpty(v: String?): String = v ?: ""

    private fun normalizeNetwork(v: String): String {
        val n = v.lowercase().ifBlank { "tcp" }
        return when (n) {
            "h2", "http" -> "http"
            "ws" -> "ws"
            "grpc" -> "grpc"
            "xhttp", "splithttp" -> "xhttp"
            "tcp" -> "tcp"
            else -> "tcp"
        }
    }

    private fun normalizeSecurity(v: String?): String {
        val s = (v ?: "none").lowercase()
        return when (s) {
            "tls" -> "tls"
            "reality" -> "reality"
            "" , "none" -> "none"
            else -> "none"
        }
    }

    /** Base64 قابل لأنواع standard وurl-safe، وبلا padding. */
    private fun decodeBase64(input: String): ByteArray {
        var s = input.trim().replace("-", "+").replace("_", "/")
        val mod = s.length % 4
        if (mod != 0) s += "=".repeat(4 - mod)
        return Base64.decode(s, Base64.DEFAULT)
    }
}
