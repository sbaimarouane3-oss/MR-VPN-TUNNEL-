package com.sshproxy.vpn.xray

import org.json.JSONArray
import org.json.JSONObject

/**
 * كيبني Xray config كامل وصالح (JSON نصي) بدءاً من ParsedProxyConfig:
 *   inbound  = SOCKS5 محلي على 127.0.0.1:localSocksPort (نفس البورت اللي
 *              SshVpnService خدام بيه أصلاً مع hev-socks5-tunnel، بحال SSH)
 *   outbound = VLESS/VMess/Trojan/Shadowsocks مبني حسب transport/security
 *
 * ماكاينش أي parsing هنا - غير بناء. الأخطاء المحتملة (JSON غير صالح
 * بعد البناء) خاصها تتشاف من طرف Xray نفسو عند startLoop عبر
 * XrayCoreManager (يرجع الخطأ الحقيقي ديال Xray).
 */
object XrayConfigBuilder {

    fun build(cfg: ParsedProxyConfig, localSocksPort: Int): String {
        val root = JSONObject()

        root.put("log", JSONObject().apply {
            put("loglevel", "warning")
        })

        // Inbound: SOCKS5 محلي - نفسو اللي hev-socks5-tunnel كيتصل بيه،
        // بحال ماشي مضبوط مع MiniSocks5Server فمسار SSH. الـudp كيبقى true
        // ديما إلا كان البروتوكول Shadowsocks وقتها كيتبنى من chkSsUdp
        // (زر UDP فواجهة Shadowsocks) - باقي البروتوكولات ماتبدلاتش.
        val udpEnabled = if (cfg.protocol == ParsedProxyConfig.ProxyProtocol.SHADOWSOCKS) cfg.ssUdp else true
        root.put("inbounds", JSONArray().put(
            JSONObject().apply {
                put("listen", "127.0.0.1")
                put("port", localSocksPort)
                put("protocol", "socks")
                put("settings", JSONObject().apply {
                    put("udp", udpEnabled)
                    put("auth", "noauth")
                })
                put("sniffing", JSONObject().apply {
                    put("enabled", true)
                    put("destOverride", JSONArray().put("http").put("tls"))
                })
                put("tag", "socks-in")
            }
        ))

        val proxyOutbound = buildOutbound(cfg)
        root.put("outbounds", JSONArray()
            .put(proxyOutbound)
            .put(JSONObject().apply { put("protocol", "freedom"); put("tag", "direct") })
            .put(JSONObject().apply { put("protocol", "blackhole"); put("tag", "block") })
        )

        return root.toString()
    }

    /**
     * Xray-core الحديث (v26.2.6+) كيرفض نهائياً أي config فيه
     * "allowInsecure" (خاصية محذوفة رسمياً من Xray). البديل المهاجَر
     * عليه رسمياً هو "verifyPeerCertByName": كنتحققو من الشهادة
     * بالاسم الحقيقي ديال السيرفر (serverName/SNI المكتوب فالكونفيغ
     * نفسو) بدل عنوان الاتصال (cfg.address) - هادشي كيحل مشكلة
     * mismatch الشهادة بلا ما نعطلو التحقق كاملاً.
     *
     * ملاحظة مهمة (domain fronting): ملي address != SNI (بحال
     * address="crazygames.ro" و serverName="fast.iqiraq.shop")،
     * الشهادة لي كيرجعها السيرفر خاصها تطابق الـSNI (فين كتوجه TLS
     * الحقيقي)، ماشي عنوان الاتصال (اللي هو غير CDN/decoy). التحقق
     * بـcfg.address فهاد الحالة كان غلط وكيخلي التحقق يفشل ديما.
     *
     * إلا كان الاسم المستعمل IP خام (بلا دومين)، ماكاينش اسم نتحققو
     * بيه، وقتها كنكتفاو بحذف allowInsecure (تفادي crash ديال Xray)
     * بلا verifyPeerCertByName - قد يفشل TLS إلا كانت الشهادة
     * فعلاً غير متطابقة، لكن هادشي خارج عن تحكمنا فهاد الحالة.
     */
    private fun migrateAllowInsecure(outbound: JSONObject, cfg: ParsedProxyConfig) {
        try {
            val stream = outbound.optJSONObject("streamSettings") ?: return
            val tls = stream.optJSONObject("tlsSettings") ?: return
            if (!tls.has("allowInsecure")) return

            val wasInsecure = tls.optBoolean("allowInsecure", false)
            tls.remove("allowInsecure")

            // نفضلو serverName المكتوب فنفس الـtlsSettings (هو لي كيتصاوب
            // فعليا فالمصافحة/SNI) - بلا ما نرجعو لـcfg.sni أو cfg.address
            // إلا كان فارغ.
            val verifyName = tls.optString("serverName").ifBlank { cfg.sni.ifBlank { cfg.address } }
            val isRawIp = verifyName.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))
            if (wasInsecure && !isRawIp && verifyName.isNotBlank() && !tls.has("verifyPeerCertByName")) {
                tls.put("verifyPeerCertByName", verifyName)
            }
        } catch (_: Throwable) { }
    }

    private fun buildOutbound(cfg: ParsedProxyConfig): JSONObject {
        // Xray JSON خام (استيراد كامل) - كنستعملوه بحالو، غير كنضمنو الـtag.
        cfg.rawOutboundJson?.let {
            val ob = JSONObject(it)
            ob.put("tag", "proxy")
            migrateAllowInsecure(ob, cfg)
            return ob
        }

        val ob = JSONObject()
        ob.put("tag", "proxy")

        when (cfg.protocol) {
            ParsedProxyConfig.ProxyProtocol.VLESS -> {
                ob.put("protocol", "vless")
                ob.put("settings", JSONObject().apply {
                    put("vnext", JSONArray().put(JSONObject().apply {
                        put("address", cfg.address)
                        put("port", cfg.port)
                        put("users", JSONArray().put(JSONObject().apply {
                            put("id", cfg.id)
                            put("encryption", cfg.encryption.ifBlank { "none" })
                            if (cfg.flow.isNotBlank()) put("flow", cfg.flow)
                        }))
                    }))
                })
                ob.put("streamSettings", buildStreamSettings(cfg))
            }

            ParsedProxyConfig.ProxyProtocol.VMESS -> {
                ob.put("protocol", "vmess")
                ob.put("settings", JSONObject().apply {
                    put("vnext", JSONArray().put(JSONObject().apply {
                        put("address", cfg.address)
                        put("port", cfg.port)
                        put("users", JSONArray().put(JSONObject().apply {
                            put("id", cfg.id)
                            put("alterId", cfg.alterId)
                            put("security", cfg.vmessSecurity.ifBlank { "auto" })
                        }))
                    }))
                })
                ob.put("streamSettings", buildStreamSettings(cfg))
            }

            ParsedProxyConfig.ProxyProtocol.TROJAN -> {
                ob.put("protocol", "trojan")
                ob.put("settings", JSONObject().apply {
                    put("servers", JSONArray().put(JSONObject().apply {
                        put("address", cfg.address)
                        put("port", cfg.port)
                        put("password", cfg.password)
                    }))
                })
                ob.put("streamSettings", buildStreamSettings(cfg))
            }

            ParsedProxyConfig.ProxyProtocol.SHADOWSOCKS -> {
                ob.put("protocol", "shadowsocks")
                ob.put("settings", JSONObject().apply {
                    put("servers", JSONArray().put(JSONObject().apply {
                        put("address", cfg.address)
                        put("port", cfg.port)
                        put("method", cfg.ssMethod)
                        put("password", cfg.ssPassword)
                    }))
                })
                // Shadowsocks عادة TCP خام بلا TLS - بلا streamSettings
                // زايدة إلا إذا كان محدد transport آخر بوضوح.
                if (cfg.network != "tcp" || cfg.security != "none") {
                    ob.put("streamSettings", buildStreamSettings(cfg))
                }
            }
        }

        return ob
    }

    private fun buildStreamSettings(cfg: ParsedProxyConfig): JSONObject {
        val stream = JSONObject()
        stream.put("network", cfg.network)

        when (cfg.network) {
            "ws" -> stream.put("wsSettings", JSONObject().apply {
                put("path", cfg.path.ifBlank { "/" })
                if (cfg.hostHeader.isNotBlank()) {
                    put("headers", JSONObject().apply { put("Host", cfg.hostHeader) })
                }
            })

            "grpc" -> stream.put("grpcSettings", JSONObject().apply {
                put("serviceName", cfg.serviceName)
                put("multiMode", false)
            })

            "http" -> stream.put("httpSettings", JSONObject().apply {
                put("path", cfg.path.ifBlank { "/" })
                if (cfg.hostHeader.isNotBlank()) {
                    put("host", JSONArray().put(cfg.hostHeader))
                }
            })

            "xhttp" -> stream.put("xhttpSettings", JSONObject().apply {
                put("path", cfg.path.ifBlank { "/" })
                if (cfg.hostHeader.isNotBlank()) put("host", cfg.hostHeader)
                put("mode", "auto")
            })

            "tcp" -> {
                if (cfg.headerType == "http") {
                    stream.put("tcpSettings", JSONObject().apply {
                        put("header", JSONObject().apply {
                            put("type", "http")
                            if (cfg.hostHeader.isNotBlank() || cfg.path.isNotBlank()) {
                                put("request", JSONObject().apply {
                                    put("path", JSONArray().put(cfg.path.ifBlank { "/" }))
                                    if (cfg.hostHeader.isNotBlank()) {
                                        put("headers", JSONObject().apply {
                                            put("Host", JSONArray().put(cfg.hostHeader))
                                        })
                                    }
                                })
                            }
                        })
                    })
                }
            }
        }

        when (cfg.security) {
            "tls" -> stream.put("security", "tls").also {
                stream.put("tlsSettings", JSONObject().apply {
                    put("serverName", cfg.sni.ifBlank { cfg.address })
                    put("fingerprint", cfg.fingerprint.ifBlank { "chrome" })
                    if (cfg.alpn.isNotBlank()) {
                        put("alpn", JSONArray(cfg.alpn.split(",").map { it.trim() }))
                    }
                })
            }
            "reality" -> stream.put("security", "reality").also {
                stream.put("realitySettings", JSONObject().apply {
                    put("serverName", cfg.sni.ifBlank { cfg.address })
                    put("fingerprint", cfg.fingerprint.ifBlank { "chrome" })
                    put("publicKey", cfg.publicKey)
                    if (cfg.shortId.isNotBlank()) put("shortId", cfg.shortId)
                    if (cfg.spiderX.isNotBlank()) put("spiderX", cfg.spiderX)
                })
            }
            else -> stream.put("security", "none")
        }

        return stream
    }
}
