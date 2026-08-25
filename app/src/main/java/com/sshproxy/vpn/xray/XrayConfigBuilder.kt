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

    private fun buildOutbound(cfg: ParsedProxyConfig): JSONObject {
        // Xray JSON خام (استيراد كامل) - كنستعملوه بحالو، غير كنضمنو الـtag.
        // allowInsecure كيبقى كيفما تحدد فالكونفيغ الأصلي (بلا ما نحيدوه)
        // باش يخدم أي سيرفر جا، حتى لو الشهادة ديالو self-signed/غير موثوقة.
        cfg.rawOutboundJson?.let {
            val ob = JSONObject(it)
            ob.put("tag", "proxy")
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
                    put("allowInsecure", true)
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
