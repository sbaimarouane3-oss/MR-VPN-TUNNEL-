package com.sshproxy.vpn

/**
 * روابط Telegram و WhatsApp المجلوبة من links.json على GitHub. راجع
 * [LinksChecker] و [LinksManager].
 */
data class LinksInfo(
    val telegramUrl: String,
    val whatsappUrl: String
)
