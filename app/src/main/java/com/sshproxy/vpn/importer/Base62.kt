package com.sshproxy.vpn.importer

import java.math.BigInteger

/**
 * ترميز Base62: أرقام وحروف فقط (0-9, A-Z, a-z)، بلا padding وبلا رموز
 * خاصة (بخلاف Base64). مناسب لكود الاستيراد MRVPN://<base62>.
 */
internal object Base62 {

    private const val ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    private val BASE = BigInteger.valueOf(62)

    fun encode(data: ByteArray): String {
        if (data.isEmpty()) return ""
        var num = BigInteger(1, data)
        val sb = StringBuilder()
        while (num > BigInteger.ZERO) {
            val divRem = num.divideAndRemainder(BASE)
            sb.append(ALPHABET[divRem[1].toInt()])
            num = divRem[0]
        }
        var leadingZeros = 0
        for (b in data) {
            if (b.toInt() == 0) leadingZeros++ else break
        }
        repeat(leadingZeros) { sb.append(ALPHABET[0]) }
        return sb.reverse().toString()
    }

    fun decode(str: String): ByteArray {
        if (str.isEmpty()) return ByteArray(0)
        var num = BigInteger.ZERO
        for (c in str) {
            val idx = ALPHABET.indexOf(c)
            if (idx < 0) throw IllegalArgumentException("invalid base62 char: $c")
            num = num.multiply(BASE).add(BigInteger.valueOf(idx.toLong()))
        }
        var bytes = num.toByteArray()
        // BigInteger.toByteArray() ممكن يزيد بايت 0x00 زائد فالبداية (sign bit)
        if (bytes.size > 1 && bytes[0].toInt() == 0) {
            bytes = bytes.copyOfRange(1, bytes.size)
        }
        var leadingZeros = 0
        for (c in str) {
            if (c == ALPHABET[0]) leadingZeros++ else break
        }
        return ByteArray(leadingZeros) + bytes
    }
}
