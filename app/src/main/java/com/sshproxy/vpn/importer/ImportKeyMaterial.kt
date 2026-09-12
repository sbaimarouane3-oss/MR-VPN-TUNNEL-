package com.sshproxy.vpn.importer

/**
 * ⚠️ ملاحظة أمنية صريحة (مهم تقراها):
 *
 * أي مفتاح تماثلي (symmetric / AES) مضمّن داخل APK يبقى، من الناحية
 * النظرية، قابل للاستخراج من طرف مهاجم مصمم بما فيه الكفاية (عبر أدوات
 * Dynamic instrumentation زي Frida اللي كتقدر "تشوف" المفتاح وقت ما
 * الكود كيستعملو فـ Cipher.init، بغض النظر على أي تشويش نديرو فالكود
 * الثابت). هادشي قانون عام فالتشفير التماثلي، ماشي عيب فهاد التطبيق
 * بالذات — هذا سبب كون تطبيقات كبيرة كتعتمد على مفاتيح تتسلم من سيرفر
 * (short-lived tokens) بدل ما تكون مضمنة بشكل دائم فالتطبيق.
 *
 * التقسيم/XOR تحت هو "دفاع فالعمق" (defense-in-depth): كيمنع اكتشاف
 * المفتاح بسهولة عبر static analysis بسيط (jadx / strings command) اللي
 * هو أغلب التهديد الواقعي، بصح ماشي حماية "مطلقة" 100%.
 *
 * ✅ الحماية الحقيقية غير القابلة للكسر هي **التوقيع الرقمي ECDSA**:
 * المفتاح الخاص للتوقيع (private key) ماكاينش فالتطبيق أصلا — كاين غير
 * فسكريبت التوليد (generate_import_code.py) اللي كيبقى عند صاحب
 * التطبيق فقط. التطبيق فيه غير المفتاح العام (public key)، وهو أصلا
 * ماشي سر — حتى لو تشاف بالكامل من طرف أي حد، ما يقدرش يوقع كود جديد
 * ولا يبدل واحد موجود، لأن التوقيع غادي يفشل مباشرة (GCM tag + ECDSA
 * كيتحققو من كل بايت). هذا هو الضمان الحقيقي ديال "رفض أي تعديل".
 */
internal object ImportKeyMaterial {

    // --- جزء 1 و2 ديال مفتاح AES-256 (32 بايت)، كل واحد معمى بـ XOR مع
    // mask مختلف، باش ما يبانش كسلسلة بايتات متتالية واضحة فالـ.class ---
    private val part1 = byteArrayOf(-31, -106, 126, -81, 43, -39, -122, -87, 71, 123, -47, 12, -43, -91, -64, -21)
    private val part2 = byteArrayOf(119, 17, -101, -77, -60, 36, 71, -102, 120, 104, -8, 84, 34, 60, 95, 22)
    private val mask1 = byteArrayOf(-31, 121, 28, 2, 19, 100, -31, 65, -45, 86, 82, -74, -25, 101, 25, 86)
    private val mask2 = byteArrayOf(-8, 88, -34, -9, -17, 53, -73, -74, -71, 112, 22, -9, 62, 92, -81, 103)

    /** كنعاودو نبنيو المفتاح الكامل (32 بايت) فالـruntime فقط، عمرو ما كيتخزن مجمّع فمكان واحد. */
    fun aesKey(): ByteArray {
        val a = xor(part1, mask1)
        val b = xor(part2, mask2)
        return a + b
    }

    private fun xor(x: ByteArray, y: ByteArray): ByteArray =
        ByteArray(x.size) { i -> (x[i].toInt() xor y[i].toInt()).toByte() }

    /**
     * المفتاح العام ECDSA (P-256 / secp256r1)، بصيغة X.509 SubjectPublicKeyInfo،
     * مرمّز Base64. هذا مفتاح عام — نشرو بلا تشويش آمن تماما.
     * المفتاح الخاص المقابل ماكاينش فهاد المشروع، كاين غير عند مولّد الأكواد.
     */
    const val SIGN_PUBLIC_KEY_B64 =
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEQ45VSeJF9MB1oDKd0JG1BilJToTl07uJKY/LW9huUOkDpN0RkR27ke6gSUD42Jd6jymOFkTH0/DnrfGE5gjZUg=="
}
