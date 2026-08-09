# keep JSch classes (كتعتمد على reflection داخليا لاختيار algorithms، بلا هاد
# القاعدة R8 غادي يكسر مصافحة SSH بعد ما نفعلو minifyEnabled)
-keep class com.jcraft.jsch.** { *; }
-dontwarn com.jcraft.jsch.**

# ⚠️ ضروري: أسماء الدوال native (JNI) خاصها تبقى بحالها بالضبط، حيت
# المكتبة .so كتربطها بالاسم الحرفي (nativeStartTunnel/nativeStopTunnel).
# بلا هاد القاعدة، R8 غادي يبدل الأسماء والتونيل غايبقاش خدام.
-keepclasseswithmembernames,includedescriptorclasses class * {
    native <methods>;
}

# ⚠️ ضروري بزاف: TProxyService كاينة غير باش libhev-socks5-tunnel.so
# (JNI_OnLoad ديالها) يقدر يدير FindClass/RegisterNatives عليها بنجاح
# عند System.loadLibrary("hev-socks5-tunnel"). ماعندهاش caller فـ Kotlin/Java،
# فـ R8 كيحسبها "ماخدماش" ويبدا يبدل/يهجّر package ديالها (بسبب
# -repackageclasses تحت) — وهادشي بالضبط كان السبب ديال
# UnsatisfiedLinkError: JNI_ERR returned from JNI_OnLoad اللي طرا بعد ما
# فعلنا minifyEnabled. القاعدة الشرطية لفوق (keepclasseswithmembernames)
# ماكانتش كافية باش تحميها من -repackageclasses، فخاصها -keep صريح.
-keep class hev.htproxy.TProxyService { *; }
-keepnames class hev.htproxy.TProxyService

# نظام الاستيراد المشفر (com.sshproxy.vpn.importer.*): ماكاينش رابط
# reflection، فـ R8 حر يبدل ويشوش أسماء الكلاسات/الدوال/الحقول بالكامل
# هنا — هادشي بالذات كيزيد صعوبة الهندسة العكسية لمنطق التشفير.

# org.json مكتبة نظام (مدمجة فـ Android)، ماخصهاش obfuscation
-dontwarn org.json.**

-repackageclasses ''
-allowaccessmodification
-optimizationpasses 5
