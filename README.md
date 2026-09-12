# SSH Proxy Payload — تطبيق VPN حقيقي (SSH + Payload + tun2socks)

تطبيق Android حقيقي: كيدير Payload bypass (بحال HTTP Custom) → SSH tunnel (JSch) →
SOCKS5 محلي → `hev-socks5-tunnel` (tun2socks) كيقرا من TUN device وكيبعث **كل** traffic
ديال الهاتف عبر الـSSH. هادشي هو الجزء اللي كان ناقص فـ `com.vpn.myapp` (كان عندك
tun2socks asset ديال 0 bytes بلا حتى process كيقراه).

## 1) كيفاش تجهز الـrepo (من الهاتف، بلا PC)

بعد ما تـpush هاد الملفات لـGitHub، خاصك تزيد submodule واحد (من موقع GitHub مباشرة
ولا من تيرمينال SSH إلا كاين عندك):

```bash
git submodule add --branch main https://github.com/heiher/hev-socks5-tunnel app/src/main/jni/hev-socks5-tunnel
git submodule update --init --recursive
git add .gitmodules app/src/main/jni/hev-socks5-tunnel
git commit -m "add hev-socks5-tunnel submodule"
git push
```

إلا ماكانش عندك SSH access باش تدير `git submodule add` من الهاتف، بدل موصل:
1. دخل لـ https://github.com/heiher/hev-socks5-tunnel وحمل الـzip (Code → Download ZIP)
2. رفعو مباشرة فـ GitHub Web UI فـ `app/src/main/jni/hev-socks5-tunnel/`
3. **مهم:** خاصك ترفع تحتاوي على `third-part/yaml`, `third-part/lwip`, `third-part/hev-task-system`
   بحال submodules ديالهم داخل (زيد Download ZIP لكل واحد وحطهم فبلاصتهم، ولا الأحسن
   دير submodule add من متصفح GitHub Codespaces اللي عندو terminal مجاني).

## 2) البناء (GitHub Actions)

كل `push` على `main` غادي يبني ليك APK أوتوماتيك:
- `Actions` tab → آخر run → `Artifacts` → `ssh-proxy-payload-apk`

الملف `.github/workflows/build.yml` كيدير:
1. Checkout مع submodules
2. تنصيب JDK 17 + Android SDK + NDK 26 + CMake
3. `gradle wrapper` (باش نتجاوزو مشكل `gradle-wrapper.jar` الغير موجود بلا PC)
4. `./gradlew assembleRelease`

## 3) كيفاش خدام التطبيق

1. `Host:Port` = IP/domain ديال السيرفر SSH (بحال `example.com:443`)
2. `Username` / `Password`
3. `Use Payload` مفعّلة بالدفو، `Payload` ممكن تبدلها بـpayload ديالك
   (استعمل `[crlf]`, `[lf]`, `[host]` بحال HTTP Custom)
4. `Remote Proxy` = IP/domain اللي الـpayload كيتبعث ليه (مثال `investor.snap.com:80`)
5. `CONNECT` → غادي يطلب صلاحية VPN (Android system dialog) → قبل → التطبيق كيبدا:
   - يفتح socket لـRemote Proxy
   - يبعث الـpayload
   - يبدا SSH handshake فوق نفس الـsocket
   - `setPortForwardingD` → SOCKS5 محلي على `127.0.0.1:10808`
   - `VpnService.Builder.establish()` → TUN device حقيقي
   - `hev-socks5-tunnel` (native) كيقرا من TUN وكيبعث عبر SOCKS5

هاد الخطوة الأخيرة هي **بالضبط** اللي كانت ناقصة فـ `com.vpn.myapp`: بلا native tunnel
اللي كيقرا من TUN، الـSSH connection كيتصل بنجاح ولكن الـtraffic ديال الهاتف مايتبعتش
لحتى بلاصة (0-byte placeholder). دابا كاين process حقيقي كيقرا الباكيتات.

## 4) نسخة Google Play

- بدل `signingConfig signingConfigs.debug` فـ `app/build.gradle` بمفتاح release ديالك
  (زيد keystore كـGitHub Secret واستعملو فـworkflow)
- زيد `versionCode`/`versionName` كل ما بغيتي تنشر تحديث
- استعمل `bundleRelease` بدل `assembleRelease` باش تجيب `.aab` (Play يطلب AAB ماشي APK)

## بنية المشروع

```
SshProxyPayloadVpn/
├── .github/workflows/build.yml     ← CI (يبني APK بلا PC)
├── app/
│   ├── build.gradle
│   └── src/main/
│       ├── AndroidManifest.xml
│       ├── jni/
│       │   ├── CMakeLists.txt      ← كيبني hev-socks5-tunnel + jni_bridge
│       │   ├── jni_bridge.c        ← الجسر بين Kotlin والـC library
│       │   └── hev-socks5-tunnel/  ← (submodule، خاصك تزيدو بيدك)
│       └── java/com/sshproxy/vpn/
│           ├── MainActivity.kt      ← الواجهة (بحال HTTP Custom)
│           ├── PayloadSocketFactory.kt  ← الـpayload bypass قبل SSH
│           └── SshVpnService.kt     ← VpnService: SSH + TUN + tun2socks
```

## ملاحظة مهمة

الجزء الأصعب فهاد المشروع هو بناء `hev-socks5-tunnel` بالـNDK (native C library).
كتب الـCMake هنا بطريقة مجربة (ExternalProject_Add كيبني بالـMakefile الأصلي ديال
المكتبة `make static`). إلا طلع خطأ فـbuild فـGitHub Actions، بعتلي الـlog ديال
`Actions` وغادي نصلحو.
