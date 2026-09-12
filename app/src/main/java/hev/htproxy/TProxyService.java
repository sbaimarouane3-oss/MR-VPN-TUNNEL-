package hev.htproxy;

/**
 * هاد الكلاس ماشي للاستعمال المباشر ديالنا - غايتو الوحيدة: يكون موجود باش
 * JNI_OnLoad ديال libhev-socks5-tunnel.so يقدر يدير FindClass/RegisterNatives
 * عليه بنجاح. بلاه، الـRegisterNatives كيلقى java_class == null ويدير abort
 * فوري (SIGABRT) عند System.loadLibrary("hev-socks5-tunnel") - وهادشي بالضبط
 * كان السبب ديال الكراش عندنا.
 *
 * التوقيعات هادو لازم يكونو مطابقين بالضبط لما كيسجل hev-jni.c (ma3roof
 * من مشروع heiher/sockstun الرسمي).
 */
public class TProxyService {
    private static native boolean TProxyStartService(String config_path, int fd);
    private static native boolean TProxyStopService();
    private static native boolean TProxyIsRunning();
    private static native long[] TProxyGetStats();
}
