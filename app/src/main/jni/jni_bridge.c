#include <jni.h>
#include <string.h>
#include <stdio.h>
#include <android/log.h>
#include "hev-main.h"

#define LOG_TAG "hev-jni-bridge"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

/*
 * nativeStartTunnel(fd, socksHost, socksPort, mtu, udpMode, udpgwHost, udpgwPort)
 * كتبني YAML config صغير ديال hev-socks5-tunnel وكتشغل hev_socks5_tunnel_main_from_str
 * اللي كيقرا الباكيتات من tun_fd (اللي جا من VpnService.Builder.establish()) وكيبعثهم
 * عبر SOCKS5 (127.0.0.1:socksPort) اللي فتحاتو JSch (setPortForwardingD).
 *
 * udpMode: "udp" (افتراضي، UDP عبر SOCKS5 UDP ASSOCIATE - السيرفر SOCKS5
 *          المحلي عندنا حاليًا كيرفضها) أو "gw" (UDP عبر UDPGW منفصل، مفتوح
 *          مسبقًا كـ Local Port Forward عبر SSH نحو badvpn-udpgw البعيد).
 * udpgwHost/udpgwPort: فين موجود UDPGW محليًا (127.0.0.1:<local forward port>)
 *          - غير كيتقراو إلا udpMode == "gw".
 *
 * هاد الدالة blocking، خاصها تخدم فـ thread/coroutine خاص (ماشي الـ main thread).
 */
JNIEXPORT jint JNICALL
Java_com_sshproxy_vpn_SshVpnService_nativeStartTunnel(
    JNIEnv *env, jobject thiz, jint fd, jstring socksHost, jint socksPort, jint mtu,
    jstring udpMode, jstring udpgwHost, jint udpgwPort)
{
    const char *host = (*env)->GetStringUTFChars(env, socksHost, NULL);
    const char *mode = (*env)->GetStringUTFChars(env, udpMode, NULL);
    const char *gwHost = (*env)->GetStringUTFChars(env, udpgwHost, NULL);

    char config[1536];
    int isGw = (strcmp(mode, "gw") == 0) && udpgwPort > 0;

    if (isGw) {
        snprintf(config, sizeof(config),
            "tunnel:\n"
            "  mtu: %d\n"
            "socks5:\n"
            "  port: %d\n"
            "  address: %s\n"
            "  udp: 'gw'\n"
            "udpgw:\n"
            "  address: %s\n"
            "  port: %d\n"
            "misc:\n"
            "  log-level: warn\n"
            "  connect-timeout: 5000\n"
            "  read-write-timeout: 60000\n",
            mtu, socksPort, host, gwHost, udpgwPort);
    } else {
        snprintf(config, sizeof(config),
            "tunnel:\n"
            "  mtu: %d\n"
            "socks5:\n"
            "  port: %d\n"
            "  address: %s\n"
            "  udp: 'udp'\n"
            "misc:\n"
            "  log-level: warn\n"
            "  connect-timeout: 5000\n"
            "  read-write-timeout: 60000\n",
            mtu, socksPort, host);
    }

    (*env)->ReleaseStringUTFChars(env, socksHost, host);
    (*env)->ReleaseStringUTFChars(env, udpMode, mode);
    (*env)->ReleaseStringUTFChars(env, udpgwHost, gwHost);

    LOGI("starting hev-socks5-tunnel on fd=%d (udp mode=%s)", fd, isGw ? "gw" : "udp");
    int ret = hev_socks5_tunnel_main_from_str((const unsigned char *)config,
                                               (unsigned int)strlen(config), fd);
    if (ret != 0) {
        LOGE("hev_socks5_tunnel_main_from_str returned %d", ret);
    }
    return ret;
}

JNIEXPORT void JNICALL
Java_com_sshproxy_vpn_SshVpnService_nativeStopTunnel(JNIEnv *env, jobject thiz)
{
    LOGI("stopping hev-socks5-tunnel");
    hev_socks5_tunnel_quit();
}
