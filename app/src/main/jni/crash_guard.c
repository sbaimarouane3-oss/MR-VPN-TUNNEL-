#include <jni.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>

#define TAG "crash-guard"

static char g_log_path[512];

static void write_line(const char *s) {
    int fd = open(g_log_path, O_CREAT | O_WRONLY | O_APPEND, 0666);
    if (fd >= 0) {
        write(fd, s, strlen(s));
        close(fd);
    }
    __android_log_write(ANDROID_LOG_ERROR, TAG, s);
}

static const char *signal_name(int sig) {
    switch (sig) {
        case SIGSEGV: return "SIGSEGV (invalid memory access)";
        case SIGABRT: return "SIGABRT (abort/assert)";
        case SIGBUS:  return "SIGBUS (bus error / alignment)";
        case SIGILL:  return "SIGILL (illegal instruction)";
        case SIGFPE:  return "SIGFPE (arithmetic error)";
        default:      return "UNKNOWN";
    }
}

static void crash_handler(int sig, siginfo_t *info, void *ctx) {
    char buf[384];
    void *addr = (info != NULL) ? info->si_addr : NULL;
    snprintf(buf, sizeof(buf),
        "\n=== NATIVE CRASH ===\nsignal=%d (%s)\nfault_addr=%p\n=====================\n",
        sig, signal_name(sig), addr);
    write_line(buf);

    // نرجعو للسلوك الافتراضي باش النظام يكمل يسجل crash عادي (tombstone)
    signal(sig, SIG_DFL);
    raise(sig);
}

JNIEXPORT void JNICALL
Java_com_sshproxy_vpn_CrashGuard_install(JNIEnv *env, jclass clazz, jstring logPath) {
    const char *path = (*env)->GetStringUTFChars(env, logPath, NULL);
    strncpy(g_log_path, path, sizeof(g_log_path) - 1);
    g_log_path[sizeof(g_log_path) - 1] = '\0';
    (*env)->ReleaseStringUTFChars(env, logPath, path);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = crash_handler;
    sa.sa_flags = SA_SIGINFO;

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGABRT, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGILL, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);

    write_line("crash guard installed successfully\n");
}
