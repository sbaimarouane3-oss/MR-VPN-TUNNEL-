cmake_minimum_required(VERSION 3.22.1)
project(hev_socks5_tunnel_jni C)

include(ExternalProject)

# ============================================================================
# hev-socks5-tunnel: نبنيوه بـ ndk-build (Android.mk الرسمي) - كيفما موثق
# رسميًا فـ README.md ديال المشروع:
#
#   mkdir hev-socks5-tunnel
#   cd hev-socks5-tunnel
#   git clone --recursive https://github.com/heiher/hev-socks5-tunnel jni
#   ndk-build
#
# جربنا قبل `make static` (Makefile العادي) بحال بديل، لكن تبين أن هاد
# الـ Makefile موثق رسميًا غير لـ Unix/Windows (host builds) - ماشي لـ
# Android. هادشي هو السبب ديال "incompatible with aarch64linux": الكود
# كيتبنى بـ macros/assumptions ماشي مصممين لـ Android cross-compile.
#
# البگ الأصلي ديال ndk-build ("undefined modules: yaml lwip hev-task-system")
# كان بسبب أننا كنا كنمررو NDK_PROJECT_PATH يأشر مباشرة لـ hev-socks5-tunnel/
# (بلا بنية jni/ بيناتهم) - وهادشي كيخرب my-dir/modules-get-list ديال
# ndk-build. الحل: ننسخو الكود لبنية <stage>/jni/Android.mk بالضبط كيفما
# فـ README، وبعدين نديرو ndk-build من <stage> (النتيجة = my-dir يخدم صحيح،
# yaml/lwip/hev-task-system كيتسجلو كـ modules صحيحين).
# ============================================================================

set(HEV_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/hev-socks5-tunnel)
set(HEV_STAGE_ROOT ${CMAKE_CURRENT_BINARY_DIR}/hev-ndk-${ANDROID_ABI})
set(HEV_JNI_DIR ${HEV_STAGE_ROOT}/jni)
set(HEV_LIBS_OUT ${HEV_STAGE_ROOT}/libs)
set(HEV_OBJ_OUT ${HEV_STAGE_ROOT}/obj)

ExternalProject_Add(
    hev-socks5-tunnel-external
    SOURCE_DIR ${HEV_SRC_DIR}
    DOWNLOAD_COMMAND ""
    UPDATE_COMMAND ""
    # ننسخو الكود لبنية jni/ القياسية - خاص لكل ABI باش مايتلاقاوش
    # armeabi-v7a و arm64-v8a وقت كيبنيو بالتوازي
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E rm -Rf ${HEV_STAGE_ROOT}
        COMMAND ${CMAKE_COMMAND} -E make_directory ${HEV_STAGE_ROOT}
        COMMAND ${CMAKE_COMMAND} -E copy_directory ${HEV_SRC_DIR} ${HEV_JNI_DIR}
    BUILD_COMMAND ${CMAKE_ANDROID_NDK}/ndk-build
        NDK_PROJECT_PATH=${HEV_STAGE_ROOT}
        APP_BUILD_SCRIPT=${HEV_JNI_DIR}/Android.mk
        NDK_APPLICATION_MK=${HEV_JNI_DIR}/Application.mk
        APP_ABI=${ANDROID_ABI}
        APP_PLATFORM=${ANDROID_PLATFORM}
        APP_STL=c++_shared
        NDK_LIBS_OUT=${HEV_LIBS_OUT}
        NDK_OUT=${HEV_OBJ_OUT}
        -j1
    BUILD_IN_SOURCE 0
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy
        ${HEV_LIBS_OUT}/${ANDROID_ABI}/libhev-socks5-tunnel.so
        ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libhev-socks5-tunnel.so
    BUILD_BYPRODUCTS ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libhev-socks5-tunnel.so
)

add_library(hev-socks5-tunnel-jni SHARED jni_bridge.c)

target_include_directories(hev-socks5-tunnel-jni PRIVATE
    ${HEV_SRC_DIR}/src
)

find_library(log-lib log)

# hev-socks5-tunnel-jni كيربط ديناميكيًا مع libhev-socks5-tunnel.so
# (اللي بناها ndk-build) - نفس بنية المشروع الأصلية
target_link_libraries(hev-socks5-tunnel-jni
    ${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libhev-socks5-tunnel.so
    ${log-lib}
)
add_dependencies(hev-socks5-tunnel-jni hev-socks5-tunnel-external)

target_link_options(hev-socks5-tunnel-jni PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384"
)

# مكتبة crash-guard - خدامة مزيان، خليناها كيفما هي
add_library(crash-guard SHARED crash_guard.c)
target_link_libraries(crash-guard ${log-lib})
target_link_options(crash-guard PRIVATE
    "-Wl,-z,max-page-size=16384"
    "-Wl,-z,common-page-size=16384"
)
