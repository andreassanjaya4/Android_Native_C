//
// Created by Andreas S on 24/3/21.
//

#include <android/log.h>

#ifndef NATIVEC_LOGUTILS_H
#define NATIVEC_LOGUTILS_H

#endif //OPENSSL_ZSD_H

#if 1
#define TAG "cipher"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL, TAG ,__VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG ,__VA_ARGS__)
#else
#define LOGI(...)
#define LOGD(...)
#define LOGE(...)
#define LOGF(...)
#define LOGW(...)
#endif //NATIVEC_LOGUTILS_H

//char *sha1OfApk(JNIEnv *env, jobject context);

//jboolean verifySha1OfApk(JNIEnv *env, jobject context);
