#include "property_spoof.h"
#include <android/log.h>

#define LOG_TAG "KGuard-Prop"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

static void set_static_string_field(JNIEnv *env, jclass clazz, const char *field_name, const char *val) {
    if (!env || !clazz || !field_name || !val) return;
    jfieldID fid = env->GetStaticFieldID(clazz, field_name, "Ljava/lang/String;");
    if (fid) {
        jstring str = env->NewStringUTF(val);
        env->SetStaticObjectField(clazz, fid, str);
        env->DeleteLocalRef(str);
    } else {
        env->ExceptionClear();
    }
}

void kguard_spoof_java_properties(JNIEnv *env) {
    if (!env) return;

    jclass build_class = env->FindClass("android/os/Build");
    if (build_class) {
        set_static_string_field(env, build_class, "TAGS", "release-keys");
        set_static_string_field(env, build_class, "TYPE", "user");
        env->DeleteLocalRef(build_class);
        LOGD("Sanitized android.os.Build fields");
    } else {
        env->ExceptionClear();
    }
}
