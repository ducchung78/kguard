#ifndef KGUARD_PROPERTY_SPOOF_H
#define KGUARD_PROPERTY_SPOOF_H

#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

// Spoofs sensitive Java Build and System properties in the target process
void kguard_spoof_java_properties(JNIEnv *env);

#ifdef __cplusplus
}
#endif

#endif // KGUARD_PROPERTY_SPOOF_H
