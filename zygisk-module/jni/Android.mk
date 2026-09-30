LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := kguard_zygisk
LOCAL_SRC_FILES := main.cpp \
                   cJSON.c \
                   kguard_client.cpp \
                   namespace_cleanup.cpp \
                   seccomp_filter.cpp \
                   property_spoof.cpp

LOCAL_CPPFLAGS  := -std=c++17 -Wall -Wextra -O2 -fvisibility=hidden -fPIC
LOCAL_CFLAGS    := -Wall -Wextra -O2 -fvisibility=hidden -fPIC
LOCAL_LDLIBS    := -llog

include $(BUILD_SHARED_LIBRARY)
