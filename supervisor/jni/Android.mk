LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := kguard-supervisor
LOCAL_SRC_FILES := supervisor_main.c \
                   supervisor_handler.c \
                   supervisor_maps.c \
                   supervisor_watchdog.c

LOCAL_CFLAGS    := -Wall -Wextra -O2 -std=c17 -D_GNU_SOURCE
LOCAL_LDFLAGS   := -pie
LOCAL_LDLIBS    := -llog

include $(BUILD_EXECUTABLE)
