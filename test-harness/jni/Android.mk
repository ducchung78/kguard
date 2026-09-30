LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := kguard-detect
LOCAL_SRC_FILES := main.c \
                   detect_maps.c \
                   detect_integrity.c \
                   detect_got.c \
                   detect_syscall.S \
                   detect_linker.c \
                   detect_seccomp.c \
                   detect_namespace.c \
                   detect_tee.c \
                   detect_props.c \
                   detect_timing.c \
                   utils/elf_parser.c \
                   utils/sha256.c

LOCAL_CFLAGS    := -Wall -Wextra -O2 -std=c17 -DANDROID -D_GNU_SOURCE
LOCAL_LDFLAGS   := -pie
LOCAL_LDLIBS    := -llog -ldl

include $(BUILD_EXECUTABLE)
