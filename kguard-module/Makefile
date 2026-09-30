# SPDX-License-Identifier: GPL-2.0
#
# Makefile for kguard kernel module
#
# Usage:
#   make KERNEL_DIR=/path/to/msm-kernel CROSS_COMPILE=aarch64-linux-android-
#   make clean
#

KERNEL_DIR     ?= /path/to/android-kernel/msm-kernel
CROSS_COMPILE  ?= aarch64-linux-android-
ARCH           ?= arm64
CLANG_TRIPLE   ?= aarch64-linux-gnu-
CC             ?= clang
KGUARD_VERSION ?= 0x010000

# AOSP prebuilt clang (adjust path for your setup)
# CLANG_PATH   ?= /path/to/aosp/prebuilts/clang/host/linux-x86/clang-r487747c/bin

export ARCH CROSS_COMPILE CLANG_TRIPLE CC KGUARD_VERSION

.PHONY: all modules clean install

all: modules

modules:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) modules

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) clean
	rm -f Module.symvers modules.order

install:
	@echo "Copy kguard.ko to device:"
	@echo "  adb push kguard.ko /data/local/tmp/"
	@echo "  adb shell su -c insmod /data/local/tmp/kguard.ko"
