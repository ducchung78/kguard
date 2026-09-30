#!/bin/bash
set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$PROJECT_ROOT/dist"

echo "========================================================"
echo " Building KGuard Framework for RedMagic 8 Pro (SM8550) "
echo "========================================================"

mkdir -p "$OUTPUT_DIR"

# 1. Build Test Harness
echo "[1/3] Building Test Harness (kguard-detect)..."
cd "$PROJECT_ROOT/test-harness"
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=jni/Android.mk
cp libs/arm64-v8a/kguard-detect "$OUTPUT_DIR/"

# 2. Build Supervisor Daemon
echo "[2/3] Building Seccomp Supervisor (kguard-supervisor)..."
cd "$PROJECT_ROOT/supervisor"
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=jni/Android.mk
cp libs/arm64-v8a/kguard-supervisor "$OUTPUT_DIR/"

# 3. Build Zygisk Module
echo "[3/3] Building Zygisk Native Module (kguard_zygisk.so)..."
cd "$PROJECT_ROOT/zygisk-module"
ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=jni/Android.mk

# Assemble Magisk/KSU Module Flashable Zip
echo "Packaging Magisk/KernelSU Flashable Zip..."
ZIP_DIR="$PROJECT_ROOT/dist/kguard-magisk"
rm -rf "$ZIP_DIR"
mkdir -p "$ZIP_DIR/zygisk"
mkdir -p "$ZIP_DIR/config"

cp "$PROJECT_ROOT/zygisk-module/module.prop" "$ZIP_DIR/"
cp "$PROJECT_ROOT/zygisk-module/customize.sh" "$ZIP_DIR/"
cp "$PROJECT_ROOT/zygisk-module/post-fs-data.sh" "$ZIP_DIR/"
cp "$PROJECT_ROOT/zygisk-module/service.sh" "$ZIP_DIR/"
cp "$PROJECT_ROOT/zygisk-module/sepolicy.rule" "$ZIP_DIR/"
cp "$PROJECT_ROOT/zygisk-module/config/policy.json" "$ZIP_DIR/config/"

cp "$PROJECT_ROOT/zygisk-module/libs/arm64-v8a/libkguard_zygisk.so" "$ZIP_DIR/zygisk/arm64-v8a.so"
cp "$OUTPUT_DIR/kguard-supervisor" "$ZIP_DIR/"

cd "$ZIP_DIR"
zip -r "$OUTPUT_DIR/KGuard-v1.0.0-SM8550.zip" ./*

echo "========================================================"
echo " BUILD FINISHED SUCCESSFULLY!"
echo " Artifacts located in: $OUTPUT_DIR"
echo "  1. Test Harness:   kguard-detect"
echo "  2. Supervisor:     kguard-supervisor"
echo "  3. Flashable Zip:  KGuard-v1.0.0-SM8550.zip"
echo "========================================================"
