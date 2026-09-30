@echo off
setlocal enabledelayedexpansion

set "PROJECT_ROOT=%~dp0"
set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"
set "OUTPUT_DIR=%PROJECT_ROOT%\dist"

echo ========================================================
echo  Building KGuard Framework for RedMagic 8 Pro (SM8550)
echo ========================================================

if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

echo [1/3] Building Test Harness (kguard-detect)...
cd /d "%PROJECT_ROOT%\test-harness"
call ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=jni/Android.mk
if %errorlevel% neq 0 (
    echo ! Error building test-harness
    goto :err
)
copy /y "libs\arm64-v8a\kguard-detect" "%OUTPUT_DIR%\"

echo [2/3] Building Seccomp Supervisor (kguard-supervisor)...
cd /d "%PROJECT_ROOT%\supervisor"
call ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=jni/Android.mk
if %errorlevel% neq 0 (
    echo ! Error building supervisor
    goto :err
)
copy /y "libs\arm64-v8a\kguard-supervisor" "%OUTPUT_DIR%\"

echo [3/3] Building Zygisk Native Module (kguard_zygisk.so)...
cd /d "%PROJECT_ROOT%\zygisk-module"
call ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=jni/Android.mk
if %errorlevel% neq 0 (
    echo ! Error building zygisk module
    goto :err
)

echo Packaging Magisk/KernelSU Zip...
set "ZIP_DIR=%PROJECT_ROOT%\dist\kguard-magisk"
if exist "%ZIP_DIR%" rd /s /q "%ZIP_DIR%"
mkdir "%ZIP_DIR%\zygisk"
mkdir "%ZIP_DIR%\config"

copy /y "%PROJECT_ROOT%\zygisk-module\module.prop" "%ZIP_DIR%\"
copy /y "%PROJECT_ROOT%\zygisk-module\customize.sh" "%ZIP_DIR%\"
copy /y "%PROJECT_ROOT%\zygisk-module\post-fs-data.sh" "%ZIP_DIR%\"
copy /y "%PROJECT_ROOT%\zygisk-module\service.sh" "%ZIP_DIR%\"
copy /y "%PROJECT_ROOT%\zygisk-module\sepolicy.rule" "%ZIP_DIR%\"
copy /y "%PROJECT_ROOT%\zygisk-module\config\policy.json" "%ZIP_DIR%\config\"
copy /y "%PROJECT_ROOT%\zygisk-module\libs\arm64-v8a\libkguard_zygisk.so" "%ZIP_DIR%\zygisk\arm64-v8a.so"
copy /y "%OUTPUT_DIR%\kguard-supervisor" "%ZIP_DIR%\"

echo Output ready in: %OUTPUT_DIR%
echo Zip packaging directory prepared at: %ZIP_DIR%
echo Done!
exit /b 0

:err
echo Build failed!
exit /b 1
