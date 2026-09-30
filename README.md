# KGuard — Android Process Isolation & Anti-Detection Framework

> **Target Platform:** RedMagic 8 Pro (NX729J) · Qualcomm Snapdragon 8 Gen 2 (SM8550)  
> **Kernel Version:** Linux 5.15.167 (msm-kernel / GKI 2.0, ARM64)  
> **Android Base:** Android 13 (Tiramisu) / Android 14 (Upside Down Cake)

---

## 1. Cấu trúc Dự án

```
kguard-android/
├── test-harness/          # Phase 1: Bộ kiểm thử mô phỏng 9 vector phát hiện
│   └── jni/
│       ├── main.c                  # Scoring & runner
│       ├── detect_maps.c           # /proc/self/maps H1-H5 scanner
│       ├── detect_integrity.c      # .text SHA256 & trampoline scanner
│       ├── detect_got.c            # PLT/GOT integrity inspector
│       ├── detect_syscall.S        # Direct ARM64 syscall stubs (SVC #0)
│       ├── detect_linker.c         # Linker / soinfo cross-check
│       ├── detect_seccomp.c        # Seccomp filter detector
│       ├── detect_namespace.c      # Mount namespace isolation checker
│       ├── detect_tee.c            # TEE Simulator & Keybox file detector
│       ├── detect_props.c          # System property analysis
│       ├── detect_timing.c         # Timing side-channel detector
│       └── utils/                  # ELF parser & SHA-256
│
├── kguard-module/         # Phase 2: Kernel Module (kguard.ko)
│   ├── Kbuild & Makefile           # Cross-compilation for Linux 5.15
│   ├── kguard_main.c               # /dev/kguard misc device & ioctl
│   ├── kguard_ftrace.c             # CFI-safe ftrace hooking engine
│   ├── kguard_pid.c                # RCU-protected PID hash table
│   ├── kguard_filter.c             # Multi-layer string & path filter
│   ├── kguard_procfs_maps.c        # show_map_vma & show_smap hook
│   ├── kguard_procfs_mounts.c      # show_vfsmnt & show_mountinfo hook
│   ├── kguard_file_hide.c          # do_faccessat & do_sys_openat2 hook
│   └── include/
│       ├── kguard.h                # Internal kernel declarations
│       └── kguard_uapi.h           # Shared ioctl API
│
├── zygisk-module/         # Phase 2: Zygisk Native Module
│   ├── module.prop & customize.sh  # Magisk / KernelSU installer
│   ├── post-fs-data.sh             # Early driver loader & resetprop
│   ├── service.sh                  # Supervisor daemon watchdog
│   ├── sepolicy.rule               # SELinux transition policies
│   ├── config/policy.json          # Target package rules (Banking & GMS)
│   └── jni/
│       ├── main.cpp                # Zygisk lifecycle & DLCLOSE zero-footprint
│       ├── namespace_cleanup.cpp   # unshare(CLONE_NEWNS) & mount detachment
│       ├── seccomp_filter.cpp      # Seccomp-BPF & io_uring block
│       ├── property_spoof.cpp      # Runtime Build & property spoofing
│       └── kguard_client.cpp       # Client ioctl to /dev/kguard
│
├── supervisor/            # Phase 2: Seccomp Supervisor Daemon
│   └── jni/
│       ├── supervisor_main.c       # epoll listener on /data/adb/kguard/supervisor.sock
│       ├── supervisor_handler.c    # SECCOMP_IOCTL_NOTIF dispatcher & filter
│       ├── supervisor_maps.c       # In-memory memfd sanitized maps generator
│       └── supervisor_watchdog.c   # Heartbeat watchdog thread
│
├── build_all.sh           # Linux / WSL build script
├── build_all.bat          # Windows batch build script
└── README.md
```

---

## 2. Hướng dẫn Build

### Yêu cầu
- **Android NDK r25b+** (đã cấu hình trong `PATH` để gọi `ndk-build`).
- **AOSP Clang toolchain + MSM Kernel Source** (dành cho `kguard.ko`).

### Biên dịch Userland & Zygisk Module
Trên Windows:
```cmd
cd C:\Users\ASUS\.gemini\antigravity\scratch\kguard-android
build_all.bat
```
Trên Linux / macOS:
```bash
chmod +x build_all.sh
./build_all.sh
```

### Biên dịch Kernel Module (`kguard.ko`)
```bash
cd kguard-module
make KERNEL_DIR=/path/to/redmagic_sm8550_kernel ARCH=arm64 CROSS_COMPILE=aarch64-linux-android-
```

---

## 3. Quy trình Triển khai trên RedMagic 8 Pro

1. **Cài đặt Module qua Magisk / KernelSU:**
   - Flash file `dist/KGuard-v1.0.0-SM8550.zip`.
   - Nếu tự build kernel module: chép `kguard.ko` vào thư mục module `/data/adb/modules/kguard/kguard.ko`.
   - Khởi động lại thiết bị.

2. **Chạy Test Harness kiểm thử:**
   ```bash
   adb push dist/kguard-detect /data/local/tmp/
   adb shell chmod 755 /data/local/tmp/kguard-detect
   adb shell /data/local/tmp/kguard-detect --verbose
   ```

