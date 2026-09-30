import os
import zipfile
import shutil

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DIST_DIR = os.path.join(PROJECT_ROOT, "dist")
STAGE_DIR = os.path.join(DIST_DIR, "kguard-magisk")
ZIP_PATH = os.path.join(DIST_DIR, "KGuard-v1.0.0-SM8550.zip")

def main():
    print(f"Creating packaging staging directory at: {STAGE_DIR}")
    if os.path.exists(STAGE_DIR):
        shutil.rmtree(STAGE_DIR)
    os.makedirs(STAGE_DIR, exist_ok=True)

    # 1. Structure directories
    os.makedirs(os.path.join(STAGE_DIR, "META-INF", "com", "google", "android"), exist_ok=True)
    os.makedirs(os.path.join(STAGE_DIR, "config"), exist_ok=True)
    os.makedirs(os.path.join(STAGE_DIR, "zygisk"), exist_ok=True)

    # 2. Copy module base files
    zygisk_src = os.path.join(PROJECT_ROOT, "zygisk-module")
    
    shutil.copy2(os.path.join(zygisk_src, "module.prop"), STAGE_DIR)
    shutil.copy2(os.path.join(zygisk_src, "customize.sh"), STAGE_DIR)
    shutil.copy2(os.path.join(zygisk_src, "post-fs-data.sh"), STAGE_DIR)
    shutil.copy2(os.path.join(zygisk_src, "service.sh"), STAGE_DIR)
    shutil.copy2(os.path.join(zygisk_src, "sepolicy.rule"), STAGE_DIR)
    shutil.copy2(os.path.join(zygisk_src, "config", "policy.json"), os.path.join(STAGE_DIR, "config", "policy.json"))

    # META-INF installer scripts
    shutil.copy2(os.path.join(zygisk_src, "META-INF", "com", "google", "android", "update-binary"),
                 os.path.join(STAGE_DIR, "META-INF", "com", "google", "android", "update-binary"))
    shutil.copy2(os.path.join(zygisk_src, "META-INF", "com", "google", "android", "updater-script"),
                 os.path.join(STAGE_DIR, "META-INF", "com", "google", "android", "updater-script"))

    # Add README
    with open(os.path.join(STAGE_DIR, "README.txt"), "w", encoding="utf-8") as f:
        f.write("KGuard Magisk/KernelSU Module for RedMagic 8 Pro (SM8550)\n")

    # If compiled binaries exist, include them
    compiled_zygisk_so = os.path.join(PROJECT_ROOT, "zygisk-module", "libs", "arm64-v8a", "libkguard_zygisk.so")
    if os.path.exists(compiled_zygisk_so):
        shutil.copy2(compiled_zygisk_so, os.path.join(STAGE_DIR, "zygisk", "arm64-v8a.so"))
        print("Included compiled libkguard_zygisk.so as zygisk/arm64-v8a.so")
    else:
        # Keep directory alive
        with open(os.path.join(STAGE_DIR, "zygisk", ".keep"), "w") as f:
            f.write("")

    compiled_supervisor = os.path.join(PROJECT_ROOT, "supervisor", "libs", "arm64-v8a", "kguard-supervisor")
    if os.path.exists(compiled_supervisor):
        shutil.copy2(compiled_supervisor, os.path.join(STAGE_DIR, "kguard-supervisor"))
        print("Included compiled kguard-supervisor")

    compiled_ko = os.path.join(PROJECT_ROOT, "kguard-module", "kguard.ko")
    if os.path.exists(compiled_ko):
        shutil.copy2(compiled_ko, os.path.join(STAGE_DIR, "kguard.ko"))
        print("Included compiled kguard.ko")

    # 3. Create zip archive with POSIX forward slashes
    if os.path.exists(ZIP_PATH):
        os.remove(ZIP_PATH)

    with zipfile.ZipFile(ZIP_PATH, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(STAGE_DIR):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, STAGE_DIR)
                # Force forward slash for POSIX/Android compatibility
                arcname = rel_path.replace(os.sep, '/')
                zf.write(full_path, arcname=arcname)

    print(f"Successfully packaged ZIP: {ZIP_PATH} ({os.path.getsize(ZIP_PATH)} bytes)")

if __name__ == "__main__":
    main()
