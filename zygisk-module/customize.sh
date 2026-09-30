SKIPUNZIP=0

ui_print "***************************************************"
ui_print "*   KGuard Isolation Framework for RedMagic 8 Pro *"
ui_print "*        Kernel 5.15.167 (SM8550 Platform)        *"
ui_print "***************************************************"

# Check Architecture
if [ "$ARCH" != "arm64" ]; then
    abort "! Unsupported CPU Architecture: $ARCH (Requires ARM64)"
fi

# Check Kernel Version
KERNEL_VER=$(uname -r)
ui_print "- Detected Kernel: $KERNEL_VER"
case "$KERNEL_VER" in
    5.15*)
        ui_print "- Verified Linux 5.15 GKI base."
        ;;
    *)
        ui_print "! Warning: Kernel is not 5.15 ($KERNEL_VER). Some ftrace hooks may require adaptation."
        ;;
esac

# Create persistent runtime data directories
mkdir -p /data/adb/kguard
mkdir -p /data/adb/kguard/bin
chmod 700 /data/adb/kguard

# Copy default config if not present
if [ ! -f /data/adb/kguard/policy.json ]; then
    ui_print "- Deploying default policy configuration..."
    cp "$MODPATH/config/policy.json" /data/adb/kguard/policy.json
    chmod 644 /data/adb/kguard/policy.json
fi

# Set proper permissions for module directories & binaries
set_perm_recursive "$MODPATH" 0 0 0755 0644
set_perm "$MODPATH/post-fs-data.sh" 0 0 0755
set_perm "$MODPATH/service.sh" 0 0 0755

ui_print "- Installation complete. Please reboot to activate kernel driver and Zygisk engine."
