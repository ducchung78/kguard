#!/system/bin/sh
MODDIR=${0%/*}

# 1. Load kguard kernel module if present
if [ -f "$MODDIR/kguard.ko" ]; then
    insmod "$MODDIR/kguard.ko" 2>/dev/null
    sleep 0.2
fi

# 2. Check /dev/kguard character device node
if [ ! -c /dev/kguard ]; then
    # In case mknod is needed manually
    MAJOR=$(grep kguard /proc/devices | awk '{print $1}')
    if [ -n "$MAJOR" ]; then
        mknod /dev/kguard c "$MAJOR" 0
    fi
fi

if [ -c /dev/kguard ]; then
    chmod 0666 /dev/kguard
fi

# 3. Apply baseline boot property sanitization via resetprop
if command -v resetprop >/dev/null 2>&1; then
    resetprop -n ro.boot.vbmeta.device_state "locked"
    resetprop -n ro.boot.verifiedbootstate "green"
    resetprop -n ro.boot.flash.locked "1"
    resetprop -n ro.debuggable "0"
    resetprop -n ro.secure "1"
    resetprop -n ro.build.type "user"
    resetprop -n ro.build.tags "release-keys"
fi
