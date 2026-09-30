#!/system/bin/sh
MODDIR=${0%/*}

# Start kguard-supervisor daemon
SUPERVISOR_BIN="$MODDIR/kguard-supervisor"
RUN_DIR="/data/adb/kguard"

mkdir -p "$RUN_DIR"
chmod 700 "$RUN_DIR"

if [ -f "$SUPERVISOR_BIN" ]; then
    chmod 755 "$SUPERVISOR_BIN"
    
    # Watchdog loop
    while true; do
        if ! pgrep -f "$SUPERVISOR_BIN" >/dev/null 2>&1; then
            "$SUPERVISOR_BIN" &
        fi
        sleep 10
    done &
fi
