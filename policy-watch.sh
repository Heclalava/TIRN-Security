#!/system/bin/sh
MODDIR="${0%/*}"
DATA_DIR="/data/adb/tirnsecurity"
POLICY_FILE="$DATA_DIR/policy.conf"
SERVICE="$MODDIR/service.sh"

while true; do
    /system/bin/inotifyd "$MODDIR/policy-watch.sh-handler" "$POLICY_FILE:w" "$DATA_DIR:my"
    sleep 1
done
