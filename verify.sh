#!/system/bin/sh

MODPATH="${0%/*}"

echo "========================================="
echo "        TIRN Security Verification"
echo "========================================="

FAILED=0

check_file() {
    if [ -f "$1" ]; then
        echo "[OK] $1"
    else
        echo "[FAIL] Missing: $1"
        FAILED=1
    fi
}

check_file "$MODPATH/module.prop"
check_file "$MODPATH/service.sh"
check_file "$MODPATH/customize.sh"
check_file "$MODPATH/uninstall.sh"
check_file "$MODPATH/webroot/index.html"
check_file "$MODPATH/webroot/ui"

if [ "$FAILED" -eq 0 ]; then
    echo "========================================="
    echo "Verification successful"
    echo "========================================="
    exit 0
fi

echo "========================================="
echo "Verification failed"
echo "========================================="
exit 1
