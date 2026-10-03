#!/system/bin/sh
MODDIR="${0%/*}"
URL="http://127.0.0.1:8765/index.html"
echo "- Refreshing TIRN Security rules..."
if /system/bin/sh "$MODDIR/service.sh" --refresh >/dev/null 2>&1; then
    echo "- Firewall refresh ✓"
else
    echo "- Firewall refresh failed ✗"
    exit 1
fi
echo "- Starting TIRN Security web UI..."
if /system/bin/sh "$MODDIR/webserver.sh"; then
    echo "- Web server started ✓"
else
    echo "- Web server failed ✗"
    exit 1
fi
echo "- Opening TIRN Security..."
am start -a android.intent.action.VIEW -d "$URL" >/dev/null 2>&1
echo "- Browser launch triggered ✓"
exit 0
