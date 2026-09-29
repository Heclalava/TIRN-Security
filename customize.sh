#!/system/bin/sh

MODDIR="$MODPATH"
DATA_DIR="/data/adb/tirnsecurity"
INSTALL_LOG="$DATA_DIR/installation.log"

mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"

if [ -f "$MODDIR/data/labels.conf" ]; then
    cp -f "$MODDIR/data/labels.conf" "$DATA_DIR/labels.conf"
    chmod 600 "$DATA_DIR/labels.conf"
fi

if [ -f "$MODDIR/app-common.sh" ]; then
    cp -f "$MODDIR/app-common.sh" "$DATA_DIR/app-common.sh"
    chmod 755 "$DATA_DIR/app-common.sh"
fi

log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$INSTALL_LOG"
}

MODNAME=$(grep_prop name "$TMPDIR/module.prop")
MODVER=$(grep_prop version "$TMPDIR/module.prop")
AUTHOR=$(grep_prop author "$TMPDIR/module.prop")

BRAND=$(getprop ro.product.brand)
MODEL=$(getprop ro.product.model)
ANDROID=$(getprop ro.system.build.version.release)
SDK=$(getprop ro.build.version.sdk)
ARCH=$(getprop ro.product.cpu.abi)
SE=$(getenforce)

log_msg "========================================="
log_msg "          TIRN Security Installer"
log_msg "========================================="
log_msg "Module Name    : $MODNAME"
log_msg "Version        : $MODVER"
log_msg "Author         : $AUTHOR"
log_msg "Device         : $BRAND $MODEL"
log_msg "Android        : $ANDROID (SDK $SDK)"
log_msg "Architecture   : $ARCH"
log_msg "SELinux        : $SE"
log_msg "Module Path    : $MODDIR"
log_msg "Data Path      : $DATA_DIR"
log_msg "========================================="



chmod 755 "$MODDIR/action.sh" "$MODDIR/apphelper" "$MODDIR/appaudit" "$MODDIR/app-watch.sh" "$MODDIR/apklabel" "$MODDIR/customize.sh" "$MODDIR/policy-watch.sh" "$MODDIR/policy-watch.sh-handler" "$MODDIR/post-fs-data.sh" "$MODDIR/refresh_apps" "$MODDIR/refresh_app_single" "$MODDIR/service.sh" "$MODDIR/uninstall.sh" "$MODDIR/verify.sh" "$MODDIR/webserver.sh" "$MODDIR/webserver-start.sh"
chmod 644 "$MODDIR/webroot/ui"
chmod 755 "$MODDIR/webroot/cgi-bin/apps" "$MODDIR/webroot/cgi-bin/apps-refresh-progress" "$MODDIR/webroot/cgi-bin/apps-revision" "$MODDIR/webroot/cgi-bin/logs" "$MODDIR/webroot/cgi-bin/policy" "$MODDIR/webroot/cgi-bin/policy-import" "$MODDIR/webroot/cgi-bin/policy-import-commit" "$MODDIR/webroot/cgi-bin/policy-stale-commit" "$MODDIR/webroot/cgi-bin/policy-stale-scan" "$MODDIR/webroot/cgi-bin/refresh-apps" "$MODDIR/webroot/cgi-bin/status"


log_msg "TIRN Security installation files verified"
log_msg "Installation completed"
exit 0
