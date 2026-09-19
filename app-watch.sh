#!/system/bin/sh

MODDIR="${0%/*}"
DATA_DIR="/data/adb/tirnsecurity"
POLICY_FILE="$DATA_DIR/policy.conf"
LOGCAT="/system/bin/logcat"
SH="/system/bin/sh"

LOG="$DATA_DIR/service.log"
EVENT="$DATA_DIR/app-watch.event"

. "$MODDIR/logging-common.sh"
AUDIT_LOG="$LOG"
DEBUG_LOG="$DATA_DIR/debug.log"
LOCK="$DATA_DIR/app-watch.lock"
DEBOUNCE=2

WORKER_PID=""

refresh_cache() {
    debug_log "Apps" "Cache refresh started" "startup cache refresh"

    REFRESH_START="$(date +%s)"

    if "$SH" "$MODDIR/refresh_apps" >/dev/null 2>&1; then
        REFRESH_DURATION=$(( $(date +%s) - REFRESH_START ))
        log_info "Apps" "Cache refreshed" "application database updated duration=${REFRESH_DURATION}s"
    else
        REFRESH_DURATION=$(( $(date +%s) - REFRESH_START ))
        log_error "Apps" "Cache refresh failed" "application database update failed duration=${REFRESH_DURATION}s"
    fi
}

queue_event() {
    EVENT_DATA="$(cat "$EVENT" 2>/dev/null)"

    ACTION="$(printf '%s\n' "$EVENT_DATA" | cut -d'|' -f1)"
    PACKAGE="$(printf '%s\n' "$EVENT_DATA" | cut -d'|' -f2)"

    [ -n "$ACTION" ] || return 0
    [ -n "$PACKAGE" ] || return 0

    if ! "$SH" "$MODDIR/app-queue.sh" add "$ACTION" "$PACKAGE" >/dev/null 2>&1; then
        log_error "App Watcher" "Queue failed" "$ACTION $PACKAGE"
    fi
}

process_queue() {
    while true
    do
        ITEM="$("$SH" "$MODDIR/app-queue.sh" next 2>/dev/null)"

        if [ -z "$ITEM" ] || [ "$ITEM" = "QUEUE_EMPTY" ] || [ "$ITEM" = "QUEUE_BUSY" ]; then
            sleep 2
            continue
        fi

        ACTION="$(printf '%s\n' "$ITEM" | cut -d'|' -f1)"
        PACKAGE="$(printf '%s\n' "$ITEM" | cut -d'|' -f2)"

        if [ -z "$ACTION" ] || [ -z "$PACKAGE" ]; then
            sleep 2
            continue
        fi

        RESULT="$("$MODDIR/apphelper" "$ACTION" "$PACKAGE" 2>&1)"
        STATUS=$?

        if [ "$STATUS" -eq 0 ]; then
            if [ "$ACTION" = "REMOVED" ]; then
                POLICY_TMP="$DATA_DIR/policy.conf.tmp.$$"

                if awk -F"|" -v pkg="$PACKAGE" '$2 != pkg {print}' "$POLICY_FILE" > "$POLICY_TMP"; then
                    mv -f "$POLICY_TMP" "$POLICY_FILE"
                    log_info "Policy" "Removed package rules" "$PACKAGE"
                else
                    rm -f "$POLICY_TMP"
                    log_error "Policy" "Package rule cleanup failed" "$PACKAGE"
                fi
            fi

            "$SH" "$MODDIR/app-queue.sh" remove >/dev/null 2>&1
            log_info "Package" "Database updated" "$ACTION $PACKAGE"
        elif printf '%s\n' "$RESULT" | grep -q "APPS_BUSY"; then
            sleep 10
        else
            log_error "Package" "Database update failed" "$ACTION $PACKAGE"
            "$SH" "$MODDIR/app-queue.sh" retry >/dev/null 2>&1
            sleep 5
        fi
    done
}

cleanup() {
    [ -n "$WORKER_PID" ] && kill "$WORKER_PID" 2>/dev/null
    [ -n "$QUEUE_PID" ] && kill "$QUEUE_PID" 2>/dev/null
    rm -f "$EVENT"
    rmdir "$LOCK" 2>/dev/null || true
    exit 0
}

mkdir -p "$DATA_DIR" || exit 1

if ! mkdir "$LOCK" 2>/dev/null; then
    log_warn "App Watcher" "Already running" "duplicate start ignored"
    exit 0
fi

trap cleanup EXIT INT TERM HUP

rm -f "$EVENT"

log_info "App Watcher" "Started" "package event monitor"

refresh_cache

(
    while true
    do
        if [ -f "$EVENT" ]; then
            LAST="$(cat "$EVENT" 2>/dev/null)"

            sleep "$DEBOUNCE"

            CURRENT="$(cat "$EVENT" 2>/dev/null)"

            if [ "$LAST" = "$CURRENT" ]; then
                rm -f "$EVENT"
            fi
        else
            sleep 1
        fi
    done
) &

WORKER_PID=$!

process_queue &
QUEUE_PID=$!

while true
do
    START_TIME="$(date "+%m-%d %H:%M:%S.000")"

    "$LOGCAT" -v threadtime -T "$START_TIME" 2>/dev/null |
    while IFS= read -r line
    do
        case "$line" in
            *PACKAGE_ADDED*)
                PACKAGE="$(printf '%s\n' "$line" | sed -n 's/.*dat=package:\([^ ]*\).*/\1/p; s/.*pkg=\([^ ]*\).*/\1/p; s/.*for package \([^ ]*\).*/\1/p')"
                if [ -n "$PACKAGE" ]; then
                    log_info "Package" "Event detected" "ADDED $PACKAGE"
                    printf 'ADDED|%s|%s\n' "$PACKAGE" "$(date +%s)" > "$EVENT"
                    queue_event
                fi
                ;;

            *PACKAGE_REPLACED*)
                PACKAGE="$(printf '%s\n' "$line" | sed -n 's/.*dat=package:\([^ ]*\).*/\1/p; s/.*pkg=\([^ ]*\).*/\1/p; s/.*for package \([^ ]*\).*/\1/p')"
                if [ -n "$PACKAGE" ]; then
                    log_info "Package" "Event detected" "REPLACED $PACKAGE"
                    printf 'REPLACED|%s|%s\n' "$PACKAGE" "$(date +%s)" > "$EVENT"
                    queue_event
                fi
                ;;

            *PACKAGE_REMOVED*|*PACKAGE_FULLY_REMOVED*)
                PACKAGE="$(printf '%s\n' "$line" | sed -n 's/.*dat=package:\([^ ]*\).*/\1/p; s/.*pkg=\([^ ]*\).*/\1/p; s/.*for package \([^ ]*\).*/\1/p')"
                if [ -n "$PACKAGE" ]; then
                    log_info "Package" "Event detected" "REMOVED $PACKAGE"
                    printf 'REMOVED|%s|%s\n' "$PACKAGE" "$(date +%s)" > "$EVENT"
                    queue_event
                fi
                ;;

        esac
    done

    log_warn "App Watcher" "Log monitor restarted" "logcat monitor exited"
    sleep 2
done
