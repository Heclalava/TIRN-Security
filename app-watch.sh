#!/system/bin/sh

MODDIR="${0%/*}"
DATA_DIR="/data/adb/tirnsecurity"
LOGCAT="/system/bin/logcat"
SH="/system/bin/sh"

LOG="$DATA_DIR/service.log"
EVENT="$DATA_DIR/app-watch.event"
LOCK="$DATA_DIR/app-watch.lock"
DEBOUNCE=2

WORKER_PID=""

log_msg() {
    printf "[%s] %s\n" "$(date "+%Y-%m-%d %H:%M:%S")" "$1" >> "$LOG"
}

refresh_cache() {
    log_msg "Refreshing apps cache"

    if "$SH" "$MODDIR/refresh_apps" >/dev/null 2>&1; then
        log_msg "Apps cache refreshed"
    else
        log_msg "ERROR: Apps cache refresh failed"
    fi
}

queue_event() {
    EVENT_DATA="$(cat "$EVENT" 2>/dev/null)"

    ACTION="$(printf '%s\n' "$EVENT_DATA" | cut -d'|' -f1)"
    PACKAGE="$(printf '%s\n' "$EVENT_DATA" | cut -d'|' -f2)"

    [ -n "$ACTION" ] || return 0
    [ -n "$PACKAGE" ] || return 0

    if "$SH" "$MODDIR/app-queue.sh" add "$ACTION" "$PACKAGE" >/dev/null 2>&1; then
        log_msg "Queued app event: $ACTION $PACKAGE"
    else
        log_msg "ERROR: Failed to queue app event: $ACTION $PACKAGE"
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

        log_msg "Processing app event: $ACTION $PACKAGE"

        RESULT="$("$MODDIR/apphelper" "$ACTION" "$PACKAGE" 2>&1)"
        STATUS=$?

        printf '%s\n' "$RESULT" >> "$LOG"

        if [ "$STATUS" -eq 0 ]; then
            "$SH" "$MODDIR/app-queue.sh" remove >/dev/null 2>&1
            log_msg "App event completed: $ACTION $PACKAGE"
        elif printf '%s\n' "$RESULT" | grep -q "APPS_BUSY"; then
            log_msg "Apps cache busy, retrying later: $ACTION $PACKAGE"
            sleep 10
        else
            log_msg "App event failed: $ACTION $PACKAGE"
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
    log_msg "App watcher already running"
    exit 0
fi

trap cleanup EXIT INT TERM HUP

rm -f "$EVENT"

log_msg "App watcher started"

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
            *PACKAGE_ADDED*|*PACKAGE_REMOVED*|*PACKAGE_REPLACED*|*PACKAGE_FULLY_REMOVED*)
                log_msg "DEBUG package line: $line"
                ;;
        esac

        case "$line" in
            *PACKAGE_ADDED*)
                PACKAGE="$(printf '%s\n' "$line" | sed -n 's/.*dat=package:\([^ ]*\).*/\1/p; s/.*pkg=\([^ ]*\).*/\1/p; s/.*for package \([^ ]*\).*/\1/p')"
                if [ -n "$PACKAGE" ]; then
                    log_msg "Package event detected: ADDED $PACKAGE"
                    printf 'ADDED|%s|%s\n' "$PACKAGE" "$(date +%s)" > "$EVENT"
                    queue_event
                fi
                ;;

            *PACKAGE_REPLACED*)
                PACKAGE="$(printf '%s\n' "$line" | sed -n 's/.*dat=package:\([^ ]*\).*/\1/p; s/.*pkg=\([^ ]*\).*/\1/p; s/.*for package \([^ ]*\).*/\1/p')"
                if [ -n "$PACKAGE" ]; then
                    log_msg "Package event detected: REPLACED $PACKAGE"
                    printf 'REPLACED|%s|%s\n' "$PACKAGE" "$(date +%s)" > "$EVENT"
                    queue_event
                fi
                ;;

            *PACKAGE_REMOVED*|*PACKAGE_FULLY_REMOVED*)
                PACKAGE="$(printf '%s\n' "$line" | sed -n 's/.*dat=package:\([^ ]*\).*/\1/p; s/.*pkg=\([^ ]*\).*/\1/p; s/.*for package \([^ ]*\).*/\1/p')"
                if [ -n "$PACKAGE" ]; then
                    log_msg "Package event detected: REMOVED $PACKAGE"
                    printf 'REMOVED|%s|%s\n' "$PACKAGE" "$(date +%s)" > "$EVENT"
                    queue_event
                fi
                ;;

        esac
    done

    log_msg "App log monitor exited, restarting"
    sleep 2
done
