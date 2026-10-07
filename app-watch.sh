#!/system/bin/sh

MODDIR="${0%/*}"
DATA_DIR="/data/adb/tirnsecurity"

LOGCAT="/system/bin/logcat"
PM="/system/bin/pm"
SH="/system/bin/sh"
DATE="/system/bin/date"
if [ -x /system/bin/awk ]; then
    AWK="/system/bin/awk"
elif [ -x /system/xbin/awk ]; then
    AWK="/system/xbin/awk"
else
    exit 1
fi
SED="/system/bin/sed"
GREP="/system/bin/grep"
SORT="/system/bin/sort"
CAT="/system/bin/cat"
CUT="/system/bin/cut"
MV="/system/bin/mv"
RM="/system/bin/rm"
MKDIR="/system/bin/mkdir"

LOG="$DATA_DIR/service.log"
DEBUG_LOG="$DATA_DIR/debug.log"
LOCK="$DATA_DIR/app-watch.lock"
APP_EVENT_QUEUE="$DATA_DIR/app-events"

DEBOUNCE=2

. "$MODDIR/logging-common.sh" || exit 1
AUDIT_LOG="$LOG"
DEBUG_LOG="$DEBUG_LOG"

mkdir -p "$DATA_DIR" || exit 1
chmod 700 "$DATA_DIR"

if ! "$MKDIR" "$APP_EVENT_QUEUE" 2>/dev/null; then
    if [ ! -d "$APP_EVENT_QUEUE" ]; then
        log_error "App Watcher" "Startup failed" "unable to create app event directory"
        exit 1
    fi
fi

chmod 700 "$APP_EVENT_QUEUE"

if ! mkdir "$LOCK" 2>/dev/null; then
    log_warn "App Watcher" "Already running" "lock=$LOCK"
    exit 0
fi

WATCH_PID=$$
WATCH_START="$("$AWK" '{print $22}' /proc/$$/stat 2>/dev/null)"

if [ -z "$WATCH_START" ]; then
    log_error "App Watcher" "Startup failed"         "unable to determine process start time"
    exit 1
fi

printf '%s %s\n' "$WATCH_PID" "$WATCH_START" > "$LOCK/.owner.tmp" &&
"$MV" -f "$LOCK/.owner.tmp" "$LOCK/owner" || {
    log_error "App Watcher" "Startup failed"         "unable to create lock owner"
    exit 1
}

cleanup() {
    if [ -n "${LOGCAT_PID:-}" ]; then
        kill "$LOGCAT_PID" 2>/dev/null
    fi

    "$RM" -f "$APP_EVENT_QUEUE"/.watch.* 2>/dev/null
    "$RM" -f "$APP_EVENT_QUEUE"/.work.* 2>/dev/null
    "$RM" -rf "$LOCK" 2>/dev/null
}

trap cleanup EXIT
trap 'cleanup; exit 0' INT TERM HUP

UNINSTALL_ACTIVE=0
UNINSTALL_PACKAGE=""
UNINSTALL_USER=""
UNINSTALL_ALL_USERS=""

queue_event() {
    QUEUE_ACTION="$1"
    QUEUE_USER="$2"
    QUEUE_PACKAGE="$3"

    case "$QUEUE_ACTION" in
        ADDED|REPLACED|REMOVED)
            ;;
        *)
            return 1
            ;;
    esac

    case "$QUEUE_USER" in
        ''|*[!0-9]*)
            return 1
            ;;
    esac

    case "$QUEUE_PACKAGE" in
        ''|*[!A-Za-z0-9._-]*)
            return 1
            ;;
    esac

    EVENT_FILE="$APP_EVENT_QUEUE/${QUEUE_USER}_${QUEUE_PACKAGE}"
    EVENT_TMP="$APP_EVENT_QUEUE/.event.$$"

    OLD_ACTION=""
    if [ -f "$EVENT_FILE" ]; then
        OLD_ACTION="$("$AWK" -F'|' 'NR == 1 {print $1}' "$EVENT_FILE" 2>/dev/null)"
    fi

    if [ -n "$OLD_ACTION" ]; then
        case "$QUEUE_ACTION" in
            REMOVED)
                QUEUE_ACTION="REMOVED"
                ;;
            REPLACED)
                case "$OLD_ACTION" in
                    REMOVED) QUEUE_ACTION="REMOVED" ;;
                    *)       QUEUE_ACTION="REPLACED" ;;
                esac
                ;;
            ADDED)
                case "$OLD_ACTION" in
                    REMOVED)  QUEUE_ACTION="REMOVED" ;;
                    REPLACED) QUEUE_ACTION="REPLACED" ;;
                    *)        QUEUE_ACTION="ADDED" ;;
                esac
                ;;
        esac
    fi

    printf '%s|%s|%s|%s\n' \
        "$QUEUE_ACTION" \
        "$QUEUE_USER" \
        "$QUEUE_PACKAGE" \
        "$("$DATE" +%s)" > "$EVENT_TMP" || {
        "$RM" -f "$EVENT_TMP"
        return 1
    }

    "$MV" -f "$EVENT_TMP" "$EVENT_FILE" || {
        "$RM" -f "$EVENT_TMP"
        return 1
    }

    debug_log "App Watcher" "Queued package event" \
        "action=$QUEUE_ACTION user=$QUEUE_USER package=$QUEUE_PACKAGE"

    return 0
}

process_logcat_line() {
    LINE="$1"

    if [ "$UNINSTALL_ACTIVE" -eq 1 ]; then
        case "$LINE" in
            *EXTRA_PACKAGE_NAME=*)
                UNINSTALL_PACKAGE="${LINE#*EXTRA_PACKAGE_NAME=}"
                UNINSTALL_PACKAGE="${UNINSTALL_PACKAGE%%,*}"
                UNINSTALL_PACKAGE="${UNINSTALL_PACKAGE%%]*}"
                ;;
            *EXTRA_TARGET_USER_ID=*)
                UNINSTALL_USER="${LINE#*EXTRA_TARGET_USER_ID=}"
                UNINSTALL_USER="${UNINSTALL_USER%%,*}"
                UNINSTALL_USER="${UNINSTALL_USER%%]*}"
                ;;
            *android.intent.extra.UNINSTALL_ALL_USERS=*)
                UNINSTALL_ALL_USERS="${LINE#*android.intent.extra.UNINSTALL_ALL_USERS=}"
                UNINSTALL_ALL_USERS="${UNINSTALL_ALL_USERS%%,*}"
                UNINSTALL_ALL_USERS="${UNINSTALL_ALL_USERS%%]*}"
                ;;
        esac

        case "$LINE" in
            *"}]"*)
                if [ "$UNINSTALL_ALL_USERS" = "false" ] &&
                   [ -n "$UNINSTALL_PACKAGE" ] &&
                   [ -n "$UNINSTALL_USER" ]; then
                    process_profile "REMOVED" \
                        "$UNINSTALL_USER" \
                        "$UNINSTALL_PACKAGE"
                fi

                UNINSTALL_ACTIVE=0
                UNINSTALL_PACKAGE=""
                UNINSTALL_USER=""
                UNINSTALL_ALL_USERS=""
                ;;
        esac

        return 0
    fi

    case "$LINE" in
        *"ActivityManager:"*"Force stopping "*"pkg removed"*)
            EVENT_PACKAGE="${LINE#*Force stopping }"
            EVENT_PACKAGE="${EVENT_PACKAGE%% appid=*}"

            EVENT_USER="${LINE#* user=}"
            EVENT_USER="${EVENT_USER%%:*}"

            case "$EVENT_USER" in
                ''|*[!0-9]*)
                    return 0
                    ;;
            esac

            if [ -n "$EVENT_PACKAGE" ]; then
                if "$PM" list packages --user "$EVENT_USER" "$EVENT_PACKAGE" 2>/dev/null |
                    "$GREP" -q "^package:$EVENT_PACKAGE$"
                then
                    debug_log "App Watcher" "Ignoring stale REMOVED event after replace" \
                        "user=$EVENT_USER package=$EVENT_PACKAGE"
                else
                    debug_log "App Watcher" "Confirmed package removal" \
                        "user=$EVENT_USER package=$EVENT_PACKAGE"
                    process_profile "REMOVED" "$EVENT_USER" "$EVENT_PACKAGE"
                fi
            fi

            return 0
            ;;

        *"ActivityManager:"*"Force stopping "*)
            return 0
            ;;
    esac

    case "$LINE" in
        *"PackageManager:"*"Update package "*)
            EVENT_PACKAGE="${LINE#*Update package }"
            EVENT_PACKAGE="${EVENT_PACKAGE%% *}"
            EVENT_ACTION="REPLACED"
            ;;

        *"PackageManager:"*"Package "*" codePath changed from "*"; Retaining data and using new"*)
            EVENT_PACKAGE="${LINE#*PackageManager: Package }"
            EVENT_PACKAGE="${EVENT_PACKAGE%% codePath changed from *}"
            debug_log "App Watcher" "Legacy REPLACED parser matched" \
                "package=$EVENT_PACKAGE"
            EVENT_ACTION="REPLACED"
            ;;

        *"PackageManager:"*"installation completed for package:"*)
            EVENT_PACKAGE="${LINE#*installation completed for package:}"
            EVENT_PACKAGE="${EVENT_PACKAGE%%. Final code path:*}"
            debug_log "App Watcher" "ADDED parser matched" \
                "package=$EVENT_PACKAGE"
            EVENT_ACTION="ADDED"
            ;;

        *"android.intent.action.PACKAGE_ADDED"*"dat=package:"*)
            EVENT_PACKAGE="${LINE#*dat=package:}"
            EVENT_PACKAGE="${EVENT_PACKAGE%% *}"
            debug_log "App Watcher" "Legacy ADDED parser matched" \
                "package=$EVENT_PACKAGE"
            EVENT_ACTION="ADDED"
            ;;

        *)
            return 0
            ;;
    esac

    case "$EVENT_PACKAGE" in
        ''|*[!A-Za-z0-9._-]*)
            return 0
            ;;
    esac

    case "$EVENT_ACTION" in
        ADDED|REPLACED)
            ORIGINAL_EVENT_ACTION="$EVENT_ACTION"
            "$PM" list users 2>/dev/null |
            "$SED" -n 's/.*UserInfo{\([0-9][0-9]*\):.*/\1/p' |
            "$SORT" -nu |
            while IFS= read -r USER
            do
                [ -n "$USER" ] || continue

                if "$PM" list packages --user "$USER" "$EVENT_PACKAGE" 2>/dev/null |
                    "$AWK" -v p="$EVENT_PACKAGE" '
                        $1 == ("package:" p) {
                            found=1
                            exit
                        }
                        END {
                            exit(found ? 0 : 1)
                        }
                    '
                then
                    debug_log "App Watcher" "ADDED identity resolved" \
                        "action=$ORIGINAL_EVENT_ACTION user=$USER package=$EVENT_PACKAGE"

                    process_profile "$ORIGINAL_EVENT_ACTION" "$USER" "$EVENT_PACKAGE"
                fi
            done
            ;;

        REMOVED)
            process_profile "$EVENT_ACTION" "$EVENT_USER" "$EVENT_PACKAGE"
            ;;
    esac
}

write_app_event() {
    APP_EVENT_ACTION="$1"
    APP_EVENT_USER="$2"
    APP_EVENT_PACKAGE="$3"

    EVENT_TMP="$APP_EVENT_QUEUE/.event.$$"
    EVENT_FILE="$APP_EVENT_QUEUE/${APP_EVENT_USER}_${APP_EVENT_PACKAGE}"

    printf '%s|%s|%s\n' \
        "$APP_EVENT_ACTION" "$APP_EVENT_USER" "$APP_EVENT_PACKAGE" > "$EVENT_TMP" || {
            "$RM" -f "$EVENT_TMP"
            return 1
        }

    "$MV" -f "$EVENT_TMP" "$EVENT_FILE" || {
        "$RM" -f "$EVENT_TMP"
        return 1
    }

    return 0
}

process_profile() {
    ACTION="$1"
    USER="$2"
    PACKAGE="$3"

    case "$ACTION" in
        ADDED|REPLACED|REMOVED)
            ;;
        *)
            log_error "Package" "Invalid action" \
                "action=$ACTION user=$USER package=$PACKAGE"
            return 1
            ;;
    esac

    RESULT="$("$MODDIR/apphelper" "$ACTION" "$USER" "$PACKAGE" 2>&1)"
    STATUS=$?

    if [ "$STATUS" -eq 0 ]; then
        RESULT_LINE="$(printf '%s\n' "$RESULT" | "$GREP" -E '^(ADDED|UPDATED|REMOVED|UNCHANGED)\|')"

        log_info "Package" "Processed" \
            "action=$ACTION user=$USER package=$PACKAGE status=${RESULT_LINE:-OK}"

        EVENT_ACTION="$ACTION"

        RESULT_ACTION="$(printf '%s\n' "$RESULT_LINE" | "$CUT" -d'|' -f1)"
        RESULT_DETAIL="$(printf '%s\n' "$RESULT_LINE" | "$CUT" -d'|' -f2)"

        case "$RESULT_ACTION" in
            ADDED)
                case "$ACTION" in
                    REPLACED)
                        EVENT_ACTION="UNCHANGED"
                        ;;
                    *)
                        EVENT_ACTION="ADDED"
                        ;;
                esac
                ;;
            UPDATED|REMOVED)
                EVENT_ACTION="$RESULT_ACTION"
                ;;
            UNCHANGED)
                case "$RESULT_DETAIL" in
                    ADDED|UPDATED|REMOVED)
                        EVENT_ACTION="$RESULT_DETAIL"
                        ;;
                    REPLACED)
                        EVENT_ACTION="UNCHANGED"
                        ;;
                esac
                ;;
        esac

        case "$EVENT_ACTION" in
            ADDED|UPDATED|REMOVED)
                if ! write_app_event "$EVENT_ACTION" "$USER" "$PACKAGE"; then
                    log_error "Package" "Event dispatch failed" \
                        "action=$ACTION event_action=$EVENT_ACTION user=$USER package=$PACKAGE"
                    return 1
                fi
                ;;
            UNCHANGED)
                log_info "Package" "No policy event required" \
                    "action=$ACTION event_action=$EVENT_ACTION user=$USER package=$PACKAGE status=UNCHANGED"
                ;;
            *)
                log_warn "Package" "Policy event skipped" \
                    "action=$ACTION event_action=${EVENT_ACTION:-UNKNOWN} user=$USER package=$PACKAGE status=UNEXPECTED_APPHELPER_RESULT"
                ;;
        esac

        return 0
    fi

    if printf '%s\n' "$RESULT" | "$GREP" -q '^STATUS|NOT_INSTALLED|'; then
        log_warn "Package" "Profile resolution raced" \
            "action=$ACTION user=$USER package=$PACKAGE status=NOT_INSTALLED"
        return 2
    fi

    if printf '%s\n' "$RESULT" | "$GREP" -q '^STATUS|IGNORED_UID|'; then
        log_info "Package" "Processed" \
            "action=$ACTION user=$USER package=$PACKAGE status=IGNORED_UID"
        return 0
    fi

    if printf '%s\n' "$RESULT" | "$GREP" -q 'APPS_BUSY'; then
        log_warn "Package" "Processing deferred" \
            "action=$ACTION user=$USER package=$PACKAGE status=APPS_BUSY"
        return 2
    fi

    log_error "Package" "Processing failed" \
        "action=$ACTION user=$USER package=$PACKAGE status=$STATUS"
    return 1
}

log_info "App Watcher" "Started" \
    "package event monitor debounce=${DEBOUNCE}s"

START_TIME="$("$DATE" "+%m-%d %H:%M:%S.000")"

"$LOGCAT" \
    -b system \
    -v threadtime \
    -T "$START_TIME" \
    'PackageManager:I' \
    'ActivityManager:I' \
    '*:S' \
    2>/dev/null |
while IFS= read -r LINE
do
    process_logcat_line "$LINE"
done &

SYSTEM_LOGCAT_PID=$!

"$LOGCAT" \
    -b main \
    -v threadtime \
    -T "$START_TIME" \
    '*:I' \
    2>/dev/null |
while IFS= read -r LINE
do
    case "$LINE" in
        *"android.intent.action.PACKAGE_ADDED"*)
            process_logcat_line "$LINE"
            ;;
    esac
done &

MAIN_LOGCAT_PID=$!

while true
do
    if ! kill -0 "$SYSTEM_LOGCAT_PID" 2>/dev/null; then
        log_error "App Watcher" "System logcat reader stopped" \
            "pid=$SYSTEM_LOGCAT_PID"
        exit 1
    fi

    if ! kill -0 "$MAIN_LOGCAT_PID" 2>/dev/null; then
        log_error "App Watcher" "Main logcat reader stopped" \
            "pid=$MAIN_LOGCAT_PID"
        exit 1
    fi

    sleep 3
done
