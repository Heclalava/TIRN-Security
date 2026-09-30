#!/system/bin/sh

MODDIR="${0%/*}"
DATA_DIR="/data/adb/tirnsecurity"
APPS_IDENTITY="$DATA_DIR/apps.identity"
SERVICE="$MODDIR/service.sh"

LOGCAT="/system/bin/logcat"
PM="/system/bin/pm"
SH="/system/bin/sh"
DATE="/system/bin/date"
AWK="/system/bin/awk"
SED="/system/bin/sed"
GREP="/system/bin/grep"
SORT="/system/bin/sort"
CAT="/system/bin/cat"
MV="/system/bin/mv"
RM="/system/bin/rm"
MKDIR="/system/bin/mkdir"

LOG="$DATA_DIR/service.log"
DEBUG_LOG="$DATA_DIR/debug.log"
LOCK="$DATA_DIR/app-watch.lock"
APP_EVENT_QUEUE="$DATA_DIR/app-events"
APP_RETRY_QUEUE="$DATA_DIR/app-events-retry"

DEBOUNCE=2

. "$MODDIR/logging-common.sh" || exit 1
AUDIT_LOG="$LOG"
DEBUG_LOG="$DEBUG_LOG"

mkdir -p "$DATA_DIR" || exit 1
chmod 700 "$DATA_DIR"

if ! "$MKDIR" "$APP_EVENT_QUEUE" "$APP_RETRY_QUEUE" 2>/dev/null; then
    if [ ! -d "$APP_EVENT_QUEUE" ] || [ ! -d "$APP_RETRY_QUEUE" ]; then
        log_error "App Watcher" "Startup failed" "unable to create app event directories"
        exit 1
    fi
fi

chmod 700 "$APP_EVENT_QUEUE" "$APP_RETRY_QUEUE"

if ! mkdir "$LOCK" 2>/dev/null; then
    log_warn "App Watcher" "Already running" "lock=$LOCK"
    exit 0
fi

cleanup() {
    if [ -n "${LOGCAT_PID:-}" ]; then
        kill "$LOGCAT_PID" 2>/dev/null
    fi

    "$RM" -f "$APP_EVENT_QUEUE"/.watch.* 2>/dev/null
    "$RM" -f "$APP_EVENT_QUEUE"/.work.* 2>/dev/null
    "$RM" -f "$APP_RETRY_QUEUE"/.retry.* 2>/dev/null
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
                    queue_event "REMOVED" \
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
        *"ActivityManager:"*"Force stopping "*)
            EVENT_PACKAGE="${LINE#*Force stopping }"
            EVENT_PACKAGE="${EVENT_PACKAGE%% appid=*}"

            EVENT_USER="${LINE#* user=}"
            EVENT_USER="${EVENT_USER%%:*}"

            if [ -n "$EVENT_PACKAGE" ] &&
               [ -n "$EVENT_USER" ]; then
                debug_log "App Watcher" "REMOVED parser matched" \
                    "user=$EVENT_USER package=$EVENT_PACKAGE"
                queue_event "REMOVED" "$EVENT_USER" "$EVENT_PACKAGE"
            fi

            return 0
            ;;
    esac

    case "$LINE" in
        *"PackageManager:"*"Update package "*)
            EVENT_PACKAGE="${LINE#*Update package }"
            EVENT_PACKAGE="${EVENT_PACKAGE%% *}"
            EVENT_ACTION="REPLACED"
            ;;

        *"PackageManager:"*"installation completed for package:"*)
            EVENT_PACKAGE="${LINE#*installation completed for package:}"
            EVENT_PACKAGE="${EVENT_PACKAGE%%. Final code path:*}"
            debug_log "App Watcher" "ADDED parser matched" \
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

    if [ -f "$APPS_IDENTITY" ]; then
        "$AWK" -F'|' -v p="$EVENT_PACKAGE" '
            NF == 3 && $2 == p {
                print $1
            }
        ' "$APPS_IDENTITY" |
        "$SORT" -nu |
        while IFS= read -r USER
        do
            [ -n "$USER" ] || continue

            debug_log "App Watcher" "ADDED identity match" \
                "action=$EVENT_ACTION user=$USER package=$EVENT_PACKAGE"

            queue_event "$EVENT_ACTION" "$USER" "$EVENT_PACKAGE"
            QUEUE_STATUS=$?

            debug_log "App Watcher" "ADDED queue result" \
                "action=$EVENT_ACTION user=$USER package=$EVENT_PACKAGE status=$QUEUE_STATUS"
        done
    fi
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
        ADDED|REPLACED)
            RESULT="$("$MODDIR/apphelper" "$ACTION" "$USER" "$PACKAGE" 2>&1)"
            STATUS=$?
            ;;
        REMOVED)
            RESULT="$("$MODDIR/apphelper" "$ACTION" "$USER" "$PACKAGE" 2>&1)"
            STATUS=$?
            ;;
        *)
            log_error "Package" "Invalid action" \
                "action=$ACTION user=$USER package=$PACKAGE"
            return 1
            ;;
    esac

    if [ "$STATUS" -eq 0 ]; then
        RESULT_LINE="$(printf '%s\n' "$RESULT" | "$GREP" -E '^(ADDED|UPDATED|REMOVED|UNCHANGED)\|')"

        log_info "Package" "Processed" \
            "action=$ACTION user=$USER package=$PACKAGE status=${RESULT_LINE:-OK}"

        EVENT_ACTION="${RESULT_LINE%%\|*}"

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

process_event_file() {
    EVENT_FILE="$1"
    EVENT_SOURCE="$2"
    EVENT_NAME="${EVENT_FILE##*/}"

    case "$EVENT_NAME" in
        ''|.*|*[!A-Za-z0-9._-]*)
            "$RM" -f "$EVENT_FILE"
            return 0
            ;;
    esac

    EVENT_DATA="$("$CAT" "$EVENT_FILE" 2>/dev/null)" || return 1

    FIELD_COUNT="$(printf '%s\n' "$EVENT_DATA" |
        "$AWK" -F'|' 'NR==1 {print NF}')"

    ACTION="$(printf '%s\n' "$EVENT_DATA" |
        "$AWK" -F'|' 'NR==1 {print $1}')"

    EVENT_USER=""
    EVENT_PACKAGE=""
    EVENT_TIME=""
    RETRY_USERS=""

    case "$EVENT_SOURCE:$FIELD_COUNT" in
        EVENT:4)
            EVENT_USER="$(printf '%s\n' "$EVENT_DATA" |
                "$AWK" -F'|' 'NR==1 {print $2}')"
            EVENT_PACKAGE="$(printf '%s\n' "$EVENT_DATA" |
                "$AWK" -F'|' 'NR==1 {print $3}')"
            EVENT_TIME="$(printf '%s\n' "$EVENT_DATA" |
                "$AWK" -F'|' 'NR==1 {print $4}')"
            ;;
        RETRY:4)
            EVENT_TIME="$(printf '%s\n' "$EVENT_DATA" |
                "$AWK" -F'|' 'NR==1 {print $2}')"
            RETRY_USERS="$(printf '%s\n' "$EVENT_DATA" |
                "$AWK" -F'|' 'NR==1 {print $3}')"
            EVENT_PACKAGE="$(printf '%s\n' "$EVENT_DATA" |
                "$AWK" -F'|' 'NR==1 {print $4}')"
            ;;
        *)
            "$RM" -f "$EVENT_FILE"
            return 0
            ;;
    esac

    case "$ACTION" in
        ADDED|REPLACED|REMOVED)
            ;;
        *)
            "$RM" -f "$EVENT_FILE"
            return 0
            ;;
    esac

    case "$EVENT_TIME" in
        ''|*[!0-9]*)
            "$RM" -f "$EVENT_FILE"
            return 0
            ;;
    esac

    if [ "$EVENT_SOURCE" = "EVENT" ]; then
        case "$EVENT_USER" in
            ''|*[!0-9]*)
                "$RM" -f "$EVENT_FILE"
                return 0
                ;;
        esac

        case "$EVENT_PACKAGE" in
            ''|*[!A-Za-z0-9._-]*)
                "$RM" -f "$EVENT_FILE"
                return 0
                ;;
        esac
    else
        case "$RETRY_USERS" in
            ''|*[!0-9,]*)
                log_error "Package" "Invalid retry profile list" \
                    "action=$ACTION package=$EVENT_PACKAGE users=$RETRY_USERS"
                "$RM" -f "$EVENT_FILE"
                return 1
                ;;
        esac

        if ! printf '%s\n' "$RETRY_USERS" |
            "$AWK" -F',' '
                {
                    if ($0 == "")
                        exit 1
                    for (i = 1; i <= NF; i++) {
                        if ($i !~ /^[0-9]+$/)
                            exit 1
                    }
                }
            '; then
            log_error "Package" "Invalid retry profile list" \
                "action=$ACTION package=$EVENT_PACKAGE users=$RETRY_USERS"
            "$RM" -f "$EVENT_FILE"
            return 1
        fi
    fi

    NOW="$("$DATE" +%s)"
    AGE=$((NOW - EVENT_TIME))

    if [ "$AGE" -lt "$DEBOUNCE" ]; then
        return 0
    fi

    WORK_FILE="$APP_EVENT_QUEUE/.work.$$"
    if ! "$MV" -f "$EVENT_FILE" "$WORK_FILE" 2>/dev/null; then
        return 0
    fi

    if [ "$EVENT_SOURCE" = "RETRY" ]; then
        USERS="$(printf '%s\n' "$RETRY_USERS" |
            tr ',' '\n' |
            "$SORT" -nu)"

        log_info "Package" "Retry profiles restored" \
            "action=$ACTION package=$EVENT_PACKAGE users=$RETRY_USERS"
    else
        USERS="$EVENT_USER"

        log_info "Package" "Event coalesced" \
            "action=$ACTION user=$EVENT_USER package=$EVENT_PACKAGE"
    fi

    if [ -z "$USERS" ]; then
        log_info "Package" "No affected profiles" \
            "action=$ACTION package=$EVENT_PACKAGE"
        "$RM" -f "$WORK_FILE"
        return 0
    fi

    PROCESS_FAILED=0
    USERS_FILE="$APP_EVENT_QUEUE/.users.$$"
    RETRY_FILE="$APP_EVENT_QUEUE/.retry.$$"

    : > "$RETRY_FILE" || {
        "$RM" -f "$RETRY_FILE"
        "$MV" -f "$WORK_FILE" "$EVENT_FILE" 2>/dev/null || {
            log_error "Package" "Event recovery failed" \
                "action=$ACTION package=$EVENT_PACKAGE status=RETRY_FILE_CREATE"
        }
        return 1
    }

    printf '%s\n' "$USERS" > "$USERS_FILE" || {
        "$RM" -f "$USERS_FILE"
        "$RM" -f "$RETRY_FILE"
        "$MV" -f "$WORK_FILE" "$EVENT_FILE" 2>/dev/null || {
            log_error "Package" "Event recovery failed" \
                "action=$ACTION package=$EVENT_PACKAGE status=USERS_FILE_CREATE"
        }
        return 1
    }

    while IFS= read -r USER
    do
        [ -n "$USER" ] || continue

        log_info "Package" "Profile resolved" \
            "action=$ACTION user=$USER package=$EVENT_PACKAGE"

        process_profile "$ACTION" "$USER" "$EVENT_PACKAGE"
        STATUS=$?

        if [ "$STATUS" -eq 2 ]; then
            PROCESS_FAILED=1
            printf '%s\n' "$USER" >> "$RETRY_FILE"
        elif [ "$STATUS" -ne 0 ]; then
            PROCESS_FAILED=1
            printf '%s\n' "$USER" >> "$RETRY_FILE"
        fi
    done < "$USERS_FILE"

    "$RM" -f "$USERS_FILE"

    if [ "$PROCESS_FAILED" -ne 0 ]; then
        RETRY_ACTION="$ACTION"
        RETRY_TIME="$("$DATE" +%s)"

        RETRY_USERS="$("$SORT" -nu "$RETRY_FILE" |
            "$AWK" '
                BEGIN { sep="" }
                {
                    printf "%s%s", sep, $1
                    sep=","
                }
                END { printf "\n" }
            ')"

        case "$RETRY_USERS" in
            ''|*[!0-9,]*)
                "$RM" -f "$RETRY_FILE"
                "$MV" -f "$WORK_FILE" "$EVENT_FILE" 2>/dev/null || {
                    log_error "Package" "Event recovery failed" \
                        "action=$ACTION package=$EVENT_PACKAGE status=RETRY_STATE"
                }
                log_error "Package" "Retry state creation failed" \
                    "action=$ACTION package=$EVENT_PACKAGE users=$RETRY_USERS"
                return 1
                ;;
        esac

        RETRY_TMP="$APP_RETRY_QUEUE/.retry-event.$$"

        printf '%s|%s|%s|%s\n' \
            "$RETRY_ACTION" \
            "$RETRY_TIME" \
            "$RETRY_USERS" \
            "$EVENT_PACKAGE" > "$RETRY_TMP" || {
            "$RM" -f "$RETRY_TMP" "$RETRY_FILE"
            "$MV" -n "$WORK_FILE" "$EVENT_FILE" 2>/dev/null || {
                log_error "Package" "Event recovery failed" \
                    "action=$ACTION package=$EVENT_PACKAGE status=RETRY_EVENT_CREATE"
            }
            return 1
        }

        RETRY_EVENT_FILE="$APP_RETRY_QUEUE/${EVENT_PACKAGE}"

        "$MV" -n "$RETRY_TMP" "$RETRY_EVENT_FILE" 2>/dev/null
        RETRY_INSTALL_STATUS=$?

        if [ -e "$EVENT_FILE" ]; then
            "$RM" -f "$RETRY_TMP"
        elif [ "$RETRY_INSTALL_STATUS" -ne 0 ]; then
            "$RM" -f "$RETRY_TMP" "$RETRY_FILE"
            "$MV" -n "$WORK_FILE" "$EVENT_FILE" 2>/dev/null || {
                log_error "Package" "Event recovery failed" \
                    "action=$ACTION package=$EVENT_PACKAGE status=RETRY_EVENT_INSTALL"
            }
            return 1
        else
            "$RM" -f "$RETRY_TMP" "$RETRY_FILE"
            log_error "Package" "Event recovery failed" \
                "action=$ACTION package=$EVENT_PACKAGE status=RETRY_EVENT_MISSING"
            return 1
        fi

        log_warn "Package" "Processing deferred" \
            "action=$ACTION package=$EVENT_PACKAGE retry=1 users=$RETRY_USERS"

        "$RM" -f "$RETRY_FILE" "$WORK_FILE"
        return 2
    fi

    "$RM" -f "$RETRY_FILE" "$WORK_FILE"

    return 0
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

LOGCAT_PID=$!

while true
do
    if ! kill -0 "$LOGCAT_PID" 2>/dev/null; then
        log_error "App Watcher" "Logcat reader stopped" \
            "pid=$LOGCAT_PID"
        exit 1
    fi

    FOUND=0

    for EVENT_FILE in "$APP_EVENT_QUEUE"/*
    do
        [ -f "$EVENT_FILE" ] || continue
        case "${EVENT_FILE##*/}" in
            .*) continue ;;
        esac

        FOUND=1
        process_event_file "$EVENT_FILE" "EVENT"
    done

    for RETRY_EVENT in "$APP_RETRY_QUEUE"/*
    do
        [ -f "$RETRY_EVENT" ] || continue
        case "${RETRY_EVENT##*/}" in
            .*) continue ;;
        esac

        FOUND=1
        process_event_file "$RETRY_EVENT" "RETRY"
    done

    if [ "$FOUND" -eq 0 ]; then
        sleep 3
    else
        sleep 1
    fi
done
