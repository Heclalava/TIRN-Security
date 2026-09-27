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
EVENT_DIR="$DATA_DIR/app-watch-events"
APP_EVENT_QUEUE="$DATA_DIR/app-events"

DEBOUNCE=2

. "$MODDIR/logging-common.sh" || exit 1
AUDIT_LOG="$LOG"
DEBUG_LOG="$DEBUG_LOG"

mkdir -p "$DATA_DIR" || exit 1
chmod 700 "$DATA_DIR"

if ! "$MKDIR" "$EVENT_DIR" 2>/dev/null; then
    if [ ! -d "$EVENT_DIR" ]; then
        log_error "App Watcher" "Startup failed" "unable to create event directory"
        exit 1
    fi
fi

chmod 700 "$EVENT_DIR"

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

cleanup() {
    if [ -n "${LOGCAT_PID:-}" ]; then
        kill "$LOGCAT_PID" 2>/dev/null
    fi

    "$RM" -f "$EVENT_DIR"/.watch.* 2>/dev/null
    "$RM" -f "$EVENT_DIR"/.work.* 2>/dev/null
    "$RM" -rf "$LOCK" 2>/dev/null
}

trap cleanup EXIT
trap 'cleanup; exit 0' INT TERM HUP

package_from_event() {
    LINE="$1"

    PACKAGE="$(
        printf '%s\n' "$LINE" |
            "$SED" -n 's/.*package:\([A-Za-z0-9._-][A-Za-z0-9._-]*\).*/\1/p' |
            "$SED" -n '1p'
    )"

    if [ -n "$PACKAGE" ]; then
        printf '%s\n' "$PACKAGE"
        return 0
    fi

    PACKAGE="$(
        printf '%s\n' "$LINE" |
            "$SED" -n 's/.*for package \([A-Za-z0-9._-][A-Za-z0-9._-]*\).*/\1/p' |
            "$SED" -n '1p'
    )"

    if [ -n "$PACKAGE" ]; then
        printf '%s\n' "$PACKAGE"
        return 0
    fi

    printf '%s\n' "$LINE" |
        "$SED" -n 's/.*pkg=\([A-Za-z0-9._-][A-Za-z0-9._-]*\).*/\1/p' |
        "$SED" -n '1p'
}

merge_event_action() {
    OLD_ACTION="$1"
    NEW_ACTION="$2"

    case "$NEW_ACTION" in
        REMOVED)
            printf '%s\n' "REMOVED"
            ;;
        REPLACED)
            case "$OLD_ACTION" in
                REMOVED) printf '%s\n' "REMOVED" ;;
                *)       printf '%s\n' "REPLACED" ;;
            esac
            ;;
        ADDED)
            case "$OLD_ACTION" in
                REMOVED) printf '%s\n' "REMOVED" ;;
                REPLACED) printf '%s\n' "REPLACED" ;;
                *)       printf '%s\n' "ADDED" ;;
            esac
            ;;
        *)
            printf '%s\n' "$OLD_ACTION"
            ;;
    esac
}

queue_event() {
    ACTION="$1"
    PACKAGE="$2"

    case "$ACTION" in
        ADDED|REPLACED|REMOVED)
            ;;
        *)
            return 1
            ;;
    esac

    case "$PACKAGE" in
        ''|*[!A-Za-z0-9._-]*)
            return 1
            ;;
    esac

    EVENT_FILE="$EVENT_DIR/$PACKAGE"
    EVENT_TMP="$EVENT_DIR/.event.$$"

    OLD_ACTION=""
    if [ -f "$EVENT_FILE" ]; then
        OLD_ACTION="$("$AWK" -F'|' 'NR == 1 {print $1}' "$EVENT_FILE" 2>/dev/null)"
    fi

    if [ -n "$OLD_ACTION" ]; then
        ACTION="$(merge_event_action "$OLD_ACTION" "$ACTION")"
    fi

    printf '%s|%s\n' "$ACTION" "$("$DATE" +%s)" > "$EVENT_TMP" || {
        "$RM" -f "$EVENT_TMP"
        return 1
    }

    "$MV" -f "$EVENT_TMP" "$EVENT_FILE" || {
        "$RM" -f "$EVENT_TMP"
        return 1
    }

    log_info "Package" "Event detected" \
        "action=$ACTION package=$PACKAGE"

    return 0
}

resolve_added_replaced_users() {
    PACKAGE="$1"

    "$PM" list users 2>/dev/null |
        "$SED" -n 's/.*UserInfo{\([0-9][0-9]*\):.*/\1/p' |
        "$SORT" -nu |
        while IFS= read -r USER
        do
            [ -n "$USER" ] || continue

            if "$PM" list packages --user "$USER" -U "$PACKAGE" 2>/dev/null |
                "$AWK" -v p="$PACKAGE" '
                    $1 == ("package:" p) && $2 ~ /^uid:[0-9]+$/ {
                        sub(/^uid:/, "", $2)
                        print $2
                        exit
                    }
                ' |
                "$GREP" -q '^[0-9][0-9]*$'; then
                printf '%s\n' "$USER"
            fi
        done
}

resolve_removed_users() {
    PACKAGE="$1"

    [ -f "$APPS_IDENTITY" ] || return 0

    "$AWK" -F'|' -v p="$PACKAGE" '
        NF == 3 && $2 == p && $1 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ {
            print $1
        }
    ' "$APPS_IDENTITY" |
    "$SORT" -nu |
    while IFS= read -r USER
    do
        [ -n "$USER" ] || continue

        if ! "$PM" list packages --user "$USER" -U "$PACKAGE" 2>/dev/null |
            "$AWK" -v p="$PACKAGE" '
                $1 == ("package:" p) && $2 ~ /^uid:[0-9]+$/ {
                    found = 1
                    exit
                }
                END {
                    exit(found ? 0 : 1)
                }
            '; then
            printf '%s\n' "$USER"
        fi
    done
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
    PACKAGE="${EVENT_FILE##*/}"

    case "$PACKAGE" in
        ''|.*|*[!A-Za-z0-9._-]*)
            "$RM" -f "$EVENT_FILE"
            return 0
            ;;
    esac

    EVENT_DATA="$("$CAT" "$EVENT_FILE" 2>/dev/null)" || return 1

    ACTION="$(printf '%s\n' "$EVENT_DATA" | "$AWK" -F'|' 'NR==1 {print $1}')"
    EVENT_TIME="$(printf '%s\n' "$EVENT_DATA" | "$AWK" -F'|' 'NR==1 {print $2}')"

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

    NOW="$("$DATE" +%s)"
    AGE=$((NOW - EVENT_TIME))

    if [ "$AGE" -lt "$DEBOUNCE" ]; then
        return 0
    fi

    WORK_FILE="$EVENT_DIR/.work.$$"
    if ! "$MV" -f "$EVENT_FILE" "$WORK_FILE" 2>/dev/null; then
        return 0
    fi

    EVENT_DATA="$("$CAT" "$WORK_FILE" 2>/dev/null)"
    ACTION="$(printf '%s\n' "$EVENT_DATA" | "$AWK" -F'|' 'NR==1 {print $1}')"
    RETRY_USERS="$(printf '%s\n' "$EVENT_DATA" | "$AWK" -F'|' 'NR==1 {print $3}')"

    if [ -n "$RETRY_USERS" ]; then
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
                "action=$ACTION package=$PACKAGE users=$RETRY_USERS"
            "$RM" -f "$WORK_FILE"
            return 1
        fi
    fi

    log_info "Package" "Event coalesced" \
        "action=$ACTION package=$PACKAGE"

    if [ -n "$RETRY_USERS" ]; then
        USERS="$(printf '%s\n' "$RETRY_USERS" |
            tr ',' '\n' |
            "$SORT" -nu)"

        log_info "Package" "Retry profiles restored" \
            "action=$ACTION package=$PACKAGE users=$RETRY_USERS"
    else
        case "$ACTION" in
            ADDED|REPLACED)
                USERS="$(resolve_added_replaced_users "$PACKAGE")"
                ;;
            REMOVED)
                USERS="$(resolve_removed_users "$PACKAGE")"
                log_info "Package" "Removal users resolved"                     "package=$PACKAGE users=${USERS:-NONE}"
                ;;
        esac
    fi

    if [ -z "$USERS" ]; then
        log_info "Package" "No affected profiles" \
            "action=$ACTION package=$PACKAGE"
        "$RM" -f "$WORK_FILE"
        return 0
    fi

    PROCESS_FAILED=0
    USERS_FILE="$EVENT_DIR/.users.$$"
    RETRY_FILE="$EVENT_DIR/.retry.$$"

    : > "$RETRY_FILE" || {
        "$RM" -f "$RETRY_FILE"
        "$MV" -f "$WORK_FILE" "$EVENT_FILE" 2>/dev/null || {
            log_error "Package" "Event recovery failed" \
                "action=$ACTION package=$PACKAGE status=RETRY_FILE_CREATE"
        }
        return 1
    }

    printf '%s\n' "$USERS" > "$USERS_FILE" || {
        "$RM" -f "$USERS_FILE"
        "$RM" -f "$RETRY_FILE"
        "$MV" -f "$WORK_FILE" "$EVENT_FILE" 2>/dev/null || {
            log_error "Package" "Event recovery failed" \
                "action=$ACTION package=$PACKAGE status=USERS_FILE_CREATE"
        }
        return 1
    }

    while IFS= read -r USER
    do
        [ -n "$USER" ] || continue

        log_info "Package" "Profile resolved" \
            "action=$ACTION user=$USER package=$PACKAGE"

        process_profile "$ACTION" "$USER" "$PACKAGE"
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
                        "action=$ACTION package=$PACKAGE status=RETRY_STATE"
                }
                log_error "Package" "Retry state creation failed" \
                    "action=$ACTION package=$PACKAGE users=$RETRY_USERS"
                return 1
                ;;
        esac

        RETRY_TMP="$EVENT_DIR/.retry-event.$$"

        printf '%s|%s|%s\n' \
            "$RETRY_ACTION" \
            "$RETRY_TIME" \
            "$RETRY_USERS" > "$RETRY_TMP" || {
            "$RM" -f "$RETRY_TMP" "$RETRY_FILE"
            "$MV" -n "$WORK_FILE" "$EVENT_FILE" 2>/dev/null || {
                log_error "Package" "Event recovery failed" \
                    "action=$ACTION package=$PACKAGE status=RETRY_EVENT_CREATE"
            }
            return 1
        }

        "$MV" -n "$RETRY_TMP" "$EVENT_FILE" 2>/dev/null
        RETRY_INSTALL_STATUS=$?

        if [ -e "$EVENT_FILE" ]; then
            "$RM" -f "$RETRY_TMP"
        elif [ "$RETRY_INSTALL_STATUS" -ne 0 ]; then
            "$RM" -f "$RETRY_TMP" "$RETRY_FILE"
            "$MV" -n "$WORK_FILE" "$EVENT_FILE" 2>/dev/null || {
                log_error "Package" "Event recovery failed" \
                    "action=$ACTION package=$PACKAGE status=RETRY_EVENT_INSTALL"
            }
            return 1
        else
            "$RM" -f "$RETRY_TMP" "$RETRY_FILE"
            log_error "Package" "Event recovery failed" \
                "action=$ACTION package=$PACKAGE status=RETRY_EVENT_MISSING"
            return 1
        fi

        log_warn "Package" "Processing deferred" \
            "action=$ACTION package=$PACKAGE retry=1 users=$RETRY_USERS"

        "$RM" -f "$RETRY_FILE" "$WORK_FILE"
        return 2
    fi

    "$RM" -f "$RETRY_FILE" "$WORK_FILE"

    return 0
}

log_info "App Watcher" "Started" \
    "package event monitor debounce=${DEBOUNCE}s"

START_TIME="$("$DATE" "+%m-%d %H:%M:%S.000")"

"$LOGCAT" -v threadtime -T "$START_TIME" 2>/dev/null |
while IFS= read -r LINE
do
    case "$LINE" in
        *PACKAGE_ADDED*)
            PACKAGE="$(package_from_event "$LINE")"
            [ -n "$PACKAGE" ] &&
                queue_event "ADDED" "$PACKAGE"
            ;;
        *PACKAGE_REPLACED*)
            PACKAGE="$(package_from_event "$LINE")"
            [ -n "$PACKAGE" ] &&
                queue_event "REPLACED" "$PACKAGE"
            ;;
        *PACKAGE_REMOVED*|*PACKAGE_FULLY_REMOVED*)
            PACKAGE="$(package_from_event "$LINE")"
            [ -n "$PACKAGE" ] &&
                queue_event "REMOVED" "$PACKAGE"
            ;;
    esac
done &

LOGCAT_PID=$!

while true
do
    FOUND=0

    for EVENT_FILE in "$EVENT_DIR"/*
    do
        [ -f "$EVENT_FILE" ] || continue
        case "${EVENT_FILE##*/}" in
            .*) continue ;;
        esac

        FOUND=1
        process_event_file "$EVENT_FILE"
    done

    if [ "$FOUND" -eq 0 ]; then
        sleep 1
    else
        sleep 1
    fi
done
