#!/system/bin/sh

# TIRN Security logging helpers.
# This file only defines logging functions; it performs no I/O when sourced.

DATA_DIR="${DATA_DIR:-/data/adb/tirnsecurity}"
AUDIT_LOG="${AUDIT_LOG:-$DATA_DIR/service.log}"
DEBUG_LOG="${DEBUG_LOG:-$DATA_DIR/debug.log}"

_log_event() {
    _LOG_LEVEL="$1"
    _LOG_COMPONENT="$2"
    _LOG_EVENT="$3"
    _LOG_DETAILS="$4"

    _LOG_DETAILS="$(printf '%s' "$_LOG_DETAILS" | tr '\n' ' ' | tr '\r' ' ')"
    if [ -n "$_LOG_DETAILS" ]; then
        printf '%s %s  %s — %s — %s — PID=%s PPID=%s\n' \
            "$(/system/bin/date '+%Y-%m-%d %H:%M:%S')" \
            "$_LOG_LEVEL" "$_LOG_COMPONENT" "$_LOG_EVENT" "$_LOG_DETAILS" \
            "$$" "$PPID" >> "$AUDIT_LOG"
    else
        printf '%s %s  %s — %s — PID=%s PPID=%s\n' \
            "$(/system/bin/date '+%Y-%m-%d %H:%M:%S')" \
            "$_LOG_LEVEL" "$_LOG_COMPONENT" "$_LOG_EVENT" \
            "$$" "$PPID" >> "$AUDIT_LOG"
    fi
}

log_info() {
    _log_event "INFO" "$1" "$2" "$3"
}

log_warn() {
    _log_event "WARN" "$1" "$2" "$3"
}

log_error() {
    _log_event "ERROR" "$1" "$2" "$3"
}

debug_log() {
    _DEBUG_DETAILS="$(printf '%s' "$3" | tr '\n' ' ' | tr '\r' ' ')"
    printf '%s DEBUG  %s — %s — %s — PID=%s PPID=%s\n' \
        "$(/system/bin/date '+%Y-%m-%d %H:%M:%S')" \
        "$1" "$2" "$_DEBUG_DETAILS" \
        "$$" "$PPID" >> "$DEBUG_LOG"
}
