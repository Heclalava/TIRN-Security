#!/system/bin/sh

DATA_DIR="${DATA_DIR:-/data/adb/tirnsecurity}"
QUEUE="$DATA_DIR/app-queue"
LOCK="$DATA_DIR/app-queue.lock"
TMP="$DATA_DIR/app-queue.tmp"
MAX_RETRIES=5

mkdir -p "$DATA_DIR" || exit 1
[ -f "$QUEUE" ] || : > "$QUEUE"

acquire_lock() {
    if ! mkdir "$LOCK" 2>/dev/null; then
        echo "QUEUE_BUSY"
        exit 2
    fi
}

release_lock() {
    rmdir "$LOCK" 2>/dev/null || true
}

valid_action() {
    case "$1" in
        ADDED|REMOVED|REPLACED) return 0 ;;
        *) return 1 ;;
    esac
}

valid_package() {
    case "$1" in
        ""|*[!A-Za-z0-9._]*) return 1 ;;
        *) return 0 ;;
    esac
}

case "$1" in
    add)
        ACTION="$2"
        PACKAGE="$3"
        valid_action "$ACTION" || { echo "INVALID_ACTION"; exit 1; }
        valid_package "$PACKAGE" || { echo "INVALID_PACKAGE"; exit 1; }
        acquire_lock || exit $?
        awk -F"|" -v pkg="$PACKAGE" -v action="$ACTION" '$2 == pkg { found=1; print action "|" pkg "|" $3; next } { print } END { if (!found) print action "|" pkg "|0" }' "$QUEUE" > "$TMP" && mv -f "$TMP" "$QUEUE"
        RC=$?
        release_lock
        exit "$RC"
        ;;
    next)
        acquire_lock || exit $?
        NEXT=$(awk -F"|" 'NF == 3 && $1 != "" && $2 != "" && $3 ~ /^[0-9]+$/ { print; exit }' "$QUEUE")
        if [ -z "$NEXT" ]; then echo "QUEUE_EMPTY"; release_lock; exit 0; fi
        printf "%s
" "$NEXT"
        RC=$?
        release_lock
        exit "$RC"
        ;;
    retry)
        acquire_lock || exit $?
        if [ ! -s "$QUEUE" ]; then
            release_lock
            echo "QUEUE_EMPTY"
            exit 0
        fi
        FIRST=$(awk -F"|" 'NF == 3 && $1 != "" && $2 != "" && $3 ~ /^[0-9]+$/ { print; exit }' "$QUEUE")
        ACTION=$(printf "%s\n" "$FIRST" | cut -d"|" -f1)
        PACKAGE=$(printf "%s\n" "$FIRST" | cut -d"|" -f2)
        RETRIES=$(printf "%s\n" "$FIRST" | cut -d"|" -f3)
        NEXT_RETRIES=$((RETRIES + 1))
        if [ "$NEXT_RETRIES" -ge "$MAX_RETRIES" ]; then
            awk -F"|" -v pkg="$PACKAGE" '$2 == pkg { next } { print }' "$QUEUE" > "$TMP" && mv -f "$TMP" "$QUEUE"
            RC=$?
            release_lock
            if [ "$RC" -eq 0 ]; then
                printf "MAX_RETRIES|%s|%s|%s\n" "$ACTION" "$PACKAGE" "$NEXT_RETRIES"
            fi
            exit "$RC"
        fi
        awk -F"|" -v pkg="$PACKAGE" -v retries="$NEXT_RETRIES" '$2 == pkg { print $1 "|" $2 "|" retries; next } { print }' "$QUEUE" > "$TMP" && mv -f "$TMP" "$QUEUE"
        RC=$?
        release_lock
        if [ "$RC" -eq 0 ]; then
            printf "RETRY|%s|%s|%s\n" "$ACTION" "$PACKAGE" "$NEXT_RETRIES"
        fi
        exit "$RC"
        ;;
    remove)
        acquire_lock || exit $?
        if [ ! -s "$QUEUE" ]; then
            release_lock
            echo "QUEUE_EMPTY"
            exit 0
        fi
        FIRST=$(awk -F"|" 'NF == 3 && $1 != "" && $2 != "" && $3 ~ /^[0-9]+$/ { print; exit }' "$QUEUE")
        ACTION=$(printf "%s\n" "$FIRST" | cut -d"|" -f1)
        PACKAGE=$(printf "%s\n" "$FIRST" | cut -d"|" -f2)
        awk -F"|" -v pkg="$PACKAGE" '$2 == pkg { if (!removed) { removed=1; next } } { print }' "$QUEUE" > "$TMP" && mv -f "$TMP" "$QUEUE"
        RC=$?
        release_lock
        if [ "$RC" -eq 0 ]; then
            printf "REMOVED|%s|%s\n" "$ACTION" "$PACKAGE"
        fi
        exit "$RC"
        ;;

    *)
        echo "Usage: $0 {add|next|retry|remove}"
        exit 1
        ;;
esac
