#!/system/bin/sh

MODDIR="${0%/*}"
chmod 755 "$MODDIR/policy-watch.sh" "$MODDIR/policy-watch.sh-handler"
DATA_DIR="/data/adb/tirnsecurity"
LOG_FILE="$DATA_DIR/service.log"
STATE_FILE="$DATA_DIR/network.state"
POLICY_FILE="$DATA_DIR/policy.conf"
POLICY_STATE_FILE="$DATA_DIR/policy.applied"

IPTABLES="/system/bin/iptables"
IP6TABLES="/system/bin/ip6tables"
IP="/system/bin/ip"

MAIN_CHAIN="TIRNFW"
MOBILE_CHAIN="TIRNFW-MOBILE"
WIFI_CHAIN="TIRNFW-WIFI"
LAN_CHAIN="TIRNFW-LAN"

POLL_INTERVAL=30
POST_BOOT_REFRESH_DELAY=30

NETWORK_EVENT_FILE="$DATA_DIR/network-event.pending"
NETWORK_EVENT_SETTLE=3
NETWORK_WATCH_PID=""
NETWORK_WATCH_FIFO="$DATA_DIR/network-event.monitor.$$"

umask 077

mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"

if [ "${1:-}" != "--policy-event" ] &&
   [ "${1:-}" != "--refresh" ] &&
   [ "${1:-}" != "--import-policy" ] &&
   [ "${1:-}" != "--reconcile-stale-policy" ]; then
    touch "$POLICY_FILE"
    chmod 600 "$POLICY_FILE"
fi

. "$MODDIR/logging-common.sh"
AUDIT_LOG="$LOG_FILE"

# Atomic firewall transaction lock. This is separate from policy.lock.
FIREWALL_LOCK="$DATA_DIR/firewall.lock"
FIREWALL_LOCK_OWNER="$FIREWALL_LOCK/owner"

acquire_firewall_lock() {
    LOCK_WAIT=0

    while ! mkdir "$FIREWALL_LOCK" 2>/dev/null; do

        if [ ! -r "$FIREWALL_LOCK_OWNER" ]; then
            rmdir "$FIREWALL_LOCK" 2>/dev/null || true
            continue
        fi

        read -r LOCK_PID LOCK_START < "$FIREWALL_LOCK_OWNER"

        if ! kill -0 "$LOCK_PID" 2>/dev/null; then
            rmdir "$FIREWALL_LOCK" 2>/dev/null || true
            continue
        fi

        CURRENT_START="$(awk '{print $22}' /proc/$LOCK_PID/stat 2>/dev/null)"

        if [ -n "$LOCK_START" ] && [ -n "$CURRENT_START" ] &&
           [ "$LOCK_START" != "$CURRENT_START" ]; then
            if [ "$(cat "$FIREWALL_LOCK_OWNER" 2>/dev/null)" = "$LOCK_PID $LOCK_START" ]; then
                rmdir "$FIREWALL_LOCK" 2>/dev/null || true
            fi
            continue
        fi

        sleep 0.05
        LOCK_WAIT=$((LOCK_WAIT + 1))

        if [ "$LOCK_WAIT" -ge 1200 ]; then
            log_error "Firewall" "Lock timeout" "another firewall transaction is active"
            return 1
        fi
    done

    {
        printf '%s\n' "$$"
        awk '{print $22}' /proc/$$/stat 2>/dev/null || printf '0\n'
    } > "$FIREWALL_LOCK_OWNER"

    return 0
}

release_firewall_lock() {
    rm -f "$FIREWALL_LOCK_OWNER" 2>/dev/null || true
    rmdir "$FIREWALL_LOCK" 2>/dev/null || true
}

POLICY_LOCK="$DATA_DIR/policy.lock"

acquire_policy_lock() {
    POLICY_LOCK_WAIT=0

    while ! mkdir "$POLICY_LOCK" 2>/dev/null; do
        sleep 0.05
        POLICY_LOCK_WAIT=$((POLICY_LOCK_WAIT + 1))

        if [ "$POLICY_LOCK_WAIT" -ge 200 ]; then
            log_error "Policy" "Lock timeout"                 "another policy transaction is active"
            return 1
        fi
    done

    return 0
}

release_policy_lock() {
    rmdir "$POLICY_LOCK" 2>/dev/null || true
}

clear_stale_boot_locks() {
    for LOCK in "$FIREWALL_LOCK" "$POLICY_LOCK"; do
        [ -e "$LOCK" ] || continue
        rm -rf "$LOCK" 2>/dev/null || true
        log_warn "Lock" "Removed boot lock" "lock=$LOCK"
    done
}

recover_stale_app_events() {
    APP_EVENT_DIR="$DATA_DIR/app-events"

    [ -d "$APP_EVENT_DIR" ] || return 0

    for EVENT_WORK in "$APP_EVENT_DIR"/.work.*; do
        [ -f "$EVENT_WORK" ] || continue

        EVENT_DATA="$(cat "$EVENT_WORK" 2>/dev/null)"
        EVENT_ACTION="$(printf '%s\n' "$EVENT_DATA" | awk -F'|' 'NR == 1 {print $1}')"
        EVENT_USER="$(printf '%s\n' "$EVENT_DATA" | awk -F'|' 'NR == 1 {print $2}')"
        EVENT_PACKAGE="$(printf '%s\n' "$EVENT_DATA" | awk -F'|' 'NR == 1 {print $3}')"

        case "$EVENT_ACTION" in
            ADDED|UPDATED|REMOVED)
                ;;
            *)
                rm -f "$EVENT_WORK" 2>/dev/null || true
                log_warn "App Event" "Removed invalid stale work file" \
                    "file=$EVENT_WORK"
                continue
                ;;
        esac

        case "$EVENT_USER" in
            ''|*[!0-9]*)
                rm -f "$EVENT_WORK" 2>/dev/null || true
                log_warn "App Event" "Removed invalid stale work file" \
                    "file=$EVENT_WORK"
                continue
                ;;
        esac

        case "$EVENT_PACKAGE" in
            ''|*[!A-Za-z0-9._-]*)
                rm -f "$EVENT_WORK" 2>/dev/null || true
                log_warn "App Event" "Removed invalid stale work file" \
                    "file=$EVENT_WORK"
                continue
                ;;
        esac

        EVENT_FILE="$APP_EVENT_DIR/${EVENT_USER}_${EVENT_PACKAGE}"

        if [ -e "$EVENT_FILE" ]; then
            rm -f "$EVENT_WORK" 2>/dev/null || true
            log_warn "App Event" "Discarded duplicate stale work file" \
                "file=$EVENT_WORK event=$EVENT_FILE"
            continue
        fi

        if mv -f "$EVENT_WORK" "$EVENT_FILE" 2>/dev/null; then
            log_warn "App Event" "Recovered stale work file" \
                "file=$EVENT_WORK event=$EVENT_FILE"
        else
            log_error "App Event" "Stale work recovery failed" \
                "file=$EVENT_WORK event=$EVENT_FILE"
        fi
    done
}
start_network_watch() {
    rm -f "$NETWORK_WATCH_FIFO" 2>/dev/null || true

    if ! mkfifo "$NETWORK_WATCH_FIFO" 2>/dev/null; then
        log_error "Network Watcher" "FIFO creation failed"             "file=$NETWORK_WATCH_FIFO"
        return 1
    fi

    (
        MONITOR_PID=""

        cleanup_network_watch() {
            if [ -n "$MONITOR_PID" ]; then
                kill "$MONITOR_PID" 2>/dev/null || true
                wait "$MONITOR_PID" 2>/dev/null || true
            fi
            rm -f "$NETWORK_WATCH_FIFO" 2>/dev/null || true
        }

        trap 'cleanup_network_watch; exit 0' EXIT INT TERM

        "$IP" monitor link address route 2>/dev/null > "$NETWORK_WATCH_FIFO" &
        MONITOR_PID=$!

        while IFS= read -r EVENT; do
            [ -n "$EVENT" ] || continue

            if [ ! -f "$NETWORK_EVENT_FILE" ]; then
                : > "$NETWORK_EVENT_FILE"
            fi
        done < "$NETWORK_WATCH_FIFO"
    ) &

    NETWORK_WATCH_PID=$!

    log_info "Network Watcher" "Started"         "pid=$NETWORK_WATCH_PID event=link,address,route"
}

start_app_watch() {
    "$MODDIR/app-watch.sh" >/dev/null 2>&1 &
    APP_WATCH_PID=$!
    log_info "App Watcher" "Started" "pid=$APP_WATCH_PID"
}

ensure_app_watch_running() {
    if [ -d "$DATA_DIR/app-watch.lock" ]; then
        return 0
    fi

    log_warn "App Watcher" "Process unhealthy" \
        "old_pid=$APP_WATCH_PID lock=$DATA_DIR/app-watch.lock"

    start_app_watch
}

GENERATION_GUARD_CHAIN="TIRNFW-GUARD"

generation_chain_exists() {
    "$1" -w 5 -S "$2" >/dev/null 2>&1
}


generation_dispatcher_chain() {
    case "$1" in
        TIRNFW-G*)
            printf '%s\n' "$1"
            ;;
        *)
            printf 'TIRNFW-G%s\n' "$1"
            ;;
    esac
}

network_dispatcher_chain() {
    GEN="$1"
    case "$GEN" in
        TIRNFW-NET-G*) printf '%s\n' "$GEN" ;;
        *) printf 'TIRNFW-NET-G%s\n' "$GEN" ;;
    esac
}

policy_mobile_pointer_chain() {
    printf '%s\n' 'TIRNFW-POLICY-M'
}

policy_wifi_pointer_chain() {
    printf '%s\n' 'TIRNFW-POLICY-W'
}

policy_lan_pointer_chain() {
    printf '%s\n' 'TIRNFW-POLICY-L'
}

policy_mobile_chain() {
    GEN="$1"
    printf 'TIRNFW-G%s-M\n' "$GEN"
}

policy_wifi_chain() {
    GEN="$1"
    printf 'TIRNFW-G%s-W\n' "$GEN"
}

policy_lan_chain() {
    GEN="$1"
    printf 'TIRNFW-G%s-L\n' "$GEN"
}

network_dispatcher_chain_exists() {
    IPT="$1"
    CHAIN="$2"
    chain_exists "$IPT" "$CHAIN"
}

network_generation_create_family() {
    GEN="$1"
    FAMILY="$2"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    DISP="$(network_dispatcher_chain "$GEN")"

    network_dispatcher_chain_exists "$IPT" "$DISP" && return 1

    "$IPT" -w 5 -N "$DISP" || return 1

    return 0
}

network_generation_delete_family() {
    GEN="$1"
    FAMILY="$2"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    DISP="$(network_dispatcher_chain "$GEN")"

    if ! network_dispatcher_chain_exists "$IPT" "$DISP"; then
        return 0
    fi

    "$IPT" -w 5 -F "$DISP" || return 1
    "$IPT" -w 5 -X "$DISP" || return 1

    return 0
}

network_generation_cleanup_new() {
    GEN="$1"
    CLEANUP_FAILED=0

    if ! network_generation_delete_family "$GEN" ipv4 >/dev/null 2>&1; then
        log_warn "Firewall" "New IPv4 network generation cleanup failed" \
            "generation=$GEN"
        CLEANUP_FAILED=1
    fi

    if ! network_generation_delete_family "$GEN" ipv6 >/dev/null 2>&1; then
        log_warn "Firewall" "New IPv6 network generation cleanup failed" \
            "generation=$GEN"
        CLEANUP_FAILED=1
    fi

    return "$CLEANUP_FAILED"
}

network_generation_populate_family() {
    GEN="$1"
    FAMILY="$2"
    NETWORK_STATE="$3"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    DISP="$(network_dispatcher_chain "$GEN")"

    MOB="$(policy_mobile_pointer_chain)"
    WIFI="$(policy_wifi_pointer_chain)"
    LAN="$(policy_lan_pointer_chain)"

    network_dispatcher_chain_exists "$IPT" "$DISP" || return 1

    policy_pointer_chain_exists "$IPT" "$MOB" || return 1
    policy_pointer_chain_exists "$IPT" "$WIFI" || return 1
    policy_pointer_chain_exists "$IPT" "$LAN" || return 1

    while IFS='|' read -r TYPE VALUE EXTRA; do
        case "$TYPE" in
            MOBILE)
                [ -n "$VALUE" ] || continue

                "$IPT" -w 5 -A "$DISP" \
                    -o "$VALUE" -j "$MOB" || return 1

                "$IPT" -w 5 -A "$DISP" \
                    -o "$VALUE" -j ACCEPT || return 1
                ;;

            WLAN4)
                [ "$FAMILY" = "ipv4" ] || continue
                [ -n "$VALUE" ] || continue

                "$IPT" -w 5 -A "$DISP" \
                    -d "$VALUE" -o wlan0 -j "$LAN" || return 1

                "$IPT" -w 5 -A "$DISP" \
                    -d "$VALUE" -o wlan0 -j ACCEPT || return 1
                ;;

            WLAN6)
                [ "$FAMILY" = "ipv6" ] || continue
                [ -n "$VALUE" ] || continue

                "$IPT" -w 5 -A "$DISP" \
                    -d "$VALUE" -o wlan0 -j "$LAN" || return 1

                "$IPT" -w 5 -A "$DISP" \
                    -d "$VALUE" -o wlan0 -j ACCEPT || return 1
                ;;
        esac
    done < "$NETWORK_STATE"

    if [ "$FAMILY" = "ipv4" ]; then
        if grep -q '^WLAN4|' "$NETWORK_STATE"; then
            "$IPT" -w 5 -A "$DISP" \
                -o wlan0 -j "$WIFI" || return 1

            "$IPT" -w 5 -A "$DISP" \
                -o wlan0 -j ACCEPT || return 1
        fi
    else
        if grep -q '^WLAN6|' "$NETWORK_STATE"; then
            "$IPT" -w 5 -A "$DISP" \
                -o wlan0 -j "$WIFI" || return 1

            "$IPT" -w 5 -A "$DISP" \
                -o wlan0 -j ACCEPT || return 1
        fi
    fi

    while IFS='|' read -r TYPE VPN_IFACE UNDERLYING_IFACE; do
        [ "$TYPE" = "VPN" ] || continue
        [ -n "$VPN_IFACE" ] || continue
        [ -n "$UNDERLYING_IFACE" ] || continue

        case "$UNDERLYING_IFACE" in
            wlan*)
                if [ "$FAMILY" = "ipv4" ]; then
                    if ! grep -q '^WLAN4|' "$NETWORK_STATE"; then
                        log_error "Firewall" "Unsupported VPN topology" \
                            "family=ipv4 vpn=$VPN_IFACE underlying=$UNDERLYING_IFACE missing=WLAN4"
                        return 1
                    fi

                    while IFS='|' read -r WLAN_TYPE WLAN_VALUE EXTRA; do
                        [ "$WLAN_TYPE" = "WLAN4" ] || continue
                        [ -n "$WLAN_VALUE" ] || continue

                        "$IPT" -w 5 -A "$DISP" \
                            -o "$VPN_IFACE" -d "$WLAN_VALUE" -j "$LAN" || return 1

                        "$IPT" -w 5 -A "$DISP" \
                            -o "$VPN_IFACE" -d "$WLAN_VALUE" -j ACCEPT || return 1
                    done < "$NETWORK_STATE"

                    "$IPT" -w 5 -A "$DISP" \
                        -o "$VPN_IFACE" -j "$WIFI" || return 1

                    "$IPT" -w 5 -A "$DISP" \
                        -o "$VPN_IFACE" -j ACCEPT || return 1
                else
                    if ! grep -q '^WLAN6|' "$NETWORK_STATE"; then
                        log_error "Firewall" "Unsupported VPN topology" \
                            "family=ipv6 vpn=$VPN_IFACE underlying=$UNDERLYING_IFACE missing=WLAN6"
                        return 1
                    fi

                    while IFS='|' read -r WLAN_TYPE WLAN_VALUE EXTRA; do
                        [ "$WLAN_TYPE" = "WLAN6" ] || continue
                        [ -n "$WLAN_VALUE" ] || continue

                        "$IPT" -w 5 -A "$DISP" \
                            -o "$VPN_IFACE" -d "$WLAN_VALUE" -j "$LAN" || return 1

                        "$IPT" -w 5 -A "$DISP" \
                            -o "$VPN_IFACE" -d "$WLAN_VALUE" -j ACCEPT || return 1
                    done < "$NETWORK_STATE"

                    "$IPT" -w 5 -A "$DISP" \
                        -o "$VPN_IFACE" -j "$WIFI" || return 1

                    "$IPT" -w 5 -A "$DISP" \
                        -o "$VPN_IFACE" -j ACCEPT || return 1
                fi
                ;;

            rmnet*)
                "$IPT" -w 5 -A "$DISP" \
                    -o "$VPN_IFACE" -j "$MOB" || return 1

                "$IPT" -w 5 -A "$DISP" \
                    -o "$VPN_IFACE" -j ACCEPT || return 1
                ;;

            *)
                log_error "Firewall" "Unsupported VPN topology" \
                    "family=$FAMILY vpn=$VPN_IFACE underlying=$UNDERLYING_IFACE"
                return 1
                ;;
        esac
    done < "$NETWORK_STATE"

    "$IPT" -w 5 -A "$DISP" -j RETURN || return 1

    return 0
}

network_generation_verify_family() {
    GEN="$1"
    FAMILY="$2"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    DISP="$(network_dispatcher_chain "$GEN")"

    MOB="$(policy_mobile_pointer_chain)"
    WIFI="$(policy_wifi_pointer_chain)"
    LAN="$(policy_lan_pointer_chain)"

    policy_pointer_chain_exists "$IPT" "$MOB" || return 1
    policy_pointer_chain_exists "$IPT" "$WIFI" || return 1
    policy_pointer_chain_exists "$IPT" "$LAN" || return 1

    RULES="$("$IPT" -w 5 -S "$DISP" 2>/dev/null)" || return 1

    RETURN_COUNT=0
    LAST_RULE=""

    while IFS= read -r RULE; do
        [ -n "$RULE" ] || continue

        case "$RULE" in
            "-N $DISP")
                continue
                ;;
            "-A $DISP -o "*"-j $MOB")
                ;;
            "-A $DISP -o "*"-j $WIFI")
                ;;
            "-A $DISP -o "*"-j $LAN")
                ;;
            "-A $DISP -d "*"-o "*"-j $LAN")
                ;;
            "-A $DISP -d "*"-o "*"-j RETURN")
                ;;
            "-A $DISP -o "*"-d "*"-j RETURN")
                ;;
            "-A $DISP -j $WIFI")
                ;;
            "-A $DISP -j $MOB")
                ;;
            "-A $DISP -o "*"-j ACCEPT")
                ;;
            "-A $DISP -d "*"-o "*"-j ACCEPT")
                ;;
            "-A $DISP -o "*"-d "*"-j ACCEPT")
                ;;
            "-A $DISP -j RETURN")
                RETURN_COUNT=$((RETURN_COUNT + 1))
                ;;
            "")
                ;;
            *)
                debug_log "Firewall" "network dispatcher unexpected rule" \
                    "family=$FAMILY rule=$RULE"
                return 1
                ;;
        esac

        [ -n "$RULE" ] && LAST_RULE="$RULE"
    done <<EOF
$RULES
EOF

    [ "$RETURN_COUNT" -eq 1 ] || return 1
    [ "$LAST_RULE" = "-A $DISP -j RETURN" ] || return 1

    return 0
}

network_generation_verify_complete() {
    GEN="$1"

    network_generation_verify_family "$GEN" ipv4 || return 1
    network_generation_verify_family "$GEN" ipv6 || return 1

    return 0
}

policy_pointer_chain_exists() {
    IPT="$1"
    CHAIN="$2"
    chain_exists "$IPT" "$CHAIN"
}

policy_pointer_family_exists() {
    FAMILY="$1"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    policy_pointer_chain_exists "$IPT" "$(policy_mobile_pointer_chain)" || return 1
    policy_pointer_chain_exists "$IPT" "$(policy_wifi_pointer_chain)" || return 1
    policy_pointer_chain_exists "$IPT" "$(policy_lan_pointer_chain)" || return 1

    return 0
}

policy_pointer_create_family() {
    FAMILY="$1"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    MOB="$(policy_mobile_pointer_chain)"
    WIFI="$(policy_wifi_pointer_chain)"
    LAN="$(policy_lan_pointer_chain)"

    if policy_pointer_chain_exists "$IPT" "$MOB" ||
       policy_pointer_chain_exists "$IPT" "$WIFI" ||
       policy_pointer_chain_exists "$IPT" "$LAN"; then
        return 1
    fi

    "$IPT" -w 5 -N "$MOB" || return 1

    if ! "$IPT" -w 5 -N "$WIFI"; then
        "$IPT" -w 5 -X "$MOB" >/dev/null 2>&1 || true
        return 1
    fi

    if ! "$IPT" -w 5 -N "$LAN"; then
        "$IPT" -w 5 -X "$WIFI" >/dev/null 2>&1 || true
        "$IPT" -w 5 -X "$MOB" >/dev/null 2>&1 || true
        return 1
    fi

    return 0
}

policy_pointer_delete_family() {
    FAMILY="$1"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    MOB="$(policy_mobile_pointer_chain)"
    WIFI="$(policy_wifi_pointer_chain)"
    LAN="$(policy_lan_pointer_chain)"

    for CHAIN in "$MOB" "$WIFI" "$LAN"; do
        if policy_pointer_chain_exists "$IPT" "$CHAIN"; then
            "$IPT" -w 5 -F "$CHAIN" || return 1
            "$IPT" -w 5 -X "$CHAIN" || return 1
        fi
    done

    return 0
}

policy_pointer_verify_family() {
    FAMILY="$1"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    MOB="$(policy_mobile_pointer_chain)"
    WIFI="$(policy_wifi_pointer_chain)"
    LAN="$(policy_lan_pointer_chain)"

    for CHAIN in "$MOB" "$WIFI" "$LAN"; do
        case "$CHAIN" in
            "$MOB") SUFFIX="M" ;;
            "$WIFI") SUFFIX="W" ;;
            "$LAN") SUFFIX="L" ;;
            *) return 1 ;;
        esac

        RULES="$("$IPT" -w 5 -S "$CHAIN" 2>/dev/null)" || return 1

        TARGET=""
        RETURN_COUNT=0
        OTHER_COUNT=0

        while IFS= read -r RULE; do
            [ -n "$RULE" ] || continue

            case "$RULE" in
                "-N $CHAIN")
                    continue
                    ;;
                "-A $CHAIN -j TIRNFW-G"[0-9]*"-$SUFFIX")
                    if [ -n "$TARGET" ]; then
                        OTHER_COUNT=$((OTHER_COUNT + 1))
                    else
                        TARGET="${RULE#-A $CHAIN -j }"
                    fi
                    ;;
                "-A $CHAIN -j RETURN")
                    RETURN_COUNT=$((RETURN_COUNT + 1))
                    ;;
                *)
                    OTHER_COUNT=$((OTHER_COUNT + 1))
                    ;;
            esac
        done <<EOF
$RULES
EOF

        [ "$OTHER_COUNT" -eq 0 ] || return 1
        [ "$RETURN_COUNT" -eq 1 ] || return 1
        [ -n "$TARGET" ] || return 1

        case "$TARGET" in
            TIRNFW-G*-"$SUFFIX")
                TARGET_GEN="${TARGET#TIRNFW-G}"
                TARGET_GEN="${TARGET_GEN%-${SUFFIX}}"
                ;;
            *)
                return 1
                ;;
        esac

        case "$TARGET_GEN" in
            ''|*[!0-9]*)
                return 1
                ;;
        esac

        POINTER_CHAIN="$CHAIN"
        TARGET_CHAIN="TIRNFW-G${TARGET_GEN}-${SUFFIX}"
        policy_pointer_chain_exists "$IPT" "$TARGET_CHAIN" || return 1

        FIRST_RULE="$(printf '%s\n' "$RULES" | sed -n '2p')"
        SECOND_RULE="$(printf '%s\n' "$RULES" | sed -n '3p')"

        [ "$FIRST_RULE" = "-A $POINTER_CHAIN -j $TARGET" ] || return 1
        [ "$SECOND_RULE" = "-A $POINTER_CHAIN -j RETURN" ] || return 1
    done

    return 0
}



generation_guard_create() {
    if generation_chain_exists "$IPTABLES" "$GENERATION_GUARD_CHAIN"; then
        "$IPTABLES" -w 5 -F "$GENERATION_GUARD_CHAIN" || return 1
    else
        "$IPTABLES" -w 5 -N "$GENERATION_GUARD_CHAIN" || return 1
    fi

    if generation_chain_exists "$IP6TABLES" "$GENERATION_GUARD_CHAIN"; then
        "$IP6TABLES" -w 5 -F "$GENERATION_GUARD_CHAIN" || return 1
    else
        "$IP6TABLES" -w 5 -N "$GENERATION_GUARD_CHAIN" || {
            "$IPTABLES" -w 5 -F "$GENERATION_GUARD_CHAIN" >/dev/null 2>&1 || true
            return 1
        }
    fi

    "$IPTABLES" -w 5 -A "$GENERATION_GUARD_CHAIN" -j DROP || {
        "$IPTABLES" -w 5 -F "$GENERATION_GUARD_CHAIN" >/dev/null 2>&1 || true
        "$IP6TABLES" -w 5 -F "$GENERATION_GUARD_CHAIN" >/dev/null 2>&1 || true
        return 1
    }

    "$IP6TABLES" -w 5 -A "$GENERATION_GUARD_CHAIN" -j DROP || {
        "$IPTABLES" -w 5 -F "$GENERATION_GUARD_CHAIN" >/dev/null 2>&1 || true
        "$IP6TABLES" -w 5 -F "$GENERATION_GUARD_CHAIN" >/dev/null 2>&1 || true
        return 1
    }

    return 0
}

generation_guard_install() {
    generation_guard_create || return 1

    if ! "$IPTABLES" -w 5 -C "$MAIN_CHAIN" -j "$GENERATION_GUARD_CHAIN" 2>/dev/null; then
        if ! "$IPTABLES" -w 5 -I "$MAIN_CHAIN" 1 -j "$GENERATION_GUARD_CHAIN"; then
            log_error "Firewall" "IPv4 guard installation failed" \
                "guard state must be re-evaluated"
            return 1
        fi
    fi

    if ! "$IP6TABLES" -w 5 -C "$MAIN_CHAIN" -j "$GENERATION_GUARD_CHAIN" 2>/dev/null; then
        if ! "$IP6TABLES" -w 5 -I "$MAIN_CHAIN" 1 -j "$GENERATION_GUARD_CHAIN"; then
            log_error "Firewall" "IPv6 guard installation failed" \
                "ipv4=active ipv6=missing; IPv4 guard retained"
            return 1
        fi
    fi

    if ! generation_guard_verify; then
        log_error "Firewall" "Guard verification failed after installation" \
            "guard state must be retained and re-evaluated"
        return 1
    fi

    debug_log "Firewall" "Fail-closed guard installed" \
        "ipv4=active ipv6=active"

    return 0
}

generation_guard_remove() {
    IPV4_RULES="$("$IPTABLES" -w 5 -S "$MAIN_CHAIN" 2>/dev/null)" || {
        log_error "Firewall" "IPv4 guard state read failed"             "guard state unknown"
        return 1
    }

    IPV6_RULES="$("$IP6TABLES" -w 5 -S "$MAIN_CHAIN" 2>/dev/null)" || {
        log_error "Firewall" "IPv6 guard state read failed"             "guard state unknown"
        return 1
    }

    IPV4_GUARD_COUNT="$(
        printf '%s\n' "$IPV4_RULES" |
        awk -v chain="$MAIN_CHAIN" -v guard="$GENERATION_GUARD_CHAIN"             '$0 == "-A " chain " -j " guard {count++} END {print count+0}'
    )"

    IPV6_GUARD_COUNT="$(
        printf '%s\n' "$IPV6_RULES" |
        awk -v chain="$MAIN_CHAIN" -v guard="$GENERATION_GUARD_CHAIN"             '$0 == "-A " chain " -j " guard {count++} END {print count+0}'
    )"

    case "$IPV4_GUARD_COUNT:$IPV6_GUARD_COUNT" in
        0:0)
            log_info "Firewall" "Guard already absent"                 "ipv4=absent ipv6=absent"
            return 0
            ;;
        1:1)
            ;;
        *)
            log_error "Firewall" "Guard state inconsistent"                 "ipv4_hooks=$IPV4_GUARD_COUNT ipv6_hooks=$IPV6_GUARD_COUNT"
            return 1
            ;;
    esac

    if ! "$IPTABLES" -w 5 -D "$MAIN_CHAIN"         -j "$GENERATION_GUARD_CHAIN"; then
        log_error "Firewall" "IPv4 guard removal failed"             "guard state must be re-evaluated"
        return 1
    fi

    if ! "$IP6TABLES" -w 5 -D "$MAIN_CHAIN"         -j "$GENERATION_GUARD_CHAIN"; then

        log_error "Firewall" "IPv6 guard removal failed"             "restoring IPv4 guard"

        if ! "$IPTABLES" -w 5 -I "$MAIN_CHAIN" 1             -j "$GENERATION_GUARD_CHAIN"; then
            log_error "Firewall" "IPv4 guard restoration failed"                 "guard state is inconsistent"
        fi

        return 1
    fi

    IPV4_VERIFY="$("$IPTABLES" -w 5 -S "$MAIN_CHAIN" 2>/dev/null)" || {
        log_error "Firewall" "IPv4 guard state verification failed"             "restoring fail-closed guard"

        "$IPTABLES" -w 5 -I "$MAIN_CHAIN" 1             -j "$GENERATION_GUARD_CHAIN" >/dev/null 2>&1 ||             log_error "Firewall" "IPv4 guard restoration failed"                 "guard state is inconsistent"

        "$IP6TABLES" -w 5 -I "$MAIN_CHAIN" 1             -j "$GENERATION_GUARD_CHAIN" >/dev/null 2>&1 ||             log_error "Firewall" "IPv6 guard restoration failed"                 "guard state is inconsistent"

        return 1
    }

    IPV6_VERIFY="$("$IP6TABLES" -w 5 -S "$MAIN_CHAIN" 2>/dev/null)" || {
        log_error "Firewall" "IPv6 guard state verification failed"             "restoring fail-closed guard"

        "$IPTABLES" -w 5 -I "$MAIN_CHAIN" 1             -j "$GENERATION_GUARD_CHAIN" >/dev/null 2>&1 ||             log_error "Firewall" "IPv4 guard restoration failed"                 "guard state is inconsistent"

        "$IP6TABLES" -w 5 -I "$MAIN_CHAIN" 1             -j "$GENERATION_GUARD_CHAIN" >/dev/null 2>&1 ||             log_error "Firewall" "IPv6 guard restoration failed"                 "guard state is inconsistent"

        return 1
    }

    IPV4_REMAINING="$(
        printf '%s\n' "$IPV4_VERIFY" |
        awk -v chain="$MAIN_CHAIN" -v guard="$GENERATION_GUARD_CHAIN"             '$0 == "-A " chain " -j " guard {count++} END {print count+0}'
    )"

    IPV6_REMAINING="$(
        printf '%s\n' "$IPV6_VERIFY" |
        awk -v chain="$MAIN_CHAIN" -v guard="$GENERATION_GUARD_CHAIN"             '$0 == "-A " chain " -j " guard {count++} END {print count+0}'
    )"

    if [ "$IPV4_REMAINING" -ne 0 ] ||
       [ "$IPV6_REMAINING" -ne 0 ]; then
        log_error "Firewall" "Guard removal verification failed"             "ipv4_hooks=$IPV4_REMAINING ipv6_hooks=$IPV6_REMAINING"
        return 1
    fi

    debug_log "Firewall" "Fail-closed guard removed"         "ipv4=absent ipv6=absent"

    return 0
}

generation_guard_verify() {
    "$IPTABLES" -w 5 -C "$MAIN_CHAIN" -j "$GENERATION_GUARD_CHAIN" >/dev/null 2>&1 || return 1
    "$IP6TABLES" -w 5 -C "$MAIN_CHAIN" -j "$GENERATION_GUARD_CHAIN" >/dev/null 2>&1 || return 1

    IPV4_GUARD_RULES="$("$IPTABLES" -w 5 -S "$GENERATION_GUARD_CHAIN" 2>/dev/null)" || return 1
    IPV6_GUARD_RULES="$("$IP6TABLES" -w 5 -S "$GENERATION_GUARD_CHAIN" 2>/dev/null)" || return 1

    IPV4_RULE_COUNT=0
    IPV6_RULE_COUNT=0

    while IFS= read -r RULE; do
        [ -n "$RULE" ] || continue
        case "$RULE" in
            "-N $GENERATION_GUARD_CHAIN")
                continue
                ;;
            "-A $GENERATION_GUARD_CHAIN -j DROP")
                IPV4_RULE_COUNT=$((IPV4_RULE_COUNT + 1))
                ;;
            *)
                return 1
                ;;
        esac
    done <<EOF
$IPV4_GUARD_RULES
EOF

    while IFS= read -r RULE; do
        [ -n "$RULE" ] || continue
        case "$RULE" in
            "-N $GENERATION_GUARD_CHAIN")
                continue
                ;;
            "-A $GENERATION_GUARD_CHAIN -j DROP")
                IPV6_RULE_COUNT=$((IPV6_RULE_COUNT + 1))
                ;;
            *)
                return 1
                ;;
        esac
    done <<EOF
$IPV6_GUARD_RULES
EOF

    [ "$IPV4_RULE_COUNT" -eq 1 ] || return 1
    [ "$IPV6_RULE_COUNT" -eq 1 ] || return 1

    return 0
}

network_active_generation() {
    FAMILY="$1"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    RULES="$("$IPT" -w 5 -S "$MAIN_CHAIN" 2>/dev/null)" || return 1

    TARGETS=""
    COUNT=0

    while IFS= read -r RULE; do
        [ -n "$RULE" ] || continue

        case "$RULE" in
            "-A $MAIN_CHAIN -j TIRNFW-NET-G"[0-9]*)
                TARGET="${RULE#-A $MAIN_CHAIN -j }"
                TARGET_GEN="${TARGET#TIRNFW-NET-G}"

                case "$TARGET_GEN" in
                    ''|*[!0-9]*)
                        return 1
                        ;;
                esac

                COUNT=$((COUNT + 1))
                TARGETS="${TARGETS}${TARGET}
"
                ;;
        esac
    done <<EOF
$RULES
EOF

    [ "$COUNT" -eq 1 ] || return 1

    TARGET="$(printf '%s' "$TARGETS" | sed -n '1p')"
    TARGET_GEN="${TARGET#TIRNFW-NET-G}"

    network_dispatcher_chain_exists "$IPT" "$TARGET" || return 1

    printf '%s
' "$TARGET_GEN"
}

network_active_generation_complete() {
    OLD4="$(network_active_generation ipv4)" || return 1
    OLD6="$(network_active_generation ipv6)" || return 1

    [ "$OLD4" = "$OLD6" ] || return 1

    printf '%s
' "$OLD4"
}

network_generation_active_rule_ipv4() {
    GEN="$1"
    DISP="$(network_dispatcher_chain "$GEN")"
    "$IPTABLES" -w 5 -C "$MAIN_CHAIN" -j "$DISP" >/dev/null 2>&1
}

network_generation_active_rule_ipv6() {
    GEN="$1"
    DISP="$(network_dispatcher_chain "$GEN")"
    "$IP6TABLES" -w 5 -C "$MAIN_CHAIN" -j "$DISP" >/dev/null 2>&1
}

network_generation_install_active_ipv4() {
    GEN="$1"
    DISP="$(network_dispatcher_chain "$GEN")"

    network_dispatcher_chain_exists "$IPTABLES" "$DISP" || return 1

    LOOPBACK_POSITION="$(
        "$IPTABLES" -w 5 -S "$MAIN_CHAIN" 2>/dev/null |
            awk -v chain="$MAIN_CHAIN" '
                /^-A / { RULE_POSITION++ }
                $0 == "-A " chain " -o lo -j RETURN" {
                    print RULE_POSITION
                    exit
                }
            '
    )"
    case "$LOOPBACK_POSITION" in
        ''|*[!0-9]*)
            return 1
            ;;
    esac

    INSERT_POSITION=$((LOOPBACK_POSITION + 1))
    "$IPTABLES" -w 5 -I "$MAIN_CHAIN" "$INSERT_POSITION" -j "$DISP"
}

network_generation_install_active_ipv6() {
    GEN="$1"
    DISP="$(network_dispatcher_chain "$GEN")"

    network_dispatcher_chain_exists "$IP6TABLES" "$DISP" || return 1

    LOOPBACK_POSITION="$(
        "$IP6TABLES" -w 5 -S "$MAIN_CHAIN" 2>/dev/null |
            awk -v chain="$MAIN_CHAIN" '
                /^-A / { RULE_POSITION++ }
                $0 == "-A " chain " -o lo -j RETURN" {
                    print RULE_POSITION
                    exit
                }
            '
    )"
    case "$LOOPBACK_POSITION" in
        ''|*[!0-9]*)
            return 1
            ;;
    esac

    INSERT_POSITION=$((LOOPBACK_POSITION + 1))
    "$IP6TABLES" -w 5 -I "$MAIN_CHAIN" "$INSERT_POSITION" -j "$DISP"
}

network_generation_remove_active_ipv4() {
    GEN="$1"
    DISP="$(network_dispatcher_chain "$GEN")"
    "$IPTABLES" -w 5 -D "$MAIN_CHAIN" -j "$DISP"
}

network_generation_remove_active_ipv6() {
    GEN="$1"
    DISP="$(network_dispatcher_chain "$GEN")"
    "$IP6TABLES" -w 5 -D "$MAIN_CHAIN" -j "$DISP"
}

chain_exists() {
    "$1" -w 5 -S "$2" >/dev/null 2>&1
}

bootstrap_main_chain_fail_closed_family() {
    FAMILY="$1"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    if ! chain_exists "$IPT" "$MAIN_CHAIN"; then
        "$IPT" -w 5 -N "$MAIN_CHAIN" || return 1
        "$IPT" -w 5 -A "$MAIN_CHAIN" -o lo -j RETURN || return 1
        "$IPT" -w 5 -A "$MAIN_CHAIN" -j DROP || return 1
        "$IPT" -w 5 -A "$MAIN_CHAIN" -j RETURN || return 1
        return 0
    fi

    RULES="$("$IPT" -w 5 -S "$MAIN_CHAIN" 2>/dev/null)" || return 1


    LOOPBACK_COUNT=0
    DROP_COUNT=0
    RETURN_COUNT=0
    OTHER_COUNT=0

    while IFS= read -r RULE; do
        [ -n "$RULE" ] || continue

        case "$RULE" in
            "-N $MAIN_CHAIN")
                continue
                ;;
            "-A $MAIN_CHAIN -o lo -j RETURN")
                LOOPBACK_COUNT=$((LOOPBACK_COUNT + 1))
                ;;
            "-A $MAIN_CHAIN -j DROP")
                DROP_COUNT=$((DROP_COUNT + 1))
                ;;
            "-A $MAIN_CHAIN -j RETURN")
                RETURN_COUNT=$((RETURN_COUNT + 1))
                ;;
            *)
                OTHER_COUNT=$((OTHER_COUNT + 1))
                ;;
        esac
    done <<EOF
$RULES
EOF

    # An existing network generation is not modified here.
    ACTIVE_NETWORK_GENERATION="$(
        "$IPT" -w 5 -S "$MAIN_CHAIN" 2>/dev/null |
            sed -n 's/^-A TIRNFW -j \(TIRNFW-NET-G[0-9][0-9]*\)$/\1/p' |
            head -n 1
    )"

    if [ -n "$ACTIVE_NETWORK_GENERATION" ] &&
       network_generation_verify_complete \
           "${ACTIVE_NETWORK_GENERATION#TIRNFW-NET-G}" 2>/dev/null; then
        if [ "$LOOPBACK_COUNT" -eq 0 ]; then
            "$IPT" -w 5 -I "$MAIN_CHAIN" 1 -o lo -j RETURN || return 1
        elif [ "$LOOPBACK_COUNT" -ne 1 ]; then
            return 1
        fi
        return 0
    fi

    # An existing policy generation or guard is not modified here.
    ACTIVE_GENERATION="$(
        "$IPT" -w 5 -S "$MAIN_CHAIN" 2>/dev/null |
            sed -n 's/^-A TIRNFW -j \(TIRNFW-G[0-9][0-9]*\)$/\1/p' |
            head -n 1
    )"

    if generation_verify_stable_dispatcher_family \
        "$ACTIVE_GENERATION" "$FAMILY" 2>/dev/null; then
        if [ "$LOOPBACK_COUNT" -eq 0 ]; then
            "$IPT" -w 5 -I "$MAIN_CHAIN" 1 -o lo -j RETURN || return 1
        elif [ "$LOOPBACK_COUNT" -ne 1 ]; then
            return 1
        fi
        return 0
    fi

    # A completely empty/legacy-unknown chain must never be converted
    # destructively. Only the exact loopback + DROP + RETURN baseline is safe.
    [ "$LOOPBACK_COUNT" -eq 1 ] || return 1
    [ "$DROP_COUNT" -eq 1 ] || return 1
    [ "$RETURN_COUNT" -eq 1 ] || return 1
    [ "$OTHER_COUNT" -eq 0 ] || return 1

    FIRST_RULE="$(printf '%s\n' "$RULES" | sed -n '1p')"
    SECOND_RULE="$(printf '%s\n' "$RULES" | sed -n '2p')"
    THIRD_RULE="$(printf '%s\n' "$RULES" | sed -n '3p')"

    [ "$FIRST_RULE" = "-A $MAIN_CHAIN -o lo -j RETURN" ] || return 1
    [ "$SECOND_RULE" = "-A $MAIN_CHAIN -j DROP" ] || return 1
    [ "$THIRD_RULE" = "-A $MAIN_CHAIN -j RETURN" ] || return 1

    return 0
}

bootstrap_output_hook_family() {
    FAMILY="$1"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    RULES="$("$IPT" -w 5 -S OUTPUT 2>/dev/null)" || return 1

    COUNT=0
    POSITION=0
    HOOK_POSITION=0

    while IFS= read -r RULE; do
        [ -n "$RULE" ] || continue

        case "$RULE" in
            "-N OUTPUT")
                continue
                ;;
        esac

        case "$RULE" in
            "-A OUTPUT "*)
                POSITION=$((POSITION + 1))

                if [ "$RULE" = "-A OUTPUT -j $MAIN_CHAIN" ]; then
                    COUNT=$((COUNT + 1))
                    HOOK_POSITION="$POSITION"
                fi
                ;;
        esac
    done <<EOF
$RULES
EOF

    if [ "$COUNT" -eq 1 ] && [ "$HOOK_POSITION" -eq 1 ]; then
        return 0
    fi

    if [ "$COUNT" -gt 1 ]; then
        log_error "Firewall" "Bootstrap failed" \
            "multiple owned OUTPUT hooks family=$FAMILY"
        return 1
    fi

    if [ "$COUNT" -eq 1 ]; then
        # Remove only our exact owned hook. Do not touch any other OUTPUT rule.
        "$IPT" -w 5 -D OUTPUT -j "$MAIN_CHAIN" || return 1
    fi

    "$IPT" -w 5 -I OUTPUT 1 -j "$MAIN_CHAIN" || return 1

    RULES="$("$IPT" -w 5 -S OUTPUT 2>/dev/null)" || return 1
    COUNT=0
    POSITION=0
    HOOK_POSITION=0

    while IFS= read -r RULE; do
        [ -n "$RULE" ] || continue

        case "$RULE" in
            "-N OUTPUT")
                continue
                ;;
        esac

        case "$RULE" in
            "-A OUTPUT "*)
                POSITION=$((POSITION + 1))
                if [ "$RULE" = "-A OUTPUT -j $MAIN_CHAIN" ]; then
                    COUNT=$((COUNT + 1))
                    HOOK_POSITION="$POSITION"
                fi
                ;;
        esac
    done <<EOF
$RULES
EOF

    [ "$COUNT" -eq 1 ] || return 1
    [ "$HOOK_POSITION" -eq 1 ] || return 1

    return 0
}

prepare_policy() {
    PREPARED_POLICY="$1"
    PREPARED_COUNT="$2"
    POLICY_SOURCE="${3:-$POLICY_FILE}"

    TMP_MAP="$DATA_DIR/apps.uidmap.$$"
    TMP_PREPARED="$PREPARED_POLICY.tmp.$$"
    TMP_NORMALIZED="$PREPARED_POLICY.normalized.$$"

    rm -f "$TMP_MAP" "$TMP_PREPARED" "$TMP_NORMALIZED"

    if [ ! -f "$DATA_DIR/apps.json" ]; then
        log_error "Policy" "Preparation failed" "apps cache missing"
        return 1
    fi

    if ! sed 's/},{/}\n{/g' "$DATA_DIR/apps.json" |
        awk '
            {
                user = ""
                pkg = ""
                uid = ""

                if (match($0, /"user":"[0-9]+"/)) {
                    x = substr($0, RSTART, RLENGTH)
                    sub(/^"user":"/, "", x)
                    sub(/"$/, "", x)
                    user = x
                }

                if (match($0, /"pkg":"[^"]+"/)) {
                    x = substr($0, RSTART, RLENGTH)
                    sub(/^"pkg":"/, "", x)
                    sub(/"$/, "", x)
                    pkg = x
                }

                if (match($0, /"uid":"[0-9]+"/)) {
                    x = substr($0, RSTART, RLENGTH)
                    sub(/^"uid":"/, "", x)
                    sub(/"$/, "", x)
                    uid = x
                }

                if (user != "" && pkg != "" && uid != "")
                    print user "|" pkg "|" uid
            }
        ' > "$TMP_MAP"; then
        rm -f "$TMP_MAP" "$TMP_PREPARED" "$TMP_NORMALIZED"
        log_error "Policy" "Preparation failed" "unable to build app UID map"
        return 1
    fi

    if ! awk -F'|' '
        FILENAME == ARGV[1] {
            if (NF == 3)
                app_uid[$1 SUBSEP $2] = $3
            next
        }

        FILENAME == ARGV[2] {
            line_no++

            if ($0 ~ /^[[:space:]]*#/)
                next

            if ($0 ~ /^[[:space:]]*$/)
                next

            if (NF != 5) {
                error = "invalid field count on line " line_no
                exit 2
            }

            user = $1
            pkg = $2
            uid = $3
            network = $4
            action = $5

            if (user !~ /^[0-9]+$/ || user > 2147483647) {
                error = "invalid user on line " line_no
                exit 2
            }

            if (pkg !~ /^[A-Za-z0-9._-]+$/) {
                error = "invalid package on line " line_no
                exit 2
            }

            if (uid !~ /^[0-9]+$/ || uid < 1 || uid > 2147483647) {
                error = "invalid UID on line " line_no
                exit 2
            }

            if (network != "MOBILE" &&
                network != "WIFI" &&
                network != "LAN") {
                error = "invalid network on line " line_no
                exit 2
            }

            if (action != "BLOCK") {
                error = "invalid action on line " line_no
                exit 2
            }

            key = user SUBSEP pkg

            if (!(key in app_uid)) {
                print user "|" pkg "|" uid "|" network "|" action
                next
            }

            if (app_uid[key] != uid) {
                print user "|" pkg "|" uid "|" network "|" action
                next
            }

            print user "|" pkg "|" uid "|" network "|" action
            next
        }

        END {
            if (error != "") {
                print error > "/dev/stderr"
                exit 2
            }
        }
    ' "$TMP_MAP" "$POLICY_SOURCE" > "$TMP_NORMALIZED"; then
        rm -f "$TMP_MAP" "$TMP_PREPARED" "$TMP_NORMALIZED"
        log_error "Policy" "Preparation failed" "policy validation or UID resolution failed"
        return 1
    fi

    if ! sort -u "$TMP_NORMALIZED" > "$TMP_PREPARED"; then
        rm -f "$TMP_MAP" "$TMP_PREPARED" "$TMP_NORMALIZED"
        log_error "Policy" "Preparation failed" "unable to sort prepared policy"
        return 1
    fi

    rm -f "$TMP_MAP" "$TMP_NORMALIZED"

    if ! mv -f "$TMP_PREPARED" "$PREPARED_POLICY"; then
        rm -f "$TMP_PREPARED" "$PREPARED_POLICY"
        log_error "Policy" "Preparation failed" "unable to finalize prepared policy"
        return 1
    fi

    PREPARED_RULE_COUNT="$(wc -l < "$PREPARED_POLICY" 2>/dev/null)"
    PREPARED_RULE_COUNT="$(printf "%s" "$PREPARED_RULE_COUNT" | tr -d " ")"

    printf "%s\n" "$PREPARED_RULE_COUNT" > "$PREPARED_COUNT"

    log_info "Policy" "Prepared" "rules=$PREPARED_RULE_COUNT"
    return 0
}
validate_policy_applied_file() {
    POLICY_SOURCE="$1"

    awk -F'|' '
        {
            if ($0 ~ /^[[:space:]]*#/)
                next

            if ($0 ~ /^[[:space:]]*$/)
                next

            if (NF != 5)
                exit 2

            if ($1 !~ /^[0-9]+$/ || $1 > 2147483647)
                exit 2

            if ($2 !~ /^[A-Za-z0-9._-]+$/)
                exit 2

            if ($3 !~ /^[0-9]+$/ || $3 < 1 || $3 > 2147483647)
                exit 2

            if ($4 != "MOBILE" &&
                $4 != "WIFI" &&
                $4 != "LAN")
                exit 2

            if ($5 != "BLOCK")
                exit 2
        }
    ' "$POLICY_SOURCE"
}

validate_policy_conf_file() {
    POLICY_SOURCE="$1"

    awk -F'|' '
        {
            if ($0 ~ /^[[:space:]]*#/)
                next

            if ($0 ~ /^[[:space:]]*$/)
                next

            if (NF != 5)
                exit 2

            if ($1 !~ /^[0-9]+$/ || $1 > 2147483647)
                exit 2

            if ($2 !~ /^[A-Za-z0-9._-]+$/)
                exit 2

            if ($3 !~ /^[0-9]+$/ || $3 < 1 || $3 > 2147483647)
                exit 2

            if ($4 != "MOBILE" &&
                $4 != "WIFI" &&
                $4 != "LAN")
                exit 2

            if ($5 != "BLOCK")
                exit 2
        }

        END {
            if (NR == 0)
                exit 2
        }
    ' "$POLICY_SOURCE"

    return $?
}


recover_boot_policy_state() {

    POLICY_APPLIED_VALID=0
    POLICY_CONF_VALID=0

    if [ -f "$POLICY_STATE_FILE" ] &&
       validate_policy_applied_file "$POLICY_STATE_FILE"; then
        POLICY_APPLIED_VALID=1
    fi

    if [ -f "$POLICY_FILE" ]; then
        validate_policy_conf_file "$POLICY_FILE"
        POLICY_CONF_RESULT=$?

        if [ "$POLICY_CONF_RESULT" -eq 0 ]; then
            POLICY_CONF_VALID=1
        fi
    fi

    if [ "$POLICY_APPLIED_VALID" -eq 1 ] &&
       [ "$POLICY_CONF_VALID" -eq 1 ]; then
        return 0
    fi

    if [ "$POLICY_APPLIED_VALID" -eq 1 ]; then
        log_warn "Policy" "policy.conf invalid" \
            "rebuilding from policy.applied"

        if ! cp -f "$POLICY_STATE_FILE" "$POLICY_FILE"; then
            log_error "Policy" "Recovery failed" \
                "unable to rebuild policy.conf"
            return 1
        fi

        chmod 600 "$POLICY_FILE" || return 1

        return 0
    fi

    if [ "$POLICY_CONF_VALID" -eq 1 ]; then
        log_warn "Policy" "policy.applied invalid" \
            "rebuilding from policy.conf"

        RECOVERY_POLICY="$DATA_DIR/policy.recovery.prepare.$$"
        RECOVERY_COUNT="$DATA_DIR/policy.recovery.count.$$"
        RECOVERY_STATE="$DATA_DIR/policy.applied.recovery.$$"

        rm -f "$RECOVERY_POLICY" "$RECOVERY_COUNT" "$RECOVERY_STATE"

        if ! prepare_policy \
            "$RECOVERY_POLICY" \
            "$RECOVERY_COUNT" \
            "$POLICY_FILE"; then
            rm -f "$RECOVERY_POLICY" "$RECOVERY_COUNT"
            return 1
        fi

        if ! cp -f "$RECOVERY_POLICY" "$RECOVERY_STATE"; then
            rm -f "$RECOVERY_POLICY" "$RECOVERY_COUNT" "$RECOVERY_STATE"
            return 1
        fi

        chmod 600 "$RECOVERY_STATE" || return 1

        if ! mv -f "$RECOVERY_STATE" "$POLICY_STATE_FILE"; then
            rm -f "$RECOVERY_STATE"
            return 1
        fi

        rm -f "$RECOVERY_POLICY" "$RECOVERY_COUNT"

        return 0
    fi

    log_warn "Policy" "Both policy states invalid" \
        "creating empty recovery state"

    if ! : > "$POLICY_FILE"; then
        return 1
    fi

    chmod 600 "$POLICY_FILE" || return 1

    if ! : > "$POLICY_STATE_FILE"; then
        return 1
    fi

    chmod 600 "$POLICY_STATE_FILE" || return 1

    return 0
}


prepare_applied_policy_for_boot() {
    PREPARED_POLICY="$1"
    PREPARED_COUNT="$2"
    POLICY_SOURCE="$POLICY_STATE_FILE"

    TMP_PREPARED="$PREPARED_POLICY.tmp.$$"
    TMP_NORMALIZED="$PREPARED_POLICY.normalized.$$"

    rm -f "$TMP_PREPARED" "$TMP_NORMALIZED"

    if [ ! -f "$POLICY_SOURCE" ]; then
        log_error "Policy" "Boot policy preparation failed" \
            "policy.applied missing"
        return 1
    fi

    if ! awk -F'|' '
        {
            line_no++

            if ($0 ~ /^[[:space:]]*#/)
                next

            if ($0 ~ /^[[:space:]]*$/)
                next

            if (NF != 5) {
                error = "invalid field count on line " line_no
                exit 2
            }

            user = $1
            pkg = $2
            uid = $3
            network = $4
            action = $5

            if (user !~ /^[0-9]+$/ || user > 2147483647) {
                error = "invalid user on line " line_no
                exit 2
            }

            if (pkg !~ /^[A-Za-z0-9._-]+$/) {
                error = "invalid package on line " line_no
                exit 2
            }

            if (uid !~ /^[0-9]+$/ || uid < 1 || uid > 2147483647) {
                error = "invalid UID on line " line_no
                exit 2
            }

            if (network != "MOBILE" &&
                network != "WIFI" &&
                network != "LAN") {
                error = "invalid network on line " line_no
                exit 2
            }

            if (action != "BLOCK") {
                error = "invalid action on line " line_no
                exit 2
            }

            print user "|" pkg "|" uid "|" network "|" action
        }

        END {
            if (error != "") {
                print error > "/dev/stderr"
                exit 2
            }
        }
    ' "$POLICY_SOURCE" > "$TMP_NORMALIZED"; then
        rm -f "$TMP_PREPARED" "$TMP_NORMALIZED"

        log_error "Policy" "Boot policy invalid" \
            "entering empty-policy recovery"

        : > "$TMP_PREPARED"

        if ! mv -f "$TMP_PREPARED" "$PREPARED_POLICY"; then
            rm -f "$TMP_PREPARED"
            log_error "Policy" "Boot policy recovery failed" \
                "unable to create empty prepared policy"
            return 1
        fi

        printf "0\n" > "$PREPARED_COUNT"

        log_info "Policy" "Boot policy recovered" \
            "rules=0 source=empty recovery"

        return 0
    fi

    if ! sort -u "$TMP_NORMALIZED" > "$TMP_PREPARED"; then
        rm -f "$TMP_PREPARED" "$TMP_NORMALIZED"
        log_error "Policy" "Boot policy preparation failed" \
            "unable to sort policy.applied"
        return 1
    fi

    rm -f "$TMP_NORMALIZED"

    if ! mv -f "$TMP_PREPARED" "$PREPARED_POLICY"; then
        rm -f "$TMP_PREPARED" "$PREPARED_POLICY"
        log_error "Policy" "Boot policy preparation failed" \
            "unable to finalize prepared policy"
        return 1
    fi

    PREPARED_RULE_COUNT="$(wc -l < "$PREPARED_POLICY" 2>/dev/null)"
    PREPARED_RULE_COUNT="$(printf "%s" "$PREPARED_RULE_COUNT" | tr -d " ")"

    printf "%s\n" "$PREPARED_RULE_COUNT" > "$PREPARED_COUNT"

    log_info "Policy" "Boot policy prepared" \
        "rules=$PREPARED_RULE_COUNT source=policy.applied"

    return 0
}

prepare_existing_policy_for_removal() {
    PREPARED_POLICY="$1"
    PREPARED_COUNT="$2"
    POLICY_SOURCE="${3:-$POLICY_FILE}"
    REMOVE_USER="$4"
    REMOVE_PACKAGE="$5"
    REMOVED_COUNT_FILE="$6"

    TMP_PREPARED="$PREPARED_POLICY.tmp.$$"
    TMP_NORMALIZED="$PREPARED_POLICY.normalized.$$"
    TMP_REMOVED="$REMOVED_COUNT_FILE.tmp.$$"

    rm -f "$TMP_PREPARED" "$TMP_NORMALIZED" \
        "$TMP_REMOVED" "$PREPARED_POLICY" "$REMOVED_COUNT_FILE"

    if ! awk -F'|' \
        -v remove_user="$REMOVE_USER" \
        -v remove_package="$REMOVE_PACKAGE" \
        -v removed_file="$TMP_REMOVED" '
        {
            line_no++

            if ($0 ~ /^[[:space:]]*#/)
                next

            if ($0 ~ /^[[:space:]]*$/)
                next

            if (NF != 5) {
                error = "invalid field count on line " line_no
                exit 2
            }

            user = $1
            pkg = $2
            uid = $3
            network = $4
            action = $5

            if (user !~ /^[0-9]+$/ || user > 2147483647) {
                error = "invalid user on line " line_no
                exit 2
            }

            if (pkg !~ /^[A-Za-z0-9._-]+$/) {
                error = "invalid package on line " line_no
                exit 2
            }

            if (uid !~ /^[0-9]+$/ || uid < 1 || uid > 2147483647) {
                error = "invalid UID on line " line_no
                exit 2
            }

            if (network != "MOBILE" &&
                network != "WIFI" &&
                network != "LAN") {
                error = "invalid network on line " line_no
                exit 2
            }

            if (action != "BLOCK") {
                error = "invalid action on line " line_no
                exit 2
            }

            if (user == remove_user && pkg == remove_package) {
                removed++
                next
            }

            print user "|" pkg "|" uid "|" network "|" action
            next
        }

        END {
            if (error != "") {
                print error > "/dev/stderr"
                exit 2
            }

            print removed + 0 > removed_file
        }
    ' removed_file="$TMP_REMOVED" "$POLICY_SOURCE" > "$TMP_NORMALIZED"; then
        rm -f "$TMP_PREPARED" "$TMP_NORMALIZED" \
            "$TMP_REMOVED" "$PREPARED_POLICY" "$REMOVED_COUNT_FILE"
        log_error "Policy" "Removal preparation failed" \
            "policy validation failed user=$REMOVE_USER package=$REMOVE_PACKAGE"
        return 1
    fi

    if ! sort -u "$TMP_NORMALIZED" > "$TMP_PREPARED"; then
        rm -f "$TMP_PREPARED" "$TMP_NORMALIZED" \
            "$TMP_REMOVED" "$PREPARED_POLICY" "$REMOVED_COUNT_FILE"
        log_error "Policy" "Removal preparation failed" \
            "unable to sort prepared policy user=$REMOVE_USER package=$REMOVE_PACKAGE"
        return 1
    fi

    if ! mv -f "$TMP_PREPARED" "$PREPARED_POLICY"; then
        rm -f "$TMP_PREPARED" "$TMP_NORMALIZED" "$TMP_REMOVED"
        log_error "Policy" "Removal preparation failed" \
            "unable to finalize prepared policy user=$REMOVE_USER package=$REMOVE_PACKAGE"
        return 1
    fi

    if ! mv -f "$TMP_REMOVED" "$REMOVED_COUNT_FILE"; then
        rm -f "$TMP_NORMALIZED" "$PREPARED_POLICY" "$TMP_REMOVED"
        log_error "Policy" "Removal preparation failed" \
            "unable to finalize removal count user=$REMOVE_USER package=$REMOVE_PACKAGE"
        return 1
    fi

    rm -f "$TMP_NORMALIZED"

    PREPARED_RULE_COUNT="$(wc -l < "$PREPARED_POLICY" 2>/dev/null)"
    PREPARED_RULE_COUNT="$(printf "%s" "$PREPARED_RULE_COUNT" | tr -d " ")"

    case "$PREPARED_RULE_COUNT" in
        ''|*[!0-9]*)
            rm -f "$PREPARED_POLICY" "$PREPARED_COUNT" "$REMOVED_COUNT_FILE"
            log_error "Policy" "Removal preparation failed" \
                "invalid prepared rule count user=$REMOVE_USER package=$REMOVE_PACKAGE"
            return 1
            ;;
    esac

    REMOVED_COUNT="$(cat "$REMOVED_COUNT_FILE" 2>/dev/null)"

    case "$REMOVED_COUNT" in
        ''|*[!0-9]*)
            rm -f "$PREPARED_POLICY" "$PREPARED_COUNT" "$REMOVED_COUNT_FILE"
            log_error "Policy" "Removal preparation failed" \
                "invalid removal count user=$REMOVE_USER package=$REMOVE_PACKAGE"
            return 1
            ;;
    esac

    printf "%s\n" "$PREPARED_RULE_COUNT" > "$PREPARED_COUNT"

    log_info "Policy" "Removal prepared" \
        "user=$REMOVE_USER package=$REMOVE_PACKAGE removed=$REMOVED_COUNT remaining=$PREPARED_RULE_COUNT"

    return 0
}

validate_apps_cache() {
    CACHE="$DATA_DIR/apps.json"

    [ -s "$CACHE" ] || return 1

    if ! grep -q '"status":"OK"' "$CACHE"; then
        return 1
    fi

    if ! grep -q '"profiles":\[' "$CACHE"; then
        return 1
    fi

    if ! grep -q '"apps":\[' "$CACHE"; then
        return 1
    fi

    if grep -q '"apps":\[\]' "$CACHE"; then
        return 1
    fi

    if ! grep -q '"user":"[0-9]*"' "$CACHE"; then
        return 1
    fi

    if ! grep -q '"pkg":"[^"]*"' "$CACHE"; then
        return 1
    fi

    if ! grep -q '"uid":"[0-9]*"' "$CACHE"; then
        return 1
    fi

    return 0
}


verify_apps_refresh()
{
    PROGRESS="$DATA_DIR/apps-refresh-progress"

    [ -s "$PROGRESS" ] || return 1

    STATUS="$(grep -o '"status":"[^"]*"' "$PROGRESS" | cut -d'"' -f4)"
    PROCESSED="$(grep -o '"processed":[0-9]*' "$PROGRESS" | cut -d: -f2)"
    TOTAL="$(grep -o '"total":[0-9]*' "$PROGRESS" | cut -d: -f2)"

    [ "$STATUS" = "COMPLETE" ] || return 1

    case "$PROCESSED" in
        ''|*[!0-9]*) return 1 ;;
    esac

    case "$TOTAL" in
        ''|*[!0-9]*) return 1 ;;
    esac

    [ "$TOTAL" -gt 0 ] || return 1
    [ "$PROCESSED" -eq "$TOTAL" ] || return 1

    CACHE_TIME="$(stat -c %Y "$DATA_DIR/apps.json" 2>/dev/null)"
    case "$CACHE_TIME" in
        ''|*[!0-9]*) return 1 ;;
    esac

    [ "$CACHE_TIME" -ge "$REFRESH_STARTED" ] || return 1

    validate_apps_cache
}


refresh_apps_verified()
{
    MODE="$1"

    ATTEMPT=1
    MAX_ATTEMPTS=2

    if [ "$MODE" = "post-bootstrap" ]; then
        sleep "$POST_BOOT_REFRESH_DELAY"
    elif [ "$MODE" = "bootstrap" ]; then
        sleep 10
    fi

    while [ "$ATTEMPT" -le "$MAX_ATTEMPTS" ]; do

        rm -f "$DATA_DIR/apps-refresh-progress"

        REFRESH_STARTED="$(date +%s)"

        log_info "Apps" "Cache refresh started" \
            "mode=$MODE attempt=$ATTEMPT"

        if /system/bin/sh "$MODDIR/refresh_apps" >/dev/null 2>&1; then

            if verify_apps_refresh; then
                log_info "Apps" "Cache ready" \
                    "mode=$MODE attempt=$ATTEMPT"
                return 0
            fi

            log_warn "Apps" "Cache verification failed" \
                "mode=$MODE attempt=$ATTEMPT"

        else

            log_warn "Apps" "Refresh command failed" \
                "mode=$MODE attempt=$ATTEMPT"

        fi

        if [ "$ATTEMPT" -lt "$MAX_ATTEMPTS" ]; then
            sleep 10
        fi

        ATTEMPT=$((ATTEMPT + 1))
    done

    log_error "Apps" "Cache refresh failed" \
        "mode=$MODE attempts=$MAX_ATTEMPTS"

    return 1
}


bootstrap_post_refresh()
{
    refresh_apps_verified "post-bootstrap"
}


bootstrap_initialize() {
    if [ -f "$POLICY_STATE_FILE" ] &&
       [ -f "$STATE_FILE" ]; then
        bootstrap_existing_install
    else
        bootstrap_fresh_install
    fi
}


bootstrap_existing_install() {
    CACHE_RECOVERY=0

    if ! acquire_firewall_lock; then
        log_error "Firewall" "Existing install bootstrap failed" \
            "firewall lock unavailable"
        return 1
    fi

    if ! validate_apps_cache; then
        log_warn "Apps" "Cached app database unavailable" \
            "entering fail-closed recovery"

        if ! bootstrap_main_chain_fail_closed_family ipv4 ||
           ! bootstrap_main_chain_fail_closed_family ipv6 ||
           ! bootstrap_output_hook_family ipv4 ||
           ! bootstrap_output_hook_family ipv6; then
            release_firewall_lock
            log_error "Firewall" "Existing install bootstrap failed" \
                "fail-closed recovery unavailable"
            return 1
        fi

        release_firewall_lock

        if ! bootstrap_post_refresh; then
            log_error "Firewall" "Existing install bootstrap failed" \
                "unable to recover app cache"
            return 1
        fi

        CACHE_RECOVERY=1

        if ! acquire_firewall_lock; then
            log_error "Firewall" "Existing install bootstrap failed" \
                "firewall lock unavailable after cache recovery"
            return 1
        fi
    else
        log_info "Apps" "Cached app database valid" \
            "using previous boot snapshot"
    fi

    if ! bootstrap_main_chain_fail_closed_family ipv4 ||
       ! bootstrap_main_chain_fail_closed_family ipv6 ||
       ! bootstrap_output_hook_family ipv4 ||
       ! bootstrap_output_hook_family ipv6; then
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed" \
            "TIRNFW fail-closed state unavailable"
        return 1
    fi

    if [ ! -s "$STATE_FILE" ]; then
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed" \
            "persisted network.state missing or empty"
        return 1
    fi

    if ! recover_boot_policy_state; then
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed" \
            "policy recovery unavailable"
        return 1
    fi

    PREPARED_POLICY="$DATA_DIR/policy.prepared.bootstrap.$$"
    PREPARED_COUNT="$DATA_DIR/policy.count.bootstrap.$$"

    rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"

    if ! prepare_applied_policy_for_boot \
        "$PREPARED_POLICY" \
        "$PREPARED_COUNT"; then
        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed" \
            "last-known-good policy unavailable"
        return 1
    fi

    # iptables state does not survive reboot. Recreate the split policy
    # pointer families before constructing the first boot generation.
    if ! policy_pointer_verify_complete; then
        policy_pointer_delete_family ipv4 >/dev/null 2>&1 || true
        policy_pointer_delete_family ipv6 >/dev/null 2>&1 || true

        if ! policy_pointer_create_family ipv4 ||
           ! policy_pointer_create_family ipv6 ||
           ! policy_pointer_family_exists ipv4 ||
           ! policy_pointer_family_exists ipv6; then
            rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
            release_firewall_lock
            log_error "Firewall" "Existing install bootstrap failed" \
                "policy pointer family unavailable"
            return 1
        fi
    fi

    # Build the first split policy generation from persisted policy.applied.
    if ! policy_generation_transaction "$PREPARED_POLICY"; then
        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed" \
            "initial split policy generation failed"
        return 1
    fi

    # Build the first split network generation from persisted network.state.
    # Do not replace it with an early-boot network probe.
    if ! network_generation_transaction "$STATE_FILE"; then
        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed" \
            "initial split network generation failed"
        return 1
    fi

    rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"

    ACTIVE_POLICY_GEN="$(policy_pointer_active_generation_complete 2>/dev/null || true)"
    ACTIVE_NETWORK_GEN="$(network_active_generation_complete 2>/dev/null || true)"

    if [ -z "$ACTIVE_POLICY_GEN" ] ||
       [ -z "$ACTIVE_NETWORK_GEN" ] ||
       ! policy_pointer_verify_complete ||
       ! policy_generation_verify_complete "$ACTIVE_POLICY_GEN" ||
       ! network_generation_verify_complete "$ACTIVE_NETWORK_GEN"; then
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed" \
            "initial split firewall verification failed"
        return 1
    fi

    log_info "Firewall" "Initial split firewall verified" \
        "policy=$ACTIVE_POLICY_GEN network=$ACTIVE_NETWORK_GEN"

    release_firewall_lock

    log_info "Firewall" "Existing install bootstrap completed" \
        "split firewall activated from persisted state"

    # A recovered cache has already performed the required full refresh.
    # Otherwise wait for a usable current network topology before performing
    # the normal post-bootstrap full app refresh.
    if [ "$CACHE_RECOVERY" -eq 0 ]; then
        NETWORK_READY=0
        NETWORK_WAIT_STATE="$DATA_DIR/network.state.bootwait.$$"
        rm -f "$NETWORK_WAIT_STATE"

        NETWORK_WAIT=0
        NETWORK_WAIT_MAX=120

        while [ "$NETWORK_WAIT" -lt "$NETWORK_WAIT_MAX" ]; do
            if build_network_state > "$NETWORK_WAIT_STATE" &&
               [ -s "$NETWORK_WAIT_STATE" ]; then
                NETWORK_READY=1
                break
            fi

            sleep 2
            NETWORK_WAIT=$((NETWORK_WAIT + 2))
        done

        if [ "$NETWORK_READY" -ne 1 ]; then
            rm -f "$NETWORK_WAIT_STATE"
            log_warn "Network" "Post-bootstrap reconciliation deferred" \
                "current network topology unavailable"
            return 0
        fi

        rm -f "$NETWORK_WAIT_STATE"

        if ! bootstrap_post_refresh; then
            log_error "Apps" "Post-bootstrap refresh failed" \
                "existing verified split firewall retained"
            return 0
        fi
    fi

    # Network reconciliation is independent of application refresh.
    # apply_dispatcher compares the current effective topology with the
    # persisted state and creates a new generation only when it differs.
    if ! apply_dispatcher; then
        log_error "Network" "Post-bootstrap reconciliation failed" \
            "existing verified split firewall retained"
    fi

    return 0
}

bootstrap_fresh_install() {
    if ! acquire_firewall_lock; then
        log_error "Firewall" "Bootstrap failed" "firewall lock unavailable"
        return 1
    fi

    if ! refresh_apps_verified "bootstrap"; then
        release_firewall_lock
        log_error "Firewall" "Bootstrap failed" "app cache unavailable"
        return 1
    fi

    # Establish only the TIRN-owned main chains. Existing chains are never flushed.
    if ! bootstrap_main_chain_fail_closed_family ipv4; then
        release_firewall_lock
        log_error "Firewall" "Bootstrap failed" "IPv4 TIRNFW state invalid"
        return 1
    fi

    if ! bootstrap_main_chain_fail_closed_family ipv6; then
        release_firewall_lock
        log_error "Firewall" "Bootstrap failed" "IPv6 TIRNFW state invalid"
        return 1
    fi

    if ! bootstrap_output_hook_family ipv4; then
        release_firewall_lock
        log_error "Firewall" "Bootstrap failed" "IPv4 OUTPUT hook unavailable"
        return 1
    fi

    if ! bootstrap_output_hook_family ipv6; then
        release_firewall_lock
        log_error "Firewall" "Bootstrap failed" "IPv6 OUTPUT hook unavailable"
        return 1
    fi

    PREPARED_POLICY="$DATA_DIR/policy.prepared.bootstrap.$$"
    PREPARED_COUNT="$DATA_DIR/policy.count.bootstrap.$$"

    rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"

    if ! prepare_policy "$PREPARED_POLICY" "$PREPARED_COUNT"; then
        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Bootstrap failed" "policy preparation failed"
        return 1
    fi

    # Fresh install has no previous policy or network generation. Build the
    # policy pointer family first, then create the first policy generation.
    if ! policy_pointer_verify_complete; then
        policy_pointer_delete_family ipv4 >/dev/null 2>&1 || true
        policy_pointer_delete_family ipv6 >/dev/null 2>&1 || true

        if ! policy_pointer_create_family ipv4 ||
           ! policy_pointer_create_family ipv6 ||
           ! policy_pointer_family_exists ipv4 ||
           ! policy_pointer_family_exists ipv6; then
            rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
            release_firewall_lock
            log_error "Firewall" \
                "Bootstrap failed" \
                "policy pointer family creation failed"
            return 1
        fi
    fi

    if ! policy_generation_transaction "$PREPARED_POLICY"; then
        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Bootstrap failed" \
            "initial policy generation transaction failed"
        return 1
    fi

    # Network state is deliberately obtained after the policy layer exists.
    # The first network generation is built from the actual current topology.
    TMP_STATE="$DATA_DIR/network.state.bootstrap.$$"
    rm -f "$TMP_STATE"

    if ! build_network_state > "$TMP_STATE" || [ ! -s "$TMP_STATE" ]; then
        rm -f "$TMP_STATE" "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Bootstrap failed" \
            "initial network state unavailable"
        return 1
    fi

    if ! network_generation_transaction "$TMP_STATE"; then
        rm -f "$TMP_STATE" "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Bootstrap failed" \
            "initial network generation transaction failed"
        return 1
    fi

    rm -f "$TMP_STATE"

    rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"

    release_firewall_lock

    log_info "Firewall" "Bootstrap completed" \
        "initial split policy/network generations activated"
    return 0
}

normalize_ipv6_64() {
    ADDR="$1"

    ADDR="${ADDR%%/*}"

    echo "$ADDR" | awk -F: '
    {
        left=$0
        right=""

        if (index($0,"::") > 0) {
            split($0,a,"::")
            left=a[1]
            right=a[2]

            ln=0
            rn=0

            if (left != "")
                ln=split(left,l,":")

            if (right != "")
                rn=split(right,r,":")

            missing=8-ln-rn
            n=0

            for (i=1;i<=ln;i++) {
                if (n < 4) {
                    if (l[i] == "") l[i]="0"
                    printf "%s%s", l[i], (n < 3 ? ":" : "")
                    n++
                }
            }

            while (n < 4 && missing > 0) {
                printf "%s%s", "0", (n < 3 ? ":" : "")
                n++
                missing--
            }

            for (i=1;i<=rn && n<4;i++) {
                printf "%s%s", r[i], (n < 3 ? ":" : "")
                n++
            }

            print "::/64"
        } else {
            split($0,h,":")
            printf "%s:%s:%s:%s::/64\n", h[1],h[2],h[3],h[4]
        }
    }'
}

build_network_state() {
    {
        WLAN_UP=$("$IP" -o link show up 2>/dev/null | awk -F': ' '$2=="wlan0" {print "yes"}')

        if [ "$WLAN_UP" = "yes" ]; then
            WLAN4_FOUND=$("$IP" -4 route show dev wlan0 proto kernel scope link 2>/dev/null |
                awk '$1 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/ {print $1; exit}')

            if [ -n "$WLAN4_FOUND" ]; then
                printf 'WLAN4|%s\n' "$WLAN4_FOUND"
            else
                "$IP" -4 -o addr show dev wlan0 scope global 2>/dev/null |
                    awk '
                    function network(ip, prefix,    a,n,b,mask,i,out) {
                        split(ip,a,".")
                        n=prefix
                        out=""

                        for (i=1;i<=4;i++) {
                            if (n >= 8) {
                                b=a[i]
                                n-=8
                            } else if (n > 0) {
                                mask=256-(2^(8-n))
                                b=int(a[i]/mask)*mask
                                n=0
                            } else {
                                b=0
                            }

                            out=out (i > 1 ? "." : "") b
                        }

                        return out "/" prefix
                    }

                    $4 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\/[0-9]+$/ {
                        split($4,a,"/")
                        print "WLAN4|" network(a[1],a[2])
                        exit
                    }'
            fi

            "$IP" -6 -o addr show dev wlan0 scope global 2>/dev/null |
                awk '{print $4}' |
                while read -r ADDR; do
                    case "$ADDR" in
                        */64)
                            PREFIX=$(normalize_ipv6_64 "$ADDR")
                            [ -n "$PREFIX" ] && printf 'WLAN6|%s\n' "$PREFIX"
                            ;;
                    esac
                done
        fi

        "$IP" -o link show up 2>/dev/null |
            awk -F': ' '$2 ~ /^rmnet[0-9]+$/ {print "MOBILE|" $2}'

        /system/bin/dumpsys connectivity 2>/dev/null |
            awk '
            /NetworkAgentInfo\{network\{/ {
                id=""
                iface=""
                underlying=""
                isvpn=0

                if (match($0,/network\{[0-9]+\}/)) {
                    x=substr($0,RSTART,RLENGTH)
                    sub(/^network\{/,"",x)
                    sub(/\}$/,"",x)
                    id=x
                }

                if (match($0,/InterfaceName: [^ ]+/)) {
                    x=substr($0,RSTART,RLENGTH)
                    sub(/^InterfaceName: /,"",x)
                    iface=x
                }

                if ($0 ~ /ni\{VPN CONNECTED/) {
                    isvpn=1
                }

                if (match($0,/underlying\{\[[^]]*\]\}/)) {
                    x=substr($0,RSTART,RLENGTH)
                    sub(/^underlying\{\[/,"",x)
                    sub(/\]\}$/,"",x)
                    underlying=x
                } else if (match($0,/UnderlyingNetworks: \[[^]]*\]/)) {
                    x=substr($0,RSTART,RLENGTH)
                    sub(/^UnderlyingNetworks: \[/,"",x)
                    sub(/\]$/,"",x)
                    underlying=x
                }

                if (id != "" && iface != "")
                    netiface[id]=iface

                if (isvpn && id != "" && iface != "" && underlying != "")
                    vpn[id]=iface "|" underlying
            }

            END {
                for (v in vpn) {
                    split(vpn[v],a,"|")
                    split(a[2],u,",")
                    for (i in u) {
                        if (u[i] in netiface)
                            printf "VPN|%s|%s\n",a[1],netiface[u[i]]
                    }
                }
            }'
    } | sort -u
}


next_split_generation_id() {
    MAX_GENERATION=0

    for IPT in "$IPTABLES" "$IP6TABLES"; do
        for CHAIN in $(
            "$IPT" -w 5 -S 2>/dev/null |
            sed -n \
                -e 's/^-N TIRNFW-G\([0-9][0-9]*\)$/\1/p' \
                -e 's/^-N TIRNFW-G\([0-9][0-9]*\)-[MWL]$/\1/p' \
                -e 's/^-N TIRNFW-NET-G\([0-9][0-9]*\)$/\1/p'
        ); do
            case "$CHAIN" in
                ''|*[!0-9]*) ;;
                *)
                    if [ "$CHAIN" -gt "$MAX_GENERATION" ] 2>/dev/null; then
                        MAX_GENERATION="$CHAIN"
                    fi
                    ;;
            esac
        done
    done

    printf '%s\n' "$((MAX_GENERATION + 1))"
}

policy_generation_create_family() {
    GEN="$1"
    FAMILY="$2"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    MOB="$(policy_mobile_chain "$GEN")"
    WIFI="$(policy_wifi_chain "$GEN")"
    LAN="$(policy_lan_chain "$GEN")"

    generation_chain_exists "$IPT" "$MOB" && return 1
    generation_chain_exists "$IPT" "$WIFI" && return 1
    generation_chain_exists "$IPT" "$LAN" && return 1

    "$IPT" -w 5 -N "$MOB" || return 1

    if ! "$IPT" -w 5 -N "$WIFI"; then
        "$IPT" -w 5 -X "$MOB" >/dev/null 2>&1 || true
        return 1
    fi

    if ! "$IPT" -w 5 -N "$LAN"; then
        "$IPT" -w 5 -X "$WIFI" >/dev/null 2>&1 || true
        "$IPT" -w 5 -X "$MOB" >/dev/null 2>&1 || true
        return 1
    fi

    return 0
}

policy_generation_delete_family() {
    GEN="$1"
    FAMILY="$2"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    MOB="$(policy_mobile_chain "$GEN")"
    WIFI="$(policy_wifi_chain "$GEN")"
    LAN="$(policy_lan_chain "$GEN")"

    for CHAIN in "$MOB" "$WIFI" "$LAN"; do
        if generation_chain_exists "$IPT" "$CHAIN"; then
            "$IPT" -w 5 -F "$CHAIN" || return 1
            "$IPT" -w 5 -X "$CHAIN" || return 1
        fi
    done

    return 0
}

policy_generation_cleanup_new() {
    GEN="$1"
    CLEANUP_FAILED=0

    if ! policy_generation_delete_family "$GEN" ipv4 >/dev/null 2>&1; then
        log_warn "Firewall" "New IPv4 policy generation cleanup failed" \
            "generation=$GEN"
        CLEANUP_FAILED=1
    fi

    if ! policy_generation_delete_family "$GEN" ipv6 >/dev/null 2>&1; then
        log_warn "Firewall" "New IPv6 policy generation cleanup failed" \
            "generation=$GEN"
        CLEANUP_FAILED=1
    fi

    return "$CLEANUP_FAILED"
}

policy_generation_populate_family() {
    GEN="$1"
    FAMILY="$2"
    PREPARED_POLICY="$3"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    MOB="$(policy_mobile_chain "$GEN")"
    WIFI="$(policy_wifi_chain "$GEN")"
    LAN="$(policy_lan_chain "$GEN")"

    "$IPT" -w 5 -A "$MOB" -j RETURN || return 1
    "$IPT" -w 5 -A "$WIFI" -j RETURN || return 1
    "$IPT" -w 5 -A "$LAN" -j RETURN || return 1

    while IFS='|' read -r USER PACKAGE UID NETWORK ACTION; do
        case "$NETWORK" in
            MOBILE) TARGET="$MOB" ;;
            WIFI) TARGET="$WIFI" ;;
            LAN) TARGET="$LAN" ;;
            *) return 1 ;;
        esac

        case "$ACTION" in
            BLOCK)
                "$IPT" -w 5 -I "$TARGET" 1 \
                    -m owner --uid-owner "$UID" -j DROP || return 1
                ;;
            *)
                return 1
                ;;
        esac
    done < "$PREPARED_POLICY"

    return 0
}

policy_generation_verify_family() {
    GEN="$1"
    FAMILY="$2"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    MOB="$(policy_mobile_chain "$GEN")"
    WIFI="$(policy_wifi_chain "$GEN")"
    LAN="$(policy_lan_chain "$GEN")"

    for CHAIN in "$MOB" "$WIFI" "$LAN"; do
        RULES="$("$IPT" -w 5 -S "$CHAIN" 2>/dev/null)" || return 1

        RETURN_COUNT=0
        LAST_RULE=""

        while IFS= read -r RULE; do
            [ -n "$RULE" ] || continue

            case "$RULE" in
                "-N $CHAIN")
                    continue
                    ;;
                "-A $CHAIN -m owner --uid-owner "[0-9]*" -j DROP")
                    ;;
                "-A $CHAIN -j RETURN")
                    RETURN_COUNT=$((RETURN_COUNT + 1))
                    ;;
                *)
                    return 1
                    ;;
            esac

            LAST_RULE="$RULE"
        done <<EOF
$RULES
EOF

        [ "$RETURN_COUNT" -eq 1 ] || return 1
        [ "$LAST_RULE" = "-A $CHAIN -j RETURN" ] || return 1
    done

    return 0
}

policy_generation_verify_complete() {
    GEN="$1"

    policy_generation_verify_family "$GEN" ipv4 || return 1
    policy_generation_verify_family "$GEN" ipv6 || return 1

    return 0
}


generation_verify_stable_dispatcher_family() {
    GEN="$1"
    FAMILY="$2"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    EXPECTED="$(generation_dispatcher_chain "$GEN")"
    RULES="$("$IPT" -w 5 -S "$MAIN_CHAIN" 2>/dev/null)" || return 1

    GENERATION_COUNT=0
    GENERATION_TARGET=""
    RETURN_COUNT=0
    GUARD_COUNT=0
    GENERATION_POSITION=0
    RETURN_POSITION=0
    POSITION=0

    while IFS= read -r RULE; do
        [ -n "$RULE" ] || continue

        case "$RULE" in
            "-N $MAIN_CHAIN")
                continue
                ;;
        esac

        POSITION=$((POSITION + 1))

        case "$RULE" in
            "-A $MAIN_CHAIN -j $GENERATION_GUARD_CHAIN")
                GUARD_COUNT=$((GUARD_COUNT + 1))
                ;;
            "-A $MAIN_CHAIN -j $EXPECTED")
                GENERATION_COUNT=$((GENERATION_COUNT + 1))
                GENERATION_TARGET="$EXPECTED"
                GENERATION_POSITION="$POSITION"
                ;;
            "-A $MAIN_CHAIN -j RETURN")
                RETURN_COUNT=$((RETURN_COUNT + 1))
                RETURN_POSITION="$POSITION"
                ;;
            *)
                return 1
                ;;
        esac
    done <<EOF
$RULES
EOF

    if [ "$GENERATION_COUNT" -ne 1 ]; then
        debug_log "Firewall" "stable dispatcher generation count failed" "count=$GENERATION_COUNT expected=$EXPECTED rules=$RULES"
        return 1
    fi

    if [ "$GENERATION_TARGET" != "$EXPECTED" ]; then
        debug_log "Firewall" "stable dispatcher target failed" "target=$GENERATION_TARGET expected=$EXPECTED rules=$RULES"
        return 1
    fi

    if [ "$RETURN_COUNT" -ne 1 ]; then
        debug_log "Firewall" "stable dispatcher return count failed" "count=$RETURN_COUNT rules=$RULES"
        return 1
    fi

    if [ "$GUARD_COUNT" -gt 1 ]; then
        debug_log "Firewall" "stable dispatcher guard count failed" "count=$GUARD_COUNT rules=$RULES"
        return 1
    fi

    if [ "$RETURN_POSITION" -ne "$POSITION" ]; then
        debug_log "Firewall" "stable dispatcher return position failed" "return=$RETURN_POSITION last=$POSITION rules=$RULES"
        return 1
    fi

    if [ "$GUARD_COUNT" -eq 1 ]; then
        if [ "$GENERATION_POSITION" -ne 1 ]; then
            debug_log "Firewall" "stable dispatcher generation position failed with guard" "position=$GENERATION_POSITION rules=$RULES"
            return 1
        fi
    else
        if [ "$GENERATION_POSITION" -ne 1 ]; then
            debug_log "Firewall" "stable dispatcher generation position failed without guard" "position=$GENERATION_POSITION rules=$RULES"
            return 1
        fi
    fi

    return 0
}

policy_pointer_active_generation() {
    FAMILY="$1"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    MOB="$(policy_mobile_pointer_chain)"
    WIFI="$(policy_wifi_pointer_chain)"
    LAN="$(policy_lan_pointer_chain)"

    RULES_M="$("$IPT" -w 5 -S "$MOB" 2>/dev/null)" || return 1
    RULES_W="$("$IPT" -w 5 -S "$WIFI" 2>/dev/null)" || return 1
    RULES_L="$("$IPT" -w 5 -S "$LAN" 2>/dev/null)" || return 1

    TARGET_M="$(printf '%s\n' "$RULES_M" |
        sed -n 's/^-A TIRNFW-POLICY-M -j \(TIRNFW-G[0-9][0-9]*-M\)$/\1/p')"
    TARGET_W="$(printf '%s\n' "$RULES_W" |
        sed -n 's/^-A TIRNFW-POLICY-W -j \(TIRNFW-G[0-9][0-9]*-W\)$/\1/p')"
    TARGET_L="$(printf '%s\n' "$RULES_L" |
        sed -n 's/^-A TIRNFW-POLICY-L -j \(TIRNFW-G[0-9][0-9]*-L\)$/\1/p')"

    [ -n "$TARGET_M" ] || return 1
    [ -n "$TARGET_W" ] || return 1
    [ -n "$TARGET_L" ] || return 1

    GEN_M="${TARGET_M#TIRNFW-G}"
    GEN_M="${GEN_M%-M}"

    GEN_W="${TARGET_W#TIRNFW-G}"
    GEN_W="${GEN_W%-W}"

    GEN_L="${TARGET_L#TIRNFW-G}"
    GEN_L="${GEN_L%-L}"

    case "$GEN_M" in ''|*[!0-9]*) return 1 ;; esac
    case "$GEN_W" in ''|*[!0-9]*) return 1 ;; esac
    case "$GEN_L" in ''|*[!0-9]*) return 1 ;; esac

    [ "$GEN_M" = "$GEN_W" ] || return 1
    [ "$GEN_M" = "$GEN_L" ] || return 1

    printf '%s\n' "$GEN_M"
}

policy_pointer_activate_family() {
    FAMILY="$1"
    GEN="$2"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    case "$GEN" in
        ''|*[!0-9]*) return 1 ;;
    esac

    MOB="$(policy_mobile_pointer_chain)"
    WIFI="$(policy_wifi_pointer_chain)"
    LAN="$(policy_lan_pointer_chain)"

    TARGET_M="$(policy_mobile_chain "$GEN")"
    TARGET_W="$(policy_wifi_chain "$GEN")"
    TARGET_L="$(policy_lan_chain "$GEN")"

    generation_chain_exists "$IPT" "$TARGET_M" || return 1
    generation_chain_exists "$IPT" "$TARGET_W" || return 1
    generation_chain_exists "$IPT" "$TARGET_L" || return 1

    policy_pointer_chain_exists "$IPT" "$MOB" || return 1
    policy_pointer_chain_exists "$IPT" "$WIFI" || return 1
    policy_pointer_chain_exists "$IPT" "$LAN" || return 1

    "$IPT" -w 5 -F "$MOB" || return 1
    "$IPT" -w 5 -F "$WIFI" || return 1
    "$IPT" -w 5 -F "$LAN" || return 1

    "$IPT" -w 5 -A "$MOB" -j "$TARGET_M" || return 1
    "$IPT" -w 5 -A "$MOB" -j RETURN || return 1

    "$IPT" -w 5 -A "$WIFI" -j "$TARGET_W" || return 1
    "$IPT" -w 5 -A "$WIFI" -j RETURN || return 1

    "$IPT" -w 5 -A "$LAN" -j "$TARGET_L" || return 1
    "$IPT" -w 5 -A "$LAN" -j RETURN || return 1

    policy_pointer_verify_family "$FAMILY"
}

policy_pointer_restore_family() {
    FAMILY="$1"
    GEN="$2"

    [ -n "$GEN" ] || return 1
    policy_pointer_activate_family "$FAMILY" "$GEN"
}

policy_pointer_verify_complete() {
    policy_pointer_verify_family ipv4 || return 1
    policy_pointer_verify_family ipv6 || return 1
    return 0
}

policy_pointer_active_generation_complete() {
    OLD4="$(policy_pointer_active_generation ipv4)" || return 1
    OLD6="$(policy_pointer_active_generation ipv6)" || return 1

    [ "$OLD4" = "$OLD6" ] || return 1

    printf '%s\n' "$OLD4"
}


policy_state_transaction_commit() {
    SOURCE="$1"

    [ -f "$SOURCE" ] || return 1

    POLICY_STATE_TMP="$DATA_DIR/policy.applied.transaction.tmp.$$"

    if ! cp -f "$SOURCE" "$POLICY_STATE_TMP"; then
        rm -f "$POLICY_STATE_TMP"
        return 1
    fi

    if ! chmod 600 "$POLICY_STATE_TMP"; then
        rm -f "$POLICY_STATE_TMP"
        return 1
    fi

    if ! mv -f "$POLICY_STATE_TMP" "$POLICY_STATE_FILE"; then
        rm -f "$POLICY_STATE_TMP"
        return 1
    fi

    cmp -s "$SOURCE" "$POLICY_STATE_FILE"
}

policy_generation_transaction() {
    PREPARED_POLICY="$1"

    [ -f "$PREPARED_POLICY" ] || return 1

    POINTERS_EXIST=1
    if ! policy_pointer_verify_complete; then
        POINTERS_EXIST=0
        log_info "Firewall" "Creating initial policy pointer family" ""
        policy_pointer_delete_family ipv4 >/dev/null 2>&1 || true
        policy_pointer_delete_family ipv6 >/dev/null 2>&1 || true

        if ! policy_pointer_create_family ipv4 ||
           ! policy_pointer_create_family ipv6 ||
           ! policy_pointer_family_exists ipv4 ||
           ! policy_pointer_family_exists ipv6; then
            log_error "Firewall" \
                "Initial policy pointer family creation failed" ""
            return 1
        fi
    fi

    OLD_GEN=""
    if [ "$POINTERS_EXIST" -eq 1 ]; then
        OLD_GEN="$(policy_pointer_active_generation_complete 2>/dev/null || true)"
        if [ -n "$OLD_GEN" ]; then
            log_info "Firewall" "Policy generation transaction started" \
                "generation source=$OLD_GEN"
        else
            log_info "Firewall" "Policy generation transaction started" \
                "no previous generation"
        fi
    fi

    NEW_GEN="$(next_split_generation_id)" || return 1

    policy_generation_cleanup_new "$NEW_GEN" >/dev/null 2>&1 || true

    log_info "Firewall" "Policy generation build started" \
        "generation=$NEW_GEN old=${OLD_GEN:-none}"

    if ! policy_generation_create_family "$NEW_GEN" ipv4 ||
       ! policy_generation_create_family "$NEW_GEN" ipv6 ||
       ! policy_generation_populate_family "$NEW_GEN" ipv4 "$PREPARED_POLICY" ||
       ! policy_generation_populate_family "$NEW_GEN" ipv6 "$PREPARED_POLICY" ||
       ! policy_generation_verify_complete "$NEW_GEN"; then

        log_error "Firewall" "Policy generation build failed" \
            "generation=$NEW_GEN"

        policy_generation_cleanup_new "$NEW_GEN" >/dev/null 2>&1 || true
        return 1
    fi

    log_info "Firewall" "Policy generation verified off-path" \
        "generation=$NEW_GEN"

    if ! generation_guard_install ||
       ! generation_guard_verify; then

        log_error "Firewall" \
            "Policy transaction guard installation failed" \
            "generation=$NEW_GEN"

        if generation_guard_verify; then
            log_warn "Firewall" "Fail-closed guard retained" \
                "generation=$NEW_GEN"
        else
            policy_generation_cleanup_new "$NEW_GEN" >/dev/null 2>&1 || true
        fi

        return 1
    fi

    if ! policy_pointer_activate_family ipv4 "$NEW_GEN" ||
       ! policy_pointer_activate_family ipv6 "$NEW_GEN" ||
       ! policy_pointer_verify_complete ||
       ! policy_generation_verify_complete "$NEW_GEN"; then

        log_error "Firewall" \
            "Policy pointer activation or verification failed; rollback required" \
            "generation=$NEW_GEN old=${OLD_GEN:-none}"

        if [ -n "$OLD_GEN" ]; then
            ROLLBACK_OK=1

            policy_pointer_restore_family ipv4 "$OLD_GEN" || ROLLBACK_OK=0
            policy_pointer_restore_family ipv6 "$OLD_GEN" || ROLLBACK_OK=0
            policy_pointer_verify_complete || ROLLBACK_OK=0

            if [ "$ROLLBACK_OK" -ne 1 ]; then
                log_error "Firewall" \
                    "Policy pointer rollback verification failed" \
                    "generation=$NEW_GEN old=$OLD_GEN"
                return 1
            fi
        fi

        if [ -n "$OLD_GEN" ]; then
            if ! generation_guard_remove; then
                log_error "Firewall" \
                    "Guard removal after policy rollback failed" \
                    "generation=$NEW_GEN old=$OLD_GEN"
                return 1
            fi
        else
            if ! generation_guard_verify; then
                log_error "Firewall" \
                    "No previous policy generation; fail-closed guard verification failed" \
                    "generation=$NEW_GEN"
                return 1
            fi

            log_warn "Firewall" \
                "No previous policy generation; fail-closed guard retained" \
                "generation=$NEW_GEN"
        fi

        policy_generation_cleanup_new "$NEW_GEN" >/dev/null 2>&1 || true

        log_warn "Firewall" "Policy generation rollback verified" \
            "generation=$NEW_GEN old=${OLD_GEN:-none}"

        return 1
    fi

    # Persistence is part of the transaction boundary. The old generation
    # must remain available until policy.applied has been committed.
    if [ "${TIRN_DEV_MODE:-0}" -eq 1 ] &&
       [ "${TIRN_TEST_FAIL_POLICY_STATE_COMMIT:-0}" -eq 1 ]; then

        log_error "Firewall" "TEST FAULT" \
            "forcing policy.applied commit failure"

        POLICY_STATE_TEST_FAIL=1
    else
        POLICY_STATE_TEST_FAIL=0
    fi

    POLICY_STATE_ROLLBACK_TMP="$DATA_DIR/policy.applied.rollback.$$"

    cleanup_policy_state_rollback_tmp() {
        rm -f "$POLICY_STATE_ROLLBACK_TMP"
    }

    if ! cp -f "$POLICY_STATE_FILE" "$POLICY_STATE_ROLLBACK_TMP"; then
        log_error "Firewall" \
            "policy.applied rollback backup creation failed" \
            "generation=$NEW_GEN"
        return 1
    fi

    if [ "$POLICY_STATE_TEST_FAIL" -eq 1 ] ||
       ! policy_state_transaction_commit "$PREPARED_POLICY"; then

        log_error "Firewall" \
            "policy.applied commit failed; restoring previous policy" \
            "generation=$NEW_GEN old=${OLD_GEN:-none}"

        if [ -n "$OLD_GEN" ]; then
            ROLLBACK_OK=1

            policy_pointer_restore_family ipv4 "$OLD_GEN" || ROLLBACK_OK=0
            policy_pointer_restore_family ipv6 "$OLD_GEN" || ROLLBACK_OK=0
            policy_pointer_verify_complete || ROLLBACK_OK=0

            if [ "$ROLLBACK_OK" -ne 1 ]; then
                log_error "Firewall" \
                    "Policy rollback after persistence failure failed" \
                    "generation=$NEW_GEN old=$OLD_GEN"
                return 1
            fi
        fi

        if [ -n "$OLD_GEN" ]; then
            generation_guard_remove || true
            policy_generation_cleanup_new "$NEW_GEN" >/dev/null 2>&1 || true
        fi

        return 1
    fi

    if [ "${TIRN_DEV_MODE:-0}" -eq 1 ] &&
       [ "${TIRN_TEST_FAIL_POLICY_STATE_VERIFY:-0}" -eq 1 ]; then

        log_error "Firewall" "TEST FAULT" \
            "forcing policy.applied verification failure"

        POLICY_STATE_VERIFY_TEST_FAIL=1
    else
        POLICY_STATE_VERIFY_TEST_FAIL=0
    fi

    if [ "$POLICY_STATE_VERIFY_TEST_FAIL" -eq 1 ] ||
       ! cmp -s "$PREPARED_POLICY" "$POLICY_STATE_FILE"; then
        log_error "Firewall" \
            "policy.applied verification failed after commit" \
            "generation=$NEW_GEN"

        if [ -f "$POLICY_STATE_ROLLBACK_TMP" ]; then
            if ! cp -f "$POLICY_STATE_ROLLBACK_TMP" "$POLICY_STATE_FILE"; then
                log_error "Firewall" \
                    "policy.applied rollback restore failed" \
                    "generation=$NEW_GEN"
                return 1
            fi
        fi

        if [ -n "$OLD_GEN" ]; then
            ROLLBACK_OK=1

            policy_pointer_restore_family ipv4 "$OLD_GEN" || ROLLBACK_OK=0
            policy_pointer_restore_family ipv6 "$OLD_GEN" || ROLLBACK_OK=0
            policy_pointer_verify_complete || ROLLBACK_OK=0

            if [ "$ROLLBACK_OK" -ne 1 ]; then
                log_error "Firewall" \
                    "Policy rollback after persistence verification failure failed" \
                    "generation=$NEW_GEN old=$OLD_GEN"
                return 1
            fi

            generation_guard_remove || true
            policy_generation_cleanup_new "$NEW_GEN" >/dev/null 2>&1 || true
        fi

        return 1
    fi

    if ! policy_pointer_verify_complete ||
       ! policy_generation_verify_complete "$NEW_GEN"; then

        log_error "Firewall" \
            "Policy verification failed before guard removal" \
            "generation=$NEW_GEN"

        return 1
    fi

    OLD_CLEANUP_OK=1

    if [ -n "$OLD_GEN" ]; then
        if ! policy_generation_delete_family "$OLD_GEN" ipv4; then
            OLD_CLEANUP_OK=0
            log_warn "Firewall" \
                "Old IPv4 policy generation cleanup deferred" \
                "generation=$OLD_GEN active=$NEW_GEN"
        fi

        if ! policy_generation_delete_family "$OLD_GEN" ipv6; then
            OLD_CLEANUP_OK=0
            log_warn "Firewall" \
                "Old IPv6 policy generation cleanup deferred" \
                "generation=$OLD_GEN active=$NEW_GEN"
        fi
    fi

    if ! policy_pointer_verify_complete ||
       ! policy_generation_verify_complete "$NEW_GEN"; then

        log_error "Firewall" \
            "Final policy verification failed; fail-closed guard retained" \
            "generation=$NEW_GEN"

        return 1
    fi

    if ! generation_guard_remove; then
        log_error "Firewall" \
            "Policy transaction guard removal failed" \
            "generation=$NEW_GEN"

        if generation_guard_verify; then
            log_warn "Firewall" "Fail-closed guard retained" \
                "generation=$NEW_GEN"
        fi

        return 1
    fi

    if [ "$OLD_CLEANUP_OK" -eq 1 ]; then
        log_info "Firewall" "Policy generation activated" \
            "generation=$NEW_GEN old=${OLD_GEN:-none}"
    else
        log_warn "Firewall" \
            "Policy generation activated with old cleanup deferred" \
            "generation=$NEW_GEN old=$OLD_GEN"
    fi

    cleanup_policy_state_rollback_tmp
    return 0
}

network_generation_transaction() {
    NETWORK_STATE="$1"

    [ -f "$NETWORK_STATE" ] || return 1

    # A network transaction may be the first firewall generation after boot.
    # Policy pointers are required as construction targets, but an existing
    # network generation is not required.
    policy_pointer_verify_complete || {
        log_error "Firewall" \
            "Policy pointer family invalid before network transaction" ""
        return 1
    }

    if [ ! -s "$NETWORK_STATE" ]; then
        log_error "Firewall" \
            "Network transaction rejected empty network state" ""
        return 1
    fi

    OLD_GEN="$(network_active_generation_complete 2>/dev/null || true)"

    NEW_GEN="$(next_split_generation_id)" || return 1

    log_info "Firewall" "Network generation build started" \
        "generation=$NEW_GEN old=${OLD_GEN:-none}"

    network_generation_cleanup_new "$NEW_GEN" >/dev/null 2>&1 || true

    if ! network_generation_create_family "$NEW_GEN" ipv4 ||
       ! network_generation_create_family "$NEW_GEN" ipv6 ||
       ! network_generation_populate_family "$NEW_GEN" ipv4 "$NETWORK_STATE" ||
       ! network_generation_populate_family "$NEW_GEN" ipv6 "$NETWORK_STATE" ||
       ! network_generation_verify_complete "$NEW_GEN"; then

        log_error "Firewall" "Network generation build failed" \
            "generation=$NEW_GEN"

        network_generation_cleanup_new "$NEW_GEN" >/dev/null 2>&1 || true
        return 1
    fi

    log_info "Firewall" "Network generation verified off-path" \
        "generation=$NEW_GEN"

    NETWORK_TIMING_START=$(date +%s)

    if ! generation_guard_install ||
       ! generation_guard_verify; then

        log_error "Firewall" \
            "Network transaction guard installation failed" \
            "generation=$NEW_GEN"

        if generation_guard_verify; then
            log_warn "Firewall" "Fail-closed guard retained" \
                "generation=$NEW_GEN"
        else
            network_generation_cleanup_new "$NEW_GEN" >/dev/null 2>&1 || true
        fi

        return 1
    fi

    NETWORK_TIMING_GUARD=$(( $(date +%s) - NETWORK_TIMING_START ))
    debug_log "Firewall" "Network activation timing" \
        "stage=guard-installed seconds=$NETWORK_TIMING_GUARD generation=$NEW_GEN"

    NETWORK_SWITCHED=0

    if network_generation_install_active_ipv4 "$NEW_GEN" &&
       network_generation_install_active_ipv6 "$NEW_GEN" &&
       network_generation_active_rule_ipv4 "$NEW_GEN" &&
       network_generation_active_rule_ipv6 "$NEW_GEN"; then
        NETWORK_SWITCHED=1
    fi

    NETWORK_TIMING_ACTIVATE=$(( $(date +%s) - NETWORK_TIMING_START ))
    debug_log "Firewall" "Network activation timing" \
        "stage=activation-complete seconds=$NETWORK_TIMING_ACTIVATE generation=$NEW_GEN"

    if [ "$NETWORK_SWITCHED" -ne 1 ]; then
        log_error "Firewall" \
            "Network generation activation failed; beginning rollback" \
            "generation=$NEW_GEN old=${OLD_GEN:-none}"

        ROLLBACK_OK=1

        network_generation_remove_active_ipv4 "$NEW_GEN" >/dev/null 2>&1 || true
        network_generation_remove_active_ipv6 "$NEW_GEN" >/dev/null 2>&1 || true

        network_generation_active_rule_ipv4 "$NEW_GEN" && ROLLBACK_OK=0
        network_generation_active_rule_ipv6 "$NEW_GEN" && ROLLBACK_OK=0

        if [ -n "$OLD_GEN" ]; then
            if ! network_generation_active_rule_ipv4 "$OLD_GEN"; then
                network_generation_install_active_ipv4 "$OLD_GEN" || ROLLBACK_OK=0
            fi

            if ! network_generation_active_rule_ipv6 "$OLD_GEN"; then
                network_generation_install_active_ipv6 "$OLD_GEN" || ROLLBACK_OK=0
            fi

            network_generation_active_rule_ipv4 "$OLD_GEN" || ROLLBACK_OK=0
            network_generation_active_rule_ipv6 "$OLD_GEN" || ROLLBACK_OK=0
        fi

        if [ "$ROLLBACK_OK" -ne 1 ]; then
            log_error "Firewall" \
                "Network generation rollback verification failed" \
                "generation=$NEW_GEN old=${OLD_GEN:-none}"
            return 1
        fi

        if [ -n "$OLD_GEN" ]; then
            if ! generation_guard_remove; then
                log_error "Firewall" \
                    "Guard removal after network rollback failed" \
                    "generation=$NEW_GEN old=$OLD_GEN"
                return 1
            fi
        else
            if ! generation_guard_verify; then
                log_error "Firewall" \
                    "No previous network generation; fail-closed guard verification failed" \
                    "generation=$NEW_GEN"
                return 1
            fi

            log_warn "Firewall" \
                "No previous network generation; fail-closed guard retained" \
                "generation=$NEW_GEN"
        fi

        network_generation_cleanup_new "$NEW_GEN" >/dev/null 2>&1 || true

        log_warn "Firewall" "Network generation rollback verified" \
            "generation=$NEW_GEN old=${OLD_GEN:-none}"

        return 1
    fi

    if ! network_generation_verify_complete "$NEW_GEN" ||
       ! network_generation_active_rule_ipv4 "$NEW_GEN" ||
       ! network_generation_active_rule_ipv6 "$NEW_GEN"; then

        log_error "Firewall" \
            "New network generation verification failed after activation" \
            "generation=$NEW_GEN old=${OLD_GEN:-none}"

        if [ -n "$OLD_GEN" ]; then
            network_generation_remove_active_ipv4 "$NEW_GEN" >/dev/null 2>&1 || true
            network_generation_remove_active_ipv6 "$NEW_GEN" >/dev/null 2>&1 || true

            network_generation_install_active_ipv4 "$OLD_GEN" || true
            network_generation_install_active_ipv6 "$OLD_GEN" || true

            if network_generation_active_rule_ipv4 "$OLD_GEN" &&
               network_generation_active_rule_ipv6 "$OLD_GEN"; then
                generation_guard_remove || true
                network_generation_cleanup_new "$NEW_GEN" >/dev/null 2>&1 || true
                return 1
            fi
        fi

        return 1
    fi

    NETWORK_TIMING_POST_ACTIVATION_VERIFY=$(( $(date +%s) - NETWORK_TIMING_START ))
    debug_log "Firewall" "Network activation timing" \
        "stage=post-activation-verify seconds=$NETWORK_TIMING_POST_ACTIVATION_VERIFY generation=$NEW_GEN"

    # Commit the authoritative network state while OLD is still available.
    # This is the persistence boundary: before this succeeds OLD remains a
    # valid rollback target; after it succeeds the new firewall generation
    # and persisted network.state describe the same topology.
    NETWORK_STATE_TMP="$STATE_FILE.transaction.tmp.$$"

    if ! cp -f "$NETWORK_STATE" "$NETWORK_STATE_TMP" ||
       ! chmod 600 "$NETWORK_STATE_TMP" ||
       ! mv -f "$NETWORK_STATE_TMP" "$STATE_FILE" ||
       ! cmp -s "$NETWORK_STATE" "$STATE_FILE"; then

        rm -f "$NETWORK_STATE_TMP"

        log_error "Firewall" \
            "Network state commit failed; beginning rollback" \
            "generation=$NEW_GEN old=${OLD_GEN:-none}"

        network_generation_remove_active_ipv4 "$NEW_GEN" >/dev/null 2>&1 || true
        network_generation_remove_active_ipv6 "$NEW_GEN" >/dev/null 2>&1 || true

        if [ -n "$OLD_GEN" ]; then
            network_generation_install_active_ipv4 "$OLD_GEN" || true
            network_generation_install_active_ipv6 "$OLD_GEN" || true

            if network_generation_active_rule_ipv4 "$OLD_GEN" &&
               network_generation_active_rule_ipv6 "$OLD_GEN"; then
                generation_guard_remove || true
                network_generation_cleanup_new "$NEW_GEN" >/dev/null 2>&1 || true
                return 1
            fi
        fi

        log_error "Firewall" \
            "Network state rollback failed" \
            "generation=$NEW_GEN old=${OLD_GEN:-none}"
        return 1
    fi

    NETWORK_TIMING_PERSISTENCE=$(( $(date +%s) - NETWORK_TIMING_START ))
    debug_log "Firewall" "Network activation timing" \
        "stage=persistence-complete seconds=$NETWORK_TIMING_PERSISTENCE generation=$NEW_GEN"

    if [ -n "$OLD_GEN" ]; then
        if ! network_generation_remove_active_ipv4 "$OLD_GEN"; then
            log_error "Firewall" \
                "Old IPv4 network generation removal failed after persistence" \
                "generation=$NEW_GEN old=$OLD_GEN"
            return 1
        fi

        if ! network_generation_remove_active_ipv6 "$OLD_GEN"; then
            log_error "Firewall" \
                "Old IPv6 network generation removal failed after persistence" \
                "generation=$NEW_GEN old=$OLD_GEN"
            return 1
        fi

        if network_generation_active_rule_ipv4 "$OLD_GEN" ||
           network_generation_active_rule_ipv6 "$OLD_GEN"; then
            log_error "Firewall" \
                "Old network generation remains active after removal" \
                "generation=$NEW_GEN old=$OLD_GEN"
            return 1
        fi
    fi

    NETWORK_TIMING_OLD_REMOVAL=$(( $(date +%s) - NETWORK_TIMING_START ))
    debug_log "Firewall" "Network activation timing" \
        "stage=old-generation-removal-complete seconds=$NETWORK_TIMING_OLD_REMOVAL generation=$NEW_GEN"

    if ! network_generation_verify_complete "$NEW_GEN" ||
       ! network_generation_active_rule_ipv4 "$NEW_GEN" ||
       ! network_generation_active_rule_ipv6 "$NEW_GEN" ||
       [ "$(network_active_generation_complete)" != "$NEW_GEN" ]; then

        log_error "Firewall" \
            "Post-switch network verification failed" \
            "generation=$NEW_GEN"
        return 1
    fi

    NETWORK_TIMING_POST_SWITCH_VERIFY=$(( $(date +%s) - NETWORK_TIMING_START ))
    debug_log "Firewall" "Network activation timing" \
        "stage=post-switch-verify seconds=$NETWORK_TIMING_POST_SWITCH_VERIFY generation=$NEW_GEN"

    if [ -n "$OLD_GEN" ]; then
        if ! network_generation_delete_family "$OLD_GEN" ipv4 ||
           ! network_generation_delete_family "$OLD_GEN" ipv6; then
            log_warn "Firewall" \
                "Old network generation cleanup deferred" \
                "generation=$OLD_GEN active=$NEW_GEN"
        fi
    fi

    NETWORK_TIMING_CLEANUP=$(( $(date +%s) - NETWORK_TIMING_START ))
    debug_log "Firewall" "Network activation timing" \
        "stage=old-generation-cleanup-complete seconds=$NETWORK_TIMING_CLEANUP generation=$NEW_GEN"

    if ! network_generation_verify_complete "$NEW_GEN" ||
       ! network_generation_active_rule_ipv4 "$NEW_GEN" ||
       ! network_generation_active_rule_ipv6 "$NEW_GEN" ||
       [ "$(network_active_generation_complete)" != "$NEW_GEN" ]; then

        log_error "Firewall" \
            "Final network transaction verification failed; fail-closed guard retained" \
            "generation=$NEW_GEN"
        return 1
    fi

    NETWORK_TIMING_FINAL_VERIFY=$(( $(date +%s) - NETWORK_TIMING_START ))
    debug_log "Firewall" "Network activation timing" \
        "stage=final-verify seconds=$NETWORK_TIMING_FINAL_VERIFY generation=$NEW_GEN"

    NETWORK_TIMING_GUARD_REMOVE_START=$(date +%s)

    if ! generation_guard_remove; then
        log_error "Firewall" \
            "Network transaction guard removal failed" \
            "generation=$NEW_GEN"

        if generation_guard_verify; then
            log_warn "Firewall" "Fail-closed guard retained" \
                "generation=$NEW_GEN"
        fi

        return 1
    fi


    NETWORK_TIMING_GUARD_REMOVE=$(( $(date +%s) - NETWORK_TIMING_GUARD_REMOVE_START ))
    NETWORK_TIMING_TOTAL=$(( $(date +%s) - NETWORK_TIMING_START ))

    debug_log "Firewall" "Network activation timing" \
        "stage=guard-removed seconds=$NETWORK_TIMING_GUARD_REMOVE generation=$NEW_GEN"

    debug_log "Firewall" "Network activation timing" \
        "stage=total seconds=$NETWORK_TIMING_TOTAL generation=$NEW_GEN"

    log_info "Firewall" "Network generation activated" \
        "generation=$NEW_GEN old=${OLD_GEN:-none}"

    return 0
}


apply_dispatcher() {
    TMP_STATE="$DATA_DIR/network.state.tmp.$$"
    CURRENT_STATE="$DATA_DIR/network.state.current.$$"

    if ! acquire_firewall_lock; then
        log_error "Network" "Dispatcher update failed" \
            "firewall lock unavailable"
        return 1
    fi

    if ! build_network_state > "$CURRENT_STATE"; then
        rm -f "$TMP_STATE" "$CURRENT_STATE"
        release_firewall_lock
        log_error "Network" "State build failed"
        return 1
    fi

    if [ ! -s "$CURRENT_STATE" ]; then
        rm -f "$TMP_STATE" "$CURRENT_STATE"
        release_firewall_lock
        log_warn "Network" "Dispatcher update skipped" \
            "current network state empty"
        return 1
    fi

    if [ -f "$STATE_FILE" ] && [ -s "$STATE_FILE" ]; then
        awk -F'|' '
        NR == FNR {
            if ($1 == "MOBILE") {
                old_mobile[$2] = 1
            } else if ($1 == "WLAN4") {
                old_wlan4[$2] = 1
            } else if ($1 == "WLAN6") {
                old_wlan6[$2] = 1
            }
            next
        }

        {
            if ($1 == "MOBILE") {
                current_mobile[$2] = 1
            } else if ($1 == "WLAN4") {
                current_wlan4[$2] = 1
            } else if ($1 == "WLAN6") {
                current_wlan6[$2] = 1
            } else if ($1 == "VPN") {
                vpn[$0] = 1
            }
        }

        END {
            for (v in old_mobile)
                mobile[v] = 1
            for (v in current_mobile)
                mobile[v] = 1

            if (length(current_wlan4)) {
                for (v in current_wlan4)
                    wlan4[v] = 1
            } else {
                for (v in old_wlan4)
                    wlan4[v] = 1
            }

            if (length(current_wlan6)) {
                for (v in current_wlan6)
                    wlan6[v] = 1
            } else {
                for (v in old_wlan6)
                    wlan6[v] = 1
            }

            for (v in mobile)
                print "MOBILE|" v
            for (v in wlan4)
                print "WLAN4|" v
            for (v in wlan6)
                print "WLAN6|" v
            for (v in vpn)
                print v
        }' "$STATE_FILE" "$CURRENT_STATE" | sort -u > "$TMP_STATE"
    else
        cp -f "$CURRENT_STATE" "$TMP_STATE"
    fi

    if [ ! -s "$TMP_STATE" ]; then
        rm -f "$TMP_STATE" "$CURRENT_STATE"
        release_firewall_lock
        log_warn "Network" "Dispatcher update skipped" \
            "effective network state empty"
        return 1
    fi

    if [ -f "$STATE_FILE" ] && cmp -s "$TMP_STATE" "$STATE_FILE"; then
        rm -f "$TMP_STATE" "$CURRENT_STATE"
        release_firewall_lock
        return 0
    fi

    if network_generation_transaction "$TMP_STATE"; then
        rm -f "$TMP_STATE" "$CURRENT_STATE"

        release_firewall_lock

        log_info "Network" "Dispatcher updated" \
            "network generation transaction completed"
        return 0
    fi

    rm -f "$TMP_STATE" "$CURRENT_STATE"
    release_firewall_lock

    log_error "Network" "Dispatcher update failed" \
        "existing generation retained"
    return 1
}

apply_policy() {
    PREPARED_POLICY="$DATA_DIR/policy.prepared.$$"
    PREPARED_COUNT="$DATA_DIR/policy.count.$$"

    if ! acquire_firewall_lock; then
        log_error "Policy" "Apply failed" \
            "firewall lock unavailable"
        return 1
    fi

    if ! prepare_policy "$PREPARED_POLICY" "$PREPARED_COUNT"; then
        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        return 1
    fi

    if [ -f "$POLICY_STATE_FILE" ] &&
       cmp -s "$PREPARED_POLICY" "$POLICY_STATE_FILE"; then
        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_info "Policy" "No change" \
            "prepared policy matches policy.applied; firewall generation retained"
        return 0
    fi

    if policy_generation_transaction "$PREPARED_POLICY"; then

        APPLIED_COUNT="$(wc -l < "$POLICY_STATE_FILE" 2>/dev/null)"
        APPLIED_COUNT="$(printf '%s' "$APPLIED_COUNT" | tr -d ' ')"

        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock

        log_info "Policy" "Applied" "$APPLIED_COUNT rules"
        return 0
    fi

    rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
    release_firewall_lock

    log_error "Policy" "Apply failed" \
        "existing policy generation retained"
    return 1
}

import_policy_transaction() (
    IMPORT_CONTEXT="${1:-import}"
    REMOVE_USER="${2:-}"
    REMOVE_PACKAGE="${3:-}"

    case "$IMPORT_CONTEXT" in
        stale)
            IMPORT_LABEL="Stale reconciliation"
            ;;
        import)
            IMPORT_LABEL="Policy import"
            ;;
        remove)
            IMPORT_LABEL="Policy removal"
            ;;
        *)
            log_error "Policy" "Import transaction failed" \
                "invalid transaction context=$IMPORT_CONTEXT"
            exit 1
            ;;
    esac

    CANDIDATE_POLICY="$DATA_DIR/policy.import.$$"
    PREPARED_POLICY="$DATA_DIR/policy.import.prepared.$$"
    PREPARED_COUNT="$DATA_DIR/policy.import.count.$$"
    REMOVED_COUNT_FILE="$DATA_DIR/policy.remove.count.$$"

    TMP_POLICY="$DATA_DIR/policy.conf.import.$$"
    BACKUP_POLICY="$DATA_DIR/policy.conf.import.backup.$$"

    IMPORT_MARKER="$DATA_DIR/policy.importing"

    IMPORT_POLICY_LOCK=0
    IMPORT_FIREWALL_LOCK=0
    IMPORT_COMMIT_OK=0
    IMPORT_ROLLBACK_OK=0
    IMPORT_REMOVED_COUNT=0
    IMPORT_POLICY_EXISTED=0

    cleanup_import() {
        rm -f \
            "$CANDIDATE_POLICY" \
            "$PREPARED_POLICY" \
            "$PREPARED_COUNT" \
            "$REMOVED_COUNT_FILE" \
            "$TMP_POLICY"

        if [ "$IMPORT_COMMIT_OK" -eq 1 ] ||
           [ "$IMPORT_ROLLBACK_OK" -eq 1 ]; then
            rm -f \
                "$BACKUP_POLICY" \
                "$IMPORT_MARKER"
        fi

        if [ "$IMPORT_FIREWALL_LOCK" -eq 1 ]; then
            release_firewall_lock
            IMPORT_FIREWALL_LOCK=0
        fi

        if [ "$IMPORT_POLICY_LOCK" -eq 1 ]; then
            release_policy_lock
            IMPORT_POLICY_LOCK=0
        fi
    }

    trap cleanup_import EXIT HUP INT TERM

    if [ "$IMPORT_CONTEXT" != "remove" ]; then
        if ! cat > "$CANDIDATE_POLICY"; then
            log_error "Policy" "$IMPORT_LABEL failed" \
                "unable to read candidate policy"
            exit 1
        fi

        if ! chmod 600 "$CANDIDATE_POLICY"; then
            log_error "Policy" "$IMPORT_LABEL failed" \
                "unable to set candidate permissions"
            exit 1
        fi
    fi

    if ! acquire_policy_lock; then
        log_error "Policy" "$IMPORT_LABEL failed" \
            "policy lock unavailable"
        exit 1
    fi
    IMPORT_POLICY_LOCK=1

    if ! acquire_firewall_lock; then
        log_error "Policy" "$IMPORT_LABEL failed" \
            "firewall lock unavailable"
        exit 1
    fi
    IMPORT_FIREWALL_LOCK=1

    if ! : > "$IMPORT_MARKER"; then
        log_error "Policy" "$IMPORT_LABEL failed" \
            "unable to create transaction marker"
        exit 1
    fi
    chmod 600 "$IMPORT_MARKER" || exit 1

    if [ -e "$POLICY_FILE" ]; then
        IMPORT_POLICY_EXISTED=1

        if ! cp -f "$POLICY_FILE" "$BACKUP_POLICY"; then
            log_error "Policy" "$IMPORT_LABEL failed" \
                "unable to back up policy.conf"
            exit 1
        fi

        if ! chmod 600 "$BACKUP_POLICY"; then
            log_error "Policy" "$IMPORT_LABEL failed" \
                "unable to set policy backup permissions"
            exit 1
        fi
    fi

    if [ "$IMPORT_CONTEXT" = "remove" ]; then
        if ! prepare_existing_policy_for_removal \
            "$PREPARED_POLICY" \
            "$PREPARED_COUNT" \
            "$POLICY_FILE" \
            "$REMOVE_USER" \
            "$REMOVE_PACKAGE" \
            "$REMOVED_COUNT_FILE"; then
            log_error "Policy" "$IMPORT_LABEL failed" \
                "existing policy removal preparation failed"
            exit 1
        fi

        IMPORT_REMOVED_COUNT="$(cat "$REMOVED_COUNT_FILE" 2>/dev/null)"

        case "$IMPORT_REMOVED_COUNT" in
            ''|*[!0-9]*)
                log_error "Policy" "$IMPORT_LABEL failed" \
                    "invalid removal count"
                exit 1
                ;;
        esac

        if [ "$IMPORT_REMOVED_COUNT" -eq 0 ]; then
            log_info "Policy" "App removal" \
                "user=$REMOVE_USER package=$REMOVE_PACKAGE status=NO_RULES"
            IMPORT_COMMIT_OK=1
            exit 0
        fi
    else
        if ! prepare_policy \
            "$PREPARED_POLICY" \
            "$PREPARED_COUNT" \
            "$CANDIDATE_POLICY"; then
            log_error "Policy" "$IMPORT_LABEL failed" \
                "policy preparation failed"
            exit 1
        fi
    fi

    if ! cp -f "$PREPARED_POLICY" "$TMP_POLICY"; then
        log_error "Policy" "$IMPORT_LABEL failed" \
            "unable to prepare policy.conf replacement"
        exit 1
    fi

    if ! chmod 600 "$TMP_POLICY"; then
        log_error "Policy" "$IMPORT_LABEL failed" \
            "unable to set policy.conf replacement permissions"
        exit 1
    fi

    if [ "${TIRN_DEV_MODE:-0}" -eq 1 ] &&
       [ "${TIRN_TEST_FAIL_POLICY_COMMIT:-0}" -eq 1 ]; then
        log_error "Policy" "TEST FAULT" \
            "forcing policy.conf commit failure"
        exit 1
    fi

    if ! mv -f "$TMP_POLICY" "$POLICY_FILE"; then
        log_error "Policy" "$IMPORT_LABEL failed" \
            "policy.conf commit failed"
        exit 1
    fi

    if ! cmp -s "$POLICY_FILE" "$PREPARED_POLICY"; then
        log_error "Policy" "$IMPORT_LABEL failed" \
            "policy.conf verification failed before firewall transaction"
        exit 1
    fi

    if ! policy_generation_transaction "$PREPARED_POLICY"; then
        if [ -f "$POLICY_STATE_FILE" ] &&
           cmp -s "$POLICY_STATE_FILE" "$PREPARED_POLICY"; then

            log_warn "Policy" "$IMPORT_LABEL failed after policy state commit" \
                "policy.conf retained because policy.applied matches prepared policy"

            IMPORT_COMMIT_OK=1
            exit 1
        fi

        if [ "$IMPORT_POLICY_EXISTED" -eq 1 ]; then
            RESTORE_POLICY="$DATA_DIR/policy.conf.import.restore.$$"

            if ! cp -f "$BACKUP_POLICY" "$RESTORE_POLICY" ||
               ! chmod 600 "$RESTORE_POLICY" ||
               ! mv -f "$RESTORE_POLICY" "$POLICY_FILE"; then
                rm -f "$RESTORE_POLICY"
                log_error "Policy" "$IMPORT_LABEL rollback failed" \
                    "unable to restore policy.conf"
                exit 1
            fi
        else
            rm -f "$POLICY_FILE"
        fi

        if [ "$IMPORT_POLICY_EXISTED" -eq 1 ] &&
           ! cmp -s "$POLICY_FILE" "$BACKUP_POLICY"; then
            log_error "Policy" "$IMPORT_LABEL rollback failed" \
                "restored policy.conf verification failed"
            exit 1
        fi

        IMPORT_ROLLBACK_OK=1

        log_warn "Policy" "$IMPORT_LABEL rolled back" \
            "policy generation transaction failed before policy state commit"

        exit 1
    fi

    if ! cmp -s "$POLICY_FILE" "$PREPARED_POLICY" ||
       ! cmp -s "$POLICY_STATE_FILE" "$PREPARED_POLICY"; then

        log_error "Policy" "$IMPORT_LABEL failed" \
            "policy persistence verification failed after committed firewall transaction"

        if cmp -s "$POLICY_STATE_FILE" "$PREPARED_POLICY"; then
            log_error "Policy" "$IMPORT_LABEL failed" \
                "policy.applied committed but policy.conf diverged"
        else
            log_error "Policy" "$IMPORT_LABEL failed" \
                "policy.applied diverged after successful transaction"
        fi

        exit 1
    fi

    IMPORT_COMMIT_OK=1

    IMPORT_COUNT="$(wc -l < "$PREPARED_POLICY" 2>/dev/null)"
    IMPORT_COUNT="$(printf '%s' "$IMPORT_COUNT" | tr -d ' ')"

    if [ "$IMPORT_CONTEXT" = "remove" ]; then
        log_info "Policy" "App removal" \
            "user=$REMOVE_USER package=$REMOVE_PACKAGE rules=$IMPORT_REMOVED_COUNT status=REMOVED"
    else
        log_info "Policy" "$IMPORT_LABEL committed" \
            "rules=$IMPORT_COUNT exact replacement"
    fi

    exit 0
)


if [ "${1:-}" = "--import-policy" ]; then
    import_policy_transaction "import"
    exit $?
fi

if [ "${1:-}" = "--reconcile-stale-policy" ]; then
    import_policy_transaction "stale"
    exit $?
fi


if [ "${1:-}" = "--policy-event" ]; then
    apply_policy
    exit $?
fi

policy_has_app_rule() {
    CHECK_USER="$1"
    CHECK_PACKAGE="$2"

    awk -F'|' -v user="$CHECK_USER" -v package="$CHECK_PACKAGE" '
        $1 == user && $2 == package {
            found = 1
            exit
        }
        END {
            exit(found ? 0 : 1)
        }
    ' "$POLICY_FILE" 2>/dev/null
}

process_app_events() {
    APP_EVENT_DIR="$DATA_DIR/app-events"

    [ -d "$APP_EVENT_DIR" ] || return 0

    for EVENT_FILE in "$APP_EVENT_DIR"/*
    do
        [ -f "$EVENT_FILE" ] || continue

        EVENT_WORK="$APP_EVENT_DIR/.work.$$"

        if ! mv -f "$EVENT_FILE" "$EVENT_WORK" 2>/dev/null; then
            continue
        fi

        EVENT_DATA="$(cat "$EVENT_WORK" 2>/dev/null)"
        ACTION="$(printf '%s\n' "$EVENT_DATA" | awk -F'|' 'NR==1 {print $1}')"
        USER="$(printf '%s\n' "$EVENT_DATA" | awk -F'|' 'NR==1 {print $2}')"
        PACKAGE="$(printf '%s\n' "$EVENT_DATA" | awk -F'|' 'NR==1 {print $3}')"

        case "$ACTION" in
            ADDED|UPDATED|REMOVED)
                ;;
            *)
                rm -f "$EVENT_WORK"
                continue
                ;;
        esac

        case "$USER" in
            ''|*[!0-9]*)
                rm -f "$EVENT_WORK"
                continue
                ;;
        esac

        case "$PACKAGE" in
            ''|*[!A-Za-z0-9._-]*)
                rm -f "$EVENT_WORK"
                continue
                ;;
        esac

        log_info "App Event" "Received" \
            "action=$ACTION user=$USER package=$PACKAGE"

        case "$ACTION" in
            ADDED|UPDATED)
                if ! policy_has_app_rule "$USER" "$PACKAGE"; then
                    log_info "App Event" "No policy transaction required" \
                        "action=$ACTION user=$USER package=$PACKAGE status=NO_RULES"
                    rm -f "$EVENT_WORK"
                    continue
                fi

                if apply_policy; then
                    log_info "App Event" "Policy transaction completed" \
                        "action=$ACTION user=$USER package=$PACKAGE"
                else
                    log_error "App Event" "Policy transaction failed" \
                        "action=$ACTION user=$USER package=$PACKAGE"

                    if [ ! -e "$EVENT_FILE" ]; then
                        mv -f "$EVENT_WORK" "$EVENT_FILE" 2>/dev/null || {
                            log_error "App Event" "Event recovery failed" \
                                "action=$ACTION user=$USER package=$PACKAGE"
                            rm -f "$EVENT_WORK"
                        }
                    else
                        rm -f "$EVENT_WORK"
                    fi
                    continue
                fi
                ;;
            REMOVED)
                if import_policy_transaction "remove" "$USER" "$PACKAGE"; then
                    log_info "App Event" "Policy removal transaction completed" \
                        "action=$ACTION user=$USER package=$PACKAGE"
                else
                    log_error "App Event" "Policy removal transaction failed" \
                        "action=$ACTION user=$USER package=$PACKAGE"

                    if [ ! -e "$EVENT_FILE" ]; then
                        mv -f "$EVENT_WORK" "$EVENT_FILE" 2>/dev/null || {
                            log_error "App Event" "Event recovery failed" \
                                "action=$ACTION user=$USER package=$PACKAGE"
                            rm -f "$EVENT_WORK"
                        }
                    else
                        rm -f "$EVENT_WORK"
                    fi
                    continue
                fi
                ;;
        esac

        rm -f "$EVENT_WORK"
    done
}

log_info "Service" "Started" "module initialization"

clear_stale_boot_locks
recover_stale_app_events

if ! bootstrap_initialize; then
    log_error "Service" "Initialization failed" \
        "firewall remains fail-closed; see preceding transaction error"
    exit 1
fi

log_info "Service" "Ready" "transactional firewall active"

"$MODDIR/policy-watch.sh" "$POLICY_FILE:w" "$DATA_DIR:nm" >/dev/null 2>&1 &
POLICY_WATCH_PID=$!

trap 'rm -f "$NETWORK_EVENT_FILE" "$NETWORK_WATCH_FIFO" 2>/dev/null || true; kill "$NETWORK_WATCH_PID" "$POLICY_WATCH_PID" "$APP_WATCH_PID" 2>/dev/null || true; wait "$NETWORK_WATCH_PID" "$POLICY_WATCH_PID" "$APP_WATCH_PID" 2>/dev/null || true' EXIT INT TERM

rm -f "$NETWORK_EVENT_FILE" 2>/dev/null || true

start_app_watch
start_network_watch

while true; do
    WAITED=0

    while [ "$WAITED" -lt "$POLL_INTERVAL" ]; do
        if [ -f "$NETWORK_EVENT_FILE" ]; then
            sleep "$NETWORK_EVENT_SETTLE"

            if [ -f "$NETWORK_EVENT_FILE" ]; then
                rm -f "$NETWORK_EVENT_FILE" 2>/dev/null || true
                break
            fi
        fi

        sleep 1
        WAITED=$((WAITED + 1))
    done

    ensure_app_watch_running
    process_app_events
    apply_dispatcher
done
