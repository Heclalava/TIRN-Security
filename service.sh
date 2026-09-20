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

ipt() {
    "$IPTABLES" -w 5 "$@"
}

ip6t() {
    "$IP6TABLES" -w 5 "$@"
}

MAIN_CHAIN="TIRNFW"
MOBILE_CHAIN="TIRNFW-MOBILE"
WIFI_CHAIN="TIRNFW-WIFI"
LAN_CHAIN="TIRNFW-LAN"

POLL_INTERVAL=30

umask 077

mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR"

if [ "${1:-}" != "--policy-event" ] &&
   [ "${1:-}" != "--refresh" ] &&
   [ "${1:-}" != "--import-policy" ]; then
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

        OWNER="$LOCK/owner"

        if [ -r "$OWNER" ]; then
            read -r PID < "$OWNER"

            if [ -n "$PID" ] && kill -0 "$PID" 2>/dev/null; then
                log_warn "Lock" "Active lock preserved" "lock=$LOCK pid=$PID"
                continue
            fi
        fi

        rm -rf "$LOCK" 2>/dev/null || true
        log_warn "Lock" "Removed stale boot lock" "lock=$LOCK"
    done
}

GENERATION_GUARD_CHAIN="TIRNFW-GUARD"

generation_chain_exists() {
    "$1" -w 5 -L "$2" >/dev/null 2>&1
}

next_generation_id() {
    MAX_GENERATION=0

    for CHAIN in $(
        "$IPTABLES" -w 5 -S 2>/dev/null |
        sed -n 's/^-N TIRNFW-G\([0-9][0-9]*\)$/\1/p'
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

    for CHAIN in $(
        "$IP6TABLES" -w 5 -S 2>/dev/null |
        sed -n 's/^-N TIRNFW-G\([0-9][0-9]*\)$/\1/p'
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

    printf '%s\n' "$((MAX_GENERATION + 1))"
}

active_generation_ipv4() {
    "$IPTABLES" -w 5 -S "$MAIN_CHAIN" 2>/dev/null |
        sed -n 's/^-A TIRNFW -j \(TIRNFW-G[0-9][0-9]*\)$/\1/p' |
        head -n 1
}

active_generation_ipv6() {
    "$IP6TABLES" -w 5 -S "$MAIN_CHAIN" 2>/dev/null |
        sed -n 's/^-A TIRNFW -j \(TIRNFW-G[0-9][0-9]*\)$/\1/p' |
        head -n 1
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

generation_mobile_chain() {
    printf 'TIRNFW-G%s-M\n' "$1"
}

generation_wifi_chain() {
    printf 'TIRNFW-G%s-W\n' "$1"
}

generation_lan_chain() {
    printf 'TIRNFW-G%s-L\n' "$1"
}

generation_create_family() {
    GEN="$1"
    FAMILY="$2"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    DISP="$(generation_dispatcher_chain "$GEN")"
    MOB="$(generation_mobile_chain "$GEN")"
    WIFI="$(generation_wifi_chain "$GEN")"
    LAN="$(generation_lan_chain "$GEN")"

    generation_chain_exists "$IPT" "$DISP" && return 1
    generation_chain_exists "$IPT" "$MOB" && return 1
    generation_chain_exists "$IPT" "$WIFI" && return 1
    generation_chain_exists "$IPT" "$LAN" && return 1

    "$IPT" -w 5 -N "$DISP" || return 1
    "$IPT" -w 5 -N "$MOB" || {
        "$IPT" -w 5 -X "$DISP" >/dev/null 2>&1 || true
        return 1
    }
    "$IPT" -w 5 -N "$WIFI" || {
        "$IPT" -w 5 -X "$MOB" >/dev/null 2>&1 || true
        "$IPT" -w 5 -X "$DISP" >/dev/null 2>&1 || true
        return 1
    }
    "$IPT" -w 5 -N "$LAN" || {
        "$IPT" -w 5 -X "$WIFI" >/dev/null 2>&1 || true
        "$IPT" -w 5 -X "$MOB" >/dev/null 2>&1 || true
        "$IPT" -w 5 -X "$DISP" >/dev/null 2>&1 || true
        return 1
    }

    return 0
}

generation_delete_family() {
    GEN="$1"
    FAMILY="$2"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    DISP="$(generation_dispatcher_chain "$GEN")"
    MOB="$(generation_mobile_chain "$GEN")"
    WIFI="$(generation_wifi_chain "$GEN")"
    LAN="$(generation_lan_chain "$GEN")"

    if ! generation_chain_exists "$IPT" "$DISP" &&
       ! generation_chain_exists "$IPT" "$MOB" &&
       ! generation_chain_exists "$IPT" "$WIFI" &&
       ! generation_chain_exists "$IPT" "$LAN"; then
        return 0
    fi

    "$IPT" -w 5 -F "$MOB" || return 1
    "$IPT" -w 5 -F "$WIFI" || return 1
    "$IPT" -w 5 -F "$LAN" || return 1
    "$IPT" -w 5 -F "$DISP" || return 1

    "$IPT" -w 5 -X "$MOB" || return 1
    "$IPT" -w 5 -X "$WIFI" || return 1
    "$IPT" -w 5 -X "$LAN" || return 1
    "$IPT" -w 5 -X "$DISP" || return 1

    return 0
}

generation_verify_family() {
    GEN="$1"
    FAMILY="$2"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    DISP="$(generation_dispatcher_chain "$GEN")"
    MOB="$(generation_mobile_chain "$GEN")"
    WIFI="$(generation_wifi_chain "$GEN")"
    LAN="$(generation_lan_chain "$GEN")"

    generation_chain_exists "$IPT" "$DISP" || return 1
    generation_chain_exists "$IPT" "$MOB" || return 1
    generation_chain_exists "$IPT" "$WIFI" || return 1
    generation_chain_exists "$IPT" "$LAN" || return 1

    DISP_RULES="$("$IPT" -w 5 -S "$DISP" 2>/dev/null)" || return 1
    MOB_RULES="$("$IPT" -w 5 -S "$MOB" 2>/dev/null)" || return 1
    WIFI_RULES="$("$IPT" -w 5 -S "$WIFI" 2>/dev/null)" || return 1
    LAN_RULES="$("$IPT" -w 5 -S "$LAN" 2>/dev/null)" || return 1


    # Every network policy chain must contain only TIRN-generated
    # owner DROP rules followed by exactly one final RETURN.
    for CHAIN in "$MOB" "$WIFI" "$LAN"; do
        case "$CHAIN" in
            "$MOB") CHAIN_RULES="$MOB_RULES" ;;
            "$WIFI") CHAIN_RULES="$WIFI_RULES" ;;
            "$LAN") CHAIN_RULES="$LAN_RULES" ;;
            *) return 1 ;;
        esac

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
$CHAIN_RULES
EOF

        [ "$RETURN_COUNT" -eq 1 ] || return 1
        [ "$LAST_RULE" = "-A $CHAIN -j RETURN" ] || return 1
    done

    # The generation dispatcher may contain only TIRN-owned
    # classification rules and one final RETURN.
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
            "-A $DISP -j RETURN")
                RETURN_COUNT=$((RETURN_COUNT + 1))
                ;;
            *)
                return 1
                ;;
        esac

        LAST_RULE="$RULE"
    done <<EOF
$DISP_RULES
EOF

    [ "$RETURN_COUNT" -eq 1 ] || return 1
    [ "$LAST_RULE" = "-A $DISP -j RETURN" ] || return 1

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

generation_guard_delete() {
    generation_guard_remove || return 1

    "$IPTABLES" -w 5 -F "$GENERATION_GUARD_CHAIN" || return 1
    "$IP6TABLES" -w 5 -F "$GENERATION_GUARD_CHAIN" || return 1

    "$IPTABLES" -w 5 -X "$GENERATION_GUARD_CHAIN" || return 1
    "$IP6TABLES" -w 5 -X "$GENERATION_GUARD_CHAIN" || return 1

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

generation_active_rule_ipv4() {
    GEN="$1"
    "$IPTABLES" -w 5 -C "$MAIN_CHAIN" -j "$GEN" >/dev/null 2>&1
}

generation_active_rule_ipv6() {
    GEN="$1"
    "$IP6TABLES" -w 5 -C "$MAIN_CHAIN" -j "$GEN" >/dev/null 2>&1
}

generation_install_active_ipv4() {
    GEN="$1"

    if ! "$IPTABLES" -w 5 -I "$MAIN_CHAIN" 1 -j "$GEN"; then
        debug_log "Firewall" "IPv4 activation command failed"             "main=$MAIN_CHAIN target=$GEN"
        "$IPTABLES" -w 5 -S "$MAIN_CHAIN" 2>&1 | while IFS= read -r LINE; do
            debug_log "Firewall" "IPv4 main chain state" "rule=$LINE"
        done
        "$IPTABLES" -w 5 -L "$GEN" >/dev/null 2>&1 ||             debug_log "Firewall" "IPv4 target chain missing" "target=$GEN"
        return 1
    fi

    return 0
}

generation_install_active_ipv6() {
    GEN="$1"

    if ! "$IP6TABLES" -w 5 -I "$MAIN_CHAIN" 1 -j "$GEN"; then
        debug_log "Firewall" "IPv6 activation command failed"             "main=$MAIN_CHAIN target=$GEN"
        "$IP6TABLES" -w 5 -S "$MAIN_CHAIN" 2>&1 | while IFS= read -r LINE; do
            debug_log "Firewall" "IPv6 main chain state" "rule=$LINE"
        done
        "$IP6TABLES" -w 5 -L "$GEN" >/dev/null 2>&1 ||             debug_log "Firewall" "IPv6 target chain missing" "target=$GEN"
        return 1
    fi

    return 0
}

generation_remove_active_ipv4() {
    GEN="$1"
    "$IPTABLES" -w 5 -D "$MAIN_CHAIN" -j "$GEN"
}

generation_remove_active_ipv6() {
    GEN="$1"
    "$IP6TABLES" -w 5 -D "$MAIN_CHAIN" -j "$GEN"
}

chain_exists() {
    "$1" -w 5 -L "$2" >/dev/null 2>&1
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
        "$IPT" -w 5 -A "$MAIN_CHAIN" -j DROP || return 1
        "$IPT" -w 5 -A "$MAIN_CHAIN" -j RETURN || return 1
        return 0
    fi

    RULES="$("$IPT" -w 5 -S "$MAIN_CHAIN" 2>/dev/null)" || return 1


    DROP_COUNT=0
    RETURN_COUNT=0
    OTHER_COUNT=0

    while IFS= read -r RULE; do
        [ -n "$RULE" ] || continue

        case "$RULE" in
            "-N $MAIN_CHAIN")
                continue
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

    # An existing generation or guard is not modified here.
    if generation_verify_stable_dispatcher_family \
        "$(
            "$IPT" -w 5 -S "$MAIN_CHAIN" 2>/dev/null |
                sed -n 's/^-A TIRNFW -j \(TIRNFW-G[0-9][0-9]*\)$/\1/p' |
                head -n 1
        )" "$FAMILY" 2>/dev/null; then
        return 0
    fi

    # A completely empty/legacy-unknown chain must never be converted
    # destructively. Only the exact two-rule fail-closed baseline is safe.
    [ "$DROP_COUNT" -eq 1 ] || return 1
    [ "$RETURN_COUNT" -eq 1 ] || return 1
    [ "$OTHER_COUNT" -eq 0 ] || return 1

    FIRST_RULE="$(printf '%s\n' "$RULES" | sed -n '2p')"
    SECOND_RULE="$(printf '%s\n' "$RULES" | sed -n '3p')"

    [ "$FIRST_RULE" = "-A $MAIN_CHAIN -j DROP" ] || return 1
    [ "$SECOND_RULE" = "-A $MAIN_CHAIN -j RETURN" ] || return 1

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

bootstrap_verify_existing_family() {
    FAMILY="$1"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    chain_exists "$IPT" "$MAIN_CHAIN" || return 1

    RULES="$("$IPT" -w 5 -S "$MAIN_CHAIN" 2>/dev/null)" || return 1

    GEN="$(
        printf '%s\n' "$RULES" |
            sed -n 's/^-A TIRNFW -j \(TIRNFW-G[0-9][0-9]*\)$/\1/p' |
            head -n 1
    )"

    [ -n "$GEN" ] || return 1

    generation_verify_family "$GEN" "$FAMILY" || return 1

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
                error = "unresolved app on line " line_no
                exit 2
            }

            if (app_uid[key] != uid) {
                error = "UID mismatch on line " line_no
                exit 2
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

    if [ "$MODE" = "bootstrap" ] || [ "$MODE" = "post-bootstrap" ]; then
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


bootstrap_existing_install() {
    CACHE_RECOVERY=0

    if ! acquire_firewall_lock; then
        log_error "Firewall" "Existing install bootstrap failed"             "firewall lock unavailable"
        return 1
    fi

    if ! validate_apps_cache; then
        log_warn "Apps" "Cached app database unavailable"             "entering fail-closed recovery"

        if ! bootstrap_main_chain_fail_closed_family ipv4; then
            release_firewall_lock
            log_error "Firewall" "Existing install bootstrap failed"                 "IPv4 fail-closed recovery unavailable"
            return 1
        fi

        if ! bootstrap_main_chain_fail_closed_family ipv6; then
            release_firewall_lock
            log_error "Firewall" "Existing install bootstrap failed"                 "IPv6 fail-closed recovery unavailable"
            return 1
        fi

        if ! bootstrap_output_hook_family ipv4; then
            release_firewall_lock
            log_error "Firewall" "Existing install bootstrap failed"                 "IPv4 fail-closed OUTPUT hook unavailable"
            return 1
        fi

        if ! bootstrap_output_hook_family ipv6; then
            release_firewall_lock
            log_error "Firewall" "Existing install bootstrap failed"                 "IPv6 fail-closed OUTPUT hook unavailable"
            return 1
        fi

        release_firewall_lock

        if ! bootstrap_post_refresh; then
            log_error "Firewall" "Existing install bootstrap failed"                 "unable to recover app cache"
            return 1
        fi

        CACHE_RECOVERY=1

        if ! acquire_firewall_lock; then
            log_error "Firewall" "Existing install bootstrap failed"                 "firewall lock unavailable after cache recovery"
            return 1
        fi
    else
        log_info "Apps" "Cached app database valid"             "using previous boot snapshot"
    fi

    if [ "$CACHE_RECOVERY" -eq 0 ] && ! bootstrap_main_chain_fail_closed_family ipv4; then
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed"             "IPv4 TIRNFW state invalid"
        return 1
    fi

    if [ "$CACHE_RECOVERY" -eq 0 ] && ! bootstrap_main_chain_fail_closed_family ipv6; then
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed"             "IPv6 TIRNFW state invalid"
        return 1
    fi

    if [ "$CACHE_RECOVERY" -eq 0 ] && ! bootstrap_output_hook_family ipv4; then
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed"             "IPv4 OUTPUT hook unavailable"
        return 1
    fi

    if [ "$CACHE_RECOVERY" -eq 0 ] && ! bootstrap_output_hook_family ipv6; then
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed"             "IPv6 OUTPUT hook unavailable"
        return 1
    fi

    TMP_STATE="$DATA_DIR/network.state.bootstrap.$$"
    PREPARED_POLICY="$DATA_DIR/policy.prepared.bootstrap.$$"
    PREPARED_COUNT="$DATA_DIR/policy.count.bootstrap.$$"

    rm -f "$TMP_STATE" "$PREPARED_POLICY" "$PREPARED_COUNT"

    if ! build_network_state > "$TMP_STATE"; then
        rm -f "$TMP_STATE" "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed"             "network state build failed"
        return 1
    fi

    if ! prepare_policy "$PREPARED_POLICY" "$PREPARED_COUNT"; then
        rm -f "$TMP_STATE" "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed"             "policy preparation failed"
        return 1
    fi

    if ! generation_switch_transaction "$TMP_STATE" "$PREPARED_POLICY"; then
        rm -f "$TMP_STATE" "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed"             "generation transaction aborted; rollback completed or fail-closed retained"
        return 1
    fi

    if ! mv -f "$TMP_STATE" "$STATE_FILE"; then
        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed" \
            "network state commit failed"
        return 1
    fi

    if ! cp -f "$PREPARED_POLICY" "$POLICY_STATE_FILE"; then
        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed" \
            "applied policy commit failed"
        return 1
    fi

    if ! chmod 600 "$POLICY_STATE_FILE"; then
        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Existing install bootstrap failed" \
            "applied policy permissions failed"
        return 1
    fi

    rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"

    release_firewall_lock

    log_info "Firewall" "Existing install bootstrap completed"         "verified generation activated"

    if [ "$CACHE_RECOVERY" -eq 0 ] && bootstrap_post_refresh; then
        if apply_policy; then
            log_info "Firewall" "Post-bootstrap refresh applied"                 "new application state activated"
        else
            log_error "Firewall" "Post-bootstrap refresh failed"                 "existing verified generation retained"
        fi
    elif [ "$CACHE_RECOVERY" -eq 0 ]; then
        log_error "Apps" "Post-bootstrap refresh failed"             "existing verified generation retained"
    fi

    return 0
}

refresh_apps_bootstrap()
{
    refresh_apps_verified "bootstrap"
}

bootstrap_initialize() {
    if [ -f "$POLICY_STATE_FILE" ] &&
       [ -f "$STATE_FILE" ]; then
        bootstrap_existing_install
    else
        bootstrap_fresh_install
    fi
}

bootstrap_fresh_install() {
    if ! acquire_firewall_lock; then
        log_error "Firewall" "Bootstrap failed" "firewall lock unavailable"
        return 1
    fi

    if ! refresh_apps_bootstrap; then
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

    # Once the TIRNFW hooks exist, the chains are fail-closed until a
    # verified generation is activated.
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

    TMP_STATE="$DATA_DIR/network.state.bootstrap.$$"
    PREPARED_POLICY="$DATA_DIR/policy.prepared.bootstrap.$$"
    PREPARED_COUNT="$DATA_DIR/policy.count.bootstrap.$$"

    rm -f "$TMP_STATE" "$PREPARED_POLICY" "$PREPARED_COUNT"

    if ! build_network_state > "$TMP_STATE"; then
        rm -f "$TMP_STATE" "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Bootstrap failed" "network state build failed"
        return 1
    fi

    if ! prepare_policy "$PREPARED_POLICY" "$PREPARED_COUNT"; then
        rm -f "$TMP_STATE" "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Bootstrap failed" "policy preparation failed"
        return 1
    fi

    if ! generation_switch_transaction "$TMP_STATE" "$PREPARED_POLICY"; then
        rm -f "$TMP_STATE" "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Bootstrap failed" \
            "generation transaction aborted; fail-closed state retained"
        return 1
    fi

    if ! mv -f "$TMP_STATE" "$STATE_FILE"; then
        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Bootstrap failed" \
            "unable to commit network state; verified firewall remains active"
        return 1
    fi

    if ! cp -f "$PREPARED_POLICY" "$POLICY_STATE_FILE"; then
        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Bootstrap failed" \
            "unable to commit applied policy; verified firewall remains active"
        return 1
    fi

    if ! chmod 600 "$POLICY_STATE_FILE"; then
        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Firewall" "Bootstrap failed" \
            "unable to secure policy.applied permissions; verified firewall remains active"
        return 1
    fi

    rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"

    release_firewall_lock

    log_info "Firewall" "Bootstrap completed" "verified generation activated"
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

generation_populate_family() {
    GEN="$1"
    FAMILY="$2"
    PREPARED_POLICY="$3"
    NETWORK_STATE="$4"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    MOB="$(generation_mobile_chain "$GEN")"
    WIFI="$(generation_wifi_chain "$GEN")"
    LAN="$(generation_lan_chain "$GEN")"
    DISP="$(generation_dispatcher_chain "$GEN")"

    "$IPT" -w 5 -A "$MOB" -j RETURN || return 1
    "$IPT" -w 5 -A "$WIFI" -j RETURN || return 1
    "$IPT" -w 5 -A "$LAN" -j RETURN || return 1

    while IFS='|' read -r TYPE VALUE EXTRA; do
        case "$TYPE" in
            MOBILE)
                [ -n "$VALUE" ] || continue
                "$IPT" -w 5 -A "$DISP" -o "$VALUE" -j "$MOB" || return 1
                ;;

            WLAN4)
                [ "$FAMILY" = "ipv4" ] || continue
                [ -n "$VALUE" ] || continue
                "$IPT" -w 5 -A "$DISP" -d "$VALUE" -o wlan0 -j "$LAN" || return 1
                "$IPT" -w 5 -A "$DISP" -d "$VALUE" -o wlan0 -j RETURN || return 1
                ;;

            WLAN6)
                [ "$FAMILY" = "ipv6" ] || continue
                [ -n "$VALUE" ] || continue
                "$IPT" -w 5 -A "$DISP" -d "$VALUE" -o wlan0 -j "$LAN" || return 1
                "$IPT" -w 5 -A "$DISP" -d "$VALUE" -o wlan0 -j RETURN || return 1
                ;;
        esac
    done < "$NETWORK_STATE"

    if [ "$FAMILY" = "ipv4" ]; then
        if grep -q '^WLAN4|' "$NETWORK_STATE"; then
            "$IPT" -w 5 -A "$DISP" -o wlan0 -j "$WIFI" || return 1
        fi
    else
        if grep -q '^WLAN6|' "$NETWORK_STATE"; then
            "$IPT" -w 5 -A "$DISP" -o wlan0 -j "$WIFI" || return 1
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
                            -o "$VPN_IFACE" -d "$WLAN_VALUE" -j RETURN || return 1
                    done < "$NETWORK_STATE"

                    "$IPT" -w 5 -A "$DISP" \
                        -o "$VPN_IFACE" -j "$WIFI" || return 1
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
                            -o "$VPN_IFACE" -d "$WLAN_VALUE" -j RETURN || return 1
                    done < "$NETWORK_STATE"

                    "$IPT" -w 5 -A "$DISP" \
                        -o "$VPN_IFACE" -j "$WIFI" || return 1
                fi
                ;;

            rmnet*)
                "$IPT" -w 5 -A "$DISP" \
                    -o "$VPN_IFACE" -j "$MOB" || return 1
                ;;

            *)
                log_error "Firewall" "Unsupported VPN topology" \
                    "family=$FAMILY vpn=$VPN_IFACE underlying=$UNDERLYING_IFACE"
                return 1
                ;;
        esac
    done < "$NETWORK_STATE"

    "$IPT" -w 5 -A "$DISP" -j RETURN || return 1

    while IFS='|' read -r USER PACKAGE UID NETWORK ACTION; do
        case "$NETWORK" in
            MOBILE) TARGET="$MOB" ;;
            WIFI) TARGET="$WIFI" ;;
            LAN) TARGET="$LAN" ;;
            *) continue ;;
        esac

        "$IPT" -w 5 -I "$TARGET" 1 \
            -m owner --uid-owner "$UID" -j DROP || return 1
    done < "$PREPARED_POLICY"

    return 0
}

generation_verify_complete() {
    GEN="$1"

    if ! generation_verify_family "$GEN" ipv4; then
        debug_log "Firewall" "verify ipv4 failed" "generation=$GEN"
        return 1
    fi

    if ! generation_verify_family "$GEN" ipv6; then
        debug_log "Firewall" "verify ipv6 failed" "generation=$GEN"
        return 1
    fi

    return 0
}

generation_verify_dispatcher_family() {
    GEN="$1"
    FAMILY="$2"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    DISP="$(generation_dispatcher_chain "$GEN")"

    generation_chain_exists "$IPT" "$DISP" || return 1

    RULES="$("$IPT" -w 5 -S "$DISP" 2>/dev/null)" || return 1

    RETURN_COUNT=0
    LAST_RULE=""

    while IFS= read -r RULE; do
        case "$RULE" in
            "-N $DISP")
                continue
                ;;
            "-A $DISP -j RETURN")
                RETURN_COUNT=$((RETURN_COUNT + 1))
                ;;
            "-A $DISP -o "*"-j TIRNFW-G"$GEN"-M")
                ;;
            "-A $DISP -o "*"-j TIRNFW-G"$GEN"-W")
                ;;
            "-A $DISP -o "*"-j TIRNFW-G"$GEN"-L")
                ;;
            "-A $DISP -d "*"-o "*"-j TIRNFW-G"$GEN"-L")
                ;;
            "-A $DISP -d "*"-o "*"-j RETURN")
                ;;
            "")
                ;;
            *)
                debug_log "Firewall" "dispatcher unexpected rule" "family=$FAMILY rule=$RULE"
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

generation_verify_dispatcher_complete() {
    GEN="$1"

    generation_verify_dispatcher_family "$GEN" ipv4 || return 1
    generation_verify_dispatcher_family "$GEN" ipv6 || return 1

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

generation_verify_retained_dispatcher_family() {
    NEW_GEN="$1"
    OLD_GEN="$2"
    FAMILY="$3"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    NEW_CHAIN="$(generation_dispatcher_chain "$NEW_GEN")"
    OLD_CHAIN=""
    if [ -n "$OLD_GEN" ]; then
        OLD_CHAIN="$(generation_dispatcher_chain "$OLD_GEN")"
    fi

    RULES="$($IPT -w 5 -S "$MAIN_CHAIN" 2>/dev/null)" || return 1

    EXPECTED_RULES=0
    POSITION=0
    while IFS= read -r RULE; do
        [ -n "$RULE" ] || continue
        case "$RULE" in
            "-N $MAIN_CHAIN") continue ;;
        esac
        POSITION=$((POSITION + 1))
        case "$POSITION:$RULE" in
            "1:-A $MAIN_CHAIN -j $NEW_CHAIN") EXPECTED_RULES=$((EXPECTED_RULES + 1)) ;;
            "2:-A $MAIN_CHAIN -j $GENERATION_GUARD_CHAIN") EXPECTED_RULES=$((EXPECTED_RULES + 1)) ;;
            "3:-A $MAIN_CHAIN -j $OLD_CHAIN") [ -n "$OLD_CHAIN" ] || return 1; EXPECTED_RULES=$((EXPECTED_RULES + 1)) ;;
            "3:-A $MAIN_CHAIN -j RETURN") [ -z "$OLD_CHAIN" ] || return 1; EXPECTED_RULES=$((EXPECTED_RULES + 1)) ;;
            "4:-A $MAIN_CHAIN -j RETURN") [ -n "$OLD_CHAIN" ] || return 1; EXPECTED_RULES=$((EXPECTED_RULES + 1)) ;;
            *) return 1 ;;
        esac
    done <<EOF
$RULES
EOF

    if [ -n "$OLD_CHAIN" ]; then
        [ "$POSITION" -eq 4 ] || return 1
    else
        [ "$POSITION" -eq 3 ] || return 1
    fi

    [ "$EXPECTED_RULES" -eq "$POSITION" ] || return 1
    return 0
}

generation_verify_retained_final_dispatcher_family() {
    NEW_GEN="$1"
    OLD_GEN="$2"
    FAMILY="$3"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    NEW_CHAIN="$(generation_dispatcher_chain "$NEW_GEN")"
    OLD_CHAIN=""
    if [ -n "$OLD_GEN" ]; then
        OLD_CHAIN="$(generation_dispatcher_chain "$OLD_GEN")"
    fi

    RULES="$($IPT -w 5 -S "$MAIN_CHAIN" 2>/dev/null)" || return 1

    EXPECTED_RULES=0
    POSITION=0
    while IFS= read -r RULE; do
        [ -n "$RULE" ] || continue
        case "$RULE" in
            "-N $MAIN_CHAIN") continue ;;
        esac
        POSITION=$((POSITION + 1))
        case "$POSITION:$RULE" in
            "1:-A $MAIN_CHAIN -j $NEW_CHAIN") EXPECTED_RULES=$((EXPECTED_RULES + 1)) ;;
            "2:-A $MAIN_CHAIN -j $OLD_CHAIN") [ -n "$OLD_CHAIN" ] || return 1; EXPECTED_RULES=$((EXPECTED_RULES + 1)) ;;
            "2:-A $MAIN_CHAIN -j RETURN") [ -z "$OLD_CHAIN" ] || return 1; EXPECTED_RULES=$((EXPECTED_RULES + 1)) ;;
            "3:-A $MAIN_CHAIN -j RETURN") [ -n "$OLD_CHAIN" ] || return 1; EXPECTED_RULES=$((EXPECTED_RULES + 1)) ;;
            *) return 1 ;;
        esac
    done <<EOF
$RULES
EOF

    if [ -n "$OLD_CHAIN" ]; then
        [ "$POSITION" -eq 3 ] || return 1
    else
        [ "$POSITION" -eq 2 ] || return 1
    fi

    [ "$EXPECTED_RULES" -eq "$POSITION" ] || return 1
    return 0
}

generation_verify_stable_dispatcher_complete() {
    GEN="$1"

    generation_verify_stable_dispatcher_family "$GEN" ipv4 || return 1
    generation_verify_stable_dispatcher_family "$GEN" ipv6 || return 1

    return 0
}


generation_remove_old_active_ipv4() {
    OLD="$1"

    [ -n "$OLD" ] || return 0

    generation_active_rule_ipv4 "$OLD" || return 0

    "$IPTABLES" -w 5 -D "$MAIN_CHAIN" -j "$OLD" || return 1

    ! generation_active_rule_ipv4 "$OLD"
}

generation_remove_old_active_ipv6() {
    OLD="$1"

    [ -n "$OLD" ] || return 0

    generation_active_rule_ipv6 "$OLD" || return 0

    "$IP6TABLES" -w 5 -D "$MAIN_CHAIN" -j "$OLD" || return 1

    ! generation_active_rule_ipv6 "$OLD"
}

generation_verify_old_removed() {
    OLD4="$1"
    OLD6="$2"

    if [ -n "$OLD4" ] && generation_active_rule_ipv4 "$OLD4"; then
        return 1
    fi

    if [ -n "$OLD6" ] && generation_active_rule_ipv6 "$OLD6"; then
        return 1
    fi

    return 0
}

generation_finalize_retained_old() {
    NEW_GEN="$1"
    OLD4="$2"
    OLD6="$3"

    NEW4="$(generation_dispatcher_chain "$NEW_GEN")"
    NEW6="$(generation_dispatcher_chain "$NEW_GEN")"

    if [ -n "$OLD4" ]; then
        generation_remove_active_ipv4_checked "$OLD4" || return 1
    fi

    if [ -n "$OLD6" ]; then
        generation_remove_active_ipv6_checked "$OLD6" || return 1
    fi

    generation_active_rule_ipv4 "$NEW4" || return 1
    generation_active_rule_ipv6 "$NEW6" || return 1
    generation_verify_stable_dispatcher_complete "$NEW_GEN" || return 1

    if [ -n "$OLD4" ]; then
        OLD4_ID="${OLD4#TIRNFW-G}"
        [ -n "$OLD4_ID" ] || return 1

        if ! generation_delete_family "$OLD4_ID" ipv4; then
            log_warn "Firewall" "Old IPv4 generation cleanup deferred"                 "generation=$OLD4"
        fi
    fi

    if [ -n "$OLD6" ]; then
        OLD6_ID="${OLD6#TIRNFW-G}"
        [ -n "$OLD6_ID" ] || return 1

        if ! generation_delete_family "$OLD6_ID" ipv6; then
            log_warn "Firewall" "Old IPv6 generation cleanup deferred"                 "generation=$OLD6"
        fi
    fi

    return 0
}

generation_remove_legacy_dispatcher_rules() {
    FAMILY="$1"

    case "$FAMILY" in
        ipv4) IPT="$IPTABLES" ;;
        ipv6) IPT="$IP6TABLES" ;;
        *) return 1 ;;
    esac

    RULES="$("$IPT" -w 5 -S "$MAIN_CHAIN" 2>/dev/null)" || return 1

    while IFS= read -r RULE; do
        case "$RULE" in
            "-N $MAIN_CHAIN")
                continue
                ;;
        esac

        case "$RULE" in
            "-A $MAIN_CHAIN -j $GENERATION_GUARD_CHAIN")
                continue
                ;;

            "-A $MAIN_CHAIN -j TIRNFW-G"[0-9]*)
                continue
                ;;

            "-A $MAIN_CHAIN -j RETURN")
                continue
                ;;

            "-A $MAIN_CHAIN -j TIRNFW-MOBILE")
                "$IPT" -w 5 -D "$MAIN_CHAIN" -j TIRNFW-MOBILE || return 1
                ;;

            "-A $MAIN_CHAIN -j TIRNFW-WIFI")
                "$IPT" -w 5 -D "$MAIN_CHAIN" -j TIRNFW-WIFI || return 1
                ;;

            "-A $MAIN_CHAIN -j TIRNFW-LAN")
                "$IPT" -w 5 -D "$MAIN_CHAIN" -j TIRNFW-LAN || return 1
                ;;

            "-A $MAIN_CHAIN -j DROP")
                "$IPT" -w 5 -D "$MAIN_CHAIN" -j DROP || return 1
                ;;

            "-A $MAIN_CHAIN "*)
                log_error "Firewall" "Unknown dispatcher rule" \
                    "family=$FAMILY rule=$RULE"
                return 1
                ;;
        esac
    done <<EOF
$RULES
EOF

    return 0
}

generation_remove_active_ipv4_checked() {
    GEN="$1"

    generation_active_rule_ipv4 "$GEN" || return 0
    generation_remove_active_ipv4 "$GEN" || return 1

    ! generation_active_rule_ipv4 "$GEN"
}

generation_remove_active_ipv6_checked() {
    GEN="$1"

    generation_active_rule_ipv6 "$GEN" || return 0
    generation_remove_active_ipv6 "$GEN" || return 1

    ! generation_active_rule_ipv6 "$GEN"
}

generation_restore_old() {
    NEW_GEN="$1"
    OLD4="$2"
    OLD6="$3"

    NEW4="$(generation_dispatcher_chain "$NEW_GEN")"
    NEW6="$(generation_dispatcher_chain "$NEW_GEN")"

    log_warn "Firewall" "Generation rollback started" \
        "new=$NEW_GEN old4=${OLD4:-none} old6=${OLD6:-none}"

    generation_remove_active_ipv4_checked "$NEW4" || return 1
    generation_remove_active_ipv6_checked "$NEW6" || return 1

    if [ -n "$OLD4" ]; then
        if ! generation_active_rule_ipv4 "$OLD4"; then
            generation_install_active_ipv4 "$OLD4" || return 1
        fi
        if ! generation_active_rule_ipv4 "$OLD4"; then
            debug_log "Firewall" "Rollback IPv4 active verification failed" "old=$OLD4"
            return 1
        fi
    fi

    if [ -n "$OLD6" ]; then
        if ! generation_active_rule_ipv6 "$OLD6"; then
            generation_install_active_ipv6 "$OLD6" || return 1
        fi
        if ! generation_active_rule_ipv6 "$OLD6"; then
            debug_log "Firewall" "Rollback IPv6 active verification failed" "old=$OLD6"
            return 1
        fi
    fi

    if [ -z "$OLD4" ] && generation_active_rule_ipv4 "$NEW4"; then
        return 1
    fi

    if [ -z "$OLD6" ] && generation_active_rule_ipv6 "$NEW6"; then
        return 1
    fi

    if [ -n "$OLD4" ] && [ -n "$OLD6" ]; then
        OLD4_ID="${OLD4#TIRNFW-G}"
        OLD6_ID="${OLD6#TIRNFW-G}"

        if [ "$OLD4_ID" != "$OLD6_ID" ]; then
            debug_log "Firewall" "Rollback generation mismatch" "old4=$OLD4 old6=$OLD6"
            return 1
        fi

        generation_guard_remove || return 1

        if ! generation_verify_stable_dispatcher_family "$OLD4_ID" ipv4; then
            debug_log "Firewall" "Rollback IPv4 stable dispatcher verification failed" "generation=$OLD4_ID"
            return 1
        fi

        if ! generation_verify_stable_dispatcher_family "$OLD6_ID" ipv6; then
            debug_log "Firewall" "Rollback IPv6 stable dispatcher verification failed" "generation=$OLD6_ID"
            return 1
        fi

        if generation_active_rule_ipv4 "$NEW4"; then
            debug_log "Firewall" "Rollback left new IPv4 generation active" "generation=$NEW_GEN"
            return 1
        fi

        if generation_active_rule_ipv6 "$NEW6"; then
            debug_log "Firewall" "Rollback left new IPv6 generation active" "generation=$NEW_GEN"
            return 1
        fi
    elif [ -z "$OLD4" ] && [ -z "$OLD6" ]; then
        if generation_active_rule_ipv4 "$NEW4" ||
           generation_active_rule_ipv6 "$NEW6"; then
            return 1
        fi
    else
        return 1
    fi

    if [ "${TIRN_DEV_MODE:-0}" -eq 1 ] && [ "${TIRN_TEST_FAIL_ROLLBACK_VERIFY:-0}" -eq 1 ]; then
        log_error "Firewall" "TEST FAULT" "forcing rollback verification failure"
        return 1
    fi

    log_warn "Firewall" "Generation rollback verified" \
        "old4=${OLD4:-none} old6=${OLD6:-none}"

    return 0
}

generation_transaction_cleanup_new() {
    GEN="$1"
    CLEANUP_FAILED=0

    if ! generation_delete_family "$GEN" ipv4 >/dev/null 2>&1; then
        log_warn "Firewall" "New IPv4 generation cleanup failed" \
            "generation=$GEN"
        CLEANUP_FAILED=1
    fi

    if ! generation_delete_family "$GEN" ipv6 >/dev/null 2>&1; then
        log_warn "Firewall" "New IPv6 generation cleanup failed" \
            "generation=$GEN"
        CLEANUP_FAILED=1
    fi

    return "$CLEANUP_FAILED"
}

generation_switch_transaction() {
    NEW_STATE="$1"
    PREPARED_POLICY="$2"
    RETAIN_OLD="${3:-0}"

    OLD4="$(active_generation_ipv4 2>/dev/null || true)"
    OLD6="$(active_generation_ipv6 2>/dev/null || true)"

    NEW_GEN="$(next_generation_id)"
    NEW4="$(generation_dispatcher_chain "$NEW_GEN")"
    NEW6="$(generation_dispatcher_chain "$NEW_GEN")"

    log_info "Firewall" "Generation build started"         "generation=$NEW_GEN"

    BUILD_OK=0

    for BUILD_ATTEMPT in 1 2; do
        generation_transaction_cleanup_new "$NEW_GEN"

        if ! generation_create_family "$NEW_GEN" ipv4; then
            debug_log "Firewall" "create ipv4 failed" "generation=$NEW_GEN"
        elif ! generation_create_family "$NEW_GEN" ipv6; then
            debug_log "Firewall" "create ipv6 failed" "generation=$NEW_GEN"
        elif ! generation_populate_family "$NEW_GEN" ipv4 "$PREPARED_POLICY" "$NEW_STATE"; then
            debug_log "Firewall" "populate ipv4 failed" "generation=$NEW_GEN"
        elif ! generation_populate_family "$NEW_GEN" ipv6 "$PREPARED_POLICY" "$NEW_STATE"; then
            debug_log "Firewall" "populate ipv6 failed" "generation=$NEW_GEN"
        elif ! generation_verify_complete "$NEW_GEN"; then
            debug_log "Firewall" "verify complete failed" "generation=$NEW_GEN"
        elif ! generation_verify_dispatcher_complete "$NEW_GEN"; then
            debug_log "Firewall" "verify dispatcher failed" "generation=$NEW_GEN"
        else
            BUILD_OK=1
            break
        fi

        log_warn "Firewall" "Generation build retry"             "generation=$NEW_GEN attempt=$BUILD_ATTEMPT"
    done

    if [ "$BUILD_OK" -ne 1 ]; then
        generation_transaction_cleanup_new "$NEW_GEN"
        log_error "Firewall" "Generation build failed"             "generation=$NEW_GEN attempts=2"
        return 1
    fi

    log_info "Firewall" "Generation verified off-path"         "generation=$NEW_GEN"

    if ! chain_exists "$IPTABLES" "$MAIN_CHAIN" ||
       ! chain_exists "$IP6TABLES" "$MAIN_CHAIN"; then
        log_error "Firewall" "Stable dispatcher missing"             "generation=$NEW_GEN"
        generation_transaction_cleanup_new "$NEW_GEN"
        return 1
    fi

    if ! generation_guard_install; then
        log_error "Firewall" "Guard installation failed"             "generation=$NEW_GEN"

        if generation_guard_verify; then
            log_warn "Firewall" "Fail-closed guard retained"                 "generation=$NEW_GEN"
        fi

        generation_transaction_cleanup_new "$NEW_GEN"
        return 1
    fi

    if ! generation_guard_verify; then
        log_error "Firewall" "Guard verification failed"             "generation=$NEW_GEN"
        return 1
    fi

    if ! generation_install_active_ipv4 "$NEW4"; then
        log_error "Firewall" "IPv4 activation failed"             "generation=$NEW_GEN"

        if generation_restore_old "$NEW_GEN" "$OLD4" "$OLD6"; then
            if generation_guard_remove; then
                generation_transaction_cleanup_new "$NEW_GEN"
                return 1
            fi

            log_error "Firewall" "Guard removal after rollback failed"                 "generation=$NEW_GEN"
            return 1
        fi

        log_error "Firewall" "Rollback verification failed"             "generation=$NEW_GEN"
        return 1
    fi

    if ! generation_install_active_ipv6 "$NEW6"; then
        log_error "Firewall" "IPv6 activation failed"             "generation=$NEW_GEN"

        if generation_restore_old "$NEW_GEN" "$OLD4" "$OLD6"; then
            if generation_guard_remove; then
                generation_transaction_cleanup_new "$NEW_GEN"
                return 1
            fi

            log_error "Firewall" "Guard removal after rollback failed"                 "generation=$NEW_GEN"
            return 1
        fi

        log_error "Firewall" "Rollback verification failed"             "generation=$NEW_GEN"
        return 1
    fi

    if [ "${TIRN_TEST_FAIL_ACTIVE_VERIFY:-0}" -eq 1 ]; then
        log_warn "Firewall" "TEST MODE — injected active generation verification failure"             "generation=$NEW_GEN"

        if generation_restore_old "$NEW_GEN" "$OLD4" "$OLD6"; then
            if generation_guard_remove; then
                generation_transaction_cleanup_new "$NEW_GEN"
                return 1
            fi
        fi

        log_error "Firewall" "Rollback verification failed"             "generation=$NEW_GEN"
        return 1
    fi

    if ! generation_active_rule_ipv4 "$NEW4" ||
       ! generation_active_rule_ipv6 "$NEW6"; then
        log_error "Firewall" "Generation activation verification failed"             "generation=$NEW_GEN"

        if generation_restore_old "$NEW_GEN" "$OLD4" "$OLD6"; then
            if generation_guard_remove; then
                generation_transaction_cleanup_new "$NEW_GEN"
                return 1
            fi

            log_error "Firewall" "Guard removal after rollback failed"                 "generation=$NEW_GEN"
            return 1
        fi

        log_error "Firewall" "Rollback verification failed"             "generation=$NEW_GEN"
        return 1
    fi

    if ! generation_remove_legacy_dispatcher_rules ipv4 ||
       ! generation_remove_legacy_dispatcher_rules ipv6; then
        log_error "Firewall" "Dispatcher cleanup failed"             "generation=$NEW_GEN"

        if generation_restore_old "$NEW_GEN" "$OLD4" "$OLD6"; then
            if generation_guard_remove; then
                generation_transaction_cleanup_new "$NEW_GEN"
                return 1
            fi

            log_error "Firewall" "Guard removal after rollback failed"                 "generation=$NEW_GEN"
            return 1
        fi

        log_error "Firewall" "Rollback verification failed"             "generation=$NEW_GEN"
        return 1
    fi

    if [ "$RETAIN_OLD" -eq 1 ]; then
        log_info "Firewall" "Old generation retained"             "generation=$NEW_GEN old4=${OLD4:-none} old6=${OLD6:-none}"
    else
        if ! generation_remove_old_active_ipv4 "$OLD4" ||
           ! generation_remove_old_active_ipv6 "$OLD6" ||
           ! generation_verify_old_removed "$OLD4" "$OLD6"; then
            log_error "Firewall" "Old generation removal failed"                 "generation=$NEW_GEN old4=${OLD4:-none} old6=${OLD6:-none}"

            if generation_restore_old "$NEW_GEN" "$OLD4" "$OLD6"; then
                if generation_guard_remove; then
                    generation_transaction_cleanup_new "$NEW_GEN"
                    return 1
                fi

                log_error "Firewall" "Guard removal after rollback failed"                     "generation=$NEW_GEN"
                return 1
            fi

            log_error "Firewall" "Rollback verification failed"                 "generation=$NEW_GEN"
            return 1
        fi
    fi

    if [ "$RETAIN_OLD" -eq 1 ]; then
        if ! generation_verify_retained_dispatcher_family "$NEW_GEN" "${OLD4#TIRNFW-G}" ipv4 ||
           ! generation_verify_retained_dispatcher_family "$NEW_GEN" "${OLD6#TIRNFW-G}" ipv6; then
            log_error "Firewall" "Retained dispatcher verification failed"                 "generation=$NEW_GEN old4=${OLD4:-none} old6=${OLD6:-none}"

            if generation_restore_old "$NEW_GEN" "$OLD4" "$OLD6"; then
                if generation_guard_remove; then
                    generation_transaction_cleanup_new "$NEW_GEN"
                    return 1
                fi

                log_error "Firewall" "Guard removal after rollback failed"                     "generation=$NEW_GEN"
                return 1
            fi

            log_error "Firewall" "Rollback verification failed"                 "generation=$NEW_GEN"
            return 1
        fi
    elif ! generation_verify_stable_dispatcher_complete "$NEW_GEN"; then
        log_error "Firewall" "Guarded stable dispatcher verification failed"             "generation=$NEW_GEN"

        if generation_restore_old "$NEW_GEN" "$OLD4" "$OLD6"; then
            if generation_guard_remove; then
                generation_transaction_cleanup_new "$NEW_GEN"
                return 1
            fi

            log_error "Firewall" "Guard removal after rollback failed"                 "generation=$NEW_GEN"
            return 1
        fi

        log_error "Firewall" "Rollback verification failed"             "generation=$NEW_GEN"
        return 1
    fi

    if ! generation_guard_remove; then
        log_error "Firewall" "Guard removal failed"             "generation=$NEW_GEN"

        if generation_guard_verify; then
            log_warn "Firewall" "Fail-closed guard retained"                 "generation=$NEW_GEN"
        fi

        return 1
    fi

    if ! "$IPTABLES" -w 5 -S "$MAIN_CHAIN" 2>/dev/null |
       awk -v chain="$MAIN_CHAIN" -v guard="$GENERATION_GUARD_CHAIN"            '$0 == "-A " chain " -j " guard {count++}
            END {exit(count == 0 ? 0 : 1)}'; then
        log_error "Firewall" "IPv4 guard absence verification failed"             "generation=$NEW_GEN"
        return 1
    fi

    if ! "$IP6TABLES" -w 5 -S "$MAIN_CHAIN" 2>/dev/null |
       awk -v chain="$MAIN_CHAIN" -v guard="$GENERATION_GUARD_CHAIN"            '$0 == "-A " chain " -j " guard {count++}
            END {exit(count == 0 ? 0 : 1)}'; then
        log_error "Firewall" "IPv6 guard absence verification failed"             "generation=$NEW_GEN"
        return 1
    fi

    if [ "$RETAIN_OLD" -eq 1 ]; then
        if ! generation_verify_retained_final_dispatcher_family "$NEW_GEN" "${OLD4#TIRNFW-G}" ipv4 ||
           ! generation_verify_retained_final_dispatcher_family "$NEW_GEN" "${OLD6#TIRNFW-G}" ipv6 ||
           ! generation_active_rule_ipv4 "$NEW4" ||
           ! generation_active_rule_ipv6 "$NEW6"; then
            log_error "Firewall" "Post-guard retained verification failed"                 "generation=$NEW_GEN"

            if ! generation_guard_install ||
               ! generation_guard_verify; then
                log_error "Firewall" "Fail-closed guard restoration failed"                     "generation=$NEW_GEN"
                return 1
            fi

            if ! generation_restore_old "$NEW_GEN" "$OLD4" "$OLD6"; then
                log_error "Firewall" "Rollback verification failed"                     "generation=$NEW_GEN"
                return 1
            fi

            if ! generation_guard_remove; then
                log_error "Firewall" "Guard removal after rollback failed"                     "generation=$NEW_GEN"
                return 1
            fi

            generation_transaction_cleanup_new "$NEW_GEN"
            return 1
        fi
    elif ! generation_verify_stable_dispatcher_complete "$NEW_GEN" ||
       ! generation_active_rule_ipv4 "$NEW4" ||
       ! generation_active_rule_ipv6 "$NEW6"; then

        log_error "Firewall" "Post-guard verification failed"             "generation=$NEW_GEN"

        if ! generation_guard_install ||
           ! generation_guard_verify; then
            log_error "Firewall" "Fail-closed guard restoration failed"                 "generation=$NEW_GEN"
            return 1
        fi

        if ! generation_restore_old "$NEW_GEN" "$OLD4" "$OLD6"; then
            log_error "Firewall" "Rollback verification failed"                 "generation=$NEW_GEN"
            return 1
        fi

        if ! generation_guard_remove; then
            log_error "Firewall" "Guard removal after rollback failed"                 "generation=$NEW_GEN"
            return 1
        fi

        generation_transaction_cleanup_new "$NEW_GEN"
        return 1
    fi

    if [ "$RETAIN_OLD" -ne 1 ]; then
        if [ -n "$OLD4" ] && [ "$OLD4" != "$NEW4" ]; then
            OLD4_ID="${OLD4#TIRNFW-G}"
            if [ -n "$OLD4_ID" ]; then
                generation_delete_family "$OLD4_ID" ipv4 ||                     log_warn "Firewall" "Old IPv4 generation cleanup deferred"                     "generation=$OLD4"
            fi
        fi

        if [ -n "$OLD6" ] && [ "$OLD6" != "$NEW6" ]; then
            OLD6_ID="${OLD6#TIRNFW-G}"
            if [ -n "$OLD6_ID" ]; then
                generation_delete_family "$OLD6_ID" ipv6 ||                     log_warn "Firewall" "Old IPv6 generation cleanup deferred"                     "generation=$OLD6"
            fi
        fi
    fi

    log_info "Firewall" "Generation activated"         "generation=$NEW_GEN"

    return 0
}

apply_dispatcher() {
    TMP_STATE="$DATA_DIR/network.state.tmp.$$"
    PREPARED_POLICY="$DATA_DIR/policy.prepared.$$"
    PREPARED_COUNT="$DATA_DIR/policy.count.$$"

    if ! acquire_firewall_lock; then
        log_error "Network" "Dispatcher update failed" \
            "firewall lock unavailable"
        return 1
    fi

    if ! build_network_state > "$TMP_STATE"; then
        rm -f "$TMP_STATE" "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        log_error "Network" "State build failed"
        return 1
    fi

    if [ -f "$STATE_FILE" ] && cmp -s "$TMP_STATE" "$STATE_FILE"; then
        rm -f "$TMP_STATE" "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        return 0
    fi

    if ! prepare_policy "$PREPARED_POLICY" "$PREPARED_COUNT"; then
        rm -f "$TMP_STATE" "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock
        return 1
    fi

    if generation_switch_transaction \
        "$TMP_STATE" "$PREPARED_POLICY"; then

        if ! mv -f "$TMP_STATE" "$STATE_FILE"; then
            log_error "Network" "State commit failed" \
                "generation transaction succeeded but network.state could not be committed"
            rm -f "$PREPARED_COUNT"
            release_firewall_lock
            return 1
        fi

        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock

        log_info "Network" "Dispatcher updated" \
            "generation transaction completed"
        return 0
    fi

    rm -f "$TMP_STATE" "$PREPARED_POLICY" "$PREPARED_COUNT"
    release_firewall_lock

    log_error "Network" "Dispatcher update failed" \
        "existing generation retained"
    return 1
}

apply_policy() {
    PREPARED_POLICY="$DATA_DIR/policy.prepared.$$"
    PREPARED_COUNT="$DATA_DIR/policy.count.$$"
    TMP_STATE="$DATA_DIR/network.state.tmp.$$"

    if ! acquire_firewall_lock; then
        log_error "Policy" "Apply failed" \
            "firewall lock unavailable"
        return 1
    fi

    if ! prepare_policy "$PREPARED_POLICY" "$PREPARED_COUNT"; then
        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT" "$TMP_STATE"
        release_firewall_lock
        return 1
    fi

    if ! build_network_state > "$TMP_STATE"; then
        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT" "$TMP_STATE"
        release_firewall_lock
        log_error "Network" "State build failed"
        return 1
    fi

    if generation_switch_transaction \
        "$TMP_STATE" "$PREPARED_POLICY"; then

        if ! mv -f "$TMP_STATE" "$STATE_FILE"; then
            log_error "Policy" "State commit failed" \
                "generation transaction succeeded but network.state could not be committed"
            rm -f "$PREPARED_COUNT"
            release_firewall_lock
            return 1
        fi

        if ! cp -f "$PREPARED_POLICY" "$POLICY_STATE_FILE"; then
            log_error "Policy" "Applied policy commit failed" \
                "generation transaction succeeded but policy.applied could not be committed"
            rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
            release_firewall_lock
            return 1
        fi

        if ! chmod 600 "$POLICY_STATE_FILE"; then
            log_error "Policy" "Applied policy permissions failed" \
                "generation transaction succeeded but policy.applied mode could not be set"
            rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
            release_firewall_lock
            return 1
        fi

        APPLIED_COUNT="$(wc -l < "$POLICY_STATE_FILE" 2>/dev/null)"
        APPLIED_COUNT="$(printf '%s' "$APPLIED_COUNT" | tr -d ' ')"

        rm -f "$PREPARED_POLICY" "$PREPARED_COUNT"
        release_firewall_lock

        log_info "Policy" "Applied" "$APPLIED_COUNT rules"
        return 0
    fi

    rm -f "$PREPARED_POLICY" "$PREPARED_COUNT" "$TMP_STATE"
    release_firewall_lock

    log_error "Policy" "Apply failed" \
        "existing generation retained"
    return 1
}

import_policy_transaction() {
    CANDIDATE_POLICY="$DATA_DIR/policy.import.$$"
    PREPARED_POLICY="$DATA_DIR/policy.import.prepared.$$"
    PREPARED_COUNT="$DATA_DIR/policy.import.count.$$"

    TMP_STATE="$DATA_DIR/network.state.import.$$"
    PREPARED_STATE="$DATA_DIR/network.state.import.prepared.$$"

    TMP_POLICY="$DATA_DIR/policy.conf.import.$$"
    TMP_APPLIED="$DATA_DIR/policy.applied.import.$$"

    BACKUP_POLICY="$DATA_DIR/policy.conf.import.backup.$$"
    BACKUP_APPLIED="$DATA_DIR/policy.applied.import.backup.$$"
    BACKUP_STATE="$DATA_DIR/network.state.import.backup.$$"

    IMPORT_MARKER="$DATA_DIR/policy.importing"

    IMPORT_POLICY_LOCK=0
    IMPORT_FIREWALL_LOCK=0
    IMPORT_NEW_ACTIVE=0
    IMPORT_ROLLBACK_OK=0
    IMPORT_COMMIT_OK=0

    IMPORT_OLD4=""
    IMPORT_OLD6=""
    IMPORT_NEW_GEN=""

    IMPORT_POLICY_EXISTED=0
    IMPORT_APPLIED_EXISTED=0
    IMPORT_STATE_EXISTED=0

    cleanup_import() {
        rm -f \
            "$CANDIDATE_POLICY" \
            "$PREPARED_POLICY" \
            "$PREPARED_COUNT" \
            "$TMP_STATE" \
            "$PREPARED_STATE" \
            "$TMP_POLICY" \
            "$TMP_APPLIED"

        if [ "$IMPORT_COMMIT_OK" -eq 1 ] ||
           [ "$IMPORT_ROLLBACK_OK" -eq 1 ]; then
            rm -f \
                "$BACKUP_POLICY" \
                "$BACKUP_APPLIED" \
                "$BACKUP_STATE" \
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

    trap 'cleanup_import' EXIT

    if ! cat > "$CANDIDATE_POLICY"; then
        log_error "Policy" "Import failed" \
            "unable to read candidate policy"
        return 1
    fi

    chmod 600 "$CANDIDATE_POLICY" || {
        log_error "Policy" "Import failed" \
            "unable to protect candidate policy"
        return 1
    }

    if ! acquire_policy_lock; then
        log_error "Policy" "Import failed" \
            "policy transaction busy"
        return 1
    fi

    IMPORT_POLICY_LOCK=1

    if ! acquire_firewall_lock; then
        log_error "Policy" "Import failed" \
            "firewall transaction busy"
        return 1
    fi

    IMPORT_FIREWALL_LOCK=1

    if ! (umask 077; : > "$IMPORT_MARKER"); then
        log_error "Policy" "Import failed" \
            "unable to create import marker"
        return 1
    fi

    # Capture the currently active generation before constructing the
    # replacement. RETAIN_OLD keeps these chains available until the
    # persistent transaction has committed and verified all state.
    IMPORT_OLD4="$(active_generation_ipv4 2>/dev/null || true)"
    IMPORT_OLD6="$(active_generation_ipv6 2>/dev/null || true)"

    # Preserve the exact pre-import persistent state, including whether
    # each file existed at all.
    if [ -e "$POLICY_FILE" ]; then
        IMPORT_POLICY_EXISTED=1
        if ! cp -f "$POLICY_FILE" "$BACKUP_POLICY"; then
            log_error "Policy" "Import failed" \
                "unable to back up policy.conf"
            return 1
        fi
        chmod 600 "$BACKUP_POLICY" || return 1
    fi

    if [ -e "$POLICY_STATE_FILE" ]; then
        IMPORT_APPLIED_EXISTED=1
        if ! cp -f "$POLICY_STATE_FILE" "$BACKUP_APPLIED"; then
            log_error "Policy" "Import failed" \
                "unable to back up policy.applied"
            return 1
        fi
        chmod 600 "$BACKUP_APPLIED" || return 1
    fi

    if [ -e "$STATE_FILE" ]; then
        IMPORT_STATE_EXISTED=1
        if ! cp -f "$STATE_FILE" "$BACKUP_STATE"; then
            log_error "Policy" "Import failed" \
                "unable to back up network.state"
            return 1
        fi
        chmod 600 "$BACKUP_STATE" || return 1
    fi

    if ! prepare_policy \
        "$PREPARED_POLICY" \
        "$PREPARED_COUNT" \
        "$CANDIDATE_POLICY"; then
        log_error "Policy" "Import failed" \
            "candidate policy preparation failed"
        return 1
    fi

    if ! build_network_state > "$TMP_STATE"; then
        log_error "Policy" "Import failed" \
            "network state build failed"
        return 1
    fi

    # Preserve an independent verification copy. TMP_STATE will later be
    # moved atomically into place and therefore cannot be used afterwards.
    if ! cp -f "$TMP_STATE" "$PREPARED_STATE"; then
        log_error "Policy" "Import failed" \
            "unable to preserve prepared network state"
        return 1
    fi

    if ! cp -f "$PREPARED_POLICY" "$TMP_POLICY"; then
        log_error "Policy" "Import failed" \
            "unable to prepare policy.conf"
        return 1
    fi

    if ! cp -f "$PREPARED_POLICY" "$TMP_APPLIED"; then
        log_error "Policy" "Import failed" \
            "unable to prepare policy.applied"
        return 1
    fi

    chmod 600 \
        "$TMP_POLICY" \
        "$TMP_APPLIED" \
        "$TMP_STATE" \
        "$PREPARED_STATE" || {
        log_error "Policy" "Import failed" \
            "replacement file permissions preparation failed"
        return 1
    }

    # Construct and activate the replacement generation while retaining the
    # old generation for the complete filesystem transaction.
    if ! generation_switch_transaction \
        "$TMP_STATE" \
        "$PREPARED_POLICY" \
        1; then
        log_error "Policy" "Import failed" \
            "generation transaction aborted; existing policy retained"
        return 1
    fi

    IMPORT_NEW_GEN="$NEW_GEN"
    IMPORT_NEW_ACTIVE=1

    # Commit each persistent file atomically. The old firewall generation
    # remains available until every commit and verification has succeeded.
    if [ "${TIRN_DEV_MODE:-0}" -eq 1 ] && [ "${TIRN_TEST_FAIL_POLICY_COMMIT:-0}" -eq 1 ]; then
        log_error "Policy" "TEST FAULT" "forcing policy.conf commit failure"
        IMPORT_COMMIT_FAILED=1
    elif ! mv -f "$TMP_POLICY" "$POLICY_FILE"; then
        log_error "Policy" "Import failed" \
            "policy.conf commit failed; starting rollback"
        IMPORT_COMMIT_FAILED=1
    elif [ "${TIRN_DEV_MODE:-0}" -eq 1 ] && [ "${TIRN_TEST_FAIL_POLICY_APPLIED_COMMIT:-0}" -eq 1 ]; then
        log_error "Policy" "TEST FAULT" "forcing policy.applied commit failure"
        IMPORT_COMMIT_FAILED=1
    elif ! mv -f "$TMP_APPLIED" "$POLICY_STATE_FILE"; then
        log_error "Policy" "Import failed" \
            "policy.applied commit failed; starting rollback"
        IMPORT_COMMIT_FAILED=1
    elif [ "${TIRN_DEV_MODE:-0}" -eq 1 ] && [ "${TIRN_TEST_FAIL_STATE_COMMIT:-0}" -eq 1 ]; then
        log_error "Policy" "TEST FAULT" "forcing network.state commit failure"
        IMPORT_COMMIT_FAILED=1
    elif ! mv -f "$TMP_STATE" "$STATE_FILE"; then
        log_error "Policy" "Import failed" \
            "network.state commit failed; starting rollback"
        IMPORT_COMMIT_FAILED=1
    else
        IMPORT_COMMIT_FAILED=0
    fi

    if [ "$IMPORT_COMMIT_FAILED" -eq 1 ]; then
        if [ "$IMPORT_POLICY_EXISTED" -eq 1 ]; then
            RESTORE_POLICY="$DATA_DIR/policy.conf.import.restore.$$"
            if ! cp -f "$BACKUP_POLICY" "$RESTORE_POLICY" || ! chmod 600 "$RESTORE_POLICY" || ! mv -f "$RESTORE_POLICY" "$POLICY_FILE"; then
                rm -f "$RESTORE_POLICY"
                log_error "Policy" "Import rollback failed" \
                    "unable to restore policy.conf"
                return 1
            fi
        else
            rm -f "$POLICY_FILE"
        fi

        if [ "$IMPORT_APPLIED_EXISTED" -eq 1 ]; then
            RESTORE_APPLIED="$DATA_DIR/policy.applied.import.restore.$$"
            if ! cp -f "$BACKUP_APPLIED" "$RESTORE_APPLIED" || ! chmod 600 "$RESTORE_APPLIED" || ! mv -f "$RESTORE_APPLIED" "$POLICY_STATE_FILE"; then
                rm -f "$RESTORE_APPLIED"
                log_error "Policy" "Import rollback failed" \
                    "unable to restore policy.applied"
                return 1
            fi
        else
            rm -f "$POLICY_STATE_FILE"
        fi

        if [ "$IMPORT_STATE_EXISTED" -eq 1 ]; then
            RESTORE_STATE="$DATA_DIR/network.state.import.restore.$$"
            if ! cp -f "$BACKUP_STATE" "$RESTORE_STATE" || ! chmod 600 "$RESTORE_STATE" || ! mv -f "$RESTORE_STATE" "$STATE_FILE"; then
                rm -f "$RESTORE_STATE"
                log_error "Policy" "Import rollback failed" \
                    "unable to restore network.state"
                return 1
            fi
        else
            rm -f "$STATE_FILE"
        fi

        if ! generation_guard_install ||
           ! generation_guard_verify; then
            log_error "Policy" "Import rollback failed" \
                "unable to establish fail-closed guard"
            return 1
        fi

        if ! generation_restore_old \
            "$IMPORT_NEW_GEN" \
            "$IMPORT_OLD4" \
            "$IMPORT_OLD6"; then
            log_error "Policy" "Import rollback failed" \
                "old firewall generation could not be restored"
            return 1
        fi

        generation_transaction_cleanup_new "$IMPORT_NEW_GEN"

        if ! generation_guard_remove; then
            log_error "Policy" "Import rollback failed" \
                "guard removal failed"
            return 1
        fi

        IMPORT_NEW_ACTIVE=0
        IMPORT_ROLLBACK_OK=1

        log_warn "Policy" "Import rolled back" \
            "existing firewall generation and persistent policy restored"

        return 1
    fi

    # Verify all three committed persistent files against their preserved
    # prepared versions before the retained old generation is destroyed.
    if ! cmp -s "$POLICY_FILE" "$PREPARED_POLICY" ||
       ! cmp -s "$POLICY_STATE_FILE" "$PREPARED_POLICY" ||
       ! cmp -s "$STATE_FILE" "$PREPARED_STATE"; then

        log_error "Policy" "Import failed" \
            "persistent state verification failed; starting rollback"

        if [ "$IMPORT_POLICY_EXISTED" -eq 1 ]; then
            RESTORE_POLICY="$DATA_DIR/policy.conf.import.restore.$$"
            if ! cp -f "$BACKUP_POLICY" "$RESTORE_POLICY" || ! chmod 600 "$RESTORE_POLICY" || ! mv -f "$RESTORE_POLICY" "$POLICY_FILE"; then
                rm -f "$RESTORE_POLICY"
                log_error "Policy" "Import rollback failed" \
                    "unable to restore policy.conf"
                return 1
            fi
        else
            rm -f "$POLICY_FILE"
        fi

        if [ "$IMPORT_APPLIED_EXISTED" -eq 1 ]; then
            RESTORE_APPLIED="$DATA_DIR/policy.applied.import.restore.$$"
            if ! cp -f "$BACKUP_APPLIED" "$RESTORE_APPLIED" || ! chmod 600 "$RESTORE_APPLIED" || ! mv -f "$RESTORE_APPLIED" "$POLICY_STATE_FILE"; then
                rm -f "$RESTORE_APPLIED"
                log_error "Policy" "Import rollback failed" \
                    "unable to restore policy.applied"
                return 1
            fi
        else
            rm -f "$POLICY_STATE_FILE"
        fi

        if [ "$IMPORT_STATE_EXISTED" -eq 1 ]; then
            RESTORE_STATE="$DATA_DIR/network.state.import.restore.$$"
            if ! cp -f "$BACKUP_STATE" "$RESTORE_STATE" || ! chmod 600 "$RESTORE_STATE" || ! mv -f "$RESTORE_STATE" "$STATE_FILE"; then
                rm -f "$RESTORE_STATE"
                log_error "Policy" "Import rollback failed" \
                    "unable to restore network.state"
                return 1
            fi
        else
            rm -f "$STATE_FILE"
        fi

        if ! generation_guard_install ||
           ! generation_guard_verify; then
            log_error "Policy" "Import rollback failed" \
                "unable to establish fail-closed guard"
            return 1
        fi

        if ! generation_restore_old \
            "$IMPORT_NEW_GEN" \
            "$IMPORT_OLD4" \
            "$IMPORT_OLD6"; then
            log_error "Policy" "Import rollback failed" \
                "old firewall generation could not be restored"
            return 1
        fi

        generation_transaction_cleanup_new "$IMPORT_NEW_GEN"

        if ! generation_guard_remove; then
            log_error "Policy" "Import rollback failed" \
                "guard removal failed"
            return 1
        fi

        IMPORT_NEW_ACTIVE=0
        IMPORT_ROLLBACK_OK=1

        log_warn "Policy" "Import rolled back" \
            "persistent verification failure"

        return 1
    fi

    # At this point:
    #   - the new generation is active
    #   - policy.conf is committed and verified
    #   - policy.applied is committed and verified
    #   - network.state is committed and verified
    #
    # The retained old generation is no longer required for rollback.
    # Remove its dispatcher references first, then clean up its chains.
    if ! generation_finalize_retained_old         "$IMPORT_NEW_GEN"         "$IMPORT_OLD4"         "$IMPORT_OLD6"; then
        log_error "Policy" "Import failed"             "retained old generation dispatcher finalization failed"

        if generation_guard_install && generation_guard_verify &&
           generation_restore_old                "$IMPORT_NEW_GEN"                "$IMPORT_OLD4"                "$IMPORT_OLD6"; then
            generation_transaction_cleanup_new "$IMPORT_NEW_GEN"

            if generation_guard_remove; then
                IMPORT_NEW_ACTIVE=0
                IMPORT_ROLLBACK_OK=1

                log_warn "Policy" "Import rolled back"                     "old generation dispatcher finalization failed"
                return 1
            fi
        fi

        log_error "Policy" "Import rollback failed"             "old generation dispatcher finalization left firewall in uncertain state"
        return 1
    fi

    IMPORT_NEW_ACTIVE=0
    IMPORT_COMMIT_OK=1

    IMPORT_COUNT="$(wc -l < "$PREPARED_POLICY" 2>/dev/null)"
    IMPORT_COUNT="$(printf '%s' "$IMPORT_COUNT" | tr -d ' ')"

    log_info "Policy" "Import committed" \
        "rules=$IMPORT_COUNT exact replacement"

    return 0
}

if [ "${1:-}" = "--refresh" ]; then
    log_info "Refresh" "Started" "manual refresh requested"

    FAILED=0

    if refresh_apps_verified "manual"; then
        log_info "Apps" "Cache refreshed" "manual refresh"
    else
        log_error "Apps" "Cache refresh failed" "manual refresh"
        FAILED=1
    fi

    if [ "$FAILED" -eq 0 ]; then
        if apply_policy; then
            log_info "Refresh" "Completed" "app cache refreshed and firewall policy transaction succeeded"
        else
            log_error "Refresh" "Failed" \
                "policy transaction failed; fail-closed state retained"
            FAILED=1
        fi
    fi

    if [ "$FAILED" -eq 0 ]; then
        exit 0
    fi

    exit 1
fi

if [ "${1:-}" = "--import-policy" ]; then
    import_policy_transaction
    exit $?
fi

if [ "${1:-}" = "--policy-event" ]; then
    apply_policy
    exit $?
fi

log_info "Service" "Started" "module initialization"

clear_stale_boot_locks

if ! bootstrap_initialize; then
    log_error "Service" "Initialization failed" \
        "firewall remains fail-closed; see preceding transaction error"
    exit 1
fi

log_info "Service" "Ready" "transactional firewall active"

"$MODDIR/policy-watch.sh" "$POLICY_FILE:w" "$DATA_DIR:nm" >/dev/null 2>&1 &
POLICY_WATCH_PID=$!

"$MODDIR/app-watch.sh" >/dev/null 2>&1 &
APP_WATCH_PID=$!

trap 'kill "$POLICY_WATCH_PID" "$APP_WATCH_PID" 2>/dev/null || true' EXIT INT TERM

while true; do
    sleep "$POLL_INTERVAL"
    apply_dispatcher
done
