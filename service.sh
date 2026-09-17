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

touch "$POLICY_FILE"
chmod 600 "$POLICY_FILE"

. "$MODDIR/logging-common.sh"
AUDIT_LOG="$LOG_FILE"

# Atomic firewall transaction lock. This is separate from policy.lock.
FIREWALL_LOCK="$DATA_DIR/firewall.lock"

acquire_firewall_lock() {
    LOCK_WAIT=0
    while ! mkdir "$FIREWALL_LOCK" 2>/dev/null; do
        sleep 0.05
        LOCK_WAIT=$((LOCK_WAIT + 1))
        if [ "$LOCK_WAIT" -ge 200 ]; then
            log_error "Firewall" "Lock timeout" "another firewall transaction is active"
            return 1
        fi
    done
    return 0
}

release_firewall_lock() {
    rmdir "$FIREWALL_LOCK" 2>/dev/null || true
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
    printf 'TIRNFW-G%s\n' "$1"
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

    log_error "DEBUG" "verify family chains" "family=$FAMILY mob=$MOB wifi=$WIFI lan=$LAN"
    log_error "DEBUG" "mob rules" "rules=$(printf '%s' "$MOB_RULES" | tr '\\n' ';')"
    log_error "DEBUG" "wifi rules" "rules=$(printf '%s' "$WIFI_RULES" | tr '\\n' ';')"
    log_error "DEBUG" "lan rules" "rules=$(printf '%s' "$LAN_RULES" | tr '\\n' ';')"
    log_error "DEBUG" "disp rules" "rules=$(printf '%s' "$DISP_RULES" | tr '\\n' ';')"

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

    log_info "Firewall" "Fail-closed guard installed" \
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

    log_info "Firewall" "Fail-closed guard removed"         "ipv4=absent ipv6=absent"

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
        log_error "DEBUG" "IPv4 activation command failed"             "main=$MAIN_CHAIN target=$GEN"
        "$IPTABLES" -w 5 -S "$MAIN_CHAIN" 2>&1 | while IFS= read -r LINE; do
            log_error "DEBUG" "IPv4 main chain state" "rule=$LINE"
        done
        "$IPTABLES" -w 5 -L "$GEN" >/dev/null 2>&1 ||             log_error "DEBUG" "IPv4 target chain missing" "target=$GEN"
        return 1
    fi

    return 0
}

generation_install_active_ipv6() {
    GEN="$1"

    if ! "$IP6TABLES" -w 5 -I "$MAIN_CHAIN" 1 -j "$GEN"; then
        log_error "DEBUG" "IPv6 activation command failed"             "main=$MAIN_CHAIN target=$GEN"
        "$IP6TABLES" -w 5 -S "$MAIN_CHAIN" 2>&1 | while IFS= read -r LINE; do
            log_error "DEBUG" "IPv6 main chain state" "rule=$LINE"
        done
        "$IP6TABLES" -w 5 -L "$GEN" >/dev/null 2>&1 ||             log_error "DEBUG" "IPv6 target chain missing" "target=$GEN"
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
    ' "$TMP_MAP" "$POLICY_FILE" > "$TMP_NORMALIZED"; then
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
bootstrap_existing_install() {
    log_error "Firewall" "Existing install bootstrap not implemented"         "waiting for policy restore path"
    return 1
}

refresh_apps_bootstrap()
{
    log_info "Apps" "Cache refresh started" "bootstrap"

    if ! /system/bin/sh "$MODDIR/refresh_apps" >/dev/null 2>&1; then
        log_error "Apps" "Cache refresh failed" "bootstrap"
        return 1
    fi

    TIMEOUT=180
    ELAPSED=0

    while [ "$ELAPSED" -lt "$TIMEOUT" ]; do
        if [ -s "$DATA_DIR/apps.json" ]; then
            log_info "Apps" "Cache ready" "bootstrap"
            return 0
        fi

        sleep 2
        ELAPSED=$((ELAPSED + 2))
    done

    log_error "Apps" "Cache refresh timeout" \
        "apps.json not available after ${TIMEOUT}s"

    return 1
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
            "generation transaction failed; fail-closed state retained"
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
        log_error "DEBUG" "verify ipv4 failed" "generation=$GEN"
        return 1
    fi

    if ! generation_verify_family "$GEN" ipv6; then
        log_error "DEBUG" "verify ipv6 failed" "generation=$GEN"
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
                log_error "DEBUG" "dispatcher unexpected rule" "family=$FAMILY rule=$RULE"
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
            "-A $MAIN_CHAIN -j TIRNFW-G"[0-9]*)
                GENERATION_COUNT=$((GENERATION_COUNT + 1))
                GENERATION_TARGET="${RULE##*-j }"
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

    [ "$GENERATION_COUNT" -eq 1 ] || return 1
    [ "$GENERATION_TARGET" = "$EXPECTED" ] || return 1
    [ "$RETURN_COUNT" -eq 1 ] || return 1
    [ "$GUARD_COUNT" -le 1 ] || return 1
    [ "$RETURN_POSITION" -eq "$POSITION" ] || return 1

    if [ "$GUARD_COUNT" -eq 1 ]; then
        [ "$GENERATION_POSITION" -eq 2 ] || return 1
    else
        [ "$GENERATION_POSITION" -eq 1 ] || return 1
    fi

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

    NEW4="TIRNFW-G${NEW_GEN}"
    NEW6="TIRNFW-G${NEW_GEN}"

    log_warn "Firewall" "Generation rollback started" \
        "new=$NEW_GEN old4=${OLD4:-none} old6=${OLD6:-none}"

    generation_remove_active_ipv4_checked "$NEW4" || return 1
    generation_remove_active_ipv6_checked "$NEW6" || return 1

    if [ -n "$OLD4" ]; then
        if ! generation_active_rule_ipv4 "$OLD4"; then
            generation_install_active_ipv4 "$OLD4" || return 1
        fi
        generation_active_rule_ipv4 "$OLD4" || return 1
    fi

    if [ -n "$OLD6" ]; then
        if ! generation_active_rule_ipv6 "$OLD6"; then
            generation_install_active_ipv6 "$OLD6" || return 1
        fi
        generation_active_rule_ipv6 "$OLD6" || return 1
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

        [ "$OLD4_ID" = "$OLD6_ID" ] || return 1
        generation_verify_stable_dispatcher_complete "$OLD4_ID" || return 1
    elif [ -z "$OLD4" ] && [ -z "$OLD6" ]; then
        if generation_active_rule_ipv4 "$NEW4" ||
           generation_active_rule_ipv6 "$NEW6"; then
            return 1
        fi
    else
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
            log_error "DEBUG" "create ipv4 failed" "generation=$NEW_GEN"
        elif ! generation_create_family "$NEW_GEN" ipv6; then
            log_error "DEBUG" "create ipv6 failed" "generation=$NEW_GEN"
        elif ! generation_populate_family "$NEW_GEN" ipv4 "$PREPARED_POLICY" "$NEW_STATE"; then
            log_error "DEBUG" "populate ipv4 failed" "generation=$NEW_GEN"
        elif ! generation_populate_family "$NEW_GEN" ipv6 "$PREPARED_POLICY" "$NEW_STATE"; then
            log_error "DEBUG" "populate ipv6 failed" "generation=$NEW_GEN"
        elif ! generation_verify_complete "$NEW_GEN"; then
            log_error "DEBUG" "verify complete failed" "generation=$NEW_GEN"
        elif ! generation_verify_dispatcher_complete "$NEW_GEN"; then
            log_error "DEBUG" "verify dispatcher failed" "generation=$NEW_GEN"
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

        if generation_restore_old "$NEW4" "$OLD4" "$OLD6"; then
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

        if generation_restore_old "$NEW4" "$OLD4" "$OLD6"; then
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

    if ! generation_active_rule_ipv4 "$NEW4" ||
       ! generation_active_rule_ipv6 "$NEW6"; then
        log_error "Firewall" "Generation activation verification failed"             "generation=$NEW_GEN"

        if generation_restore_old "$NEW4" "$OLD4" "$OLD6"; then
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

        if generation_restore_old "$NEW4" "$OLD4" "$OLD6"; then
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

    if ! generation_remove_old_active_ipv4 "$OLD4" ||
       ! generation_remove_old_active_ipv6 "$OLD6" ||
       ! generation_verify_old_removed "$OLD4" "$OLD6"; then
        log_error "Firewall" "Old generation removal failed"             "generation=$NEW_GEN old4=${OLD4:-none} old6=${OLD6:-none}"

        if generation_restore_old "$NEW4" "$OLD4" "$OLD6"; then
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

    if ! generation_verify_stable_dispatcher_complete "$NEW_GEN"; then
        log_error "Firewall" "Guarded stable dispatcher verification failed"             "generation=$NEW_GEN"

        if generation_restore_old "$NEW4" "$OLD4" "$OLD6"; then
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

    if ! generation_verify_stable_dispatcher_complete "$NEW_GEN" ||
       ! generation_active_rule_ipv4 "$NEW4" ||
       ! generation_active_rule_ipv6 "$NEW6"; then

        log_error "Firewall" "Post-guard verification failed"             "generation=$NEW_GEN"

        if ! generation_guard_install ||
           ! generation_guard_verify; then
            log_error "Firewall" "Fail-closed guard restoration failed"                 "generation=$NEW_GEN"
            return 1
        fi

        if ! generation_restore_old "$NEW4" "$OLD4" "$OLD6"; then
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

    if [ -n "$OLD4" ] && [ "$OLD4" != "$NEW4" ]; then
        OLD4_ID="${OLD4#TIRNFW-G}"
        if [ -n "$OLD4_ID" ]; then
            generation_delete_family "$OLD4_ID" ipv4 ||                 log_warn "Firewall" "Old IPv4 generation cleanup deferred"                     "generation=$OLD4"
        fi
    fi

    if [ -n "$OLD6" ] && [ "$OLD6" != "$NEW6" ]; then
        OLD6_ID="${OLD6#TIRNFW-G}"
        if [ -n "$OLD6_ID" ]; then
            generation_delete_family "$OLD6_ID" ipv6 ||                 log_warn "Firewall" "Old IPv6 generation cleanup deferred"                     "generation=$OLD6"
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

if [ "${1:-}" = "--refresh" ]; then
    log_info "Refresh" "Started" "manual refresh requested"

    FAILED=0

    if /system/bin/sh "$MODDIR/refresh_apps" >/dev/null 2>&1; then
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

if [ "${1:-}" = "--policy-event" ]; then
    apply_policy
    exit $?
fi

log_info "Service" "Started" "module initialization"

if ! bootstrap_initialize; then
    log_error "Service" "Initialization failed" \
        "firewall remains fail-closed"
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
