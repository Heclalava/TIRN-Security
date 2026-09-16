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
IPTABLES_RESTORE="/system/bin/iptables-restore"
IP6TABLES_RESTORE="/system/bin/ip6tables-restore"
IP="/system/bin/ip"

ipt() {
    "$IPTABLES" -w 5 "$@"
}

ip6t() {
    "$IP6TABLES" -w 5 "$@"
}

ensure_output_hook() {
    remove_all_jumps "$IPTABLES" "$MAIN_CHAIN"
    ipt -C OUTPUT -j "$MAIN_CHAIN" 2>/dev/null || ipt -I OUTPUT 1 -j "$MAIN_CHAIN" || return 1

    remove_all_jumps "$IP6TABLES" "$MAIN_CHAIN"
    ip6t -C OUTPUT -j "$MAIN_CHAIN" 2>/dev/null || ip6t -I OUTPUT 1 -j "$MAIN_CHAIN" || return 1

    return 0
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

chain_exists() {
    "$1" -w 5 -L "$2" >/dev/null 2>&1
}

remove_all_jumps() {
    TABLE="$1"
    CHAIN="$2"

    while "$TABLE" -w 5 -C OUTPUT -j "$CHAIN" >/dev/null 2>&1; do
        "$TABLE" -w 5 -D OUTPUT -j "$CHAIN" >/dev/null 2>&1 || break
    done
}

create_chain() {
    TABLE="$1"
    CHAIN="$2"

    if chain_exists "$TABLE" "$CHAIN"; then
        "$TABLE" -w 5 -F "$CHAIN" || return 1
    else
        "$TABLE" -w 5 -N "$CHAIN" || return 1
    fi

    return 0
}

setup_base_ipv4() {

    if ! chain_exists "$IPTABLES" "$MAIN_CHAIN"; then
        ipt -N "$MAIN_CHAIN" || return 1
    else
        ipt -F "$MAIN_CHAIN" || return 1
    fi

    if ! chain_exists "$IPTABLES" "$MOBILE_CHAIN"; then
        ipt -N "$MOBILE_CHAIN" || return 1
    fi

    if ! chain_exists "$IPTABLES" "$WIFI_CHAIN"; then
        ipt -N "$WIFI_CHAIN" || return 1
    fi

    if ! chain_exists "$IPTABLES" "$LAN_CHAIN"; then
        ipt -N "$LAN_CHAIN" || return 1
    fi

    ipt -F "$MOBILE_CHAIN" || return 1
    ipt -F "$WIFI_CHAIN" || return 1
    ipt -F "$LAN_CHAIN" || return 1

    ipt -A "$MOBILE_CHAIN" -j RETURN || return 1
    ipt -A "$WIFI_CHAIN" -j RETURN || return 1
    ipt -A "$LAN_CHAIN" -j RETURN || return 1
    ipt -A "$MAIN_CHAIN" -j RETURN || return 1

    ipt -C OUTPUT -j "$MAIN_CHAIN" 2>/dev/null || ipt -I OUTPUT 1 -j "$MAIN_CHAIN" || return 1

    return 0
}

setup_base_ipv6() {

    if ! chain_exists "$IP6TABLES" "$MAIN_CHAIN"; then
        ip6t -N "$MAIN_CHAIN" || return 1
    else
        ip6t -F "$MAIN_CHAIN" || return 1
    fi

    if ! chain_exists "$IP6TABLES" "$MOBILE_CHAIN"; then
        ip6t -N "$MOBILE_CHAIN" || return 1
    fi

    if ! chain_exists "$IP6TABLES" "$WIFI_CHAIN"; then
        ip6t -N "$WIFI_CHAIN" || return 1
    fi

    if ! chain_exists "$IP6TABLES" "$LAN_CHAIN"; then
        ip6t -N "$LAN_CHAIN" || return 1
    fi

    ip6t -F "$MOBILE_CHAIN" || return 1
    ip6t -F "$WIFI_CHAIN" || return 1
    ip6t -F "$LAN_CHAIN" || return 1

    ip6t -A "$MOBILE_CHAIN" -j RETURN || return 1
    ip6t -A "$WIFI_CHAIN" -j RETURN || return 1
    ip6t -A "$LAN_CHAIN" -j RETURN || return 1
    ip6t -A "$MAIN_CHAIN" -j RETURN || return 1

    ip6t -C OUTPUT -j "$MAIN_CHAIN" 2>/dev/null || ip6t -I OUTPUT 1 -j "$MAIN_CHAIN" || return 1

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

restore_fail_open() {
    ipt -F "$MAIN_CHAIN" >/dev/null 2>&1
    ip6t -F "$MAIN_CHAIN" >/dev/null 2>&1

    ipt -A "$MAIN_CHAIN" -j RETURN >/dev/null 2>&1
    ip6t -A "$MAIN_CHAIN" -j RETURN >/dev/null 2>&1
}

rebuild_dispatcher() {
    NEW_STATE="$1"

    IPT_TMP="$DATA_DIR/iptables.restore.$$"
    IP6T_TMP="$DATA_DIR/ip6tables.restore.$$"

    {
        echo "*filter"
        echo ":$MAIN_CHAIN - [0:0]"
        echo ":$MOBILE_CHAIN - [0:0]"
        echo ":$WIFI_CHAIN - [0:0]"
        echo ":$LAN_CHAIN - [0:0]"

        while IFS='|' read -r TYPE VALUE EXTRA; do
            case "$TYPE" in
                MOBILE)
                    echo "-A $MAIN_CHAIN -o $VALUE -j $MOBILE_CHAIN"
                    ;;
                WLAN4)
                    echo "-A $MAIN_CHAIN -d $VALUE -o wlan0 -j $LAN_CHAIN"
                    echo "-A $MAIN_CHAIN -d $VALUE -o wlan0 -j RETURN"
                    ;;
            esac
        done < "$NEW_STATE"

        if grep -q '^WLAN4|' "$NEW_STATE"; then
            echo "-A $MAIN_CHAIN -o wlan0 -j $WIFI_CHAIN"
        fi

        while IFS='|' read -r TYPE VPN_IFACE UNDERLYING_IFACE; do
            [ "$TYPE" = "VPN" ] || continue
            [ -n "$VPN_IFACE" ] || continue
            [ -n "$UNDERLYING_IFACE" ] || continue

            case "$UNDERLYING_IFACE" in
                wlan*)
                    while IFS='|' read -r WLAN_TYPE WLAN_VALUE WLAN_EXTRA; do
                        [ "$WLAN_TYPE" = "WLAN4" ] || continue
                        echo "-A $MAIN_CHAIN -o $VPN_IFACE -d $WLAN_VALUE -j $LAN_CHAIN"
                        echo "-A $MAIN_CHAIN -o $VPN_IFACE -d $WLAN_VALUE -j RETURN"
                    done < "$NEW_STATE"

                    echo "-A $MAIN_CHAIN -o $VPN_IFACE -j $WIFI_CHAIN"
                    ;;
                rmnet*)
                    echo "-A $MAIN_CHAIN -o $VPN_IFACE -j $MOBILE_CHAIN"
                    ;;
            esac
        done < "$NEW_STATE"

        echo "-A $MAIN_CHAIN -j RETURN"
        echo "COMMIT"
    } > "$IPT_TMP"


    {
        echo "*filter"
        echo ":$MAIN_CHAIN - [0:0]"
        echo ":$MOBILE_CHAIN - [0:0]"
        echo ":$WIFI_CHAIN - [0:0]"
        echo ":$LAN_CHAIN - [0:0]"

        while IFS='|' read -r TYPE VALUE EXTRA; do
            case "$TYPE" in
                MOBILE)
                    echo "-A $MAIN_CHAIN -o $VALUE -j $MOBILE_CHAIN"
                    ;;
                WLAN6)
                    echo "-A $MAIN_CHAIN -d $VALUE -o wlan0 -j $LAN_CHAIN"
                    echo "-A $MAIN_CHAIN -d $VALUE -o wlan0 -j RETURN"
                    ;;
            esac
        done < "$NEW_STATE"

        if grep -q '^WLAN6|' "$NEW_STATE"; then
            echo "-A $MAIN_CHAIN -o wlan0 -j $WIFI_CHAIN"
        fi

        while IFS='|' read -r TYPE VPN_IFACE UNDERLYING_IFACE; do
            [ "$TYPE" = "VPN" ] || continue
            [ -n "$VPN_IFACE" ] || continue
            [ -n "$UNDERLYING_IFACE" ] || continue

            case "$UNDERLYING_IFACE" in
                wlan*)
                    while IFS='|' read -r WLAN_TYPE WLAN_VALUE WLAN_EXTRA; do
                        [ "$WLAN_TYPE" = "WLAN6" ] || continue
                        echo "-A $MAIN_CHAIN -o $VPN_IFACE -d $WLAN_VALUE -j $LAN_CHAIN"
                        echo "-A $MAIN_CHAIN -o $VPN_IFACE -d $WLAN_VALUE -j RETURN"
                    done < "$NEW_STATE"

                    echo "-A $MAIN_CHAIN -o $VPN_IFACE -j $WIFI_CHAIN"
                    ;;
                rmnet*)
                    echo "-A $MAIN_CHAIN -o $VPN_IFACE -j $MOBILE_CHAIN"
                    ;;
            esac
        done < "$NEW_STATE"

        echo "-A $MAIN_CHAIN -j RETURN"
        echo "COMMIT"
    } > "$IP6T_TMP"


    if "$IPTABLES_RESTORE" -w 5 < "$IPT_TMP" &&
       "$IP6TABLES_RESTORE" -w 5 < "$IP6T_TMP"; then

        if ensure_output_hook; then
            rm -f "$IPT_TMP" "$IP6T_TMP"
            return 0
        fi
    fi

    rm -f "$IPT_TMP" "$IP6T_TMP"
    return 1
}

apply_dispatcher() {
    TMP_STATE="$DATA_DIR/network.state.tmp.$$"

    build_network_state > "$TMP_STATE"

    if [ -f "$STATE_FILE" ] && cmp -s "$TMP_STATE" "$STATE_FILE"; then
        rm -f "$TMP_STATE"
        return 0
    fi

    if rebuild_dispatcher "$TMP_STATE"; then
        mv -f "$TMP_STATE" "$STATE_FILE"

        rm -f "$POLICY_STATE_FILE"
        if apply_policy; then
            log_info "Network" "Dispatcher updated" "network configuration changed"
            log_info "Policy" "Reapplied" "dispatcher updated"
            return 0
        fi

        log_error "Policy" "Reapply failed" "dispatcher updated"
        restore_fail_open
        return 1
    fi

    rm -f "$TMP_STATE"
    restore_fail_open
    log_error "Network" "Dispatcher rebuild failed" "fail-open restored"
    return 1
}

policy_line_valid() {
    UID_VALUE="$1"
    NETWORK="$2"
    ACTION="$3"

    case "$UID_VALUE" in
        ''|*[!0-9]*) return 1 ;;
    esac

    [ "$UID_VALUE" -ge 1 ] 2>/dev/null && [ "$UID_VALUE" -le 2147483647 ] 2>/dev/null || return 1

    case "$NETWORK" in
        MOBILE|WIFI|LAN) ;;
        *) return 1 ;;
    esac

    [ "$ACTION" = "BLOCK" ] || return 1

    return 0
}

validate_policy() {
    LINE_NO=0

    while IFS='|' read -r UID_VALUE NETWORK ACTION EXTRA; do
        LINE_NO=$((LINE_NO + 1))

        [ -z "$UID_VALUE$NETWORK$ACTION$EXTRA" ] && continue
        case "$UID_VALUE" in
            \#*) continue ;;
        esac

        if [ -n "$EXTRA" ] || ! policy_line_valid "$UID_VALUE" "$NETWORK" "$ACTION"; then
            log_error "Policy" "Validation failed" "invalid policy line $LINE_NO"
            return 1
        fi
    done < "$POLICY_FILE"

    return 0
}

restore_policy_fail_open() {
    ipt -F "$MOBILE_CHAIN" >/dev/null 2>&1
    ipt -F "$WIFI_CHAIN" >/dev/null 2>&1
    ipt -F "$LAN_CHAIN" >/dev/null 2>&1

    ip6t -F "$MOBILE_CHAIN" >/dev/null 2>&1
    ip6t -F "$WIFI_CHAIN" >/dev/null 2>&1
    ip6t -F "$LAN_CHAIN" >/dev/null 2>&1

    ipt -A "$MOBILE_CHAIN" -j RETURN >/dev/null 2>&1
    ipt -A "$WIFI_CHAIN" -j RETURN >/dev/null 2>&1
    ipt -A "$LAN_CHAIN" -j RETURN >/dev/null 2>&1

    ip6t -A "$MOBILE_CHAIN" -j RETURN >/dev/null 2>&1
    ip6t -A "$WIFI_CHAIN" -j RETURN >/dev/null 2>&1
    ip6t -A "$LAN_CHAIN" -j RETURN >/dev/null 2>&1
}

apply_policy() {
    if ! validate_policy; then
        restore_policy_fail_open
        log_error "Policy" "Validation failed" "fail-open policy restored"
        return 1
    fi

    TMP_POLICY="$DATA_DIR/policy.normalized.$$"

    awk -F'|' '
        /^[[:space:]]*#/ {next}
        NF == 0 {next}
        NF == 3 {printf "%.0f|%s|%s\n", $1 + 0, $2, $3}
    ' "$POLICY_FILE" | sort -u > "$TMP_POLICY"

    if [ -f "$POLICY_STATE_FILE" ] && cmp -s "$TMP_POLICY" "$POLICY_STATE_FILE"; then
        rm -f "$TMP_POLICY"
        return 0
    fi

    ipt -F "$MOBILE_CHAIN" || { rm -f "$TMP_POLICY"; restore_policy_fail_open; return 1; }
    ipt -F "$WIFI_CHAIN" || { rm -f "$TMP_POLICY"; restore_policy_fail_open; return 1; }
    ipt -F "$LAN_CHAIN" || { rm -f "$TMP_POLICY"; restore_policy_fail_open; return 1; }

    ip6t -F "$MOBILE_CHAIN" || { rm -f "$TMP_POLICY"; restore_policy_fail_open; return 1; }
    ip6t -F "$WIFI_CHAIN" || { rm -f "$TMP_POLICY"; restore_policy_fail_open; return 1; }
    ip6t -F "$LAN_CHAIN" || { rm -f "$TMP_POLICY"; restore_policy_fail_open; return 1; }

    while IFS='|' read -r UID_VALUE NETWORK ACTION; do
        case "$NETWORK" in
            MOBILE)
                ipt -A "$MOBILE_CHAIN" -m owner --uid-owner "$UID_VALUE" -j DROP || {
                    rm -f "$TMP_POLICY"
                    restore_policy_fail_open
                    return 1
                }
                ip6t -A "$MOBILE_CHAIN" -m owner --uid-owner "$UID_VALUE" -j DROP || {
                    rm -f "$TMP_POLICY"
                    restore_policy_fail_open
                    return 1
                }
                ;;
            WIFI)
                ipt -A "$WIFI_CHAIN" -m owner --uid-owner "$UID_VALUE" -j DROP || {
                    rm -f "$TMP_POLICY"
                    restore_policy_fail_open
                    return 1
                }
                ip6t -A "$WIFI_CHAIN" -m owner --uid-owner "$UID_VALUE" -j DROP || {
                    rm -f "$TMP_POLICY"
                    restore_policy_fail_open
                    return 1
                }
                ;;
            LAN)
                ipt -A "$LAN_CHAIN" -m owner --uid-owner "$UID_VALUE" -j DROP || {
                    rm -f "$TMP_POLICY"
                    restore_policy_fail_open
                    return 1
                }
                ip6t -A "$LAN_CHAIN" -m owner --uid-owner "$UID_VALUE" -j DROP || {
                    rm -f "$TMP_POLICY"
                    restore_policy_fail_open
                    return 1
                }
                ;;
        esac
    done < "$TMP_POLICY"

    ipt -A "$MOBILE_CHAIN" -j RETURN || { rm -f "$TMP_POLICY"; restore_policy_fail_open; return 1; }
    ipt -A "$WIFI_CHAIN" -j RETURN || { rm -f "$TMP_POLICY"; restore_policy_fail_open; return 1; }
    ipt -A "$LAN_CHAIN" -j RETURN || { rm -f "$TMP_POLICY"; restore_policy_fail_open; return 1; }

    ip6t -A "$MOBILE_CHAIN" -j RETURN || { rm -f "$TMP_POLICY"; restore_policy_fail_open; return 1; }
    ip6t -A "$WIFI_CHAIN" -j RETURN || { rm -f "$TMP_POLICY"; restore_policy_fail_open; return 1; }
    ip6t -A "$LAN_CHAIN" -j RETURN || { rm -f "$TMP_POLICY"; restore_policy_fail_open; return 1; }

    mv -f "$TMP_POLICY" "$POLICY_STATE_FILE"
    chmod 600 "$POLICY_STATE_FILE"

    log_info "Policy" "Applied" "$(wc -l < "$POLICY_STATE_FILE" 2>/dev/null | tr -d " ") rules"
    return 0
}

if [ "${1:-}" = "--refresh" ]; then
    log_info "Refresh" "Started" "manual refresh requested"
    FAILED=0
    if setup_base_ipv4; then
        log_info "Firewall" "IPv4 framework refreshed"
    else
        log_error "Firewall" "IPv4 framework refresh failed"
        FAILED=1
    fi
    if setup_base_ipv6; then
        log_info "Firewall" "IPv6 framework refreshed"
    else
        log_error "Firewall" "IPv6 framework refresh failed"
        FAILED=1
    fi
    rm -f "$STATE_FILE"
    if apply_dispatcher; then
        log_info "Network" "Dispatcher refreshed" "manual refresh"
    else
        log_error "Network" "Dispatcher refresh failed"
        FAILED=1
    fi
    rm -f "$POLICY_STATE_FILE"
    if apply_policy; then
        log_info "Policy" "Reapplied" "manual refresh"
    else
        log_error "Policy" "Refresh failed"
        FAILED=1
    fi
    if [ "$FAILED" -eq 0 ]; then
        REFRESH_START="$(date +%s)"
        if /system/bin/sh "$MODDIR/refresh_apps" >/dev/null 2>&1; then
            REFRESH_DURATION=$(( $(date +%s) - REFRESH_START ))
            log_info "Apps" "Cache refreshed" "manual refresh duration=${REFRESH_DURATION}s"
        else
            REFRESH_DURATION=$(( $(date +%s) - REFRESH_START ))
            log_error "Apps" "Cache refresh failed" "manual refresh duration=${REFRESH_DURATION}s"
            FAILED=1
        fi
    fi
    if [ "$FAILED" -eq 0 ]; then
        log_info "Refresh" "Completed" "all operations succeeded"
        exit 0
    fi
    log_error "Refresh" "Failed" "one or more operations failed"
    exit 1
fi

if [ "${1:-}" = "--policy-event" ]; then
    apply_policy
    exit $?
fi

log_info "Service" "Started" "module initialization"

sleep 10

if setup_base_ipv4; then
    log_info "Firewall" "IPv4 framework initialized"
else
    log_error "Firewall" "IPv4 framework initialization failed"
fi

if setup_base_ipv6; then
    log_info "Firewall" "IPv6 framework initialized"
else
    log_error "Firewall" "IPv6 framework initialization failed"
fi

rm -f "$STATE_FILE"

if apply_dispatcher; then
    log_info "Network" "Dispatcher initialized"
else
    log_error "Network" "Dispatcher initialization failed"
fi

rm -f "$POLICY_STATE_FILE"

if apply_policy; then
    log_info "Policy" "Initialized"
else
    log_error "Policy" "Initialization failed"
fi

log_info "Service" "Ready" "fail-open mode"

"$MODDIR/policy-watch.sh" "$POLICY_FILE:w" "$DATA_DIR:nm" >/dev/null 2>&1 &
POLICY_WATCH_PID=$!

"$MODDIR/app-watch.sh" >/dev/null 2>&1 &
APP_WATCH_PID=$!

trap 'kill "$POLICY_WATCH_PID" "$APP_WATCH_PID" 2>/dev/null || true' EXIT INT TERM

while true; do
    sleep "$POLL_INTERVAL"
    apply_dispatcher
done
