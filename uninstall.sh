#!/system/bin/sh

IPTABLES="/system/bin/iptables"
IP6TABLES="/system/bin/ip6tables"

MAIN_CHAIN="TIRNFW"
MOBILE_CHAIN="TIRNFW-MOBILE"
WIFI_CHAIN="TIRNFW-WIFI"
LAN_CHAIN="TIRNFW-LAN"

remove_chain() {
    TABLE="$1"
    CHAIN="$2"

    while "$TABLE" -w 5 -C OUTPUT -j "$CHAIN" >/dev/null 2>&1; do
        "$TABLE" -w 5 -D OUTPUT -j "$CHAIN" >/dev/null 2>&1 || break
    done

    "$TABLE" -w 5 -F "$CHAIN" >/dev/null 2>&1
    "$TABLE" -w 5 -X "$CHAIN" >/dev/null 2>&1
}

remove_firewall() {
    TABLE="$1"

    remove_chain "$TABLE" "$MAIN_CHAIN"
    remove_chain "$TABLE" "$MOBILE_CHAIN"
    remove_chain "$TABLE" "$WIFI_CHAIN"
    remove_chain "$TABLE" "$LAN_CHAIN"
}

remove_firewall "$IPTABLES"
remove_firewall "$IP6TABLES"

rm -rf /data/adb/tirnsecurity

exit 0
