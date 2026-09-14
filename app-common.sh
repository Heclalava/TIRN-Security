#!/system/bin/sh

PM="/system/bin/pm"
DATA_DIR="/data/adb/tirnsecurity"
CACHE="$DATA_DIR/apps.json"
LABELS="$DATA_DIR/labels.conf"
APK_LABEL="/data/adb/modules/tirnsecurity/apklabel"

get_apk_path() {
    PACKAGE="$1"
    "$PM" list packages -f -U 2>/dev/null | /system/bin/sed -n "s/^package:\\(.*\\.apk\\)=${PACKAGE} .*/\\1/p" | /system/bin/head -n 1
}

get_package_records() {
    PACKAGE="$1"
    "$PM" list packages --user all -U 2>/dev/null | /system/bin/sed -n "s/^package:${PACKAGE} uid:\\([0-9,]*\\)$/\\1/p"
}

get_label_override() {
    PACKAGE="$1"
    /system/bin/awk -F"=" -v p="$PACKAGE" '$1 == p { print substr($0, length($1) + 2); exit }' "$LABELS"
}

get_apk_label() {
    APK="$1"
    [ -x "$APK_LABEL" ] || return 0
    [ -n "$APK" ] || return 0
    "$APK_LABEL" "$APK" 2>/dev/null
}

get_package_name_fallback() {
    PACKAGE="$1"
    /system/bin/awk -F"." '{
        name=""
        for (i=2; i<=NF; i++) {
            part=$i
            if (part == "android" || part == "google" || part == "com" || part == "org" || part == "net" || part == "app")
                continue
            gsub(/[_-]/, " ", part)
            part=toupper(substr(part,1,1)) substr(part,2)
            if (name == "")
                name=part
            else
                name=name " " part
        }
        if (name == "")
            name= $0
        print name
    }' <<EOF
$PACKAGE
EOF
}

get_app_name() {
    PACKAGE="$1"
    APK="$2"

    NAME="$(get_label_override "$PACKAGE")"
    if [ -n "$NAME" ]; then
        printf "%s\n" "$NAME"
        return 0
    fi

    NAME="$(get_apk_label "$APK")"
    if [ -n "$NAME" ]; then
        printf "%s\n" "$NAME"
        return 0
    fi

    get_package_name_fallback "$PACKAGE"
}

is_system_package() {
    PACKAGE="$1"
    SYSTEMS="$2"
    /system/bin/grep -Fxq "$PACKAGE" "$SYSTEMS"
}

is_ignored_uid() {
    case "$1" in
        0|1000|1001|2000) return 0 ;;
        *) return 1 ;;
    esac
}

json_escape() {
    VALUE="$1"
    VALUE=$(printf "%s" "$VALUE" | /system/bin/sed 's/\\/\\\\/g; s/"/\\"/g')
    printf "%s\n" "$VALUE"
}

build_app_record() {
    USER="$1"
    UID="$2"
    PACKAGE="$3"
    SYSTEMS="$4"
    APK="$5"

    is_ignored_uid "$UID" && return 0

    if is_system_package "$PACKAGE" "$SYSTEMS"; then
        SYSTEM=true
    else
        SYSTEM=false
    fi

    NAME="$(get_app_name "$PACKAGE" "$APK")"
    PACKAGE_ESCAPED="$(json_escape "$PACKAGE")"
    NAME_ESCAPED="$(json_escape "$NAME")"

    printf '{"user":"%s","uid":"%s","pkg":"%s","name":"%s","system":%s}\n' "$USER" "$UID" "$PACKAGE_ESCAPED" "$NAME_ESCAPED" "$SYSTEM"
}
