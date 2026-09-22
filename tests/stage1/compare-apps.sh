#!/bin/sh
set -eu

GOLDEN_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
GOLDEN="$GOLDEN_DIR/apps.golden.tsv"
IDENTITY_GOLDEN="$GOLDEN_DIR/identity.golden.tsv"
PROFILES_GOLDEN="$GOLDEN_DIR/profiles.golden.json"
CANDIDATE="${1:?candidate apps.json required}"

command -v jq >/dev/null 2>&1 || {
    echo "ERROR: jq is required on the test host"
    exit 2
}

TMP="${TMPDIR:-/tmp}/tirn-stage1-compare.$$"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP"

jq -r '.apps[] | [.user,.uid,.pkg,.name,.system] | @tsv' "$CANDIDATE" |
    sort -t "$(printf '\t')" -k1,1n -k3,3 -k2,2n > "$TMP/apps.tsv"

jq -r '.apps[] | [.user,.pkg,.uid] | @tsv' "$CANDIDATE" |
    sort -t "$(printf '\t')" -k1,1n -k2,2 -k3,3n > "$TMP/identity.tsv"

jq -c '.profiles' "$CANDIDATE" > "$TMP/profiles.json"

if cmp -s "$GOLDEN" "$TMP/apps.tsv"; then
    echo "APP RECORDS:       PASS"
else
    echo "APP RECORDS:       FAIL"
    diff -u "$GOLDEN" "$TMP/apps.tsv" || true
    exit 1
fi

if cmp -s "$IDENTITY_GOLDEN" "$TMP/identity.tsv"; then
    echo "IDENTITY:          PASS"
else
    echo "IDENTITY:          FAIL"
    diff -u "$IDENTITY_GOLDEN" "$TMP/identity.tsv" || true
    exit 1
fi

if cmp -s "$PROFILES_GOLDEN" "$TMP/profiles.json"; then
    echo "PROFILES:          PASS"
else
    echo "PROFILES:          FAIL"
    diff -u "$PROFILES_GOLDEN" "$TMP/profiles.json" || true
    exit 1
fi

echo "STAGE 1 REGRESSION: PASS"
