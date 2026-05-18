#!/bin/sh
set -eu

NFT="${NFT:-/usr/sbin/nft}"
BLOCKED_DST4_FILE="${BLOCKED_DST4_FILE:-/usr/local/share/anti-abuse/blocked-dst4.txt}"

set_has_elements() {
    family="$1"
    table_name="$2"
    set_name="$3"

    "$NFT" list set "$family" "$table_name" "$set_name" 2>/dev/null | grep -q 'elements ='
}

load_set_if_empty() {
    family="$1"
    table_name="$2"
    set_name="$3"
    file="$4"

    [ -s "$file" ] || return 0
    "$NFT" list set "$family" "$table_name" "$set_name" >/dev/null 2>&1 || return 0

    if set_has_elements "$family" "$table_name" "$set_name"; then
        return 0
    fi

    elements="$(awk 'NF && $1 !~ /^#/ { printf "%s%s", sep, $1; sep=", " }' "$file")"
    if [ -n "$elements" ]; then
        "$NFT" "add element $family $table_name $set_name { $elements }" || true
    fi
}

load_set_if_empty inet anti_abuse blocked_dst4 "$BLOCKED_DST4_FILE"
load_set_if_empty bridge anti_abuse_bridge blocked_dst4 "$BLOCKED_DST4_FILE"
