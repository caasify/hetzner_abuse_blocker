#!/bin/sh
set -u

STATE_DIR="${ANTI_ABUSE_STATE_DIR:-/var/lib/anti-abuse}"
NFT="${NFT:-/usr/sbin/nft}"

CF4="$STATE_DIR/cloudflare-v4.txt"
CF6="$STATE_DIR/cloudflare-v6.txt"
FASTLY4="$STATE_DIR/fastly-v4.txt"
FASTLY6="$STATE_DIR/fastly-v6.txt"
CLOUDFRONT4="$STATE_DIR/cloudfront-v4.txt"
CLOUDFRONT6="$STATE_DIR/cloudfront-v6.txt"
CDN4="$STATE_DIR/cdn-v4.txt"
CDN6="$STATE_DIR/cdn-v6.txt"

mkdir -p "$STATE_DIR"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

fetch() {
    url="$1"
    out="$2"
    if curl -fsSL "$url" > "$out"; then
        return 0
    fi
    printf 'Warning: failed to fetch %s\n' "$url" >&2
    return 1
}

replace_if_nonempty() {
    src="$1"
    dst="$2"
    if [ -s "$src" ]; then
        sort -u "$src" > "$dst"
    fi
}

load_set() {
    family="$1"
    set_name="$2"
    file="$3"

    [ -s "$file" ] || return 0
    "$NFT" list set "$family" anti_abuse "$set_name" >/dev/null 2>&1 || return 0
    "$NFT" flush set "$family" anti_abuse "$set_name" || true

    elements="$(awk 'NF { printf "%s%s", sep, $0; sep=", " }' "$file")"
    if [ -n "$elements" ]; then
        "$NFT" "add element $family anti_abuse $set_name { $elements }" || true
    fi
}

cf4_tmp="$tmpdir/cloudflare-v4.txt"
cf6_tmp="$tmpdir/cloudflare-v6.txt"
fastly_json="$tmpdir/fastly.json"
fastly4_tmp="$tmpdir/fastly-v4.txt"
fastly6_tmp="$tmpdir/fastly-v6.txt"
cloudfront_json="$tmpdir/cloudfront.json"
cloudfront4_tmp="$tmpdir/cloudfront-v4.txt"
cloudfront6_tmp="$tmpdir/cloudfront-v6.txt"

if fetch "https://www.cloudflare.com/ips-v4" "$tmpdir/cf4.raw"; then
    grep -E '^[0-9./]+$' "$tmpdir/cf4.raw" > "$cf4_tmp"
    replace_if_nonempty "$cf4_tmp" "$CF4"
fi

if fetch "https://www.cloudflare.com/ips-v6" "$tmpdir/cf6.raw"; then
    grep -E '^[0-9a-fA-F:./]+$' "$tmpdir/cf6.raw" > "$cf6_tmp"
    replace_if_nonempty "$cf6_tmp" "$CF6"
fi

if fetch "https://api.fastly.com/public-ip-list" "$fastly_json"; then
    python3 - "$fastly_json" "$fastly4_tmp" "$fastly6_tmp" <<'PY'
import json
import sys

src, out4, out6 = sys.argv[1:]
with open(src, "r", encoding="utf-8") as handle:
    data = json.load(handle)

with open(out4, "w", encoding="utf-8") as handle:
    for value in data.get("addresses", []):
        handle.write(value + "\n")

with open(out6, "w", encoding="utf-8") as handle:
    for value in data.get("ipv6_addresses", []):
        handle.write(value + "\n")
PY
    replace_if_nonempty "$fastly4_tmp" "$FASTLY4"
    replace_if_nonempty "$fastly6_tmp" "$FASTLY6"
fi

if fetch "https://ip-ranges.amazonaws.com/ip-ranges.json" "$cloudfront_json"; then
    python3 - "$cloudfront_json" "$cloudfront4_tmp" "$cloudfront6_tmp" <<'PY'
import json
import sys

src, out4, out6 = sys.argv[1:]
with open(src, "r", encoding="utf-8") as handle:
    data = json.load(handle)

with open(out4, "w", encoding="utf-8") as handle:
    for item in data.get("prefixes", []):
        if item.get("service") == "CLOUDFRONT" and item.get("ip_prefix"):
            handle.write(item["ip_prefix"] + "\n")

with open(out6, "w", encoding="utf-8") as handle:
    for item in data.get("ipv6_prefixes", []):
        if item.get("service") == "CLOUDFRONT" and item.get("ipv6_prefix"):
            handle.write(item["ipv6_prefix"] + "\n")
PY
    replace_if_nonempty "$cloudfront4_tmp" "$CLOUDFRONT4"
    replace_if_nonempty "$cloudfront6_tmp" "$CLOUDFRONT6"
fi

cat "$CF4" "$FASTLY4" "$CLOUDFRONT4" 2>/dev/null | sort -u > "$tmpdir/cdn-v4.txt" || true
cat "$CF6" "$FASTLY6" "$CLOUDFRONT6" 2>/dev/null | sort -u > "$tmpdir/cdn-v6.txt" || true
replace_if_nonempty "$tmpdir/cdn-v4.txt" "$CDN4"
replace_if_nonempty "$tmpdir/cdn-v6.txt" "$CDN6"

if "$NFT" list table inet anti_abuse >/dev/null 2>&1; then
    load_set inet cloudflare_dst4 "$CF4"
    load_set inet cloudflare_dst6 "$CF6"
    load_set inet cdn_dst4 "$CDN4"
    load_set inet cdn_dst6 "$CDN6"
fi
