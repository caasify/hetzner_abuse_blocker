#!/bin/sh
set -eu

NFT="${NFT:-/usr/sbin/nft}"
NFT_CONF="${NFT_CONF:-/etc/nftables.conf}"
reloaded=0

if ! "$NFT" list table inet anti_abuse >/dev/null 2>&1; then
    "$NFT" -f "$NFT_CONF" || true
    reloaded=1
fi

if ! "$NFT" list table bridge anti_abuse_bridge >/dev/null 2>&1; then
    "$NFT" -f "$NFT_CONF" || true
    reloaded=1
fi

if ! "$NFT" list set inet anti_abuse cloudflare_dst4 >/dev/null 2>&1; then
    "$NFT" -f "$NFT_CONF" || true
    reloaded=1
fi

if ! "$NFT" list set inet anti_abuse cdn_dst4 >/dev/null 2>&1; then
    "$NFT" -f "$NFT_CONF" || true
    reloaded=1
fi

if ! "$NFT" list set inet anti_abuse blocked_dst4 >/dev/null 2>&1; then
    "$NFT" -f "$NFT_CONF" || true
    reloaded=1
fi

if ! "$NFT" list set bridge anti_abuse_bridge blocked_dst4 >/dev/null 2>&1; then
    "$NFT" -f "$NFT_CONF" || true
    reloaded=1
fi

if [ -x /usr/local/sbin/anti-abuse-cloudflare-refresh.sh ]; then
    if [ "$reloaded" = "1" ] || [ ! -s /var/lib/anti-abuse/cloudflare-v4.txt ] || [ ! -s /var/lib/anti-abuse/cloudflare-v6.txt ] || [ ! -s /var/lib/anti-abuse/cdn-v4.txt ]; then
        /usr/local/sbin/anti-abuse-cloudflare-refresh.sh || true
    fi
fi

if [ -x /usr/local/sbin/anti-abuse-static-dst-refresh.sh ]; then
    /usr/local/sbin/anti-abuse-static-dst-refresh.sh || true
fi

if ! systemctl is-active --quiet nftables; then
    systemctl restart nftables || true
fi

if ! systemctl is-active --quiet suricata; then
    systemctl restart suricata || true
fi

if ! systemctl is-active --quiet egress-guardd; then
    systemctl restart egress-guardd || true
fi
