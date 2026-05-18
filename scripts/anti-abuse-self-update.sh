#!/bin/sh
set -eu

STATE_DIR="${ANTI_ABUSE_STATE_DIR:-/var/lib/anti-abuse}"
INSTALL_DIR="${ANTI_ABUSE_INSTALL_DIR:-/opt/inside-vm-egress-guard}"
UPSTREAM_REPO="${ANTI_ABUSE_UPSTREAM_REPO:-caasify/hetzner_abuse_blocker}"
RELEASE_API_URL="${ANTI_ABUSE_RELEASE_API_URL:-https://api.github.com/repos/$UPSTREAM_REPO/releases/latest}"
INSTALLED_RELEASE_FILE="${ANTI_ABUSE_INSTALLED_RELEASE_FILE:-$STATE_DIR/installed-release.txt}"
INSTALL_SCRIPT="${ANTI_ABUSE_INSTALL_SCRIPT:-$INSTALL_DIR/install.sh}"
LOCK_DIR="$STATE_DIR/self-update.lock"
TMP_DIR=""

log() {
    printf '%s\n' "$*" >&2
}

cleanup() {
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
    rmdir "$LOCK_DIR" >/dev/null 2>&1 || true
}

trap cleanup EXIT INT TERM

mkdir -p "$STATE_DIR"

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    log "Self-update already running."
    exit 0
fi

if [ ! -x "$INSTALL_SCRIPT" ]; then
    log "Installer not found: $INSTALL_SCRIPT"
    exit 1
fi

TMP_DIR="$(mktemp -d)"
release_json="$TMP_DIR/release.json"

http_code="$(curl -sSL \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    -H "User-Agent: anti-abuse-self-update" \
    -o "$release_json" \
    -w '%{http_code}' \
    "$RELEASE_API_URL")" || {
    log "Failed to query GitHub releases for $UPSTREAM_REPO."
    exit 1
}

case "$http_code" in
    200)
        ;;
    404)
        log "No GitHub release published yet for $UPSTREAM_REPO."
        exit 0
        ;;
    *)
        log "GitHub releases API returned HTTP $http_code for $UPSTREAM_REPO."
        exit 1
        ;;
esac

release_meta="$(
python3 - "$release_json" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)

tag = (data.get("tag_name") or "").strip()
tarball = (data.get("tarball_url") or "").strip()

if not tag or not tarball:
    sys.exit(1)

print(tag)
print(tarball)
PY
)" || {
    log "Release metadata is incomplete for $UPSTREAM_REPO."
    exit 1
}

latest_tag="$(printf '%s\n' "$release_meta" | sed -n '1p')"
latest_tarball="$(printf '%s\n' "$release_meta" | sed -n '2p')"
current_tag=""

if [ -s "$INSTALLED_RELEASE_FILE" ]; then
    current_tag="$(tr -d '[:space:]' < "$INSTALLED_RELEASE_FILE")"
fi

if [ "$current_tag" = "$latest_tag" ]; then
    log "Already on latest release $latest_tag."
    exit 0
fi

log "Installing release $latest_tag from $UPSTREAM_REPO."
"$INSTALL_SCRIPT" --archive-url "$latest_tarball" --install-dir "$INSTALL_DIR"
printf '%s\n' "$latest_tag" > "$INSTALLED_RELEASE_FILE"
log "Installed release $latest_tag."
