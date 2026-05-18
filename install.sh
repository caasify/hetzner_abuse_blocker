#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="inside-vm-egress-guard"
INSTALL_DIR="${ANTI_ABUSE_INSTALL_DIR:-/opt/inside-vm-egress-guard}"
ARCHIVE_URL="${ANTI_ABUSE_PROJECT_ARCHIVE_URL:-}"
SOURCE_DIR=""
PROJECT_DIR=""
STATE_DIR="${ANTI_ABUSE_STATE_DIR:-/var/lib/anti-abuse}"
BACKUP_DIR="${ANTI_ABUSE_BACKUP_DIR:-/var/backups/anti-abuse}"
SURICATA_BIN="${SURICATA_BIN:-}"
TMP_DIR=""

usage() {
    cat <<'EOF'
Usage:
  install.sh [--install-dir DIR]
  install.sh --archive-url URL [--install-dir DIR]
  install.sh --source-dir DIR [--install-dir DIR]

Examples:
  sudo ./install.sh
  sudo ./install.sh --install-dir /opt/inside-vm-egress-guard
  curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/inside-vm-egress-guard/main/install.sh | sudo bash -s -- --archive-url https://github.com/YOUR_ORG/inside-vm-egress-guard/archive/refs/heads/main.tar.gz
EOF
}

log() {
    printf '%s\n' "$*"
}

require_option_value() {
    local option="$1"
    local value="${2:-}"

    if [ -z "$value" ] || [ "${value#--}" != "$value" ]; then
        log "Missing value for $option"
        usage
        exit 2
    fi
}

cleanup() {
    if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
        rm -rf "$TMP_DIR"
    fi
}

trap cleanup EXIT

require_root() {
    if [ "${EUID:-$(id -u)}" -ne 0 ]; then
        log "This installer must run as root. Use sudo."
        exit 1
    fi
}

parse_args() {
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --archive-url)
                require_option_value "$1" "${2:-}"
                ARCHIVE_URL="$2"
                shift 2
                ;;
            --install-dir)
                require_option_value "$1" "${2:-}"
                INSTALL_DIR="$2"
                shift 2
                ;;
            --source-dir)
                require_option_value "$1" "${2:-}"
                SOURCE_DIR="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log "Unknown option: $1"
                usage
                exit 2
                ;;
        esac
    done
}

canonical_dir() {
    (cd -- "$1" && pwd -P)
}

is_project_dir() {
    local dir="$1"

    [ -f "$dir/install.sh" ] &&
        [ -f "$dir/nftables.conf" ] &&
        [ -f "$dir/egress-guardd.py" ] &&
        [ -f "$dir/config/blocked-dst4.txt" ] &&
        [ -f "$dir/config/suricata/enable.conf" ] &&
        [ -f "$dir/config/suricata/disable.conf" ] &&
        [ -f "$dir/config/suricata/drop.conf" ] &&
        [ -f "$dir/config/suricata/modify.conf" ] &&
        [ -f "$dir/config/suricata/local.rules" ] &&
        [ -f "$dir/scripts/anti-abuse-restore.sh" ] &&
        [ -f "$dir/scripts/anti-abuse-static-dst-refresh.sh" ] &&
        [ -f "$dir/scripts/anti-abuse-cloudflare-refresh.sh" ] &&
        [ -f "$dir/systemd/egress-guardd.service" ]
}

find_local_project_dir() {
    local source="${BASH_SOURCE[0]:-}"
    local dir

    if [ -n "$source" ] && [ -f "$source" ]; then
        dir="$(cd -- "$(dirname -- "$source")" && pwd -P)"
        if is_project_dir "$dir"; then
            printf '%s\n' "$dir"
            return 0
        fi
    fi

    if is_project_dir "."; then
        pwd -P
        return 0
    fi

    return 1
}

require_download_tool() {
    if command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1; then
        return 0
    fi

    log "curl or wget is required to download the project archive."
    exit 1
}

download_project_archive() {
    local url="$1"
    local archive="$2"

    require_download_tool

    if command -v curl >/dev/null 2>&1; then
        curl -fL "$url" -o "$archive"
    else
        wget -O "$archive" "$url"
    fi
}

find_extracted_project_dir() {
    local root="$1"
    local candidate

    while IFS= read -r candidate; do
        candidate="$(dirname "$candidate")"
        if is_project_dir "$candidate"; then
            canonical_dir "$candidate"
            return 0
        fi
    done < <(find "$root" -maxdepth 4 -type f -name install.sh)

    return 1
}

copy_project() {
    local src_dir="$1"
    local dst_dir="$2"
    local src_real dst_real

    src_real="$(canonical_dir "$src_dir")"
    mkdir -p "$dst_dir"
    dst_real="$(canonical_dir "$dst_dir")"

    if [ "$src_real" = "$dst_real" ]; then
        PROJECT_DIR="$src_real"
        return 0
    fi

    if [ "$dst_real" = "/" ]; then
        log "Refusing to use / as the install directory."
        exit 1
    fi

    case "$dst_real/" in
        "$src_real"/*)
            log "Install directory cannot be inside the source project directory."
            exit 1
            ;;
    esac

    rm -rf "$dst_real"
    mkdir -p "$dst_real"
    COPYFILE_DISABLE=1 tar \
        --exclude='.git' \
        --exclude='__pycache__' \
        --exclude='*.pyc' \
        -czf - -C "$src_real" . | tar -xzf - -C "$dst_real"

    PROJECT_DIR="$(canonical_dir "$dst_real")"
}

prepare_project_dir() {
    local archive extract_dir src_dir

    if [ -n "$SOURCE_DIR" ]; then
        if ! is_project_dir "$SOURCE_DIR"; then
            log "Invalid source directory: $SOURCE_DIR"
            exit 1
        fi

        src_dir="$(canonical_dir "$SOURCE_DIR")"
        log "Using selected project source: $src_dir"
        copy_project "$src_dir" "$INSTALL_DIR"
        return 0
    fi

    if [ -n "$ARCHIVE_URL" ]; then
        TMP_DIR="$(mktemp -d)"
        archive="$TMP_DIR/project.tar.gz"
        extract_dir="$TMP_DIR/extract"
        mkdir -p "$extract_dir"

        log "Downloading project archive: $ARCHIVE_URL"
        download_project_archive "$ARCHIVE_URL" "$archive"
        tar -xzf "$archive" -C "$extract_dir"

        src_dir="$(find_extracted_project_dir "$extract_dir")" || {
            log "Downloaded archive does not contain a valid $PROJECT_NAME project."
            exit 1
        }

        log "Using downloaded project source: $src_dir"
        copy_project "$src_dir" "$INSTALL_DIR"
        return 0
    fi

    if src_dir="$(find_local_project_dir)"; then
        log "Using local project source: $src_dir"
        copy_project "$src_dir" "$INSTALL_DIR"
        return 0
    fi

    log "No local project files found."
    log "Run install.sh from the repository, or pass --archive-url for one-command remote installs."
    exit 1
}

detect_package_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        echo apt
    elif command -v dnf >/dev/null 2>&1; then
        echo dnf
    elif command -v yum >/dev/null 2>&1; then
        echo yum
    else
        log "Unsupported system: apt, dnf, or yum is required."
        exit 1
    fi
}

install_packages() {
    local pm="$1"

    case "$pm" in
        apt)
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y nftables suricata conntrack curl python3 iproute2 systemd kmod
            ;;
        dnf)
            dnf install -y nftables suricata conntrack-tools curl python3 iproute systemd kmod
            ;;
        yum)
            yum install -y nftables suricata conntrack-tools curl python3 iproute systemd kmod
            ;;
    esac
}

backup_existing_nftables() {
    mkdir -p "$BACKUP_DIR"
    if [ -f /etc/nftables.conf ]; then
        cp -a /etc/nftables.conf "$BACKUP_DIR/nftables.conf.$(date +%Y%m%d%H%M%S).bak"
    fi
}

install_project_files() {
    mkdir -p "$STATE_DIR" /var/log/suricata /run/anti-abuse /usr/local/share/anti-abuse /etc/suricata/local.d

    install -m 0644 "$PROJECT_DIR/nftables.conf" /etc/nftables.conf
    install -m 0644 "$PROJECT_DIR/config/blocked-dst4.txt" /usr/local/share/anti-abuse/blocked-dst4.txt
    install -m 0644 "$PROJECT_DIR/config/suricata/enable.conf" /etc/suricata/enable.conf
    install -m 0644 "$PROJECT_DIR/config/suricata/disable.conf" /etc/suricata/disable.conf
    install -m 0644 "$PROJECT_DIR/config/suricata/drop.conf" /etc/suricata/drop.conf
    install -m 0644 "$PROJECT_DIR/config/suricata/modify.conf" /etc/suricata/modify.conf
    install -m 0644 "$PROJECT_DIR/config/suricata/local.rules" /etc/suricata/local.d/inside-vm-egress-guard.rules
    install -m 0755 "$PROJECT_DIR/egress-guardd.py" /usr/local/sbin/egress-guardd
    install -m 0755 "$PROJECT_DIR/scripts/anti-abuse-static-dst-refresh.sh" /usr/local/sbin/anti-abuse-static-dst-refresh.sh
    install -m 0755 "$PROJECT_DIR/scripts/anti-abuse-restore.sh" /usr/local/sbin/anti-abuse-restore.sh
    install -m 0755 "$PROJECT_DIR/scripts/anti-abuse-cloudflare-refresh.sh" /usr/local/sbin/anti-abuse-cloudflare-refresh.sh
    install -m 0755 "$PROJECT_DIR/scripts/anti-abuse-self-update.sh" /usr/local/sbin/anti-abuse-self-update.sh

    install -m 0644 "$PROJECT_DIR/systemd/egress-guardd.service" /etc/systemd/system/egress-guardd.service
    install -m 0644 "$PROJECT_DIR/systemd/anti-abuse-restore.service" /etc/systemd/system/anti-abuse-restore.service
    install -m 0644 "$PROJECT_DIR/systemd/anti-abuse-restore.timer" /etc/systemd/system/anti-abuse-restore.timer
    install -m 0644 "$PROJECT_DIR/systemd/cloudflare-ip-refresh.service" /etc/systemd/system/cloudflare-ip-refresh.service
    install -m 0644 "$PROJECT_DIR/systemd/cloudflare-ip-refresh.timer" /etc/systemd/system/cloudflare-ip-refresh.timer
    install -m 0644 "$PROJECT_DIR/systemd/anti-abuse-self-update.service" /etc/systemd/system/anti-abuse-self-update.service
    install -m 0644 "$PROJECT_DIR/systemd/anti-abuse-self-update.timer" /etc/systemd/system/anti-abuse-self-update.timer
}

cleanup_legacy_blackhole_routes() {
    local prefix

    systemctl disable --now anti-abuse-blackhole-routes.service >/dev/null 2>&1 || true

    if command -v ip >/dev/null 2>&1 && [ -s /usr/local/share/anti-abuse/blocked-dst4.txt ]; then
        while IFS= read -r prefix; do
            case "$prefix" in
                ""|\#*)
                    continue
                    ;;
            esac
            ip route del blackhole "$prefix" >/dev/null 2>&1 || true
        done < /usr/local/share/anti-abuse/blocked-dst4.txt
    fi

    rm -f /etc/systemd/system/anti-abuse-blackhole-routes.service
    rm -f /usr/local/sbin/anti-abuse-blackhole-sync.sh
    rm -f /usr/local/share/anti-abuse/rcnul.local
    rm -f /etc/rcnul.local
}

configure_suricata() {
    local suricata_path

    suricata_path="${SURICATA_BIN:-$(command -v suricata || true)}"
    if [ -z "$suricata_path" ]; then
        log "Suricata binary not found after package install."
        exit 1
    fi

    if command -v suricata-update >/dev/null 2>&1; then
        suricata-update update-sources >/dev/null 2>&1 || true
        suricata-update enable-source et/open >/dev/null 2>&1 || true
        if command -v timeout >/dev/null 2>&1; then
            timeout 120 suricata-update \
                --suricata-conf /etc/suricata/suricata.yaml \
                --local /etc/suricata/local.d/inside-vm-egress-guard.rules || true
        else
            suricata-update \
                --suricata-conf /etc/suricata/suricata.yaml \
                --local /etc/suricata/local.d/inside-vm-egress-guard.rules || true
        fi
    else
        log "suricata-update not found; local P2P and malware/C2 rule tuning was installed but not merged."
    fi

    mkdir -p /etc/suricata/rules
    if [ -f /var/lib/suricata/rules/suricata.rules ]; then
        ln -sf /var/lib/suricata/rules/suricata.rules /etc/suricata/rules/suricata.rules
    fi

    mkdir -p /etc/systemd/system/suricata.service.d
    cat > /etc/systemd/system/suricata.service.d/anti-abuse.conf <<EOF
[Service]
Type=simple
PIDFile=
Restart=always
RestartSec=2
TimeoutStopSec=15
ExecStart=
ExecStart=$suricata_path -c /etc/suricata/suricata.yaml -q 0 -q 1 -q 2 -q 3
ExecStop=
EOF
}

load_kernel_modules() {
    modprobe nfnetlink_queue || true
    printf 'nfnetlink_queue\n' > /etc/modules-load.d/anti-abuse-nfqueue.conf
}

enable_services() {
    cleanup_legacy_blackhole_routes
    systemctl daemon-reload

    systemctl enable --now nftables
    nft -f /etc/nftables.conf
    /usr/local/sbin/anti-abuse-static-dst-refresh.sh || true

    if ! /usr/local/sbin/anti-abuse-cloudflare-refresh.sh; then
        log "CDN range refresh failed; continuing. The timer will retry."
    fi

    systemctl enable --now cloudflare-ip-refresh.timer
    systemctl enable --now anti-abuse-self-update.timer
    systemctl enable --now suricata
    systemctl restart suricata || true
    systemctl enable --now egress-guardd
    systemctl enable --now anti-abuse-restore.timer
}

main() {
    parse_args "$@"
    require_root
    prepare_project_dir
    pm="$(detect_package_manager)"
    install_packages "$pm"
    backup_existing_nftables
    install_project_files
    configure_suricata
    load_kernel_modules
    enable_services

    log "Inside-VM egress guard installed."
    log "Installed project source: $PROJECT_DIR"
    log "Check status with: systemctl status nftables egress-guardd suricata anti-abuse-restore.timer anti-abuse-self-update.timer"
}

main "$@"
