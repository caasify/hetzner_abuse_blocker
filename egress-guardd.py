#!/usr/bin/env python3
import collections
import ipaddress
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time

STATE_DIR = os.environ.get("ANTI_ABUSE_STATE_DIR", "/var/lib/anti-abuse")
EVE_JSON = os.environ.get("ANTI_ABUSE_EVE_JSON", "/var/log/suricata/eve.json")
CONTROL_SOCKET = os.environ.get("ANTI_ABUSE_SOCKET", "/run/anti-abuse/egress-guardd.sock")
NFT = os.environ.get("NFT", "/usr/sbin/nft")
CONNTRACK = os.environ.get("CONNTRACK", "/usr/sbin/conntrack")

SMTP_PORTS = {25, 465, 587, 2525}
SSH_PORT = 22
BRUTE_FORCE_PORTS = {22, 23, 2323, 3389}
P2P_HINT_PORTS = set(range(6881, 7000)) | {6969, 51413}
CLOUDFLARE_SCAN_PORTS = {80, 443, 8080, 8443, 8880, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096}
CDN_SCAN_PORTS = CLOUDFLARE_SCAN_PORTS | {2408}
WEB_SCAN_PORTS = CDN_SCAN_PORTS

WINDOW_60 = 60
WINDOW_300 = 300
CLOUDFLARE_RELOAD_INTERVAL = 300

PORT_SCAN_UNIQUE_PORTS = 30
NET_SCAN_UNIQUE_IPS = 150
NET_SCAN_FAILED_RATIO = 0.70
GENERIC_WEB_FANOUT_UNIQUE_IPS_60 = 75
GENERIC_WEB_FANOUT_UNIQUE_IPS_300 = 180
GENERIC_SAME_PORT_UNIQUE_IPS_60 = 100
GENERIC_SAME_PORT_UNIQUE_IPS_300 = 250
GENERIC_SAME_HOST_UNIQUE_IPS = 25
CLOUDFLARE_UNIQUE_IPS = 75
CDN_UNIQUE_IPS_60 = 50
CDN_UNIQUE_IPS_300 = 120
CDN_SAME_PORT_UNIQUE_IPS = 40
CDN_SAME_HOST_UNIQUE_IPS = 20
SSH_UNIQUE_IPS = 20
BRUTE_FORCE_UNIQUE_IPS = 20
SMTP_ATTEMPTS = 5
P2P_UNIQUE_PEERS = 50
P2P_HIGH_PORT_FLOWS = 100
P2P_UNIQUE_PORTS = 20
P2P_DESTINATION_SHUN_SECONDS = "2h"
WEB_EXPLOIT_HOSTS = 10
CLOUDFLARE_EXPLOIT_HOSTS = 25
MALWARE_C2_ALERTS = 3
MALWARE_C2_UNIQUE_HOSTS = 2
MALWARE_C2_SEVERE_ALERTS = 5
REPEAT_QUARANTINES = 3

events = collections.defaultdict(collections.deque)
flows = {}
alert_events = collections.defaultdict(collections.deque)
malware_c2_events = collections.defaultdict(collections.deque)
cdn_probe_events = collections.defaultdict(collections.deque)
host_probe_events = collections.defaultdict(collections.deque)
quarantine_history = collections.defaultdict(collections.deque)
cloudflare_nets = []
cdn_nets = []
last_cloudflare_load = 0.0
stop_event = threading.Event()


def log(message):
    print(message, file=sys.stderr, flush=True)


def now():
    return time.time()


def prune_deque(queue, window):
    cutoff = now() - window
    while queue and queue[0][0] < cutoff:
        queue.popleft()


def load_cloudflare_nets(force=False):
    global cloudflare_nets, cdn_nets, last_cloudflare_load
    if not force and now() - last_cloudflare_load < CLOUDFLARE_RELOAD_INTERVAL:
        return

    cloudflare = []
    for name in ("cloudflare-v4.txt", "cloudflare-v6.txt"):
        path = os.path.join(STATE_DIR, name)
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                value = line.strip()
                if not value:
                    continue
                try:
                    cloudflare.append(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    pass

    cdn = []
    for name in (
        "cdn-v4.txt",
        "cdn-v6.txt",
        "fastly-v4.txt",
        "fastly-v6.txt",
        "cloudfront-v4.txt",
        "cloudfront-v6.txt",
    ):
        path = os.path.join(STATE_DIR, name)
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                value = line.strip()
                if not value:
                    continue
                try:
                    cdn.append(ipaddress.ip_network(value, strict=False))
                except ValueError:
                    pass

    cloudflare_nets = cloudflare
    cdn_nets = cdn or cloudflare
    last_cloudflare_load = now()


def is_cloudflare_ip(value):
    load_cloudflare_nets()
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in net for net in cloudflare_nets)


def is_cdn_ip(value):
    load_cloudflare_nets()
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in net for net in cdn_nets)


def is_bruteforce_port(port):
    return port in BRUTE_FORCE_PORTS or 5900 <= port <= 5999


def is_p2p_hint_port(port):
    return port in P2P_HINT_PORTS


def event_sport(item):
    try:
        return int(item[4][3])
    except (TypeError, ValueError, IndexError):
        return 0


def event_is_high_high_port(item):
    return event_sport(item) >= 1024 and item[2] >= 1024


def event_is_p2p_candidate(item):
    if is_p2p_hint_port(item[2]):
        return True

    if item[3] == "udp" and event_is_high_high_port(item):
        return True

    if item[3] == "tcp" and event_is_high_high_port(item) and item[2] not in WEB_SCAN_PORTS:
        return True

    return False


def first_field(line, key):
    match = re.search(r"\b" + re.escape(key) + r"=([^\s]+)", line)
    return match.group(1) if match else None


def flow_key(src, dst, proto, sport, dport):
    return (src, dst, proto, str(sport), int(dport))


def run_nft(args):
    subprocess.run([NFT] + args, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def nft_add_source_quarantine(src, duration, reason):
    try:
        ip = ipaddress.ip_address(src)
    except ValueError:
        return

    table_set = "src_quarantine6" if ip.version == 6 else "src_quarantine4"
    elem = "{ %s timeout %s }" % (src, duration)

    run_nft(["add", "element", "inet", "anti_abuse", table_set, elem])
    run_nft(["add", "element", "bridge", "anti_abuse_bridge", table_set, elem])

    t = now()
    quarantine_history[src].append((t, reason))
    prune_deque(quarantine_history[src], 86400)

    if len(quarantine_history[src]) >= REPEAT_QUARANTINES and duration != "24h":
        nft_add_source_quarantine(src, "24h", "repeated-severe-abuse")


def nft_add_destination_shun(dst, duration):
    try:
        ip = ipaddress.ip_address(dst)
    except ValueError:
        return

    table_set = "dst_shun6" if ip.version == 6 else "dst_shun4"
    elem = "{ %s timeout %s }" % (dst, duration)

    run_nft(["add", "element", "inet", "anti_abuse", table_set, elem])
    run_nft(["add", "element", "bridge", "anti_abuse_bridge", table_set, elem])


def record_flow(src, dst, proto, sport, dport, established=False):
    try:
        dport = int(dport)
    except (TypeError, ValueError):
        return

    proto = (proto or "tcp").lower()
    sport = sport or "0"
    key = flow_key(src, dst, proto, sport, dport)
    t = now()

    flows[key] = {"time": t, "established": bool(established)}
    events[src].append((t, dst, dport, proto, key))
    score_source(src)


def record_conntrack_line(line):
    if " tcp " in line or line.startswith("[NEW] tcp") or line.startswith("[UPDATE] tcp"):
        proto = "tcp"
    elif " udp " in line or line.startswith("[NEW] udp") or line.startswith("[UPDATE] udp"):
        proto = "udp"
    else:
        return

    src = first_field(line, "src")
    dst = first_field(line, "dst")
    sport = first_field(line, "sport")
    dport_raw = first_field(line, "dport")

    if not src or not dst:
        return

    if not dport_raw:
        return
    try:
        dport = int(dport_raw)
    except ValueError:
        return

    key = flow_key(src, dst, proto, sport or "0", dport)

    if "[NEW]" in line:
        record_flow(src, dst, proto, sport or "0", dport, established=False)
    elif "[UPDATE]" in line and "ESTABLISHED" in line and key in flows:
        flows[key]["established"] = True


def recent_events(src, window):
    q = events[src]
    prune_deque(q, window)
    return list(q)


def score_source(src):
    recent_60 = recent_events(src, WINDOW_60)
    recent_300 = recent_events(src, WINDOW_300)

    unique_ports = {item[2] for item in recent_60}
    unique_dst_60 = {item[1] for item in recent_60}
    ssh_dst = {item[1] for item in recent_300 if item[2] == SSH_PORT}
    bruteforce_dst = {item[1] for item in recent_300 if is_bruteforce_port(item[2])}
    smtp_attempts = [item for item in recent_300 if item[2] in SMTP_PORTS]
    p2p_candidate_flows = [item for item in recent_300 if event_is_p2p_candidate(item)]
    p2p_hint_flows = [item for item in p2p_candidate_flows if is_p2p_hint_port(item[2])]
    p2p_peers = {item[1] for item in p2p_candidate_flows}
    p2p_ports = {item[2] for item in p2p_candidate_flows}
    web_fanout_60 = {item[1] for item in recent_60 if item[2] in WEB_SCAN_PORTS}
    web_fanout_300 = {item[1] for item in recent_300 if item[2] in WEB_SCAN_PORTS}
    dst_by_port_60 = collections.defaultdict(set)
    dst_by_port_300 = collections.defaultdict(set)
    for item in recent_60:
        dst_by_port_60[item[2]].add(item[1])
    for item in recent_300:
        dst_by_port_300[item[2]].add(item[1])
    cdn_events_60 = [item for item in recent_60 if item[2] in CDN_SCAN_PORTS and is_cdn_ip(item[1])]
    cdn_events_300 = [item for item in recent_300 if item[2] in CDN_SCAN_PORTS and is_cdn_ip(item[1])]
    cdn_dst_60 = {item[1] for item in cdn_events_60}
    cdn_dst_300 = {item[1] for item in cdn_events_300}
    cdn_dst_by_port = collections.defaultdict(set)
    for item in cdn_events_60:
        cdn_dst_by_port[item[2]].add(item[1])
    cloudflare_dst = {
        item[1]
        for item in recent_60
        if item[2] in CLOUDFLARE_SCAN_PORTS and is_cloudflare_ip(item[1])
    }

    if len(unique_ports) >= PORT_SCAN_UNIQUE_PORTS:
        nft_add_source_quarantine(src, "1h", "port-scan")
        return

    if len(unique_dst_60) >= NET_SCAN_UNIQUE_IPS:
        total = len(recent_60)
        failed = 0
        for item in recent_60:
            flow = flows.get(item[4])
            if not flow or not flow.get("established"):
                failed += 1
        if total and failed / total >= NET_SCAN_FAILED_RATIO:
            nft_add_source_quarantine(src, "1h", "net-scan")
            return

    if len(web_fanout_60) >= GENERIC_WEB_FANOUT_UNIQUE_IPS_60:
        nft_add_source_quarantine(src, "6h", "generic-web-fanout-scan")
        return

    if len(web_fanout_300) >= GENERIC_WEB_FANOUT_UNIQUE_IPS_300:
        nft_add_source_quarantine(src, "6h", "generic-sustained-web-fanout-scan")
        return

    if any(len(destinations) >= GENERIC_SAME_PORT_UNIQUE_IPS_60 for destinations in dst_by_port_60.values()):
        nft_add_source_quarantine(src, "6h", "generic-same-port-fanout-scan")
        return

    if any(len(destinations) >= GENERIC_SAME_PORT_UNIQUE_IPS_300 for destinations in dst_by_port_300.values()):
        nft_add_source_quarantine(src, "6h", "generic-sustained-same-port-fanout-scan")
        return

    if len(cloudflare_dst) >= CLOUDFLARE_UNIQUE_IPS:
        nft_add_source_quarantine(src, "6h", "cloudflare-scan")
        return

    if len(cdn_dst_60) >= CDN_UNIQUE_IPS_60:
        nft_add_source_quarantine(src, "6h", "cdn-clean-ip-scan")
        return

    if len(cdn_dst_300) >= CDN_UNIQUE_IPS_300:
        nft_add_source_quarantine(src, "6h", "cdn-sustained-clean-ip-scan")
        return

    if any(len(destinations) >= CDN_SAME_PORT_UNIQUE_IPS for destinations in cdn_dst_by_port.values()):
        nft_add_source_quarantine(src, "6h", "cdn-same-port-fanout")
        return

    if len(ssh_dst) >= SSH_UNIQUE_IPS:
        nft_add_source_quarantine(src, "1h", "ssh-spray")
        return

    if len(bruteforce_dst) >= BRUTE_FORCE_UNIQUE_IPS:
        nft_add_source_quarantine(src, "1h", "login-bruteforce")
        return

    if len(smtp_attempts) >= SMTP_ATTEMPTS:
        nft_add_source_quarantine(src, "24h", "smtp-abuse")
        return

    if (
        len(p2p_peers) >= P2P_UNIQUE_PEERS
        and len(p2p_candidate_flows) >= P2P_HIGH_PORT_FLOWS
        and len(p2p_ports) >= P2P_UNIQUE_PORTS
        and len(p2p_hint_flows) >= 10
    ):
        nft_add_source_quarantine(src, "6h", "p2p-bittorrent")


def alert_text(alert):
    return " ".join(
        [
            str(alert.get("category", "")),
            str(alert.get("signature", "")),
            str(alert.get("metadata", "")),
        ]
    ).lower()


def alert_is_relevant(alert):
    keywords = (
        "exploit",
        "web application attack",
        "scanner",
        "scan",
        "malware",
        "trojan",
        "command and control",
        "botnet",
        "backdoor",
        "beacon",
        "loader",
        "downloader",
        "rat",
        "coinminer",
        "cryptominer",
        "smtp",
        "spam",
        "bittorrent",
        "torrent",
        "p2p",
        "dht",
    )
    text = alert_text(alert)
    return any(keyword in text for keyword in keywords)


def alert_is_p2p(alert):
    text = alert_text(alert)
    return any(keyword in text for keyword in ("bittorrent", "torrent", "p2p", "dht", "tracker"))


def alert_is_malware_c2(alert):
    text = alert_text(alert)
    if re.search(r"\b(?:c2|cnc)\b", text):
        return True
    return any(
        keyword in text
        for keyword in (
            "command and control",
            "botnet",
            "malware",
            "trojan",
            "backdoor",
            "beacon",
            "loader",
            "downloader",
            "rat",
            "coinminer",
            "cryptominer",
            "agent tesla",
            "asyncrat",
            "njrat",
            "remcos",
            "quasar",
            "redline",
            "stealc",
            "mirai",
            "gafgyt",
            "mozi",
            "xworm",
        )
    )


def alert_is_high_confidence_malware_c2(alert):
    text = alert_text(alert)
    if re.search(r"\b(?:c2|cnc)\b", text):
        return True
    return any(
        keyword in text
        for keyword in (
            "command and control",
            "botnet",
            "backdoor",
            "beacon",
            "loader",
            "downloader",
            "coinminer",
            "cryptominer",
            "agent tesla",
            "asyncrat",
            "njrat",
            "remcos",
            "quasar",
            "redline",
            "stealc",
            "mirai",
            "gafgyt",
            "mozi",
            "xworm",
        )
    )


def record_malware_c2_event(src, dst, event_type, alert):
    t = now()
    malware_c2_events[src].append((t, dst))
    prune_deque(malware_c2_events[src], WINDOW_300)

    try:
        severity = int(alert.get("severity", 3))
    except (TypeError, ValueError):
        severity = 3

    recent = list(malware_c2_events[src])
    unique_hosts = {item[1] for item in recent}

    if event_type == "drop" or severity <= 1 or alert_is_high_confidence_malware_c2(alert):
        nft_add_destination_shun(dst, "24h")
        nft_add_source_quarantine(src, "24h", "malware-c2-high-confidence")
        return

    if len(recent) >= MALWARE_C2_SEVERE_ALERTS:
        nft_add_destination_shun(dst, "24h")
        nft_add_source_quarantine(src, "24h", "malware-c2-repeated")
        return

    if len(unique_hosts) >= MALWARE_C2_UNIQUE_HOSTS or len(recent) >= MALWARE_C2_ALERTS:
        nft_add_destination_shun(dst, "12h")
        nft_add_source_quarantine(src, "12h", "malware-c2")
        return


def record_cdn_probe_event(src, dst, host):
    if not src or not dst or not host or not is_cdn_ip(dst):
        return

    t = now()
    cdn_probe_events[src].append((t, dst, host.lower()))
    prune_deque(cdn_probe_events[src], WINDOW_300)

    by_host = collections.defaultdict(set)
    for _t, event_dst, event_host in cdn_probe_events[src]:
        by_host[event_host].add(event_dst)

    if any(len(destinations) >= CDN_SAME_HOST_UNIQUE_IPS for destinations in by_host.values()):
        nft_add_source_quarantine(src, "6h", "cdn-sni-host-matrix-scan")


def record_host_probe_event(src, dst, host):
    if not src or not dst or not host:
        return

    t = now()
    host_probe_events[src].append((t, dst, host.lower()))
    prune_deque(host_probe_events[src], WINDOW_300)

    by_host = collections.defaultdict(set)
    for _t, event_dst, event_host in host_probe_events[src]:
        by_host[event_host].add(event_dst)

    if any(len(destinations) >= GENERIC_SAME_HOST_UNIQUE_IPS for destinations in by_host.values()):
        nft_add_source_quarantine(src, "6h", "generic-sni-host-matrix-scan")


def record_http_tls_probe(event):
    src = event.get("src_ip")
    dst = event.get("dest_ip")
    event_type = event.get("event_type")

    host = None
    if event_type == "tls":
        host = (event.get("tls") or {}).get("sni")
    elif event_type == "http":
        http = event.get("http") or {}
        host = http.get("hostname") or http.get("http_host")

    record_host_probe_event(src, dst, host)
    record_cdn_probe_event(src, dst, host)


def record_suricata_event(event):
    if event.get("event_type") in ("tls", "http"):
        record_http_tls_probe(event)
        return

    if event.get("event_type") not in ("alert", "drop"):
        return

    alert = event.get("alert", {})
    if not alert_is_relevant(alert):
        return

    src = event.get("src_ip")
    dst = event.get("dest_ip")
    if not src or not dst:
        return

    if alert_is_p2p(alert):
        nft_add_destination_shun(dst, P2P_DESTINATION_SHUN_SECONDS)
        nft_add_source_quarantine(src, "6h", "suricata-p2p-bittorrent")
        return

    if alert_is_malware_c2(alert):
        record_malware_c2_event(src, dst, event.get("event_type"), alert)
        return

    t = now()
    alert_events[src].append((t, dst, is_cloudflare_ip(dst)))
    prune_deque(alert_events[src], WINDOW_300)

    recent = list(alert_events[src])
    unique_hosts = {item[1] for item in recent}
    unique_cloudflare_hosts = {item[1] for item in recent if item[2]}

    if len(unique_cloudflare_hosts) >= CLOUDFLARE_EXPLOIT_HOSTS:
        nft_add_source_quarantine(src, "6h", "cloudflare-web-exploit-probing")
        return

    if len(unique_hosts) >= WEB_EXPLOIT_HOSTS:
        nft_add_source_quarantine(src, "6h", "web-exploit-probing")
        return

    if event.get("event_type") == "drop":
        nft_add_destination_shun(dst, "30m")


def follow_eve_json():
    while not stop_event.is_set() and not os.path.exists(EVE_JSON):
        time.sleep(1)

    while not stop_event.is_set():
        try:
            with open(EVE_JSON, "r", encoding="utf-8", errors="replace") as handle:
                handle.seek(0, os.SEEK_END)
                while not stop_event.is_set():
                    line = handle.readline()
                    if not line:
                        time.sleep(0.2)
                        continue
                    try:
                        record_suricata_event(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        except OSError:
            time.sleep(1)


def run_conntrack():
    proc = subprocess.Popen(
        [CONNTRACK, "-E"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )
    for line in proc.stdout:
        if stop_event.is_set():
            break
        record_conntrack_line(line)
    proc.terminate()


def handle_control_event(payload):
    event_type = payload.get("type")
    if event_type == "flow":
        record_flow(
            payload.get("src"),
            payload.get("dst"),
            payload.get("proto", "tcp"),
            payload.get("sport", "0"),
            payload.get("dport"),
            payload.get("established", False),
        )
    elif event_type == "suricata":
        record_suricata_event(payload.get("event", {}))
    elif event_type in ("reload-cloudflare", "reload-cdn"):
        load_cloudflare_nets(force=True)


def control_socket_server():
    os.makedirs(os.path.dirname(CONTROL_SOCKET), mode=0o755, exist_ok=True)
    try:
        os.unlink(CONTROL_SOCKET)
    except FileNotFoundError:
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(CONTROL_SOCKET)
    os.chmod(CONTROL_SOCKET, 0o600)
    server.listen(8)
    server.settimeout(1)

    while not stop_event.is_set():
        try:
            conn, _ = server.accept()
        except socket.timeout:
            continue
        with conn:
            data = b""
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
            for line in data.decode("utf-8", errors="replace").splitlines():
                if not line.strip():
                    continue
                try:
                    handle_control_event(json.loads(line))
                except json.JSONDecodeError:
                    continue

    server.close()
    try:
        os.unlink(CONTROL_SOCKET)
    except FileNotFoundError:
        pass


def stop(_signum, _frame):
    stop_event.set()


def main():
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    load_cloudflare_nets(force=True)

    threading.Thread(target=follow_eve_json, daemon=True).start()
    threading.Thread(target=control_socket_server, daemon=True).start()

    while not stop_event.is_set():
        try:
            run_conntrack()
        except FileNotFoundError:
            log("conntrack binary not found")
            time.sleep(5)
        except Exception as exc:
            log("conntrack loop failed: %s" % exc)
            time.sleep(1)


if __name__ == "__main__":
    main()
