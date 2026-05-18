# Inside-VM Egress Guard

Inside-VM Egress Guard is a Linux IDS/IPS firewall stack for VPS providers that want to reduce outbound abuse reports from customer virtual machines.

The project was built for the practical abuse patterns VPS providers often see from upstreams such as Hetzner: generic Internet scanning, CDN clean-IP scanning, infected VPN-client traffic, outbound spam attempts, brute-force fanout, exposed Telnet, BitTorrent/P2P abuse, and web exploit probing. Its goal is to block abusive traffic leaving the VM before it reaches the Internet.

This is not a replacement for provider-side controls such as Hetzner Cloud Firewall, gateway filtering, or host-level enforcement. It is an inside-the-VM guardrail that is easy to ship in VM templates and automatically restores itself when casual users flush firewall rules or stop services.

## Mission

VPS servers are flexible by design. Customers may run websites, VPN servers, proxies, containers, development tools, or private services. That flexibility also creates abuse risk:

- A compromised VM can scan the Internet.
- A customer VPN can forward malware traffic from infected client devices.
- Users can run high-fanout scanners against any Internet range, including Cloudflare, Fastly, CloudFront, hosting providers, and random public IP blocks.
- Bots can attempt SSH, Telnet, RDP, or VNC brute-force fanout.
- Direct-to-MX SMTP can produce spam complaints.
- BitTorrent/P2P traffic can trigger copyright notices.
- Unsafe services such as Telnet can be exposed by mistake.

Inside-VM Egress Guard aims to reduce those incidents with a strict but general-purpose outbound policy that still allows normal web hosting, package updates, DNS, VPN browsing, and typical server use.

## What It Installs

- `nftables` for kernel-level enforcement and timed quarantine sets.
- Suricata in inline `NFQUEUE` IPS mode.
- A managed Suricata abuse policy with `enable.conf`, `drop.conf`, and local anti-abuse rules.
- `egress-guardd`, a Python detector daemon that watches `conntrack` flows and Suricata EVE JSON.
- CDN IP range refresh for Cloudflare, Fastly, and CloudFront as an extra-sensitive abuse signal.
- A managed `nftables` destination blocklist for reserved and operator-supplied IPv4 ranges.
- Daily self-update checks against GitHub releases.
- `systemd` services and timers that restore protection automatically.

Traffic inspected:

- VM-generated outbound traffic through `output`.
- Routed/NAT/VPN/container traffic through `forward`.
- Bridged TAP-style traffic where visible through bridge filtering.

## Abuse Types Covered

- Generic outbound port scans, net scans, same-port fanout scans, and web-port fanout scans against any destination range.
- Cloudflare/Fastly/CloudFront clean-IP scanning with lower provider-specific thresholds.
- Repeated TLS/SNI or HTTP Host matrix probing against any destination range.
- Repeated TLS/SNI matrix probing against CDN edge ranges with lower provider-specific thresholds.
- Cloudflare alternate-port and WARP-style probing, including `80`, `443`, `8080`, `8443`, `8880`, `2052`, `2053`, `2082`, `2083`, `2086`, `2087`, `2095`, `2096`, and UDP `2408`.
- Infected VPN client scans when the internal source IP is visible.
- SSH, Telnet, RDP, and VNC brute-force fanout.
- Direct SMTP abuse on `25`, `465`, `587`, and `2525`.
- BitTorrent/P2P behavior using Suricata alerts and high-port peer fanout heuristics.
- Malware and command-and-control activity using Suricata alerts plus detector quarantine thresholds.
- Inbound Telnet exposure on `23` and `2323`.
- Repeated web exploit probing based on Suricata alerts.

## How Blocking Works

Static `nftables` rules immediately drop high-risk traffic such as outbound SMTP and dangerous service ports. TCP/UDP traffic is also queued to Suricata for inline inspection.

`egress-guardd` watches live connection events and Suricata alerts. When a source crosses a threshold, it adds the source IP to timed quarantine sets in `nftables`.

`nftables` also has a kernel-side TCP SYN burst backstop. This catches very fast scanners that create hundreds of short connections before user-space conntrack scoring can process every event.

Examples:

- Many unique destination ports in a short window: quarantine for port scanning.
- Many unique destination IPs on the same port: quarantine for generic same-port fanout scanning.
- Many unique destination IPs on web/CDN-style ports such as `443`, `8080`, `8443`, and `2053`: quarantine for generic web fanout scanning.
- Extreme TCP connection bursts from one source: quarantine directly in the kernel.
- Many unique CDN destination IPs on `443` or alternate CDN ports: quarantine faster using provider-specific thresholds.
- The same Host/SNI value tested against many destination IPs: quarantine for generic clean-IP or origin-finding behavior.
- Repeated management-port fanout to many hosts: quarantine for brute-force behavior.
- Repeated SMTP attempts: quarantine for spam behavior.
- Repeated BitTorrent/P2P signals: quarantine for P2P abuse.
- High-confidence malware/C2 signatures: quarantine the source quickly and shun the destination.

For routed VPN traffic, the guard tries to quarantine the internal VPN client IP instead of the whole VM when that source is visible before NAT.

## Persistence

Customers with root access can eventually remove anything inside their VM. This project is honest about that.

The design is still useful because many abuse incidents are automated, accidental, or caused by customers who only run simple commands such as:

```bash
iptables -F
nft flush ruleset
systemctl stop suricata
```

The restore timer runs every 20 seconds and:

- Reloads the `nftables` policy if the anti-abuse tables are missing.
- Rebuilds the managed destination blocklist if the rules or set entries are flushed.
- Restarts Suricata if it is stopped.
- Restarts `egress-guardd` if it is stopped.
- Reloads CDN range sets if they are missing.

## Supported Systems

Target:

- Linux VMs with `systemd`.
- Debian/Ubuntu using `apt`.
- RHEL-like systems using `dnf` or `yum`.

Required kernel capability:

- `nfnetlink_queue` for Suricata inline `NFQUEUE` mode.

## Quick Install

Clone this repository on the VM, then run:

```bash
sudo ./install.sh
```

The installer:

- Installs required packages.
- Backs up an existing `/etc/nftables.conf` into `/var/backups/anti-abuse/`.
- Installs scripts into `/usr/local/sbin`.
- Installs systemd units.
- Removes the older route-based blocklist files if they exist.
- Enables `nftables`, Suricata, `egress-guardd`, CDN refresh, and restore timers.
- Enables the daily self-update timer for GitHub releases.

## One-Command Git Install

VM templates can install it with a single shell command by cloning the public repo and running the installer:

```bash
sudo git clone https://github.com/caasify/hetzner_abuse_blocker.git /opt/inside-vm-egress-guard && cd /opt/inside-vm-egress-guard && sudo ./install.sh
```

For curl-based provisioning, use the merged installer with a GitHub archive URL:

```bash
curl -fsSL https://raw.githubusercontent.com/caasify/hetzner_abuse_blocker/main/install.sh | sudo bash -s -- --archive-url https://github.com/caasify/hetzner_abuse_blocker/archive/refs/heads/main.tar.gz
```

## Operational Checks

Check services:

```bash
systemctl status nftables suricata egress-guardd anti-abuse-restore.timer cloudflare-ip-refresh.timer anti-abuse-self-update.timer
```

Inspect rules:

```bash
nft list table inet anti_abuse
```

Inspect quarantined sources:

```bash
nft list set inet anti_abuse src_quarantine4
nft list set inet anti_abuse src_quarantine6
```

Inspect CDN ranges:

```bash
nft list set inet anti_abuse cdn_dst4
nft list set inet anti_abuse cdn_dst6
```

Inspect the managed destination blocklist:

```bash
nft list set inet anti_abuse blocked_dst4
```

## Validation

Run local syntax checks from the repository:

```bash
bash -n install.sh scripts/*.sh
python3 -m py_compile egress-guardd.py
```

After installing on a test VM, verify restore behavior:

```bash
nft flush ruleset
sleep 30
nft list table inet anti_abuse
```

Verify service restore:

```bash
systemctl stop suricata
sleep 30
systemctl is-active suricata
```

Verify blocklist restore:

```bash
nft flush set inet anti_abuse blocked_dst4
sleep 30
nft list set inet anti_abuse blocked_dst4
```

## Automatic Self-Update

The installed VM checks `caasify/hetzner_abuse_blocker` once a day for the latest GitHub release.

- If no release exists yet, the updater exits quietly and retries the next day.
- If a newer release is published, it downloads the release source archive and reruns the installer automatically.
- The last installed release tag is stored in `/var/lib/anti-abuse/installed-release.txt`.

Manual check:

```bash
sudo systemctl start anti-abuse-self-update.service
```

Use safe lab targets for scan tests. Do not run broad scans against public Cloudflare, Fastly, CloudFront, or random Internet ranges from a production VPS.

## Removal

This repository currently focuses on installation and restore behavior. To remove it manually from a test VM:

```bash
sudo systemctl disable --now anti-abuse-restore.timer cloudflare-ip-refresh.timer anti-abuse-self-update.timer egress-guardd
sudo systemctl stop suricata
sudo rm -f /usr/local/sbin/egress-guardd
sudo rm -f /usr/local/sbin/anti-abuse-static-dst-refresh.sh
sudo rm -f /usr/local/sbin/anti-abuse-restore.sh
sudo rm -f /usr/local/sbin/anti-abuse-cloudflare-refresh.sh
sudo rm -f /usr/local/sbin/anti-abuse-self-update.sh
sudo rm -f /usr/local/share/anti-abuse/blocked-dst4.txt
sudo rm -f /var/lib/anti-abuse/installed-release.txt
sudo rm -f /etc/systemd/system/egress-guardd.service
sudo rm -f /etc/systemd/system/anti-abuse-restore.service
sudo rm -f /etc/systemd/system/anti-abuse-restore.timer
sudo rm -f /etc/systemd/system/cloudflare-ip-refresh.service
sudo rm -f /etc/systemd/system/cloudflare-ip-refresh.timer
sudo rm -f /etc/systemd/system/anti-abuse-self-update.service
sudo rm -f /etc/systemd/system/anti-abuse-self-update.timer
sudo rm -f /etc/systemd/system/suricata.service.d/anti-abuse.conf
sudo systemctl daemon-reload
```

Saved `nftables` backups are stored in `/var/backups/anti-abuse/` during installation. Suricata and nftables packages are intentionally left installed.

## Important Limitations

- This project cannot guarantee zero future abuse reports.
- A knowledgeable root user can disable or remove inside-VM controls.
- Hosted phishing/content abuse is not solved by firewalling alone.
- TLS-encrypted content is not decrypted or classified.
- Provider-side firewalling is still stronger for hard enforcement.
- False positives are possible with strict universal egress policies.

For production VPS hosting, use this as one layer:

- Inside-VM Egress Guard for template-level prevention and casual tamper recovery.
- Provider firewall/gateway controls for enforcement outside customer root access.
- Abuse desk workflows for repeat offenders.
- Monitoring and tuning before mass rollout.

## Public Safety Note

This repository should not include raw provider abuse reports, customer data, server credentials, test VM passwords, or private IP lists. Keep those in private incident systems, not in a public GitHub repo.
