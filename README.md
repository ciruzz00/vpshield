# vpshield

Interactive hardening for internet facing Linux servers and VPS, in a single static binary with a terminal UI.

Every change is shown as a **plan** before it runs, executed inside a **snapshot** you can roll back, and risky SSH changes are protected by a **dead-man switch** that restores the previous config if you lock yourself out.

```
 vpshield  my-vps  Debian GNU/Linux 12 · systemd
 ╭──────────────────────────────────────────────────────────────────────────────╮
 │ firewall  ● nftables active             ssh port  2222                       │
 │ allowed   80/tcp 443/tcp 2222/tcp⏱      root      ● prohibit-password        │
 │ fail2ban  ● 3 jails, 14 banned now      password  ● disabled (keys only)     │
 │ updates   ● unattended-upgrades enabled kernel    ● 11/11 sysctl hardened    │
 ╰──────────────────────────────────────────────────────────────────────────────╯
```

## Features

| Area | What it does |
|---|---|
| **Firewall & ports** | ufw, firewalld or native nftables (auto-detected per distro). Default deny inbound, SSH always allowed first, service whitelist, open/close ports, per-IP rate limiting, view of what is really listening and whether it is exposed. Disables a second active firewall to avoid conflicts. |
| **SSH** | Port change (e.g. 22 → 2222) handling firewall, SELinux (`semanage`), Ubuntu socket activation and `sshd -t` validation. Hardening wizard (root login, passwords, MaxAuthTries, grace time, idle timeout, forwarding, AllowUsers). Lockout guards: warns when no `authorized_keys` exist, when AllowUsers misses you, etc. Add an authorized key from the TUI. |
| **Fail2ban** | Interactive wizard: ban/find time, retries, incremental bans, sshd mode (normal/aggressive/ddos/extra), extra jails auto-detected (recidive, nginx, apache, postfix, dovecot), whitelist pre-filled with your current IP, ban action matched to the firewall. Live view of jails and banned IPs, unban/ban, log viewer. |
| **Port-scan protection** | `vpshield-portscan` jail: IPs that hit too many closed ports (dropped by ufw / firewalld / nftables) get banned on all ports. |
| **Banners & fingerprint** | Hides the distro suffix in the SSH identification string, `server_tokens off` (nginx), `ServerTokens Prod` (Apache), neutral Postfix greeting, disables dynamic MOTD, cleans `/etc/issue*`, optional pre-login legal warning. |
| **DNS records** | Cloudflare API (scoped token): list/add/edit/delete records, "point a name to this server" (detects public IPv4/IPv6), SPF / DMARC / CAA helpers. |
| **DNS resolver** | systemd-resolved (DoT, DNSSEC) or `/etc/resolv.conf` (keeps NetworkManager, dhclient and udhcpc from overwriting it). |
| **Cron** | Managed jobs with presets (daily audit, reboot-if-required, certbot, docker prune, snapshot pruning) or custom; read-only view of every crontab and systemd timer. |
| **Automatic updates** | unattended-upgrades (Debian/Ubuntu), dnf-automatic (RHEL family), apk cron (Alpine), notify-only on Arch. Security-only and reboot window options. |
| **Kernel hardening** | Curated sysctl groups (SYN cookies, rp_filter, redirects, kptr/dmesg restrict, BPF, ptrace...) with current vs target view. IP-forwarding knob is skipped when Docker/WireGuard/k8s are detected. |
| **Security audit** | Score plus findings: SSH, firewall, fail2ban, updates, publicly listening risky services (Redis, MySQL, Docker API...), UID 0 accounts, empty passwords, `.ssh` permissions, sysctl, world-writable files, SUID. Can be saved daily via cron. |
| **Backups & rollback** | Every plan snapshots the files it touches. Restore any snapshot from the TUI or CLI. |

## Supported distributions

Detected automatically from `/etc/os-release`:

| Family | Targets | Firewall default | Notes |
|---|---|---|---|
| Debian | Debian 12/13, Ubuntu 22.04/24.04 | ufw | `DebianBanner`, ssh.socket handled |
| RHEL | Rocky, AlmaLinux, RHEL 8/9, Fedora | firewalld | EPEL enabled for fail2ban, SELinux port labelling |
| Alpine | 3.19+ | nftables | OpenRC, busybox crond |
| Arch | Arch, EndeavourOS, Manjaro | nftables | no unattended upgrades (rolling) |

## Install

From a release:

```sh
curl -fsSL https://raw.githubusercontent.com/ciruzz00/vpshield/main/install.sh | sudo sh
```

From source (Go 1.24+):

```sh
git clone https://github.com/ciruzz00/vpshield && cd vpshield
go mod tidy
make build && sudo make install
```

## Usage

```sh
sudo vpshield --dry-run   # explore everything, nothing is changed
sudo vpshield             # the real thing
```

```
vpshield status                 one screen summary
vpshield audit [--save]         security report
vpshield confirm                keep a pending SSH change
vpshield rollback --list        list snapshots
vpshield rollback <snapshot>    restore a snapshot
vpshield prune --days 30        delete old snapshots
```

## Safety model

1. **Plan → review → apply.** Each action shows the commands and the file contents it will write. Warnings (possible lockout, missing keys) are shown in red before you confirm.
2. **Snapshots.** Files are backed up in `/var/lib/vpshield/backups/<id>` before being touched; firewall state files are saved before command-based changes. If a required step fails, the snapshot is restored automatically.
3. **Dead-man switch.** After any SSH change, an automatic rollback is scheduled *outside* the TUI process (`systemd-run` timer, or a detached process on OpenRC). Log in from a new terminal and press `c` (or run `vpshield confirm`). If your session dies or you get locked out, the old config comes back by itself.
4. **Anti-lockout defaults.** The SSH port is allowed before default-deny is enabled, the old SSH port stays open until the new one is confirmed, and your current IP is pre-filled in the fail2ban whitelist.

## Files vpshield manages

| Path | Purpose |
|---|---|
| `/etc/ssh/sshd_config.d/00-vpshield.conf` | SSH settings (loaded first, so it wins) |
| `/etc/ssh/sshd_config.d/01-vpshield-banner.conf` | SSH banner/version settings |
| `/etc/fail2ban/jail.d/vpshield.local`, `filter.d/vpshield-portscan.conf` | fail2ban |
| `/etc/nftables.conf` / `/etc/nftables.nft` | nftables backend (table `inet vpshield`) |
| `/etc/sysctl.d/99-vpshield.conf` | kernel hardening |
| `/etc/cron.d/vpshield` or a marked block in `/etc/crontabs/root` | cron jobs |
| `/etc/vpshield/` | state and the Cloudflare token (0600) |
| `/var/lib/vpshield/backups/` | snapshots |
| `/var/log/vpshield/` | action log, audit reports |

## Limitations

- The SSH protocol always announces `SSH-2.0-OpenSSH_x.y`; only the distro part can be hidden.
- Firewalld rate limits are global per rule, not per source IP.
- Sysctl rollback restores the file; values already applied stay until reboot or until you set them again.
- Changing the SSH port is noise reduction, not security: keys + fail2ban + firewall are what matter.

## License

MIT
