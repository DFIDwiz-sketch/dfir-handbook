---
title: Logs, Processes & Live Triage
tags:
  - artifact
  - linux
  - logs
  - triage
---

# Logs, Processes & Live Triage

<div class="dfir-meta" markdown>
**Category:** Linux · **Last updated:** 2026-09-17
</div>

!!! abstract "In one sentence"
    On a live or freshly-imaged Linux host, the fast wins are: enumerate the **logs** (syslog, journald, audit), snapshot the **running state** (processes, network, open files) before it changes, and know which log answers which question — this page is that map plus a copy-ready triage script.

## Log locations

| Log | Path | Answers |
|---|---|---|
| System messages | `/var/log/syslog` (Debian), `/var/log/messages` (RHEL) | General daemon/kernel messages |
| Auth | `/var/log/auth.log` / `secure` | Logins, sudo — see [Auth & history](auth-and-history.md) |
| Kernel | `/var/log/kern.log`, `dmesg` | Driver/module loads, OOM, USB, segfaults |
| systemd journal | `journalctl` (binary, `/var/log/journal/` if persistent) | Everything, structured; often the **only** copy |
| auditd | `/var/log/audit/audit.log` | execve, file access, syscalls — richest, if enabled |
| Package manager | `/var/log/dpkg.log`, `/var/log/apt/history.log`, `/var/log/yum.log`/`dnf.rpm.log` | What was installed/removed and when |
| Cron | `/var/log/cron` (RHEL), syslog (Debian) | Cron job execution |
| Web/app | `/var/log/apache2/`, `/var/log/nginx/`, app dirs | See [Web shell playbook](../playbooks/webshell-server.md) |
| Wtmp/btmp/lastlog | `/var/log/wtmp` etc. | Login database — [Auth & history](auth-and-history.md) |
| Firewall | `journalctl -u firewalld` / `ufw.log` / `iptables` syslog | Blocked/allowed connections |

```bash
# journald is the safety net when text logs are deleted or rotated
journalctl --list-boots                    # boot sessions
journalctl -b -1 -p err -o short-iso       # errors from the previous boot
journalctl -S "2026-08-20 00:00" -U "2026-08-21 00:00" -o short-iso   # a time window
journalctl _COMM=sshd + _COMM=sudo -o short-iso   # combine matches (auth events)
journalctl -k | grep -iE "module|segfault|oom|usb"

# What was installed around the incident
grep -E " install " /var/log/dpkg.log
awk '/Commandline:/{print}' /var/log/apt/history.log
```

!!! warning "auditd is the game-changer"
    If `auditd` is running, `execve` records give you **every command with full arguments and the invoking user** — the Linux equivalent of Sysmon 1 / process command-line logging, and it survives shell-history wiping. Check `auditctl -l` for rules and search `ausearch -m EXECVE -ts today` / `aureport -x`. If it's *not* enabled, note that gap in the report and lean on journald + bash history + network telemetry.

## Running-state snapshot (live response — capture first)

Volatile state disappears on reboot or when the attacker cleans up. Grab it before anything else (and before a memory image if you're taking one — see [imaging](../tools/imaging-collection.md)):

```bash
# Processes — full tree, with command lines
ps auxfww                                   # forest view, full args
ps -eo pid,ppid,user,etimes,cmd --sort=start_time | tail -40   # newest processes

# Network — connections with owning process (the key pivot)
ss -tunap                                    # TCP/UDP, numeric, all, process
ss -tlnp                                     # listening ports + process (backdoor listeners)
# Old school if ss unavailable:
netstat -tunap

# Open files & deleted-but-running binaries
lsof -nP | grep -iE "LISTEN|ESTABLISHED"     # network file handles
ls -l /proc/*/exe 2>/dev/null | grep -i deleted   # self-deleting malware
lsof +L1                                      # deleted files still open

# Loaded kernel modules (rootkits)
lsmod ; cat /proc/modules

# Scheduled / persistence quick look — see Persistence page for the full sweep
systemctl list-timers --all ; crontab -l 2>/dev/null
```

## Process triage — what's suspicious

| Look for | Why |
|---|---|
| Process whose `exe` is `(deleted)` | Self-deleting malware still running |
| Binary running from `/tmp`, `/dev/shm`, `/var/tmp`, a home dir | Normal daemons run from `/usr`/`/sbin` |
| A process with no matching binary on disk / not package-owned | Injected or dropped |
| Listening socket on an odd port with an odd owner | Backdoor / reverse-shell listener |
| A "kernel" name (`[kworker/…]`) that is **not** a kernel thread (has a real `exe`, network sockets) | Masquerading — real kthreads have PPID 2 and no `/proc/<pid>/exe` |
| High CPU + outbound connection to one IP | Cryptominer / beacon |
| `bash -i`, `nc`, `socat`, `python -c '...socket...'`, `/dev/tcp/` redirection | Reverse shell |

```bash
# Processes running from suspicious paths
ls -l /proc/*/exe 2>/dev/null | grep -E "/tmp/|/dev/shm/|/var/tmp/|/home/"
# A process's full context
cat /proc/<pid>/cmdline | tr '\0' ' '; echo
readlink /proc/<pid>/cwd ; readlink /proc/<pid>/exe
cat /proc/<pid>/environ | tr '\0' '\n'      # env vars (LD_PRELOAD? proxy?)
ls -l /proc/<pid>/fd                          # open files/sockets
```

## One-shot triage script

```bash
#!/bin/sh
# Minimal live-response collector — redirect to a file on removable/network storage
OUT=/mnt/evidence/$(hostname)_$(date +%Y%m%d_%H%M%S)
mkdir -p "$OUT"; exec > "$OUT/triage.txt" 2>&1
echo "=== date/uptime ==="; date -u; uptime
echo "=== who ==="; w; who -a; last -Faiw | head -40
echo "=== processes ==="; ps auxfww
echo "=== newest procs ==="; ps -eo pid,ppid,user,etimes,cmd --sort=start_time | tail -40
echo "=== network ==="; ss -tunap; echo "-- listening --"; ss -tlnp
echo "=== deleted-but-open ==="; ls -l /proc/*/exe 2>/dev/null | grep -i deleted; lsof +L1 2>/dev/null
echo "=== modules ==="; lsmod
echo "=== cron/timers ==="; for u in $(cut -f1 -d: /etc/passwd); do crontab -l -u "$u" 2>/dev/null | sed "s/^/[$u] /"; done; cat /etc/crontab /etc/cron.d/* 2>/dev/null; systemctl list-timers --all
echo "=== authorized_keys ==="; for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do echo "-- $f --"; cat "$f" 2>/dev/null; done
echo "=== recent auth ==="; grep -Ei "accepted|failed|sudo.*command|useradd" /var/log/auth.log /var/log/secure 2>/dev/null | tail -80
echo "=== UID0 accounts ==="; awk -F: '$3==0{print $1}' /etc/passwd
echo "=== package integrity (sample) ==="; command -v rpm >/dev/null && rpm -Va 2>/dev/null | grep -E "^..5|missing" | head; command -v dpkg >/dev/null && dpkg --verify 2>/dev/null | head
```

Use purpose-built collectors for a thorough, defensible job: **UAC** (Unix-like Artifacts Collector) and **CatScale** gather all of the above into a structured archive; **Velociraptor** does it remotely across many hosts ([Tools](../tools/velociraptor.md)).

## References

- [systemd journalctl](https://www.freedesktop.org/software/systemd/man/journalctl.html) · [auditd / ausearch / aureport](https://man7.org/linux/man-pages/man8/auditd.8.html)
- [UAC](https://github.com/tclahr/uac) · [CatScale](https://github.com/WithSecureLabs/LinuxCatScale)
- Pages: [Auth & history](auth-and-history.md) · [Persistence](persistence.md) · [Filesystem & timestamps](filesystem-timestamps.md) · [Imaging](../tools/imaging-collection.md)
