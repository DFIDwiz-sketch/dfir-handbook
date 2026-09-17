---
title: Authentication & Shell History
tags:
  - artifact
  - linux
  - logs
---

# Authentication & Shell History

<div class="dfir-meta" markdown>
**Category:** Linux · **Sources:** auth logs, wtmp/btmp, shell history · **Last updated:** 2026-09-17
</div>

!!! abstract "In one sentence"
    On Linux the "who got in and what did they type" story lives in a handful of text logs (`/var/log/auth.log` or `secure`, journald), the binary login databases (`wtmp`/`btmp`/`lastlog`), and per-user shell history files — each easy to read, and each easy for an attacker to tamper with, so you cross-check them against each other and against the file-system timeline.

## Authentication logs

| File | Distro | Contents |
|---|---|---|
| `/var/log/auth.log` | Debian/Ubuntu | SSH, sudo, su, PAM, cron auth, login |
| `/var/log/secure` | RHEL/CentOS/Fedora | same, RHEL family |
| `journalctl` (systemd journal) | all systemd | structured logs incl. auth (`_SYSTEMD_UNIT=sshd.service`) — may be the *only* copy if text logging is off |
| `/var/log/audit/audit.log` | auditd installed | kernel-level auth, execve, file access — the richest source when present |

What to read from them:

```bash
# Successful SSH logins: user, source IP, method (password/publickey)
grep -E "sshd.*Accepted" /var/log/auth.log
#   "Accepted publickey for root from 203.0.113.7 port 5123 ssh2: RSA SHA256:..."

# Failed SSH (brute force) — count by source IP
grep -E "sshd.*Failed password" /var/log/auth.log | grep -oE "from [0-9.]+" | sort | uniq -c | sort -rn | head

# sudo usage: who ran what as whom
grep -E "sudo:.*COMMAND" /var/log/auth.log
#   "user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash"

# su / new sessions / user & group changes
grep -E "su\[|session opened|useradd|usermod|groupadd|passwd" /var/log/auth.log

# From the journal instead (survives text-log deletion)
journalctl -u ssh -o short-iso | grep -Ei "accepted|failed|invalid user"
journalctl _COMM=sudo -o short-iso
```

Signals: `Accepted publickey for root` (direct root login should usually be disabled), `Failed password` bursts (brute force) then an `Accepted` (successful), `Invalid user` sweeps (username enumeration), `Accepted` from an unexpected country/ASN, sudo to root by a user who normally doesn't, and new-account/group events (`useradd`, added to `sudo`/`wheel`).

## Login databases (binary)

| File | Read with | Contents |
|---|---|---|
| `/var/log/wtmp` | `last` | Successful logins/logouts + reboots, with source & duration |
| `/var/log/btmp` | `lastb` (root) | **Failed** login attempts |
| `/var/run/utmp` | `who`, `w` | **Currently** logged-in users |
| `/var/log/lastlog` | `lastlog` | Last login time per account |

```bash
last -Faiw                 # full timestamps, IPs, no truncation
last -f /path/to/wtmp      # a wtmp pulled from an image
lastb -Fai                 # failed logins (brute-force sources)
who -a ; w                 # live sessions right now (do this during live response)
```

!!! warning "These are tamper targets"
    `wtmp`/`btmp`/`utmp` are binary and attackers zero specific entries with tools (`utmpdump` edit + re-import, or purpose-built cleaners). A login in `auth.log` with no matching `last` entry (or vice-versa), or a suspiciously clean `wtmp` on a busy server, is itself a finding. `journalctl` and `audit.log` are separate copies — compare them.

## Shell history

| File | Notes |
|---|---|
| `~/.bash_history` | Bash — **only written on clean logout**, no timestamps unless `HISTTIMEFORMAT` was set; size capped by `HISTSIZE` |
| `~/.zsh_history` | Zsh — often has epoch timestamps (`: 1699999999:0;command`) |
| `~/.local/share/fish/fish_history`, `~/.python_history`, `~/.mysql_history`, `~/.psql_history`, `~/.rediscli_history`, `~/.lesshst` | Other interactive tools |
| `/root/.bash_history` | Root's history — always check |

```bash
# Every user's bash history in one pass
for h in /home/*/.bash_history /root/.bash_history; do echo "== $h =="; cat "$h" 2>/dev/null; done

# Zsh with timestamps decoded
awk -F';' '/^: [0-9]/{ "date -d @"substr($1,3,10) | getline d; print d" | "$0 }' ~/.zsh_history
```

!!! tip "Absence of history is a signal, not an all-clear"
    Attackers routinely disable or wipe history: `unset HISTFILE`, `export HISTSIZE=0`, `ln -sf /dev/null ~/.bash_history`, `history -c`, or running from a shell that doesn't persist. An empty or symlinked-to-`/dev/null` history on an actively-used account is suspicious. Fall back to **auditd** (`execve` records every command with args), `journald`, process accounting (`lastcomm`/`sa` if `acct` is enabled), and network/host telemetry.

## Cross-check everything

A single log lies; the intersection doesn't. Build the picture from all sources and note the disagreements:

- `auth.log` says user X logged in from IP at time T → does `last`/`wtmp` agree? Does the shell history show commands right after T? Does the file-system `$MFT`-equivalent ([timestamps](filesystem-timestamps.md)) show files created then?
- A sudo-to-root in `auth.log` → what did they run (`COMMAND=`), and does bash history / auditd confirm?
- SSH `Accepted publickey` → whose key? Check `~/.ssh/authorized_keys` for keys the user didn't add ([persistence](persistence.md)).

## Live-response quick set

```bash
w ; who -a                                  # who's on now
last -Faiw | head -40                       # recent logins
lastb -Fai | head                           # recent failures
ss -tunap                                    # current connections + owning process
grep -E "Accepted|sudo.*COMMAND|useradd" /var/log/auth.log | tail -50
for h in /home/*/.bash_history /root/.bash_history; do echo "== $h =="; tail -50 "$h"; done
```

## References

- [Linux auth logging — man sshd, PAM](https://man7.org/linux/man-pages/man8/sshd.8.html)
- [`last`, `lastb`, `utmp` formats](https://man7.org/linux/man-pages/man1/last.1.html)
- [Linux auditd](https://man7.org/linux/man-pages/man8/auditd.8.html)
- Pages: [Persistence](persistence.md) · [Filesystem & timestamps](filesystem-timestamps.md) · [Logs & triage](logs-and-triage.md)
