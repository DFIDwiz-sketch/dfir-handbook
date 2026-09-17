---
title: Linux Persistence
tags:
  - artifact
  - linux
  - persistence
---

# Linux Persistence

<div class="dfir-meta" markdown>
**Category:** Linux · **Tactic:** Persistence (ATT&CK T1053/T1543/T1546/T1098) · **Last updated:** 2026-09-17
</div>

!!! abstract "In one sentence"
    Linux offers dozens of places to auto-run code — cron, systemd, shell profiles, SSH keys, PAM, kernel modules, and more — and an attacker only needs one. This is the checklist: where each lives, what "normal" looks like, and how to spot the planted one.

## Scheduled tasks (cron & friends)

| Location | Notes |
|---|---|
| `/etc/crontab`, `/etc/cron.d/*` | System-wide; each line names the user to run as |
| `/etc/cron.{hourly,daily,weekly,monthly}/` | Scripts run on that cadence |
| `/var/spool/cron/crontabs/<user>` (Debian) · `/var/spool/cron/<user>` (RHEL) | Per-user crontabs — `crontab -l -u <user>` to read |
| `/etc/anacrontab` | Anacron (for machines not always on) |
| `at` jobs: `/var/spool/at/` , `atq` | One-shot scheduled jobs |
| systemd timers | See below — the modern cron replacement |

```bash
# Dump every crontab on the box
for u in $(cut -f1 -d: /etc/passwd); do echo "== $u =="; crontab -l -u "$u" 2>/dev/null; done
cat /etc/crontab /etc/cron.d/* 2>/dev/null
ls -la /etc/cron.{hourly,daily,weekly,monthly}/ /var/spool/cron/ /var/spool/cron/crontabs/ 2>/dev/null
```

Signals: a cron line running a script from `/tmp`, `/dev/shm`, `/var/tmp`, a user home, or a base64/`curl|bash` one-liner; a job every minute (beacon); an entry in `cron.d` with an odd filename.

## systemd (services & timers)

```bash
# Services & timers, including recently changed unit files
systemctl list-unit-files --type=service --state=enabled
systemctl list-timers --all
# Unit files sorted by modification time — recently added = suspicious
ls -lat /etc/systemd/system/ /usr/lib/systemd/system/ /run/systemd/system/ ~/.config/systemd/user/ 2>/dev/null | head -40
# Read a suspicious unit
systemctl cat suspicious.service
```

Signals: a `.service` whose `ExecStart=` points to `/tmp`/home/an odd path or a script that downloads-and-runs; a **user** unit under `~/.config/systemd/user/` (runs at that user's login, easy to miss); a `.timer` paired with a malicious `.service`; a unit file with a recent mtime among old ones. `systemd-run` can also create transient units — check `journalctl` for their creation.

## Shell & login profiles

Every interactive (and some non-interactive) shells source these — a classic quiet persistence:

```bash
ls -la /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc ~/.bashrc ~/.bash_profile ~/.profile ~/.bash_login ~/.zshrc /etc/zsh/* 2>/dev/null
grep -REn "curl|wget|base64|/tmp/|/dev/shm|nc |ncat|bash -i|python -c|eval" /etc/profile.d/ ~/.bashrc ~/.profile 2>/dev/null
```

Also `~/.ssh/rc` and `/etc/ssh/sshrc` (run on every SSH login), and `~/.config/environment.d/`.

## SSH keys & config

```bash
# Unauthorised authorized_keys entries (the #1 Linux backdoor)
for f in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do echo "== $f =="; cat "$f" 2>/dev/null; done
# Odd SSHD config: forced commands, alternate authorized_keys paths, PermitRootLogin
grep -Ev "^#|^$" /etc/ssh/sshd_config | grep -Ei "AuthorizedKeysFile|ForceCommand|PermitRootLogin|Match|PermitUserEnvironment"
```

Signals: a key in `authorized_keys` the user didn't add (compare comment/date against `$MFT`-equivalent mtime); `AuthorizedKeysFile` pointed at an attacker-writable path; `ForceCommand`; `PermitUserEnvironment yes` (lets `~/.ssh/environment` inject vars).

## Accounts & privileges

```bash
# UID 0 accounts other than root (backdoor superusers)
awk -F: '$3==0 {print $1}' /etc/passwd
# Accounts with a login shell / recently added; empty-password accounts
awk -F: '$7 ~ /(bash|sh|zsh)$/ {print $1":"$7}' /etc/passwd
awk -F: '($2=="" ){print $1" has EMPTY password"}' /etc/shadow 2>/dev/null
# Sudoers changes
cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -Ev "^#|^$"
# passwd/shadow/group modification times vs other /etc files
ls -la --time-style=full-iso /etc/passwd /etc/shadow /etc/group /etc/sudoers
```

Signals: a second UID-0 account; a service account given a shell; a new entry in `sudoers.d/` granting NOPASSWD; `passwd`/`shadow` mtime that doesn't match a known change.

## PAM, LD_PRELOAD, and lower-level tricks

| Vector | Where | What to check |
|---|---|---|
| Malicious PAM module | `/etc/pam.d/*`, `/lib*/security/` | A `pam_*.so` not from a package (`rpm -Vf` / `dpkg -V`); a line invoking an odd module (credential-stealing PAM backdoor) |
| `LD_PRELOAD` / `ld.so.preload` | `/etc/ld.so.preload`, `LD_PRELOAD` in profiles/units | Any content in `/etc/ld.so.preload` is worth scrutiny (userland rootkit hook) |
| Loadable kernel module | `lsmod`, `/etc/modules`, `/etc/modules-load.d/` | An unsigned/unknown module (kernel rootkit); compare `lsmod` to package-owned modules |
| Init scripts (SysV) | `/etc/init.d/`, `/etc/rc.local`, `/etc/rc*.d/` | `rc.local` is a classic drop spot |
| Message-of-the-day | `/etc/update-motd.d/` | Scripts here run on login as root |
| Udev rules | `/etc/udev/rules.d/` | `RUN+=` executing on device events |
| Git hooks / app-level | repo `.git/hooks/`, web app configs | App-specific auto-run |
| Xorg/desktop autostart | `~/.config/autostart/`, `/etc/xdg/autostart/` | On workstations |

```bash
grep -R "" /etc/ld.so.preload 2>/dev/null            # should be empty on most systems
lsmod | tail -n +2 | awk '{print $1}'                 # compare against known-good
cat /etc/rc.local /etc/update-motd.d/* 2>/dev/null
```

## Integrity check — let the package manager find tampering

The fastest way to find modified system binaries and configs is to ask the package database what changed:

```bash
# Debian/Ubuntu — files whose checksum no longer matches the package
dpkg --verify 2>/dev/null           # lines starting with "??5" = content changed
# RHEL/CentOS — S(size) M(mode) 5(md5) T(mtime) etc. flags per changed file
rpm -Va 2>/dev/null | grep -vE "^\.{8}" | grep -E "^..5|missing"
```

A system binary (`/bin/ls`, `sshd`, `/usr/bin/passwd`) flagged as content-changed is a trojaned binary or rootkit — very high signal.

## Sweep tools

`chkrootkit` and `rkhunter` automate many of these checks; `Linux Forensics`-style scripts (`UAC`, `CatScale`, `LinPEAS` for the offensive view) collect the lot. On an image, `Velociraptor` Linux artifacts do the same remotely — see [Tools](../tools/velociraptor.md).

## References

- [MITRE ATT&CK — Persistence (Linux)](https://attack.mitre.org/tactics/TA0003/) — T1053.003 (cron), T1543.002 (systemd), T1546.004 (shell config), T1098.004 (SSH keys)
- [chkrootkit](http://www.chkrootkit.org/) · [rkhunter](https://rkhunter.sourceforge.net/) · [UAC — Unix-like Artifacts Collector](https://github.com/tclahr/uac)
- Pages: [Auth & history](auth-and-history.md) · [Filesystem & timestamps](filesystem-timestamps.md) · [Logs & triage](logs-and-triage.md)
