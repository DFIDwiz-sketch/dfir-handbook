---
title: Filesystem & Timestamps
tags:
  - artifact
  - linux
  - filesystem
---

# Filesystem & Timestamps

<div class="dfir-meta" markdown>
**Category:** Linux · **Filesystems:** ext4, xfs · **Last updated:** 2026-09-17
</div>

!!! abstract "In one sentence"
    Linux files carry four timestamps (MACB) but — unlike NTFS — the **crtime (birth)** is hidden and there is no `$FILE_NAME` second set, so timestomping is harder to detect; you lean on the **change time (ctime)**, the journal, and inode/link anomalies instead.

## The four timestamps (MACB)

| Timestamp | `stat` name | Set when | Attacker control |
|---|---|---|---|
| **M** — modify | `Modify` (mtime) | File **content** changes | `touch -m -d`, `touch -r` — easily forged |
| **A** — access | `Access` (atime) | File **read** | Often disabled (`relatime`/`noatime`) for performance; unreliable |
| **C** — change | `Change` (ctime) | **Inode metadata** changes (perms, owner, links, *or* mtime being set) | **Cannot be set by `touch`** without changing the clock — the timestomp tell |
| **B** — birth | `Birth` (crtime) | File **created** | Stored in ext4/xfs inode but **not shown by default** — needs `debugfs`/`xfs_db` or `stat` on new kernels |

```bash
stat file                          # M, A, C shown; Birth shown if kernel/fs supports it
# ext4 birth time when stat won't show it:
debugfs -R "stat <inode>" /dev/sda1 2>/dev/null | grep -i crtime
# get inode first:
ls -i file
```

!!! tip "ctime catches timestomping"
    `touch -d "2020-01-01" evil` sets **mtime and atime** to the past — but **ctime updates to now** (you changed the inode). So `mtime` far in the past while `ctime` is recent = the file was timestomped (or its metadata legitimately changed). Compare `stat`'s Modify vs Change. Attackers who also want to fix ctime must change the system clock or use raw device writes — much harder and itself detectable.

## Finding recently changed files

```bash
# Files with content changed in the incident window (mtime)
find / -xdev -type f -newermt "2026-08-20 00:00" ! -newermt "2026-08-21 00:00" 2>/dev/null

# Files whose inode changed recently (ctime) — catches perms/owner/link changes and timestomps
find / -xdev -type f -cnewer /etc/hostname 2>/dev/null      # changed more recently than a reference file

# Suspicious locations first
find /tmp /var/tmp /dev/shm /run -type f 2>/dev/null | xargs ls -la --time-style=full-iso 2>/dev/null
```

`-xdev` keeps `find` on one filesystem (don't wander into `/proc`, `/sys`, network mounts). `/dev/shm` (RAM-backed) is a favourite drop spot because it vanishes on reboot and isn't "disk".

## Hidden & disguised files

```bash
# Dotfiles and dot-dir tricks (". " , ".. ", "..." names)
find / -xdev -name ".*" -type f 2>/dev/null | grep -vE "/(\.bashrc|\.profile|\.ssh|\.config)"
find / -xdev -name "* *" 2>/dev/null            # names with spaces
# setuid/setgid binaries (privilege persistence) — compare to a known-good baseline
find / -xdev -perm -4000 -o -perm -2000 -type f 2>/dev/null | xargs ls -la 2>/dev/null

# Files masquerading by extension vs actual type
file /tmp/*                                       # "PNG" that is really an ELF
```

Signals: an ELF binary named `.systemd` in `/tmp`; a setuid root binary that isn't part of any package (`dpkg -S`/`rpm -qf` returns nothing); a "log" file that `file` says is an executable; immutable files (`lsattr` shows `i`) an attacker set so you can't delete them (`chattr -i` to remove).

## Deleted-but-open files (live systems)

A process can hold a file open after it's unlinked from disk — malware deletes itself but keeps running:

```bash
# Files that are deleted but still held open by a running process
ls -l /proc/*/exe 2>/dev/null | grep -i deleted          # deleted binaries still executing
lsof +L1 2>/dev/null                                       # files with link count 0 (deleted, still open)
# Recover the content while the process lives:
cp /proc/<pid>/exe /evidence/recovered_binary
cat /proc/<pid>/maps                                       # memory-mapped files
```

`/proc/<pid>/exe` pointing at `(deleted)` is a strong indicator of self-deleting malware — you can still copy the live binary out of `/proc` for analysis.

## The ext4 journal & inode reuse

Ext4's journal (`$journal`, inode 8) records recent metadata transactions and can, with `ext4magic`/`extundelete`/`debugfs`, help recover recently deleted files or show prior inode states — the closest ext4 equivalent to reading the NTFS `$LogFile`. On xfs, `xfs_db` inspects metadata. These are image-level techniques:

```bash
# On a mounted-read-only image or raw device
debugfs -R "ls -d /tmp" /dev/sda1                          # deleted entries in a directory
ext4magic /dev/sda1 -a <start_epoch> -b <end_epoch> -j /dev/sda1   # recover in a time window
extundelete /dev/sda1 --restore-directory /home/user
```

## Building a Linux timeline

The Sleuth Kit / Plaso equivalent of the Windows super-timeline:

```bash
# Sleuth Kit: body file (MAC times per file) → mactime timeline
fls -r -m / /dev/sda1 > body.txt          # on an image; -m prefixes the mount point
mactime -b body.txt -d 2026-08-20 > timeline.csv

# Plaso covers Linux too (syslog, bash history, ext4, systemd, audit…)
log2timeline.py --parsers linux case.plaso /evidence/
psort.py -o l2tcsv -w timeline.csv case.plaso "date > '2026-08-20' AND date < '2026-08-21'"
```

See [Plaso & timelines](../tools/plaso-timelines.md) for filtering; the same "anchor on a known event, window ±1 hour" method applies.

## References

- [ext4 disk layout & timestamps (kernel docs)](https://www.kernel.org/doc/html/latest/filesystems/ext4/)
- [The Sleuth Kit — fls / mactime](https://www.sleuthkit.org/sleuthkit/man/)
- [debugfs / extundelete / ext4magic](https://linux.die.net/man/8/debugfs)
- Pages: [Auth & history](auth-and-history.md) · [Persistence](persistence.md) · [Plaso & timelines](../tools/plaso-timelines.md)
