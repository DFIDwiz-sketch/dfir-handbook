---
title: Essential Linux Commands
tags:
  - concept
  - basics
  - linux
---

# Essential Linux Commands

<div class="dfir-meta" markdown>
**Category:** basics · **Focus:** commands a DFIR analyst uses daily · **Last updated:** 2026-09-17
</div>

!!! abstract "In one sentence"
    From the true basics — creating, copying, moving and deleting files and folders, editing, redirection — through the commands that come up over and over in an investigation: navigating, searching, piping, inspecting processes and the network, and handling evidence safely. Each with a worked example and the flags that matter. For the *investigative* use of these (which log answers which question), see the [Linux forensics section](../linux/index.md).

## Command anatomy

A command is `program [options] [arguments]`. Options (flags) start with `-` (short, `-l`) or `--` (long, `--all`); short flags combine (`ls -la` = `ls -l -a`). Some take a value (`-p 2222`, `--output=file`). Arguments are what it acts on (files, paths).

```bash
ls -la /var/log        # program=ls, options=-la, argument=/var/log
```

Everyday keys: ++tab++ auto-completes names, ++ctrl+c++ stops a running command, ++ctrl+r++ searches your command history, ++up++/++down++ scroll previous commands, `clear` (or ++ctrl+l++) clears the screen. `history` lists what you've typed; `!!` re-runs the last command (`sudo !!` re-runs it as root).

Paths: `/` is the root, `.` is here, `..` is the parent, `~` is your home, and a leading `/` means absolute (`/etc/passwd`) versus relative (`logs/auth.log`).

## Navigating & looking around

| Command | Does | Example |
|---|---|---|
| `pwd` | Print working directory | `pwd` → `/var/log` |
| `ls` | List files | `ls -la` (all, long) · `ls -lat` (newest first) · `ls -laR` (recursive) · `ls -li` (inode) |
| `cd` | Change directory | `cd /var/log` · `cd -` (previous) · `cd` (home) |
| `tree` | Directory as a tree | `tree -a -L 2 /etc` (all files, 2 levels deep) |
| `stat` | File metadata + timestamps | `stat auth.log` (shows M/A/C, and Birth if supported) |
| `file` | Identify a file by content | `file /tmp/x` → `ELF 64-bit executable` (a "PNG" that's really an ELF = suspicious) |
| `du` / `df` | Disk used by files / by filesystem | `du -sh /var/log/*` (size per item) · `df -h` (free space) |

```bash
# Newest files in a directory (recently touched = interesting during an incident)
ls -lat --time-style=full-iso /tmp | head
# Long listing explained: -l long, -a hidden(dot) files, -t sort by mtime, --time-style full timestamp
```

`ls -la` is the one you'll type most. Columns: permissions, link count, owner, group, size, mtime, name. A leading `.` in the name = hidden file (attackers love `.` names).

## Creating files & folders

| Command | Does | Example |
|---|---|---|
| `mkdir` | Make a directory | `mkdir cases` · `mkdir -p cases/2026/incident1` (`-p` makes parents too) |
| `touch` | Create an empty file, or update its timestamp | `touch notes.txt` · `touch a.txt b.txt c.txt` (several at once) |
| `echo >` | Write text into a new file | `echo "first line" > notes.txt` |
| `printf >` | Like echo, precise formatting | `printf "a\nb\n" > list.txt` |
| `cat >` | Type content into a file (end with ++ctrl+d++) | `cat > notes.txt` then type, then ++ctrl+d++ |
| `tee` | Write to a file **and** the screen | `echo hi \| tee notes.txt` |

```bash
# Make a nested folder structure in one go
mkdir -p cases/incident-2026-0917/{collected,parsed,report}
#   -p creates every level; {a,b,c} expands to three siblings → creates all four dirs at once

# Create an empty file (or refresh its modification time if it exists)
touch cases/incident-2026-0917/report/notes.md

# Create a file with initial content
echo "# Incident notes" > cases/incident-2026-0917/report/notes.md
```

!!! warning "`>` overwrites, `>>` appends"
    `echo "x" > file` **replaces** the file's whole content (and creates it if absent). `echo "x" >> file` **adds** to the end. Mixing these up silently wipes a file — when in doubt, use `>>`.

## Copying, moving, renaming & deleting

| Command | Does | Example |
|---|---|---|
| `cp` | Copy a file | `cp a.txt b.txt` · `cp -r dir/ backup/` (recursive, for folders) · `cp -a` (preserve all metadata) |
| `mv` | Move **or** rename (same command) | `mv old.txt new.txt` (rename) · `mv file.txt /tmp/` (move) |
| `rm` | Delete a file | `rm file.txt` · `rm -r dir/` (recursive) · `rm -i file` (ask first) |
| `rmdir` | Delete an **empty** directory | `rmdir emptydir` |
| `ln -s` | Create a symbolic link (shortcut) | `ln -s /var/log/auth.log here.log` |

```bash
# Copy a whole folder, keeping timestamps/permissions (use -a for evidence)
cp -a /var/log/ ./log-backup/

# Rename is just "move to a new name in the same folder"
mv report-draft.md report-final.md

# Move several files into a directory
mv *.log logs/

# Delete — there is no recycle bin, deletion is immediate
rm scratch.txt
rm -r old-case/          # -r removes a directory and everything inside
```

!!! danger "`rm` is permanent — no undo, no trash"
    There is no recycle bin on the command line. `rm -rf` deletes a directory tree instantly and irreversibly, and `rm -rf /` (or a stray space, `rm -rf / tmp`) can wipe the system. Habits that save you: use `rm -i` (prompts before each delete), double-check the path before pressing ++enter++, and never run `rm -rf` with a variable path (`rm -rf "$DIR/"`) without confirming `$DIR` is set. On evidence, don't delete — **move** to a quarantine folder instead (`mv suspect /quarantine/`).

## Editing files

Two editors are on almost every system. **nano** is the beginner-friendly one:

```bash
nano notes.txt
#   Ctrl+O then Enter = save (write Out) ; Ctrl+X = exit ; Ctrl+W = search ; Ctrl+K = cut line
```

**vim** is everywhere and worth knowing the survival subset (you *will* land in it by accident):

```bash
vim notes.txt
#   i        enter insert mode (now you can type)
#   Esc      leave insert mode (back to command mode)
#   :w       save        :q   quit        :wq  save & quit        :q!  quit WITHOUT saving
#   /word    search      dd   delete line      u   undo
```

For quick edits without opening an editor, `sed` does find-and-replace in place:

```bash
sed -i 's/old/new/g' file.txt      # -i edits the file directly; s/old/new/g replaces all occurrences
```

## Reading files

| Command | Does | Example |
|---|---|---|
| `cat` | Dump whole file | `cat /etc/passwd` |
| `less` | Page through (searchable) | `less /var/log/auth.log` — `/pattern` search, `q` quit, `G` end, `g` top |
| `head` / `tail` | First / last N lines | `head -50 file` · `tail -100 file` · `tail -f file` (follow live) |
| `nl` | Number lines | `nl script.sh` |
| `strings` | Printable strings from a binary/blob | `strings -a malware.bin \| grep -iE "http\|cmd\|\.dll"` |
| `xxd` / `hexdump` | Hex view | `xxd file \| head` · `xxd -s 0 -l 64 file` (offset 0, 64 bytes) |
| `zcat` / `zless` / `zgrep` | Read gzipped logs without unzipping | `zgrep "Failed" /var/log/auth.log.*.gz` |

```bash
# Follow a log live during response (Ctrl+C to stop)
tail -f /var/log/auth.log
# Read a rotated, compressed log
zcat /var/log/syslog.2.gz | tail -50
```

!!! tip "On evidence, prefer read-only tools"
    `cat`/`less`/`grep` read without modifying, but they update the file's **atime** (access time) on a live system. When examining evidence, work on a **copy** or a **read-only mount** so you don't disturb timestamps — and remember `atime` is often disabled anyway ([timestamps](../linux/filesystem-timestamps.md)).

## Searching — grep, find, and friends

`grep` (search text) and `find` (search the filesystem) are the two you cannot do without.

```bash
# grep: search inside files
grep "Failed password" auth.log            # lines containing the phrase
grep -i "error" log                         # -i case-insensitive
grep -r "password" /etc/                     # -r recursive through a directory
grep -n "root" /etc/passwd                   # -n show line numbers
grep -v "^#" sshd_config                     # -v invert: lines NOT matching (drop comments)
grep -c "Accepted" auth.log                  # -c count matches
grep -E "Failed|Invalid" auth.log            # -E extended regex (OR)
grep -A3 -B1 "segfault" kern.log             # -A/-B lines After/Before context
grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" access.log   # -o only the match (extract IPs)
```

```bash
# find: locate files by criteria
find /home -name "*.sh"                       # by name
find / -type f -newermt "2026-08-20" 2>/dev/null   # modified after a date
find / -perm -4000 -type f 2>/dev/null        # setuid binaries (privilege persistence)
find /tmp -type f -mmin -60                    # modified in the last 60 minutes
find / -user www-data -type f 2>/dev/null      # owned by a user
find . -size +100M                             # larger than 100 MB (staged archives?)
find / -xdev -name ".*" -type f 2>/dev/null    # hidden files, stay on one filesystem
```

`2>/dev/null` throws away the "permission denied" noise so you see only results. `-xdev` keeps `find` from wandering into `/proc`, `/sys`, or network mounts.

Related: `awk` (field processing), `sed` (stream edit), `sort`, `uniq`, `cut`, `wc` — covered under pipes below.

## Redirection & chaining

Every command has three streams: **stdin** (input), **stdout** (normal output), **stderr** (errors). You redirect them with these operators:

| Operator | Does | Example |
|---|---|---|
| `>` | stdout → file (**overwrite**) | `ls > files.txt` |
| `>>` | stdout → file (**append**) | `echo done >> log.txt` |
| `2>` | stderr → file | `find / 2> errors.txt` |
| `2>/dev/null` | discard errors | `find / -name x 2>/dev/null` (hide "permission denied") |
| `&>` | both stdout+stderr → file | `command &> all.txt` |
| `<` | file → stdin | `sort < names.txt` |
| `\|` | stdout of one → stdin of next (a "pipe") | `ps aux \| grep ssh` |

Chaining commands on one line:

| Operator | Does | Example |
|---|---|---|
| `;` | run in sequence regardless | `cd /tmp ; ls` |
| `&&` | run next **only if** previous succeeded | `mkdir out && cd out` |
| `\|\|` | run next **only if** previous failed | `ping -c1 host \|\| echo "down"` |
| `&` | run in the background | `long-job &` |

```bash
# Save results and errors separately
find / -name "*.conf" > found.txt 2> denied.txt
# Only continue if the first step worked
tar czf backup.tgz /data && echo "backup ok"
```

## Pipes & text processing — the real power

The pipe `|` sends one command's output into the next. This is how you turn a raw log into an answer.

```bash
# Top 10 source IPs of failed SSH logins
grep "Failed password" auth.log \
  | grep -oE "from [0-9.]+" \
  | awk '{print $2}' \
  | sort | uniq -c | sort -rn | head
```

Reading it: `grep` finds the failure lines → `grep -oE` extracts `from <IP>` → `awk '{print $2}'` prints the second word (the IP) → `sort` groups identical IPs together → `uniq -c` collapses duplicates and **counts** them → `sort -rn` sorts by that count, highest first → `head` shows the top 10. The result is a ranked brute-force source list.

The building blocks:

| Command | Does | Example |
|---|---|---|
| `awk` | Field-based processing | `awk -F: '{print $1}' /etc/passwd` (first field, `:`-separated) |
| `sed` | Find/replace, edit stream | `sed 's/old/new/g' file` · `sed -n '10,20p' file` (lines 10–20) |
| `sort` | Order lines | `sort -rn` (reverse numeric) · `sort -u` (unique) · `sort -t: -k3 -n` (by 3rd `:` field) |
| `uniq` | Collapse adjacent duplicates | `uniq -c` (count) — **must `sort` first** |
| `cut` | Extract columns | `cut -d: -f1,3 /etc/passwd` (fields 1 and 3) |
| `wc` | Count | `wc -l file` (lines) · `wc -c` (bytes) |
| `tr` | Translate/delete chars | `tr 'A-Z' 'a-z'` · `tr -d '\0'` (strip nulls) · `tr '\0' '\n'` |
| `tee` | Write to file **and** screen | `... | tee out.txt` |
| `xargs` | Turn input into arguments | `find . -name "*.log" | xargs grep "error"` |

```bash
# awk is a mini-language: filter + compute
awk -F: '$3 == 0 {print $1}' /etc/passwd        # users with UID 0 (should be only root)
awk -F: '$3 >= 1000 {print $1}' /etc/passwd      # regular (human) accounts
awk '{sum+=$1} END {print sum}' numbers          # sum a column
awk '$9 == 404 {print $7}' access.log            # requested paths that returned 404

# Unique-and-count pattern (memorise this one)
cut -d' ' -f1 access.log | sort | uniq -c | sort -rn | head   # top client IPs in a web log
```

## Processes & the network

| Command | Does | Example |
|---|---|---|
| `ps` | Process snapshot | `ps auxfww` (all, full, forest/tree) · `ps -eo pid,ppid,user,cmd` |
| `top` / `htop` | Live process view | `top` — `P` sort by CPU, `M` by memory, `q` quit |
| `ss` | Sockets/connections | `ss -tunap` (TCP+UDP, numeric, all, process) · `ss -tlnp` (listening) |
| `lsof` | Open files/sockets | `lsof -nP -iTCP -sTCP:LISTEN` (listening ports) · `lsof +L1` (deleted-but-open) |
| `kill` | Signal a process | `kill -9 <pid>` (force) — **capture evidence first** |
| `pgrep` / `pkill` | Find/kill by name | `pgrep -a nginx` (list with args) |

```bash
# Full process tree with command lines (read this to spot bad parent→child)
ps auxfww
# Network connections with the owning process — the key pivot in live response
ss -tunap
# What is listening (backdoor listeners show here)
ss -tlnp
# A process's details via /proc
cat /proc/<pid>/cmdline | tr '\0' ' '; echo      # full command line
readlink /proc/<pid>/exe                          # the actual binary (may say "(deleted)")
```

See [Linux logs & triage](../linux/logs-and-triage.md) for how to read these during an incident.

## Permissions & ownership

```bash
ls -l file            # -rwxr-xr-- : owner rwx, group r-x, others r--
chmod 640 file        # rw- r-- --- (owner read/write, group read, others none)
chmod +x script.sh    # add execute
chown user:group file # change owner and group
id                    # your uid/gid/groups
sudo -l               # what you're allowed to run as root
lsattr file           # extended attrs — 'i' = immutable (attacker anti-delete trick)
chattr -i file        # remove immutable so you can delete/quarantine
```

Permission notation: three groups of `rwx` (owner, group, others). Numeric: `r=4, w=2, x=1` summed per group, so `750` = `rwxr-x---`. A world-writable file (`chmod 777`) or an unexpected setuid bit (`s` in the owner-execute slot) is worth a second look.

## Handling evidence safely

```bash
# Hash a file (integrity — do this to every piece of evidence)
sha256sum evidence.raw > evidence.raw.sha256
sha256sum -c evidence.raw.sha256                  # verify later (prints OK/FAILED)
md5sum file                                        # legacy tools still want md5

# Copy preserving all metadata (timestamps, perms, owner)
cp -a source dest                                  # -a = archive (preserve everything)
rsync -a --progress src/ dest/                     # large trees, resumable

# Mount a disk image read-only (never write to evidence)
mount -o ro,loop,noexec image.dd /mnt/evidence
mount -o ro,loop,offset=$((2048*512)) image.dd /mnt/evidence   # partition at sector 2048

# Compress/extract collections
tar czf triage.tar.gz /path/to/collect            # create gzip archive
tar xzf triage.tar.gz                              # extract
gzip -d file.gz ; zcat file.gz                     # single-file gzip
```

!!! warning "Hash before and after, mount read-only"
    Every evidence file gets a **SHA-256 before you touch it** and again after, and they must match — that's how you prove it didn't change ([imaging & collection](../tools/imaging-collection.md)). Always mount images **`ro`** (read-only); a stray write destroys evidence and breaks the hash.

## SSH & remote work

```bash
ssh user@host                                      # connect
ssh -i key.pem user@host                            # with a specific key
ssh -p 2222 user@host                               # non-standard port
scp file user@host:/path/                           # copy a file over SSH
scp -r dir user@host:/path/                          # recursive
scp user@host:/var/log/auth.log ./                  # pull a log from a remote box
sftp user@host                                       # interactive file transfer
# Check what keys grant access to an account you're investigating
cat ~/.ssh/authorized_keys
```

## Getting help

```bash
man ss              # full manual (q to quit, /pattern to search)
ss --help           # quick option summary
tldr find           # community examples (if tldr installed) — faster than man
which volatility3   # where is this binary?
apropos network     # find commands related to a keyword
type -a ls          # is it a binary, alias, or function?
```

## The commands you'll actually reach for first

In a live-response moment, this handful covers most of it:

```bash
w; who -a                                    # who's logged in now
ps auxfww                                     # what's running
ss -tunap                                     # what's connected / listening
ls -lat /tmp /dev/shm /var/tmp | head         # recent drops
grep -Ei "accepted|failed|sudo" /var/log/auth.log | tail   # recent auth
find / -xdev -mmin -120 -type f 2>/dev/null | head    # changed in last 2 hours
```

## References

- [The Linux Command Line (free book, W. Shotts)](https://linuxcommand.org/tlcl.php)
- [explainshell.com — paste a command, see each flag explained](https://explainshell.com/)
- [GTFOBins — how LOLBin-style Unix binaries get abused](https://gtfobins.github.io/)
- Pages: [Linux forensics](../linux/index.md) — the investigative use of these commands · [Well-known ports](well-known-ports.md)
