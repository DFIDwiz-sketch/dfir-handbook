---
title: Linux Privilege Escalation
tags:
  - oscp
---

# Linux Privilege Escalation

<div class="dfir-meta" markdown>
**Exam weight:** 10 points per Linux standalone (`proof.txt`) · **Last updated:** 2026-10-23
</div>

!!! abstract "In one sentence"
    Low-privilege shell to root: enumerate thoroughly first, work the common misconfigurations in order, and keep kernel exploits for last.

!!! note "How this page is organised"
    A study checklist. Learn to read the output of the enumeration scripts — the answer is almost always already on the screen; the skill is spotting it. Practise on Proving Grounds Linux boxes → [Practice labs](practice-labs.md).

## 0. Stabilise the shell first { #shell-upgrade }

A raw reverse shell has no tab-completion, no arrow keys, and dies on Ctrl-C. Upgrade before you do anything else:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# then: Ctrl-Z
stty raw -echo; fg
export TERM=xterm
```

## 1. Enumerate { #enumeration }

Run an automated script **and** read it yourself — scripts flag the obvious, you catch the subtle.

```bash
./linpeas.sh | tee linpeas.txt      # red/yellow highlights = most interesting
```

Always check these by hand too:

```bash
id; sudo -l                 # what can I run as root without a password?
find / -perm -4000 -type f 2>/dev/null   # SUID binaries
getcap -r / 2>/dev/null     # capabilities
crontab -l; cat /etc/crontab; ls -la /etc/cron.*
uname -a; cat /etc/os-release            # kernel / distro version
ps aux --forest             # running services, who owns them
netstat -tulpn              # local-only services → candidates for a port forward
```

## 2. Work the common vectors, in order { #vectors }

Easiest and most reliable first:

| Vector | What to look for | Lead |
|---|---|---|
| **sudo rules** | `sudo -l` shows a binary you can run as root | Look it up on [GTFOBins](https://gtfobins.github.io/) — most have a documented escape |
| **SUID binaries** | An unusual SUID binary (not the standard set) | GTFOBins again; a custom binary may call something with a relative path |
| **Capabilities** | `cap_setuid`, `cap_dac_read_search` on a binary | GTFOBins "Capabilities" section |
| **Cron jobs** | A root cron running a script you can write, or using a wildcard | Edit the script, or abuse the wildcard (`tar`/`rsync` tricks) |
| **Writable `PATH` / scripts** | A root process calling a command by name, in a directory you can write | Drop a malicious binary earlier in `PATH` |
| **Credentials on disk** | Passwords in config files, history, `.ssh`, DB files, web app configs | Reuse them for `su`, SSH, or other services |
| **Writable `/etc/passwd`** | File is world-writable | Add a root-UID user with a known password |

## 3. Credentials and internal services { #credentials }

Privilege escalation is often just **credential reuse**:

```bash
cat ~/.bash_history ~/.*_history 2>/dev/null
grep -riE 'password|passwd|secret|api[_-]?key' /var/www /opt /home 2>/dev/null
cat ~/.ssh/id_rsa 2>/dev/null
```

A service listening only on `127.0.0.1` (from `netstat`) can't be reached from outside — forward a port to it (see [Pivoting › SSH forwarding](pivoting.md#ssh-forwarding)) and attack it locally.

## 4. Kernel exploits — last resort { #kernel }

Match `uname -a` and the distro version to a known exploit (DirtyPipe, DirtyCOW, PwnKit, etc.). Keep this last: a kernel exploit can crash the box, costing you a revert, and the exam almost always has a cleaner misconfiguration path intended.

## Checklist { #checklist }

- [ ] Shell upgraded to a proper TTY
- [ ] `sudo -l` checked → GTFOBins
- [ ] SUID + capabilities enumerated → GTFOBins
- [ ] Cron jobs read (writable scripts? wildcards?)
- [ ] Config files / history / SSH keys searched for credentials
- [ ] Local-only services found and reachable via a port forward
- [ ] Kernel / distro version noted (kept as the last option)

## Related pages

- [Linux auth & history](../../linux/auth-and-history.md) · [Linux persistence](../../linux/persistence.md) · [Linux logs & triage](../../linux/logs-and-triage.md)
- [Linux commands](../../basics/linux-commands.md) · [Methodology & habits](methodology.md)

## References

- [GTFOBins](https://gtfobins.github.io/)
- [PEASS-ng (linpeas)](https://github.com/peass-ng/PEASS-ng)
