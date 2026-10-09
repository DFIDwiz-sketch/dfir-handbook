---
title: Identifying Artefacts by Scenario
tags:
  - windows
  - triage
  - methodology
---

# Identifying Artefacts by Scenario

<div class="dfir-meta" markdown>
**Category:** Triage methodology · **OS:** Windows · **Last updated:** 2026-10-09
</div>

A single artefact rarely proves anything on its own. The same trace can be routine or malicious depending on **who, when, where and how**. This page gives a repeatable way to judge an artefact, decide what context you need, and pick the next artefact that confirms or rules it out.

## The three-step method

1. **Classify** — is it *likely normal*, *possibly suspicious* or *definitely suspicious*?
2. **Ask for context** — the question that decides whether the behaviour is expected. *Is this a known admin task? Is remote access expected for this user?*
3. **Find the next artefact** — the evidence that answers that question. *4624 logons, VPN logs, Prefetch, USBSTOR.*

!!! tip "Rule of thumb"
    Context is the question. The next artefact is the evidence that answers it.

When a baseline exists, sort every deviation into one of three buckets: **normal variation** (documented reason, no security impact), **potential misconfiguration** (security weakened, no attack evidence yet) or **suspicious/malicious** (matches a known attack pattern).

## Six-question checklist

| Question | Leans normal | Leans suspicious |
| --- | --- | --- |
| **When?** | Business hours, scheduled maintenance (e.g. AV scan at 02:00) | Overnight, weekends, leave, off-pattern times |
| **Where from?** | Internal IP, corporate VPN, usual location | New external IP, overseas, hosting/VPS ranges |
| **Who?** | Account fits the job; admin doing admin work | Intern or standard user on sensitive data; service account logging on interactively |
| **Which path?** | `C:\Program Files`, `C:\Windows\System32` | `%Temp%`, `%AppData%`, `Downloads`, `C:\Users\Public`, `C:\ProgramData` |
| **What does it look like?** | Signed binary, recognisable name | Double extension (`invoice.doc.exe`), random name, Base64/obfuscation, look-alike names (`svch0st.exe`) |
| **What changed?** | Documented change with a change request | New autorun, weakened security settings, cleared logs, AV stopped |

One hit → **possibly suspicious**. Two or three together → **definitely suspicious**. "03:00 + `%Temp%` + obfuscated PowerShell" is three hits.

These are **definitely suspicious on their own**:

- An autorun location (Run/RunOnce, scheduled task, service) pointing at a random name or a temp path
- Encoded or obfuscated PowerShell (`-enc`, `FromBase64String`, `IEX`)
- Security or antivirus logs cleared manually
- An executable with a double extension

## Scenario guide

### 1. Logons and remote access

- **Normal:** internal IP during business hours.
- **Suspicious:** overnight logons, external IPs, impossible travel, failures followed by success.
- **Context:** external IP → *approved IP list, user role, login history*. Internal movement (RDP, SMB) → *is remote access expected for that user/system?*
- **Next artefact:** Security 4624/4625/4634/4647/4648, logon type (3 network, 10 RDP), VPN logs, RDP logs (`TerminalServices-LocalSessionManager` 21/24/25, `RemoteConnectionManager` 1149).

### 2. PowerShell and scripts

- **Normal:** an admin running a signed script from a known location.
- **Suspicious:** execution from `%Temp%`, `-enc` / `-w hidden` / `-nop`, `FromBase64String`, `IEX`, `DownloadString`.
- **Context:** is it a known admin task? What does the script contain? What is the parent process?
- **Next artefact:** PowerShell 4104 (script block — the decoded code), 4103 (module logging), 4688 / Sysmon 1 (process and command line), `ConsoleHost_history.txt`, process tree.

### 3. Persistence

- **Normal:** documented entries such as antivirus or updater services.
- **Suspicious:** random names under Run/RunOnce, tasks on short intervals (e.g. every 30 minutes), services pointing at temp folders.
- **Context:** was it in the baseline? Who created it and when? What file does it launch?
- **Next artefact:** `HKCU/HKLM\...\CurrentVersion\Run` and `RunOnce`, `C:\Windows\System32\Tasks\`, 4698 (task created), 7045 (service installed), binary path/hash/signature, Autoruns.

### 4. DNS and network

- **Normal:** `microsoft.com`, internal `*.local` names.
- **Suspicious:** random-looking domains (possible DGA, e.g. `xf21zy.biz`), newly registered domains, external 443 from a host that should only reach an internal database, regular beaconing.
- **Context:** domain age, WHOIS, threat-intel reputation, does this host normally talk to the internet?
- **Next artefact:** DNS, firewall and proxy logs, PCAP, Zeek `conn.log` / `dns.log` / `ssl.log`, Sysmon 3 and 22, the process that opened the connection.

### 5. Files and executables

- **Normal:** signed installer from an official source.
- **Suspicious:** double extensions, `update.exe` run from `Downloads`, unsigned binaries, name impersonation.
- **Context:** where did the file come from? Did the user knowingly download it? Is it a legitimate update?
- **Next artefact:** hash + VirusTotal, digital signature, `Zone.Identifier` (source URL), [Prefetch](prefetch.md) (execution and count), [Amcache](amcache.md), [Shimcache](shimcache.md), browser download history.

### 6. USB and data exfiltration

- **Normal:** approved device during work hours.
- **Suspicious:** device connected overnight on a no-USB host, bulk file access right after connection, uploads to external FTP or cloud storage.
- **Context:** work schedule, USB policy, sensitivity of files touched.
- **Next artefact:** `USBSTOR`, `MountedDevices`, `setupapi.dev.log` (first connection), `Partition/Diagnostic` 1006, [LNK and Jump Lists](lnk-jumplists.md) (files opened from the device), Shellbags.

### 7. Browser extensions

- **Normal:** extensions on the allow list.
- **Judgement:** not on the list but no malicious evidence → start at *policy violation / misconfiguration*. Excessive permissions (read all sites, cookies), outbound data or sideloading → *malicious*.
- **Context:** source (store or sideloaded), requested permissions, who installed it.
- **Next artefact:** `...\User Data\Default\Extensions\<ID>\manifest.json`, `Preferences` / `Secure Preferences`, extension ID reputation, proxy logs.

### 8. Log clearing and defence evasion

- **Normal:** retention-based log rollover.
- **Suspicious:** manual clearing, AV disabled, new AV exclusions, audit policy changes.
- **Context:** who cleared them? Was there a recent malware detection?
- **Next artefact:** 1102 (Security log cleared), 104 (System log cleared), 4719 (audit policy changed), Defender 5001/5007, last scan results, copies in the SIEM.

### 9. Privilege and policy changes

- **Normal:** admin change backed by a change request.
- **Judgement:** weakening security (e.g. password complexity disabled) → *potential misconfiguration* until proven otherwise. A standard user modifying a logon script → *suspicious*.
- **Context:** group policy permissions, user privileges, change records.
- **Next artefact:** 5136 (directory object changed), 4728/4732 (member added to group), 4670 (permissions changed), GPO version history, SYSVOL timestamps, registry changes.

### 10. Sensitive file access

- **Normal:** a user whose role fits, during work hours (HR staff opening the HR share at 13:00).
- **Suspicious:** an intern opening `payroll.xlsx`, many files touched in a short time.
- **Context:** job role, access rights, group membership.
- **Next artefact:** 4663 (object access), 5140/5145 (share access), ACLs, access timestamps, group info, LNK and Jump Lists.

## Comparing against a baseline

| Bucket | Test | Example | Next step |
| --- | --- | --- | --- |
| **Normal variation** | Reason recorded, no security impact | AV update moved 02:00 → 07:00 due to network latency | No action if logs and policy agree |
| **Potential misconfiguration** | Security weakened, no attack evidence yet | Password complexity disabled; unlisted browser extension | Check change history; accidental or deliberate? |
| **Suspicious/malicious** | Matches a known technique | 03:14 logon, new Run key, `.ps1` task every 30 min, DGA domain, 01:12 USB, AV process missing | Pull related artefacts and build a timeline |

Order of review:

1. **What disappeared** — a missing AV process matters more than a new one.
2. **What appeared** — autoruns, tasks, services, extensions, accounts.
3. **What changed** — policies, permissions, times, destinations.
4. **Put the times on one line** — 01:12 USB → 03:14 logon → PowerShell → external 443. Weak signals alone become a clear story together.

No baseline? Compare with another host in the same role.

## 2026 trends that change what you look for

Attackers increasingly use **the user's own hands and legitimate tools** instead of custom malware. Look for normal tools used abnormally.

### ClickFix variants — RunMRU is no longer enough

ClickFix tricks users into pasting and running a command from a fake CAPTCHA or error. The classic Win+R version leaves the command in `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`. Early-2026 variants use Win+X → I to open Windows Terminal instead, so RunMRU stays empty ([trackr.live](https://www.trackr.live/?p=1192)).

- **Check:** explorer.exe, a browser or wt.exe spawning powershell/cmd/mshta/regsvr32/rundll32 (Sysmon 1, 4688 with command-line auditing), `-w hidden` / `-enc` / `IEX`, a first-seen domain right after, 4104, `ConsoleHost_history.txt`.
- **Note:** RunMRU shows a command was *entered*, not that it *succeeded*. Padding with spaces can hide the real command.

### CrashFix — a browser extension as the lure

In January 2026 Huntress described CrashFix: a fake extension (**NexShield**, posing as uBlock Origin Lite) deliberately crashes the browser, then a fake "stopped abnormally" warning gets the user to paste a PowerShell command already on the clipboard. It waits an hour after install so the user doesn't connect the two ([Cyber Security News](https://cybersecuritynews.com/crashfix-hackers-using-malicious-extensions/)).

- **Lesson:** an unlisted extension starts as a policy issue, but **extension install → browser crash → RunMRU/PowerShell** on one timeline is malicious.

### RMM abuse — legitimate tools as C2

Huntress's 2026 Cyber Threat Report found RMM abuse up 277% year on year, while traditional hacking tools fell 53%. ScreenConnect, AnyDesk, Atera, NetSupport, PDQ Connect and Splashtop all feature ([Dark Reading](https://www.darkreading.com/application-security/rmm-abuse-explodes-hackers-ditch-malware)).

- **Judgement:** is this RMM **actually approved here**? Even an approved product is suspicious if it connects to an unfamiliar tenant, account or relay.
- **Check:** 7045, install path and signature, first execution in Prefetch/Amcache, the RMM's own connection logs (often under `ProgramData`), external relay domains.

### BYOVD and EDR killers

ESET's June 2026 analysis of **GentleKiller** (The Gentlemen ransomware) shows it loading a vulnerable or malicious kernel driver to kill 400+ processes from 48 security products, disguised with vendor-like names, fake version info and copied signatures ([Security Affairs](https://securityaffairs.com/posts/inside-gentlekiller-the-edr-killer-powering-the-gentlemen)).

- **Judgement:** a security process that **vanished** is a strong signal on its own.
- **Check:** Sysmon 6 (driver loaded), 7045/4697, `.sys` files outside `C:\Windows\System32\drivers`, Defender 5001, driver hashes against LOLDrivers.

### Native Sysmon in Windows 11

In February 2026 Microsoft began shipping Sysmon as a built-in optional feature in Windows 11 Insider builds. It is off by default; enable the feature, then run `sysmon -i`, and events go to the Windows Event Log ([BleepingComputer](https://bleepingcomputer.com/news/microsoft/microsoft-rolls-out-native-windows-11-sysmon-security-monitoring)).

- **Meaning:** more hosts will have Sysmon 1/3/6/13/22. At the start of an investigation, check **whether Sysmon was on and which config it used** — some public configs don't log per-user Explorer keys such as RunMRU.

## Quick reference

Full lists: [Windows event IDs](../basics/windows-event-ids.md) · [Registry keys](registry-keys.md) · [Event logs](event-logs.md)

### Event IDs

| Log | ID | Meaning |
| --- | --- | --- |
| Security | 4624 / 4625 | Logon success / failure (type 3 network, type 10 RDP) |
| Security | 4634 / 4647 | Logoff / user-initiated logoff |
| Security | 4648 | Logon with explicit credentials |
| Security | 4663 | Object (file) access |
| Security | 4688 | Process created (command line needs auditing enabled) |
| Security | 4697 / 4698 | Service installed / scheduled task created |
| Security | 4719 | Audit policy changed |
| Security | 4728 / 4732 | Member added to global / local group |
| Security | 5136 | Directory object modified (e.g. GPO) |
| Security | 5140 / 5145 | Share accessed / detailed share file access |
| Security | 1102 | Security log cleared |
| System | 7045 | New service installed |
| System | 104 | Event log cleared |
| PowerShell | 4103 / 4104 | Module logging / script block logging |
| TS-LocalSessionManager | 21 / 24 / 25 | RDP logon / disconnect / reconnect |
| TS-RemoteConnectionManager | 1149 | RDP authentication succeeded (source IP) |
| Defender | 5001 / 5007 | Real-time protection disabled / config changed |
| Partition/Diagnostic | 1006 | Storage device connected (USB) |
| Sysmon | 1 / 3 / 6 / 13 / 22 | Process / network / driver load / registry value / DNS |

### Registry paths

| Purpose | Path |
| --- | --- |
| Autorun | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, `RunOnce` (and HKLM) |
| Run dialog history | `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` |
| USB devices | `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`, `HKLM\SYSTEM\MountedDevices` |
| Services | `HKLM\SYSTEM\CurrentControlSet\Services` |
| Execution traces | `AppCompatCache` (Shimcache), `UserAssist`, BAM (`...\Services\bam\State\UserSettings`) |

### File locations

| Purpose | Location |
| --- | --- |
| Execution | `C:\Windows\Prefetch\*.pf`, `C:\Windows\AppCompat\Programs\Amcache.hve` |
| Scheduled tasks | `C:\Windows\System32\Tasks\` |
| PowerShell history | `%AppData%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` |
| Event logs | `C:\Windows\System32\winevt\Logs\*.evtx` |
| First USB connection | `C:\Windows\INF\setupapi.dev.log` |
| Recently opened files | `%AppData%\Microsoft\Windows\Recent\` (LNK, `AutomaticDestinations`) |
| Chrome extensions | `%LocalAppData%\Google\Chrome\User Data\Default\Extensions\` |
| Download origin | `Zone.Identifier` ADS (`HostUrl`, `ReferrerUrl`) |

## Sources

- [ClickFix's Cleanest Artifact Is RunMRU. The 2026 Variants Walked Away From It](https://www.trackr.live/?p=1192) — trackr.live
- [CrashFix: hackers using malicious extensions](https://cybersecuritynews.com/crashfix-hackers-using-malicious-extensions/) — Cyber Security News, 2026-01-19
- [RMM Abuse Explodes as Hackers Ditch Malware](https://www.darkreading.com/application-security/rmm-abuse-explodes-hackers-ditch-malware) — Dark Reading, 2026-02-17
- [Inside GentleKiller: The EDR-Killer Powering The Gentlemen](https://securityaffairs.com/posts/inside-gentlekiller-the-edr-killer-powering-the-gentlemen) — Security Affairs, 2026-06-20
- [Microsoft rolls out native Windows 11 Sysmon security monitoring](https://bleepingcomputer.com/news/microsoft/microsoft-rolls-out-native-windows-11-sysmon-security-monitoring) — BleepingComputer, 2026-02-04
