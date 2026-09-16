---
title: Windows Event IDs
tags:
  - concept
  - basics
  - windows
---

# Windows Event IDs

<div class="dfir-meta" markdown>
**Category:** basics · **Last updated:** 2026-09-09
</div>

!!! abstract "In one sentence"
    The event IDs an incident responder looks for first, grouped by question ("who logged on?", "what ran?", "what persisted?"). Legacy (pre-Vista) IDs are usually the modern ID minus 4096 — `528` → `4624`.

!!! warning "Not everything is on by default"
    `4688` (process creation), `4698` (scheduled task), `4104` (PowerShell script block) and most object-access events need audit policy or GPO changes. Before concluding "nothing ran", confirm the log source was enabled — check `Security` for `4719` (audit policy changed) and look at the earliest event timestamp to detect log clearing / rollover.

## Logon & authentication (Security log)

| ID | Meaning | Notes |
|---|---|---|
| 4624 | Successful logon | See **Logon Type** table below. `Logon ID` links to 4634/4647 and to 4672 |
| 4625 | Failed logon | `Status`/`SubStatus` say why (`0xC000006A` wrong password, `0xC0000064` no such user, `0xC0000234` locked out) |
| 4634 | Logoff | Session end |
| 4647 | User-initiated logoff | Interactive logoff |
| 4648 | Logon with explicit credentials | `runas`, scheduled tasks with stored creds, lateral movement with alternate creds |
| 4672 | Special privileges assigned | Admin-equivalent logon. Pair with the 4624 that has the same Logon ID |
| 4768 | Kerberos TGT requested (AS-REQ) | On DC. `Result Code 0x6` = user does not exist; `0x18` = bad password |
| 4769 | Kerberos service ticket requested (TGS-REQ) | On DC. **Kerberoasting**: many 4769 with `Ticket Encryption Type 0x17` (RC4) from one account |
| 4771 | Kerberos pre-auth failed | Kerberos brute force |
| 4776 | NTLM credential validation | On DC (domain) or local machine. Bursts = spraying |
| 4778 / 4779 | RDP session reconnected / disconnected | Includes source hostname & IP |
| 4740 | Account locked out | Points to the `Caller Computer Name` |
| 4767 | Account unlocked | |

### 4624 Logon Types

| Type | Name | Typical meaning |
|---|---|---|
| 2 | Interactive | At the keyboard (or via VNC-style tool) |
| 3 | Network | SMB share access, WinRM (pre-auth), PsExec, WMI. Most lateral movement |
| 4 | Batch | Scheduled task |
| 5 | Service | Service start |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | IIS Basic auth, some PowerShell remoting |
| 9 | NewCredentials | `runas /netonly`, Cobalt Strike `make_token`, pass-the-hash tooling |
| 10 | RemoteInteractive | RDP / Terminal Services |
| 11 | CachedInteractive | Domain creds used while DC unreachable (laptop off-network) |

## Account management (Security log)

| ID | Meaning |
|---|---|
| 4720 | User account created |
| 4722 | User account enabled |
| 4723 / 4724 | Password change attempt (user) / reset (admin) |
| 4725 | User account disabled |
| 4726 | User account deleted |
| 4728 / 4732 / 4756 | Member added to global / local / universal **security** group |
| 4729 / 4733 / 4757 | Member removed from the same |
| 4738 | User account changed |
| 4741 / 4742 / 4743 | Computer account created / changed / deleted |
| 4794 | DSRM password set (Directory Services Restore Mode — DC persistence) |

## Process & command execution

| Log | ID | Meaning | Notes |
|---|---|---|---|
| Security | 4688 | New process created | Enable *Include command line in process creation events* via GPO, otherwise you get the image path only |
| Security | 4689 | Process exited | |
| Sysmon | 1 | Process create | Command line, hashes, parent — the gold standard if Sysmon is deployed |
| Sysmon | 3 | Network connection | Process ↔ destination IP/port |
| Sysmon | 7 | Image loaded | DLL load — side-loading, unsigned DLLs |
| Sysmon | 8 | CreateRemoteThread | Classic injection |
| Sysmon | 10 | ProcessAccess | LSASS access (`lsass.exe` target, `0x1010`/`0x1fffff` access) = credential dumping |
| Sysmon | 11 | File created | Droppers, staged tools |
| Sysmon | 12 / 13 / 14 | Registry object create/delete / value set / key rename | Run keys, services |
| Sysmon | 22 | DNS query | Process → domain |
| PowerShell/Operational | 4103 | Module logging (pipeline execution) | |
| PowerShell/Operational | 4104 | Script block logging | Decoded script content — even `-enc` payloads. Enable via GPO |
| Windows PowerShell (classic) | 400 / 403 | Engine start / stop | `HostApplication` field shows the command line even without 4688 |
| Windows PowerShell (classic) | 600 | Provider started | |
| Security | 4698 / 4699 | Scheduled task created / deleted | Task XML is in the event |
| Security | 4700 / 4701 / 4702 | Scheduled task enabled / disabled / updated | |
| TaskScheduler/Operational | 106 / 140 / 141 / 200 / 201 | Task registered / updated / deleted / action started / action completed | Log is often disabled by default on newer builds |
| System | 7045 | New service installed | PsExec (`PSEXESVC`), Cobalt Strike `jump psexec`, Meterpreter services |
| Security | 4697 | Service installed (Security-side view of 7045) | Requires audit policy |
| System | 7034 / 7035 / 7036 / 7040 | Service crashed / control sent / state change / start type changed | 7040 = someone set a service to disabled (e.g. Defender, VSS) |
| Application | 1000 / 1001 | Application crash / WER report | Exploit gone wrong, injected process crashing |

## Persistence & tampering

| Log | ID | Meaning |
|---|---|---|
| Security | 4657 | Registry value modified (needs SACL) |
| Security | 4663 | Object access attempt (file/registry, needs SACL) |
| Security | 4670 | Permissions on an object changed |
| Security | 4719 | System audit policy changed — attackers turn logging off |
| Security | 1102 | **Security log cleared** |
| System | 104 | **Event log cleared** (any log) |
| Security | 4616 | System time changed |
| Security | 4720 | (see above) new local user = persistence |
| Security | 5140 / 5145 | Network share accessed / share object checked (`\\*\ADMIN$`, `\\*\C$`, `IPC$`) |
| Security | 5156 / 5157 | Windows Filtering Platform allowed / blocked a connection (very noisy) |
| Windows Defender/Operational | 1116 / 1117 | Malware detected / action taken |
| Windows Defender/Operational | 5001 / 5007 | Real-time protection disabled / config changed |
| Microsoft-Windows-WMI-Activity/Operational | 5857 – 5861 | WMI provider / consumer activity. **5861** = permanent event consumer created (WMI persistence) |
| Security | 4720 + 4732 in quick succession | New user immediately added to Administrators |

## Remote access & lateral movement

| Log | ID | Meaning |
|---|---|---|
| Security | 4624 type 3 + 5140 `ADMIN$` + System 7045 | PsExec-style execution chain |
| Security | 4624 type 10 / 4778 | RDP logon |
| TerminalServices-RemoteConnectionManager/Operational | 1149 | RDP network connection succeeded (pre-logon) — includes source IP |
| TerminalServices-LocalSessionManager/Operational | 21 / 22 / 24 / 25 | RDP session logon / shell start / disconnect / reconnect |
| RemoteDesktopServices-RdpCoreTS/Operational | 131 | Incoming RDP connection (source IP) |
| Microsoft-Windows-WinRM/Operational | 6 / 91 / 168 | WinRM client connecting / shell created / authenticating user |
| Security | 4688 `wsmprovhost.exe` | PowerShell Remoting on the **target** |
| Security | 4688 `wmiprvse.exe` parent | WMI execution on the **target** |
| Security | 4648 | Explicit creds — often the **source** side of lateral movement |
| Security | 4624 type 9 | `runas /netonly` / pass-the-hash style token |

## USB & devices

| Log | ID | Meaning |
|---|---|---|
| Security | 6416 | New external device recognised |
| Security | 6419 – 6424 | Device install / disable / enable events |
| DriverFrameworks-UserMode/Operational | 2003 / 2100 / 2102 | USB device plugged in / unplugged (log often disabled) |
| Microsoft-Windows-Partition/Diagnostic | 1006 | Device connected/disconnected with serial & partition info |
| Security | 4663 on `\Device\HarddiskVolume` | File access on removable media (needs SACL) |

## Cheat: first triage query set

=== "Splunk"

    ```spl
    index=wineventlog sourcetype=WinEventLog:Security
    EventCode IN (1102, 4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4732, 4776)
    | eval LogonType=coalesce(Logon_Type, LogonType)
    | stats count min(_time) as first max(_time) as last by host, EventCode, user, LogonType
    | convert ctime(first) ctime(last)
    | sort host, EventCode
    ```

=== "PowerShell (live)"

    ```powershell
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4648,4672,4688,4698,4720,1102; StartTime=(Get-Date).AddDays(-7)} |
      Select-Object TimeCreated, Id, @{n='Msg';e={$_.Message.Split("`n")[0]}} |
      Format-Table -AutoSize
    ```

=== "EvtxECmd (offline)"

    ```powershell
    EvtxECmd.exe -d C:\Case\Logs --csv C:\Case\Out --inc 1102,4624,4625,4648,4672,4688,4697,4698,4720,4732,7045
    ```

## References

- [Microsoft — Security auditing event reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [Ultimate Windows Security — Event ID encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [SANS — Windows Event Log Analysis poster / Hunt Evil](https://www.sans.org/posters/)
- [Sysmon event ID reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
