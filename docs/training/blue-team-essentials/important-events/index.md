---
title: Important Events
tags:
  - training
  - blue-team
  - windows
  - linux
  - logging
---

# Important Events { #important-events }

!!! abstract "In one line"
    A handful of Windows event IDs and Linux log lines answer most investigation questions: who logged on, how and from where; what ran; what was allowed or blocked; what was installed to survive a reboot; which accounts changed; what the antivirus and PowerShell saw; and how Kerberos tickets were issued. This section reads each of them field by field, with what it means, when it fires and why attackers care.

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [Login Events — 4624/4625 and Logon Types, 4648 Explicit Credentials, Linux Logins and Login Failures](logins.md) | 4624 written on the target, full EventData field by field (Subject vs Target, `TargetDomainName` = computer name for local accounts, `LogonProcessName`, `AuthenticationPackageName`, untrustworthy `WorkstationName`, `IpAddress`, `ElevatedToken`/linked logons); logon types 2–13 table with corrections (type 11 = cached, type 2 ≠ physical presence), RDP as type 3 + 10; Logon ID pivot to 4672/4688/4634/4647; computer-account and service noise, `Get-WinEvent` filter read line by line; 4625 with Status/SubStatus table, RDP-with-NLA failures as type 3, DC-side 4771/4776; 4648 on the source machine, subject/target/server/process, runas story, type 9 `seclogo`; Linux SSH login spread over PID-linked lines, key fingerprints (T1098.004), `sshd-session`; Linux failure shapes (`Invalid user`, `Failed password`, PAM `authentication failure`, sudo), passwords typed as usernames, counting failures per IP; Windows vs Linux table; T1078, T1110, T1021, T1550.002, T1134.002; SOC checklist; practice questions |
| 2 | [Process Creation Events — 4688, Sysmon Event 1, auditd and audit.log, Snoopy](process-creation.md) | Why process logs catch most attacks (LOLBins, T1059/T1218), ideal fields table and sources; 4688 with Audit Process Creation and the separate command-line policy, full EventData field by field (`ProcessId` = parent, `TokenElevationType` %%1936/7/8, `MandatoryLabel`), Word → cmd → certutil chain, `Get-WinEvent` filter line by line; Sysmon Event 1 extras (`ProcessGuid`, `OriginalFileName`, `Hashes`/IMPHASH, `ParentCommandLine`, `ParentUser`) and the correction that it carries no signature; 4688 vs Sysmon table; auditd `execve` rule word by word (b64 + b32, `execveat`, rules.d), six-line `audit.log` record read field by field (serial number, `syscall=59`, `auid` vs `uid`, `tty`, `ses`), hex-encoded EXECVE/PROCTITLE, `ausearch -i` and `aureport -x`; tuning and protecting auditd (T1562.012, `-e 2`); Snoopy via `ld.so.preload`, a line field by field, enumeration-script story, bypasses (T1574.006); four-source comparison; SOC checklist; practice questions |
| 3 | [Firewall and Object Access Events — Windows Firewall Logs (pfirewall.log, 5156/5157/5152/5154), iptables/UFW Logs, 4663/4657/4660](firewall-object-access.md) | Host firewalls as process-aware sensors for east-west traffic; `pfirewall.log` setup (per-profile files, 4,096 KB default, ~32 MB max, `.old` rollover), header and every column read, local time, PID but no name, a neighbour probing 445/3389/ICMP; Filtering Platform audit subcategories with `auditpol`, 5156/5157/5152/5154/5158 table, a full 5156 field by field (decimal `ProcessID`, device paths, `%%14593` direction, `FilterRTID`, layers); firewall-change events 4946–4950 and 2003–2006/2097 (T1562.004); iptables `LOG` rule word by word, UFW prefixes, two kernel lines split into syslog header and `KEY=value` fields, bare flags and the double `LEN`, no process, nftables; comparison table; object access needs policy **and** SACL, 4663 Subject/Object/Process/Access with access-mask table and SMB as PID 4, 4657 old/new value on a Run key (T1547.001), 4660 joined by `HandleId`, 4656/4658/4670/5140/5145 and LSASS; SOC checklist; practice questions |
| 4 | [Service, Scheduled Task and USB Events — 7045/4697, 4698–4702 and Task Scheduler Logs, 6416 Plug and Play](services-tasks-usb.md) | Services as persistence (T1543.003) and remote execution (T1569.002, PsExec-style temporary services); service settings table (`ImagePath`, type, start type, account); 7045 in the System channel read field by field (`Security UserID` as the only "who", command-line `ImagePath` with `%COMSPEC%` and `\\127.0.0.1\C$`, demand vs auto start), companion 7036/7009/7040 and parent `services.exe`; modified `ImagePath` writes no install event; 4697 with *Security System Extension* and Subject/Logon ID, 7045 vs 4697 table; triage checklist and stacking; scheduled tasks (T1053.005) for persistence and remote execution, *Other Object Access Events* (no SACL needed), full 4698 with nested `TaskContent` XML read line by line (trigger, SYSTEM principal, `Hidden`, `Exec` with rundll32), parsing the nested XML; 4699–4702 table; Task Scheduler Operational 106/129/140/141/200/201 timeline; hidden tasks via deleted `SD` value; USB threats (T1091, T1052.001, T1200), *Plug and Play Events*, full 6416 field by field (subject is always SYSTEM, VID/PID/instance ID, `HIDClass`, `Class_03` keyboard), multiple 6416s per device, VID/PID lookups and their limits, other device logs; SOC checklist; practice questions |
| 5 | [Account, Defender and PowerShell Events — 4720, 4728/4732/4756 Group Changes, Defender 1116/1117/1006, PowerShell 4103/4104](accounts-defender-powershell.md) | Account creation as persistence (T1136.001/.002) and admin-group adds (T1098.007); *User Account Management* and *Security Group Management* checked with `auditpol`; full 4720 field by field (`TargetDomainName` = computer for local accounts, RID, `%%` codes, `UserAccountControl` %%2080/2082/2084, `SidHistory`), the 4722/4724/4738/4732 burst behind `net user /add`; full 4732 (`MemberName` `-` for local accounts, `MemberSid`, `TargetSid` S-1-5-32-544, other well-known group SIDs); correction: ID by group scope — 4732 local/domain local incl. BUILTIN\\Administrators on DCs, 4728 global, 4756 universal; life-cycle table (4722–4726, 4738, 4740/4767, 4781, 4798/4799); triage order and `Get-WinEvent` line by line; Defender Operational channel, full 1116 field by field (threat name types, `Process Name`, `Path` prefixes, `Origin`, `Execution`, `Source`), 1117 by `Detection ID`, event table 1006/1007/1008/1015/1118/1119/1121–1126/2001/5001/5007/5010/5013, exclusions abuse (T1562.001), `Get-MpThreatDetection`; PowerShell log types table, `ScriptBlockLogging` registry check, full 4104 for an `-Enc` cradle (Level 3 auto-warning, `ProcessID`, split blocks, `ScriptBlockId`, `Path`), why obfuscation layers show up, Base64 UTF-16LE decoding and reassembly line by line, noise handling and log size, 4103 `ParameterBinding`, transcription, v2 downgrade (T1562.010, event 400) and its removal, PowerShell 7 `PowerShellCore/Operational`; SOC checklist; practice questions |

!!! info "Coming next"
    Kerberos: the authentication service and ticket-granting service, and events 4768, 4769 and 4770.

## Things to remember { #must-know }

1. 4624/4625 are written on the machine being logged on to; 4648 on the machine the credentials were used from. Collect from workstations, servers and domain controllers.
2. Logon type is the door: 2 console, 3 network, 4 batch, 5 service, 7 unlock, 8 cleartext, 9 new credentials, 10 RDP, 11 cached. Type 11 is not "domain user at the keyboard"; type 2 is not proof of physical presence.
3. For a local account, the domain field is the computer name — a local account logging on over the network to many hosts is a red flag.
4. The Logon ID links a logon to its privileges, processes and logoff; search it together with the host name.
5. Filter computer accounts and service identities in queries, never at collection.
6. SubStatus tells you why a logon failed: `0xc0000064` no such user, `0xc000006a` wrong password, `0xc0000234` locked out.
7. Linux logins are multi-line free text tied by PID; every login program and every failure reason needs its own pattern.
8. Login logs contain sensitive data (passwords typed as usernames) — restrict access.
9. Process creation: the command line and the parent are the fields that matter. 4688 needs the separate command-line policy; in 4688 `ProcessId` is the parent.
10. On Linux, auditd `auid` keeps the original login user through `sudo`; `auid` unset + `tty=(none)` running a shell means a daemon or webshell, not a person.
11. Host firewall logs see east-west traffic; on Windows, 5156/5157 also name the process. Plan volume before enabling Filtering Platform Connection success.
12. Object access events (4663/4657/4660) need the audit subcategory **and** a SACL on the object; no SACL, no event. 4660 has no name — follow the `HandleId`.
13. Service installs: 7045 in **System** (always on) and 4697 in Security (needs *Security System Extension*). Read `ImagePath` first — a command line or a user-writable folder is the red flag.
14. Scheduled tasks: 4698–4702 need *Other Object Access Events*; the command is in nested XML inside `TaskContent`. 6416 shows new devices by class and VID/PID — watch keyboards and network adapters, not just storage.
15. Account changes: 4720 for new users; group adds by **scope** — 4732 local/domain local (including Administrators on DCs), 4728 global, 4756 universal. Match on `MemberSid` and `TargetSid`, and collect from every DC.
16. Defender writes to its own Operational channel: 1116/1117 (and 1006/1007) for detections, 5001/5007/5013 for someone tampering with Defender. PowerShell 4104 shows the decoded code but not its output; watch for version 2 (event 400) and collect PowerShell 7's own channel.

## Related { #related }

- [Windows Logging](../windows-logging/index.md) — how the Security log is produced and structured
- [Linux Logging](../linux-logging/index.md) — syslog, log files and the journal
- [Endpoint Attacks](../endpoint-attacks/index.md) — the attacker actions these events record
- [Windows Event Logs (EVTX)](../../../windows/event-logs.md)
