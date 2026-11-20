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

!!! info "Coming next"
    Services, scheduled tasks and USB devices, account and group changes, Defender and PowerShell logging, and Kerberos (4768, 4769, 4770).

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

## Related { #related }

- [Windows Logging](../windows-logging/index.md) — how the Security log is produced and structured
- [Linux Logging](../linux-logging/index.md) — syslog, log files and the journal
- [Endpoint Attacks](../endpoint-attacks/index.md) — the attacker actions these events record
- [Windows Event Logs (EVTX)](../../../windows/event-logs.md)
