---
title: Windows Logging
tags:
  - training
  - blue-team
  - windows
  - logging
---

# Windows Logging { #windows-logging }

!!! abstract "In one line"
    Almost every endpoint investigation ends up in Windows event logs, so an analyst has to know where they come from: which program (provider) wrote an event, how the Event Log service sorts it into a channel and an `.evtx` file, what decided whether the event was recorded at all (audit policy, Sysmon, custom channels), and how one event's XML becomes the readable message you see — because that decides what you can search for, what can be missing, and how your SIEM should parse it.

## Reading order { #reading-order }

| # | Page | Key points |
| --- | --- | --- |
| 1 | [How Windows Event Logging Works — Providers, Channels, the Log Path, Audit Settings and the Three Views of One Event](how-event-logging-works.md) | Why analysts must understand collection (zero results = didn't happen / never recorded / never collected); format, content, collection; Windows vs Linux, binary-XML `.evtx`; Windows Logs vs Applications and Services Logs, channel types (Admin/Operational/Analytic/Debug), why Security is special; the log path provider → EventLog service → channel → `winevt\Logs` (`%4` in file names) → Event Viewer/`Get-WinEvent`/`wevtutil`/agents; tampering T1070.001/T1562.002, 1102/104; `Get-WinEvent -ListLog` and `-FilterHashtable` read line by line, 4625 bursts (T1110); audit policy with `auditpol` (4624/4625/4688/4663, SACLs), legacy vs advanced, 4719; Sysmon and a custom channel with `New-EventLog`/`Write-EventLog` (5.1 only); apps with their own logs, Zeek/Suricata; metadata: level table, keywords Audit Success/Failure, provider, event ID per provider (System ID 1 Power-Troubleshooter vs Kernel-General), task category, `EventRecordID` gaps; one 4625 in General, Friendly and XML views field by field (UTC, `%%2313`), message templates, localisation and why the SIEM needs EventData; practice questions |
| 2 | [Inside a Windows Event — System vs EventData, Templates and Descriptions, and the Channels Worth Collecting](event-structure-channels.md) | Envelope vs letter; a full 4624 v2 read field by field — System (Provider/GUID, Version, Level, Task, Opcode, Keywords, UTC `TimeCreated`, `EventRecordID`, Correlation, `Execution ProcessID` = writer/LSASS, Channel, Computer, Security UserID) and EventData (Subject vs Target, `TargetLogonId` as session pivot, LogonType 10, padded `"User32 "`, `IpAddress`, `%%1833`/`%%1843`, linked/elevated tokens); UserData in 1102 (Eventlog provider, T1070.001) and unnamed classic `<Data>`; `Get-WinEvent -ListProvider`, three 4624 versions, the template with `inType`/`outType`, `wevtutil gp`, `[xml]$e.ToXml()` field extraction; the description with `%1`…`%27`, SID rendering; putting it together, why a message regex fails, agent JSON; channels of interest table (PowerShell 4104 cradle T1059.001/T1105, PowerShellCore, Security-Mitigations, CodeIntegrity 3076/3077, AppLocker 8002–8007, Defender 1116/1117/5001/5007/5013, Firewall IDs on new builds, Sysmon) plus TaskScheduler, TerminalServices, WMI-Activity 5861, Bits-Client; `IsEnabled` check; XPath QueryList filtering; the four section questions; practice questions |

!!! success "Section complete"
    The Windows logging section is complete. Next: **Linux Logging** — how Linux logging works, what "syslog" means (format, network protocol, daemons), facility and severity, the traditional log files, the systemd journal and command-line logging.

## Things to remember { #must-know }

1. Zero results means nothing until you know the event was configured, recorded, kept and collected.
2. Path: provider → Windows Event Log service → channel → `.evtx` in `C:\Windows\System32\winevt\Logs` → reader or agent. Every step can be attacked, so ship logs off the host fast and alert on 1102, 104 and 4719.
3. The audit policy decides which Security events exist. Verify the effective policy with `auditpol`, use the advanced policy only, and add Sysmon where the built-in policy is blind.
4. An event ID only means something with its provider. Write detections on provider (or channel) + ID.
5. The General view is a template filled with XML values — localised and hard to parse. Send structured EventData fields to the SIEM.
6. System fields are the same in every event; EventData/UserData fields depend on provider, ID and version. `Execution ProcessID` is the writer; `TargetLogonId` is the session pivot.
7. Collect beyond the big three — PowerShell/Operational with script block logging, Sysmon, Defender, CodeIntegrity, AppLocker, Security-Mitigations, Firewall, TaskScheduler, TerminalServices, WMI-Activity — and check on the hosts that they are enabled.

## Related { #related }

- [Endpoint Defense](../endpoint-defense/index.md) — audit policy and central collection as a defence layer
- [Windows Event Logs (EVTX)](../../../windows/event-logs.md)
- [Windows Event IDs](../../../basics/windows-event-ids.md)
