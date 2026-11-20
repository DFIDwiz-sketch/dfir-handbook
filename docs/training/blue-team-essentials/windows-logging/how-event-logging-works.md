---
title: "How Windows Event Logging Works — Providers, Channels, the Log Path, Audit Settings and the Three Views of One Event"
tags:
  - training
  - blue-team
  - windows
  - logging
  - event-logs
---

# How Windows Event Logging Works — Providers, Channels, the Log Path, Audit Settings and the Three Views of One Event { #how-event-logging-works }

!!! abstract "What this page covers"
    Why an analyst should understand log collection even when "someone else" runs it, and then how Windows actually produces the events you search every day. The path a log takes — program (provider) → Windows Event Log service → channel → `.evtx` file → Event Viewer, `Get-WinEvent`, `wevtutil` or a collection agent — and what each step means for you. Why `.evtx` files can't be read in a text editor, where they live and why the file names contain `%4`. Channel types (Admin, Operational, Analytic, Debug). What decides *which* security events exist in the first place: audit policies (legacy vs advanced, success vs failure, SACLs), add-ons such as Sysmon, custom channels written by scripts, and applications that keep their own text logs. The metadata every event carries — level, provider (source), event ID, task category, keywords — and the important correction that an event ID only means something together with its provider. Finally the same event in three views (General, Friendly, XML), how the "message" text is built from a template, and why the SIEM should receive the structured fields. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs, file names and hashes are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. **Log collection is not "someone else's job"** for an analyst. If you don't know where a log comes from, what it can contain and what gets lost on the way, you can't tell "the attacker didn't do it" from "we never recorded it".
2. Windows programs don't write log files themselves. They hand events to the **Windows Event Log service**, which sorts each event into a **channel** (Security, System, Application, and hundreds more) and stores every channel in its own **`.evtx`** file under `C:\Windows\System32\winevt\Logs`.
3. `.evtx` is a **binary-encoded XML** format. You need a tool to read it — Event Viewer, `Get-WinEvent`, `wevtutil`, a forensic parser or a log agent — never Notepad.
4. Which security events exist at all is decided **before** anything happens, by the **audit policy** (what to record, on success and/or failure), plus add-ons such as **Sysmon**, plus custom channels. If the audit setting was off, there is no event to find later.
5. Not everything goes to the event log. Many applications and network services (web servers, DNS servers, databases) write **their own text logs** — or log nothing useful — so you configure them separately or capture that activity from the network with sensors such as Zeek or Suricata.
6. Every event carries metadata: **level** (how serious), **provider / source** (which program wrote it), **event ID** (what kind of event), **task category** and **keywords** (for Security: Audit Success / Audit Failure).
7. **[Correction]** An event ID is only unique **per provider**, not globally — and one channel can contain several providers. "Event ID 1" means different things from different providers, even in the same channel. Always filter on provider (or channel *and* provider) plus ID.
8. One event, **three views**: the readable **General** (message) view, the **Friendly** details view and the raw **XML** view. The message is built by pouring the XML fields into a text template. Send the structured XML fields to your SIEM — the message text is for humans, is localised, and is hard to parse.

## Why an analyst must understand log collection { #why-it-matters }

### "Isn't that someone else's job?" { #someone-elses-job }

In many organisations a separate team installs the log agents, builds the SIEM and decides what gets forwarded. It is tempting to treat logs like tap water: you open the SIEM and data comes out. The problem appears the first time you search for something and get **zero results**. Zero results can mean three very different things:

1. The activity really didn't happen.
2. It happened, but Windows was never configured to record it (audit policy off, Sysmon not installed, command-line logging disabled).
3. It was recorded on the host but never reached the SIEM (the channel isn't collected, the agent was down, the local log rolled over before collection, a parser dropped the field).

Only the first is a real "no". An analyst who doesn't know the pipeline will report case 2 or 3 as "no evidence of compromise" — which is one of the most expensive mistakes in a SOC.

Think of logs as a **security camera system**. If you don't know which corridors have cameras, whether they record at night, and how long footage is kept, an empty recording proves nothing. Knowing the camera map is part of the investigator's job, not just the installer's.

### What you need to know about every log source { #three-things }

For every log source you rely on, you should be able to answer three questions:

- **Format** — how is it stored and structured? (binary XML for Windows, text lines for classic Linux syslog, JSON for many cloud and EDR sources). This decides how it can be parsed and what can go wrong.
- **Content** — which fields exist and what do they really mean? (Does this 4688 include the command line? Is that IP the client or the proxy?)
- **Collection** — how does it get from the host to you, how fast, and what gets dropped or changed along the way?

Reading logs is a daily task for an analyst. Understanding the pipeline turns that from "staring at whatever arrives" into knowing what you *should* be seeing — and asking for improvements when it's missing. The rest of this page answers the three questions for Windows.

## How Windows event logging works { #how-it-works }

### Why Windows is different from Linux { #windows-vs-linux }

On a classic Linux system, logs are mostly plain text: a daemon sends a line to syslog, and syslog appends it to a file such as `/var/log/auth.log`. You can `cat` or `grep` it immediately (the next section, Linux Logging, covers this and the systemd journal).

Windows takes a more structured — and more complex — route:

- The operating system and applications write events to **log channels**.
- Each channel is stored in an **`.evtx` file<strong>, which contains </strong>XML records in a binary-encoded form**.
- So a `.evtx` file can't simply be opened in a text editor. It must be interpreted by a tool that understands the format.
- The most familiar tool is **Event Viewer** (`eventvwr.msc`). Its left pane lists the channels.

The analogy: a Linux text log is a notebook you can read by opening it. A Windows `.evtx` file is closer to a **database file** — the data is all there and well structured, but you need the right program to open it. The pay-off for the complexity is that every Windows event has named fields, which makes it far easier to parse reliably than free-form text.

### Opening Event Viewer: the channels you see { #channels-overview }

Open Event Viewer and you see two groups on the left:

- **Windows Logs** — the classic channels everybody knows: **Application**, **Security**, **Setup**, **System** and **Forwarded Events** (the destination for Windows Event Forwarding).
- **Applications and Services Logs** — hundreds of more specific channels, mostly under `Microsoft → Windows → <component> → <type>`, for example `Microsoft-Windows-PowerShell/Operational`, `Microsoft-Windows-TaskScheduler/Operational`, `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` or, once installed, `Microsoft-Windows-Sysmon/Operational`.

Many people stop at Application, Security and System. That's a mistake: several of the most useful sources for detecting attacks (PowerShell script blocks, scheduled-task changes, RDP session history, Defender detections, Sysmon) live in the second group. Many of the rest are noise. Which channels a SOC should actually collect is covered on the next page of this section.

**[Supplement] Channel types.** Each channel has a type that tells you its purpose:

| Type | Meant for | Enabled by default? | Example |
| --- | --- | --- | --- |
| Admin | Administrators — events that usually need action | Yes | `Microsoft-Windows-PrintService/Admin` and other `…/Admin` channels |
| Operational | Analysis and troubleshooting of a component | Usually yes | `Microsoft-Windows-PowerShell/Operational` |
| Analytic | High-volume, detailed tracing | No (hidden) | various `…/Analytic` channels |
| Debug | Developers | No (hidden) | various `…/Debug` channels |

Analytic and Debug channels only appear after **View → Show Analytic and Debug Logs**, and must be enabled before they record anything. They are rarely worth collecting centrally because of the volume.

**[Supplement] The Security channel is special.** Only the Local Security Authority (LSA) can write to it, through the auditing subsystem. Normal programs can't add events to Security, which is part of why it is trusted. (Reading it also needs administrative rights or the "Manage auditing and security log" privilege.)

### The log path, step by step { #log-path }

Here is the journey of one event, from the moment something happens to the moment you read it:

```
[program / OS component]           e.g. LSA, Service Control Manager, PowerShell, Sysmon
        |  "provider" writes an event (ID + fields) via the Event Log / ETW API
        v
[Windows Event Log service]        svchost.exe hosting the "EventLog" service
        |  uses the provider's metadata (manifest) to pick the channel
        v
[log channels]                     Security, System, Application, …/Operational
        |  each channel = one file
        v
C:\Windows\System32\winevt\Logs\*.evtx
        |
        +--> Event Viewer (eventvwr.msc)
        +--> PowerShell Get-WinEvent / wevtutil.exe
        +--> forensic parsers (EvtxECmd, Hayabusa, Chainsaw, …)
        +--> collection agents / Windows Event Forwarding --> SIEM
```

Step by step:

1. **The provider writes the event.** A *provider* is the software component that defines and emits events — for example `Microsoft-Windows-Security-Auditing` (LSA auditing), `Service Control Manager`, `Microsoft-Windows-PowerShell` or `Microsoft-Windows-Sysmon`. The provider supplies an event ID and the values for that event's fields.
2. **The Windows Event Log service receives it.** This service (`EventLog`, running inside a `svchost.exe`) is the single post office for events. Using the provider's registered metadata (its *manifest*), it knows which channel the event belongs to.
3. **The event is written to a channel.** Each channel is its own `.evtx` file. Each channel also has a maximum size and a retention behaviour (by default, overwrite the oldest events when full).
4. **Something reads the file.** Event Viewer is the usual GUI, but PowerShell, `wevtutil`, forensic tools and log agents all read the same files through the same Windows API (or, for offline forensic parsers, by decoding the binary format directly).

Let's look at the files themselves:

```
PS C:\> Get-ChildItem C:\Windows\System32\winevt\Logs |
>>   Sort-Object Length -Descending | Select-Object -First 6 Name, @{n='MB';e={[math]::Round($_.Length/1MB,1)}}

Name                                                        MB
----                                                        --
Microsoft-Windows-Sysmon%4Operational.evtx                64.1
Security.evtx                                             20.1
System.evtx                                               20.1
Application.evtx                                          20.1
Microsoft-Windows-PowerShell%4Operational.evtx            15.1
Microsoft-Windows-TaskScheduler%4Operational.evtx         10.1
```

- `Get-ChildItem C:\Windows\System32\winevt\Logs` — lists the folder where every channel's `.evtx` file lives.
- `Sort-Object Length -Descending | Select-Object -First 6 …` — shows the six largest files with their size in MB (`@{n='MB';e={…}}` is a calculated column).
- `Security.evtx 20.1` — the Security channel. About 20 MB is the long-standing default maximum on many Windows versions. On a busy server that may hold only hours of events, which is why security baselines raise it a lot and why central collection must be quick.
- `Microsoft-Windows-Sysmon%4Operational.evtx` — the channel `Microsoft-Windows-Sysmon/Operational`. A `/` can't appear in a file name, so Windows writes it as **`%4`**. When you search a forensic image for a channel's file, swap `/` for `%4`.
- `Microsoft-Windows-Sysmon%4Operational.evtx 64.1` — Sysmon is noisy, so its channel is usually given a larger maximum size than the default.

**Why attackers care about this path.** Every step is a place to blind the defender: stop or crash the EventLog service, turn auditing off with `auditpol`, shrink a channel so it rolls over fast, delete or corrupt `.evtx` files, or clear a channel (MITRE ATT&CK **T1070.001** Clear Windows Event Logs, **T1562.002** Disable Windows Event Logging). Clearing the Security log itself leaves **Security 1102** ("The audit log was cleared"), and clearing other channels leaves **System 104**. That is exactly why logs must leave the host quickly — a copy in the SIEM survives what happens on the endpoint. See [Impair Defenses & Log Clearing](../../../adversary/impair-defenses-log-clearing.md).

### Reading events from the command line { #reading-events }

Event Viewer is fine for one event; for triage and hunting you'll use PowerShell. First, which channels exist and how full are they?

```
PS C:\> Get-WinEvent -ListLog Security, System, 'Microsoft-Windows-PowerShell/Operational' |
>>   Format-Table LogName, RecordCount, MaximumSizeInBytes, LogMode -AutoSize

LogName                                  RecordCount MaximumSizeInBytes   LogMode
-------                                  ----------- ------------------   -------
Security                                       41873           20971520  Circular
System                                         18240           20971520  Circular
Microsoft-Windows-PowerShell/Operational        9311           15728640  Circular
```

- `Get-WinEvent -ListLog …` — returns the *configuration* of the named channels, not their events. `-ListLog *` lists every channel on the machine (several hundred).
- `RecordCount` — how many events the channel currently holds.
- `MaximumSizeInBytes 20971520` — 20 MB. When full, `LogMode Circular` means the oldest events are overwritten. So "the earliest event in Security" tells you how far back the local evidence reaches.

Now the events themselves — the last three failed logons:

```
PS C:\> Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 3

   ProviderName: Microsoft-Windows-Security-Auditing

TimeCreated                     Id LevelDisplayName Message
-----------                     -- ---------------- -------
20/11/2026 02:14:09 AM        4625 Information      An account failed to log on....
20/11/2026 02:14:07 AM        4625 Information      An account failed to log on....
20/11/2026 02:14:05 AM        4625 Information      An account failed to log on....
```

- `-FilterHashtable @{LogName='Security'; Id=4625}` — the filter is handed to the Event Log service, so only matching events are returned. This is far faster than fetching everything and filtering with `Where-Object`.
- `-MaxEvents 3` — newest first, stop after three.
- `ProviderName: Microsoft-Windows-Security-Auditing` — the provider that wrote these events (the LSA auditing provider).
- `Id 4625` — **4625 = "An account failed to log on"**. It is written on the machine where the logon was attempted, whenever a logon fails (bad password, unknown user, disabled account, logon type not allowed). Attackers generate it when guessing or spraying passwords (T1110), so bursts of 4625 — three in four seconds here — are a classic detection.
- `LevelDisplayName Information` — note that a *failed* logon still shows as "Information". For Security audit events, success or failure is carried in the **keywords** (Audit Success / Audit Failure), not in the level. More on this below.
- `Message` — the rendered description, truncated here. That's the "General" view you'll meet shortly.

`wevtutil` is the built-in command-line equivalent and is handy for quick XML output:

```
C:\> wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:1 /rd:true /f:xml
```

- `qe Security` — *query events* from the Security channel.
- `/q:"*[System[(EventID=4625)]]"` — an XPath filter on the System part of the event (the same filter language Event Viewer uses in "Filter Current Log → XML").
- `/c:1` — return one event. `/rd:true` — reverse direction, i.e. newest first. `/f:xml` — output the raw XML (`/f:text` gives the message view).

The XML it returns is shown in the [three views](#three-views) section below.

**[Supplement] Not every program uses the event log.** Some applications write their own logs in text or other formats in their own folders: IIS writes W3C logs under `C:\inetpub\logs\LogFiles`, the Windows DNS server can write a text debug log, many third-party products keep logs under `C:\ProgramData\<vendor>`. These never appear in Event Viewer, so a "collect all event channels" policy silently misses them.

## Deciding which security events get created { #audit-settings }

A camera that was never switched on doesn't record. In Windows logging terms, events only exist if something was configured to produce them *before* the activity. There are three sources of control.

### 1. Built-in: Windows audit policies { #audit-policies }

The main switch for operating-system security events is the **audit policy**. It is a set of fine-grained settings — "subcategories" — each of which can be set to record on **Success**, **Failure**, both or neither. Examples: Logon, Logoff, Process Creation, User Account Management, Security Group Management, File System, Registry, Kerberos Authentication Service.

```
C:\> auditpol /get /subcategory:"Logon","Process Creation","File System"
System audit policy
Category/Subcategory                      Setting
Logon/Logoff
  Logon                                   Success and Failure
Detailed Tracking
  Process Creation                        Success
Object Access
  File System                             No Auditing
```

- `auditpol /get /subcategory:…` — shows the *effective* advanced audit policy for the named subcategories (`/category:*` shows them all). Run it as administrator.
- `Logon … Success and Failure` — successful logons produce **4624**, failed ones **4625**. Turning on only Success would make password-guessing invisible.
- `Process Creation … Success` — produces **4688** ("A new process has been created") each time a program starts. Failure has little meaning here, so Success is the usual setting. Remember the separate policy "Include command line in process creation events", or 4688 won't show arguments.
- `File System … No Auditing` — no file-access events (**4663**). Note that for object access, turning the subcategory on is only half the job: you must also put an audit entry (a **SACL**, system access control list) on the specific folders or registry keys you care about. Auditing every file on the disk would bury you.

**[Supplement] Legacy vs advanced audit policy.** Windows has two layers: nine old "basic" categories (Local Policies → Audit Policy) and the newer ~60 "advanced" subcategories (Advanced Audit Policy Configuration). If both are configured through Group Policy, they can overwrite each other in confusing ways. The rule of thumb is to use only the advanced policy and enable **"Audit: Force audit policy subcategory settings … to override audit policy category settings"** (the `SCENoApplyLegacyAuditPolicy` setting). Always verify the result on a real host with `auditpol` rather than trusting what the GPO says.

**Why attackers care:** `auditpol /clear` or `auditpol /set /subcategory:"Logon" /success:disable` turns recording off without clearing anything — quieter than wiping a log. Changes to the audit policy are themselves recorded as **4719** ("System audit policy was changed"), which is worth an alert. (Audit policy design was also covered on [PAWs, Permissions and Privileges, EDR, DLP, UEBA and Audit Logging](../endpoint-defense/paw-edr-dlp-ueba.md#audit-logging).)

### 2. Add-ons: Sysmon and custom scripts { #add-ons }

The built-in audit policy has gaps: it doesn't record outbound network connections per process with full detail, image hashes, DLL loads, named pipes, or DNS queries per process. Many organisations add **Sysmon** (System Monitor), a free Microsoft Sysinternals tool that installs a driver and service and writes rich events into its own channel, `Microsoft-Windows-Sysmon/Operational`: process creation with hashes and parent command line (Sysmon 1), network connections (3), driver and image loads (6, 7), process access such as opening LSASS (10), file creation (11), registry changes (12–14), DNS queries (22) and more. Because it writes to a normal event channel, the same agent that collects Security can collect it. Its value depends almost entirely on its **configuration file** — what to include and exclude.

You can also create **your own channel**. A short PowerShell script can register a new log and write any text into it — for example, the result of a nightly check of local administrators — so the log agent ships it with everything else:

```
PS C:\> New-EventLog -LogName 'SOC-Checks' -Source 'LocalAdminAudit'
PS C:\> Write-EventLog -LogName 'SOC-Checks' -Source 'LocalAdminAudit' -EventId 100 `
>>   -EntryType Information -Message 'Local Administrators: CORP\Domain Admins, CORP\ws-admins, WS-FIN-0217\Administrator'
```

- `New-EventLog -LogName 'SOC-Checks' -Source 'LocalAdminAudit'` — registers a new classic channel called `SOC-Checks` and a source (provider) name allowed to write to it. Needs administrator rights, once per machine.
- `Write-EventLog … -EventId 100 -EntryType Information -Message '…'` — writes one event. You choose the ID scheme (here 100 = "local admin snapshot"), so document it.
- In the SIEM you can now alert when the member list changes. **[Caution]** these two cmdlets exist only in **Windows PowerShell 5.1**; they were removed from PowerShell 7. In PowerShell 7 use `eventcreate.exe`, a small .NET call, or run the script under `powershell.exe` 5.1.

### 3. Applications that log for themselves { #app-logging }

For applications that do *not* use the Windows event log, what gets recorded depends entirely on the application's own settings and abilities. For network services — web servers, DNS servers, proxies — there are two good options:

- **Configure the service's logging** so it includes every field security needs (for IIS: client IP, `X-Forwarded-For`, user agent, URI query, status, bytes; for DNS: queries and responses), and collect those files with the agent.
- **Capture the activity from the wire** with a network sensor such as **Zeek** or **Suricata**, which writes consistent `http.log`, `dns.log` and similar records no matter how the server itself is configured. Earlier network pages, such as [SMB](../other-protocols/smb.md), show what those records look like.

Often you'll want both: the server log shows what the application decided; the network log shows what actually crossed the wire.

## What every Windows event carries: the metadata { #log-breakdown }

Within a channel, each event is written with a set of metadata fields. You can see them at the bottom of Event Viewer's General tab, and they are the first things you filter on.

### Level — how serious? { #level }

The level describes the importance of the message. In the XML it's a number; Event Viewer shows a word:

| XML `Level` | Shown as | Meaning |
| --- | --- | --- |
| 0 | Information (LogAlways) | Always logged; Security audit events use this |
| 1 | Critical | Severe failure, e.g. unexpected reboot (Kernel-Power 41) |
| 2 | Error | A problem, e.g. a service failed to start |
| 3 | Warning | Possible problem worth noticing |
| 4 | Information | Normal operation |
| 5 | Verbose | Detailed tracing |

Most events are informational. When hunting for crashes or failures (a security product crashing after tampering, a service that won't start because its binary was replaced), filtering for levels 1–3 is useful. But **for Security events, level tells you nothing** — successes and failures are both level 0. What separates them is the **keywords** field: `Audit Success` (`0x8020000000000000`) or `Audit Failure` (`0x8010000000000000`). Event Viewer shows this in the "Keywords" column of the Security log.

### Source (provider) — who wrote it? { #source }

Some channels have a single writer. Others, like **Application** and **System**, have many programs writing into them. The **Source** field (in XML, `Provider Name`) is how you tell which program generated a given event. In System, for example, you'll see `Service Control Manager` (service installs and state changes), `Microsoft-Windows-Kernel-General` (time changes, boot), `Microsoft-Windows-Eventlog` (log cleared, 104) and many more side by side.

### Event ID — what kind of event? { #event-id }

The event ID is the most important field for Windows logs. Each provider defines a fixed set of event IDs so that the same kind of event always has the same number and is easy to find: in Security, every successful logon is **4624** and every failed logon is **4625**, whichever machine you're on.

**[Correction] Event IDs are unique per provider, not per channel and not globally.** A common simplification is "event IDs are unique within a channel". Strictly, the ID is defined by the *provider*, and because one channel can contain several providers, the same number can mean different things even inside one channel. A real-world example from the **System** channel:

```
PS C:\> Get-WinEvent -FilterHashtable @{LogName='System'; Id=1} -MaxEvents 4 |
>>   Format-Table TimeCreated, Id, ProviderName -AutoSize

TimeCreated            Id ProviderName
-----------            -- ------------
19/11/2026 07:58:31     1 Microsoft-Windows-Power-Troubleshooter
19/11/2026 07:58:30     1 Microsoft-Windows-Kernel-General
18/11/2026 23:10:02     1 Microsoft-Windows-Kernel-General
18/11/2026 17:42:55     1 Microsoft-Windows-Power-Troubleshooter
```

- Both rows say `Id 1` and both are in System.
- From `Microsoft-Windows-Power-Troubleshooter`, ID 1 means "the system has resumed from a low-power state" (woke from sleep).
- From `Microsoft-Windows-Kernel-General`, ID 1 means "the system time has changed". Changing the clock is an anti-forensic trick (it confuses timelines), so this one can matter.
- And in the Sysmon channel, ID 1 means "process created". A detection written as just `EventID=1` would mix all three.

So the reliable key is **provider + event ID** (and channel, to make collection filters explicit). Across channels, the well-known security IDs (4624, 4688, 7045 …) are effectively unique, which is why people get away with the shortcut — until they don't.

### Task category — a little more description { #task-category }

The task category is another metadata field. Each provider can define its own numbered categories with a text label. In Security they group events by audit subcategory: 4624 and 4625 have the task category **Logon** (in XML, `<Task>12544</Task>`), 4688 has **Process Creation** (13312), 4720 has **User Account Management** (13824). It's useful for broad filtering ("show me everything in Logon"), but the event ID is more precise.

**[Supplement]** The other System fields you'll meet — `Opcode`, `Version`, `EventRecordID`, `Execution ProcessID/ThreadID`, `Correlation`, `Computer`, `TimeCreated` — are taken apart field by field on the next page. One quick tip now: `EventRecordID` is a sequence number per channel. A jump in it (record 51203 followed by 51890 with nothing in between) on an exported log can show that events were removed.

## Same log, different views { #three-views }

Windows logs are XML underneath, but Event Viewer can show them three ways, from easiest-to-read-but-least-structured to the raw XML. Let's take one failed logon on `WS-FIN-0217`.

### View 1: General (the "message") { #general-view }

This is what you see when you click on an event. It's the most human-readable and what analysts usually read:

```
An account failed to log on.

Subject:
	Security ID:		NULL SID
	Account Name:		-
	Account Domain:		-
	Logon ID:		0x0

Logon Type:			3

Account For Which Logon Failed:
	Security ID:		NULL SID
	Account Name:		svc-sql
	Account Domain:		CORP

Failure Information:
	Failure Reason:		Unknown user name or bad password.
	Status:			0xC000006D
	Sub Status:		0xC000006A

Process Information:
	Caller Process ID:	0x0
	Caller Process Name:	-

Network Information:
	Workstation Name:	WS-MKT-0088
	Source Network Address:	10.20.7.54
	Source Port:		0

Detailed Authentication Information:
	Logon Process:		NtLmSsp 
	Authentication Package:	NTLM
	...
```

It reads like a letter: an NTLM network logon (type 3) from `WS-MKT-0088` at `10.20.7.54` for `CORP\svc-sql` failed because of a wrong password (`0xC000006A` = bad password for an existing account; `0xC0000064` would mean the user doesn't exist). The tabs and spacing are inconsistent, labels repeat ("Security ID" appears twice with different meanings), and the text is **translated into the operating system's display language** — on a Korean Windows install the same event reads "계정에 로그온하지 못했습니다." Lovely for a person, painful for a parser.

### View 2: Details → Friendly View { #friendly-view }

Click the **Details** tab and choose **Friendly View**. You now see the actual data the event was built from, as a tree with the XML tags hidden:

```
- System
    - Provider  [ Name]  Microsoft-Windows-Security-Auditing
                [ Guid]  {54849625-5478-4994-a5ba-3e3b0328c30d}
      EventID   4625
      Level     0
      Task      12544
      Keywords  0x8010000000000000
    - TimeCreated [ SystemTime] 2026-11-20T02:14:09.4371152Z
      EventRecordID 51207
      Channel   Security
      Computer  WS-FIN-0217.corp.example
- EventData
      TargetUserName      svc-sql
      TargetDomainName    CORP
      Status              0xc000006d
      SubStatus           0xc000006a
      LogonType           3
      LogonProcessName    NtLmSsp
      AuthenticationPackageName NTLM
      WorkstationName     WS-MKT-0088
      IpAddress           10.20.7.54
      IpPort              0
```

### View 3: Details → XML View { #xml-view }

And the full XML — the true form in which the event is stored:

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}" />
    <EventID>4625</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime="2026-11-20T02:14:09.4371152Z" />
    <EventRecordID>51207</EventRecordID>
    <Channel>Security</Channel>
    <Computer>WS-FIN-0217.corp.example</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-0-0</Data>
    <Data Name="TargetUserName">svc-sql</Data>
    <Data Name="TargetDomainName">CORP</Data>
    <Data Name="Status">0xc000006d</Data>
    <Data Name="FailureReason">%%2313</Data>
    <Data Name="SubStatus">0xc000006a</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="LogonProcessName">NtLmSsp </Data>
    <Data Name="AuthenticationPackageName">NTLM</Data>
    <Data Name="WorkstationName">WS-MKT-0088</Data>
    <Data Name="IpAddress">10.20.7.54</Data>
    <Data Name="IpPort">0</Data>
  </EventData>
</Event>
```

Reading the parts that matter now (the full field-by-field walk-through of System and EventData is on the next page):

- `<Provider Name="Microsoft-Windows-Security-Auditing" …/>` and `<EventID>4625</EventID>` — the provider + ID pair that identifies the event type.
- `<Level>0</Level>` with `<Keywords>0x8010000000000000</Keywords>` — level 0 as for all audit events; the keyword value is **Audit Failure**.
- `<Task>12544</Task>` — task category Logon.
- `<TimeCreated SystemTime="…Z" />` — always stored in **UTC** (the `Z`). Event Viewer's General tab converts to the viewer's local time, which is a classic source of timeline mistakes. In the SIEM, keep UTC.
- `<Computer>WS-FIN-0217.corp.example</Computer>` — the machine that *recorded* the event: the target of the logon attempt, not the source.
- `TargetUserName` / `TargetDomainName` — the account someone tried to use.
- `FailureReason %%2313` — not text but a **message-string placeholder**. `%%2313` is looked up in a message table and rendered as "Unknown user name or bad password." in the General view. That's why some XML values look cryptic.
- `LogonType 3`, `IpAddress 10.20.7.54`, `WorkstationName WS-MKT-0088` — where the attempt came from. A burst of these across many usernames from one IP is password spraying (T1110.003).

### How the message is built — and why it matters for the SIEM { #message-template }

The General view is not stored in the file. Each provider ships a **message template** for each event ID, with numbered slots, roughly:

```
An account failed to log on.
...
Account For Which Logon Failed:
	Account Name:		%6
	Account Domain:		%7
...
Network Information:
	Workstation Name:	%14
	Source Network Address:	%20
```

When you open the event, Windows takes the EventData values in order and fills them into the slots (`%6` ← `TargetUserName`, `%7` ← `TargetDomainName` …), resolves `%%` placeholders, and shows the result. Windows and most log agents call this rendered text the **`Message`** field. A good analogy is a mail-merge letter: the XML is the spreadsheet row, the template is the letter, and the General view is the printed letter.

Three practical consequences:

1. **Rendering needs the provider's template on the reading machine.** If you open an exported `.evtx` on a machine that doesn't have that provider installed (say a Sysmon or vendor log on your analysis laptop), Event Viewer shows "The description for Event ID … from source … cannot be found". The data isn't lost — it's still in the XML/Details view.
2. **The template decides what is shown.** The log's author chooses which fields appear in the message. Some EventData values never appear in the General view at all, so reading only the message can make you miss fields.
3. **For the SIEM, send the structured fields.** When logs are collected and shipped, the agent may send the XML data, the rendered message, or both, and that choice decides how the data is parsed on the other side:
    - The **XML / EventData fields** are well formatted, named, language-independent and easy for a SIEM to extract reliably (`TargetUserName`, `IpAddress`, `LogonType` …). These should always be sent.
    - The **message** is easier for a person to read and helpful for events whose XML uses generic field names (some providers only give `param1`, `param2` …). But it is free text with inconsistent tabs and spaces, localised, and makes every event several times larger. Many teams drop it at ingestion or keep it only for selected events.

**[Supplement]** A real failure seen in multinational environments: a SIEM parser extracts the user name with a regular expression on `Account Name:` in the message. It works on English hosts and silently returns nothing for hosts installed in Korean, Japanese or German. Parsing EventData fields avoids this completely.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The architecture is unchanged: providers write events, the Windows Event Log service sorts them into channels, channels live as binary-XML `.evtx` files in `C:\Windows\System32\winevt\Logs`, and Event Viewer, `Get-WinEvent` and `wevtutil` read them. Audit policies still decide which Security events exist; the General/Friendly/XML views, the message-template mechanism and "provider + event ID" identity are the same. Event IDs 4624, 4625, 4688, 4719 and 1102 have not changed, and the advice to collect structured fields rather than message text is, if anything, stronger now that SIEMs normalise into common schemas.

!!! info "[Changed] What has changed"
    - **Sysmon is now part of Windows.** Since the February 2026 optional update for Windows 11 (KB5077241), Sysmon functionality ships as a built-in optional feature. It is **off by default**: you enable the feature and still supply a configuration, and the events still need to be collected. Server support and exact behaviour are rolling out over time — check the current Microsoft documentation for your build rather than assuming.
    - **Agents changed.** Microsoft's legacy Log Analytics agent (MMA) was retired in 2024; Azure Monitor Agent with data collection rules replaced it for Microsoft Sentinel. Elastic, Splunk and others have also moved to unified agents. Windows Event Forwarding (WEF/WEC) is still built in and still widely used as a free collection layer.
    - **More of the important signal is no longer in local channels.** Cloud sign-ins (Entra ID), Microsoft 365 audit data and EDR telemetry are collected through APIs, not `.evtx` files. Endpoint event logs remain essential, but they are one source among several.
    - **Offline triage tools matured.** Parsers such as EvtxECmd and rule-based scanners such as Hayabusa and Chainsaw (running Sigma rules directly over `.evtx`) are now standard in DFIR kits and are useful when a host was never collected into the SIEM.
    - Microsoft's documentation moved from docs.microsoft.com to **learn.microsoft.com**; the event-schema pages referenced by older material are still there under the new address.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't assume default log sizes are enough.** With roughly 20 MB per channel a busy server can overwrite Security in hours. Raise sizes (baselines commonly call for hundreds of MB for Security) *and* forward events off the host quickly.
    - **Don't write detections as bare `EventID = N`.** Always pin the provider (or channel) too, or you'll mix unrelated events with the same number.
    - **Don't parse the Message field with regex** in a multi-language or multi-version estate. Use EventData fields.
    - **Don't read zero results as "didn't happen"** until you've checked the audit policy, the channel's collection and its retention for that time.
    - **Don't rely on `New-EventLog`/`Write-EventLog` in PowerShell 7** — they don't exist there.
    - **Don't trust a GPO screen for audit settings**; verify the effective policy with `auditpol` on real hosts, and alert on **4719** and **1102**/**104**.

## Practice questions { #quiz }

### Question 1

A colleague builds a SIEM dashboard "process creations per host" by counting events with `EventID = 1`. Laptops that don't have Sysmon installed still show a few "process creations" every morning, all with an empty process name. What is going on, and how should the query be written?

??? success "Answer and explanation"
    **What's going on:** event IDs are only unique **per provider**. On laptops without Sysmon, events with ID 1 still exist — for example in the System channel from `Microsoft-Windows-Power-Troubleshooter` (resume from sleep, every morning) or `Microsoft-Windows-Kernel-General` (time changed). The query matches the number, not the event type, and those events have no process-name field — hence the empty values.

    **Fix:** pin the source as well as the ID — channel `Microsoft-Windows-Sysmon/Operational` *and* provider `Microsoft-Windows-Sysmon` *and* `EventID = 1` — then count. If you also want coverage where Sysmon is absent, add a second branch on Security **4688** from `Microsoft-Windows-Security-Auditing` (with command-line logging enabled).

### Question 2

Your SIEM extracts the user name from failed logons by matching `Account Name:` in the message text. After an acquisition, the new subsidiary's servers (installed in Korean) show 4625 events with an empty user field. Separately, when you open an exported Sysmon `.evtx` on your analysis laptop, Event Viewer says "The description for Event ID 1 from source Microsoft-Windows-Sysmon cannot be found". Explain both problems with one idea, and give the fix.

??? success "Answer and explanation"
    **One idea:** the readable message is **not stored in the event**. It is built when displayed (or when the agent renders it) by filling the EventData values into the provider's **message template** — and that template is localised and has to be present on the machine doing the rendering.

    - On Korean-language servers the template is Korean, so the text no longer contains `Account Name:` and the regex finds nothing.
    - On the analysis laptop the Sysmon provider (and its templates) isn't installed, so Event Viewer can't build the message. The data is still there in **Details → XML**.

    **Fix:** parse the structured **EventData** fields (`TargetUserName`, `IpAddress`, `LogonType` …), which have the same names in every language, and make sure the agent ships them. Keep the message only as a human convenience (or drop it to save volume). For offline work, use a parser that reads the XML fields (or install the provider) instead of relying on Event Viewer's rendering.

### Question 3

During an incident you search the SIEM for 4625 events on file server `FS-02` during a suspected password-spraying window two weeks ago and get **zero results**. Your manager wants to write "no failed logons observed". What would you check before agreeing, and in what order?

??? success "Answer and explanation"
    Zero results can mean "didn't happen", "never recorded" or "recorded but not collected". Check, roughly in this order:

    1. **Was it recorded?** Run `auditpol /get /subcategory:"Logon"` on `FS-02` (and check the GPO history). If Failure wasn't enabled at the time, no 4625 could exist. Look for **4719** audit-policy changes around the window — an attacker might have turned it off.
    2. **Is the local evidence still there?** `Get-WinEvent -ListLog Security` → `MaximumSizeInBytes`, `LogMode`, and the oldest event's time. With a small circular log, two-week-old events are probably overwritten. Look for **1102** (Security log cleared) or **104** (another log cleared).
    3. **Was it collected?** Is the Security channel in the agent's configuration for `FS-02`? Was the agent healthy and sending during that window (heartbeat or gap in any event types from that host)? Did a filter or parser drop 4625 or the fields you searched on?
    4. **Did you search correctly?** Right host name format (short name vs FQDN in `Computer`), right time zone (events are UTC), right index/provider.
    5. **Is FS-02 the right place to look?** 4625 is written on the machine where the logon was attempted. Domain-account failures may also show on domain controllers as Kerberos (4771) or NTLM credential validation (4776) failures.

    Only after these checks can you write "no failed logons observed"; otherwise write "no data available for that period", and record the logging gap as a finding.

## Related { #related }

- [Windows Logging](index.md) — this section's overview
- [PAWs, Permissions and Privileges, EDR, DLP, UEBA and Audit Logging](../endpoint-defense/paw-edr-dlp-ueba.md) — audit policy and central collection from the defence side
- [Windows Event Logs (EVTX)](../../../windows/event-logs.md) · [Windows Event IDs](../../../basics/windows-event-ids.md) · [Impair Defenses & Log Clearing](../../../adversary/impair-defenses-log-clearing.md)
