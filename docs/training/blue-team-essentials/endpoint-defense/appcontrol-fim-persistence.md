---
title: "Application Control, File Integrity Monitoring and Catching Persistence — Only Known Programs Run, Every Change Gets Noticed"
tags:
  - training
  - blue-team
  - endpoint
  - hardening
  - application-control
  - fim
  - persistence
---

# Application Control, File Integrity Monitoring and Catching Persistence — Only Known Programs Run, Every Change Gets Noticed { #appcontrol-fim-persistence }

!!! abstract "What this page covers"
    Three controls aimed at the *installation* stage, when the attacker tries to get their own code running and to make it survive a reboot. First, application control (allowlisting): why "only run what is on the list" catches unknown malware that antivirus misses, the rule types (name, path, publisher/signature, hash) and how strong each one is, audit vs enforce mode, the built-in options on Windows (AppLocker, App Control for Business), macOS (Gatekeeper) and Linux (AppArmor/SELinux, fapolicyd), and how to read their block and audit events. Second, the ways attackers get around it — scripts, living-off-the-land binaries, code injection, writable allowed paths, renamed files, stolen signing keys and hash collisions — and what each bypass leaves behind for the SOC. Third, file integrity monitoring (FIM): what it checks, how a web shell drop is caught, and how AIDE and an agent alert look line by line. Finally, catching persistence: the common auto-start extensibility points (ASEPs), how privilege level decides which ones the attacker can use, and how to hunt them with Autoruns. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs, file names and hashes are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. **Application control** (allowlisting) flips the antivirus question around. Antivirus asks "is this on the *bad* list?"; application control asks "is this on the *good* list?". Anything not approved is blocked or reported — including malware nobody has ever seen before.
2. It works on **execution**, not on files arriving. Malware can still be downloaded and written to disk; it just can't *run*. Good products also cover scripts, installers (MSI) and DLLs — if they don't, that gap is the attacker's way in.
3. **Audit mode** reports what *would* have been blocked without blocking it. You need it to learn your environment before enforcing — and even if you never enforce, the audit events are an excellent "unknown software ran here" sensor.
4. Rule types differ hugely in strength: **filename** (weakest — just rename the file), **path** (only as strong as the folder's permissions), **publisher/signature** (strong unless a signing key is stolen) and **hash** (strongest, but breaks on every update).
5. The main bypasses are **scripts** (T1059), **trusted system binaries used as launchers** — living off the land (T1218), **injecting code into an already-allowed process** (T1055), **overwriting a file in an allowed but writable path** (T1574), **renaming** (T1036.005) and **signed malware** (T1553.002). Each leaves different evidence.
6. **File integrity monitoring (FIM)** records a baseline (hash, size, owner, permissions, which files exist) for chosen files and folders and alerts on any change. It is excellent where change is rare and meaningful: system binaries, web roots (web shells, T1505.003), startup locations and the `hosts` file.
7. **Persistence** depends on privilege. A normal user can only touch *their own* run keys, startup folder and scheduled tasks; an administrator or root can add services, system-wide tasks, drivers and rootkits. The common ASEPs are run keys/startup folder (T1547.001), services (T1543.003), scheduled tasks (T1053.005), browser extensions (T1176.001) and simply stolen valid accounts (T1078).
8. **Autoruns** (Sysinternals) lists hundreds of ASEPs with signature and optional reputation checks — the quickest way to spot-check one machine. For the whole fleet, turn the same idea into continuous logging (Sysmon/EDR registry and file events, service and task creation events) and alert on *new* entries.

## Application control — only known programs may run { #application-control }

### Why it is worth so much { #why-app-control }

Think about how antivirus works: it has a list of known criminals and checks every visitor's face against it. A criminal nobody has photographed yet walks straight in. **Application control** works like the guest list at a private event: the bouncer doesn't care whether you are a known criminal — if your name isn't on the list, you don't get in. That one change in question is why it is so effective. A brand-new piece of malware compiled an hour ago for your organisation only has to meet one condition to be caught: *it is not on the approved list*.

Technically, application control hooks into the point where the operating system is about to create a process or load code. Before the code runs, the OS (or an agent's driver) compares the file against policy rules. If a rule allows it, it runs; if not, it is blocked (enforce mode) or allowed but logged (audit mode).

Two consequences follow straight away:

- It does **not** stop the file from arriving. A phishing attachment can still be saved, a dropper can still write `update.exe` into `%TEMP%`. Application control only decides whether it may *execute*. That's why it pairs well with FIM and EDR, which notice the write.
- It covers whatever it is told to cover. Many incidents involve an executable at some point, so covering `.exe` already removes a lot. But good policies also cover **scripts** (PowerShell, VBScript, JScript), **installer packages** (`.msi`) and ideally **DLLs** and **drivers**. Every type left uncovered is a door.

Security frameworks consistently rank this near the top: in CIS Controls v8.1, Safeguards 2.5 (allowlist authorised software), 2.6 (allowlist authorised libraries) and 2.7 (allowlist authorised scripts) are all about this. The Australian Essential Eight puts application control first in its list of mitigations.

### The four rule types — and how strong each is { #rule-types }

How a rule identifies "this program" decides how easy it is to fool. An analogy: checking guests by **name only** (anyone can say "I'm Kim"), by **which door they came through** (fine, unless someone props the side door open), by **an ID card issued by a trusted authority** (strong, unless the ID office itself is robbed) or by **fingerprint** (nearly impossible to fake, but you must re-enrol someone every time they change).

| Rule type | Matches on | Strength | Practical problem |
| --- | --- | --- | --- |
| Filename | `chrome.exe` | Very weak — rename the malware | Should almost never be used |
| Path | `C:\Program Files\*` | As strong as the folder's write permissions | Breaks if users can write there |
| Publisher / signature | Code-signing certificate (publisher, product, version) | Strong | Trusts *everything* that publisher signed, including its vulnerable or abusable tools |
| Hash | SHA-256 of the file | Strongest | Every update changes the hash, so rules need constant maintenance |

Real policies combine them: publisher rules for well-known signed software (Microsoft, your browser vendor, your line-of-business vendors), path rules only for folders that standard users can't write to (`C:\Windows`, `C:\Program Files`), and hash rules for the few unsigned internal tools.

The classic trap with path rules: someone allows `C:\Tools\*` because the finance team's report tool lives there, but `C:\Tools` was created by an installer that gave `Users` modify rights. Now every user — and every attacker who phishes a user — can drop anything into an allowed folder.

```
C:\> icacls C:\Tools
C:\Tools BUILTIN\Administrators:(OI)(CI)(F)
         NT AUTHORITY\SYSTEM:(OI)(CI)(F)
         BUILTIN\Users:(OI)(CI)(M)

Successfully processed 1 files; Failed processing 0 files
```

- `icacls C:\Tools` — shows the access control list (ACL) of the folder.
- `BUILTIN\Administrators:(OI)(CI)(F)` — administrators have full control (`F`), inherited by files (`OI`, object inherit) and subfolders (`CI`, container inherit). Expected.
- `NT AUTHORITY\SYSTEM:(OI)(CI)(F)` — the same for SYSTEM. Expected.
- `BUILTIN\Users:(OI)(CI)(M)` — **all users have Modify** (`M`: read, write, delete). This is the finding. A path rule that allows `C:\Tools\*` is effectively "allow anything any user writes here".

Fix it by removing `Users` write rights or replacing the path rule with publisher/hash rules.

### Audit first, then enforce { #audit-vs-enforce }

Turning on enforcement on day one in a real organisation breaks things: the payroll tool nobody told IT about, the engineering team's scripts, a printer driver helper. So application control is normally rolled out in stages:

1. **Inventory and audit.** Build an initial policy (often from a "golden" reference machine plus the software inventory from [the inventory page](inventory-vulns-patching.md#inventory-systems)), deploy it in **audit mode**, and collect the "would have been blocked" events for weeks.
2. **Tune.** Each audit event is either legitimate software that needs a rule, or something that should not be there at all — which is already a SOC lead.
3. **Enforce** in waves — high-risk, low-variety groups first (kiosks, servers with fixed roles, admin workstations), general desktops later.

**[Supplement] Audit mode is a detection tool in its own right.** Even an organisation that never gets to enforcement can feed audit events into the SIEM. In a stable environment, "an executable not seen in the policy ran from `C:\Users\<user>\AppData\Local\Temp\`" is a strong, low-volume alert. The cost is the same work as building the policy — the difference is only whether the final switch is flipped.

### Built-in options per operating system { #built-in-options }

**Windows** has two built-in engines:

- **AppLocker** — the older one (since Windows 7 / Server 2008 R2). Rules for executables, Windows Installer files, scripts, DLLs and packaged (Store) apps, by path, publisher or hash, and rules can apply to specific users or groups. It is enforced by the **Application Identity** service (`AppIDSvc`) — which must be running.
- **App Control for Business** — the newer engine, formerly called **Windows Defender Application Control (WDAC)**. It is enforced by the kernel's code integrity component, covers drivers and user-mode code, can use reputation (the Intelligent Security Graph) and managed installers, and policies are device-wide. It is the engine Microsoft recommends for new deployments; AppLocker is still supported but is not where new capability is going.

**macOS** has **Gatekeeper**, which checks that apps downloaded from the internet are signed by an identified developer and **notarised** by Apple before they run the first time, and asks the user before opening anything else. It is a reputation/signature gate rather than an organisation-defined allowlist; strict allowlisting on macOS usually means an MDM policy plus a third-party tool.

**Linux** has no single "allowlist" switch in the base system, but has related building blocks:

- **AppArmor** (Ubuntu, SUSE) and **SELinux** (Red Hat family) are *mandatory access control* systems. Instead of "may this program run?", they say "this program may only read, write and execute these resources". A confined web server that gets exploited still can't run `/bin/bash` or write outside its directories if the profile forbids it. Different mechanism, many of the same benefits.
- **fapolicyd** (Red Hat family) is closer to true application allowlisting: it decides which files may be executed based on a trust database (by default, files installed from the system's packages).
- Otherwise, strict allowlisting on Linux usually means a third-party agent.

### What the events look like { #app-control-events }

**AppLocker** writes to `Applications and Services Logs → Microsoft → Windows → AppLocker`, with one channel per rule collection. The IDs you'll see most:

| Channel | Allowed | Audit ("would have been blocked") | Blocked |
| --- | --- | --- | --- |
| EXE and DLL | 8002 | 8003 | 8004 |
| MSI and Script | 8005 | 8006 | 8007 |

A blocked executable, as the event's XML `UserData` section (shortened, invented values):

```xml
<Event>
  <System>
    <Provider Name="Microsoft-Windows-AppLocker" />
    <EventID>8004</EventID>
    <TimeCreated SystemTime="2026-11-18T23:41:07.5512Z" />
    <Channel>Microsoft-Windows-AppLocker/EXE and DLL</Channel>
    <Computer>WS-FIN-0412.corp.example</Computer>
    <Security UserID="S-1-5-21-1111111111-2222222222-3333333333-4120" />
  </System>
  <UserData>
    <RuleAndFileData>
      <PolicyNameBuffer>EXE</PolicyNameBuffer>
      <RuleId>{00000000-0000-0000-0000-000000000000}</RuleId>
      <RuleNameBuffer>-</RuleNameBuffer>
      <RuleSddlBuffer>-</RuleSddlBuffer>
      <TargetUser>S-1-5-21-1111111111-2222222222-3333333333-4120</TargetUser>
      <TargetProcessId>9184</TargetProcessId>
      <FilePath>%OSDRIVE%\USERS\J.PARK\APPDATA\LOCAL\TEMP\INVOICE_VIEWER.EXE</FilePath>
      <FileHash>3F1C...9A0E</FileHash>
      <Fqbn>-</Fqbn>
    </RuleAndFileData>
  </UserData>
</Event>
```

- `EventID 8004` in the `EXE and DLL` channel — an executable was **blocked** (8003 would mean audit mode: allowed, but logged as "would have been blocked").
- `Computer` / `Security UserID` / `TargetUser` — which machine and which user's session tried to run it (resolve the SID to a username in your SIEM).
- `PolicyNameBuffer EXE` — the rule collection that applied.
- `RuleId {00000000-…}` and `RuleNameBuffer -` — **no rule matched**. That's what an implicit block looks like: the file simply wasn't on the list. (On an *allowed* 8002 event you would see the matching rule's GUID and name.)
- `FilePath …\APPDATA\LOCAL\TEMP\INVOICE_VIEWER.EXE` — an "invoice viewer" executable in the user's temp folder, typical of something extracted from an email attachment or archive.
- `FileHash` — SHA-256 of the file: your pivot for searching other hosts and reputation sources.
- `Fqbn -` — fully qualified binary name, which holds the publisher, product and version from the signature. A dash means **unsigned**.

Read together: an unsigned executable from the temp folder, blocked because nothing allowed it, at 23:41 for a finance user. The control did its job — but the SOC still wants to know how it got there (the email, the download, the parent process) and whether the same hash appeared on hosts without enforcement.

**App Control for Business** writes to `Microsoft-Windows-CodeIntegrity/Operational`: **3076** = audit (would have been blocked), **3077** = blocked in enforce mode, with fields such as the file name, the process that tried to load it, the policy name and the file's signature information. Script enforcement events appear in `Microsoft-Windows-AppLocker/MSI and Script` (8028 audit, 8029 blocked) because App Control reuses that channel for scripts.

**AppArmor** denials appear in the kernel/audit log (`/var/log/audit/audit.log`, `/var/log/kern.log` or `journalctl -k`):

```
type=AVC msg=audit(1763509267.441:2218): apparmor="DENIED" operation="exec" profile="/usr/sbin/nginx" name="/usr/bin/bash" pid=40211 comm="nginx" requested_mask="x" denied_mask="x" fsuid=33 ouid=0
```

- `type=AVC` — an access-vector-cache message, the format used for MAC decisions.
- `msg=audit(1763509267.441:2218)` — Unix timestamp with milliseconds, and the audit serial number (correlates related records).
- `apparmor="DENIED"` — the profile blocked the action (`"ALLOWED"` appears in *complain* mode — AppArmor's audit mode).
- `operation="exec"` — the action was executing a program.
- `profile="/usr/sbin/nginx"` — the confined program whose rules applied: the web server.
- `name="/usr/bin/bash"` — what it tried to execute: a shell.
- `pid=40211 comm="nginx"` — the process ID and command name doing it.
- `requested_mask="x" denied_mask="x"` — execute permission was requested and denied.
- `fsuid=33` — the process ran as UID 33 (`www-data` on Debian/Ubuntu). `ouid=0` — the target file is owned by root.

A web server trying to run `bash` is one of the clearest signs of web exploitation or a web shell — this one line is worth an alert on its own.

## How attackers get around application control { #app-control-bypass }

Application control is not perfect, and the SOC should know the gaps so it knows where to look. Each bypass below has a defence and leaves evidence.

### Scripts and installers { #bypass-scripts }

If the policy only covers `.exe` files, the attacker writes the payload as a script instead — PowerShell, VBScript, JScript, an HTA, a batch file — and lets an *allowed* interpreter run it (**T1059 Command and Scripting Interpreter**). The interpreter (`powershell.exe`, `wscript.exe`, `mshta.exe`) is a signed Microsoft binary, so it passes.

Defence and evidence: include script and MSI rules. On Windows, when AppLocker or App Control script enforcement is on, PowerShell drops to **Constrained Language Mode** for untrusted scripts, which blocks most of the dangerous .NET and COM calls. You can check the mode in a session:

```powershell
PS C:\> $ExecutionContext.SessionState.LanguageMode
ConstrainedLanguage
```

- `$ExecutionContext.SessionState.LanguageMode` — prints the language mode of the current PowerShell session.
- `ConstrainedLanguage` — restrictions are active. `FullLanguage` on a machine that is supposed to be enforced means a gap (or that PowerShell 2.0, which ignores these restrictions, is still installed and being used — check for `powershell.exe -Version 2`).

PowerShell script-block logging (event 4104) records the script content even when it was obfuscated or fetched from the network; that event gets its own page later.

### Living off the land — trusted binaries as launchers { #bypass-lolbins }

Windows ships with many signed programs that can load or run *other* code: `rundll32.exe` runs an exported function from any DLL, `regsvr32.exe` registers COM components (and can fetch a scriptlet from a URL), `mshta.exe` runs HTML applications, `msbuild.exe` compiles and runs inline project code, `installutil.exe` runs code in .NET assemblies. MITRE groups these as **T1218 System Binary Proxy Execution** (for example **T1218.011 Rundll32**, **T1218.010 Regsvr32**, **T1218.005 Mshta**), and the community list LOLBAS documents them. If DLLs are not covered by the policy, an attacker writes `evil.dll` and runs:

```
rundll32.exe C:\Users\j.park\AppData\Roaming\cache.dll,Start
```

- `rundll32.exe` — allowed, signed by Microsoft, lives in `C:\Windows\System32`.
- `C:\Users\j.park\AppData\Roaming\cache.dll` — the attacker's DLL, in a user-writable folder.
- `,Start` — the exported function to call. The code inside it now runs inside a trusted process.

Defence and evidence: cover DLLs if you can (it is heavy on performance and maintenance, so many start with executables and scripts), and use Microsoft's recommended block rules that deny the binaries ordinary users never need (`mshta.exe`, `msbuild.exe`, `installutil.exe` and similar on non-developer machines). For detection, the process-creation log is your friend: `rundll32.exe` loading a DLL from `AppData` or `Temp`, `regsvr32.exe` with `/i:http…`, or `mshta.exe` started by Outlook or Word are all classic alerts. See [LOLBins](../../../adversary/lolbins.md).

### Code injection into an approved process { #bypass-injection }

Application control checks code at the moment it is loaded as a file. If the attacker already has *some* code running — for example a macro or a script — they can use Windows APIs to write their payload into the memory of an already-running, already-approved process and start a thread there (**T1055 Process Injection**). Nothing new is "launched", so no allow/deny decision happens.

Defence and evidence: this is where EDR, ASR rules and memory scanning come in, not application control. EDRs record cross-process memory writes and remote thread creation; Sysmon event 8 (`CreateRemoteThread`) and event 10 (`ProcessAccess`) are the free-tool equivalents. A browser or Office process creating a thread in `explorer.exe` is not normal. See [Process Injection](../../../adversary/process-injection.md).

### Abusing weak rules: names, paths and permissions { #bypass-weak-rules }

- **Filename rules** — the attacker learns what is allowed (for example by reading the policy, which users can often do, or by guessing common names) and renames the malware `chrome.exe` (**T1036.005 Masquerading: Match Legitimate Name or Location**). Defence: don't use filename rules.
- **Path rules on writable folders** — as shown with `icacls` above, the attacker writes into an allowed folder. A variant: an allowed program in a writable folder is *replaced* by the malware, or a DLL is planted next to it so it gets loaded (**T1574 Hijack Execution Flow**). Defence: path rules only for admin-only folders; check ACLs regularly; FIM on allowed folders catches the overwrite.

### Signatures and hashes { #bypass-signatures-hashes }

- **Publisher rules** are hard to beat directly: the attacker needs malware signed by a publisher you trust. That has happened — attackers have stolen code-signing keys from software companies and signed their tools or drivers with them (**T1553.002 Subvert Trust Controls: Code Signing**); well-known state operations used stolen driver-signing certificates. It's rare and expensive, but don't rule it out for high-value targets. A more common variant is abusing *legitimately signed* but vulnerable or dual-use software from a trusted publisher — which is why trusting "everything signed by vendor X" is broader than it sounds.
- **Hash rules** are practically unbeatable as long as the algorithm is strong. To fool one, an attacker would need a different file with the same hash — a **collision**. For SHA-1 that was shown to be possible in 2017, when researchers produced two different PDF files with the same SHA-1 using roughly 6,500 CPU-years plus about 110 GPU-years of computation. Chosen-prefix SHA-1 collisions have since become cheaper still. SHA-256 has no known practical collisions. AppLocker and App Control use SHA-256 for their hash rules, so this is a theoretical concern — but it's the reason never to build an allowlist on MD5 or SHA-1.

### So is it worth it? Yes { #worth-it }

None of this means application control is weak. It removes the huge volume of opportunistic attacks — the downloaded "invoice viewer", the cracked software, the commodity loader — so the team can spend its time on the attacks that are left. And it forces the remaining attackers onto a smaller set of tricks (LOLBins, injection, scripts), each of which you can watch for specifically. Raising the bar *and* narrowing where to look is exactly what a SOC wants.

## File integrity monitoring — noticing every change { #fim }

### What it is { #fim-what }

Almost every intrusion changes a file somewhere: a dropped tool, a replaced binary, a new startup script, an edited `hosts` file, a web shell in the website folder. **File integrity monitoring (FIM)** takes a snapshot of what chosen files and folders look like and then checks, on a schedule or in real time, whether anything differs.

An analogy: before leaving a holiday house empty for the winter, you photograph every room. When you come back, you compare the photos with the rooms — anything moved, added or missing stands out immediately, even if you can't say yet who did it.

For each monitored item FIM typically records:

- **Hash** of the content (SHA-256) — catches any change to what's inside.
- **Size** and **modification time** — cheap, quick hints (but timestamps can be faked, so hashes matter).
- **Owner and group** — catches ownership changes.
- **Permissions** — catches, for example, a script made world-writable or a binary given the SUID bit.
- **Which files exist** — catches **new** files appearing and files disappearing.

FIM is usually a feature of a **host-based intrusion detection/prevention system (HIDS/HIPS)** or an EDR/security agent (for example Wazuh/OSSEC "syscheck", Tripwire, AIDE on Linux, and the FIM modules of commercial agents). On Windows the native building block is **object access auditing**: put an audit rule (SACL) on a folder and Windows writes event **4663** ("an attempt was made to access an object") when someone writes to it — that event gets its own page later.

### Where to point it { #fim-where }

FIM is only useful where change is rare and meaningful. Point it at the whole disk and you get alerts for every log file and browser cache. Good targets:

- **System binaries and libraries** — `C:\Windows\System32`, `/bin`, `/sbin`, `/usr/bin`, `/lib`. Only patching should change these, so changes outside patch windows are suspicious.
- **Web roots** — `/var/www/html`, `C:\inetpub\wwwroot`. Site content changes on deployments; a new `.php`/`.aspx`/`.jsp` file at any other time is a web shell until proven otherwise.
- **Startup and persistence locations** — startup folders, `/etc/systemd/system`, `/etc/cron*`, `~/.bashrc`, `/etc/rc.local`, the task and service folders.
- **Security-relevant configuration** — `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `C:\Windows\System32\drivers\etc\hosts`.
- **Folders your application control path rules allow** — so an overwrite of an allowed program is caught.

### Example: catching a web shell { #fim-webshell }

A company website runs on `web01.corp.example` from `/var/www/html`. An attacker exploits a vulnerable plugin in the content management system and uploads a small PHP file — a **web shell** (**T1505.003 Server Software Component: Web Shell**). From then on they visit `https://www.shop.example/wp-content/uploads/2026/11/thumb.php?c=...` and the PHP code runs their commands on the server, like a remote command prompt over HTTP.

The website's files only change during planned releases. So "any new file in `/var/www/html` outside a release" is a perfect FIM rule. Here is how **AIDE** (Advanced Intrusion Detection Environment) reports it:

```
$ sudo aide --check
Start timestamp: 2026-11-19 02:00:01 +0000 (AIDE 0.18.6)
AIDE found differences between database and filesystem!!

Summary:
  Total number of entries:      48211
  Added entries:                1
  Removed entries:              0
  Changed entries:              1

---------------------------------------------------
Added entries:
---------------------------------------------------

f++++++++++++++++: /var/www/html/wp-content/uploads/2026/11/thumb.php

---------------------------------------------------
Changed entries:
---------------------------------------------------

f   ...    .C... : /var/www/html/.htaccess

---------------------------------------------------
Detailed information about changes:
---------------------------------------------------

File: /var/www/html/.htaccess
  SHA256    : 9b0e3c...41aa                   | 77d1f2...c0e8
```

- `sudo aide --check` — compares the current filesystem with the baseline database that was made earlier with `aide --init` (and copied into place as the reference). It is usually run from cron or a systemd timer, here at 02:00.
- `AIDE found differences…` — something differs from the baseline.
- `Total number of entries: 48211` — how many files and folders are monitored.
- `Added entries: 1`, `Changed entries: 1` — one new file, one modified file.
- `f++++++++++++++++: …/thumb.php` — `f` = regular file; all `+` means **every attribute is new**: the file didn't exist in the baseline. A PHP file inside an *uploads* folder (which should only hold images) is the web shell.
- `f   ...    .C... : /var/www/html/.htaccess` — the attribute string shows which properties changed; `C` means the **checksum (content) changed**, while the dots mean size, permissions and owner stayed the same. Attackers often edit `.htaccess` to make the server run PHP in a folder where it otherwise wouldn't, or to redirect visitors.
- `SHA256 : old | new` — the old and new content hashes.

Notice the limitation: AIDE ran at 02:00, so if the web shell was uploaded at 14:00 the day before, the attacker had twelve hours before anyone knew. Agent-based FIM with **real-time** monitoring (inotify on Linux, a filesystem driver on Windows) closes that gap. A Wazuh-style alert for the same event, as it arrives in the SIEM (shortened):

```json
{
  "timestamp": "2026-11-18T14:03:27.118+0000",
  "agent": { "name": "web01", "ip": "10.20.1.15" },
  "rule": { "id": "554", "level": 5, "description": "File added to the system." },
  "syscheck": {
    "path": "/var/www/html/wp-content/uploads/2026/11/thumb.php",
    "event": "added",
    "mode": "realtime",
    "size_after": "1184",
    "uname_after": "www-data",
    "perm_after": "rw-r--r--",
    "sha256_after": "c41b...7e02"
  }
}
```

- `timestamp` — when the change was seen: 14:03, within seconds of the upload.
- `agent.name` / `agent.ip` — which server.
- `rule.description "File added to the system."` — a new-file rule fired. (Rule IDs and levels depend on the product and version; tune severity up for web roots.)
- `syscheck.path` — the new file.
- `event "added"` and `mode "realtime"` — new file, detected by real-time monitoring rather than a scheduled scan.
- `size_after 1184` — about 1 KB: web shells are often tiny.
- `uname_after "www-data"` — **owned by the web server's user**. Legitimate site files are usually deployed by a deployment account; a file *created by the web server process itself* means the web application wrote it — exactly what an upload exploit does.
- `perm_after`, `sha256_after` — permissions and the hash to search for elsewhere.

Next steps for the SOC: look in the web server's access log for the request that uploaded the file (a `POST` to the plugin's upload endpoint around 14:03) and for every request to `thumb.php` afterwards (who used it, from which IPs, what parameters); check whether the web server process started shells (`www-data` running `sh`, `bash`, `id`, `whoami` — an AppArmor denial like the one above is the same story); and preserve the file before removing it.

### Making FIM livable { #fim-tuning }

- **Baseline after every approved change.** Patch day changes hundreds of system files. Either suppress FIM alerts in the patch window and re-baseline after, or correlate changes with the patch/deployment system so only unexplained changes alert.
- **Real-time where it matters, scheduled elsewhere.** Real-time for web roots and persistence locations; nightly scans for large system folders.
- **Include "who"**. Plain FIM tells you *what* changed. Combining it with audit data (Linux `auditd` rules on the same paths, Windows 4663, or an EDR that records the writing process) tells you *which process and user* changed it — usually the more useful answer.

## Catching persistence { #catching-persistence }

### How many ways are there? { #how-many-asep }

Persistence is how an attacker makes sure their access survives a reboot, a logoff or a password change. The places in an operating system where something can be configured to start automatically are called **auto-start extensibility points (ASEPs)**. There is no fixed number — every Windows version and every installed product (Office add-ins, print providers, browser extensions) adds new ones, and researchers keep finding obscure ones. MITRE ATT&CK's **Persistence** tactic (TA0003) lists the well-known techniques and is a good checklist.

The defender's strategy has two parts:

1. **Know the common ones and watch them continuously** — ideally with a unique alert whenever a new entry appears (registry auditing, FIM, Sysmon/EDR).
2. **Spot-check the full list during an incident** with a tool that knows hundreds of locations.

### The most common ASEPs { #common-aseps }

| ASEP | What it is | ATT&CK | Example evidence |
| --- | --- | --- | --- |
| Run keys and startup folder | Programs started at logon via `…\CurrentVersion\Run` keys or the Startup folder | T1547.001 | Registry write (Sysmon 13), new file in Startup (Sysmon 11) |
| Services | A new or modified Windows service (runs as SYSTEM, starts at boot) | T1543.003 | System 7045, Security 4697 |
| Scheduled tasks | A task that runs at logon, at boot or on a timer | T1053.005 | Security 4698, TaskScheduler/Operational 106 |
| Browser extensions | An extension that runs in every browser session — reads pages, steals cookies | T1176.001 | New extension folder or policy key, browser management logs |
| Valid accounts | Simply logging back in with stolen credentials, or a new account the attacker created | T1078, T1136 | 4624 from unusual sources, 4720 account created |
| Linux: cron, systemd, shell profiles | `crontab`, a new `.service` unit, a line in `~/.bashrc` | T1053.003, T1543.002, T1546.004 | FIM/auditd on `/etc/cron*`, `/etc/systemd/system`, home dot-files |
| Linux/macOS: SSH keys | A key added to `~/.ssh/authorized_keys` | T1098.004 | FIM on `authorized_keys` |

The Run keys you will see most often:

```
HKCU\Software\Microsoft\Windows\CurrentVersion\Run         (current user, no admin needed)
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKLM\Software\Microsoft\Windows\CurrentVersion\Run         (all users, needs admin)
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup             (current user)
%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp         (all users, needs admin)
```

- `HKCU` = HKEY_CURRENT_USER — settings for the logged-on user only. Any user can write here, so even a phished standard user can persist with it.
- `HKLM` = HKEY_LOCAL_MACHINE — machine-wide. Writing requires administrator rights, and the entry runs for every user who logs on.
- `Run` entries start at every logon; `RunOnce` entries start once and are then deleted (attackers sometimes re-add them each time).
- The two `Startup` folders work the same way with files or shortcuts instead of registry values.

A quick PowerShell look at one key:

```powershell
PS C:\> Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

OneDrive     : "C:\Users\j.park\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background
MsEdgeUpdate : C:\Users\j.park\AppData\Roaming\MsEdge\msedgeupd.exe
PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
...
```

- `Get-ItemProperty '<key>'` — lists the values under that registry key; each value name is an entry, each value data the command that runs.
- `OneDrive` — the real OneDrive client from its normal install location. Expected.
- `MsEdgeUpdate` — looks like Edge's updater, but Edge's real updater runs from `C:\Program Files (x86)\Microsoft\EdgeUpdate\` as a scheduled task/service, not from a user's `AppData\Roaming\MsEdge\` folder. A name that imitates a vendor plus a user-writable path is the classic masquerade.
- `PSPath…` — PowerShell's own bookkeeping properties; ignore.

### Privilege decides the options { #privilege-and-persistence }

What the attacker can use depends on how far they got:

- **Standard user** — only per-user locations: HKCU Run keys, the user's Startup folder, per-user scheduled tasks, the user's browser extensions, shell profile files in their own home directory on Linux. These are noisy and easy to find, and they only fire when that user logs on.
- **Administrator / root** — machine-wide locations: services, system scheduled tasks, HKLM keys, WMI event subscriptions (T1546.003), system-wide systemd units and cron jobs, and the deepest one — **kernel drivers and rootkits** (T1014), which can hide files, processes and registry keys from the operating system itself. A rootkit is extremely hard to detect from inside the infected system and often the honest answer is "rebuild the machine".

That's also why privilege escalation (see [Privilege Escalation](../endpoint-attacks/privilege-escalation.md)) matters to the defender: it decides how deep the attacker can dig in and therefore how much clean-up you can trust.

### Hunting with Autoruns { #autoruns }

**Autoruns** (Sysinternals, free from Microsoft) knows hundreds of ASEP locations — logon entries, services, drivers, scheduled tasks, Explorer and Office add-ins, WMI, codecs, print monitors, LSA providers and more — and can check each entry's digital signature and look up its hash on VirusTotal. The GUI is good for one machine; the command-line version `autorunsc.exe` is better for collecting from many.

```
C:\> autorunsc64.exe -accepteula -a * -c -h -s -m -nobanner > C:\IR\ws-fin-0412_autoruns.csv
```

- `autorunsc64.exe` — the 64-bit command-line version.
- `-accepteula` — accept the licence prompt silently (needed for unattended runs).
- `-a *` — check **all** ASEP categories (you can also pick some, e.g. `-a l` logon, `-a s` services, `-a t` scheduled tasks).
- `-c` — output as CSV, so you can sort and compare.
- `-h` — include file hashes (MD5, SHA-1, SHA-256 and others).
- `-s` — verify digital signatures.
- `-m` — hide entries signed by Microsoft. This cuts the list from hundreds of lines to the dozens you actually need to look at. (Remember LOLBins: a Microsoft-signed binary in an ASEP can still be evil if its *arguments* are, so do one full pass without `-m` on important hosts.)
- `-nobanner` — no banner text at the top of the output.
- `> …csv` — save to a file for analysis or upload to your collection share.

A couple of rows from the result (columns trimmed, values invented):

```
Time,Entry Location,Entry,Enabled,Category,Description,Signer,Image Path,Launch String,SHA-256
2026-02-03 08:11,HKCU\...\CurrentVersion\Run,OneDrive,enabled,Logon,Microsoft OneDrive,(Verified) Microsoft Corporation,c:\users\j.park\appdata\local\microsoft\onedrive\onedrive.exe,"""C:\Users\j.park\AppData\Local\Microsoft\OneDrive\OneDrive.exe"" /background",5D0A...
2026-11-18 23:52,HKCU\...\CurrentVersion\Run,MsEdgeUpdate,enabled,Logon,,(Not Verified),c:\users\j.park\appdata\roaming\msedge\msedgeupd.exe,C:\Users\j.park\AppData\Roaming\MsEdge\msedgeupd.exe,8E77...
2026-11-18 23:55,Task Scheduler,\Microsoft\Windows\Maintenance\SysCheck,enabled,Tasks,,(Verified) Microsoft Windows,c:\windows\system32\windowspowershell\v1.0\powershell.exe,"powershell.exe -w hidden -enc SQBFAFgA...",9785...
```

How to read it:

- `Time` — the last-write time of the entry (the registry key or task file). Two entries created four minutes apart on 18 November late at night, right after the AppLocker block we saw earlier, line up.
- `Entry Location` / `Entry` — where and what. `MsEdgeUpdate` in the HKCU Run key; a task named `SysCheck` hidden in the `\Microsoft\Windows\Maintenance\` task folder, where real Windows tasks live — another masquerade.
- `Signer` — `(Verified) Microsoft Corporation` for OneDrive is fine. `(Not Verified)` for `msedgeupd.exe` — an unsigned file pretending to be Microsoft's updater. The task's signer is `(Verified) Microsoft Windows` because the image is `powershell.exe` — which is why `-m` would have hidden it if it weren't for the custom name, and why you must read the **Launch String**.
- `Launch String` — `powershell.exe -w hidden -enc SQBFAFgA...`: a hidden window and a Base64-encoded command (`-enc`). `SQBFAFgA` decodes from UTF-16LE Base64 to `IEX`, PowerShell's `Invoke-Expression` — the start of a download-and-run cradle. A legitimate Windows maintenance task doesn't look like this.
- `SHA-256` — the hashes to search across the fleet.

**[Supplement] Compare, don't just read.** The power of Autoruns at scale is *diffing*: collect the CSV from every machine, or compare one machine against a known-good build, and look for entries that appear on only one or a few hosts. That's the same "rarity" idea as with antivirus detections — legitimate software tends to be everywhere, attacker persistence tends to be in one place.

### From spot checks to continuous detection { #continuous-persistence-detection }

Autoruns is a snapshot. For continuous coverage, log the *creation* of persistence:

- **Registry writes** to Run/RunOnce and other ASEP keys — Sysmon event **13** (registry value set) or EDR registry telemetry.
- **File creation** in Startup folders, task folders, `/etc/cron*`, `/etc/systemd/system`, `authorized_keys` — Sysmon event **11** (file created), FIM, or `auditd` watches.
- **Service installation** — System event **7045** and Security event **4697** ("a service was installed in the system").
- **Scheduled task creation** — Security event **4698** ("a scheduled task was created") when object-access auditing for tasks is on.
- **New accounts** — Security event **4720**.

Each of these gets its own explanation on the important-events pages later. Here the point is the design: for every common ASEP, have one event that fires when a new entry appears, and send *that* to the SOC — not the full list every day.

## Putting it together — what a SOC takes from these layers { #soc-use }

- **Application control audit/block events** — "something not on the list tried to run". Low volume, high value, especially from `Temp`, `Downloads`, `AppData` and `ProgramData`. Check the parent process and how the file arrived.
- **Bypass indicators** — script blocks in Constrained Language Mode, LOLBins with odd arguments or odd parents, cross-process injection, renamed binaries, ACL changes on allowed folders.
- **FIM alerts** — new or changed files where change is rare: web roots, system binaries, persistence folders, `hosts`, SSH keys. Ask "which process and which user?".
- **Persistence creation events** — new Run values, services, tasks, accounts, cron entries, systemd units. Alert on *new*; hunt for *rare* with Autoruns diffs.
- **The story** — these controls often fire in sequence: a blocked or audited executable, then a persistence entry, then a new file in an unusual place. Seeing them together on one host turns three medium alerts into one high-confidence incident.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    Allowlisting as one of the most effective endpoint controls, the relative strength of filename/path/publisher/hash rules, audit-before-enforce and audit events as a detection source, the classic bypasses (scripts, LOLBins, injection, writable paths, stolen signing keys), FIM on rarely-changing paths such as web roots and system binaries, privilege deciding which persistence is possible, and Autoruns as the spot-check tool — all still hold. AppLocker event IDs (8002–8007) and the CodeIntegrity 3076/3077 events are unchanged.

!!! info "[Changed] What has changed"
    - **Naming.** Windows Defender Application Control (WDAC) is now called **App Control for Business**. AppLocker is still supported, but Microsoft recommends App Control for new deployments and puts new features there. Intune has a dedicated App Control policy type with managed-installer support, which made rollout much easier than the old XML-and-GPO approach.
    - **Smart App Control** brings reputation-based app control to consumer and small-business Windows 11 devices. It originally could only be turned on with a clean install; since 2026 updates it can be re-enabled without reinstalling. It is not a substitute for an organisation-managed policy, but it is worth knowing when you see its blocks.
    - **Sysmon is becoming part of Windows.** Microsoft started shipping Sysmon functionality as a built-in, optional Windows feature for Windows 11 and Windows Server 2025 in 2026. It still needs a configuration and log collection to be useful, and availability depends on the build — check your estate.
    - **MITRE ATT&CK updates.** Browser Extensions became a sub-technique: **T1176.001** under the renamed parent **T1176 Software Extensions** (which now also covers IDE extensions, T1176.002). Recent ATT&CK releases also restructured detection guidance into "detection strategies". Re-check technique IDs in old detection rules.
    - **macOS Gatekeeper got stricter.** Since macOS Sequoia, the old Control-click "open anyway" shortcut no longer bypasses Gatekeeper; users must approve the app in System Settings, which makes social engineering slightly harder.
    - **Persistence moved to identity and cloud.** Attackers increasingly persist without touching the endpoint at all: OAuth app consents, added MFA methods, mailbox rules, service-principal secrets, and stolen session tokens. ATT&CK covers these under T1098 (Account Manipulation) and T1078.004 (Cloud Accounts). Endpoint ASEP hunting is still needed, but it is no longer the whole picture.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't use filename rules**, and don't allow paths that standard users can write to. Check ACLs with `icacls` before writing a path rule.
    - **Don't cover only `.exe`.** Without script and MSI rules (and ideally DLLs), the policy has an open side door — and add Microsoft's recommended block rules for LOLBins ordinary users never need.
    - **Don't leave PowerShell 2.0 installed** on enforced machines; it ignores Constrained Language Mode. (It has been removed from current Windows 11 builds, but older images may still have it.)
    - **Don't trust a publisher rule as "only good software".** It allows every binary that publisher signed, including old vulnerable versions and dual-use tools. Add version floors and deny rules.
    - **Don't build allowlists or FIM baselines on MD5 or SHA-1.** Use SHA-256.
    - **Don't rely on nightly FIM alone for web servers.** A web shell can be used for hours before the scan. Use real-time monitoring on web roots.
    - **Don't run Autoruns only with `-m`** on critical hosts. Microsoft-signed binaries in ASEPs can carry malicious arguments — read the launch strings.
    - **Don't upload hashes or files from targeted incidents to public services without thinking.** A hash lookup is usually fine; uploading a sample can tip off the attacker.

## Practice questions { #quiz }

### Question 1

Your organisation enforces AppLocker with these rules: *Executable — allow `C:\Windows\*` and `C:\Program Files\*` for Everyone; allow `C:\Apps\*` for Everyone (added for a legacy finance tool).* There are no Script, MSI or DLL rules. An attacker phishes a standard user. Name three ways the attacker could still run code, what each would look like in your logs, and how you would close each gap.

??? success "Answer and explanation"
    Any three of these are good answers:

    - **Write into `C:\Apps`.** If standard users can write there (check with `icacls C:\Apps` — `Users:(M)` or `(W)` is the gap), the attacker drops `payload.exe` into `C:\Apps\` and it is allowed by the path rule (T1574 / abusing a weak path rule). *Evidence:* AppLocker **8002** (allowed) naming the `C:\Apps` rule for a file that isn't the finance tool, a new file in that folder (FIM or Sysmon 11). *Fix:* remove user write rights, or replace the path rule with a publisher or hash rule for the finance tool.
    - **Use a script.** No script rules means a `.ps1`, `.vbs`, `.js` or `.hta` runs through an allowed interpreter (T1059). *Evidence:* process creation of `powershell.exe`/`wscript.exe`/`mshta.exe` from Outlook or Explorer, PowerShell 4104 script blocks. *Fix:* add Script and MSI rules; enforced script rules also put untrusted PowerShell into Constrained Language Mode.
    - **Use a DLL with a LOLBin.** No DLL rules means `rundll32.exe C:\Users\<user>\AppData\Roaming\x.dll,Start` runs the attacker's code inside a Microsoft-signed binary in `C:\Windows` (T1218.011). *Evidence:* process creation of `rundll32.exe` loading a DLL from a user folder; Sysmon 7 image loads. *Fix:* DLL rules (or App Control, which covers DLLs by design) and block rules for LOLBins that users don't need.
    - **Inject into an allowed process** after getting a foothold via a macro (T1055) — *Evidence:* EDR/Sysmon 8/10; *Fix:* EDR and ASR rules, since application control doesn't see injection.

    The key insight: an executable-only allowlist with a writable path is mostly theatre — the policy has to cover the *other* ways to run code too.

### Question 2

A FIM agent on web server `web02.corp.example` (UID 33 = `www-data`) raises two alerts at 03:12: a new file `/var/www/html/images/icon_x.aspx.php`, owner `www-data`, 2 KB; and a change to `/var/www/html/.htaccess` (checksum changed, owner `deploy`, size unchanged by a few bytes). There was no release that night. What do you think happened, why does the owner field matter, and what are your next three steps?

??? success "Answer and explanation"
    **What happened:** almost certainly a **web shell** upload (T1505.003). A small script file appeared in an *images* folder, with a double extension (`.aspx.php`) designed to look harmless to a quick glance or a naive upload filter, and `.htaccess` was edited — likely to make PHP execute in that folder or to map an extension to the PHP handler. No release was scheduled, so nothing legitimate explains it.

    **Why the owner matters:** the new file is owned by **`www-data`** — the web server's own account. Site files are normally deployed by `deploy` (as the `.htaccess` owner shows). A file created by `www-data` means the **web application itself wrote it**, which is what an upload vulnerability or an already-present web shell does. The `.htaccess` keeping owner `deploy` but changing content means it was modified in place by something with write access to it — find out what, since the web user normally shouldn't be able to write that file.

    **Next steps (any reasonable three):** (1) search the web access log around 03:12 for the upload request (`POST` to an upload or plugin endpoint) and for every request to `icon_x.aspx.php` since — source IPs, parameters, response sizes; (2) check for commands run by `www-data` (process logs, `auditd` EXECVE records, AppArmor/SELinux denials such as `nginx` → `bash`) to see whether the shell was used and what was done; (3) preserve the file and `.htaccess` (copy, hash), then contain — block the source IPs, take the site into maintenance or isolate the server, patch the vulnerable component, and look for other new files across the web root (one web shell is rarely alone).

### Question 3

During an incident on workstation `WS-ENG-0077` you run `autorunsc64.exe -a * -c -h -s -m`. Among the results:

```
HKCU\...\CurrentVersion\Run, Teams, (Verified) Microsoft Corporation, c:\users\a.cho\appdata\local\microsoft\teams\current\teams.exe
HKLM\System\CurrentControlSet\Services, WinDefendHelper, (Not Verified), c:\programdata\winhelp\wdhelper.exe
Task Scheduler, \OneDrive Reporting Task-S-1-5-21-...-1107, (Verified) Microsoft Corporation, c:\users\a.cho\appdata\local\microsoft\onedrive\onedrivestandaloneupdater.exe
```

Which entry is suspicious, what does its location tell you about the attacker's privilege level, and which Windows events would you search for to find when it was created? Also: why might you still worry after removing it?

??? success "Answer and explanation"
    **Suspicious entry:** the service **`WinDefendHelper`** — a name that imitates Microsoft Defender (`WinDefend` is Defender's real service name), an **unsigned** binary (`Not Verified`), running from `C:\ProgramData\winhelp\`, a folder any process can create. Real Defender components live under `C:\ProgramData\Microsoft\Windows Defender\Platform\…` or `C:\Program Files\Windows Defender\` and are signed. This is masquerading (T1036) plus a malicious service (T1543.003). The Teams and OneDrive entries are signed and in their normal per-user locations.

    **Privilege level:** creating a service under `HKLM\System\CurrentControlSet\Services` requires **administrator** rights, and services usually run as **SYSTEM** at boot. So the attacker had (or got) admin on this machine — this isn't a standard-user foothold any more. That raises the stakes: with admin they could also have dumped credentials, created other system-wide persistence (WMI subscriptions, drivers) or tampered with security tools.

    **Events to search:** System **7045** ("a service was installed in the system": service name, image path, account, start type) and Security **4697** (the same, with the account that installed it, if the audit policy is enabled); also Sysmon 13 for the service registry keys and Sysmon 11 / process creation for when `wdhelper.exe` was written and who wrote it. Then work backwards from that time to the logon (4624) that preceded it.

    **Why worry after removing it:** an admin-level attacker rarely leaves a single persistence mechanism. There may be others that Autoruns with `-m` hid (a Microsoft-signed `powershell.exe` with malicious arguments in a task or WMI subscription), credentials they stole (persistence via **valid accounts**, T1078 — removing the service doesn't log them out), or at worst a kernel-level rootkit that hides itself from tools on the host. Scope the credentials used on the machine, do a full Autoruns pass without `-m`, and consider rebuilding the machine instead of cleaning it.

## Related { #related }

- [Credential Guard, Application Guard, Host Firewalls and Antivirus](vbs-firewall-antivirus.md) — the previous layer · [Inventory, Vulnerability Scanning, Patching and Exploit Protection](inventory-vulns-patching.md)
- [Execution, Persistence and Discovery](../endpoint-attacks/execution-persistence-discovery.md) · [Privilege Escalation](../endpoint-attacks/privilege-escalation.md)
- [Persistence — Services, Tasks & Run Keys](../../../adversary/persistence.md) · [LOLBins](../../../adversary/lolbins.md) · [Process Injection](../../../adversary/process-injection.md) · [PowerShell cradles](../../../adversary/powershell-cradles.md)
- [Impair Defenses and Log Clearing](../../../adversary/impair-defenses-log-clearing.md) · [Hardening by Windows version](../../../adversary/hardening-by-version.md)
- [Windows Event IDs](../../../basics/windows-event-ids.md)
