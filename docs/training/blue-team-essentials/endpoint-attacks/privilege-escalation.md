---
title: "Privilege Escalation — Climbing from User to Admin"
tags:
  - training
  - blue-team
  - endpoint
  - privilege-escalation
---

# Privilege Escalation — Climbing from User to Admin { #privilege-escalation }

!!! abstract "What this page covers"
    Why almost every serious intrusion has to **climb** from the low-privilege account it lands with to local admin, then to admin on many hosts, and finally to domain admin — and why every step of that ladder you make harder buys you time. How privilege escalation is even possible when operating systems are built to prevent it: the attacker gets **something that already has privilege to do the work for them** — an admin user, a service or task running as SYSTEM/root, an OS privilege, or a bug in software or the kernel. Then the two big families in detail: **abusing weak permissions** (a hijacked admin start-up item, a replaceable service binary, unquoted service paths, DLL search-order hijacking, modifiable scheduled tasks, and automated checkers like PowerUp running in memory), and **kernel exploitation** (what the kernel is, why a kernel bug means instant root, what an attacker needs, the Dirty Pipe example, and why compilers don't belong on production servers). Every sample (`icacls`, `whoami /groups`, 4688 with token fields, 4732, 4672, 7045, PowerShell 4104, auditd `SYSCALL`/`EXECVE`, `uname -r`) is broken down field by field. Practice questions at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs, hashes and file names are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. Most exploits land the attacker in a **low-privilege** context (a normal user, a web-service account). Real objectives — dumping credentials, disabling security tools, reaching other hosts — need **more**. So the attacker climbs: **user → local admin → admin on many hosts → domain admin**. ATT&CK tactic **Privilege Escalation (TA0004)**.
2. Operating systems are designed to stop this, so escalation almost always means **getting something that already has privilege to act for you**: an admin user, a service/task running as SYSTEM or root, an OS privilege (like `SeImpersonatePrivilege`), or a bug in privileged code.
3. The usual root causes are boring: **file and folder permissions** and **OS privileges** that are wider than they should be. No exploit is needed if a normal user can **write to something an admin or SYSTEM later runs**.
4. Classic Windows permission abuses: replacing an **admin start-up item**, replacing a **service binary**, **unquoted service paths** with spaces, **DLL search-order hijacking**, and **modifiable scheduled tasks**. ATT&CK groups most of them under **T1574 Hijack Execution Flow**.
5. Attackers don't hunt for these by hand: scripts such as **PowerUp** check everything in seconds, often **in memory** with no file on disk — which is why **PowerShell script block logging (4104)** and AMSI matter.
6. Once privileged code runs, attackers usually take a **permanent** foothold: add their account to Administrators (**4732**), create a service (**7045**), or start a credential dumper. Escalation and persistence are often the same action.
7. **Kernel exploitation** (**T1068**) attacks the most privileged code of all. If the kernel has a known bug, the attacker only needs to **get exploit code onto the box and run it** — and they become SYSTEM/root instantly. Patching the kernel and **removing compilers and dev tools** from production remove two of the three ingredients.
8. Detection idea for all of it: look for **identity changing without a legitimate path** — a process running as SYSTEM/root whose ancestry leads back to a normal user, a normal user writing files that privileged things run, or a user suddenly appearing in an admin group.

## Why attackers must climb { #why-climb }

### The privilege ladder { #ladder }

Think of an office building with key cards. A visitor card opens the lobby and one meeting room. A staff card opens your own floor. A facilities card opens every floor. The security manager's card opens everything, including the room where the cards are made. A burglar who steals a visitor card can't do much — so their whole plan becomes "**how do I upgrade my card?**"

On a Windows network, the steps look like this:

| Step | Typical identity | What it lets the attacker do |
| --- | --- | --- |
| 1. User | `CORP\p.nguyen`, `IIS APPPOOL\Portal`, `www-data` | Read that user's files, run programs as them, run discovery |
| 2. Local admin / SYSTEM / root | `BUILTIN\Administrators`, `NT AUTHORITY\SYSTEM`, `root` | Dump credentials from memory, disable AV/EDR, install drivers and services, read every file on the host |
| 3. Admin on many hosts | Help-desk group, server admins, a shared local admin password | Move laterally to dozens or hundreds of machines |
| 4. Domain admin | `Domain Admins`, `Enterprise Admins` | Control every domain-joined machine and account; create accounts; push ransomware by policy |

Two points that the table hides:

- **Attackers want to start as low as possible — from your point of view.** You want every exploit to land in a low-privilege account. If a web server runs as SYSTEM, or users work as local admins every day, the attacker **starts on step 2** and skips the hardest climb. That is why least privilege for services and users is so valuable (see [the attacker becomes the process](initial-exploitation.md#becomes-the-process)).
- **Each step is a chance to catch them.** Escalation is noisy compared to normal user activity: new group memberships, odd process ancestry, privileged processes started from user folders. Defences don't have to make escalation impossible; making it **slow and visible** is already a win.

Step 2 → 3 → 4 is usually done with **stolen credentials** (the next page: credential dumping) rather than exploits. This page is mainly about the **first climb on one host**: user → admin/SYSTEM/root.

!!! tip "[Supplement] Admin is not always admin: UAC and integrity levels"
    On Windows, even a member of `Administrators` normally runs with a **filtered token** at **Medium** integrity; admin rights are only used after a **UAC** prompt raises it to **High**. So an attacker who lands in an admin user's session often still needs one more step — a **UAC bypass** (ATT&CK **T1548.002**, see [UAC bypass](../../../adversary/uac-bypass.md)). SYSTEM processes run at **System** integrity. You can see this in `whoami /groups`:

    ```
    C:\> whoami /groups | findstr Label
    Mandatory Label\Medium Mandatory Level   Label   S-1-16-8192
    ```

    - `Mandatory Label\Medium Mandatory Level` — this shell runs at **Medium** integrity: admin rights (if any) are **not** active.
    - `S-1-16-8192` — the SID for Medium. High is `S-1-16-12288`, System is `S-1-16-16384`.

    In process-creation events the same idea appears as `TokenElevationType` and `MandatoryLabel` (example below). Microsoft is now replacing the UAC split-token model with **Administrator protection** — see the 2026 view.

## How escalation is possible at all { #how }

An operating system's job is to keep a normal user from touching protected things. So how does anyone get around it? Almost always by **getting a privileged party to do the work for them**. There are four ways to arrange that:

1. **Become the privileged user** — steal or guess an admin's password, hash or ticket. The OS is working correctly; it just thinks you are the admin.
2. **Trick something privileged into running your code** — an admin, a service, a scheduled task or a start-up item that runs a file **you can change**. This is the permissions family below.
3. **Abuse an OS privilege you already have** — for example, service accounts usually hold `SeImpersonatePrivilege`, which "potato"-style tools abuse to obtain a SYSTEM token ([token impersonation and potatoes](../../../adversary/token-impersonation-potato.md)). Windows itself granted the privilege; the attacker uses it in an unintended way.
4. **Exploit a bug in privileged code** — a vulnerable service, driver or the kernel itself. The code was supposed to check something and didn't.

Back to the building: (1) is stealing the manager's card, (2) is slipping your request into the manager's in-tray so they sign it without reading, (3) is using the cleaner's master key for something it wasn't meant for, and (4) is a broken lock on the card-printing room.

What does the attacker run once they get privileged execution? Usually one of three things: **a backdoor running as SYSTEM/root**, **a password dumper**, or **a command that makes their own account an admin**. The third is popular because it is **permanent**: even if their malware is later found and deleted, the account stays in Administrators and they can simply log back in.

Notice that technically, escalation **is** exploitation — but of a different kind from the first step. The initial exploit (previous page) got the attacker from *outside* to *some code running*. An escalation exploit needs the attacker to **already run code on the host** and moves them from *user* to *admin*. That makes it a **post-exploitation** activity, which is why it is so often found by looking at what happened on the host *after* the first alert.

## Abusing weak OS permissions { #permissions }

### The core idea: write to what the admin runs { #core-idea }

Here is the simplest version, and every other technique in this family is a variation of it.

An administrator on `LT-ENG-0042` built a small tool, `C:\mytools\admintool.exe`, and set it to run at start-up as **SYSTEM** through a scheduled task. When they created the folder, they didn't think about permissions. Let's look:

```
C:\> icacls C:\mytools
C:\mytools BUILTIN\Administrators:(OI)(CI)(F)
           NT AUTHORITY\SYSTEM:(OI)(CI)(F)
           BUILTIN\Users:(OI)(CI)(M)
           CREATOR OWNER:(OI)(CI)(IO)(F)
Successfully processed 1 files; Failed processing 0 files
```

- `icacls <path>` — show the access control list (ACL) of a file or folder. Each line is **who** : **(inheritance flags)(rights)**.
- `BUILTIN\Administrators:(OI)(CI)(F)` — admins have **F = Full control**. `OI` (object inherit) and `CI` (container inherit) mean the rule is copied down to files and sub-folders.
- `NT AUTHORITY\SYSTEM:(OI)(CI)(F)` — SYSTEM has full control. Normal.
- `BUILTIN\Users:(OI)(CI)(M)` — **the bug.** Every normal user has **M = Modify**: they can write, replace and delete files in this folder, and that right is inherited by `admintool.exe`. A safe ACL would give Users only `(RX)` = read and execute.
- `CREATOR OWNER:(OI)(CI)(IO)(F)` — whoever creates a file gets full control of it; `IO` (inherit only) means the rule applies to children, not the folder itself.

Now the normal user `p.nguyen` (or malware running as them) replaces `admintool.exe` with their own program that runs `net localgroup administrators p.nguyen /add`. Nothing happens immediately — the trap waits. At the next boot, the task runs the replaced file **as SYSTEM**, and `p.nguyen` becomes a local admin. The privilege was never "broken": SYSTEM used its own rights to run a file that a normal user was allowed to change.

The analogy: the manager signs every form in their in-tray each morning without reading. If anyone can put forms in the tray, anyone can get anything signed.

!!! tip "[Supplement] Why SYSTEM tasks and services, not just a Run key"
    If the admin's tool were started from the `HKLM\…\Run` key instead, it would run at log-on **as whoever logs on**, and for an admin under UAC with the **filtered (Medium) token** — so `net localgroup … /add` would fail with "Access is denied". That's why attackers prefer to hijack things that run as **SYSTEM** (services, tasks set to run as SYSTEM or "with highest privileges") and why defenders should audit those first.

### What the logs show { #permissions-evidence }

The planting step and the trigger step happen at different times, often days apart. Defenders need both.

**1. The plant** — a normal user writing an executable into a folder that a privileged task runs from. With Sysmon file-creation logging (event 11) or object-access auditing (4663) on such folders:

```
Event ID: 11   File created
UtcTime:         2026-11-17 14:02:51.733
Image:           C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename:  C:\mytools\admintool.exe
User:            CORP\p.nguyen
```

- `Event ID 11` — Sysmon "file created" (also fires when a file is overwritten by delete-and-create).
- `TargetFilename C:\mytools\admintool.exe` — the exact file the SYSTEM task runs.
- `User CORP\p.nguyen` — a **non-admin** wrote it. Whatever is in this file will soon run as SYSTEM.
- `Image … powershell.exe` — the writer was PowerShell, not an installer.

**2. The trigger** — after reboot the task runs the file as SYSTEM, and the file adds the user to Administrators. Event **4732 — "A member was added to a security-enabled local group"** (Security log, needs *Audit Security Group Management*):

```
EventID:           4732
Computer:          LT-ENG-0042.corp.example
SubjectUserName:   LT-ENG-0042$
SubjectDomainName: CORP
SubjectLogonId:    0x3E7
MemberSid:         S-1-5-21-1111111111-2222222222-3333333333-1604
TargetUserName:    Administrators
TargetDomainName:  Builtin
```

- `EventID 4732` — someone was added to a **local** group. (4728 is the domain-global-group version, 4756 universal.) Attackers care because Administrators membership survives reboots and malware clean-up.
- `SubjectUserName LT-ENG-0042$` and `SubjectLogonId 0x3E7` — **who did the adding**: the computer account, logon ID `0x3E7` = **SYSTEM**. A human admin adding someone would appear by name, from an interactive or remote session. **SYSTEM adding a user to Administrators** right after boot is a strong sign of a hijacked service or task.
- `MemberSid …-1604` — the account added (resolve it: `p.nguyen`). The event shows a SID, not a name.
- `TargetUserName Administrators` — the group.

**3. The process** — 4688 for the command, with its token fields:

```
EventID:            4688
Computer:           LT-ENG-0042.corp.example
SubjectUserName:    LT-ENG-0042$
SubjectLogonId:     0x3E7
NewProcessName:     C:\Windows\System32\net.exe
CommandLine:        net localgroup administrators p.nguyen /add
ParentProcessName:  C:\mytools\admintool.exe
TokenElevationType: %%1936
MandatoryLabel:     S-1-16-16384
```

- `ParentProcessName C:\mytools\admintool.exe` — the admin tool (now replaced) started `net.exe`. The real tool presumably never did this — compare with earlier boots.
- `TokenElevationType %%1936` — **Type 1, full token** (no UAC split; typical for SYSTEM and services). `%%1937` = Type 2, elevated; `%%1938` = Type 3, limited (filtered).
- `MandatoryLabel S-1-16-16384` — **System** integrity.

Put together: *normal user writes file → days later SYSTEM runs that file → SYSTEM adds that normal user to Administrators*. Each event alone may look explainable; the chain is not.

### The common variations { #variations }

All of these are "make something privileged run code you control", differing only in **what** the writable thing is. ATT&CK IDs are current Enterprise IDs.

| Technique | What is weak | What the attacker does | ATT&CK |
| --- | --- | --- | --- |
| Hijacked admin start-up item | Writable file/folder of something an admin or SYSTEM runs at boot/log-on | Replace the file | T1574 (family), T1547 |
| Modifiable service binary | Users can write the service's `.exe` | Replace it; restart or wait for reboot | T1574.010 Services File Permissions Weakness |
| Modifiable service configuration | Users can change the service's registry key/config | Point `ImagePath` at their own program | T1574.011 Services Registry Permissions Weakness |
| Unquoted service path | Path with spaces, no quotes, and a writable folder along the way | Drop an EXE where Windows looks first | T1574.009 Path Interception by Unquoted Path |
| DLL search-order hijacking | A privileged program loads a DLL by name from a folder users can write | Drop a malicious DLL with that name | T1574.001 DLL |
| Modifiable scheduled task | A SYSTEM task runs a script/EXE users can write (or the task definition itself is writable) | Edit the script | T1053.005, T1574 |
| Linux: SUID binaries, `sudo` rules, writable root cron scripts | Too-generous SUID bits or `sudo` entries; root jobs running user-writable files | Run the SUID/`sudo` program in an unintended way; edit the script | T1548.001 Setuid and Setgid, T1548.003 Sudo and Sudo Caching, T1053.003 |

Two of these need a closer look because their mechanism is less obvious.

#### Unquoted service paths { #unquoted }

Suppose a service is registered with this binary path — **without quotes**:

```
C:\Apps\Acme Backup\bin\agent.exe -svc
```

Because of the spaces, Windows doesn't know where the program name ends and the arguments begin. It tries each possibility **in order**:

1. `C:\Apps\Acme.exe` (with arguments `Backup\bin\agent.exe -svc`)
2. `C:\Apps\Acme Backup\bin\agent.exe` (with argument `-svc`) ← the intended one

If a normal user can write into `C:\Apps\`, they can drop `C:\Apps\Acme.exe`, and at the next service start Windows runs **their** file as the service account (often LocalSystem). With quotes (`"C:\Apps\Acme Backup\bin\agent.exe" -svc`) there is no ambiguity and no attack.

Note the condition: the attacker needs **write access to one of the earlier folders**. Under `C:\Program Files\` normal users can't write, so an unquoted path there is a bad practice but usually not exploitable. Custom folders off the root of `C:\` (like `C:\Apps`, `C:\Tools`) often inherit **Users: write/create** from `C:\` and are where it really bites.

A defender sweep for risky services:

```powershell
Get-CimInstance Win32_Service |
  Where-Object { $_.PathName -notmatch '^"' -and $_.PathName -match '^[^"]*\s.*\.exe' } |
  Select-Object Name, StartName, StartMode, PathName
```

1. `Get-CimInstance Win32_Service` — list all services with their properties (the modern replacement for `wmic service`).
2. `$_.PathName -notmatch '^"'` — the path does **not** start with a quote…
3. `-match '^[^"]*\s.*\.exe'` — …and has a **space before `.exe`**: the unquoted-with-spaces case.
4. `Select-Object …` — show the service name, the account it runs as, start mode and path.

Output:

```
Name        StartName    StartMode PathName
----        ---------    --------- --------
AcmeBackup  LocalSystem  Auto      C:\Apps\Acme Backup\bin\agent.exe -svc
```

`LocalSystem` + `Auto` + unquoted path under `C:\Apps` = check `icacls C:\Apps` right away. If `BUILTIN\Users` has `(W)`, `(M)` or `(AD)` (add sub-directory/file), fix the ACL and add quotes.

#### DLL search-order hijacking { #dll-hijack }

Programs load helper libraries (DLLs). When a program asks for a DLL **by name only** (`LoadLibrary("helper.dll")`) instead of a full path, Windows searches a list of locations, and the **application's own folder comes first**. If a privileged program lives in — or is started from — a folder normal users can write, an attacker can drop a `helper.dll` there and it loads **inside the privileged process**. No new process appears; the malicious code runs as the trusted program, which makes it also a stealth technique.

Evidence is **Sysmon 7 (image loaded)** — a DLL loaded from an unusual, user-writable path, often unsigned:

```
Event ID: 7   Image loaded
Image:           C:\Apps\Acme Backup\bin\agent.exe
ImageLoaded:     C:\Apps\Acme Backup\bin\version.dll
Signed:          false
SignatureStatus: Unavailable
User:            NT AUTHORITY\SYSTEM
```

- `Image` — the process doing the loading, running as `SYSTEM`.
- `ImageLoaded … version.dll` — `version.dll` is a real Windows DLL that normally lives in `System32`. A copy **next to the program** is the classic hijack shape.
- `Signed false` — the real one is signed by Microsoft. An unsigned "system DLL name" in an app folder is a strong signal.

(ATT&CK v17 merged the old *DLL Side-Loading* sub-technique into **T1574.001**, now simply called **DLL**, so older rules tagged T1574.002 need remapping.)

### Automated checkers: PowerUp and friends { #powerup }

Attackers don't inspect ACLs by hand. **PowerUp** — a PowerShell script from the open-source **PowerSploit** framework — checks for practically all of the above in seconds: modifiable service binaries and registry keys, unquoted paths, writable folders in `PATH`, DLL hijack opportunities, modifiable tasks, stored credentials in common files, and more. It can also **abuse** what it finds. Similar tools exist for other platforms (WinPEAS/LinPEAS-style scripts, compiled C# checkers).

Why it is hard to see: it is **pure PowerShell** and is usually **loaded straight into memory** (a download cradle — see [PowerShell cradles](../../../adversary/powershell-cradles.md)), so no file touches the disk for antivirus to scan. What *does* see it:

- **PowerShell script block logging — event 4104** in `Microsoft-Windows-PowerShell/Operational`. PowerShell logs the script text it compiles, even if it came from memory, and automatically logs blocks it considers suspicious even when full logging is off.
- **AMSI** (Antimalware Scan Interface), which lets Defender/EDR scan the script content at run time.

A 4104 record a defender might find:

```
Log Name:       Microsoft-Windows-PowerShell/Operational
Event ID:       4104
Level:          Warning
Computer:       LT-ENG-0042.corp.example
User:           CORP\p.nguyen
Message:        Creating Scriptblock text (1 of 7):
                function Get-ModifiableServiceFile {
                ...
                function Invoke-AllChecks {
                ...
ScriptBlock ID: 6b0e2c4a-91d3-4f6e-9a1b-0c55d2e7a301
Path:
```

- `Event ID 4104` — "creating script block": the text of PowerShell code being run.
- `Level Warning` — PowerShell itself flagged the block as **suspicious** (auto-logging).
- `(1 of 7)` — a large script split over seven events; join them by `ScriptBlock ID`.
- Function names like `Get-ModifiableServiceFile` / `Invoke-AllChecks` — well-known escalation-checker functions. Attackers rename them, so don't rely on names alone; also look for many ACL/service queries in one script block.
- `Path:` empty — the script was **not** loaded from a file: it came from memory or the command line.

The defender's best counter to the whole family, though, is not detection — it's **running the same checks first**. If your vulnerability management or a periodic audit runs a PowerUp-style check on your own builds, the attacker finds nothing.

## Kernel exploitation { #kernel }

### Why the kernel is the ultimate target { #kernel-why }

The **kernel** is the core of the operating system: it schedules processes, manages memory, talks to drivers and hardware, and **decides who is allowed to do what**. Every permission check on this page is, in the end, enforced by kernel code. Kernel code is still code, written by people, so it has bugs.

If an attacker finds a bug that lets them run their own code **in the kernel** (or change kernel memory, such as their own process's credentials), every permission check becomes meaningless — they can simply rewrite "this process belongs to user 1001" into "this process belongs to root". To the attacker it feels like a magic trick: run one program, get a root shell. ATT&CK: **T1068 Exploitation for Privilege Escalation**.

Going back to the building: instead of fooling a person with a key card, the attacker breaks the card-reader controller in the basement so that every door opens for every card.

### What the attacker needs { #kernel-needs }

For the most common case, **local privilege escalation**, only three ingredients:

1. **A vulnerable kernel** — a version with a known, unpatched bug. Easy to check: `uname -r` on Linux, `systeminfo` or the build number on Windows.
2. **The exploit code on the box** — downloaded as a ready binary, or **compiled on the target** if a compiler (`gcc`, `make`) is installed.
3. **The ability to run it** — any shell as any user.

That makes the defences obvious too: **patch the kernel** (removes 1), **remove compilers and development tools from production systems** and block downloads of executables (makes 2 harder), and **application control / `noexec` on writable mounts like `/tmp`** (makes 3 harder). Removing `gcc` from a web server won't stop an attacker who brings a pre-compiled binary, but it removes the easiest path and forces them to make noise downloading.

### Example: Dirty Pipe (CVE-2022-0847) { #dirty-pipe }

Dirty Pipe, disclosed in March 2022, was a bug in how the Linux kernel handled **pipe buffers** together with the page cache (the kernel's in-memory copy of files). Because of a flag that was not cleared properly, a normal user could make the kernel write data **into the cached copy of a file they were only allowed to read** — including files owned by root and even read-only ones. Overwrite part of a SUID-root program or a root-owned config file in the cache, and the next time it runs or is read, it does what the attacker wants: a root shell. It affected kernels from **5.8** and was fixed in **5.16.11, 5.15.25 and 5.10.102** (Android devices on those kernels were affected too).

A defender's first check on a Linux host:

```
$ uname -r
5.13.0-27-generic
```

- `uname -r` — print the running kernel release.
- `5.13.0-27-generic` — a 5.13 kernel (between 5.8 and the fixed versions, and 5.13 was not a long-term branch that got the fix in its own numbering), so on its face **vulnerable** to Dirty Pipe. Distribution kernels back-port fixes under their own version numbers, so always confirm against the **distribution's security advisory**, not the upstream number alone.

What a kernel escalation looks like in **auditd** (detail on auditd comes in the process-creation page later). The key idea is the **`auid` (audit/login user ID)**: it is set at log-in and **does not change** when the process becomes root. So a root process with the `auid` of a normal user, which did **not** get there through `sudo`/`su`, is the fingerprint:

```
type=SYSCALL msg=audit(1795153445.120:4182): arch=c000003e syscall=59 success=yes exit=0 ppid=24410 pid=24477 auid=1001 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=12 comm="sh" exe="/usr/bin/dash" key="exec"
type=EXECVE msg=audit(1795153445.120:4182): argc=1 a0="/bin/sh"
type=PROCTITLE msg=audit(1795153445.120:4182): proctitle="/bin/sh"
```

- `msg=audit(1795153445.120:4182)` — epoch time (2026-11-20 05:44:05 UTC) and record number; all three lines share it, so they describe **one event**.
- `syscall=59` — on x86-64 (`arch=c000003e`), 59 is `execve`: **a program was started**.
- `ppid=24410 pid=24477` — parent and new process IDs. Look up 24410 next.
- `auid=1001` — the person who **logged in** was user 1001 (say `d.okafor`)…
- `uid=0 euid=0 …` — …but this process runs as **root** in every ID field.
- `tty=pts1 ses=12` — an interactive terminal session.
- `exe="/usr/bin/dash"`, `EXECVE a0="/bin/sh"` — a root shell.

Now the parent:

```
type=SYSCALL msg=audit(1795153444.871:4179): arch=c000003e syscall=59 success=yes exit=0 ppid=24301 pid=24410 auid=1001 uid=1001 gid=1001 euid=1001 tty=pts1 ses=12 comm="dp" exe="/tmp/.cache/dp" key="exec"
```

- `uid=1001 euid=1001` — the parent ran as the normal user.
- `exe="/tmp/.cache/dp"` — a program in a **hidden folder in `/tmp`**, run by the user.
- 0.25 seconds later its child is root, and there is **no `sudo` record** in `/var/log/auth.log` or the journal. A normal user's program in `/tmp` whose child is suddenly root, without `sudo`/`su`/a SUID program you recognise, is the classic kernel-exploit picture. EDRs on Linux alert on exactly this "**unexpected UID transition**".

!!! tip "[Supplement] The Windows side of kernel escalation"
    On Windows the same idea appears as exploits against the kernel (`ntoskrnl.exe`, `win32k.sys`) or kernel drivers — for example, the Common Log File System driver bug **CVE-2025-29824** was exploited as a zero-day by ransomware operators in 2025. A common shortcut is **BYOVD (Bring Your Own Vulnerable Driver)**: the attacker installs a legitimately signed but **buggy** driver and exploits it to get kernel access, often to kill EDR. Evidence: **7045** with `Service Type: kernel mode driver`, **Sysmon 6 (driver loaded)** with an unusual driver name or path, and the **vulnerable driver blocklist** blocking it. The resulting SYSTEM process typically has a user process as its ancestor — the same "identity changed without a legitimate path" idea.

## Detecting escalation: one rule of thumb { #detect }

| Signal | Where to see it |
| --- | --- |
| Normal user writes an EXE/DLL/script into a folder that SYSTEM/root runs from | Sysmon 11, 4663 on audited folders, FIM, auditd file watches |
| SYSTEM/LocalSystem adds an account to an admin group | 4732 / 4728 / 4756 with Subject = computer account / `0x3E7` |
| New service or driver, especially from a writable path | 7045 / 4697, Sysmon 6 |
| A DLL with a system name loaded from an app/user folder | Sysmon 7 |
| Escalation checkers in PowerShell | 4104 (often `Warning` level), AMSI/EDR alerts |
| A process running as SYSTEM/root whose ancestor is a user's process (no `sudo`, `su`, UAC consent, or known service path) | 4688/Sysmon 1 ancestry, auditd `auid` ≠ `uid`, EDR |
| Special privileges assigned to a logon that shouldn't have them | **4672** "Special privileges assigned to new logon" for an account that isn't an admin |

The common thread: **identity changed, and there's no legitimate path that explains it.** A user becoming admin through the help desk leaves a ticket and an admin's name on the 4732. A user becoming admin through a hijacked task leaves SYSTEM's name and a file write by the user days before.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The ladder (user → local admin → many hosts → domain) still describes almost every hands-on intrusion and ransomware case. Weak file/service permissions, unquoted paths, DLL hijacking and modifiable tasks are still found in real enterprise builds — especially in third-party and in-house software installed outside `Program Files`. Kernel and driver exploits are still a top route: Linux **CVE-2024-1086** (nf_tables) was added to CISA's Known Exploited Vulnerabilities list and later flagged as used in ransomware campaigns, and Windows kernel-driver zero-days keep appearing in Patch Tuesday releases. "Patch the kernel, remove compilers, least privilege, run the checkers yourself" is still the right advice.

!!! info "[Changed] What has changed"
    - **Administrator protection replaces the UAC split token.** Windows 11 introduced *Administrator protection*: admins run without admin rights, and elevation creates a **separate, hidden, temporary admin token** only after Windows Hello authentication, which closes many classic UAC-bypass tricks. It is not on by default for every PC; the **Windows 11 26H2 security baseline (October 2026)** turns it on for managed devices. Expect fewer UAC bypasses where it is deployed — and compatibility issues to plan for.
    - **Vulnerable driver blocklist on by default** in Windows 11 (since 22H2), and HVCI/memory integrity is on by default on many new devices — BYOVD is harder but still common where these are off or the driver isn't on the list yet.
    - **PowerSploit is unmaintained.** The project has been archived for years; PowerUp still works and is still seen, but attackers increasingly use maintained or compiled checkers (C# assemblies run in memory, WinPEAS/LinPEAS-style tools). Detection based only on PowerUp function names is weak.
    - **ATT&CK changes.** **T1574.002 DLL Side-Loading** was merged into **T1574.001 (now "DLL")**; in v19 (April 2026) the Defense Evasion tactic was split into **Stealth (TA0005)** and **Defense Impairment (TA0112)**, so hijack-execution techniques that sit in several tactics now appear under Stealth instead of "Defense Evasion". T1068 and T1548 are unchanged.
    - **Identity and cloud escalation.** In hybrid environments a large share of "privilege escalation" now happens in the identity provider — abusing role assignments, app permissions or misconfigured certificate templates ([AD CS abuse](../../../adversary/adcs-abuse.md)) — without any host exploit.

!!! warning "[Caution] Where the old way is wrong or risky today"
    - **Don't treat "not exploitable from the internet" as "low priority" for local privilege escalation bugs.** Ransomware crews chain an initial foothold with a known LPE within hours; a LPE in CISA KEV deserves the same urgency as a remote bug.
    - **Don't rely on upstream kernel version numbers alone.** Distributions back-port fixes; check the vendor advisory (or live-patch status) before calling a host vulnerable or safe.
    - **Don't run PowerUp-style tools on production without change control** — some checks *modify* services or write files when abuse functions are used. Use read-only audit modes or vendor tools.
    - **Don't let users run as local admin "because it's easier"**, and don't share one local admin password across machines — use LAPS (now built into Windows) so one stolen local admin doesn't become step 3 of the ladder.
    - **Don't forget the `auid` field.** Many Linux detections look only at `uid=0`, which is full of normal root activity; `auid` ≠ `uid` without `sudo` is the useful signal.

## Practice questions { #quiz }

### Question 1

On `LT-ENG-0042` you find a 4732 event at 08:01 on Monday: `SubjectUserName = LT-ENG-0042$`, `SubjectLogonId = 0x3E7`, `TargetUserName = Administrators`, `MemberSid` resolving to `CORP\p.nguyen`. The help desk has no ticket. What most likely happened, what other events would you look for, and what should be fixed?

??? success "Answer and explanation"
    `0x3E7` and the computer account mean **SYSTEM** made the change, not a human admin. SYSTEM adding a normal user to Administrators right after a Monday-morning boot, without a ticket, points to **privilege escalation through something privileged that runs code the user could change** — a hijacked service binary, scheduled task, unquoted service path or DLL (T1574 family / T1053.005).

    Look for: the **4688/Sysmon 1** for `net.exe … /add` (or `Add-LocalGroupMember`) and its **parent** — that tells you which service/task ran the payload; earlier **Sysmon 11 / 4663** showing `p.nguyen` writing that parent file; **7045/4697/4698** in case a new service or task was created; **4104** for escalation-checker scripts run by `p.nguyen` before the plant; and logons by `p.nguyen` afterwards using the new rights (credential dumping is the usual next step).

    Fix: remove the user from Administrators, restore the original binary, **fix the ACL** (Users should have read/execute only), quote service paths, sweep other hosts built the same way, and treat `p.nguyen`'s account and the host's credentials as compromised.

### Question 2

A service runs as `LocalSystem` with the path `C:\Program Files\Contoso Sync\syncsvc.exe` (unquoted). Another runs as `LocalSystem` with `C:\Tools\Fleet Agent\agent.exe` (unquoted), and `icacls C:\Tools` shows `BUILTIN\Users:(OI)(CI)(M)`. Which is actually exploitable, how, and what is the fix?

??? success "Answer and explanation"
    Both are **unquoted paths with spaces**, so Windows will try earlier interpretations first (`C:\Program.exe`, `C:\Program Files\Contoso.exe`; `C:\Tools\Fleet.exe`). But the attack only works if a normal user can **write** to one of those earlier locations. Normal users can't write to `C:\` or `C:\Program Files\` by default, so the first service is **bad practice but usually not exploitable**. `C:\Tools` grants **Users: Modify**, so a user can drop `C:\Tools\Fleet.exe`; at the next service start Windows runs it **as LocalSystem** (T1574.009). That one is a live escalation path.

    Fix: put **quotes** around both service paths (in the service's `ImagePath`), and fix the `C:\Tools` ACL to read/execute for Users (or move the agent under `Program Files`). Then check for any `Fleet.exe` already sitting in `C:\Tools` and for 7036/7045 and 4688 events showing it ran.

### Question 3

On a Linux web server, auditd shows a process `exe="/tmp/.cache/dp"` with `auid=1001 uid=1001`, and 0.3 s later its child `/bin/sh` with `auid=1001 uid=0 euid=0`. There is no `sudo` or `su` entry for that time. `uname -r` returns `5.13.0-27-generic`. Explain what likely happened and what you would do.

??? success "Answer and explanation"
    The `auid` (login user) stays 1001 across both records, but the child suddenly runs as **root** — and there is no legitimate path (`sudo`, `su`, a known SUID program) to explain the change. The parent is an unknown binary in a hidden `/tmp` folder. Together with a kernel version in the range affected by **Dirty Pipe (CVE-2022-0847)** or other known kernel bugs, this is the classic picture of **kernel exploitation for privilege escalation (T1068)**: the attacker, already running as user 1001 (maybe through the web application), ran an exploit and got a root shell.

    Actions: treat the server as **fully compromised at root level** (root can hide files, install rootkits and tamper with logs, so on-host evidence may be incomplete); isolate it; collect memory and the `/tmp/.cache/dp` binary; work out how user 1001 got a shell (web logs, the earlier process tree); rebuild from a clean image on a **patched kernel** (confirm with the distribution's advisory); remove compilers and mount `/tmp` with `noexec`; rotate any secrets on the box; and hunt other servers on the same kernel.

## Related references { #related }

- [Execution, Persistence and Discovery](execution-persistence-discovery.md) — the step before this one · [Initial Exploitation](initial-exploitation.md)
- [UAC bypass](../../../adversary/uac-bypass.md) · [Token impersonation and potato attacks](../../../adversary/token-impersonation-potato.md) · [PrintNightmare](../../../adversary/printnightmare.md)
- [PowerShell download cradles](../../../adversary/powershell-cradles.md) · [Persistence](../../../adversary/persistence.md) · [AD CS abuse](../../../adversary/adcs-abuse.md)
- [Windows event IDs](../../../basics/windows-event-ids.md) · [Linux commands](../../../basics/linux-commands.md)
