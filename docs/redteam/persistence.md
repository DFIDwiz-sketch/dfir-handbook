---
title: Persistence
tags:
  - redteam
  - persistence
---

# Persistence — Master Reference

!!! abstract "About this page"
    Built on the Persistence chapter of CRTO (Certified Red Team Operator) study material, then expanded with **per-version Windows 10 / 11 behaviour**, **why some legacy techniques are now dead**, and the latest **EDR/DFIR detection matrix**.
    As with the rest of this handbook, the emphasis is on **mechanics and detection artifacts** — what the operator touches and what it leaves behind — rather than weaponization. Examples stay at the conceptual level (registry paths, flow diagrams), not working malware.

!!! note "Structure (three parts)"
    - **Part 1** — Concept, OPSEC principles, and user-land persistence (Registry Run keys, Startup folder, Scheduled Tasks)
    - **Part 2** — Advanced evasion persistence (COM Hijacking, WMI Event Subscription, Windows Services)
    - **Part 3** — System hooking, modifying existing resources, and application-level persistence (LNK tampering, IFEO/SilentProcessExit, Winlogon, ServiceDll hijacking, Office/PowerShell/dev-tool persistence, RID hijacking)

## Contents

- [1. Overview & OPSEC principles](#overview)
- [2. User-Land persistence](#userland)
- [3. Advanced evasion persistence (Part 2)](#advanced)
- [4. System hooking & modifying existing resources (Part 3)](#part3)

---

<a id="overview"></a>

# Persistence — Overview & OPSEC

## 1. What persistence is, and the operator's principles

### 1.1 What is persistence?

Persistence (MITRE ATT&CK: TA0003) is the tactic of keeping the access to a target that was hard-won through initial access. It means planting a backdoor or auto-run trigger around the system so that the operator's C2 beacon comes back and recovers the connection even after the victim shuts down (reboot), logs off, or the running process crashes.

### 1.2 Three design principles for persistence

1. **Privilege level matters:** The techniques available differ completely depending on whether you currently hold standard-user (Medium Integrity) or local-admin (High Integrity) rights. Right after initial access you usually have standard-user rights, so **user-land persistence** comes first.
2. **Separate payload from trigger (OPSEC):** Registering a blatant command like `powershell.exe -enc ...` or an unsigned malicious `.exe` directly in a persistence location (e.g. a registry Run key) gets caught in seconds by AV and by a Blue Team `Autoruns` review. The **DLL side-loading** and **.NET AppDomainManager** techniques from Initial Access should be combined with the persistence trigger so it looks like a legitimate program auto-starting.
3. **Resilience and cleanup:** Running too often generates excessive network traffic and process-creation logs, which get detected. Using a too-common default path, on the other hand, makes removal easy.

---

<a id="userland"></a>

# User-Land persistence

When you don't have local-admin rights yet (before UAC), these are the core techniques to re-run a payload at reboot or re-logon within the current logged-in user's context.

### 2.1 Registry auto-run keys (Run / RunOnce)

#### Core idea

Windows automatically runs programs registered under certain registry paths when a user logs in. A standard user can't modify the system-wide `HKLM (HKEY_LOCAL_MACHINE)`, but can freely modify the current-user hive, **`HKCU (HKEY_CURRENT_USER)`**.

- **Key registry paths:**
    - `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (runs every time the user logs in)
    - `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce` (runs once at next login, then the value is auto-deleted)
    - *(Admin required)* `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (runs for all users at login)

```
[Registry Run key flow]

[User logs into Windows]
       │
       ▼
[userinit.exe -> explorer.exe initialises]
       │
       ▼
[Reads HKCU\...\CurrentVersion\Run]
       │
       ▼
[Runs the registered value: e.g. C:\ProgramData\LegitApp\Updater.exe]
       │
       ▼
[DLL side-loading fires -> loads malicious DLL in the same folder -> C2 reconnects]
```

#### Recent behaviour and constraints (Win 10 / Win 11)

1. **Task Manager / startup-app notification:** On Win 10/11, adding a new entry under `HKCU\...\Run` can raise a system-tray toast ("a new startup app was added"), and it shows up in the Task Manager → Startup apps tab.
2. **Real-time registry monitoring by EDR:** Every commercial EDR and Microsoft Defender statically/dynamically scans the target file the instant a value is written to a `CurrentVersion\Run` key (Registry Value Set). Pointing a dropper or C2 beacon `.exe` directly here is a non-starter — it must point at a legitimately signed binary (a DLL side-loading host) or a benign routine that hides a script.

### 2.2 Startup folder

#### Core idea

Similar to Run keys, Windows Explorer (`explorer.exe`) auto-runs every file or shortcut (`.lnk`) in certain special folders when it starts.

- **Key paths:**
    - **Current user only (standard-user writable):** `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` (full path: `C:\Users\<Username>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`)
    - **All users (admin required):** `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`
- **Operation:** Rather than dropping an `.exe` directly in this folder, the usual approach is to hide the real payload (e.g. a DLL side-loading package) deep inside `%LocalAppData%` or `C:\ProgramData`, and place only a shortcut (`.lnk`) pointing to it in the Startup folder.

#### Detection

- **Highly exposed:** The Startup folder is the first path Blue Teams and AV check. A Sysmon Event ID 11 (FileCreate) for a file whose path contains `\Start Menu\Programs\Startup\` is a default alert in almost every SOC.

### 2.3 Scheduled Tasks

#### Core idea

The Windows Task Scheduler runs programs at a certain time or on a certain system event. Many assume admin rights are required, but **a standard user can create a scheduled task that runs under their own rights.**

- **Trigger constraints by privilege:**

| Trigger type | Privilege needed | Notes / usefulness |
| --- | --- | --- |
| **Specific time / periodic** (daily, weekly, every X hours) | Standard user | The safest to use. E.g. run at 9:30 AM (arrival time) or hourly so the beacon revives if it dies. |
| **On idle** | Standard user | Runs while the user is away from the keyboard — hard to notice. |
| **At logon** | Admin recommended (standard user possible in limited cases) | A full user-logon trigger generally requires High Integrity. |
| **At startup** | Admin (High Integrity / SYSTEM) | Runs as `SYSTEM` during boot, before user login. |

- **How it works:** Tasks are registered via `schtasks.exe`, PowerShell's `New-ScheduledTask` cmdlet, or the Task Scheduler COM object (`Schedule.Service`). Once created, the task definition is stored as an XML file under `C:\Windows\System32\Tasks\`, with cache info in the registry at `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\`.

#### Detection and OPSEC

1. **Avoiding `schtasks.exe` process-creation detection:** Running `schtasks.exe /create ...` from the command line records the full command line in the process-creation log (Event ID 4688, Sysmon ID 1), exposing it to EDR immediately. Modern tooling (e.g. Cobalt Strike BOFs) therefore calls the **COM API (`ITaskService`) or RPC (`ATSvc` / `ITaskSchedulerService`)** in memory to register a task quietly, without spawning a process.
2. **Windows Security log (Event ID 4698):** Even if the `schtasks.exe` execution is hidden via COM/RPC, the Task Scheduler service itself records **Security log Event ID 4698 (a scheduled task was created)** and **`Microsoft-Windows-TaskScheduler/Operational` Event ID 106** when a new task registers. So instead of an odd name like `Updater` or `Maintenance`, the key is masquerading — matching the names and folder structure of existing legitimate Microsoft or Chrome/Edge update tasks.

### [Part 1 summary] User-Land persistence comparison

| Technique | Privilege | Trigger | Main artifacts | Stealth |
| --- | --- | --- | --- | --- |
| **Registry Run Keys** (`HKCU\...\Run`) | Standard user | At user login (when `explorer.exe` starts) | Registry value change (Sysmon ID 13); exposed in Task Manager "Startup" tab | ★★☆☆☆ (very common and well known; must combine with DLL side-loading) |
| **Startup Folder** (`...\Programs\Startup`) | Standard user | At user login | `.lnk` or file creation in the folder (Sysmon ID 11) | ★☆☆☆☆ (directly exposed on the filesystem; very high detection rate) |
| **Scheduled Tasks** | Standard user or admin | Time/periodic, idle, logon, startup, etc. | XML under `C:\Windows\System32\Tasks\`; Security Event ID 4698 / TaskScheduler ID 106 | ★★★☆☆ (very useful when created via COM/BOF and masqueraded as a legitimate task) |

---

<a id="advanced"></a>

# Advanced evasion persistence

User-land registration under Run keys or the Startup folder is easily exposed to a Blue Team scan (e.g. `Autoruns`). To evade static checks by AV/EDR, operators hijack the OS's own legitimate internal components or management features.

### 3.1 COM Hijacking (Component Object Model)

#### Core idea

Windows COM (Component Object Model) is the core architecture that lets software components talk to each other and share functionality. Many legitimate applications and system services call objects with a specific COM class ID (**CLSID**) when they run.

- **CLSID resolution order:** When Windows requests a COM object by CLSID, it **consults the current user's registry path `HKCU\Software\Classes\CLSID` before** the system-wide `HKCR (HKEY_CLASSES_ROOT)` or `HKLM`.
- **Hijacking structure:** If a legitimate program frequently calls a unique CLSID at boot or on a specific event, the operator manually creates `HKCU\Software\Classes\CLSID\{target-CLSID}\InprocServer32` (or `LocalServer32`) and sets its value to the path of a **malicious payload (or a side-loading DLL)** instead of the legitimate DLL.

```
[When a legitimate program runs]
       │
       ▼
[Calls a specific CLSID object] ──> [Searches HKCU (user registry) first] ──> [Finds the attacker's malicious DLL path]
                                                                                       │
                                                                                       ▼
                                                         [Malicious DLL force-loaded inside the legitimate program]
```

- **Choosing a target:** A good target is a COM object that a background app auto-started at login (e.g. a OneDrive settings utility, a taskbar notification program) tries and fails to load (`NAME NOT FOUND`) right after boot — the beacon revives naturally without crashing the system.

#### Detection

- **EDR mechanism:** Modern EDR monitors and blocks, in real time, the creation of new keys under `HKCU\Software\Classes\CLSID` or modification of a child `InprocServer32` value to point at an abnormal path (`.exe`, `.dll`) or a script handler.

### 3.2 WMI Event Subscription

#### Core idea

WMI (Windows Management Instrumentation) is a powerful built-in framework for querying and controlling management information. Its **event subscription** feature lets you auto-run a specified payload (Consumer) when a condition (Event) is met — "at a certain time" or "when a certain process runs."

- **Three core components of WMI persistence:**
    1. **`__EventFilter` (condition):** Defines which system event to react to (e.g. 180 minutes after boot, or when a certain admin tool runs).
    2. **`__EventConsumer` (action):** Defines **what to do** when the condition is met. Usually a `CommandLineEventConsumer` to quietly invoke a specified command or script.
    3. **`__FilterToConsumerBinding`:** Binds the filter and the consumer together.
- **Fileless storage:** WMI objects don't exist as `.exe` files on disk; they live inside the WMI repository database (`C:\Windows\System32\wbem\Repository\OBJECTS.DATA`). File-scan-based AV doesn't easily find them.

#### Detection

- **Local admin required:** Creating or modifying a WMI event subscription needs **local-admin (High Integrity) or SYSTEM** rights by default. (It can't be created with the standard-user rights you have right after initial access.)
- **DFIR strategy:** Enumerate all registered filters and consumers with PowerShell (`Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer`), or detect creation of a script-bearing WMI consumer via Sysmon Event ID 19, 20, 21 (WMI monitoring).

### 3.3 Windows Services

#### Core idea

Using a Windows service that runs continuously in the background is a traditional and reliable system-persistence technique.

- **Privilege and operation:** Registering a new service requires **local-admin or SYSTEM** rights. Once registered, it's started by `Scm.exe` (Service Control Manager) at boot (`Automatic` start type), regardless of whether a user logs in.
- **OPSEC:** Name and describe the new service like a legitimate Microsoft one (e.g. `Windows Update Medic Service`), and point its binary path (`BinPath`) at a disguised path and a DLL side-loading host.

### [Part 2 summary] Advanced evasion persistence comparison

| Technique | Privilege | Storage (artifacts) | AV/EDR detection difficulty | Notes / limits |
| --- | --- | --- | --- | --- |
| **COM Hijacking** | Standard user or admin | `HKCU\Software\Classes\CLSID\` | Moderate–High | Loads via a legitimate program even with no malicious file on disk. Requires analysis to choose a target CLSID. |
| **WMI Event Subscription** | Local admin required (High / SYSTEM) | WMI repository (`OBJECTS.DATA`) | High (fileless) | Hidden inside the DB rather than as a file, evading static scans. But admin rights are a prerequisite. |
| **Windows Services** | Local admin required (High / SYSTEM) | Registry `HKLM\SYSTEM\CurrentControlSet\Services\` | Low–Medium | Always runs at boot, but easily exposed in `Autoruns` or service tools, so masquerading is essential. |

---

<a id="part3"></a>

# System hooking, modifying existing resources & app-level persistence

Creating a new file or registry key is easily caught by security event logs and EDR. A skilled operator instead quietly **modifies** settings, shortcuts, services, or business apps that already exist on the system.

### 4.1 Tampering with existing shortcuts (`.lnk`) and `StartIn` directory hijacking

#### Why modifying beats creating

Creating a new `.lnk` in the Startup folder runs once at boot but is immediately caught by Blue Team monitoring (Sysmon Event ID 11). Modifying a browser (Chrome, Edge) or messenger (Teams, Slack) shortcut **already pinned to the desktop or taskbar** — which the victim clicks voluntarily every day — avoids the boot-time auto-run scan entirely.

- **Key target paths (standard-user writable):**
    - Desktop: `%USERPROFILE%\Desktop\`
    - Taskbar pinned icons: `%APPDATA%\Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar\`

```
[Two approaches to tampering with an existing .LNK, and the OPSEC difference]

Approach A: Directly altering the TargetPath (old approach — high detection risk ⚠️)
  • Before: "C:\Program Files\Google\Chrome\Application\chrome.exe"
  • After:  "C:\Windows\System32\cmd.exe /c start payload.exe && start chrome.exe"
  ▶ Problem: creates an explorer.exe -> cmd.exe process tree, a flashing black window, and EDR command-line detection.

Approach B: Altering the working directory (StartIn) + DLL side-loading (modern OPSEC ⭐)
  • TargetPath: "C:\...\App.exe" (kept as the original! no command-line change!)
  • StartIn   : "C:\Users\Victim\AppData\Local\CustomFolder\" (a folder hiding the attacker's DLL)
  ▶ How it works: when the victim clicks the icon, the legitimate App.exe runs and looks for its DLL
    first in CustomFolder (the current working directory), loading it from there.
```

#### Recent behaviour and constraints

1. **DLL search order and `SafeDllSearchMode`:** Since Windows XP SP2, all modern Win 10/11 have `SafeDllSearchMode` on by default. In this mode the current working directory (`StartIn`) is searched *after* the system folder (`System32`) — it's 5th in the order. So the `StartIn` trick only works if the target program tries to load a **uniquely named DLL that does not exist in `System32` (`NAME NOT FOUND`)**.
2. **Direct side-loading of `%LocalAppData%`-based apps (Teams, OneDrive, Slack, Discord):** Many enterprise apps now install to user-writable paths like `%LOCALAPPDATA%\Microsoft\OneDrive` or `%LOCALAPPDATA%\Discord` so they can update without admin rights. Here you don't even need to touch the `.lnk` — just drop a proxied malicious DLL inside the real install folder, and it loads from the 1st search path (the application folder) every time the user opens the app.

### 4.2 IFEO (`Image File Execution Options`) and `SilentProcessExit`

#### Core idea

**IFEO** is a Windows kernel/loader feature originally built so developers could tune an app's heap settings or attach a debugger at launch. **(Local admin required.)**

1. **Basic `Debugger` hooking:** Create a string value `Debugger` under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe` and set it to a payload path; when the user runs Notepad (`notepad.exe`), the kernel intercepts and runs the payload instead. (Notepad itself won't open, so the victim may notice — the payload has to re-launch Notepad.)
2. **Advanced `SilentProcessExit`:** A stealthier technique that runs the payload in the background via the Windows Error Reporting system (`werfault.exe`) not when the program *starts*, but when the user **finishes and closes it (on exit).**

```
[SilentProcessExit architecture and required registry settings]

[Setup: two registry keys (admin rights)]
  ① HKLM\...\Image File Execution Options\notepad.exe
     └─ GlobalFlag (DWORD) = 0x00000200 (enables the FLG_MONITOR_SILENT_PROCESS_EXIT bitmask)
  ② HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe
     ├─ ReportingMode (DWORD) = 1 (enables LAUNCH_MONITORPROCESS)
     └─ MonitorProcess (REG_SZ) = "C:\ProgramData\LegitUpdater\updater.exe"

[Trigger flow]
[Victim opens Notepad (notepad.exe) and works normally]
       │
       ▼
[Victim closes the Notepad window (ExitProcess / NtTerminateProcess)]
       │
       ▼
[Kernel checks GlobalFlag (0x200) and signals WerSvc (Windows Error Reporting service)]
       │
       ▼
[werfault.exe runs] ──> [reads the SilentProcessExit registry] ──> [quietly runs the payload in MonitorProcess]
```

#### Detection

- **Abnormal process lineage:** When `SilentProcessExit` fires, the parent is recorded as `svchost.exe (WerSvc)` or `werfault.exe` with the attacker's binary as a child. Modern EDR (CrowdStrike, MDE) treats the error-reporting utility `werfault.exe` spawning a non-standard-path executable or shell as an immediate IoC.
- **DFIR rule:** Monitor `Debugger`/`GlobalFlag` changes under `Image File Execution Options` and `SilentProcessExit` key creation via Sysmon Event ID 12, 13.

### 4.3 Winlogon Helper and the death of legacy techniques (`AppInit_DLLs`)

#### Winlogon Helper (`Shell`, `Userinit`, `Notify`)

The registry (`HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`) that `winlogon.exe` references to initialise the session at login. **(Local admin required.)**

- **`Userinit`:** Append an executable path after the default `C:\Windows\system32\userinit.exe,` (comma-separated) to run it in sequence at logon.
- **`Shell`:** Specify a program to run alongside the default `explorer.exe`.
- **`Notify` (dead — version note ❌):** The famous old technique of registering a DLL under `Winlogon\Notify` to intercept logon events worked on Windows XP/Server 2003, but **since Windows Vista/7 and on all current Win 10/11 the architecture changed and the `Notify` key was removed entirely — it never works.**

#### [Essential update] Why `AppInit_DLLs` no longer works on current Win 10/11

`AppInit_DLLs`, introduced as a persistence technique in many older security texts, was a powerful feature: write a DLL path to the registry (`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs`) and that DLL is force-injected into nearly every process that loads `user32.dll`.

> **Why it fails today (tied to UEFI Secure Boot):**
> To stop indiscriminate DLL injection, from Windows 8 and Win 10/11 Microsoft patched it so that **if UEFI Secure Boot is enabled, the OS kernel unconditionally ignores and disables `AppInit_DLLs` even when `LoadAppInit_DLLs` is set to `1`.** Since **Windows 11 requires UEFI Secure Boot as a minimum install requirement**, the `AppInit_DLLs` technique is effectively **dead** in a modern enterprise environment.

### 4.4 Modifying existing Windows services and `svchost.exe` ServiceDll hijacking

Part 2 covered *creating* a new service. But creating one leaves a System Event ID 7045 log and is easily caught, so an operator with local-admin rights prefers to **modify an existing service.**

#### Mechanism 1: Altering the `ImagePath` of an inactive default service

Find a service that ships with Windows but is normally stopped (Disabled/Manual) — e.g. `Fax`, `Spooler`, or an old third-party service — switch its start type to `Auto`, and replace its registry `ImagePath` with the attacker's service binary. This avoids the new-service-creation log (ID 7045).

#### Mechanism 2: `ServiceDll` hijacking of `svchost.exe`-based services (advanced stealth ⭐)

Many default Windows services exist as `.dll`s hosted inside the system process **`svchost.exe -k <group>`** rather than as individual `.exe`s.

- **Registry structure:**
    - `HKLM\SYSTEM\CurrentControlSet\Services\<service>\ImagePath` → `%SystemRoot%\System32\svchost.exe -k netsvcs`
    - `HKLM\SYSTEM\CurrentControlSet\Services\<service>\Parameters\ServiceDll` → **this defines the actual DLL to load**
- **Stealth effect:** If the attacker builds a malicious DLL implementing the service entry (`ServiceMain`) and swaps an existing service's `Parameters\ServiceDll` for it, no suspicious separate `.exe` process appears in Task Manager or the process list — it runs **hidden as a thread inside the legitimate system process `svchost.exe`.**
- **Win 10/11 mitigation (signature):** Microsoft has started applying a **"Microsoft Signed Only" mitigation** to major system `svchost.exe` processes. Putting an unsigned `ServiceDll` into a core security group's `svchost` can be blocked (Event ID 7023 and CodeIntegrity logs), so targeting must shift to ordinary service groups or third-party services without the signing policy.

### 4.5 Application and modern dev-environment persistence (2025~2026 trends)

Techniques that, without admin rights, tamper with the config files of business/dev apps that security tools rarely watch.

#### ① Microsoft Office persistence (Word, Excel, COM Add-ins)

| Technique | Target path / registry (standard user) | Mechanism and constraints |
| --- | --- | --- |
| **Excel `XLSTART`** | `%APPDATA%\Microsoft\Excel\XLSTART\` | Auto-loads `.xlam`, `.xll` in the folder when Excel starts. |
| **Word `STARTUP`** | `%APPDATA%\Microsoft\Word\STARTUP\` | Auto-loads a global template (`.dotm`) or Word add-in (`.wll` — essentially a DLL) in the folder without warning when Word starts. |
| **Office COM Add-in registry** | `HKCU\Software\Microsoft\Office\<ver>\<app>\Addins\<CLSID>` | Set `LoadBehavior` to `3` (auto-load at startup) to attach a COM DLL. (Note: if an add-in takes ~1s+ to load, Office flags it as a "slow add-in", notifies the user, and moves it to `Resiliency\DisabledItems` — so the payload must return immediately on an async thread.) |

#### ② PowerShell profile (`$PROFILE`) injection

An init script that runs automatically whenever an admin or developer launches PowerShell. The file doesn't exist by default, but creating it at the path makes it work immediately.

| Profile | Variable | Filesystem path | Privilege |
| --- | --- | --- | --- |
| Current user / current host | `$PROFILE.CurrentUserCurrentHost` | `%USERPROFILE%\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1` (PowerShell 7+: `\Documents\PowerShell\...`) | Standard user |
| Current user / all hosts | `$PROFILE.CurrentUserAllHosts` | `%USERPROFILE%\Documents\WindowsPowerShell\profile.ps1` | Standard user |
| All users / all hosts | `$PROFILE.AllUsersAllHosts` | `$PSHOME\profile.ps1` (`C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1`) | Admin |

- **Constraint:** In an enterprise where PowerShell is forced into Constrained Language Mode (CLM) via WDAC/AppLocker, or the `ExecutionPolicy` is pinned to `AllSigned` by GPO, profile-script execution is blocked.

#### ③ Modern dev tools: Windows Terminal & VS Code (current trend ⭐)

A popular user-land technique when targeting IT/cloud-engineer/developer machines.

- **Windows Terminal (`settings.json`):** The settings file of Windows 11's default terminal (`%LOCALAPPDATA%\Packages\Microsoft.WindowsTerminal_...\LocalState\settings.json`) is standard-user writable. Appending a background-payload argument to a profile's `"commandline": "powershell.exe"` runs it each time the user opens the terminal.
- **Visual Studio Code (`tasks.json` & extensions):** Putting `"runOptions": { "runOn": "folderOpen" }` with a shell command in a project's `.vscode\tasks.json` auto-runs a background task the moment the developer opens that folder in VS Code. (Recent VS Code patches prompt for "allow automatic tasks" on first open, but it works smoothly in an already-trusted workspace.)

### 4.6 Account manipulation (RID Hijacking) and SDDL backdoors

#### RID Hijacking

Running `net user hacker /add` and `net localgroup administrators hacker /add` from the command line raises Windows Security Event ID 4720 and 4732 and is caught by the SOC 100% of the time.
To avoid this, the attacker (SYSTEM rights needed) overwrites the byte that defines the RID inside the binary `F` value of the registry `HKLM\SAM\SAM\Domains\Account\Users\000001F5` (`1F5` = decimal 501, i.e. the built-in **Guest account**) — changing `F5 01` to `F4 01` (decimal 500 = built-in Administrator).

- **Effect:** `net user guest` or Control Panel still shows a plain, unprivileged `Guest` account, but when you actually log in with it, the kernel recognises the RID as `500` and grants a **full local Administrator token.**

#### Service and registry SDDL (security descriptor) backdoor

When admin rights are held briefly, instead of planting a malicious file now, modify the ACL/SDDL of a specific system service (e.g. the Remote Registry service) or registry key to grant "Full Control" to a standard-user account too. Even if the admin password changes later and access is lost, logging in as the standard user and manipulating the now-open service acts as a "privilege backdoor" to recover `SYSTEM` at any time.

---

## [Final summary] Blue Team / DFIR persistence hunting checklist

| Layer | Techniques addressed | Actionable detection |
| --- | --- | --- |
| Registry & startup | Run/RunOnce keys, Startup folder, COM hijacking, Office add-ins, IFEO | Monitor writes to `CurrentVersion\Run`, `HKCU\Software\Classes\CLSID\...\InprocServer32`, `Image File Execution Options` (`Debugger`/`GlobalFlag`), `SilentProcessExit` (Sysmon ID 12/13). Alert on file creation in Startup / `XLSTART` / `Word\STARTUP` (Sysmon ID 11). |
| Scheduled tasks & WMI | Scheduled Tasks, WMI event subscription | Security Event ID 4698 + TaskScheduler ID 106 for task creation. Sysmon ID 19/20/21 for WMI subscriptions; periodically enumerate `root\subscription` consumers. |
| Services & accounts | New/modified services, ServiceDll hijacking, RID hijacking, SDDL backdoor | System Event ID 7045 (new service) / 7023 + CodeIntegrity (blocked unsigned ServiceDll). Watch `Services\...\Parameters\ServiceDll` changes. Audit SAM `F`-value edits and service/registry ACL (SDDL) changes. |
| Dev-tool / user-land | LNK tampering, PowerShell profile, Windows Terminal, VS Code | Baseline and monitor `.lnk` `StartIn`/working-directory changes, `$PROFILE` script creation, `settings.json`/`.vscode\tasks.json` edits on engineer workstations. |

---

*This page is a personal reference re-organised from CRTO study notes, for Blue Team / DFIR learning (detection and defence).*
