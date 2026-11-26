---
title: "Handling Suspect Files Safely — Analysis Environment, Moving Malware, and the Dangerous File Types (Executables, Scripts, Office Documents)"
tags:
  - training
  - blue-team
  - files
  - file-analysis
  - malware-triage
  - phishing
---

# Handling Suspect Files Safely — Analysis Environment, Moving Malware, and the Dangerous File Types { #safe-handling-file-types }

!!! abstract "What this page covers"
    Knowing **what** a file is (previous pages) is only half the job. The other half is deciding whether it is dangerous **without hurting yourself or anyone else on the way**. This page starts with the rules for a safe analysis setup — a machine you can afford to lose, a network nothing important shares, a hardened host OS, a snapshot-and-revert virtual machine, and the trick of analysing a file on an operating system that **can't run it**. Then we move files the industry-standard way (an encrypted ZIP with the password `infected`) and read every line of the commands and their output, including what that ZIP still leaks. After that we survey which file types attackers weaponise and go deep on the first three families: **executables** (the whole PE family — `.scr`, `.cpl`, `.dll`, `.sys`, `.ocx` and friends — plus installers, self-extracting archives and Java `.jar`), **scripts** (`.ps1`, `.vbs`, `.js`, `.wsf`, `.hta`, `.bat`, shell, Python) and **Microsoft Office documents** (links, embedded objects, exploits and macros; the old binary format vs the ZIP-based format; and the 2022 change that blocks macros in files from the internet). For each family you get what it looks like on disk, what it looks like in a process-creation log when it runs, the matching ATT&CK techniques, and how a SOC catches it. Practice questions with explanations at the end.

!!! note "Labels"
    **[Supplement]** = practical material you need to know, **[Correction]** = a commonly repeated claim that is wrong or outdated, **[Changed]**/**[Caution]** = what has changed recently and what is risky to do the old way. Hostnames, domains, accounts, IPs, file names and hashes are invented for illustration (`.example`, documentation and private IPs). No working malicious code appears on this page: script and macro samples are deliberately incomplete, defanged fragments that show what a defender looks for.

## The 8 key points { #key-points }

1. **Never analyse on a machine or network you care about.** Use a system you can afford to lose, isolated from production, with a hardened host OS and the suspect file inside a **virtual machine**: snapshot → copy file in → analyse → **revert**.
2. **Mismatch the operating system.** A Windows `.exe`, `.vbs`, `.bat` or macro document can't run on Linux, and an ELF or bash script means nothing to Windows. For cross-platform formats (PDF, JavaScript) Linux is still the safer default, because the payload at the end of the chain almost always targets Windows. Exception: you run the file **on purpose** in dynamic analysis.
3. **Move suspect files only inside an encrypted ZIP with the password `infected`.** It stops accidental execution, stops antivirus from deleting your evidence, and warns whoever finds it later. Classic ZIP encryption **still shows the file names**; a `.7z` with header encryption hides them.
4. **Almost any file type can be weaponised**, but four families do most of the damage: executables, scripts, documents, and "other" (shortcuts, images, fonts, email files).
5. **"Executable" is not just `.exe`.** `.scr`, `.cpl`, `.dll`, `.ocx`, `.sys`, `.drv`, `.efi`, `.ax`, `.acm`, `.mui`, `.tsp` all share the `MZ`/PE format. Installers (`.msi`, `.msp`), self-extracting archives and Java `.jar` files run code too. Block and inspect by **true type**, not by extension.
6. **Scripts are as dangerous as executables** and slip through filters more easily: Windows runs `.js`, `.vbs` and `.wsf` natively through `wscript.exe`/`cscript.exe` and `.hta` through `mshta.exe`, they are trivial to obfuscate, and application-control rules often ignore them.
7. **Office documents attack in four ways:** a lure link, an embedded file, an exploit against Office itself, or a macro. The old binary formats (`.doc`, `.xls`) hide macros without any name change; the new ZIP formats signal macros with an `m` (`.docm`, `.xlsm`) and keep them in `vbaProject.bin`.
8. **Office now blocks VBA macros in files from the internet by default** (Mark of the Web). Attackers moved to containers, shortcuts, HTML smuggling and other formats — so the file-type game is not over, it has moved.

## Why this matters in a SOC { #why }

An alert lands: the email gateway released `Remittance_Nov.doc` to three people in finance, and one of them opened it. Your EDR has the file. Within minutes you will be asked "is it bad?", "what does it do?", "who else got it?". To answer, you need a copy in front of you, and that is exactly the moment analysts infect themselves — double-clicking "just to see", dragging it to the team share where antivirus deletes it (and your evidence), or opening it on a laptop that is joined to the domain.

There are two questions on this page. **Where and how do I touch this file safely?** And **which kinds of file should make me nervous, and why?** The second question matters well beyond analysis: the same knowledge is how you write email-gateway rules, proxy blocks, application-control policies and detections for process creation.

## Choosing a safe analysis environment { #safe-environment }

Think of a suspect file as a sealed jar that may hold something infectious. You don't open it on the kitchen table. You open it in a lab, behind glass, in a room you can disinfect afterwards — and ideally you study it with tools that the bug inside can't infect at all. The four rules below are that lab.

### Rule 1 — a system you can afford to lose { #rule-lose }

Never analyse on your daily workstation. Malware may encrypt files, steal browser sessions and saved passwords, or install a backdoor, and your daily workstation has exactly the things an attacker wants: your email, VPN, admin consoles and cached credentials. The analysis machine must hold **nothing** you would mind being stolen or destroyed. If the worst happens, you wipe it and lose nothing.

### Rule 2 — a disconnected or separate network { #rule-network }

Malware scans, spreads and phones home. If the analysis machine sits on the corporate LAN, a worm-like sample can reach file servers and domain controllers, and a beacon tells the attacker that someone is examining their tool. So the analysis system is either **fully disconnected** or on its own network segment with nothing you care about (and no route to production). [Supplement] When you need to watch network behaviour, analysts use a **host-only** virtual network plus a fake-internet service (for example INetSim or FakeNet-NG) that answers DNS and HTTP locally, so the sample "connects" and reveals its URLs without ever reaching the real internet.

### Rule 3 — a hardened host operating system { #rule-host }

The host (the physical machine running the virtual machines) is your last wall. Keep it patched, minimal and hardened. Linux is a common choice for the host because most malware you will see targets Windows. Purpose-built distributions exist: [Supplement] **REMnux** (a Linux toolkit for static analysis, network emulation and document analysis) and **FLARE-VM** (a set of analysis tools installed onto a Windows VM) are the usual pair.

### Rule 4 — analyse inside a virtual machine, snapshot and revert { #rule-vm }

A **snapshot** is a saved copy of the whole VM state (disk, and optionally memory). The workflow is always the same: take a clean snapshot, copy the sample in, analyse, then **revert** to the snapshot so every change the malware made disappears.

Here is what that looks like with VirtualBox's command-line tool on the host. The VM is called `win10-analysis`.

```
$ VBoxManage snapshot win10-analysis take clean-2026-11 --description "patched, tools installed, no network"
0%...10%...20%...30%...40%...50%...60%...70%...80%...90%...100%
Snapshot taken. UUID: 6a1f2c4e-0b7d-4e55-9a10-3c2b8d7e9f01

$ VBoxManage snapshot win10-analysis list
   Name: clean-2026-11 (UUID: 6a1f2c4e-0b7d-4e55-9a10-3c2b8d7e9f01) *

$ VBoxManage controlvm win10-analysis poweroff
0%...10%...20%...30%...40%...50%...60%...70%...80%...90%...100%

$ VBoxManage snapshot win10-analysis restore clean-2026-11
Restoring snapshot 'clean-2026-11' (6a1f2c4e-0b7d-4e55-9a10-3c2b8d7e9f01)
0%...10%...20%...30%...40%...50%...60%...70%...80%...90%...100%
```

Line by line:

- `VBoxManage snapshot win10-analysis take clean-2026-11 --description "..."` — saves the current state of the VM under the name `clean-2026-11`. Take it **before** the sample ever touches the VM. The description records what "clean" means (patched, tools installed, network off), which matters months later when you wonder whether to trust it.
- The percentage bar and `Snapshot taken. UUID: ...` — the snapshot finished and got a unique ID.
- `snapshot ... list` — shows the snapshots. The `*` marks the one the VM is currently based on.
- `controlvm ... poweroff` — after the analysis, power the VM off hard. Don't shut down gracefully from inside: you don't want to give the malware a clean shutdown in which to write anything.
- `snapshot ... restore clean-2026-11` — throws away every change since the snapshot. The VM is back to clean.

On a KVM/libvirt host the same idea is `virsh snapshot-create-as win10-analysis clean-2026-11` and `virsh snapshot-revert win10-analysis clean-2026-11`.

!!! warning "[Caution] The VM is a wall, not a vault"
    VM escapes are rare but real, and convenience features punch holes in the wall. On the analysis VM turn off **shared folders**, **shared clipboard**, **drag-and-drop** and USB pass-through, don't mount host drives, and don't log in to anything real from inside it. Some malware also checks whether it is in a VM and behaves innocently if so — a clean result in a VM is not proof of innocence.

### Analyse on an OS that can't run the file { #os-mismatch }

The best way not to get infected is to look at the file on a system where its code **cannot run at all**. A Windows PE file, a VBScript, a batch file or an Office macro does nothing on Linux: there is no Windows loader, no `wscript.exe`, no Word. You can run `file`, `strings`, a hex viewer, `olevba` and friends on it in complete safety. The reverse also works: an ELF binary or a bash script is just bytes to Windows.

| Suspect file | Runs natively on | Safer place to inspect it | Why |
| --- | --- | --- | --- |
| `.exe`, `.dll`, `.scr`, `.cpl`, `.sys` | Windows | Linux | No PE loader on Linux |
| `.vbs`, `.js` (WSH), `.wsf`, `.hta`, `.bat` | Windows | Linux | No Windows Script Host, `mshta` or `cmd.exe` |
| `.doc`/`.docm`/`.xls` with macros | Windows/macOS Office | Linux (no Office) | No VBA engine |
| `.ps1` | Windows, and **Linux/macOS with PowerShell 7** | Linux **without** `pwsh` installed | PowerShell is cross-platform now |
| ELF, `.sh` | Linux | Windows (or a different Linux VM) | No ELF loader; no bash by default |
| PDF, JavaScript for browsers/Node | Everywhere | Linux | The payload it fetches is almost always Windows-only |

The last row deserves a word. A PDF or a piece of JavaScript can be dangerous everywhere, because PDF readers and browsers run on every OS. Linux is still the better choice, for two reasons. First, the attacker almost always assumes the victim runs Windows, so the exploit's shellcode, or the file it downloads and runs, is Windows code: on Linux the chain breaks. Second, writing an exploit that works across operating systems **and** across the different PDF readers each OS uses is hard. Hard, not impossible — so you still follow rules 1–4.

[Correction] "PowerShell can't run on Linux" is no longer true. PowerShell 7 (`pwsh`) runs on Linux and macOS. A `.ps1` aimed at Windows will mostly fail there (no `Add-Type` against Windows DLLs, no registry, no WMI), but simple download-and-run logic can work. Don't install `pwsh` on the inspection box, or treat `.ps1` as "runs here".

### Static vs dynamic, one more time { #static-dynamic }

Everything above is about **static analysis**: looking at a file without running it. Sometimes you need **dynamic analysis**: running it on purpose to watch what it does. Then the OS mismatch is reversed — you need a Windows VM to detonate a Windows sample — and rules 1–4 carry all the weight. Most SOCs hand that job to a **sandbox** (see [Screenshots, sandboxes and when to go manual](../http-analysis/screenshots-sandboxes.md)) and keep manual detonation for analysts with a proper lab.

## Moving suspect files safely { #moving-files }

Sooner or later you must move a sample: from the EDR's quarantine to your analysis box, from a colleague to you, from your box to a reverse engineer. Plain copy-and-paste, drag-and-drop or `copy` on the command line is the wrong way, for three reasons:

1. **Accidental execution.** One mistyped tab-completion (`./invoice` + Tab + Enter), one double-click on the wrong icon in a crowded Downloads folder, and it runs on the new machine.
2. **Antivirus deletes it.** The receiving machine's AV or EDR sees a known-bad file arrive, quarantines or deletes it, and raises a fresh alert — now someone else is investigating *you*, and your evidence is gone.
3. **Someone finds it later.** A file called `invoice.pdf.exe` left on a share or in an email thread looks like an invoice to the next person.

The industry-standard fix is a password-protected, encrypted ZIP with the password **`infected`**. It looks odd the first time, but it is a convention every malware analyst, sandbox and sample-sharing site understands: anyone who sees "password: infected" knows the content is dangerous. Encryption means antivirus can't see inside to delete it, and no one can run it by accident because it has to be extracted first. The convention applies to anything that may carry malicious content — executables, documents, scripts, PCAPs and memory images.

Here is the full routine on the analysis box. `7z` is the 7-Zip command-line tool.

```
$ sha256sum Remittance_Nov.doc
3b9e1f6c0d2a47e8b5c1f9a0e7d4c3b2a1908f7e6d5c4b3a2918f7e6d5c4b3a2  Remittance_Nov.doc

$ 7z a -tzip -pinfected -mem=AES256 Remittance_Nov.zip Remittance_Nov.doc

7-Zip 23.01 (x64) : Copyright (c) 1999-2023 Igor Pavlov : 2023-06-20

Scanning the drive:
1 file, 48128 bytes (47 KiB)

Creating archive: Remittance_Nov.zip

Add new data to archive: 1 file, 48128 bytes (47 KiB)

Files read from disk: 1
Archive size: 22650 bytes (23 KiB)
Everything is Ok

$ 7z l -slt Remittance_Nov.zip | grep -E "^(Path|Encrypted|Method|Size)"
Path = Remittance_Nov.zip
Path = Remittance_Nov.doc
Size = 48128
Encrypted = +
Method = AES-256 Deflate
```

Line by line:

- `sha256sum Remittance_Nov.doc` — hash the file **before** packing. The hash is the file's fingerprint; you record it in the ticket so everyone can confirm later that the sample wasn't changed and so you can look it up without sharing the file. (Hashes get their own page later in this section.)
- `7z a` — `a` means "add to archive".
- `-tzip` — make a `.zip` (rather than 7-Zip's own `.7z` format), because every tool and every colleague can open it.
- `-pinfected` — set the password to `infected`. There's no space between `-p` and the password.
- `-mem=AES256` — use AES-256 encryption. Without this, ZIP uses the old **ZipCrypto** scheme, which is weak; some sandboxes and sharing sites still use ZipCrypto for compatibility, but AES is better when you control both ends.
- `Remittance_Nov.zip Remittance_Nov.doc` — the archive to create, then the file to put in it.
- `Scanning the drive: 1 file, 48128 bytes` → `Archive size: 22650 bytes` → `Everything is Ok` — 7-Zip found one file of 47 KiB, compressed it to about 23 KiB, and finished without errors.
- `7z l -slt` — list the archive's contents with technical details; `grep` keeps the interesting fields.
- `Path = Remittance_Nov.doc` — **the file name is visible without the password.** In the ZIP format only the file *contents* are encrypted; names, sizes and dates sit in plaintext headers. That is usually fine (it helps people know what they've received) but matters if the name itself is sensitive, for example a victim's name in the file name.
- `Encrypted = +` and `Method = AES-256 Deflate` — confirms the content is encrypted with AES-256 and compressed with Deflate.

If you need the names hidden too, use the 7z format with header encryption:

```
$ 7z a -t7z -pinfected -mhe=on case-2026-1142.7z Remittance_Nov.doc
$ 7z l case-2026-1142.7z
...
Enter password (will not be echoed):
```

`-mhe=on` ("header encryption on") encrypts the file list as well, so even listing the archive asks for the password.

[Supplement] Good habits around the ZIP:

- **Defang the name inside the archive** when you can: `Remittance_Nov.doc_` or `3b9e1f6c....bin` won't open on a double-click even after extraction.
- **Write the hash in the ticket and in a text note next to the archive**, never inside an email body that might be auto-scanned and quarantined.
- **Some email gateways block or strip encrypted archives** precisely because attackers also send password-protected ZIPs to evade scanning. Use your case-management system, a secure file share or the sandbox's own transfer, not email.
- **Extract only on the analysis box**, and verify the hash after extraction: `sha256sum` should print the same value you recorded.

## Which file types are dangerous? { #dangerous-types }

The honest answer is "almost all of them, under the right conditions". Any program that **parses** a file can have a bug, and a crafted file can exploit that bug. But some file types are dangerous **by design** (they are code), others are dangerous because of **features** (macros, embedded objects, links), and others need a **vulnerability** in the program that opens them. That difference tells you how easy each is to weaponise.

| Family | Examples | Why it is dangerous | How hard to weaponise |
| --- | --- | --- | --- |
| Executables | Windows PE (`.exe`, `.dll`, `.scr`, `.cpl`, `.sys`...), installers, Linux ELF | They *are* code. The OS runs them | Trivial |
| Scripts | OS-specific: bash, batch, VBScript, Office macros. Multi-platform: JavaScript, Python, PowerShell | They *are* code, run by an interpreter that is already installed | Trivial |
| Documents | Office, RTF, PDF | Features that run code, embed files or point to outside content, plus exploits against the reader | Easy to moderate |
| Other | Shortcuts (`.lnk`), icons, images, video, fonts, email files | Need a parser bug or a feature abuse, and usually user help | Harder |

The rest of this page covers the first three families in depth. RTF, PDF and the "other" files come on the next page.

## Executables { #executables }

### "Executable" is a format, not an extension { #pe-family }

Everybody blocks `.exe`. Many fewer people know that a whole family of Windows files are the **same format** — the Portable Executable (**PE**) format, starting with the `MZ` magic bytes you met on [Identifying Files](file-identification.md) — and are just as capable of running code. The extension only tells Windows *which program to hand the file to*. The bytes inside are a program either way.

| Extension | What it is | How it gets run | ATT&CK |
| --- | --- | --- | --- |
| `.exe` | Normal program | Directly by the OS | T1204.002 User Execution: Malicious File |
| `.dll` | Library of functions for other programs | `rundll32.exe`, `regsvr32.exe`, or loaded by a program (side-loading) | T1218.011 Rundll32, T1218.010 Regsvr32, T1574.002 DLL Side-Loading |
| `.scr` | Screen saver | **Double-click runs it like an `.exe`**; also set as the screen saver | T1546.002 Screensaver |
| `.cpl` | Control Panel item (a DLL) | Double-click → `control.exe` → `rundll32.exe` | T1218.002 Control Panel |
| `.ocx` | ActiveX control (a DLL) | Registered with `regsvr32.exe`, loaded by apps | T1218.010 |
| `.sys`, `.drv` | Kernel or device driver | Installed as a service, runs in the kernel | T1543.003 Windows Service, T1068 (vulnerable drivers) |
| `.efi` | UEFI application/boot loader | Run by firmware before Windows starts | T1542 Pre-OS Boot |
| `.ax` | DirectShow filter (a DLL) | Loaded by media apps | — |
| `.acm` | Audio compression manager codec (a DLL) | Loaded by audio stack | — |
| `.mui` | Language resource file (PE) | Loaded for UI text; can be side-loaded | — |
| `.tsp` | Telephony service provider (a DLL) | Loaded by the telephony service | — |
| `.com` | Old DOS command file; on modern Windows often a renamed PE | Run directly, and **found before `.exe` in `PATHEXT`** | T1036 Masquerading |

[Supplement] `.fon` (old bitmap font) files also carry an `MZ` header (they use the older 16-bit "NE" layout), which is why they sometimes appear on "dangerous extension" lists. They are rarely abused today, but they are a good reminder that `MZ` turns up in surprising places.

Why does `.scr` work as an attack? Because for Windows a screen saver is simply a program with a different extension, and double-clicking it runs it. `Holiday_Photos.scr` with an image icon looks harmless to a user who has file extensions hidden. And why `.cpl`? Because many gateways that block `.exe` and `.dll` don't know the extension at all.

What does this look like on the analysis box? Rename doesn't change the bytes, and `file` reads the bytes:

```
$ file holiday_photos.scr invoice_view.cpl vidfilter.ax netcard.sys
holiday_photos.scr: PE32 executable (GUI) Intel 80386, for MS Windows, 4 sections
invoice_view.cpl:   PE32+ executable (DLL) (GUI) x86-64, for MS Windows, 6 sections
vidfilter.ax:       PE32+ executable (DLL) (GUI) x86-64, for MS Windows, 5 sections
netcard.sys:        PE32+ executable (native) x86-64, for MS Windows, 7 sections
```

- `holiday_photos.scr: PE32 executable (GUI) Intel 80386` — a 32-bit Windows GUI program. The "screen saver" is a normal executable.
- `invoice_view.cpl: PE32+ executable (DLL)` — a 64-bit DLL. That's exactly what a Control Panel item is.
- `vidfilter.ax: ... (DLL)` — a DLL wearing a DirectShow extension.
- `netcard.sys: ... (native)` — the `native` subsystem means it runs outside the normal Windows user-mode environment: a kernel driver.

The lesson for gateways and proxies: **block or inspect on the true type** (`MZ` header / PE structure), not on a list of extensions. Most modern secure email gateways and proxies can do this ("true file type" detection); make sure that option is on.

### What it looks like when it runs { #pe-in-logs }

Let's say a user double-clicks `invoice_view.cpl` from Downloads. On Windows, with process-creation auditing on, you get **Event ID 4688** ("A new process has been created") in the Security log. It fires every time a process starts, and attackers care about it because it records *what ran, with which command line, started by what* — the very trail they want to avoid. (Full field-by-field coverage is on [Process creation events](../important-events/process-creation.md).)

```xml
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2026-11-20T23:41:07.5521337Z" />
    <Computer>FIN-WS-0117.corp.example</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserName">j.kim</Data>
    <Data Name="SubjectDomainName">CORP</Data>
    <Data Name="NewProcessId">0x1f3c</Data>
    <Data Name="NewProcessName">C:\Windows\System32\rundll32.exe</Data>
    <Data Name="TokenElevationType">%%1938</Data>
    <Data Name="ProcessId">0x22a8</Data>
    <Data Name="CommandLine">"C:\Windows\System32\rundll32.exe" Shell32.dll,Control_RunDLL "C:\Users\j.kim\Downloads\invoice_view.cpl",</Data>
    <Data Name="ParentProcessName">C:\Windows\System32\control.exe</Data>
    <Data Name="MandatoryLabel">S-1-16-8192</Data>
  </EventData>
</Event>
```

- `EventID 4688` — a process started.
- `Computer FIN-WS-0117.corp.example` — a finance workstation.
- `SubjectUserName j.kim` — the process runs as the user who double-clicked.
- `NewProcessName C:\Windows\System32\rundll32.exe` — the process that actually started is the **signed Windows** `rundll32.exe`, not the `.cpl`. That's the point of the technique: the malicious DLL runs **inside** a trusted binary, so a naive "alert on unsigned processes" rule sees nothing.
- `CommandLine ... Shell32.dll,Control_RunDLL "C:\Users\j.kim\Downloads\invoice_view.cpl",` — this is the giveaway. `Control_RunDLL` is how Control Panel loads a `.cpl`, and the `.cpl` path is in the user's **Downloads** folder. Real Control Panel items live in `System32`.
- `ParentProcessName C:\Windows\System32\control.exe` — the double-click went to Control Panel first, which then started `rundll32`.
- `TokenElevationType %%1938` — a limited (non-elevated) token, and `MandatoryLabel S-1-16-8192` — **medium** integrity: normal user rights. No UAC prompt was needed.

A detection worth having: `rundll32.exe` whose command line contains `Control_RunDLL` (or a `.cpl`) with a path under `\Users\`, `\Temp\` or `\Downloads\`. The same pattern applies to `regsvr32.exe` loading a DLL or `.ocx` from a user-writable folder.

### Installers, self-extracting archives and Java { #installers-sfx-jar }

Other formats also execute code without being PE files themselves, or by wrapping a PE file:

- **`.msi` and `.msp` — Windows Installer packages and patches.** An MSI is an OLE compound file (magic bytes `D0 CF 11 E0`, the same container as old Office files) holding a database of install actions. It is run by `msiexec.exe`, and a "custom action" in it can run any embedded program or script. Attackers like MSIs because users expect installers to ask for admin rights. ATT&CK: **T1218.007 System Binary Proxy Execution: Msiexec**. In logs, watch for `msiexec.exe` with `/i` or `/q` pointing at a URL or a user folder, and child processes of `msiexec.exe` that are shells.
- **Self-extracting archives (`.sfx`, `.sea`, and many `.exe`s).** A small unpacker program with an archive glued on the end — exactly the "nested file" pattern from [Identifying Files](file-identification.md#nested-files). Running it unpacks the archive and can then run a file from it. `file` usually reports just "PE32 executable"; a signature scan (`binwalk`) finds the archive inside. `.sea` is the old Mac "self-extracting archive" name; both have been used for spam.
- **`.jar` — Java archives.** A ZIP (magic `PK\x03\x04`) containing compiled Java classes and a `META-INF/MANIFEST.MF` that names the class to start. Not a native executable — it runs inside the Java virtual machine — but with Java installed, a double-click runs it with the user's full rights.

```
$ unzip -l shipping_label.jar
Archive:  shipping_label.jar
  Length      Date    Time    Name
---------  ---------- -----   ----
       84  2026-11-18 09:12   META-INF/MANIFEST.MF
     3120  2026-11-18 09:12   com/label/Main.class
    15872  2026-11-18 09:12   com/label/res/d.bin
---------                     -------
    19076                     3 files

$ unzip -p shipping_label.jar META-INF/MANIFEST.MF
Manifest-Version: 1.0
Main-Class: com.label.Main
```

- `unzip -l` lists the archive without extracting it. Three entries.
- `META-INF/MANIFEST.MF` — the manifest; every runnable JAR has one.
- `com/label/Main.class` — compiled Java code.
- `com/label/res/d.bin` — a 15 KB "resource" with a meaningless name. Code plus an opaque blob is a classic loader shape: the class decrypts or unpacks the blob. A shipping label has no reason to contain either.
- `unzip -p ... MANIFEST.MF` prints one file to the screen. `Main-Class: com.label.Main` tells Java which class to start when the JAR is double-clicked.

[Supplement] On Linux and macOS the "executables" are **ELF** (`\x7fELF`) and **Mach-O** files, plus shared libraries (`.so`, `.dylib`). They matter for servers and developer laptops; the same "true type, not extension" rule applies.

### Executables as exploits for the OS { #pe-exploits }

An executable can be malware in its own right, or it can be an **exploit** aimed at the operating system — for example a privilege-escalation tool that abuses a kernel bug, or a malicious or **vulnerable signed driver** (`.sys`) loaded to switch off security tools ("bring your own vulnerable driver", see [Privilege Escalation](../endpoint-attacks/privilege-escalation.md)). Either way, the file must first get onto the system and be run. That is what your email, proxy and application-control rules are trying to stop.

## Scripts { #scripts }

### Why attackers love scripts { #why-scripts }

A script is a text file of instructions that an **interpreter** (an already-installed program) reads and carries out. Anything an executable can do, a script can usually do too: download files, write to the registry, start processes, call Windows APIs. And scripts have extra advantages for the attacker:

- **They are lower profile.** Many filters treat text files more kindly than binaries. An organisation that blocks `.exe` and `.bat` may still let `.js`, `.vbs`, `.ps1` or `.py` through.
- **They are easy to obfuscate.** A script is text; it can be rewritten endlessly (string splitting, encoding, junk code) so that signature-based antivirus has nothing stable to match. Its basic actions — "download", "run" — use only ordinary built-in functions, so there's little that looks inherently evil.
- **Application control often ignores them.** Many allow-list policies cover `.exe` and `.dll` but not scripts, so a script can be an **application-control bypass** (see [Application control](../endpoint-defense/appcontrol-fim-persistence.md)).
- **Windows runs many of them on a double-click.** The Windows Script Host (`wscript.exe` for windowed, `cscript.exe` for console) runs `.js`, `.jse`, `.vbs`, `.vbe` and `.wsf` files natively. `mshta.exe` runs `.hta` (HTML applications). `cmd.exe` runs `.bat`/`.cmd`. No extra software needed.
- **They hide inside other formats.** Office macros are scripts (VBA). PDFs can carry JavaScript. HTML attachments carry JavaScript.
- **So delivery tends to succeed.** In kill-chain terms, scripts make the delivery stage easy compared with most alternatives.

| Extension | Interpreter (Windows) | Notes | ATT&CK |
| --- | --- | --- | --- |
| `.ps1` | `powershell.exe` / `pwsh.exe` | Double-click opens Notepad by default, so usually launched by something else | T1059.001 PowerShell |
| `.vbs`, `.vbe` | `wscript.exe` / `cscript.exe` | `.vbe` = encoded VBScript | T1059.005 Visual Basic |
| `.js`, `.jse` | `wscript.exe` / `cscript.exe` (JScript) | Not browser JavaScript: full access to the system through ActiveX objects | T1059.007 JavaScript |
| `.wsf` | `wscript.exe` / `cscript.exe` | XML wrapper that can mix VBScript and JScript | T1059.005 / T1059.007 |
| `.hta` | `mshta.exe` | HTML page with script and **no browser sandbox** | T1218.005 Mshta |
| `.bat`, `.cmd` | `cmd.exe` | Batch file | T1059.003 Windows Command Shell |
| `.sh` | `bash`/`sh` (Linux, macOS) | Shell script | T1059.004 Unix Shell |
| `.py`, `.rb`, `.pl` | Python, Ruby, Perl (if installed) | Common on Linux and developer machines | T1059.006 Python |

[Correction] A `.js` file on the desktop is **not** like JavaScript in a web page. In a browser, JavaScript lives in a sandbox and can't touch your files. Double-clicked on Windows, the same file is run by `wscript.exe` as JScript, with the user's full rights.

### What a malicious script looks like on disk { #script-on-disk }

To `file`, a script is just text — which is why "it's only a text file" is such a dangerous thought.

```
$ file invoice_2026.js
invoice_2026.js: ASCII text, with very long lines (4812), with no line terminators

$ head -c 300 invoice_2026.js
var _0x3f1a=['\x57\x53\x63\x72\x69\x70\x74','\x53\x68\x65\x6c\x6c','\x52\x75\x6e'];var q=
_0x3f1a[0]+'.'+_0x3f1a[1];var Zt="hxxps://cdn-assets[.]example/"+"s/"+"u.p"+"s1";/* ... */
```

(The sample is a defanged, cut-down fragment written for this page; it does nothing.)

- `ASCII text, with very long lines (4812), with no line terminators` — one single line of almost 5,000 characters. Humans don't write scripts like that; obfuscators do. That alone is worth a second look.
- `var _0x3f1a=[...]` — variable names like `_0x3f1a` are the fingerprint of a common JavaScript obfuscator.
- `'\x57\x53\x63\x72\x69\x70\x74'` — hex escapes. Decode them (`\x57`=W, `\x53`=S, ...) and you get `WScript`, `Shell`, `Run`: the object and method a script uses to launch a program.
- `"hxxps://cdn-assets[.]example/"+"s/"+"u.p"+"s1"` — a URL split into pieces so a simple string search for `.ps1` fails. Put back together it is a PowerShell script to download. (We've defanged it to `hxxps` and `[.]`, as you should in tickets.)

The defender's habit: decode, don't run. Tools such as CyberChef, `box-js` (a JavaScript sandbox emulator) or simply printing the deobfuscated strings in an isolated interpreter turn this into readable text. ATT&CK calls the obfuscation **T1027 Obfuscated Files or Information** and the decoding at run time **T1140 Deobfuscate/Decode Files or Information**.

### What it looks like when it runs { #script-in-logs }

The most common modern pattern: the script arrives inside a ZIP, the user opens the ZIP in Explorer and double-clicks the script. Windows extracts it to a temporary folder and hands it to `wscript.exe`:

```xml
<EventData>
  <Data Name="SubjectUserName">j.kim</Data>
  <Data Name="NewProcessName">C:\Windows\System32\wscript.exe</Data>
  <Data Name="CommandLine">"C:\Windows\System32\WScript.exe" "C:\Users\j.kim\AppData\Local\Temp\Temp1_Invoice_2026.zip\invoice_2026.js"</Data>
  <Data Name="ParentProcessName">C:\Windows\explorer.exe</Data>
</EventData>
```

- `NewProcessName ... wscript.exe` — the Windows Script Host started. On most office PCs, ordinary users never run it.
- `CommandLine ... \AppData\Local\Temp\Temp1_Invoice_2026.zip\invoice_2026.js` — the `Temp1_<name>.zip` folder is where Explorer extracts a file you open from inside a ZIP. "A script, run from inside a ZIP that was just downloaded" is about as clear as signals get.
- `ParentProcessName ... explorer.exe` — the user double-clicked it in the Windows shell.

A few seconds later you would usually see the next step: `wscript.exe` starting `powershell.exe` or `cmd.exe`, or making a network connection (Sysmon Event ID 3). A parent-child pair of **`wscript.exe` → `powershell.exe`** on a user workstation is a high-value alert. For the PowerShell side, Script Block Logging (Event ID 4104) records the decoded code — see [Accounts, Defender and PowerShell events](../important-events/accounts-defender-powershell.md).

[Supplement] Two cheap, effective defences:

- **Re-associate script extensions with Notepad.** Through Group Policy, set the default program for `.js`, `.jse`, `.vbs`, `.vbe`, `.wsf`, `.wsh` and `.hta` to `notepad.exe`. A user who double-clicks the lure sees gibberish text instead of running it. Admins who need these files run them explicitly with `cscript.exe`.
- **Turn on the relevant Attack Surface Reduction rules** in Microsoft Defender, for example "Block JavaScript or VBScript from launching downloaded executable content" and "Block execution of potentially obfuscated scripts". **AMSI** (Antimalware Scan Interface) lets the antivirus inspect script content *after* the interpreter has decoded it, which defeats a lot of obfuscation.

## Microsoft Office documents { #office }

### Why Office is a favourite { #why-office }

Office documents are everywhere, and people exchange them all day with colleagues, customers and suppliers. An organisation can't simply block `.docx` and `.xlsx` the way it can block `.scr`. So a weaponised document is more likely to get through the filters and, because "please review the attached invoice" is so normal, more likely to be opened. ATT&CK files the delivery under **T1566.001 Phishing: Spearphishing Attachment** and the moment the user opens it under **T1204.002 User Execution: Malicious File**.

### Four ways a document does evil { #office-methods }

**1. A malicious link.** The document simply contains a link with a convincing reason to click it ("This document is protected. Click here to view it online"). Pure social engineering. It is hard to catch: lots of legitimate documents contain links, and there's no macro or exploit to write a signature for. The link usually leads to a credential-phishing page or a download. Your best signals are the URL's reputation, the domain's age and what the user's browser did next.

**2. An embedded object.** Office's "insert object" feature can put **another file of any type** inside the document — an `.exe`, a script, an `.lnk` — shown as an icon ("Double-click to open the invoice"). This is riskier for the attacker, because a mail filter that pulls out nested files and scans them recursively will find the payload. Many filters don't do that well, though. The interesting twist: an embedded object **doesn't run by itself**. In an automated sandbox that doesn't click on everything, the document can come back clean. The flip side for the attacker is that a person has a chance to stop: a security warning appears when the object is opened, and some users realise their mistake and close the document. For you as analyst, an embedded object shows up as a stream called `\x01Ole10Native` or `ObjectPool` in OLE files, or `word/embeddings/oleObject1.bin` in the ZIP formats.

**3. An exploit against Office itself.** The document contains crafted data that triggers a bug in Word, Excel or a component they load, so code runs **just by opening** (or even previewing) the file. These are rarer, but when a good one appears it spreads fast and has a **long tail**: attackers keep using it for years because they assume, often correctly, that Office isn't patched as quickly as Windows. The classic example is **CVE-2017-11882**, a bug in the old Equation Editor component, which was still in phishing campaigns many years after the fix. Another is **CVE-2022-30190 "Follina"**, where a document pulled a remote HTML file that abused the `ms-msdt:` URL handler. ATT&CK: **T1203 Exploitation for Client Execution**. A related trick, **remote template injection** (**T1221 Template Injection**), has a `.docx` load a template — possibly containing macros or an exploit — from a URL when it opens.

**4. A macro.** VBA (Visual Basic for Applications) code inside the document, often set to run automatically on opening (`AutoOpen`, `Document_Open`, `Workbook_Open`). Historically the attack relied on the user leaving **Protected View** and clicking the yellow bar's **Enable Content** button, despite the warning; lures said "This document was created in a newer version of Office, click Enable Content to view it". Malicious macros are easier for mail filters to spot than links or embedded files, but not always. ATT&CK: **T1059.005 Command and Scripting Interpreter: Visual Basic**.

| Method | Runs automatically? | Easy for a filter to catch? | Main signal |
| --- | --- | --- | --- |
| Link | No — user must click | Hard (links are normal) | URL reputation, landing page, browser activity after opening |
| Embedded object | No — user must double-click | Moderate, if the filter unpacks recursively | Embedded `.exe`/script/`.lnk` inside the document |
| Exploit | Yes, on open/preview | Moderate (signatures for known bugs) | Office process spawning unusual children or crashing |
| Macro | Usually, once enabled | Easier (macro presence and keywords) | `vbaProject.bin` / VBA streams, auto-run names, Office → shell processes |

### Two formats: the old binary one and the new ZIP one { #office-formats }

Office files come in two technically very different formats, even though users rarely notice.

**Pre-2007 binary format — `.doc`, `.xls`, `.ppt`.** An OLE **compound file**: a little file system inside one file, with "streams" for the text, the formatting and any macros. Magic bytes `D0 CF 11 E0 A1 B1 1A E1`. The crucial point: **the extension is the same whether or not there are macros**. A `.doc` may or may not contain a macro, and you can't tell from the name. To find autorun macros, a mail filter must tear the file apart and interpret it, or run every attachment in a sandbox — a serious undertaking. That is why so much Office-based malware has arrived as `.doc` and `.xls` rather than the newer formats.

**Office 2007+ XML format — `.docx`, `.xlsx`, `.pptx`** (the "x" is for XML). A **ZIP** archive (magic `PK\x03\x04`) of XML files. If the file contains macros, the extension must end in **`m`** — `.docm`, `.xlsm`, `.pptm` — and the macro code lives in a binary part called `vbaProject.bin`. That makes a blanket rule like "block `.docm` attachments" easy. Because it's a ZIP, you can rename it to `.zip` or just run `unzip -l` on it to see what's inside.

```
$ file Remittance_Nov.doc Q4_forecast.xlsm
Remittance_Nov.doc: Composite Document File V2 Document, Little Endian, Os: Windows, Version 10.0, Code page: 1252, Author: admin, Template: Normal.dotm, Last Saved By: user01, Revision Number: 2, Name of Creating Application: Microsoft Office Word, Create Time/Date: Mon Nov 16 08:02:00 2026, Last Saved Time/Date: Mon Nov 16 08:04:00 2026, Number of Pages: 1, Number of Words: 3, Number of Characters: 21

$ unzip -l Q4_forecast.xlsm | grep -E "vba|embed|xl/workbook"
     1567  2026-11-15 22:10   xl/workbook.xml
    23552  2026-11-15 22:10   xl/vbaProject.bin
```

- `Composite Document File V2 Document` — `file`'s name for the OLE compound format. This is an old-style `.doc`.
- `Author: admin`, `Last Saved By: user01` — the document's built-in metadata. Generic names like these are common in malicious documents built by kits.
- `Create Time ... 08:02:00`, `Last Saved ... 08:04:00`, `Revision Number: 2` — created and saved within two minutes, edited only twice.
- `Number of Words: 3, Number of Characters: 21` — a "remittance advice" with **three words** in it. Real business documents have content; lures often have little more than an image saying "Enable Content". Metadata is easy to fake, so treat these as hints, not proof.
- For the `.xlsm`, `unzip -l` shows `xl/vbaProject.bin`: **this workbook contains macros**. In a Word file the same part is `word/vbaProject.bin`.

[Correction] "Macros can only hide in `.docm`" is wrong. The `m` convention applies to the XML formats only. A `.doc` can carry macros silently. And Word decides how to open a file by its **content**, not only its extension, so a macro-enabled document saved with a `.doc` name will still open — attackers rely on that to slip past "block `.docm`" rules.

### Looking inside a macro without running it { #olevba }

On a Linux analysis box, the **oletools** suite (Python) reads macros straight out of both formats. `olevba` extracts the VBA source and flags suspicious keywords:

```
$ olevba Remittance_Nov.doc
olevba 0.60.2 on Python 3.12 - http://decalage.info/python/oletools
===============================================================================
FILE: Remittance_Nov.doc
Type: OLE
-------------------------------------------------------------------------------
VBA MACRO ThisDocument.cls
in file: Remittance_Nov.doc - OLE stream: 'Macros/VBA/ThisDocument'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
Sub AutoOpen()
    Dim a As String
    a = Chr(112) & Chr(111) & Chr(119) & "ershe" & "ll -w hidden -enc " & UserForm1.Tag
    ' ... (fragment shortened for this page)
End Sub
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |AutoOpen            |Runs when the Word document is opened        |
|Suspicious|Shell               |May run an executable file or a system       |
|          |                    |command                                      |
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|powershell          |May run PowerShell commands                  |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
```

- `Type: OLE` — the old binary format, as `file` said.
- `OLE stream: 'Macros/VBA/ThisDocument'` — where the macro lives inside the compound file.
- `Sub AutoOpen()` — a routine Word runs automatically when the document opens (once macros are allowed).
- `Chr(112) & Chr(111) & Chr(119) & "ershe" & "ll ..."` — `Chr(112)` is `p`, `111` is `o`, `119` is `w`: the macro builds the word `powershell` letter by letter so a plain keyword search misses it.
- `-w hidden -enc` — PowerShell options for "hidden window" and "the command follows as Base64". The encoded command is hidden in `UserForm1.Tag`, a property of a form inside the document — so even the macro text doesn't contain the payload.
- The keyword table is `olevba`'s summary. **AutoExec** rows tell you *when* it runs, **Suspicious** rows tell you *what* it might do, and if present, **IOC** rows list URLs, IPs and file names it found. `--deobf` and `--decode` ask `olevba` to undo simple obfuscation.

Related tools in the same suite: `oleid` (a quick risk overview: is it encrypted? does it have VBA? external links?), `oleobj` (extracts embedded objects), and `rtfobj` for RTF files.

### What it looks like when a document attacks { #office-in-logs }

Whatever the method, the moment of truth is usually the same: **an Office application starts a process it has no business starting.**

```xml
<EventData>
  <Data Name="SubjectUserName">j.kim</Data>
  <Data Name="NewProcessName">C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data>
  <Data Name="CommandLine">powershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...</Data>
  <Data Name="ParentProcessName">C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data>
</EventData>
```

- `ParentProcessName ... WINWORD.EXE` and `NewProcessName ... powershell.exe` — Word started PowerShell. Word's normal children are almost none (occasionally `splwow64.exe` for printing). Office → `powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`, `rundll32.exe` or `regsvr32.exe` is one of the highest-value detections a SOC can run.
- `-w hidden -enc SQBFAFgA...` — hidden window, Base64-encoded command. `SQBFAFgA` decodes from UTF-16LE Base64 to `IEX`, PowerShell's "run this string as code" (`Invoke-Expression`). (Decoding is covered on [Base64](../http-analysis/base64.md).)

[Supplement] Microsoft Defender's ASR rule **"Block all Office applications from creating child processes"** stops exactly this chain, and many EDRs alert on it by default.

### The big change: macros from the internet are blocked { #motw-macros }

Office document infection was, for years, one of the main routes into organisations. In 2022 Microsoft finally changed the default: **VBA macros in files that came from the internet are blocked**, and the user can no longer just click a button to enable them. Instead of the yellow "Enable Content" bar they see a red bar: *"SECURITY RISK — Microsoft has blocked macros from running because the source of this file is untrusted."* The change was announced for Version 2203, paused, and then rolled out in the Current Channel from Version 2206 in mid-2022, and to the other update channels after that.

How does Office know a file "came from the internet"? Through the **Mark of the Web** (MotW): when a browser or email client saves a downloaded file on an NTFS disk, Windows attaches a hidden **alternate data stream** named `Zone.Identifier` to it. You can read it with PowerShell:

```
PS C:\Users\j.kim\Downloads> Get-Content .\Remittance_Nov.doc -Stream Zone.Identifier
[ZoneTransfer]
ZoneId=3
ReferrerUrl=https://webmail.corp.example/
HostUrl=https://webmail.corp.example/attachment?id=88213
```

- `Get-Content ... -Stream Zone.Identifier` — reads the named alternate data stream instead of the file's normal content.
- `[ZoneTransfer]` — the section header for zone information.
- `ZoneId=3` — the security zone. `0` = this computer, `1` = local intranet, `2` = trusted sites, **`3` = internet**, `4` = restricted sites. Zone 3 is what triggers Protected View and the macro block.
- `ReferrerUrl` and `HostUrl` — where it was downloaded from. Gold for an investigation: it tells you the page and the exact download URL. (Not every program writes these two lines.)

The block applies to files with MotW **and** to files opened from some untrusted locations; admins can still allow macros through Trusted Locations, signed macros from trusted publishers, or policy. [Supplement] In 2023 Microsoft also began blocking **XLL add-ins** (Excel add-ins that are really DLLs) from the internet, and blocking dangerous embedded file types in **OneNote**, after attackers jumped to both.

**What attackers did next** matters as much as the change itself, because it tells you where to look now:

- **Containers that drop MotW** — ISO, IMG, VHD, 7z or ZIP files whose extracted contents didn't inherit the mark (**T1553.005 Subvert Trust Controls: Mark-of-the-Web Bypass**). Microsoft patched the ISO/IMG case in November 2022, but tools and archivers that don't propagate MotW are a recurring issue.
- **Shortcut (`.lnk`) files**, often inside those containers, that run `cmd`, `powershell`, `mshta` or `rundll32`.
- **HTML smuggling** (**T1027.006**) — an HTML attachment whose JavaScript builds the payload inside the browser.
- **OneNote, XLL, SVG, MSC, PDF-with-link and other "less usual" formats** — covered on the next page.

## Putting it together — a triage routine { #triage-routine }

When a suspect file reaches you:

1. **Hash it and look it up** before you do anything else (reputation, has anyone seen it?).
2. **Move it in an `infected` ZIP** to an isolated analysis box with a fresh snapshot.
3. **Identify it by its bytes** with `file` and a hex view — not by its name.
4. **Pick the family** — executable, script, document, other — and use the matching tools: `strings` and PE tools for executables; a text viewer and deobfuscation for scripts; `oleid`/`olevba`/`unzip -l` for Office.
5. **Look for the giveaways** — autorun macro names, embedded objects, obfuscated one-line scripts, URLs, a `.cpl` or `.scr` posing as a document.
6. **Check the endpoint logs** for the run-time pattern — `rundll32 ... Control_RunDLL` from Downloads, `wscript.exe` from a `Temp1_*.zip` folder, Office spawning a shell — and for the same hash or URL on other machines.
7. **Revert the VM** and record what you found (hashes, URLs, file names, ATT&CK techniques) in the ticket.

## The 2026 view { #trends }

!!! success "[2026 Current] Still valid"
    The four rules for a safe analysis setup (expendable machine, isolated network, hardened host, snapshot-and-revert VM), the OS-mismatch trick for static analysis, and the `infected` ZIP convention are all still standard practice; sample-sharing services such as MalwareBazaar still distribute samples as ZIPs with the password `infected`. The idea that "executable" means the PE format and not the `.exe` extension, that scripts are as dangerous as executables, and that Office documents attack through links, embedded objects, exploits and macros is unchanged. The best run-time detections are still parent-child process pairs: Office or `wscript.exe` spawning shells, and `rundll32`/`regsvr32`/`msiexec` loading files from user folders.

!!! info "[Changed] What has changed"
    - **Macros from the internet are blocked by default** in Microsoft 365 Apps and current Office versions (rolled out from mid-2022; files must carry the Mark of the Web). Macro-laden `.doc`/`.xls` phishing fell sharply afterwards. **XLL add-ins from the internet** were blocked in 2023, and OneNote began blocking dangerous embedded files the same year.
    - **The delivery mix moved** to ISO/IMG/VHD/ZIP containers, `.lnk` shortcuts, HTML smuggling, OneNote, SVG files carrying script or redirects, `.msc` (management console) files, and PDFs and QR codes leading to credential-phishing pages. Industry reports through 2025 show SVG and archive-based delivery growing especially fast.
    - **VBScript is being retired.** Microsoft deprecated it in 2023; on Windows 11 24H2 it became a "feature on demand" that is still enabled by default, with a later phase planned to turn it off by default and eventually remove it. Plan for that in detections, but don't assume it's gone on your fleet yet — check.
    - **PowerShell 7 runs on Linux and macOS**, so `.ps1` is no longer a Windows-only file for the purposes of the OS-mismatch rule.
    - **Analysis tooling has matured**: REMnux and FLARE-VM are the common analysis distributions, oletools is still the standard for Office files, and many sandboxes now add AI-generated summaries of scripts and macros. Useful, but verify against the actual code.
    - **ATT&CK names used on this page**: T1204.002 Malicious File, T1566.001 Spearphishing Attachment, T1218.002 Control Panel, T1218.005 Mshta, T1218.007 Msiexec, T1218.010 Regsvr32, T1218.011 Rundll32, T1546.002 Screensaver, T1574.002 DLL Side-Loading, T1059.001/.003/.004/.005/.006/.007, T1027, T1027.006 HTML Smuggling, T1140, T1203, T1221 Template Injection, T1553.005 Mark-of-the-Web Bypass.

!!! warning "[Caution] Wrong or risky to do the old way"
    - **Don't rely on extension block lists alone.** Block and inspect by true file type, and include the whole PE family, scripts, `.hta`, `.lnk`, `.iso`/`.img`/`.vhd`, `.one`, `.msc` and `.svg` in your thinking.
    - **Don't assume "macro blocked by default" protects you.** Policy can re-enable macros, Trusted Locations bypass the block, files without MotW (from some archives, USB sticks, or internal shares) aren't covered, and the attacker may not use a macro at all.
    - **Don't email samples, even zipped.** Gateways may block encrypted archives, and a mis-sent sample is an incident. Use your case system or a secure share, and remember that ZIP file names are visible.
    - **Don't trust a "clean" sandbox verdict on a document with an embedded object or a link.** Nothing ran because nothing clicked.
    - **Don't install PowerShell, Office, Java or Wine "for convenience" on the static-analysis box.** Each one removes the OS mismatch that keeps you safe.
    - **Don't treat `.js` as "just JavaScript".** On Windows it runs under `wscript.exe` with full user rights.

## Practice questions { #quiz }

### Question 1

A colleague wants to look at a suspicious attachment, `Payment_Advice.xls`, and plans to: copy it from the quarantine share to their laptop with drag-and-drop, open it in Excel in a Windows VM on that laptop "with macros disabled", and email it to you afterwards. List what is wrong with this plan and give the safe version step by step.

??? success "Answer and explanation"
    **What's wrong:** (1) Drag-and-drop moves the file in a runnable state — one accidental double-click and it runs, and the laptop's AV may delete it and raise an alert. (2) The laptop is a daily-use machine on the corporate network: it breaks "a system you can afford to lose" and "a separate network". (3) Opening an `.xls` in **Excel** is using the program it is designed to attack — an exploit doesn't need macros, and "macros disabled" can be undone by one click or a policy. (4) Emailing it risks gateway blocks, accidental delivery to someone else and an auto-scan quarantine.

    **Safe version:** hash it (`sha256sum`) and look the hash up; pack it with `7z a -tzip -pinfected -mem=AES256 ...`; move the ZIP to a dedicated analysis machine on an isolated network; take a VM snapshot; extract on a **Linux** analysis VM without Office (OS mismatch); run `file` (expect `Composite Document File V2`) and `oleid`/`olevba` to see macros, auto-run names and IOCs; revert the snapshot; share findings and the hash through the case system, and the sample — if needed — as the `infected` ZIP through a secure share.

### Question 2

The email gateway blocks `.exe`, `.bat` and `.docm`. In one week three attachments got through: `Holiday_Photos.scr`, `invoice_view.cpl` and `Remittance_Nov.doc`. For each, explain why it got through, how it runs, and one log pattern that would show it running.

??? success "Answer and explanation"
    **`Holiday_Photos.scr`** — a screen saver is a normal PE executable (`MZ`), but its extension isn't on the block list. A double-click runs it directly. Log: Event 4688 with `NewProcessName` ending in `Holiday_Photos.scr` (often from a Downloads or Temp path) and parent `explorer.exe` or an email client. ATT&CK T1204.002, and T1546.002 if it's set as the screen saver for persistence.

    **`invoice_view.cpl`** — a Control Panel item is a PE DLL; the extension wasn't blocked. A double-click goes to `control.exe`, which runs `rundll32.exe Shell32.dll,Control_RunDLL "<path>.cpl"`. Log: 4688 for `rundll32.exe` with `Control_RunDLL` and a `.cpl` under `\Users\...\Downloads\`, parent `control.exe`. ATT&CK T1218.002.

    **`Remittance_Nov.doc`** — the old binary format carries macros with no change of extension, so "block `.docm`" doesn't touch it; the gateway would have to parse the OLE file to find VBA. It runs when the user opens it and macros run (if they aren't blocked by MotW policy) or through an exploit. Log: 4688 with `ParentProcessName` `WINWORD.EXE` and a child such as `powershell.exe -w hidden -enc ...`. ATT&CK T1566.001, T1204.002, T1059.005.

    The fix for all three: block or inspect by **true file type**, not by extension, and parse Office files for VBA.

### Question 3

(a) Why is analysing a suspected Windows malicious PDF on Linux still safer, even though PDF readers exist on both? (b) A `.zip` you received is listed with `7z l` and shows `Path = CEO_J_Smith_passwords.xlsx` even though you don't know the password. Is the archive broken? What does this mean, and how would you avoid it? (c) Name two reasons Office documents with embedded objects can come back "clean" from an automated sandbox.

??? success "Answer and explanation"
    **(a)** The attacker nearly always assumes a Windows victim, so the exploit's code, or the payload it downloads and runs, is Windows code; on Linux the chain breaks. And exploits are usually written for one specific reader on one OS; making one work across operating systems **and** different PDF readers is hard. Hard, not impossible — so you still use an isolated VM and snapshots.

    **(b)** It's not broken. Classic ZIP encryption protects only the **contents**; names, sizes and dates sit in unencrypted headers, so anyone can list them. That can leak sensitive information (here, a person's name). Use the 7z format with header encryption (`7z a -t7z -pinfected -mhe=on ...`), or rename the inner file to something neutral (for example its hash with `.bin`) before packing.

    **(c)** Any two of: an embedded object **doesn't run automatically**, it needs a user double-click the sandbox may not perform; the security prompt that appears when the object is opened needs a human to accept it; the sandbox may not extract and examine nested files recursively; and the lure may need the user to click a link or enable something before anything happens.

## Related { #related }

- [Identifying files — magic bytes, nested files, Unicode and encodings](file-identification.md) · [Strings](strings.md)
- [Screenshots, sandboxes and when to go manual](../http-analysis/screenshots-sandboxes.md) · [Base64](../http-analysis/base64.md)
- [Process creation events](../important-events/process-creation.md) · [Accounts, Defender and PowerShell events](../important-events/accounts-defender-powershell.md)
- [Application control, FIM and catching persistence](../endpoint-defense/appcontrol-fim-persistence.md) · [Initial exploitation](../endpoint-attacks/initial-exploitation.md)
- [Phishing delivery & initial execution](../../../adversary/phishing-delivery.md) · [LOLBins](../../../adversary/lolbins.md) · [PowerShell cradles](../../../adversary/powershell-cradles.md)
