---
title: LNK Files & Jump Lists
tags:
  - artifact
  - windows
  - file-knowledge
---

# LNK Files & Jump Lists

<div class="dfir-meta" markdown>
**Category:** File / folder knowledge · **OS:** XP → 11 (Jump Lists: 7+) · **Last updated:** 2026-09-16
</div>

!!! abstract "In one sentence"
    Windows automatically creates a **shortcut (`.lnk`)** for every file or folder a user opens, and **Jump Lists** keep per-application lists of recent/pinned items — together they prove a user opened a specific file, when, from which volume, and what the file's timestamps were at that moment, even if the file has since been deleted or was on removable media.

## What they tell you

| Field inside the LNK | Why it matters |
|---|---|
| **Target path** (local path, network share, or relative) | The file/folder that was opened — survives deletion of the target |
| **Target's MAC times** at time of *last* shortcut update | Created / Modified / Accessed of the *target*, frozen — useful when the target is gone or timestomped later |
| **Target size** | |
| **Volume serial number, volume label, drive type** | Which USB stick / drive it lived on — match to `USBSTOR` / `MountedDevices` |
| **NetBIOS name / MAC address** of the machine that created the LNK (in the Tracker / Link Tracking `ObjectID`) | Ties the shortcut to a host; MAC → NIC vendor |
| **MFT entry number + sequence** of the target (in the Tracker data / shell item extension blocks) | Correlate with `$MFT` |
| **Working directory, arguments, icon location** | Attacker-crafted LNKs (phishing) hide `cmd /c powershell -enc …` in arguments |
| LNK file's own **$SI timestamps** | Created = **first** time the file was opened via this path, Modified = **last** time |

## Location

| Item | Path |
|---|---|
| Recent items (files & folders) | `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\` (`*.lnk`) |
| Office recent | `C:\Users\<user>\AppData\Roaming\Microsoft\Office\Recent\` |
| Desktop / Start menu shortcuts | User-created; also where attackers drop weaponised LNKs |
| **AutomaticDestinations** (auto-populated Jump Lists) | `...\Recent\AutomaticDestinations\<AppID>.automaticDestinations-ms` |
| **CustomDestinations** (pinned / app-managed Jump Lists) | `...\Recent\CustomDestinations\<AppID>.customDestinations-ms` |

Recent folder keeps roughly the last **149** LNKs (older ones roll off); Jump Lists are capped per app (~10–20 shown, but the container file often holds far more).

## Jump List structure

- `*.automaticDestinations-ms` is an **OLE Compound File** (like an old .doc). Each stream is numbered (`1`, `2`, … hex) and is a **full LNK structure**. The `DestList` stream is the index: entry ID ↔ path ↔ **last access time**, **access count** (Win10+), hostname and pin status.
- `*.customDestinations-ms` is a sequence of LNK structures with a small header — created when a user *pins* something or when an app (browser, media player) writes its own list.
- `AppID` = a CRC64 of the application path (or a value the app sets). Community lists map common IDs — e.g. `f01b4d95cf55d32a` Explorer (Win 8+), `9b9cdc69c1c24e2b` Notepad (x64), `5f7b5f1e01b83767` Quick Access, `1b4dd67f29cb1962` Explorer pinned, `7e4dca80246863e3` Control Panel.

## How to collect

=== "KAPE"

    ```powershell
    kape.exe --tsource C: --tdest C:\Case\out --target LNKFilesAndJumpLists --mdest C:\Case\mod --module LECmd,JLECmd
    ```

=== "Velociraptor"

    `Windows.Forensics.Lnk` and `Windows.Forensics.RecentApps` / `Windows.Applications.JumpLists` (community).

## How to parse

=== "LECmd (Eric Zimmerman)"

    ```powershell
    # All LNKs under a user's Recent → CSV; -q keeps console quiet; --mp shows more precision
    LECmd.exe -d "C:\Case\Users\sung\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\Case\out --csvf lnk.csv -q

    # One suspicious shortcut, full detail incl. shell items & tracker data
    LECmd.exe -f "C:\Case\Desktop\Invoice.pdf.lnk"

    # Treat non-.lnk files as LNKs (attackers rename)
    LECmd.exe -d C:\Case\Suspicious --all
    ```

    Key CSV columns: `SourceCreated`, `SourceModified` (the LNK itself), `TargetCreated/Modified/Accessed`, `LocalPath`, `NetworkPath`, `VolumeSerialNumber`, `VolumeLabel`, `DriveType`, `MachineID`, `MACAddress`, `Arguments`, `WorkingDirectory`.

=== "JLECmd (Eric Zimmerman)"

    ```powershell
    # Both Automatic and Custom destinations, one CSV each
    JLECmd.exe -d "C:\Case\Users\sung\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\Case\out -q

    # Include the raw LNK details for every entry (large but complete)
    JLECmd.exe -d ... --csv C:\Case\out --ld

    # Dump embedded LNKs from a jump list to files
    JLECmd.exe -f 5f7b5f1e01b83767.automaticDestinations-ms --dumpTo C:\Case\jl_lnks
    ```

    `AutomaticDestinations` CSV columns to sort by: `LastModified` (DestList last access), `EntryNumber`, `Path`, `InteractionCount`, `Hostname`, `AppIdDescription`.

=== "Plaso"

    ```bash
    log2timeline.py --parsers "lnk,custom_destinations,olecf/olecf_automatic_destinations" out.plaso /evidence/Users/
    ```

## Analysis tips

!!! tip "Three timestamps, three meanings"
    For a Recent LNK: **LNK Created** = first time the user opened that target (through this path). **LNK Modified** = most recent open. **Target Created/Modified** = the *file's* timestamps as they were at that last open. If the target's current `$SI` modified time is *older* than what the LNK recorded → timestomped.

- **Phishing LNKs**: look at `Arguments` and `IconLocation`. A "PDF" whose icon is `shell32.dll,1` and whose target is `C:\Windows\System32\cmd.exe` with a 1,000-character argument is the payload. The `MachineID`/`MAC` in tracker data can identify the **attacker's build machine** if they forgot to strip it.
- **USB exfil**: Recent LNKs pointing to `E:\...` with a volume serial that matches an `USBSTOR` device → user opened files *from* the stick; folder LNKs to `E:\` with target created times → copied *to* the stick (pair with ShellBags for folder views and `$MFT` for copy timestamps).
- **Network shares**: `NetworkPath` `\\fileserver\finance\...` proves access to a share even when server logs are gone.
- **Deleted evidence**: LNK for `C:\Users\Public\tools\mimikatz.zip` that no longer exists still gives you size, timestamps and MFT reference.
- **Jump Lists survive Recent cleanup**: users/attackers who clear "Recent items" often leave `AutomaticDestinations` intact; `InteractionCount` shows how many times a document was opened.
- **Quick Access (`5f7b5f1e01b83767`) and Explorer (`f01b4d95cf55d32a`)** Jump Lists record **folders** browsed — a second source alongside [ShellBags](registry-keys.md#files-folders-opened-per-user).
- Renamed LNKs / `.lnk` extension hidden: Explorer never shows `.lnk`, so `report.pdf.lnk` displays as `report.pdf`.

## Timeline / correlation

| Question | Cross-check with |
|---|---|
| Was the file actually on this system / which device? | Volume serial ↔ `SYSTEM\MountedDevices`, `USBSTOR`, [$MFT](mft-usn.md) |
| Which program opened it? | Jump List AppID; `OpenSavePidlMRU`/`LastVisitedPidlMRU`; Office MRU ([Registry keys](registry-keys.md)) |
| Which folder was it browsed from? | ShellBags (`UsrClass.dat`), Explorer Jump List |
| Was it executed rather than viewed? | [Prefetch](prefetch.md), [Amcache](amcache.md), `4688` |
| Who opened it? | LNK lives under the user's profile → that user; confirm with `4624` session times |

## References

- [Microsoft — [MS-SHLLINK] Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/)
- [Eric Zimmerman — LECmd, JLECmd](https://ericzimmerman.github.io/#!index.md)
- [Jump List AppID master list (community, 4n6k / EricZimmerman JumpList repo)](https://github.com/EricZimmerman/JumpList)
- [libyal — Jump Lists format (libfwsi / liblnk docs)](https://github.com/libyal/liblnk/blob/main/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc)
