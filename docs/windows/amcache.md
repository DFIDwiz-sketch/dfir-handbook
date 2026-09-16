---
title: Amcache
tags:
  - artifact
  - windows
  - execution
---

# Amcache

<div class="dfir-meta" markdown>
**Category:** Evidence of execution / program inventory · **OS:** Windows 7 (with update) → 11 · **Last updated:** 2026-09-16
</div>

!!! abstract "In one sentence"
    `Amcache.hve` is a registry hive that inventories executables, drivers and installed programs the system has seen — most valuable because it stores the **SHA-1 hash** of the file, so you can identify a renamed or deleted tool with certainty.

## What it tells you

- Full path, file size, publisher, product/version metadata (from the PE version resource), compile (link) time, and **SHA-1 of the first 31,457,280 bytes** (30 MB) of the file.
- The **first time** Windows became aware of the binary (the key's last-write time) — often, but *not always*, the first execution.
- Installed programs (from MSI/uninstall data), drivers, shortcuts, device PnP info.

!!! warning "Execution is *inferred*, not proven"
    Entries are created by the **Application Experience / Compatibility Appraiser** scheduled task (`\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser`) and by the shim engine when a process launches. A file can appear because it was **scanned** (e.g. sitting in Program Files) rather than executed. Treat Amcache as *"this binary existed here, this is its hash"*, and use Prefetch / 4688 / Sysmon 1 to prove execution.

## Location

| Item | Path |
|---|---|
| Hive | `C:\Windows\AppCompat\Programs\Amcache.hve` (+ `.LOG1`, `.LOG2` transaction logs — collect them too) |
| Predecessor (XP/7) | `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` — path only, no hash |
| Locked while running | Yes — use raw copy (KAPE, FTK Imager, `esentutl`-style volume shadow) |

## Structure (Windows 10 1709+ format)

| Key | What it inventories | Key fields |
|---|---|---|
| `Root\InventoryApplicationFile` | **Executables** seen (one subkey per file, named `<lowercase path>|<hash>`) | `LowerCaseLongPath`, `Name`, `Size`, `FileId` (`0000` + **SHA-1**), `Publisher`, `ProductName`, `ProductVersion`, `BinFileVersion`, `LinkDate`, `BinaryType`, `ProgramId`, `IsOsComponent`, `IsPeFile` |
| `Root\InventoryApplication` | **Installed programs** (MSI, uninstall entries, Store apps) | `Name`, `Publisher`, `Version`, `InstallDate`, `RootDirPath`, `Source` (Msi/AddRemoveProgram/…), `UninstallString`, `ProgramId` |
| `Root\InventoryApplicationShortcut` | `.lnk` shortcuts in Start menu / desktop | `ShortcutPath`, `ShortcutTargetPath` |
| `Root\InventoryDriverBinary` | Drivers (`.sys`) | `DriverName`, `DriverId` (SHA-1), `DriverSigned`, `DriverCompany`, `DriverLastWriteTime` |
| `Root\InventoryDevicePnp` | PnP devices | Class, manufacturer, driver, `InstallDate` |
| `Root\InventoryDeviceContainer` | Device containers (USB devices, etc.) | `FriendlyName`, `Manufacturer`, `ModelName` |

Older format (Win 8 – 10 1607) used `Root\File\<VolumeGUID>\<FileRef>` with numbered values: `15` = full path, `101` = SHA-1, `17` = last modified, `0F` = link date, `11` = created, `100` = program ID.

!!! info "Which timestamp is which"
    The **key LastWrite time** on an `InventoryApplicationFile` entry = when the appraiser wrote/updated the entry (≈ first-seen, and may be refreshed). `LinkDate` = PE compile time from the header (attacker-controllable). There is **no reliable "last executed" timestamp** in Amcache.

## How to collect

=== "KAPE"

    ```powershell
    kape.exe --tsource C: --tdest C:\Case\out --target Amcache --mdest C:\Case\mod --module AmcacheParser
    ```

=== "Velociraptor"

    `Windows.System.Amcache` — parses the live hive via raw NTFS read.

=== "Live copy"

    ```powershell
    # Locked — use a shadow copy or a raw-reading tool.  RawCopy example:
    RawCopy.exe /FileNamePath:C:\Windows\AppCompat\Programs\Amcache.hve /OutputPath:C:\Case
    ```

## How to parse

=== "AmcacheParser (Eric Zimmerman)"

    ```powershell
    # Full parse → several CSVs (UnassociatedFileEntries, AssociatedFileEntries, Programs, Drivers, Shortcuts, Devices…)
    AmcacheParser.exe -f C:\Case\Amcache.hve --csv C:\Case\out

    # Only files NOT tied to an installed program (where attacker tools live) + include Windows OS files
    AmcacheParser.exe -f C:\Case\Amcache.hve --csv C:\Case\out -i

    # Whitelist known-good hashes to shrink output
    AmcacheParser.exe -f C:\Case\Amcache.hve --csv C:\Case\out -w C:\Case\known_good_sha1.txt
    ```

    The most useful output is `*_UnassociatedFileEntries.csv`: binaries that are not part of any installed product. Sort by `FileKeyLastWriteTimestamp`.

=== "RegRipper"

    ```bash
    rip.pl -r Amcache.hve -p amcache
    ```

=== "Plaso"

    ```bash
    log2timeline.py --parsers amcache out.plaso Amcache.hve
    ```

## Analysis tips

!!! tip "Hash first, name second"
    Take every SHA-1 from `UnassociatedFileEntries`, drop the leading `0000`, and check against VirusTotal / your threat-intel. A file called `svchost.exe` whose SHA-1 is Mimikatz ends the argument.

- **Renamed tools**: Amcache keeps the on-disk name *and* the PE resource `ProductName`/`OriginalFileName`-derived fields. `Name = update.exe`, `ProductName = "mimikatz"` happens more often than you'd think.
- **Deleted binaries**: Amcache entries survive deletion of the file. Pair with `$MFT`/USN to reconstruct when it was dropped and removed.
- **Unsigned / no publisher** binaries in `Users\*`, `ProgramData`, `Windows\Temp`, `Users\Public` in the incident window are the first things to pull.
- **LinkDate sanity**: a compile time in the future or 1970/2000-ish suggests a packed or forged header.
- **Drivers**: `InventoryDriverBinary` with `DriverSigned = 0` or an unusual `DriverCompany` → BYOVD (bring-your-own-vulnerable-driver) attacks and rootkits.
- **Don't over-read the timestamp** — the appraiser task runs roughly daily; an entry's last-write may be hours after actual first execution, or refreshed later.

## Timeline / correlation

| Question | Cross-check with |
|---|---|
| Did it actually run, and when? | [Prefetch](prefetch.md), Security `4688`, Sysmon `1`, BAM/DAM |
| Does this hash match a known tool? | VirusTotal, MISP, internal hash sets |
| Where did it come from? | [USN journal](mft-usn.md) `FILE_CREATE`, Zone.Identifier ADS (`$MFT`), browser history, `4663` |
| Same tool on other hosts? | Fleet-wide Velociraptor hunt on the SHA-1 |
| Program installed vs. dropped? | `InventoryApplication` vs `UnassociatedFileEntries` |

## References

- [Blanche Lagny — Analysis of the AmCache (ANSSI, 2019)](https://www.ssi.gouv.fr/uploads/2019/01/anssi-coriin_2019-analysis_amcache.pdf)
- [Eric Zimmerman — AmcacheParser](https://ericzimmerman.github.io/#!index.md)
- [13Cubed — Amcache and Shimcache in forensic analysis](https://www.13cubed.com/)
