---
title: Prefetch
tags:
  - artifact
  - windows
  - execution
---

# Prefetch

<div class="dfir-meta" markdown>
**Category:** Evidence of execution · **OS:** Windows XP → 11 (workstation SKUs) · **Last updated:** 2026-09-16
</div>

!!! abstract "In one sentence"
    Prefetch files record that an executable **ran**, when it ran (up to the last 8 times), how many times, and which files/directories it touched in the first ~10 seconds — the single best "did it execute?" artifact on a workstation.

## What it tells you

- The executable **name** and a hash of its **full path** (so `cmd.exe` from `C:\Windows\System32` and from `C:\Temp` get different `.pf` files).
- **Run count** and up to **8 most recent run timestamps** (Win8+; XP/7 keep only the last one).
- **Files and directories referenced** while loading — DLLs, config files, the document a viewer opened, the DLL a side-loaded binary pulled in.
- Volume information: serial number and creation time of the volume it ran from (helps spot USB-launched tools).

## Location

| Item | Path |
|---|---|
| Directory | `C:\Windows\Prefetch\` |
| File naming | `<EXENAME>-<8-char hash>.pf` — e.g. `MIMIKATZ.EXE-5B7C4A2D.pf` |
| Controlling key | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher` |
| Max files | 128 (XP/7), 1024 (Win8+). Oldest are pruned when full |

`EnablePrefetcher` values: `0` disabled, `1` application only, `2` boot only, `3` application + boot (default on workstations). **Windows Server disables it by default**, and it is often off on SSD systems with Win7 (Win8+ keeps it on regardless of SSD).

## Key fields

| Field | Meaning | Notes |
|---|---|---|
| Executable name | Filename as launched | Case-insensitive; hash differentiates path |
| Hash | Derived from full path (+ command line for hosting processes like `svchost.exe`, `dllhost.exe`, `mmc.exe`, `rundll32.exe`, `backgroundtaskhost.exe`) | Same binary, different path → different `.pf` |
| Run count | Times executed | Not decremented, so gaps mean nothing was pruned |
| Last run times | Up to 8 (Win8+) | Stored as FILETIME (UTC). The **first** run is *not* stored unless it is one of the last 8 |
| File references | Files opened in the first ~10 s | Includes the document/DLL loaded — great for finding the payload a LOLBin ran |
| Directory references | Directories touched | Reveals staging directories |
| Volume serial / created | Where the exe lived | USB or mounted image detection |

!!! warning "The 10-second problem and the ~10 s offset"
    A `.pf` file is written about **10 seconds after** the process starts, so the `.pf` file's **NTFS creation time ≈ first run + 10 s** and **modification time ≈ last run + 10 s**. Also, a very short-lived process (a dropper that exits in 1 s) still gets a prefetch file — but its file references may be sparse.

## Format versions

| Version | OS | Compressed? |
|---|---|---|
| 17 | XP / 2003 | No |
| 23 | Vista / 7 | No |
| 26 | 8 / 8.1 | No |
| 30 | 10 / 11 | **Yes — MAM (Xpress Huffman)**; must be decompressed before parsing. Newer 10/11 builds use v30 with sub-variants and v31 |

Signature after decompression is `SCCA` at offset 4.

## How to collect

=== "KAPE"

    ```powershell
    kape.exe --tsource C: --tdest C:\Case\out --target Prefetch --mdest C:\Case\mod --module PECmd
    ```

=== "Velociraptor"

    Artifact `Windows.Forensics.Prefetch` — parses live and returns a table (no need to copy files first).

=== "Manual"

    ```powershell
    # Needs admin; copy the whole folder including the Layout.ini / *.db files for context
    robocopy C:\Windows\Prefetch C:\Case\Prefetch /E
    ```

## How to parse

=== "PECmd (Eric Zimmerman)"

    ```powershell
    # Whole directory → CSV (one row per pf + one row per referenced file in *_Timeline.csv)
    PECmd.exe -d C:\Case\Prefetch --csv C:\Case\out --csvf prefetch.csv

    # Single file, human readable
    PECmd.exe -f C:\Case\Prefetch\MIMIKATZ.EXE-5B7C4A2D.pf

    # Only show pf files that reference a keyword (e.g. a staging dir)
    PECmd.exe -d C:\Case\Prefetch -k "temp,appdata\local\temp,users\public"
    ```

    `--csvf` name is the main output; `*_Timeline.csv` gives every run timestamp as its own row — feed that into a super-timeline.

=== "Plaso / log2timeline"

    ```bash
    log2timeline.py --parsers prefetch out.plaso /evidence/C/Windows/Prefetch/
    psort.py -o l2tcsv -w prefetch.csv out.plaso
    ```

=== "Python (windowsprefetch / dissect)"

    ```bash
    pip install windowsprefetch
    prefetch.py -f MIMIKATZ.EXE-5B7C4A2D.pf
    ```

## Analysis tips

!!! tip "Fast triage"
    Sort `PECmd` output by **Last Run** descending and by **Run Count** ascending. Attacker tools usually have a **low run count** (1–3) in the **incident window**. Legitimate software has high counts spread over months.

- **Filename ≠ innocence.** A `.pf` for `svchost.exe` with a hash you have never seen means svchost ran from a non-standard path (or with an odd command line). Compare hashes across the fleet.
- **Look inside the file references.** `POWERSHELL.EXE-*.pf` referencing `C:\Users\Public\update.ps1` tells you *what* PowerShell ran. `RUNDLL32.EXE-*.pf` referencing an unusual DLL is a side-load / proxy execution hint.
- **Deleted tools still show.** The attacker deletes `mimikatz.exe`; the `.pf` file usually survives. Also check `$MFT`, USN journal and Amcache for the same binary.
- **Renamed tools.** Compare the prefetch *executable name* to what the **Amcache** SHA1 says it actually is.
- **Timestomping doesn't touch prefetch.** Attackers often stomp the EXE's timestamps but forget prefetch and `$MFT` `$FILE_NAME` attributes.
- **Absent ≠ didn't run.** Check `EnablePrefetcher`, Server SKU, whether the folder hit the 1024 limit (then the *oldest* were pruned), and whether the folder was **wiped** — an almost-empty Prefetch directory with a very recent folder modification time is itself suspicious.
- **Anti-forensics:** deleting `C:\Windows\Prefetch\*`, setting `EnablePrefetcher=0`, or running from a RAM disk / mapped share (files on network shares still get prefetch files, but with the UNC path hashed).

## Timeline / correlation

| Question | Cross-check with |
|---|---|
| What exactly was the binary? | [Amcache](amcache.md) (SHA1, publisher), [Shimcache](shimcache.md) (path, existence) |
| Who ran it? | Security `4688` (if enabled), [UserAssist](registry-keys.md#program-execution-per-user-unless-noted), BAM/DAM key (per-SID last-execution time) |
| What did it do next? | Sysmon 1/3/11, [USN journal](mft-usn.md) for files created ±10 s of the run time |
| Was it launched from USB? | Volume serial in the `.pf` ↔ `SYSTEM\MountedDevices`, `USBSTOR` |
| Persisted? | [Registry Run keys](registry-keys.md#autostart-persistence-asep), Scheduled task `4698`, Service `7045` |

## References

- [libscca — Windows Prefetch format documentation](https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc)
- [Eric Zimmerman — PECmd](https://ericzimmerman.github.io/#!index.md)
- [SANS Windows Forensic Analysis poster](https://www.sans.org/posters/windows-forensic-analysis/)
