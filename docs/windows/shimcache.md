---
title: Shimcache (AppCompatCache)
tags:
  - artifact
  - windows
  - execution
---

# Shimcache (AppCompatCache)

<div class="dfir-meta" markdown>
**Category:** File existence / probable execution · **OS:** XP → 11, **including Server** · **Last updated:** 2026-09-16
</div>

!!! abstract "In one sentence"
    The Application Compatibility Cache records executables the shim engine has *looked at* — full path, the file's **$STANDARD_INFORMATION last-modified time**, and (on Win7/8 only) an "executed" flag. It proves a file **existed at that path**; execution is likely but not guaranteed, and it works on **servers where Prefetch is off**.

## What it tells you

- Full path of executables (and some scripts/DLLs) that were executed **or** browsed to in Explorer (Explorer inspects files to shim them).
- The file's **last modification time (`$SI`) at the moment it was cached** — *not* the execution time.
- Ordering: entries are stored **most-recent-first**, so position is a relative timeline even without execution timestamps.
- Win7 / Win8: an **Insert flag / Execution flag** (`CSRSS` flag) that indicates actual execution.
- Windows 10/11: **no execution flag**, no insertion timestamp. Existence + order only.

!!! warning "Three things people get wrong"
    1. The timestamp is the **file's modification time**, not when it ran.
    2. On **Windows 10/11 there is no execution flag** — an entry can come from Explorer merely rendering the icon of a folder containing the EXE.
    3. The cache lives in **memory** and is only **written to the registry on shutdown/reboot** (or when it fills). A live system's `SYSTEM` hive is stale; a system that never rebooted after the attack may not have the entries yet. Memory forensics (`volatility3 windows.shimcachemem`) gets the live version.

## Location

| Item | Path / Key |
|---|---|
| Registry (Win7+) | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache` (binary value) |
| Registry (XP) | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache` |
| Offline hive | `C:\Windows\System32\config\SYSTEM` (+`.LOG1/.LOG2`). `CurrentControlSet` → check `Select\Current` to pick `ControlSet001` vs `002` |
| Max entries | XP: 96 · Win7/8: 1024 · Win10/11: 1024 (older builds) — oldest fall off the end |

Multiple `ControlSet00N` keys may each hold a cache — parse all of them; the non-current one is an older snapshot.

## Format by OS

| OS | Header / signature | Timestamp | Exec flag |
|---|---|---|---|
| XP 32-bit | `0xDEADBEEF` | Last mod + last update time | — |
| Vista / 2008 | `0xBADC0FFE` | Last mod | Insert flag |
| Win7 / 2008 R2 | `0xBADC0FFE` | Last mod | **Yes** (`CSRSS` insert flag) |
| Win8 / 2012 | `00ts` per-entry tag | Last mod | **Yes** |
| Win8.1 / 2012 R2 | `10ts` | Last mod | **Yes** |
| Win10 / 11 / 2016+ | `10ts`, header offset 0x30 (0x34 on Creators Update+) | Last mod | **No** |

## How to collect

=== "KAPE"

    ```powershell
    kape.exe --tsource C: --tdest C:\Case\out --target RegistryHivesSystem --mdest C:\Case\mod --module AppCompatCacheParser
    ```

=== "Velociraptor"

    `Windows.Registry.AppCompatCache`

=== "Live (writes to disk first!)"

    ```powershell
    # Forces the in-memory cache to flush? No — only reboot does. Export what is on disk:
    reg save HKLM\SYSTEM C:\Case\SYSTEM
    ```

    For the live in-memory version, take a memory image and use Volatility (`windows.shimcachemem`).

## How to parse

=== "AppCompatCacheParser (Eric Zimmerman)"

    ```powershell
    # Offline hive → CSV; -t sorts by timestamp, -c picks a ControlSet (default: all)
    AppCompatCacheParser.exe -f C:\Case\SYSTEM --csv C:\Case\out --csvf shimcache.csv

    # Live system
    AppCompatCacheParser.exe --csv C:\Case\out
    ```

    Columns: `ControlSet`, `CacheEntryPosition` (0 = most recent), `Path`, `LastModifiedTimeUTC`, `Executed` (Win7/8 only), `Duplicate`.

=== "RegRipper"

    ```bash
    rip.pl -r SYSTEM -p appcompatcache
    rip.pl -r SYSTEM -p shimcache      # TLN output for timelines
    ```

=== "Volatility 3 (memory)"

    ```bash
    vol -f mem.raw windows.shimcachemem
    ```

## Analysis tips

!!! tip "Use the *position*, not the timestamp, for sequencing"
    Entry 0 is the most recently shimmed. If `mimikatz.exe` is at position 3 and `psexesvc.exe` at position 4, the attacker ran PsExec, then Mimikatz — regardless of what their modification times say. Insertion order is your timeline; the timestamp just tells you how old the *file* was.

- **Server triage**: Prefetch is disabled on Server SKUs, so Shimcache + Amcache + 4688 + BAM is your execution story.
- **Path anomalies**: `\??\C:\Users\Public\`, `\Device\HarddiskVolumeShadowCopy`, UNC paths (`\\server\share\tool.exe`), removable drives — all worth pulling.
- **Timestomping detection**: if the Shimcache last-mod time is *newer* than the file's current `$SI` modification time, someone rolled the timestamp back after execution.
- **Deleted tools** stay in the cache until pushed out by 1024 newer entries.
- **Explorer noise on Win10**: browsing `C:\Tools\` in Explorer can shim every EXE inside. Corroborate with Prefetch / Amcache / 4688 before claiming execution.
- **Duplicates across ControlSets** are normal; a path present in `ControlSet001` but missing in `002` shows it appeared between the two snapshots.
- **Anti-forensics**: clearing requires modifying a binary registry value (rare) or preventing the flush by never rebooting cleanly — a system that *crashed* rather than rebooted may have lost the in-memory entries.

## Timeline / correlation

| Question | Cross-check with |
|---|---|
| Did it really execute? | [Prefetch](prefetch.md) (workstations), Security `4688`, Sysmon `1`, [Amcache](amcache.md), BAM/DAM |
| What was the file? | [Amcache](amcache.md) SHA-1 |
| When was it dropped? | [$MFT / USN](mft-usn.md) — `$FN` creation time vs Shimcache last-mod |
| Live vs. on-disk cache differ? | Memory image `shimcachemem` vs `SYSTEM` hive |

## References

- [Mandiant — Leveraging the Application Compatibility Cache in Forensic Investigations](https://www.mandiant.com/resources/blog/caching-out-the-val)
- [Eric Zimmerman — AppCompatCacheParser](https://ericzimmerman.github.io/#!index.md)
- [libyal — Windows AppCompatCache format](https://github.com/libyal/winreg-kb/blob/main/documentation/Application%20Compatibility%20Cache%20key.asciidoc)
