---
title: Eric Zimmerman Tools
tags:
  - tool
  - windows
  - parsing
  - cheatsheet
---

# Eric Zimmerman Tools

<div class="dfir-meta" markdown>
**Category:** Artifact parsers · **Platform:** Windows (.NET) · **Last updated:** 2026-09-17
</div>

!!! abstract "What they do"
    A free suite of best-in-class command-line parsers, one per Windows artifact, all sharing the same conventions (`-f` file, `-d` directory, `--csv` output) and all feeding **Timeline Explorer**. If [KAPE](kape.md) `!EZParser` collected it, these are what parsed it. Together they turn raw hives, journals and logs into clean CSVs you can sort, filter and timeline.

## Get them and keep them updated

```powershell
# Download the whole suite (net6 build recommended) and keep it current
.\Get-ZimmermanTools.ps1 -Dest C:\Tools\EZ -NetVersion 6
```

Most tools have a `--csv <dir>` (one row per record) and many a `--csvf <name>`; timestamps default to **UTC**; `--help` lists everything. Names ending in `Cmd` are CLI; `Registry Explorer`, `Timeline Explorer`, `ShellBags Explorer`, `EvtxECmd` maps have GUI/aux pieces.

## The suite by artifact

| Tool | Artifact | Typical command |
|---|---|---|
| **MFTECmd** | `$MFT`, `$J` (USN), `$LogFile`, `$Boot`, `$I30`, `$SDS` | `MFTECmd.exe -f C:\t\$MFT --csv out --csvf mft.csv` · `MFTECmd.exe -f $J -m $MFT --csv out` |
| **EvtxECmd** | Windows Event Logs (`.evtx`) with community **maps** | `EvtxECmd.exe -d C:\t\Logs --csv out` · `--sync` to update maps |
| **PECmd** | Prefetch (`.pf`) | `PECmd.exe -d C:\Windows\Prefetch --csv out --csvf pf.csv` |
| **AmcacheParser** | `Amcache.hve` (SHA-1 of binaries) | `AmcacheParser.exe -f Amcache.hve --csv out -i` |
| **AppCompatCacheParser** | Shimcache (in `SYSTEM` hive) | `AppCompatCacheParser.exe -f SYSTEM --csv out` |
| **RECmd** | Registry, batch-mode (any hive) | `RECmd.exe -d C:\t\Reg --bn BatchExamples\Kroll_Batch.reb --csv out --nl` |
| **Registry Explorer** | Registry, interactive (GUI) + deleted keys | bookmarks for every DFIR key; loads transaction logs |
| **rla** | Replay registry transaction logs into a clean hive | `rla.exe -d C:\t\Reg --out C:\t\clean` |
| **LECmd** | LNK shortcut files | `LECmd.exe -d "...\Recent" --csv out` |
| **JLECmd** | Jump Lists (Automatic/Custom Destinations) | `JLECmd.exe -d "...\Recent" --csv out` |
| **SBECmd** | ShellBags (`UsrClass.dat`, `NTUSER.dat`) | `SBECmd.exe -d C:\t\Reg --csv out` |
| **ShellBags Explorer** | ShellBags (GUI tree view) | folder-browsing reconstruction |
| **SrumECmd** | SRUM (`SRUDB.dat` + `SOFTWARE`) | `SrumECmd.exe -f SRUDB.dat -r SOFTWARE --csv out` |
| **SumECmd** | SUM (User Access Logging, Server) | `SumECmd.exe -d C:\t\SUM --csv out` |
| **RBCmd** | Recycle Bin (`$I` files) | `RBCmd.exe -d C:\t\Recycle --csv out` |
| **RecentFileCacheParser** | `RecentFileCache.bcf` (Win7 execution) | |
| **WxTCmd** | Windows 10 Timeline (`ActivitiesCache.db`) | `WxTCmd.exe -f ActivitiesCache.db --csv out` |
| **JumpList / bstrings** | `bstrings.exe` = fast string search with regex/patterns | `bstrings.exe -f file --ls "password"` |
| **PECmd/Timeline** | `*_Timeline.csv` outputs feed super-timelines | |
| **Timeline Explorer** | **View** any of the above CSVs | filter, group, tag, colour, conditional formatting |

## Timeline Explorer — the review front end

Every tool above writes CSV designed for **Timeline Explorer** (`TimelineExplorer.exe`): load a CSV, then filter per column (Excel-style), full-text search, colour rows by condition, tag rows, and pin the timestamp column. Workflow: parse everything to one output folder with KAPE `!EZParser`, open the key CSVs (MFT, EVTX, Prefetch, Amcache) in tabs, and pivot between them by time/host/user. It handles million-row CSVs far better than Excel.

## Fast recipes

```powershell
# Timestomping triage: $MFT rows where $SI < $FN or zero nanoseconds
MFTECmd.exe -f "$MFT" --csv out --csvf mft.csv
#   → open in Timeline Explorer, filter SI<FN = TRUE, or uSecZeros = TRUE

# Dropped-tool timeline from the USN journal
MFTECmd.exe -f "$J" -m "$MFT" --csv out --csvf usn.csv
#   → filter UpdateReasons contains FileCreate, Extension in exe/dll/ps1

# Execution story on a workstation
PECmd.exe -d C:\t\Prefetch --csv out --csvf pf.csv          # ran + files touched
AmcacheParser.exe -f Amcache.hve --csv out -i               # SHA-1 of every binary
AppCompatCacheParser.exe -f SYSTEM --csv out                # existence + order

# Everything in the registry at once
RECmd.exe -d C:\t\Reg --bn BatchExamples\Kroll_Batch.reb --csv out --nl

# Event-log hunting after parsing
EvtxECmd.exe -d C:\t\Logs --csv out --inc 4624,4625,4648,4672,4688,4698,4720,7045,1102
```

## Gotchas

- **.NET runtime**: use the `net6`/matching build; the old `net4` builds are frozen. `Get-ZimmermanTools.ps1` fetches the right set.
- **Registry hives are often "dirty"** on a live capture — run `rla.exe` to replay `.LOG1/.LOG2` first, or the parse misses the most recent changes (often the persistence you're chasing).
- **EvtxECmd maps** define how each provider/EventID is flattened into columns — run `--sync` regularly; without maps you stare at `PayloadData3`.
- **AmcacheParser `-i`** includes files not tied to installed programs (where attacker tools live) — usually what you want; `-w` whitelists known-good hashes.
- Timestamps are **UTC**; get the system's timezone from the `SYSTEM` hive ([Registry keys](../windows/registry-keys.md#system-identity-timing)) before building a local-time narrative.
- These parse **artifacts you've already collected** — pair with [KAPE](kape.md)/[Velociraptor](velociraptor.md) for collection.

## References

- [Eric Zimmerman's tools (download + docs)](https://ericzimmerman.github.io/#!index.md)
- [Get-ZimmermanTools updater](https://github.com/EricZimmerman/Get-ZimmermanTools)
- [SANS Windows Forensic Analysis poster](https://www.sans.org/posters/windows-forensic-analysis/)
- Pages: [KAPE](kape.md) · [Windows forensics](../windows/index.md) — each artifact page lists its parser · [Plaso & timelining](plaso-timelines.md)
