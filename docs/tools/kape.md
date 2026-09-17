---
title: KAPE
tags:
  - tool
  - windows
  - collection
  - triage
---

# KAPE

<div class="dfir-meta" markdown>
**Category:** Triage collection & parsing · **Platform:** Windows · **Last updated:** 2026-09-17
</div>

!!! abstract "What it does"
    KAPE (Kroll Artifact Parser and Extractor) does two things: **Targets** copy forensic artifacts off a live or mounted system (fast, defeats file locks via raw NTFS reads), and **Modules** run third-party tools over what was collected to produce CSV/JSON output. One command turns a running machine into a folder of parsed evidence in minutes. Free for use; GUI (`gkape.exe`) and CLI (`kape.exe`).

## The mental model

```mermaid
flowchart LR
    S[Live / mounted system] -->|Targets: copy files| C[tout: collected artifacts]
    C -->|Modules: run tools| M[mout: parsed CSV/JSON]
    M --> TE[Timeline Explorer / review]
```

- **Target** = *what to copy* (a `.tkape` file listing paths/masks). `--tsource` where to read, `--tdest` where to write.
- **Module** = *what to run* (a `.mkape` file wrapping a tool + arguments). `--msource` (usually = tdest) and `--mdest` where output goes.
- You can run Targets only, Modules only, or both in one pass.

## The commands you actually use

```powershell
# Full triage of C: — the "just collect the important stuff" command
kape.exe --tsource C: --tdest E:\%d\tout --target !SANS_Triage --vss

# Collect AND parse in one pass (triage → CSVs ready for Timeline Explorer)
kape.exe --tsource C: --tdest E:\%d\tout --target !SANS_Triage `
         --msource E:\%d\tout --mdest E:\%d\mout --module !EZParser --vss

# One artifact family
kape.exe --tsource C: --tdest E:\out --target EventLogs --mdest E:\out\m --module EvtxECmd
kape.exe --tsource C: --tdest E:\out --target RegistryHives --mdest E:\out\m --module RECmd_BatchExamples

# Parse an already-collected folder (Modules only)
kape.exe --msource E:\out\tout --mdest E:\out\mout --module !EZParser

# Mounted image (E01/VHD mounted read-only as F:)
kape.exe --tsource F: --tdest E:\out --target !SANS_Triage
```

Handy flags: `%d` / `%m` in a path expand to date / machine name (keeps cases separate); `--vss` also pulls from Volume Shadow Copies (older versions of files — huge for extending log/journal history); `--vhdx CASE` writes the collection into a VHDX container instead of loose files; `--zip NAME` zips it; `--gui` opens the file picker; `--debug`/`--trace` for troubleshooting; `--tflush`/`--mflush` clear the destination first.

## Targets worth knowing

| Target | Collects |
|---|---|
| `!SANS_Triage` | The all-in-one: `$MFT`, `$J`, `$LogFile`, registry hives + logs, EVTX, Prefetch, Amcache, SRUM, LNK/JumpLists, scheduled tasks, browser data, PowerShell history, WMI, and more — start here |
| `!BasicCollection` | Smaller core set |
| `KapeTriage` | Similar broad triage compound target |
| `FileSystem` | `$MFT`, `$J`, `$LogFile`, `$Boot`, `$SDS` |
| `RegistryHives`, `RegistryHivesSystem`, `RegistryHivesUser` | SYSTEM/SOFTWARE/SAM/SECURITY, NTUSER.DAT, UsrClass.dat + transaction logs |
| `EventLogs` | All `.evtx` |
| `Prefetch`, `Amcache`, `SRUM` | Named artifacts |
| `LNKFilesAndJumpLists`, `RecentFileCache` | File-knowledge |
| `WebBrowsers`, `Chrome`, `Edge`, `Firefox` | Browser history/cache/downloads |
| `ScheduledTasks`, `WindowsTimeline`, `PowerShellConsole` | as named |
| `RDPCache`, `EventTraceLogs`, `MFTMirror` | niche but useful |

Targets compose: `!SANS_Triage` is a *compound* target that pulls in dozens of others. List them with `--tlist` or browse the `Targets\` folder.

## Modules worth knowing

| Module | Runs |
|---|---|
| `!EZParser` | The compound module — runs all the Eric Zimmerman parsers over a triage collection (MFTECmd, EvtxECmd, PECmd, AmcacheParser, AppCompatCacheParser, RECmd, LECmd, JLECmd, SrumECmd, SBECmd, …) → one CSV per artifact |
| `EvtxECmd`, `PECmd`, `MFTECmd`, `AmcacheParser`, `AppCompatCacheParser`, `RECmd_*`, `LECmd`, `JLECmd`, `SrumECmd`, `SBECmd` | Individual [Zimmerman tools](zimmerman-tools.md) |
| `hayabusa`, `Chainsaw` | Sigma-based EVTX hunting → detections CSV |
| `Nirsoft_*`, `RegRipper` | Alternative parsers |
| `VirusTotal`, `Loki`, `capa` | Enrichment / malware triage (some need keys/binaries in the module's `bin` folder) |

Modules need the actual tool binary present — KAPE looks in `Modules\bin\`. `--mlist` lists them; `Get-KAPEUpdate.ps1` (ships with KAPE) updates Targets/Modules from the community repo.

## Typical workflow

1. Boot to the subject (or mount its image read-only), plug in an evidence drive `E:`.
2. `kape.exe --tsource C: --tdest E:\%d\tout --target !SANS_Triage --vss` — collect (minutes).
3. `kape.exe --msource E:\%d\tout --mdest E:\%d\mout --module !EZParser` — parse (can be done later, off-host).
4. Open `mout` in **Timeline Explorer**; start with `MFTECmd` (`$MFT`/`$J`), EVTX, Prefetch, Amcache.
5. For hunting, also run `--module hayabusa` or `Chainsaw` over the EVTX.

!!! tip "Collect on-host, parse off-host"
    Targets are fast and safe to run on a live machine; Modules are heavier and pull in third-party tools. Standard practice: run **Targets** on the subject to a removable/network drive, then run **Modules** on your analysis workstation against that collection. Keeps the subject's footprint small and lets you re-parse without touching it again.

## Gotchas

- **Run as Administrator** — raw volume reads and locked files need it.
- `--tdest` should be a **different volume** than `--tsource` (don't write evidence onto the subject).
- `--vss` multiplies collection size and time; worth it when you need history, skip for a quick look.
- Modules silently do nothing if the tool binary is missing from `Modules\bin\` — check `--mlist` and the console output.
- KAPE reads NTFS directly, so it copies locked/system files, but it is **not** a full disk image — for a forensic image use [imaging tools](imaging-collection.md).
- Output timestamps are UTC (the Zimmerman parsers default to UTC); confirm in Timeline Explorer.

## References

- [KAPE documentation (Kroll)](https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape)
- [KapeFiles — community Targets & Modules](https://github.com/EricZimmerman/KapeFiles)
- [KAPE docs site](https://ericzimmerman.github.io/KapeDocs/)
- Pages: [Zimmerman tools](zimmerman-tools.md) · [Velociraptor](velociraptor.md) · [Imaging & collection](imaging-collection.md) · [Windows forensics](../windows/index.md)
