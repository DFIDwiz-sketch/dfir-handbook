---
title: SRUM
tags:
  - artifact
  - windows
  - execution
  - network
---

# SRUM (System Resource Usage Monitor)

<div class="dfir-meta" markdown>
**Category:** Execution + network usage history · **OS:** Windows 8 → 11 · **Last updated:** 2026-09-16
</div>

!!! abstract "In one sentence"
    SRUM is Windows' built-in usage accounting database: for every hour of the last ~30–60 days it records **which application ran, under which user, how much CPU it used, and how many bytes it sent and received on which network** — the artifact that turns "a tool ran" into "it uploaded 3.2 GB to the internet on Tuesday between 02:00 and 03:00".

## What it tells you

| Table (provider) | What you get |
|---|---|
| **Network Data Usage** `{973F5D5C-1D90-4944-BE8E-24B94231A174}` | Per app, per user SID, per interface / network profile: **BytesSent, BytesRecvd**, hourly buckets |
| **Network Connectivity** `{DD6636C4-8929-4683-974E-22C046A43763}` | Interface connect/disconnect times, connected duration, network profile (SSID) |
| **Application Resource Usage** `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` | Per app, per user: **foreground/background CPU time, bytes read/written, face time**, hourly |
| **App Timeline** `{5C8CF1C7-7257-4F13-B223-970EF5939312}` (Win10+) | App start/end, foreground durations — more granular timeline |
| **Energy Usage** `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}` (+ `LT`) | Battery levels — shows when a laptop was on / charging |
| **Push Notifications** `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}` | Notification payload sizes per app |
| **VFU / Tagged Energy** `{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}` | Video / misc |

Every row carries a **timestamp (hourly, UTC)**, an **AppId** (index into `SruDbIdMapTable` → executable path or package name), and a **UserId** (→ SID). Retention: the on-disk ESE database holds roughly **30 days** for most tables (60 for network on some builds); the last hour lives only in the registry until flushed.

!!! warning "Flush timing"
    SRUM writes from memory to `SRUDB.dat` about **every 60 minutes** and at **shutdown**. A live image taken 20 minutes into the hour is missing the current hour. To force a flush, a **clean shutdown** works — but do not shut down a machine you want a memory image from.

## Location

| Item | Path |
|---|---|
| Database | `C:\Windows\System32\sru\SRUDB.dat` (ESE / JET Blue format, same engine as Exchange & Windows Search) |
| ESE logs | `C:\Windows\System32\sru\*.log`, `*.jrs`, `*.chk` — collect them; the DB is often in a **dirty state** |
| Registry (live buffer + settings) | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions\{provider GUID}` |
| Needed for resolving names | `SOFTWARE` hive (network profile names via `NetworkList`, interface GUIDs); user SIDs → `ProfileList` |

## How to collect

=== "KAPE"

    ```powershell
    kape.exe --tsource C: --tdest C:\Case\out --target SRUM,RegistryHivesSystem --mdest C:\Case\mod --module SrumECmd
    ```

    The `SRUM` target grabs `SRUDB.dat` plus the log/jrs files.

=== "Velociraptor"

    `Windows.Forensics.SRUM` — parses live, outputs Network Usage, App Resource Usage, Execution stats as separate tables.

=== "Manual (locked file)"

    ```powershell
    RawCopy.exe /FileNamePath:C:\Windows\System32\sru\SRUDB.dat /OutputPath:C:\Case\sru
    robocopy C:\Windows\System32\sru C:\Case\sru *.log *.jrs *.chk
    reg save HKLM\SOFTWARE C:\Case\SOFTWARE
    ```

## How to parse

=== "SrumECmd (Eric Zimmerman)"

    ```powershell
    # -f database, -r SOFTWARE hive (resolves interface / profile names). Produces one CSV per table.
    SrumECmd.exe -f C:\Case\sru\SRUDB.dat -r C:\Case\SOFTWARE --csv C:\Case\out
    ```

    If the DB is dirty, repair first (needs Windows, `esentutl` version ≥ source OS):

    ```powershell
    esentutl.exe /r sru /i /d      # replay logs, run inside the folder with the .log files
    esentutl.exe /p SRUDB.dat      # hard repair — last resort, may lose rows
    ```

    Output files: `*_SrumECmd_NetworkUsages_Output.csv`, `*_AppResourceUseInfo_Output.csv`, `*_NetworkConnections_Output.csv`, `*_AppTimelineProvider_Output.csv`, `*_EnergyUsage_Output.csv`, `*_PushNotifications_Output.csv`.

=== "srum-dump (Mark Baggett)"

    ```powershell
    # GUI or CLI → Excel workbook with one sheet per table; template controls column names
    srum_dump.exe -i C:\Case\sru\SRUDB.dat -t SRUM_TEMPLATE2.xlsx -r C:\Case\SOFTWARE -o C:\Case\out\srum.xlsx
    ```

=== "Plaso"

    ```bash
    log2timeline.py --parsers esedb/srum out.plaso SRUDB.dat
    ```

## Analysis tips

!!! tip "Exfil in three columns"
    In `NetworkUsages`: `stats sum(BytesSent) by ExeInfo, SidType/UserName, day`. Anything user-launched (not `svchost`, `MsMpEng`, backup agents, OneDrive) sending **hundreds of MB** in one hour, especially at night, especially `rclone.exe`, `megasync.exe`, `winscp.exe`, `curl.exe`, `powershell.exe`, `7z.exe`'s sibling, or a random name in `Users\Public` — that's your exfil candidate, with the hour it happened and the interface (VPN vs. Wi-Fi) it used.

- **Proves execution *and* user** where Prefetch cannot (Prefetch has no user; 4688 may be off). `AppResourceUseInfo` gives *hourly* execution evidence with SID, CPU time and I/O bytes.
- **Ratio matters**: `BytesSent >> BytesRecvd` = upload/exfil; `BytesRecvd >> BytesSent` = download/staging; both high and symmetrical = tunnel/proxy (chisel, ngrok, RDP relaying).
- **Tie network profile to place**: `NetworkConnections` + `NetworkList` profile → the laptop was on "CoffeeShop_WiFi" at that hour; combine with BSSID for geolocation.
- **Deleted tools still appear** — the `SruDbIdMapTable` keeps the path string.
- **Interface GUID → adapter**: `SOFTWARE\...\NetworkCards` / `SYSTEM\...\Tcpip\Parameters\Interfaces` — distinguish VPN adapter vs. physical NIC vs. hotspot.
- **Hour granularity**: a row stamped `14:00` covers activity **13:00–14:00** (end of bucket). Don't over-interpret exact minutes; use `$J` / Sysmon 3 / firewall logs for that.
- **Battery / energy table** tells you whether a laptop was even powered on during a window the user claims it was off.
- **Anti-forensics**: deleting `SRUDB.dat` (service recreates an empty one → big gap + brand-new file creation time), stopping the `DPS` (Diagnostic Policy Service) which hosts SRUM.

## Timeline / correlation

| Question | Cross-check with |
|---|---|
| What was the tool that sent the data? | [Amcache](amcache.md) SHA-1, [Prefetch](prefetch.md) file references |
| Where did it send it? | Sysmon 3 / `5156` WFP (if on), firewall or proxy logs, Zeek `conn.log` (`orig_bytes` by `id.orig_h`), DNS cache / Sysmon 22 |
| What did it collect first? | [$MFT / USN](mft-usn.md) — archive creation in the hour before the spike |
| Which session / logon? | `4624` for the SID in that hour, RDP `21/25` if remote |
| Same behaviour elsewhere? | Velociraptor `Windows.Forensics.SRUM` hunt across fleet, filter by exe or by BytesSent threshold |

## References

- [Yogesh Khatri — SRUM forensics (SANS DFIR Summit 2015)](https://www.sans.org/presentations/srum-forensics/)
- [Mark Baggett — srum-dump](https://github.com/MarkBaggett/srum-dump)
- [Eric Zimmerman — SrumECmd](https://ericzimmerman.github.io/#!index.md)
- [Velociraptor — Windows.Forensics.SRUM](https://docs.velociraptor.app/artifact_references/pages/windows.forensics.srum/)
