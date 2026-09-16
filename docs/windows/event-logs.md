---
title: Windows Event Logs (EVTX)
tags:
  - artifact
  - windows
  - logs
---

# Windows Event Logs (EVTX)

<div class="dfir-meta" markdown>
**Category:** Logs · **OS:** Vista → 11 / Server 2008 → 2025 · **Last updated:** 2026-09-16
</div>

!!! abstract "In one sentence"
    Everything about *where* the logs live, which channels matter, how big they are before they roll, how to collect and parse them at scale, and how to tell whether someone has cleared or tampered with them — the **event ID** meanings themselves are on the [Windows Event IDs](../basics/windows-event-ids.md) page.

## Location & format

| Item | Detail |
|---|---|
| Directory | `C:\Windows\System32\winevt\Logs\` |
| File names | `Security.evtx`, `System.evtx`, `Application.evtx`, and `Microsoft-Windows-<Provider>%4<Channel>.evtx` (the `%4` is an encoded `/`) |
| Format | Binary XML in 64 KB chunks, each with its own CRC and record range; signature `ElfFile` (file header), `ElfChnk` (chunk) |
| Time | Stored **UTC** (`TimeCreated SystemTime`) — Event Viewer shows local |
| Record ID | `EventRecordID` increments per channel — **gaps** in a sequence mean records were lost/cleared/rolled |
| Registry (channel config) | `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>` (classic) and `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\<Channel>` (`Enabled`, `MaxSize`, `File`) |
| Forwarded logs | `ForwardedEvents.evtx` on a WEC collector; SIEM (Splunk UF / Winlogbeat / Sysmon → agent) |

### Default sizes (why the Security log only goes back a few days)

| Log | Default max | Typical retention on a busy box |
|---|---|---|
| Security | 20 MB (Win7/8); **up to 128 MB** or more on modern builds via GPO / defaults on Server | Hours to days — **the first thing to check** |
| System / Application | 20 MB | Weeks |
| PowerShell/Operational | 15 MB | Days when script-block logging is on |
| Sysmon/Operational | 64 MB (default in config) | Hours to days |
| Most `*Operational` channels | 1 MB (!) | Very short — e.g. TaskScheduler, WMI-Activity |

Retention mode is almost always **"Overwrite events as needed"**, so old records are gone silently. **Volume Shadow Copies** frequently contain older versions of `Security.evtx` — always check `vssadmin list shadows` / KAPE `--vss`.

## Channels worth grabbing (beyond Security/System/Application)

| Channel file | Why |
|---|---|
| `Microsoft-Windows-PowerShell%4Operational.evtx` | Script block logging `4104`, module `4103` |
| `Windows PowerShell.evtx` | Legacy PS engine `400/403/600` — includes `HostApplication` command line |
| `Microsoft-Windows-Sysmon%4Operational.evtx` | Sysmon (if deployed) — process, network, file, registry, DNS |
| `Microsoft-Windows-TaskScheduler%4Operational.evtx` | Task registration/execution (often disabled — check `Enabled`) |
| `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` | RDP `21/22/24/25` with source IP |
| `Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx` | RDP `1149` |
| `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx` | RDP `131`, `98` |
| `Microsoft-Windows-WinRM%4Operational.evtx` | PowerShell remoting client/server `6/91/168/169` |
| `Microsoft-Windows-WMI-Activity%4Operational.evtx` | WMI persistence `5857–5861`, remote WMI exec queries |
| `Microsoft-Windows-Windows Defender%4Operational.evtx` | Detections `1116/1117`, tamper `5001/5007`, exclusions |
| `Microsoft-Windows-Bits-Client%4Operational.evtx` | BITS downloads (`59/60/61`) — LOLBin download/persist |
| `Microsoft-Windows-DNS-Client%4Operational.evtx` | Client DNS (usually disabled; Sysmon 22 instead) |
| `Microsoft-Windows-SMBServer%4Security.evtx`, `SMBClient%4Connectivity/Security` | Share access errors, lateral movement fallout |
| `Microsoft-Windows-NTLM%4Operational.evtx` | NTLM auth details when auditing enabled |
| `Microsoft-Windows-Kernel-PnP%4Configuration.evtx`, `DriverFrameworks-UserMode%4Operational.evtx`, `Partition%4Diagnostic.evtx` | USB device plug/unplug |
| `Microsoft-Windows-CodeIntegrity%4Operational.evtx` | Unsigned/blocked drivers (`3033/3077`) |
| `Microsoft-Windows-AppLocker%4EXE and DLL.evtx` etc. | AppLocker blocks/audits `8002–8007` |
| `Microsoft-Windows-Shell-Core%4Operational.evtx` | Run-key execution `9707/9708` — shows the command from Run keys |
| `Microsoft-Windows-Storage-ClassPnP%4Operational.evtx`, `Ntfs%4Operational.evtx` | Volume/disk events |
| `Microsoft-Windows-Diagnosis-Scripted%4Operational.evtx`, `Windows-Kernel-Boot%4Operational.evtx` | Boot times — corroborate uptime and shutdown/clear timing |
| `OpenSSH%4Operational.evtx` | Win32-OpenSSH server logins |
| `Microsoft-Windows-Security-Mitigations%4KernelMode.evtx` | Exploit protection |

## How to collect

=== "KAPE"

    ```powershell
    # All EVTX + parse to CSV with EvtxECmd (uses community maps to flatten fields)
    kape.exe --tsource C: --tdest C:\Case\out --target EventLogs --mdest C:\Case\mod --module EvtxECmd --vss
    ```

=== "Velociraptor"

    `Windows.EventLogs.Evtx` (filter by channel / ID), `Windows.EventLogs.EvtxHunter` (regex hunt across all logs), and `Windows.EventLogs.RDPAuth`, `Windows.EventLogs.PowershellScriptblock` for common questions.

=== "Live copy"

    ```powershell
    # Locked by the EventLog service but readable; wevtutil exports cleanly
    wevtutil epl Security C:\Case\Security.evtx
    wevtutil el | ForEach-Object { wevtutil epl $_ ("C:\Case\" + ($_ -replace '[\\/]','%4') + ".evtx") }

    # Or raw copy the directory (fine — files are consistent per chunk)
    robocopy C:\Windows\System32\winevt\Logs C:\Case\Logs *.evtx
    ```

## How to parse

=== "EvtxECmd (Eric Zimmerman)"

    ```powershell
    # Everything → one CSV, with maps applied (PayloadData1..6 columns become meaningful)
    EvtxECmd.exe -d C:\Case\Logs --csv C:\Case\out --csvf evtx.csv

    # Only chosen IDs, time-bounded
    EvtxECmd.exe -d C:\Case\Logs --csv C:\Case\out --inc 4624,4625,4648,4672,4688,4698,4720,7045,1102 --sd "2026-09-01 00:00" --ed "2026-09-16 00:00"

    # Exclude the noisy ones
    EvtxECmd.exe -d C:\Case\Logs --csv C:\Case\out --exc 5156,5158,4658,4690

    # JSON for Splunk / jq
    EvtxECmd.exe -f C:\Case\Logs\Security.evtx --json C:\Case\out

    # Update the map files first (they define how each provider/ID is flattened)
    EvtxECmd.exe --sync
    ```

    Open the CSV in **Timeline Explorer**; the `MapDescription`, `UserName`, `RemoteHost`, `PayloadData*`, `ExecutableInfo` columns are what the maps give you.

=== "Chainsaw + Sigma (fast triage)"

    ```bash
    # Hunt with Sigma rules across a folder of EVTX; outputs a table of detections
    chainsaw hunt C:\Case\Logs -s sigma/ --mapping mappings/sigma-event-logs-all.yml -o hits.csv --csv

    # Quick searches
    chainsaw search -t 'Event.System.EventID: =4624' -t 'Event.EventData.LogonType: =10' C:\Case\Logs
    chainsaw search "mimikatz" -i C:\Case\Logs
    ```

    **Hayabusa** is the alternative (`hayabusa csv-timeline -d Logs -o out.csv`) — very fast, Sigma-based, colour-coded by severity, with a timeline `logon-summary` and `metrics` modes.

=== "PowerShell"

    ```powershell
    # From saved evtx files
    Get-WinEvent -Path C:\Case\Logs\Security.evtx -FilterXPath "*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='10']]" |
      Select TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='IP';e={$_.Properties[18].Value}}

    # Find the *oldest* record per log — tells you how far back you can see
    Get-ChildItem C:\Case\Logs\*.evtx | ForEach-Object {
      $e = Get-WinEvent -Path $_.FullName -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue
      [pscustomobject]@{Log=$_.Name; Oldest=$e.TimeCreated; SizeMB=[math]::Round($_.Length/1MB,1)} }
    ```

=== "Plaso / Python"

    ```bash
    log2timeline.py --parsers winevtx out.plaso /evidence/Logs/
    # python-evtx (low level)
    evtx_dump.py Security.evtx > Security.xml
    ```

## Detecting tampering

| Sign | What it means / where to look |
|---|---|
| Security **`1102`** "The audit log was cleared" (includes the account) | `wevtutil cl Security`, Event Viewer "Clear Log", Mimikatz `event::clear` |
| System **`104`** "The <name> log file was cleared" | Any non-Security channel cleared |
| Oldest record in Security is *minutes* old on a long-running box | Cleared (1102 might itself have been the only record left, or cleared again quickly) |
| **Gaps in `EventRecordID`** within a channel | Records dropped (log rolled) or selectively deleted (e.g. **DanderSpritz `eventlogedit`** style, which leaves "unreferenced" records recoverable by carving chunks) |
| Security `4719` audit policy change / `4907` SACL change / `4912` per-user audit policy | Attacker turned off logging for what came next |
| `4688` / `4104` simply absent where they should exist | Policy was never on — check `auditpol /get /category:*` and PowerShell GPO keys `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` |
| System `7036` EventLog service stopped/started; `7040` start type changed | Service stopped to write to logs directly or to suspend logging (**Phant0m**-style thread killing leaves *no* stop event but the service shows running while nothing is written — look for a flat line of zero events for hours while `$J` is busy) |
| Time changes: Security `4616` (system time changed), Kernel-General `1` | Time manipulation to confuse timelines |
| `.evtx` file's `$SI` created time is recent while others are old | File deleted and recreated by the service |
| Channel `Enabled = 0` in `WINEVT\Channels` registry | Someone disabled a channel (e.g. TaskScheduler) |

!!! tip "Corroborate with non-log evidence"
    When logs are gone: [$UsnJrnl](mft-usn.md) still shows file activity, [Prefetch](prefetch.md)/[Amcache](amcache.md) show execution, [SRUM](srum.md) shows network bytes per app per hour, and `1102` tells you *who* cleared the log and *when* — then look at what happened in the 10 minutes before that in every other artifact.

**Carving**: cleared logs can often be partially recovered from unallocated space and VSS with **EVTXtract** (`evtxtract image.dd > recovered.xml`) or by carving `ElfChnk` chunks (each 64 KB chunk is self-contained and parseable).

## Analysis tips

- **Check coverage first**: oldest event per channel, max size, `1102/104`, `4719`, `auditpol`. Write it in the report — "the Security log covered 2026-09-14 03:12 to 2026-09-16 09:40 only".
- **Time zone**: EVTX is UTC. Timeline Explorer / EvtxECmd output UTC; Event Viewer shows local. Say which one you're quoting.
- **Logon ID is the join key**: `4624` → `4672` (admin?) → `4634/4647` (session length) → `4688` with the same `SubjectLogonId` (what ran in that session).
- **Maps matter**: without EvtxECmd maps (or a SIEM's field extraction) you are staring at `PayloadData3`. Keep maps synced; write your own for in-house apps.
- **Sysmon changes everything** — if it exists, start there (`1`, `3`, `7`, `8`, `10`, `11`, `12–14`, `22`).
- **Server vs. workstation**: DCs have `4768/4769/4776` (Kerberos/NTLM for the whole domain) and are where you hunt Kerberoasting, spraying, golden tickets; workstations have the `4624 type 2/10` and process events.
- **Don't trust `Computer` field blindly**: forwarded/imported logs keep the original hostname — good; but attacker-renamed hosts can confuse.

## References

- [Microsoft — Windows Event Log (EVTX) & wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
- [libevtx — Windows XML Event Log format](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc)
- [EvtxECmd + maps](https://github.com/EricZimmerman/evtx)
- [Chainsaw](https://github.com/WithSecureLabs/chainsaw) · [Hayabusa](https://github.com/Yamato-Security/hayabusa) · [EVTXtract](https://github.com/williballenthin/EVTXtract)
- [JPCERT — Tool Analysis Result Sheet (which events each attack tool generates)](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [Windows Event IDs cheat page](../basics/windows-event-ids.md)
