---
title: Windows Forensics
---

# Windows Forensics

Host-based artifacts on Windows — where they live, what they prove, how to parse them. Start from the **question** you need to answer, then open the artifact pages.

## Artifact map — by question

| Question | Primary artifacts | Also check |
|---|---|---|
| **Did this program run? When? How often?** | [Prefetch](prefetch.md) · BAM/DAM ([Registry](registry-keys.md#program-execution-per-user-unless-noted)) · Security `4688` / Sysmon `1` ([Event logs](event-logs.md)) | [Shimcache](shimcache.md) (existence + order), [Amcache](amcache.md), UserAssist, [SRUM](srum.md) (hourly, with user) |
| **What *was* that binary?** (renamed / deleted) | [Amcache](amcache.md) — SHA-1 | [Prefetch](prefetch.md) file references, [$MFT](mft-usn.md) resident data, `MUICache` |
| **Which user ran it?** | BAM/DAM, UserAssist, [SRUM](srum.md), `4688` `SubjectUserName` | [LNK / Jump Lists](lnk-jumplists.md) under that profile |
| **Which files/folders did the user open?** | [LNK / Jump Lists](lnk-jumplists.md) · RecentDocs, OpenSavePidlMRU, Office MRU ([Registry](registry-keys.md#files-folders-opened-per-user)) | ShellBags (folders), Office Trusted Documents (macro docs) |
| **What happened to a file — created, renamed, deleted, stomped?** | [$UsnJrnl + $MFT](mft-usn.md) | `$LogFile`, `$I30` slack, Sysmon `11`, `4663` |
| **Where did the file come from?** | `Zone.Identifier` ADS in [$MFT](mft-usn.md) (URL) | Browser history, [LNK](lnk-jumplists.md) volume serial (USB), `5145` share access |
| **Was a USB device plugged in? Which one? Who used it?** | `USBSTOR`, `MountedDevices`, `MountPoints2` ([Registry](registry-keys.md#usb-removable-devices-system)) | `setupapi.dev.log`, `Partition/Diagnostic` `1006`, [LNK](lnk-jumplists.md) to `E:\` |
| **Did data leave the machine? How much?** | [SRUM](srum.md) Network Usage — bytes per app per hour | [$UsnJrnl](mft-usn.md) archive creation, Sysmon `3`, proxy/firewall/Zeek |
| **How did they get in / move laterally?** | `4624` type 3/10, `4648`, `4778`, RDP `21/25/1149`, `7045`, `5140/5145` ([Event IDs](../basics/windows-event-ids.md)) | WinRM / WMI-Activity channels, [Prefetch](prefetch.md) for `psexesvc`, `wsmprovhost` |
| **How do they persist?** | Run keys, Services, Scheduled tasks, WMI, COM hijack ([Registry ASEP](registry-keys.md#autostart-persistence-asep)) | `7045`, `4698`, WMI `5861`, Startup folders, Autoruns offline |
| **Was logging tampered with?** | `1102`, `104`, `4719`, record-ID gaps ([Event logs](event-logs.md#detecting-tampering)) | Oldest event per channel, `$UsnJrnl` vs. empty logs, VSS copies |
| **What's the system, timezone, users, network?** | `CurrentVersion`, `TimeZoneInformation`, `ProfileList`, `NetworkList`, SAM ([Registry](registry-keys.md#system-identity-timing)) | `setupapi`, DHCP lease in `Tcpip\Parameters` |

## Artifact pages

<div class="grid cards" markdown>

-   **[Prefetch](prefetch.md)** — execution, last 8 run times, files touched
-   **[Amcache](amcache.md)** — SHA-1 of every binary seen
-   **[Shimcache](shimcache.md)** — existence & order; works on servers
-   **[Registry keys](registry-keys.md)** — identity, user activity, USB, persistence
-   **[LNK & Jump Lists](lnk-jumplists.md)** — files/folders opened, USB serials
-   **[$MFT / $UsnJrnl / $LogFile](mft-usn.md)** — file system history, timestomping
-   **[SRUM](srum.md)** — bytes sent per app per hour, with user
-   **[Event logs](event-logs.md)** — channels, retention, parsing, tampering

</div>

## Collection order (when time is short)

1. **Memory** (if the box is live and you can) — then everything else.
2. `$MFT`, `$UsnJrnl:$J`, `$LogFile` — cheap, huge payoff.
3. Registry hives + transaction logs (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, every `NTUSER.DAT` + `UsrClass.dat`), `Amcache.hve`.
4. `C:\Windows\System32\winevt\Logs\*.evtx`.
5. `C:\Windows\Prefetch\`, `C:\Windows\System32\sru\`, users' `Recent\` (LNK + Jump Lists), PowerShell `ConsoleHost_history.txt`.
6. Browser data, `Tasks\`, `Startup` folders, `Temp` directories, `setupapi.dev.log`.

KAPE's `!SANS_Triage` compound target covers all of the above in a few minutes; Velociraptor's `Windows.KapeFiles.Targets` does the same remotely.

!!! info "Adding a page here"
    `python new.py windows/<name> -t artifact` — or just drop a `.md` file in `docs/windows/`. It appears in the sidebar automatically.
