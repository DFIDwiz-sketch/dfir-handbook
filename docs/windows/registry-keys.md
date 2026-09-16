---
title: Registry Keys for DFIR
tags:
  - artifact
  - windows
  - registry
---

# Registry Keys for DFIR

<div class="dfir-meta" markdown>
**Category:** Registry · **OS:** Windows 7 → 11 · **Last updated:** 2026-09-16
</div>

!!! abstract "In one sentence"
    The registry keys you actually open in an investigation, grouped by the question they answer — system identity, user activity, program execution, USB devices, network, and persistence.

## Hives and where they live

| Hive (as seen in regedit) | File on disk | Scope |
|---|---|---|
| `HKLM\SYSTEM` | `C:\Windows\System32\config\SYSTEM` | Services, drivers, ControlSets, mounted devices, Shimcache, BAM |
| `HKLM\SOFTWARE` | `C:\Windows\System32\config\SOFTWARE` | Installed software, OS version, Run keys (machine), profiles, network list |
| `HKLM\SAM` | `C:\Windows\System32\config\SAM` | Local accounts, RIDs, last logon, password hints |
| `HKLM\SECURITY` | `C:\Windows\System32\config\SECURITY` | LSA secrets, cached domain creds (needs SYSTEM bootkey) |
| `HKU\<SID>` | `C:\Users\<user>\NTUSER.DAT` | Per-user: Run keys, MRU lists, UserAssist, WordWheel, TypedPaths |
| `HKU\<SID>_Classes` | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | **ShellBags**, MUI cache, per-user COM/class registrations |
| `HKLM\BCD00000000` | `\Boot\BCD` (system partition) | Boot config |
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve` | [Amcache](amcache.md) |

Always grab the **transaction logs** (`*.LOG1`, `*.LOG2`) with each hive — recent changes may only exist there until the hive is flushed. Parsers like Registry Explorer / `rla.exe` replay them. Also check `C:\Windows\System32\config\RegBack\` (usually empty on modern Win10+) and Volume Shadow Copies for older hive versions.

`CurrentControlSet` is a symlink: read `SYSTEM\Select\Current` (usually `1` → `ControlSet001`). `LastKnownGood` points to the previous one.

## System identity & timing

| Question | Key | Notes |
|---|---|---|
| OS version, install date | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` | `ProductName`, `CurrentBuild`, `InstallDate` (epoch), `RegisteredOwner` |
| Computer name | `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName` | |
| Time zone | `SYSTEM\CurrentControlSet\Control\TimeZoneInformation` | `ActiveTimeBias` (minutes, sign inverted), `TimeZoneKeyName`. **Essential before building any timeline** |
| Last shutdown | `SYSTEM\CurrentControlSet\Control\Windows\ShutdownTime` | FILETIME |
| Network interfaces / IPs | `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}` | `DhcpIPAddress`, `DhcpServer`, `LeaseObtainedTime`, `DhcpDomain` |
| Networks joined (SSIDs, first/last connect) | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}` + `Signatures\Unmanaged` | `ProfileName`, `DateCreated`, `DateLastConnected` (128-bit SYSTEMTIME), `DefaultGatewayMac` — geolocate via BSSID |
| User profiles on box | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>` | `ProfileImagePath`, `LocalProfileLoadTimeLow/High`, `LocalProfileUnloadTime` |
| Local accounts | `SAM\Domains\Account\Users\<RID hex>` | `F` value: last logon, pwd last set, account expiry, bad pwd count, logon count; `V` value: username, full name, comment. Parse with RegRipper `samparse` |
| Prefetch on? | `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters` | `EnablePrefetcher` |
| Cleared page file at shutdown? | `...\Memory Management\ClearPageFileAtShutdown` | Anti-forensics hint |
| Last-access timestamps on? | `SYSTEM\CurrentControlSet\Control\FileSystem\NtfsDisableLastAccessUpdate` | `0x80000000`–`0x80000003` on Win10 1803+ = system managed (on for small volumes) |
| RDP enabled? | `SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections` | `0` = RDP allowed |
| Defender tampering | `SOFTWARE\Policies\Microsoft\Windows Defender` (`DisableAntiSpyware`, `DisableRealtimeMonitoring`), `...\Exclusions\Paths` | Attackers add exclusions before dropping tools |
| WDigest cleartext creds | `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` | `1` = LSASS keeps plaintext → Mimikatz prep |
| LSA protection / RunAsPPL | `SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL` | |

## Program execution (per user unless noted)

| Key | What it records | Notes |
|---|---|---|
| **UserAssist** `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` | GUI-launched programs (Explorer, Start menu, shortcuts) with **run count, last run time, focus time** | Value names are **ROT-13**. `{CEBFF5CD-…}` = executables, `{F4E57C4B-…}` = shortcuts. Does *not* record console launches from cmd. |
| **BAM / DAM** `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` (Win10 1709+) | Full path of executables run + **last execution time**, per user SID | Background Activity Moderator. One of the few *"last executed"* timestamps with a *user* attached. Server 2019+ too. |
| **RecentApps** `NTUSER\Software\Microsoft\Windows\CurrentVersion\Search\RecentApps` | App + last access + files opened (Win10 1607–1709) | Removed in later builds |
| **MUICache** `UsrClass\Local Settings\Software\Microsoft\Windows\Shell\MuiCache` | Friendly name of executables run (from version resource) | No timestamps; proves the binary existed and was run via Explorer |
| **AppCompatFlags / Layers** `NTUSER\Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers` (also HKLM) | Programs the user set compat options on ("Run as administrator") | |
| **Store** `NTUSER\...\AppCompatFlags\Compatibility Assistant\Store` | Programs the PCA (Program Compatibility Assistant) observed — shows path of executed EXEs | Handy for installers/tools |
| **Shimcache** `SYSTEM\...\Session Manager\AppCompatCache` | See [Shimcache](shimcache.md) | System-wide |
| **RunMRU** `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` | Commands typed in **Win+R** | `MRUList` gives order |
| **TypedPaths** `NTUSER\...\Explorer\TypedPaths` | Paths typed in Explorer address bar | |
| **WordWheelQuery** `NTUSER\...\Explorer\WordWheelQuery` | Terms typed in Explorer/Start **search box** | |
| **PowerShell ConsoleHost_history** (not registry) | `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` | Every interactive PowerShell command, PS 5.1+ — listed here because you'll look for it at the same time |

## Files & folders opened (per user)

| Key | What it records | Notes |
|---|---|---|
| **RecentDocs** `NTUSER\...\Explorer\RecentDocs` (+ per-extension subkeys) | Files opened via Explorer/common dialogs, by extension | Key LastWrite = most recent; `MRUListEx` orders the rest. Pair with `.lnk` files in `Recent\` |
| **OpenSavePidlMRU** `NTUSER\...\Explorer\ComDlg32\OpenSavePidlMRU\<ext>` | Files chosen in **Open/Save dialogs** (browser downloads "Save As", attachments) | |
| **LastVisitedPidlMRU** `NTUSER\...\Explorer\ComDlg32\LastVisitedPidlMRU` | **Which executable** used the Open/Save dialog and the **last folder** it browsed | Ties program ↔ directory |
| **ShellBags** `UsrClass\Local Settings\Software\Microsoft\Windows\Shell\BagMRU` & `Bags`; also `NTUSER\Software\Microsoft\Windows\Shell\BagMRU` | Folders the user **browsed in Explorer** (local, network, removable, zip contents), with view settings and embedded **MFT reference + timestamps of the folder at the time** | Proves a folder existed and was viewed — even if deleted or on a since-removed USB. Parse with **SBECmd / ShellBags Explorer** |
| **Office MRU** `NTUSER\Software\Microsoft\Office\<ver>\<App>\File MRU` / `Place MRU` | Documents opened in Word/Excel/PowerPoint with **last-opened timestamp** | `[F00000000][T01D9A…]` — T = FILETIME hex |
| **Office Trusted Documents** `NTUSER\Software\Microsoft\Office\<ver>\<App>\Security\Trusted Documents\TrustRecords` | Documents where the user clicked **Enable Content / Enable Editing** | Malicious macro doc → this key. Timestamp = when trust granted |
| **Reading Locations** (Word) `...\Word\Reading Locations` | Last position in recently opened docs with date | |
| **MountPoints2** `NTUSER\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` | Volumes (incl. USB GUIDs, network shares) the **user** accessed | Ties a device to a *user*; see USB section |
| **Map Network Drive MRU** `NTUSER\...\Explorer\Map Network Drive MRU` | UNC paths mapped by the user | |

## USB & removable devices (system)

| Key | What it records |
|---|---|
| `SYSTEM\CurrentControlSet\Enum\USBSTOR\<Ven_Prod_Rev>\<SerialNo>` | Vendor, product, **serial number** (if the `&` is at position 2 it's a Windows-generated ID, not a real serial). Subkey `Properties\{83da6326-…}\0064` = first install, `0066` = last connected, `0067` = last removed (Win8+) |
| `SYSTEM\CurrentControlSet\Enum\USB\VID_xxxx&PID_xxxx\<Serial>` | Same device by VID/PID; `Properties` timestamps as above |
| `SYSTEM\MountedDevices` | Maps `\DosDevices\E:` and `\??\Volume{GUID}` ↔ device string containing the serial |
| `SOFTWARE\Microsoft\Windows Portable Devices\Devices` | **Friendly name / volume label** of the device |
| `SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt` | ReadyBoost — volume serial number ↔ device (older systems, spinning disks) |
| `NTUSER\...\Explorer\MountPoints2\{Volume GUID}` | **Which user** had the volume mounted (key LastWrite = last mount by that user) |
| `SYSTEM\CurrentControlSet\Enum\SWD\WPDBUSENUM` | Portable devices (phones, cameras) |
| Also (not registry) | `C:\Windows\inf\setupapi.dev.log` — first plug-in time with driver install details |

## Autostart / persistence (ASEP)

| Key | Notes |
|---|---|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `RunOnce`, `RunOnceEx` | Machine-wide, runs at any logon |
| `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, `RunOnce` | Per user |
| `HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run` | 32-bit view on 64-bit — often forgotten |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` and HKCU equivalent | Policy-based Run |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` | `Shell` (should be `explorer.exe`), `Userinit` (should be `C:\Windows\system32\userinit.exe,`), `Notify` |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<exe>` | `Debugger` value → hijack (e.g. sticky keys `sethc.exe` → `cmd.exe`); `GlobalFlag` + `SilentProcessExit` combo |
| `HKLM\SYSTEM\CurrentControlSet\Services\<name>` | `ImagePath`, `Start` (2 = auto), `Type`, `ServiceDll` under `Parameters` for svchost-hosted services. New service = System `7045` |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` (+ `LoadAppInit_DLLs`) | DLL injected into every process loading user32.dll |
| `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute` | Should be `autocheck autochk *` only |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` — `Authentication Packages`, `Security Packages`, `Notification Packages` | SSP injection (Mimikatz `memssp`, custom password filters) |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree` & `Tasks\{GUID}` | Scheduled task registry side; `Actions` blob has the command. Compare against `C:\Windows\System32\Tasks\*` XML — a task **missing from Tree but present in Tasks** is a hidden task |
| `HKLM\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32` and `HKCU\Software\Classes\CLSID\...` | **COM hijacking** — HKCU overrides HKLM |
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`, `ShellExecuteHooks`, `ShellServiceObjectDelayLoad` | Explorer/IE extension points |
| `HKLM\SOFTWARE\Microsoft\Netsh` | Netsh helper DLLs |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Font Drivers`, `Print\Monitors`, `Print\Providers` | Rarer, driver-level ASEPs |
| `HKCU\Environment\UserInitMprLogonScript` | Logon script run at logon — classic, quiet |
| `HKCU\Software\Microsoft\Command Processor\AutoRun` (and HKLM) | Runs every time `cmd.exe` starts |
| `HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components\{GUID}\StubPath` | Runs once per user at logon |
| Startup folders (not registry) | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`, `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp` |

Use **Autoruns** (`autorunsc.exe -a * -c -h -s -v -zip`) or the RegRipper `autoruns`-style plugins to sweep all of these at once; on an offline image, Autoruns can analyze a mounted system with **File → Analyze Offline System**.

## Parsing

=== "Registry Explorer / RECmd (Eric Zimmerman)"

    ```powershell
    # Batch mode with the community "Kroll" batch file — hits most keys above in one go
    RECmd.exe -d C:\Case\Registry --bn BatchExamples\Kroll_Batch.reb --csv C:\Case\out --nl

    # Replay transaction logs into a clean hive first if the tool complains the hive is dirty
    rla.exe -d C:\Case\Registry --out C:\Case\Registry\clean
    ```

    GUI: **Registry Explorer** has bookmarks for every key on this page and shows deleted keys/values from slack space.

=== "RegRipper 3"

    ```bash
    rip.pl -r NTUSER.DAT -f ntuser   > ntuser.txt
    rip.pl -r UsrClass.dat -f usrclass > usrclass.txt
    rip.pl -r SYSTEM -f system > system.txt
    rip.pl -r SOFTWARE -f software > software.txt
    rip.pl -r SAM -f sam > sam.txt
    # single plugins
    rip.pl -r NTUSER.DAT -p userassist
    rip.pl -r SYSTEM -p bam
    rip.pl -r SYSTEM -p usbstor
    ```

=== "Live (PowerShell)"

    ```powershell
    # Run keys, both hives, both views
    Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run'

    # BAM last-executed per SID
    Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings' | ForEach-Object {
      $sid=$_.PSChildName; Get-ItemProperty $_.PSPath | Select-Object -Property * -ExcludeProperty PS* |
      ForEach-Object { $_.PSObject.Properties | Where-Object { $_.Value -is [byte[]] } |
      ForEach-Object { [pscustomobject]@{SID=$sid; Path=$_.Name; Last=[DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($_.Value,0))} } } }
    ```

## Analysis tips

!!! tip "Every key has a LastWrite time — use it"
    Even keys without an explicit timestamp value (MUICache, RecentDocs subkeys, USBSTOR) tell you *when the key was last changed*. For MRU-style keys that equals the most recent entry's time.

- **Timezone first.** Registry FILETIMEs are UTC; event logs are UTC; `$SI` timestamps are UTC — but the *user's view* and many application logs are local. Pull `TimeZoneInformation` before anything else.
- **Deleted keys are recoverable.** Registry Explorer and `yarp`/`regipy` can carve unallocated cells — deleted Run values and services frequently survive.
- **HKCU beats HKLM for COM.** A CLSID under `HKCU\Software\Classes` overrides the machine one silently — hunt for `InprocServer32` values pointing to user-writable paths.
- **Dirty hives.** If the box was imaged live, apply `.LOG1/.LOG2` (rla.exe) or you can miss the last minutes of activity — often exactly the persistence being installed.

## References

- [SANS Windows Forensic Analysis poster](https://www.sans.org/posters/windows-forensic-analysis/)
- [Eric Zimmerman — Registry Explorer / RECmd / RECmd batch files](https://github.com/EricZimmerman/RECmd)
- [RegRipper 3.0](https://github.com/keydet89/RegRipper3.0)
- [Harlan Carvey — Windows Registry Forensics, 2nd ed.](https://www.elsevier.com/books/windows-registry-forensics/carvey/978-0-12-803291-6)
- [MITRE ATT&CK T1547 — Boot or Logon Autostart Execution](https://attack.mitre.org/techniques/T1547/)
