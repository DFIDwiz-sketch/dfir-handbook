---
title: $MFT, $UsnJrnl & $LogFile
tags:
  - artifact
  - windows
  - ntfs
  - filesystem
---

# $MFT, $UsnJrnl & $LogFile

<div class="dfir-meta" markdown>
**Category:** NTFS file system metadata · **OS:** any NTFS volume · **Last updated:** 2026-09-16
</div>

!!! abstract "In one sentence"
    The Master File Table is the index of every file on the volume (with **two sets of timestamps** that let you catch timestomping), the USN change journal is a **log of every file operation** for the last days/weeks (create, rename, delete, modify), and `$LogFile` is a short, very detailed transaction log — together they reconstruct *what happened to files*, including ones long since deleted.

## What they tell you

| Artifact | Answers | Retention |
|---|---|---|
| `$MFT` | What files exist(ed), where, how big, all 8 timestamps, resident data of tiny files, ADS (Zone.Identifier!), parent directory, deleted entries not yet reused | Until entry reused |
| `$UsnJrnl:$J` | *When* a file was created / renamed / deleted / written / had attributes changed, with **file name and parent MFT reference**, in order | Typically 1–4 weeks on a busy workstation (default max 32 MB, grows) |
| `$LogFile` | Low-level NTFS transactions (MFT record updates, index changes) — can recover **full previous MFT record contents** | Hours to a couple of days (default 64 MB, circular) |
| `$I30` index attributes (directories) | Slack entries for deleted files with their names and timestamps | Until slack overwritten |

## Location

All are NTFS metafiles in the root of each volume, hidden from normal listing:

| File | MFT record # | Notes |
|---|---|---|
| `C:\$MFT` | 0 | Also `$MFTMirr` (record 1) – first 4 records |
| `C:\$LogFile` | 2 | |
| `C:\$Extend\$UsnJrnl` | in `$Extend` (11) | Two streams: `$Max` (settings) and **`$J`** (the actual journal, sparse — only the tail has data) |
| `C:\$Extend\$RmMetadata\$TxfLog\...` | | Transactional NTFS — rarely needed |

You need a **raw-reading** tool (KAPE, FTK Imager, RawCopy, `icat` from Sleuth Kit, Velociraptor) — normal APIs refuse to open them.

## $MFT record essentials

Every record is **1024 bytes** (signature `FILE`). Attributes you care about:

| Attribute | Type | Content |
|---|---|---|
| `$STANDARD_INFORMATION` (**$SI**) | 0x10 | **Created, Modified, MFT-Changed, Accessed** (MACE), flags (hidden, system, …), owner/security ID, USN. **This is what Explorer / `dir` show — and what timestomping tools change** |
| `$FILE_NAME` (**$FN**) | 0x30 | Name (long + 8.3 as separate attributes), parent directory reference, **its own MACE set**, size. **Updated only by the kernel** on create/rename/move — user-mode tools cannot set it directly |
| `$DATA` | 0x80 | File content: **resident** (≤ ~700 bytes, inside the record) or non-resident (data runs). Named `$DATA` streams = **Alternate Data Streams** (`file.exe:Zone.Identifier`) |
| `$ATTRIBUTE_LIST` | 0x20 | Present when attributes overflow into extension records |
| `$INDEX_ROOT` / `$INDEX_ALLOCATION` | 0x90 / 0xA0 | Directory contents (`$I30`) |
| `$OBJECT_ID` | 0x40 | GUID used by link tracking (matches LNK ObjectID) |
| Header fields | | Sequence number (increments on reuse), hard-link count, **in-use / directory flags**, base record reference, **`$LogFile` sequence number (LSN)** |

`MFT reference` = 48-bit entry number + 16-bit sequence number. A deleted entry keeps its content (flag = not in use) until reused; the sequence bump tells you a reference in an LNK or Jump List points to an *older* incarnation.

### Timestamp rules (the ones that catch timestomping)

| Observation | Meaning |
|---|---|
| `$SI` Created **earlier than** `$FN` Created | Almost always **timestomping** (the file cannot have existed before its own directory entry). Exception: some installers / robocopy `/COPY:DAT` preserving original times |
| `$SI` timestamps with **zero nanoseconds** (`.0000000`) | Set via an API that takes seconds (many stomping tools, `touch`-style, PowerShell `[IO.File]::SetCreationTime` gives full precision though) |
| `$SI` Modified **older than** `$SI` MFT-Changed by a lot, with `$FN` matching the MFT-Changed time | File was stomped; the MFT-Changed time records when the stomp happened |
| `$FN` times **newer** than `$SI` | File was **moved/renamed** after stomping, or copied (copy → new `$FN` create) |
| Created ≠ Modified on a freshly dropped executable | Copied from elsewhere (Modified travels with the file; Created is set on write to this volume) |

!!! warning "$FN can be updated legitimately"
    On **rename or move within the volume**, Windows copies the current `$SI` values into the new `$FN` — so a stomped file that is then renamed gets stomped-looking `$FN` times too. Compare with the USN journal for the truth.

### Zone.Identifier — where did it come from?

The `Zone.Identifier` ADS on a downloaded file contains `ZoneId=3` (Internet) and, on modern Windows, **`ReferrerUrl`** and **`HostUrl`** — the actual download URL. Check it with `Get-Content file.exe -Stream Zone.Identifier` live, or MFTECmd's `ZoneIdContents` column offline. Files extracted from a zip inherit it; files copied via `copy`/`xcopy` keep it; `Unblock-File` or **Mark-of-the-Web removal** by the attacker deletes it.

## USN journal ($J) essentials

Each record: **USN** (offset), **timestamp**, **file reference** (MFT # + seq), **parent reference**, **reason flags**, file name. Reasons accumulate across a "session" until `USN_REASON_CLOSE`:

| Reason flag | Meaning |
|---|---|
| `FILE_CREATE` | New file/dir |
| `FILE_DELETE` | Deleted |
| `RENAME_OLD_NAME` / `RENAME_NEW_NAME` | Rename or move (two records; new one shows destination parent) |
| `DATA_EXTEND` / `DATA_OVERWRITE` / `DATA_TRUNCATION` | Content written / replaced / shrunk |
| `BASIC_INFO_CHANGE` | **Timestamps or attributes changed** — timestomping leaves this |
| `SECURITY_CHANGE` | ACL change |
| `NAMED_DATA_*` | Alternate Data Stream written (Zone.Identifier being added, or removed via `STREAM_CHANGE`) |
| `HARD_LINK_CHANGE`, `REPARSE_POINT_CHANGE`, `OBJECT_ID_CHANGE`, `INDEXABLE_CHANGE`, `CLOSE` | as named |

The journal has **no full paths** — only parent MFT references. Parsers rebuild paths by joining against `$MFT`; if the parent was itself deleted and reused you may get a partial path — that is why MFTECmd wants both files together.

## How to collect

=== "KAPE"

    ```powershell
    # $MFT, $J, $LogFile, $Boot, $I30 slack — in one go, then parse
    kape.exe --tsource C: --tdest C:\Case\out --target "$MFT,$J,$LogFile,$Boot" --mdest C:\Case\mod --module MFTECmd
    ```

=== "Velociraptor"

    `Windows.NTFS.MFT` (huge), `Windows.Forensics.Usn`, `Windows.NTFS.Recover` (recover deleted file data by MFT id).

=== "Live raw copy"

    ```powershell
    RawCopy.exe /FileNamePath:C:0 /OutputPath:C:\Case           # $MFT (record 0)
    RawCopy.exe /FileNamePath:C:2 /OutputPath:C:\Case           # $LogFile
    ExtractUsnJrnl64.exe /DevicePath:C: /OutputPath:C:\Case     # $J (only the non-sparse part)
    ```

=== "Sleuth Kit (image)"

    ```bash
    mmls image.E01                                    # find NTFS partition offset
    icat -o 2048 image.E01 0 > MFT                    # record 0
    fls -o 2048 -r -m C: image.E01 > bodyfile         # quick $SI/$FN body file
    ```

## How to parse

=== "MFTECmd (Eric Zimmerman)"

    ```powershell
    # $MFT → CSV (one row per file, both $SI and $FN timestamps side by side)
    MFTECmd.exe -f C:\Case\$MFT --csv C:\Case\out --csvf mft.csv

    # $MFT → bodyfile for a super-timeline (mactime / Timeline Explorer)
    MFTECmd.exe -f C:\Case\$MFT --body C:\Case\out --bodyf mft.body --bdl C

    # $J with $MFT for full paths
    MFTECmd.exe -f C:\Case\$J -m C:\Case\$MFT --csv C:\Case\out --csvf usn.csv

    # Dump one record (by entry number or path) in full detail
    MFTECmd.exe -f C:\Case\$MFT --de 0x2A3F
    MFTECmd.exe -f C:\Case\$MFT --dd C:\Case\resident --do 0x2A3F     # carve resident data

    # $LogFile (limited support) / $Boot / $I30
    MFTECmd.exe -f C:\Case\$Boot --csv C:\Case\out
    MFTECmd.exe -f C:\Case\$I30 --csv C:\Case\out
    ```

    In the `$MFT` CSV look at: `InUse`, `ParentPath`, `FileName`, `Extension`, `FileSize`, `Created0x10` vs `Created0x30`, `LastModified0x10` vs `0x30`, `SI<FN` (**true = suspicious**), `uSecZeros`, `Copied`, `ZoneIdContents`, `HasAds`, `IsAds`, `Timestomped`.

=== "Plaso / analyzeMFT / others"

    ```bash
    log2timeline.py --parsers "mft,usnjrnl" out.plaso /evidence/       # Plaso
    analyzeMFT.py -f '$MFT' -o mft.csv --bodyfull                       # analyzeMFT (older)
    ```

    **`$LogFile`**: `LogFileParser` (jschicht), `NTFS Log Tracker` (Korean tool — Windows GUI, parses $LogFile + $UsnJrnl + $MFT together, very good). **`$I30` slack**: `INDXParse.py`, MFTECmd `-f $I30`.

## Analysis tips

!!! tip "The 30-second workflow"
    1. `MFTECmd $J` → filter `UpdateReasons` contains `FileCreate` and `Extension` in `.exe .dll .ps1 .bat .vbs .zip .7z .rar` inside the incident window. That is your dropped-tool list.
    2. For each hit, open the `$MFT` row → check `SI<FN`, `ZoneIdContents` (download URL!), `ParentPath`.
    3. `$J` filter `FileDelete` for the same names → when the attacker cleaned up. Filter `RenameNewName` → what they renamed tools to.
    4. `$J` `BasicInfoChange` on the tool → timestomping moment.

- **Deleted ≠ gone**: an `$MFT` record with `InUse = False` still holds name, timestamps, size and (if resident) the **entire content** of small files — batch scripts, config, `.lnk`, small text loot lists.
- **Mass activity = ransomware / wiper / exfil staging**: thousands of `RenameNewName` with a new extension in seconds, or thousands of `DataOverwrite` — the `$J` gives exact start/stop times and order of directories hit, which shows the encryptor's traversal and the first infected path.
- **Zip staging for exfil**: `FileCreate` + rapid `DataExtend` on a `.zip/.7z/.rar` in `Users\Public`, `ProgramData`, `Temp` followed by `FileDelete` shortly after = classic collection-and-exfil pattern; the size in `$MFT` (if record survived) tells you how much left.
- **Volume Shadow Copies** contain older `$MFT` and `$J` — run the same parse on each VSC to extend the journal window weeks back (`vssadmin list shadows`, KAPE `--vss`).
- **Sequence numbers** tell you if the entry an LNK/Jump List/Prefetch refers to is the *same* file or a later one reusing the slot.
- **`$LogFile` for the last few hours**: it stores *before and after* images of MFT records — the pre-stomp timestamps, the pre-rename name. Short window, gold when it hits.
- Anti-forensics: `fsutil usn deletejournal /D C:` (leaves a very obvious hole + `$Max` reset and an event), SDelete (creates lots of renames to `AAAAAAAA.AAA`…), timestomp tools (`SI<FN`, zero nanoseconds), `cipher /w`.

## Timeline / correlation

| Question | Cross-check with |
|---|---|
| Was the dropped file executed? | [Prefetch](prefetch.md), [Amcache](amcache.md), [Shimcache](shimcache.md), `4688`, Sysmon 1 |
| Which user / process wrote it? | Sysmon 11 (`FileCreate` with process), `4663` object access (if SACL), `$SI` owner SID (→ SAM/ProfileList) |
| Where did it come from? | `Zone.Identifier` `HostUrl`, browser history, `4624` type 3 + `5145` (over SMB), USB volume serial in [LNK](lnk-jumplists.md) |
| Did the attacker open it? | [LNK / Jump Lists](lnk-jumplists.md), ShellBags, RecentDocs |
| Log gaps? | `$J` timeline vs. Security log — a busy `$J` window with zero Security events = log cleared (check `1102`) |

## References

- [Brian Carrier — File System Forensic Analysis (NTFS chapters)](https://www.digital-evidence.org/fsfa/)
- [Eric Zimmerman — MFTECmd](https://ericzimmerman.github.io/#!index.md)
- [Microsoft — USN_RECORD_V2 / change journal reason codes](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2)
- [SANS — Timestomping: detecting via $SI/$FN comparison (FOR500/FOR508 material)](https://www.sans.org/posters/windows-forensic-analysis/)
- [NTFS Log Tracker](https://sites.google.com/site/forensicnote/ntfs-log-tracker)
