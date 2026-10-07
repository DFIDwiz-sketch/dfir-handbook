---
title: $MFT, $UsnJrnl, $LogFile
tags:
  - artifact
  - windows
  - ntfs
  - filesystem
---

# $MFT, $UsnJrnl, $LogFile { #mft-usnjrnl-logfile }

<div class="dfir-meta" markdown>
**분류:** NTFS 파일시스템 메타데이터 · **OS:** 모든 NTFS 볼륨 · **최종 수정:** 2026-09-16
</div>

!!! abstract "한 줄 요약"
    마스터 파일 테이블(MFT)은 볼륨의 모든 파일 목록입니다(타임스톰핑을 잡아낼 수 있는 **두 세트의 타임스탬프** 포함). USN 변경 저널은 최근 며칠~몇 주 동안의 **모든 파일 작업 기록**(생성, 이름 변경, 삭제, 수정)이고, `$LogFile`은 짧지만 아주 자세한 트랜잭션 로그입니다. 셋을 합치면 오래전에 삭제된 파일까지 포함해 *파일에 무슨 일이 있었는지* 재구성할 수 있습니다.

## 알려 주는 것 { #what-they-tell-you }

| 아티팩트 | 답하는 질문 | 보존 기간 |
|---|---|---|
| `$MFT` | 어떤 파일이 존재(했)는지, 위치, 크기, 8개 타임스탬프 전부, 작은 파일의 상주 데이터, ADS (Zone.Identifier!), 상위 폴더, 아직 재사용되지 않은 삭제 항목 | 항목이 재사용될 때까지 |
| `$UsnJrnl:$J` | 파일이 *언제* 생성 / 이름 변경 / 삭제 / 쓰기 / 속성 변경됐는지, **파일 이름과 상위 MFT 참조**와 함께 순서대로 | 바쁜 워크스테이션에서 보통 1–4주 (기본 최대 32 MB, 커질 수 있음) |
| `$LogFile` | 저수준 NTFS 트랜잭션 (MFT 레코드 갱신, 인덱스 변경) — **이전 MFT 레코드 전체 내용**을 복구할 수 있음 | 몇 시간 ~ 이틀 정도 (기본 64 MB, 순환) |
| `$I30` 인덱스 속성 (폴더) | 삭제된 파일의 이름과 타임스탬프가 남은 슬랙 항목 | 슬랙이 덮어써질 때까지 |

## 위치 { #location }

모두 각 볼륨 루트에 있는 NTFS 메타파일이며 일반 목록에는 보이지 않습니다:

| 파일 | MFT 레코드 번호 | 메모 |
|---|---|---|
| `C:\$MFT` | 0 | `$MFTMirr` (레코드 1)도 있음 – 처음 4개 레코드 |
| `C:\$LogFile` | 2 | |
| `C:\$Extend\$UsnJrnl` | `$Extend` (11) 안 | 스트림 두 개: `$Max` (설정)와 **`$J`** (실제 저널, sparse — 끝부분에만 데이터가 있음) |
| `C:\$Extend\$RmMetadata\$TxfLog\...` | | 트랜잭션 NTFS — 거의 필요 없음 |

**원시 읽기** 도구(KAPE, FTK Imager, RawCopy, Sleuth Kit의 `icat`, Velociraptor)가 필요합니다 — 일반 API로는 열 수 없습니다.

## $MFT 레코드 핵심 { #mft-record-essentials }

모든 레코드는 **1024바이트**입니다(시그니처 `FILE`). 중요한 속성:

| 속성 | 타입 | 내용 |
|---|---|---|
| `$STANDARD_INFORMATION` (**$SI**) | 0x10 | **생성, 수정, MFT 변경, 접근** (MACE), 플래그 (숨김, 시스템, …), 소유자/보안 ID, USN. **탐색기 / `dir`이 보여 주는 값 — 타임스톰핑 도구가 바꾸는 값** |
| `$FILE_NAME` (**$FN**) | 0x30 | 이름 (긴 이름 + 8.3 이름이 별도 속성), 상위 폴더 참조, **자체 MACE 세트**, 크기. 생성/이름 변경/이동 시 **커널만 갱신** — 사용자 모드 도구는 직접 설정할 수 없음 |
| `$DATA` | 0x80 | 파일 내용: **상주** (≤ ~700바이트, 레코드 안) 또는 비상주 (데이터 런). 이름 있는 `$DATA` 스트림 = **대체 데이터 스트림** (`file.exe:Zone.Identifier`) |
| `$ATTRIBUTE_LIST` | 0x20 | 속성이 확장 레코드로 넘칠 때 존재 |
| `$INDEX_ROOT` / `$INDEX_ALLOCATION` | 0x90 / 0xA0 | 폴더 내용 (`$I30`) |
| `$OBJECT_ID` | 0x40 | 링크 추적용 GUID (LNK ObjectID와 일치) |
| 헤더 필드 | | 시퀀스 번호 (재사용 시 증가), 하드 링크 수, **사용 중 / 폴더 플래그**, 기본 레코드 참조, **`$LogFile` 시퀀스 번호 (LSN)** |

`MFT 참조` = 48비트 엔트리 번호 + 16비트 시퀀스 번호. 삭제된 항목은 재사용될 때까지 내용을 유지합니다(플래그 = 사용 안 함). 시퀀스가 올라갔다면 LNK나 Jump List의 참조가 *이전* 파일을 가리킨다는 뜻입니다.

### 타임스탬프 규칙 (타임스톰핑을 잡는 것들) { #timestamp-rules-the-ones-that-catch-timestomping }

| 관찰 | 의미 |
|---|---|
| `$SI` 생성 시각이 `$FN` 생성 시각**보다 이른** | 거의 항상 **타임스톰핑** (파일이 자기 디렉터리 항목보다 먼저 존재할 수는 없음). 예외: 일부 설치 프로그램 / 원래 시각을 보존하는 robocopy `/COPY:DAT` |
| `$SI` 타임스탬프의 **나노초가 0** (`.0000000`) | 초 단위를 받는 API로 설정됨 (많은 스톰핑 도구, `touch` 류. 단 PowerShell `[IO.File]::SetCreationTime`은 전체 정밀도로 설정) |
| `$SI` 수정 시각이 `$SI` MFT 변경 시각보다 한참 **오래됐고**, `$FN`이 MFT 변경 시각과 일치 | 파일이 스톰핑됨; MFT 변경 시각이 스톰핑이 일어난 시점 |
| `$FN` 시각이 `$SI`보다 **최신** | 스톰핑 후 **이동/이름 변경**됐거나 복사됨 (복사 → 새 `$FN` 생성) |
| 막 떨어진 실행 파일의 생성 ≠ 수정 | 다른 곳에서 복사됨 (수정 시각은 파일과 함께 이동하고, 생성 시각은 이 볼륨에 쓸 때 설정됨) |

!!! warning "$FN도 정상적으로 갱신될 수 있습니다"
    **같은 볼륨 안에서 이름을 바꾸거나 이동하면** Windows는 현재 `$SI` 값을 새 `$FN`에 복사합니다 — 그래서 스톰핑된 파일의 이름을 바꾸면 `$FN` 시각도 스톰핑된 것처럼 보입니다. 진실은 USN 저널과 비교해서 확인하세요.

### Zone.Identifier — 어디서 왔나? { #zoneidentifier-where-did-it-come-from }

다운로드한 파일의 `Zone.Identifier` ADS에는 `ZoneId=3`(인터넷)과, 최신 Windows에서는 **`ReferrerUrl`**과 **`HostUrl`** — 실제 다운로드 URL — 이 들어 있습니다. 라이브에서는 `Get-Content file.exe -Stream Zone.Identifier`로, 오프라인에서는 MFTECmd의 `ZoneIdContents` 열로 확인하세요. zip에서 풀린 파일은 이를 물려받고, `copy`/`xcopy`로 복사한 파일은 유지하며, 공격자의 `Unblock-File`이나 **MOTW(Mark-of-the-Web) 제거**는 이를 지웁니다.

## USN 저널($J) 핵심 { #usn-journal-j-essentials }

각 레코드: **USN** (오프셋), **타임스탬프**, **파일 참조** (MFT 번호 + 시퀀스), **상위 참조**, **이유 플래그**, 파일 이름. 이유는 `USN_REASON_CLOSE`까지 하나의 "세션" 동안 누적됩니다:

| 이유 플래그 | 의미 |
|---|---|
| `FILE_CREATE` | 새 파일/폴더 |
| `FILE_DELETE` | 삭제됨 |
| `RENAME_OLD_NAME` / `RENAME_NEW_NAME` | 이름 변경 또는 이동 (레코드 두 개; 새 레코드에 목적지 상위 폴더가 보임) |
| `DATA_EXTEND` / `DATA_OVERWRITE` / `DATA_TRUNCATION` | 내용이 써짐 / 교체됨 / 줄어듦 |
| `BASIC_INFO_CHANGE` | **타임스탬프나 속성 변경** — 타임스톰핑이 이것을 남김 |
| `SECURITY_CHANGE` | ACL 변경 |
| `NAMED_DATA_*` | 대체 데이터 스트림 쓰기 (Zone.Identifier 추가, 또는 `STREAM_CHANGE`로 제거) |
| `HARD_LINK_CHANGE`, `REPARSE_POINT_CHANGE`, `OBJECT_ID_CHANGE`, `INDEXABLE_CHANGE`, `CLOSE` | 이름 그대로 |

저널에는 **전체 경로가 없습니다** — 상위 MFT 참조만 있습니다. 파서는 `$MFT`와 결합해서 경로를 다시 만드는데, 상위 폴더 자체가 삭제되고 재사용됐다면 경로가 일부만 나올 수 있습니다 — 그래서 MFTECmd는 두 파일을 같이 원합니다.

## 수집 방법 { #how-to-collect }

=== "KAPE"

    ```powershell
    # $MFT, $J, $LogFile, $Boot, $I30 slack — in one go, then parse
    kape.exe --tsource C: --tdest C:\Case\out --target "$MFT,$J,$LogFile,$Boot" --mdest C:\Case\mod --module MFTECmd
    ```

=== "Velociraptor"

    `Windows.NTFS.MFT` (매우 큼), `Windows.Forensics.Usn`, `Windows.NTFS.Recover` (MFT id로 삭제된 파일 데이터 복구).

=== "라이브 원시 복사"

    ```powershell
    RawCopy.exe /FileNamePath:C:0 /OutputPath:C:\Case           # $MFT (record 0)
    RawCopy.exe /FileNamePath:C:2 /OutputPath:C:\Case           # $LogFile
    ExtractUsnJrnl64.exe /DevicePath:C: /OutputPath:C:\Case     # $J (only the non-sparse part)
    ```

=== "Sleuth Kit (이미지)"

    ```bash
    mmls image.E01                                    # find NTFS partition offset
    icat -o 2048 image.E01 0 > MFT                    # record 0
    fls -o 2048 -r -m C: image.E01 > bodyfile         # quick $SI/$FN body file
    ```

## 파싱 방법 { #how-to-parse }

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

    `$MFT` CSV에서 볼 열: `InUse`, `ParentPath`, `FileName`, `Extension`, `FileSize`, `Created0x10` vs `Created0x30`, `LastModified0x10` vs `0x30`, `SI<FN` (**true = 수상함**), `uSecZeros`, `Copied`, `ZoneIdContents`, `HasAds`, `IsAds`, `Timestomped`.

=== "Plaso / analyzeMFT / 기타"

    ```bash
    log2timeline.py --parsers "mft,usnjrnl" out.plaso /evidence/       # Plaso
    analyzeMFT.py -f '$MFT' -o mft.csv --bodyfull                       # analyzeMFT (older)
    ```

    **`$LogFile`**: `LogFileParser` (jschicht), `NTFS Log Tracker` (한국에서 만든 도구 — Windows GUI, $LogFile + $UsnJrnl + $MFT를 함께 파싱, 아주 좋음). **`$I30` 슬랙**: `INDXParse.py`, MFTECmd `-f $I30`.

## 분석 팁 { #analysis-tips }

!!! tip "30초 워크플로"
    1. `MFTECmd $J` → 사고 시간대에서 `UpdateReasons`에 `FileCreate`가 있고 `Extension`이 `.exe .dll .ps1 .bat .vbs .zip .7z .rar`인 것을 필터링. 이것이 떨어뜨린 도구 목록입니다.
    2. 각 결과마다 `$MFT` 행을 열어 `SI<FN`, `ZoneIdContents` (다운로드 URL!), `ParentPath` 확인.
    3. 같은 이름으로 `$J`에서 `FileDelete` 필터 → 공격자가 정리한 시점. `RenameNewName` 필터 → 도구 이름을 무엇으로 바꿨는지.
    4. 도구에 대한 `$J` `BasicInfoChange` → 타임스톰핑 순간.

- **삭제 ≠ 사라짐**: `InUse = False`인 `$MFT` 레코드도 이름, 타임스탬프, 크기, 그리고 (상주라면) 작은 파일의 **내용 전체**를 갖고 있습니다 — 배치 스크립트, 설정, `.lnk`, 작은 텍스트 전리품 목록.
- **대량 활동 = 랜섬웨어 / 와이퍼 / 유출 준비**: 몇 초 안에 새 확장자로 `RenameNewName` 수천 건, 또는 `DataOverwrite` 수천 건 — `$J`는 정확한 시작/종료 시각과 공격받은 폴더 순서를 알려 주어 암호화 도구의 순회 경로와 첫 감염 경로를 보여 줍니다.
- **유출용 zip 준비**: `Users\Public`, `ProgramData`, `Temp`의 `.zip/.7z/.rar`에 `FileCreate` + 빠른 `DataExtend`, 그리고 곧이어 `FileDelete` = 전형적인 수집 후 유출 패턴; (레코드가 살아 있다면) `$MFT`의 크기로 얼마나 나갔는지 알 수 있습니다.
- **볼륨 섀도 복사본**에는 더 오래된 `$MFT`와 `$J`가 있습니다 — 각 VSC에 같은 파싱을 돌려 저널 범위를 몇 주 더 과거로 늘리세요 (`vssadmin list shadows`, KAPE `--vss`).
- **시퀀스 번호**로 LNK/Jump List/Prefetch가 가리키는 항목이 *같은* 파일인지, 나중에 그 자리를 재사용한 파일인지 알 수 있습니다.
- **최근 몇 시간은 `$LogFile`**: MFT 레코드의 *변경 전과 후* 이미지를 저장합니다 — 스톰핑 전 타임스탬프, 이름 변경 전 이름. 범위는 짧지만 걸리면 금맥입니다.
- 안티포렌식: `fsutil usn deletejournal /D C:` (아주 뚜렷한 공백 + `$Max` 초기화와 이벤트를 남김), SDelete (`AAAAAAAA.AAA`… 로 이름 변경을 잔뜩 만듦), 타임스톰핑 도구 (`SI<FN`, 나노초 0), `cipher /w`.

## 타임라인 / 상관분석 { #timeline-correlation }

| 질문 | 교차 확인 |
|---|---|
| 떨어뜨린 파일이 실행됐나? | [Prefetch](prefetch.md), [Amcache](amcache.md), [Shimcache](shimcache.md), `4688`, Sysmon 1 |
| 어떤 사용자 / 프로세스가 썼나? | Sysmon 11 (프로세스가 포함된 `FileCreate`), `4663` 객체 접근 (SACL이 있다면), `$SI` 소유자 SID (→ SAM/ProfileList) |
| 어디서 왔나? | `Zone.Identifier` `HostUrl`, 브라우저 기록, `4624` type 3 + `5145` (SMB로), [LNK](lnk-jumplists.md)의 USB 볼륨 시리얼 |
| 공격자가 열었나? | [LNK / Jump Lists](lnk-jumplists.md), ShellBags, RecentDocs |
| 로그 공백? | `$J` 타임라인 vs. Security 로그 — `$J`는 바쁜데 Security 이벤트가 0개인 구간 = 로그 삭제 (`1102` 확인) |

## 참고 자료 { #references }

- [Brian Carrier — File System Forensic Analysis (NTFS chapters)](https://www.digital-evidence.org/fsfa/)
- [Eric Zimmerman — MFTECmd](https://ericzimmerman.github.io/#!index.md)
- [Microsoft — USN_RECORD_V2 / change journal reason codes](https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2)
- [SANS — Timestomping: detecting via $SI/$FN comparison (FOR500/FOR508 material)](https://www.sans.org/posters/windows-forensic-analysis/)
- [NTFS Log Tracker](https://sites.google.com/site/forensicnote/ntfs-log-tracker)
