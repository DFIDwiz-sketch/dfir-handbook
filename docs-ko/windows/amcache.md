---
title: Amcache
tags:
  - artifact
  - windows
  - execution
---

# Amcache { #amcache }

<div class="dfir-meta" markdown>
**분류:** 실행 증거 / 프로그램 인벤토리 · **OS:** Windows 7 (업데이트 적용) → 11 · **최종 수정:** 2026-09-16
</div>

!!! abstract "한 줄 요약"
    `Amcache.hve`는 시스템이 본 실행 파일, 드라이버, 설치된 프로그램의 목록을 담은 레지스트리 하이브입니다. 파일의 **SHA-1 해시**를 저장하기 때문에, 이름을 바꿨거나 삭제된 도구도 확실하게 식별할 수 있다는 점이 가장 큰 가치입니다.

## 알려 주는 것 { #what-it-tells-you }

- 전체 경로, 파일 크기, 게시자, 제품/버전 메타데이터(PE 버전 리소스에서), 컴파일(링크) 시각, 그리고 파일 **앞부분 31,457,280바이트(30 MB)의 SHA-1**.
- Windows가 그 바이너리를 **처음** 알게 된 시각(키의 마지막 쓰기 시각) — 첫 실행인 경우가 많지만 *항상 그런 건 아닙니다*.
- 설치된 프로그램(MSI/제거 정보), 드라이버, 바로가기, 장치 PnP 정보.

!!! warning "실행은 *추정*일 뿐 증명이 아닙니다"
    항목은 **Application Experience / Compatibility Appraiser** 예약 작업(`\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser`)과 프로세스 실행 시 shim 엔진이 만듭니다. 실행되지 않고 **스캔만** 돼도(예: Program Files에 있기만 해도) 파일이 나타날 수 있습니다. Amcache는 *"이 바이너리가 여기 있었고, 해시는 이것"*으로 다루고, 실행 증명은 Prefetch / 4688 / Sysmon 1로 하세요.

## 위치 { #location }

| 항목 | 경로 |
|---|---|
| 하이브 | `C:\Windows\AppCompat\Programs\Amcache.hve` (+ `.LOG1`, `.LOG2` 트랜잭션 로그 — 같이 수집) |
| 이전 버전 (XP/7) | `C:\Windows\AppCompat\Programs\RecentFileCache.bcf` — 경로만, 해시 없음 |
| 실행 중 잠김 | 예 — 원시 복사 사용 (KAPE, FTK Imager, `esentutl` 류 볼륨 섀도) |

## 구조 (Windows 10 1709+ 포맷) { #structure-windows-10-1709-format }

| 키 | 목록 대상 | 주요 필드 |
|---|---|---|
| `Root\InventoryApplicationFile` | 본 적 있는 **실행 파일** (파일마다 하위 키 하나, 이름은 `<lowercase path>|<hash>`) | `LowerCaseLongPath`, `Name`, `Size`, `FileId` (`0000` + **SHA-1**), `Publisher`, `ProductName`, `ProductVersion`, `BinFileVersion`, `LinkDate`, `BinaryType`, `ProgramId`, `IsOsComponent`, `IsPeFile` |
| `Root\InventoryApplication` | **설치된 프로그램** (MSI, 제거 항목, Store 앱) | `Name`, `Publisher`, `Version`, `InstallDate`, `RootDirPath`, `Source` (Msi/AddRemoveProgram/…), `UninstallString`, `ProgramId` |
| `Root\InventoryApplicationShortcut` | 시작 메뉴 / 바탕 화면의 `.lnk` 바로가기 | `ShortcutPath`, `ShortcutTargetPath` |
| `Root\InventoryDriverBinary` | 드라이버 (`.sys`) | `DriverName`, `DriverId` (SHA-1), `DriverSigned`, `DriverCompany`, `DriverLastWriteTime` |
| `Root\InventoryDevicePnp` | PnP 장치 | 클래스, 제조사, 드라이버, `InstallDate` |
| `Root\InventoryDeviceContainer` | 장치 컨테이너 (USB 장치 등) | `FriendlyName`, `Manufacturer`, `ModelName` |

구버전 포맷(Win 8 – 10 1607)은 `Root\File\<VolumeGUID>\<FileRef>`에 번호가 붙은 값을 썼습니다: `15` = 전체 경로, `101` = SHA-1, `17` = 마지막 수정, `0F` = 링크 시각, `11` = 생성, `100` = 프로그램 ID.

!!! info "어떤 타임스탬프가 무엇인가"
    `InventoryApplicationFile` 항목의 **키 LastWrite 시각** = appraiser가 항목을 쓰거나 갱신한 시각 (≈ 처음 본 시각, 나중에 갱신될 수 있음). `LinkDate` = 헤더의 PE 컴파일 시각 (공격자가 조작 가능). Amcache에는 **믿을 만한 "마지막 실행" 타임스탬프가 없습니다**.

## 수집 방법 { #how-to-collect }

=== "KAPE"

    ```powershell
    kape.exe --tsource C: --tdest C:\Case\out --target Amcache --mdest C:\Case\mod --module AmcacheParser
    ```

=== "Velociraptor"

    `Windows.System.Amcache` — 원시 NTFS 읽기로 라이브 하이브를 파싱합니다.

=== "라이브 복사"

    ```powershell
    # Locked — use a shadow copy or a raw-reading tool.  RawCopy example:
    RawCopy.exe /FileNamePath:C:\Windows\AppCompat\Programs\Amcache.hve /OutputPath:C:\Case
    ```

## 파싱 방법 { #how-to-parse }

=== "AmcacheParser (Eric Zimmerman)"

    ```powershell
    # Full parse → several CSVs (UnassociatedFileEntries, AssociatedFileEntries, Programs, Drivers, Shortcuts, Devices…)
    AmcacheParser.exe -f C:\Case\Amcache.hve --csv C:\Case\out

    # Only files NOT tied to an installed program (where attacker tools live) + include Windows OS files
    AmcacheParser.exe -f C:\Case\Amcache.hve --csv C:\Case\out -i

    # Whitelist known-good hashes to shrink output
    AmcacheParser.exe -f C:\Case\Amcache.hve --csv C:\Case\out -w C:\Case\known_good_sha1.txt
    ```

    가장 유용한 출력은 `*_UnassociatedFileEntries.csv`입니다: 어떤 설치 제품에도 속하지 않는 바이너리들. `FileKeyLastWriteTimestamp`로 정렬하세요.

=== "RegRipper"

    ```bash
    rip.pl -r Amcache.hve -p amcache
    ```

=== "Plaso"

    ```bash
    log2timeline.py --parsers amcache out.plaso Amcache.hve
    ```

## 분석 팁 { #analysis-tips }

!!! tip "해시 먼저, 이름은 나중"
    `UnassociatedFileEntries`의 SHA-1을 전부 뽑아 앞의 `0000`을 떼고 VirusTotal / 위협 인텔리전스와 대조하세요. 이름이 `svchost.exe`인데 SHA-1이 Mimikatz라면 더 따질 것도 없습니다.

- **이름을 바꾼 도구**: Amcache는 디스크상의 이름*과* PE 리소스의 `ProductName`/`OriginalFileName` 기반 필드를 함께 보관합니다. `Name = update.exe`, `ProductName = "mimikatz"` 같은 경우가 생각보다 자주 나옵니다.
- **삭제된 바이너리**: 파일이 지워져도 Amcache 항목은 남습니다. `$MFT`/USN과 짝지어 언제 떨어뜨리고 언제 지웠는지 재구성하세요.
- 사고 시간대에 `Users\*`, `ProgramData`, `Windows\Temp`, `Users\Public`에 있는 **서명 없는 / 게시자 없는** 바이너리를 가장 먼저 뽑으세요.
- **LinkDate 상식 점검**: 컴파일 시각이 미래이거나 1970/2000년 근처라면 패킹됐거나 헤더가 위조됐을 가능성.
- **드라이버**: `DriverSigned = 0`이거나 `DriverCompany`가 낯선 `InventoryDriverBinary` → BYOVD(취약한 드라이버 반입) 공격과 루트킷.
- **타임스탬프를 과하게 해석하지 마세요** — appraiser 작업은 대략 하루에 한 번 돌기 때문에, 항목의 마지막 쓰기 시각이 실제 첫 실행보다 몇 시간 늦거나 나중에 갱신될 수 있습니다.

## 타임라인 / 상관분석 { #timeline-correlation }

| 질문 | 교차 확인 |
|---|---|
| 실제로 실행됐나, 언제? | [Prefetch](prefetch.md), Security `4688`, Sysmon `1`, BAM/DAM |
| 이 해시가 알려진 도구와 일치하나? | VirusTotal, MISP, 내부 해시 세트 |
| 어디서 왔나? | [USN 저널](mft-usn.md) `FILE_CREATE`, Zone.Identifier ADS (`$MFT`), 브라우저 기록, `4663` |
| 다른 호스트에도 같은 도구가? | SHA-1로 전사 Velociraptor 헌트 |
| 설치된 프로그램인가 떨어뜨린 것인가? | `InventoryApplication` vs `UnassociatedFileEntries` |

## 참고 자료 { #references }

- [Blanche Lagny — Analysis of the AmCache (ANSSI, 2019)](https://www.ssi.gouv.fr/uploads/2019/01/anssi-coriin_2019-analysis_amcache.pdf)
- [Eric Zimmerman — AmcacheParser](https://ericzimmerman.github.io/#!index.md)
- [13Cubed — Amcache and Shimcache in forensic analysis](https://www.13cubed.com/)
