---
title: LNK 파일과 Jump Lists
tags:
  - artifact
  - windows
  - file-knowledge
---

# LNK 파일과 Jump Lists { #lnk-files-jump-lists }

<div class="dfir-meta" markdown>
**분류:** 파일 / 폴더 인지 · **OS:** XP → 11 (Jump Lists: 7+) · **최종 수정:** 2026-09-16
</div>

!!! abstract "한 줄 요약"
    Windows는 사용자가 연 모든 파일과 폴더에 대해 **바로가기(`.lnk`)**를 자동으로 만들고, **Jump Lists**는 애플리케이션별 최근/고정 항목 목록을 보관합니다. 둘을 합치면 사용자가 특정 파일을 열었다는 것, 언제, 어느 볼륨에서, 그 순간 파일의 타임스탬프가 무엇이었는지를 증명할 수 있습니다 — 파일이 이미 지워졌거나 이동식 매체에 있었어도 마찬가지입니다.

## 알려 주는 것 { #what-they-tell-you }

| LNK 안의 필드 | 중요한 이유 |
|---|---|
| **대상 경로** (로컬 경로, 네트워크 공유, 상대 경로) | 열었던 파일/폴더 — 대상이 지워져도 남음 |
| *마지막* 바로가기 갱신 시점의 **대상 MAC 시각** | *대상* 파일의 생성/수정/접근 시각이 그대로 고정됨 — 대상이 사라졌거나 나중에 타임스톰핑됐을 때 유용 |
| **대상 크기** | |
| **볼륨 시리얼 번호, 볼륨 레이블, 드라이브 유형** | 어느 USB / 드라이브에 있었는지 — `USBSTOR` / `MountedDevices`와 대조 |
| LNK를 만든 머신의 **NetBIOS 이름 / MAC 주소** (Tracker / 링크 추적 `ObjectID` 안에) | 바로가기를 호스트와 연결; MAC → NIC 제조사 |
| 대상의 **MFT 엔트리 번호 + 시퀀스** (Tracker 데이터 / 셸 아이템 확장 블록 안에) | `$MFT`와 상관분석 |
| **작업 폴더, 인수, 아이콘 위치** | 공격자가 만든 LNK(피싱)는 인수에 `cmd /c powershell -enc …`를 숨김 |
| LNK 파일 자체의 **$SI 타임스탬프** | 생성 = 이 경로로 파일을 **처음** 연 시각, 수정 = **마지막**으로 연 시각 |

## 위치 { #location }

| 항목 | 경로 |
|---|---|
| 최근 항목 (파일과 폴더) | `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\` (`*.lnk`) |
| Office 최근 항목 | `C:\Users\<user>\AppData\Roaming\Microsoft\Office\Recent\` |
| 바탕 화면 / 시작 메뉴 바로가기 | 사용자가 만든 것; 공격자가 무기화한 LNK를 떨어뜨리는 곳이기도 함 |
| **AutomaticDestinations** (자동으로 채워지는 Jump Lists) | `...\Recent\AutomaticDestinations\<AppID>.automaticDestinations-ms` |
| **CustomDestinations** (고정 / 앱이 관리하는 Jump Lists) | `...\Recent\CustomDestinations\<AppID>.customDestinations-ms` |

Recent 폴더는 대략 최근 **149개** LNK를 보관합니다(오래된 것은 밀려남). Jump Lists는 앱마다 상한이 있지만(~10–20개 표시), 컨테이너 파일은 훨씬 더 많이 담고 있는 경우가 많습니다.

## Jump List 구조 { #jump-list-structure }

- `*.automaticDestinations-ms`는 **OLE 복합 파일**(옛날 .doc 같은 구조)입니다. 각 스트림에는 번호(`1`, `2`, … 16진수)가 붙고 각각이 **완전한 LNK 구조**입니다. `DestList` 스트림이 인덱스입니다: 항목 ID ↔ 경로 ↔ **마지막 접근 시각**, **접근 횟수** (Win10+), 호스트명, 고정 여부.
- `*.customDestinations-ms`는 작은 헤더 뒤에 LNK 구조가 이어지는 형태입니다 — 사용자가 무언가를 *고정*하거나 앱(브라우저, 미디어 플레이어)이 자기 목록을 쓸 때 만들어집니다.
- `AppID` = 애플리케이션 경로의 CRC64 (또는 앱이 정한 값). 커뮤니티 목록이 흔한 ID를 정리해 두었습니다 — 예: `f01b4d95cf55d32a` 탐색기 (Win 8+), `9b9cdc69c1c24e2b` 메모장 (x64), `5f7b5f1e01b83767` 빠른 실행(Quick Access), `1b4dd67f29cb1962` 탐색기 고정, `7e4dca80246863e3` 제어판.

## 수집 방법 { #how-to-collect }

=== "KAPE"

    ```powershell
    kape.exe --tsource C: --tdest C:\Case\out --target LNKFilesAndJumpLists --mdest C:\Case\mod --module LECmd,JLECmd
    ```

=== "Velociraptor"

    `Windows.Forensics.Lnk`와 `Windows.Forensics.RecentApps` / `Windows.Applications.JumpLists` (커뮤니티).

## 파싱 방법 { #how-to-parse }

=== "LECmd (Eric Zimmerman)"

    ```powershell
    # All LNKs under a user's Recent → CSV; -q keeps console quiet; --mp shows more precision
    LECmd.exe -d "C:\Case\Users\sung\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\Case\out --csvf lnk.csv -q

    # One suspicious shortcut, full detail incl. shell items & tracker data
    LECmd.exe -f "C:\Case\Desktop\Invoice.pdf.lnk"

    # Treat non-.lnk files as LNKs (attackers rename)
    LECmd.exe -d C:\Case\Suspicious --all
    ```

    주요 CSV 열: `SourceCreated`, `SourceModified` (LNK 자체), `TargetCreated/Modified/Accessed`, `LocalPath`, `NetworkPath`, `VolumeSerialNumber`, `VolumeLabel`, `DriveType`, `MachineID`, `MACAddress`, `Arguments`, `WorkingDirectory`.

=== "JLECmd (Eric Zimmerman)"

    ```powershell
    # Both Automatic and Custom destinations, one CSV each
    JLECmd.exe -d "C:\Case\Users\sung\AppData\Roaming\Microsoft\Windows\Recent" --csv C:\Case\out -q

    # Include the raw LNK details for every entry (large but complete)
    JLECmd.exe -d ... --csv C:\Case\out --ld

    # Dump embedded LNKs from a jump list to files
    JLECmd.exe -f 5f7b5f1e01b83767.automaticDestinations-ms --dumpTo C:\Case\jl_lnks
    ```

    `AutomaticDestinations` CSV에서 정렬할 열: `LastModified` (DestList 마지막 접근), `EntryNumber`, `Path`, `InteractionCount`, `Hostname`, `AppIdDescription`.

=== "Plaso"

    ```bash
    log2timeline.py --parsers "lnk,custom_destinations,olecf/olecf_automatic_destinations" out.plaso /evidence/Users/
    ```

## 분석 팁 { #analysis-tips }

!!! tip "타임스탬프 세 개, 의미 세 개"
    Recent LNK의 경우: **LNK 생성** = 사용자가 (이 경로로) 그 대상을 처음 연 시각. **LNK 수정** = 가장 최근에 연 시각. **대상 생성/수정** = 마지막으로 열었을 때의 *파일* 타임스탬프. 대상의 현재 `$SI` 수정 시각이 LNK에 기록된 것보다 *오래됐다면* → 타임스톰핑.

- **피싱 LNK**: `Arguments`와 `IconLocation`을 보세요. 아이콘이 `shell32.dll,1`이고 대상이 `C:\Windows\System32\cmd.exe`이며 인수가 1,000자인 "PDF"가 바로 페이로드입니다. Tracker 데이터의 `MachineID`/`MAC`는 공격자가 지우는 걸 잊었다면 **공격자의 빌드 머신**을 식별할 수 있습니다.
- **USB 유출**: `USBSTOR` 장치와 볼륨 시리얼이 일치하는 `E:\...`를 가리키는 Recent LNK → 사용자가 USB*에서* 파일을 열었음. `E:\`를 가리키는 폴더 LNK와 대상 생성 시각 → USB*로* 복사함 (폴더 보기는 ShellBags, 복사 시각은 `$MFT`와 짝지어 볼 것).
- **네트워크 공유**: `NetworkPath` `\\fileserver\finance\...`는 서버 로그가 없어도 공유에 접근했다는 증거입니다.
- **삭제된 증거**: 더 이상 존재하지 않는 `C:\Users\Public\tools\mimikatz.zip`의 LNK도 크기, 타임스탬프, MFT 참조를 알려 줍니다.
- **Jump Lists는 Recent 정리 후에도 남습니다**: "최근 항목"을 지운 사용자/공격자도 `AutomaticDestinations`는 그대로 두는 경우가 많고, `InteractionCount`는 문서를 몇 번 열었는지 보여 줍니다.
- **빠른 실행(`5f7b5f1e01b83767`)과 탐색기(`f01b4d95cf55d32a`)** Jump Lists는 둘러본 **폴더**를 기록합니다 — [ShellBags](registry-keys.md#files-folders-opened-per-user)와 함께 쓰는 두 번째 출처.
- 이름을 바꾼 LNK / 숨겨진 `.lnk` 확장자: 탐색기는 `.lnk`를 절대 보여 주지 않으므로 `report.pdf.lnk`는 `report.pdf`로 보입니다.

## 타임라인 / 상관분석 { #timeline-correlation }

| 질문 | 교차 확인 |
|---|---|
| 파일이 실제로 이 시스템에 있었나 / 어느 장치에? | 볼륨 시리얼 ↔ `SYSTEM\MountedDevices`, `USBSTOR`, [$MFT](mft-usn.md) |
| 어떤 프로그램이 열었나? | Jump List AppID; `OpenSavePidlMRU`/`LastVisitedPidlMRU`; Office MRU ([레지스트리 키](registry-keys.md)) |
| 어느 폴더에서 둘러봤나? | ShellBags (`UsrClass.dat`), 탐색기 Jump List |
| 보기만 했나, 실행했나? | [Prefetch](prefetch.md), [Amcache](amcache.md), `4688` |
| 누가 열었나? | LNK가 들어 있는 사용자 프로필 → 그 사용자; `4624` 세션 시각으로 확인 |

## 참고 자료 { #references }

- [Microsoft — [MS-SHLLINK] Shell Link Binary File Format](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/)
- [Eric Zimmerman — LECmd, JLECmd](https://ericzimmerman.github.io/#!index.md)
- [Jump List AppID master list (community, 4n6k / EricZimmerman JumpList repo)](https://github.com/EricZimmerman/JumpList)
- [libyal — Jump Lists format (libfwsi / liblnk docs)](https://github.com/libyal/liblnk/blob/main/documentation/Windows%20Shortcut%20File%20(LNK)%20format.asciidoc)
