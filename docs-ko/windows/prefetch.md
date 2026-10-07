---
title: Prefetch
tags:
  - artifact
  - windows
  - execution
---

# Prefetch { #prefetch }

<div class="dfir-meta" markdown>
**분류:** 실행 증거 · **OS:** Windows XP → 11 (워크스테이션 SKU) · **최종 수정:** 2026-09-16
</div>

!!! abstract "한 줄 요약"
    Prefetch 파일은 실행 파일이 **실행됐다는 것**, 언제 실행됐는지(최근 8번까지), 몇 번 실행됐는지, 그리고 처음 ~10초 동안 어떤 파일/폴더에 접근했는지를 기록합니다 — 워크스테이션에서 "실행됐나?"에 답하는 최고의 아티팩트입니다.

## 알려 주는 것 { #what-it-tells-you }

- 실행 파일 **이름**과 **전체 경로**의 해시 (그래서 `C:\Windows\System32`의 `cmd.exe`와 `C:\Temp`의 `cmd.exe`는 서로 다른 `.pf` 파일이 됩니다).
- **실행 횟수**와 **최근 실행 시각 최대 8개** (Win8+; XP/7은 마지막 1개만).
- 로딩 중에 **참조한 파일과 폴더** — DLL, 설정 파일, 뷰어가 연 문서, 사이드로딩된 바이너리가 불러온 DLL.
- 볼륨 정보: 실행된 볼륨의 시리얼 번호와 생성 시각 (USB에서 실행한 도구를 찾는 데 도움).

## 위치 { #location }

| 항목 | 경로 |
|---|---|
| 폴더 | `C:\Windows\Prefetch\` |
| 파일 이름 규칙 | `<EXENAME>-<8자리 해시>.pf` — 예: `MIMIKATZ.EXE-5B7C4A2D.pf` |
| 제어 키 | `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher` |
| 최대 파일 수 | 128 (XP/7), 1024 (Win8+). 가득 차면 오래된 것부터 삭제 |

`EnablePrefetcher` 값: `0` 비활성, `1` 애플리케이션만, `2` 부팅만, `3` 애플리케이션 + 부팅 (워크스테이션 기본값). **Windows Server는 기본으로 꺼져 있고**, Win7에서는 SSD 시스템에서 꺼져 있는 경우가 많습니다 (Win8+는 SSD와 상관없이 켜 둡니다).

## 주요 필드 { #key-fields }

| 필드 | 의미 | 메모 |
|---|---|---|
| 실행 파일 이름 | 실행된 파일명 | 대소문자 구분 없음; 경로는 해시로 구분 |
| 해시 | 전체 경로로 계산 (`svchost.exe`, `dllhost.exe`, `mmc.exe`, `rundll32.exe`, `backgroundtaskhost.exe` 같은 호스팅 프로세스는 명령줄도 포함) | 같은 바이너리라도 경로가 다르면 → 다른 `.pf` |
| 실행 횟수 | 실행된 횟수 | 줄어들지 않으므로, 공백이 있다고 지워진 것은 아님 |
| 마지막 실행 시각 | 최대 8개 (Win8+) | FILETIME(UTC)으로 저장. **첫** 실행은 최근 8개 안에 들지 않으면 저장되지 *않음* |
| 파일 참조 | 처음 ~10초 동안 연 파일 | 불러온 문서/DLL도 포함 — LOLBin이 실행한 페이로드를 찾는 데 좋음 |
| 폴더 참조 | 접근한 폴더 | 스테이징 폴더가 드러남 |
| 볼륨 시리얼 / 생성 시각 | exe가 있던 곳 | USB나 마운트한 이미지 탐지 |

!!! warning "10초 문제와 ~10초 오프셋"
    `.pf` 파일은 프로세스 시작 후 약 **10초 뒤에** 기록됩니다. 그래서 `.pf` 파일의 **NTFS 생성 시각 ≈ 첫 실행 + 10초**, **수정 시각 ≈ 마지막 실행 + 10초**입니다. 또 아주 짧게 산 프로세스(1초 만에 끝나는 드로퍼)도 prefetch 파일은 생기지만 파일 참조는 적을 수 있습니다.

## 포맷 버전 { #format-versions }

| 버전 | OS | 압축? |
|---|---|---|
| 17 | XP / 2003 | 아니오 |
| 23 | Vista / 7 | 아니오 |
| 26 | 8 / 8.1 | 아니오 |
| 30 | 10 / 11 | **예 — MAM (Xpress Huffman)**; 파싱 전에 압축을 풀어야 함. 최신 10/11 빌드는 v30 변형과 v31을 사용 |

압축을 풀면 오프셋 4에 시그니처 `SCCA`가 있습니다.

## 수집 방법 { #how-to-collect }

=== "KAPE"

    ```powershell
    kape.exe --tsource C: --tdest C:\Case\out --target Prefetch --mdest C:\Case\mod --module PECmd
    ```

=== "Velociraptor"

    `Windows.Forensics.Prefetch` 아티팩트 — 라이브로 파싱해서 표로 돌려줍니다 (파일을 먼저 복사할 필요 없음).

=== "수동"

    ```powershell
    # Needs admin; copy the whole folder including the Layout.ini / *.db files for context
    robocopy C:\Windows\Prefetch C:\Case\Prefetch /E
    ```

## 파싱 방법 { #how-to-parse }

=== "PECmd (Eric Zimmerman)"

    ```powershell
    # Whole directory → CSV (one row per pf + one row per referenced file in *_Timeline.csv)
    PECmd.exe -d C:\Case\Prefetch --csv C:\Case\out --csvf prefetch.csv

    # Single file, human readable
    PECmd.exe -f C:\Case\Prefetch\MIMIKATZ.EXE-5B7C4A2D.pf

    # Only show pf files that reference a keyword (e.g. a staging dir)
    PECmd.exe -d C:\Case\Prefetch -k "temp,appdata\local\temp,users\public"
    ```

    `--csvf`로 지정한 이름이 주 출력이고, `*_Timeline.csv`는 실행 시각마다 한 줄씩 나옵니다 — 슈퍼 타임라인에 넣으세요.

=== "Plaso / log2timeline"

    ```bash
    log2timeline.py --parsers prefetch out.plaso /evidence/C/Windows/Prefetch/
    psort.py -o l2tcsv -w prefetch.csv out.plaso
    ```

=== "Python (windowsprefetch / dissect)"

    ```bash
    pip install windowsprefetch
    prefetch.py -f MIMIKATZ.EXE-5B7C4A2D.pf
    ```

## 분석 팁 { #analysis-tips }

!!! tip "빠른 트리아지"
    `PECmd` 출력을 **Last Run** 내림차순, **Run Count** 오름차순으로 정렬하세요. 공격 도구는 보통 **사고 시간대**에 **실행 횟수가 적습니다**(1–3회). 정상 소프트웨어는 몇 달에 걸쳐 실행 횟수가 많습니다.

- **파일명이 무죄를 뜻하지 않습니다.** 처음 보는 해시의 `svchost.exe` `.pf`는 svchost가 비표준 경로에서(또는 이상한 명령줄로) 실행됐다는 뜻입니다. 전체 PC의 해시를 비교하세요.
- **파일 참조 안을 보세요.** `C:\Users\Public\update.ps1`을 참조하는 `POWERSHELL.EXE-*.pf`는 PowerShell이 *무엇*을 실행했는지 알려 줍니다. 낯선 DLL을 참조하는 `RUNDLL32.EXE-*.pf`는 사이드로딩 / 프록시 실행의 단서입니다.
- **삭제된 도구도 보입니다.** 공격자가 `mimikatz.exe`를 지워도 `.pf` 파일은 대개 남습니다. 같은 바이너리를 `$MFT`, USN 저널, Amcache에서도 확인하세요.
- **이름을 바꾼 도구.** prefetch의 *실행 파일 이름*과 **Amcache** SHA1이 말하는 실제 정체를 비교하세요.
- **타임스톰핑은 prefetch를 건드리지 않습니다.** 공격자는 EXE의 타임스탬프를 조작해도 prefetch와 `$MFT` `$FILE_NAME` 속성은 잊는 경우가 많습니다.
- **없다고 실행 안 된 건 아닙니다.** `EnablePrefetcher`, Server SKU 여부, 폴더가 1024개 한도에 도달했는지(그러면 *가장 오래된* 것부터 삭제), 폴더가 **지워졌는지** 확인하세요 — 거의 비어 있는 Prefetch 폴더의 수정 시각이 아주 최근이라면 그 자체로 수상합니다.
- **안티포렌식:** `C:\Windows\Prefetch\*` 삭제, `EnablePrefetcher=0` 설정, RAM 디스크 / 매핑된 공유에서 실행 (네트워크 공유의 파일도 prefetch 파일이 생기지만 UNC 경로가 해시됩니다).

## 타임라인 / 상관분석 { #timeline-correlation }

| 질문 | 교차 확인 |
|---|---|
| 그 바이너리는 정확히 무엇이었나? | [Amcache](amcache.md) (SHA1, 게시자), [Shimcache](shimcache.md) (경로, 존재) |
| 누가 실행했나? | Security `4688` (켜져 있다면), [UserAssist](registry-keys.md#program-execution-per-user-unless-noted), BAM/DAM 키 (SID별 마지막 실행 시각) |
| 다음에 무엇을 했나? | Sysmon 1/3/11, 실행 시각 ±10초에 생성된 파일은 [USN 저널](mft-usn.md) |
| USB에서 실행됐나? | `.pf`의 볼륨 시리얼 ↔ `SYSTEM\MountedDevices`, `USBSTOR` |
| 지속성을 남겼나? | [레지스트리 Run 키](registry-keys.md#autostart-persistence-asep), 예약 작업 `4698`, 서비스 `7045` |

## 참고 자료 { #references }

- [libscca — Windows Prefetch format documentation](https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc)
- [Eric Zimmerman — PECmd](https://ericzimmerman.github.io/#!index.md)
- [SANS Windows Forensic Analysis poster](https://www.sans.org/posters/windows-forensic-analysis/)
