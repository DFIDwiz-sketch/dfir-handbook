---
title: Eric Zimmerman 도구
tags:
  - tool
  - windows
  - parsing
  - cheatsheet
---

# Eric Zimmerman 도구 { #eric-zimmerman-tools }

<div class="dfir-meta" markdown>
**분류:** 아티팩트 파서 · **플랫폼:** Windows (.NET) · **최종 수정:** 2026-09-17
</div>

!!! abstract "하는 일"
    Windows 아티팩트마다 하나씩 있는 최고 수준의 무료 명령줄 파서 모음입니다. 모두 같은 규칙(`-f` 파일, `-d` 폴더, `--csv` 출력)을 따르고, 모두 **Timeline Explorer**로 이어집니다. [KAPE](kape.md) `!EZParser`가 수집했다면 이것들이 파싱한 것입니다. 원시 하이브, 저널, 로그를 정렬하고 거르고 타임라인으로 만들 수 있는 깔끔한 CSV로 바꿔 줍니다.

## 받기와 최신 상태 유지 { #get-them-and-keep-them-updated }

```powershell
# Download the whole suite (net6 build recommended) and keep it current
.\Get-ZimmermanTools.ps1 -Dest C:\Tools\EZ -NetVersion 6
```

대부분의 도구에 `--csv <dir>`(레코드마다 한 행)이 있고 많은 도구에 `--csvf <name>`이 있습니다; 타임스탬프 기본값은 **UTC**; `--help`가 모든 옵션을 보여 줍니다. 이름이 `Cmd`로 끝나면 CLI이고, `Registry Explorer`, `Timeline Explorer`, `ShellBags Explorer`, `EvtxECmd` 맵에는 GUI/보조 구성 요소가 있습니다.

## 아티팩트별 도구 { #the-suite-by-artifact }

| 도구 | 아티팩트 | 대표 명령 |
|---|---|---|
| **MFTECmd** | `$MFT`, `$J` (USN), `$LogFile`, `$Boot`, `$I30`, `$SDS` | `MFTECmd.exe -f C:\t\$MFT --csv out --csvf mft.csv` · `MFTECmd.exe -f $J -m $MFT --csv out` |
| **EvtxECmd** | 커뮤니티 **맵**을 쓰는 Windows 이벤트 로그 (`.evtx`) | `EvtxECmd.exe -d C:\t\Logs --csv out` · 맵 업데이트는 `--sync` |
| **PECmd** | Prefetch (`.pf`) | `PECmd.exe -d C:\Windows\Prefetch --csv out --csvf pf.csv` |
| **AmcacheParser** | `Amcache.hve` (바이너리의 SHA-1) | `AmcacheParser.exe -f Amcache.hve --csv out -i` |
| **AppCompatCacheParser** | Shimcache (`SYSTEM` 하이브 안) | `AppCompatCacheParser.exe -f SYSTEM --csv out` |
| **RECmd** | 레지스트리, 배치 모드 (모든 하이브) | `RECmd.exe -d C:\t\Reg --bn BatchExamples\Kroll_Batch.reb --csv out --nl` |
| **Registry Explorer** | 레지스트리, 대화형 (GUI) + 삭제된 키 | 모든 DFIR 키 북마크; 트랜잭션 로그 로드 |
| **rla** | 레지스트리 트랜잭션 로그를 깨끗한 하이브로 재생 | `rla.exe -d C:\t\Reg --out C:\t\clean` |
| **LECmd** | LNK 바로가기 파일 | `LECmd.exe -d "...\Recent" --csv out` |
| **JLECmd** | Jump Lists (Automatic/Custom Destinations) | `JLECmd.exe -d "...\Recent" --csv out` |
| **SBECmd** | ShellBags (`UsrClass.dat`, `NTUSER.dat`) | `SBECmd.exe -d C:\t\Reg --csv out` |
| **ShellBags Explorer** | ShellBags (GUI 트리 보기) | 폴더 탐색 재구성 |
| **SrumECmd** | SRUM (`SRUDB.dat` + `SOFTWARE`) | `SrumECmd.exe -f SRUDB.dat -r SOFTWARE --csv out` |
| **SumECmd** | SUM (사용자 액세스 로깅, Server) | `SumECmd.exe -d C:\t\SUM --csv out` |
| **RBCmd** | 휴지통 (`$I` 파일) | `RBCmd.exe -d C:\t\Recycle --csv out` |
| **RecentFileCacheParser** | `RecentFileCache.bcf` (Win7 실행) | |
| **WxTCmd** | Windows 10 Timeline (`ActivitiesCache.db`) | `WxTCmd.exe -f ActivitiesCache.db --csv out` |
| **JumpList / bstrings** | `bstrings.exe` = 정규식/패턴으로 하는 빠른 문자열 검색 | `bstrings.exe -f file --ls "password"` |
| **PECmd/Timeline** | `*_Timeline.csv` 출력을 슈퍼 타임라인에 넣음 | |
| **Timeline Explorer** | 위 모든 CSV **보기** | 필터, 그룹, 태그, 색상, 조건부 서식 |

## Timeline Explorer — 검토용 화면 { #timeline-explorer-the-review-front-end }

위의 모든 도구는 **Timeline Explorer**(`TimelineExplorer.exe`)용으로 설계된 CSV를 씁니다: CSV를 불러온 뒤 열마다 필터(Excel 방식), 전체 텍스트 검색, 조건에 따른 행 색상, 행 태그, 타임스탬프 열 고정을 할 수 있습니다. 워크플로: KAPE `!EZParser`로 모든 것을 한 출력 폴더에 파싱하고, 핵심 CSV(MFT, EVTX, Prefetch, Amcache)를 탭으로 열어 시간/호스트/사용자로 서로 피벗하세요. 백만 행짜리 CSV도 Excel보다 훨씬 잘 다룹니다.

## 빠른 레시피 { #fast-recipes }

```powershell
# Timestomping triage: $MFT rows where $SI < $FN or zero nanoseconds
MFTECmd.exe -f "$MFT" --csv out --csvf mft.csv
#   → open in Timeline Explorer, filter SI<FN = TRUE, or uSecZeros = TRUE

# Dropped-tool timeline from the USN journal
MFTECmd.exe -f "$J" -m "$MFT" --csv out --csvf usn.csv
#   → filter UpdateReasons contains FileCreate, Extension in exe/dll/ps1

# Execution story on a workstation
PECmd.exe -d C:\t\Prefetch --csv out --csvf pf.csv          # ran + files touched
AmcacheParser.exe -f Amcache.hve --csv out -i               # SHA-1 of every binary
AppCompatCacheParser.exe -f SYSTEM --csv out                # existence + order

# Everything in the registry at once
RECmd.exe -d C:\t\Reg --bn BatchExamples\Kroll_Batch.reb --csv out --nl

# Event-log hunting after parsing
EvtxECmd.exe -d C:\t\Logs --csv out --inc 4624,4625,4648,4672,4688,4698,4720,7045,1102
```

## 주의할 점 { #gotchas }

- **.NET 런타임**: `net6`/맞는 빌드를 쓰세요; 예전 `net4` 빌드는 더 이상 갱신되지 않습니다. `Get-ZimmermanTools.ps1`이 맞는 세트를 가져옵니다.
- 라이브 수집에서는 **레지스트리 하이브가 "더티"인 경우가 많습니다** — 먼저 `rla.exe`로 `.LOG1/.LOG2`를 재생하세요. 그러지 않으면 가장 최근 변경(쫓고 있는 지속성인 경우가 많음)을 놓칩니다.
- **EvtxECmd 맵**은 프로바이더/EventID별로 열을 어떻게 펼칠지 정합니다 — 정기적으로 `--sync`를 돌리세요; 맵이 없으면 `PayloadData3`만 쳐다보게 됩니다.
- **AmcacheParser `-i`**는 설치된 프로그램에 속하지 않는 파일(공격 도구가 있는 곳)을 포함합니다 — 대개 원하는 동작; `-w`는 알려진 정상 해시를 허용 목록으로 뺍니다.
- 타임스탬프는 **UTC**입니다; 로컬 시간으로 이야기를 만들기 전에 `SYSTEM` 하이브에서 시스템 시간대를 확인하세요 ([레지스트리 키](../windows/registry-keys.md#system-identity-timing)).
- 이 도구들은 **이미 수집한 아티팩트**를 파싱합니다 — 수집은 [KAPE](kape.md)/[Velociraptor](velociraptor.md)와 함께 쓰세요.

## 참고 자료 { #references }

- [Eric Zimmerman's tools (download + docs)](https://ericzimmerman.github.io/#!index.md)
- [Get-ZimmermanTools updater](https://github.com/EricZimmerman/Get-ZimmermanTools)
- [SANS Windows Forensic Analysis poster](https://www.sans.org/posters/windows-forensic-analysis/)
- 관련 페이지: [KAPE](kape.md) · [Windows 포렌식](../windows/index.md) — 아티팩트 페이지마다 파서가 적혀 있음 · [Plaso와 타임라인](plaso-timelines.md)
