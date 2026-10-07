---
title: SRUM
tags:
  - artifact
  - windows
  - execution
  - network
---

# SRUM (System Resource Usage Monitor) { #srum-system-resource-usage-monitor }

<div class="dfir-meta" markdown>
**분류:** 실행 + 네트워크 사용 이력 · **OS:** Windows 8 → 11 · **최종 수정:** 2026-09-16
</div>

!!! abstract "한 줄 요약"
    SRUM은 Windows에 내장된 사용량 기록 데이터베이스입니다. 최근 ~30–60일 동안 매시간 **어떤 애플리케이션이, 어떤 사용자로, CPU를 얼마나 썼고, 어떤 네트워크로 몇 바이트를 보내고 받았는지** 기록합니다 — "도구가 실행됐다"를 "화요일 02:00–03:00 사이에 인터넷으로 3.2 GB를 올렸다"로 바꿔 주는 아티팩트입니다.

## 알려 주는 것 { #what-it-tells-you }

| 테이블 (프로바이더) | 얻는 정보 |
|---|---|
| **네트워크 데이터 사용량** `{973F5D5C-1D90-4944-BE8E-24B94231A174}` | 앱별, 사용자 SID별, 인터페이스 / 네트워크 프로필별: **BytesSent, BytesRecvd**, 시간 단위 |
| **네트워크 연결** `{DD6636C4-8929-4683-974E-22C046A43763}` | 인터페이스 연결/해제 시각, 연결 시간, 네트워크 프로필 (SSID) |
| **애플리케이션 리소스 사용량** `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` | 앱별, 사용자별: **포그라운드/백그라운드 CPU 시간, 읽기/쓰기 바이트, 화면 사용 시간**, 시간 단위 |
| **앱 타임라인** `{5C8CF1C7-7257-4F13-B223-970EF5939312}` (Win10+) | 앱 시작/종료, 포그라운드 시간 — 더 세밀한 타임라인 |
| **에너지 사용량** `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}` (+ `LT`) | 배터리 잔량 — 노트북이 켜져 있었는지 / 충전 중이었는지 |
| **푸시 알림** `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}` | 앱별 알림 페이로드 크기 |
| **VFU / Tagged Energy** `{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}` | 비디오 / 기타 |

모든 행에는 **타임스탬프 (시간 단위, UTC)**, **AppId** (`SruDbIdMapTable`의 인덱스 → 실행 파일 경로 또는 패키지 이름), **UserId** (→ SID)가 있습니다. 보존: 디스크의 ESE 데이터베이스는 대부분의 테이블을 약 **30일** 보관합니다(일부 빌드에서 네트워크는 60일). 마지막 한 시간은 기록되기 전까지 레지스트리에만 있습니다.

!!! warning "기록 시점"
    SRUM은 약 **60분마다**, 그리고 **종료 시**에 메모리에서 `SRUDB.dat`로 기록합니다. 정시에서 20분 지난 시점에 뜬 라이브 이미지는 현재 시간대가 빠져 있습니다. 강제로 기록하려면 **정상 종료**가 되지만 — 메모리 이미지를 떠야 하는 머신을 끄면 안 됩니다.

## 위치 { #location }

| 항목 | 경로 |
|---|---|
| 데이터베이스 | `C:\Windows\System32\sru\SRUDB.dat` (ESE / JET Blue 포맷, Exchange와 Windows Search와 같은 엔진) |
| ESE 로그 | `C:\Windows\System32\sru\*.log`, `*.jrs`, `*.chk` — 함께 수집; DB가 **더티 상태**인 경우가 많음 |
| 레지스트리 (라이브 버퍼 + 설정) | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions\{provider GUID}` |
| 이름 해석에 필요 | `SOFTWARE` 하이브 (`NetworkList`의 네트워크 프로필 이름, 인터페이스 GUID); 사용자 SID → `ProfileList` |

## 수집 방법 { #how-to-collect }

=== "KAPE"

    ```powershell
    kape.exe --tsource C: --tdest C:\Case\out --target SRUM,RegistryHivesSystem --mdest C:\Case\mod --module SrumECmd
    ```

    `SRUM` 타깃은 `SRUDB.dat`와 log/jrs 파일을 가져옵니다.

=== "Velociraptor"

    `Windows.Forensics.SRUM` — 라이브로 파싱해서 네트워크 사용량, 앱 리소스 사용량, 실행 통계를 각각의 표로 출력합니다.

=== "수동 (잠긴 파일)"

    ```powershell
    RawCopy.exe /FileNamePath:C:\Windows\System32\sru\SRUDB.dat /OutputPath:C:\Case\sru
    robocopy C:\Windows\System32\sru C:\Case\sru *.log *.jrs *.chk
    reg save HKLM\SOFTWARE C:\Case\SOFTWARE
    ```

## 파싱 방법 { #how-to-parse }

=== "SrumECmd (Eric Zimmerman)"

    ```powershell
    # -f database, -r SOFTWARE hive (resolves interface / profile names). Produces one CSV per table.
    SrumECmd.exe -f C:\Case\sru\SRUDB.dat -r C:\Case\SOFTWARE --csv C:\Case\out
    ```

    DB가 더티 상태라면 먼저 복구하세요 (Windows 필요, `esentutl` 버전 ≥ 원본 OS):

    ```powershell
    esentutl.exe /r sru /i /d      # replay logs, run inside the folder with the .log files
    esentutl.exe /p SRUDB.dat      # hard repair — last resort, may lose rows
    ```

    출력 파일: `*_SrumECmd_NetworkUsages_Output.csv`, `*_AppResourceUseInfo_Output.csv`, `*_NetworkConnections_Output.csv`, `*_AppTimelineProvider_Output.csv`, `*_EnergyUsage_Output.csv`, `*_PushNotifications_Output.csv`.

=== "srum-dump (Mark Baggett)"

    ```powershell
    # GUI or CLI → Excel workbook with one sheet per table; template controls column names
    srum_dump.exe -i C:\Case\sru\SRUDB.dat -t SRUM_TEMPLATE2.xlsx -r C:\Case\SOFTWARE -o C:\Case\out\srum.xlsx
    ```

=== "Plaso"

    ```bash
    log2timeline.py --parsers esedb/srum out.plaso SRUDB.dat
    ```

## 분석 팁 { #analysis-tips }

!!! tip "열 세 개로 보는 유출"
    `NetworkUsages`에서: `stats sum(BytesSent) by ExeInfo, SidType/UserName, day`. 사용자가 실행한 것(`svchost`, `MsMpEng`, 백업 에이전트, OneDrive가 아닌 것)이 한 시간에 **수백 MB**를 보냈다면 — 특히 밤에, 특히 `rclone.exe`, `megasync.exe`, `winscp.exe`, `curl.exe`, `powershell.exe`, `7z.exe` 근처의 것, 또는 `Users\Public`의 무작위 이름이라면 — 그게 유출 후보입니다. 일어난 시간대와 사용한 인터페이스(VPN vs. Wi-Fi)까지 함께 알 수 있습니다.

- Prefetch가 못 하는 **실행*과* 사용자 증명**을 합니다 (Prefetch에는 사용자가 없고 4688은 꺼져 있을 수 있음). `AppResourceUseInfo`는 SID, CPU 시간, I/O 바이트와 함께 *시간 단위* 실행 증거를 줍니다.
- **비율이 중요합니다**: `BytesSent >> BytesRecvd` = 업로드/유출; `BytesRecvd >> BytesSent` = 다운로드/스테이징; 둘 다 크고 비슷하면 = 터널/프록시 (chisel, ngrok, RDP 중계).
- **네트워크 프로필을 장소와 연결**: `NetworkConnections` + `NetworkList` 프로필 → 그 시간에 노트북이 "CoffeeShop_WiFi"에 있었음; BSSID와 합치면 위치 추정.
- **삭제된 도구도 나타납니다** — `SruDbIdMapTable`이 경로 문자열을 보관합니다.
- **인터페이스 GUID → 어댑터**: `SOFTWARE\...\NetworkCards` / `SYSTEM\...\Tcpip\Parameters\Interfaces` — VPN 어댑터, 물리 NIC, 핫스팟을 구분.
- **시간 단위**: `14:00`으로 찍힌 행은 **13:00–14:00** 활동입니다(구간의 끝). 정확한 분 단위로 과하게 해석하지 말고, 그건 `$J` / Sysmon 3 / 방화벽 로그로 확인하세요.
- **배터리 / 에너지 테이블**은 사용자가 꺼져 있었다고 주장하는 시간에 노트북이 켜져 있었는지 알려 줍니다.
- **안티포렌식**: `SRUDB.dat` 삭제 (서비스가 빈 파일을 다시 만듦 → 큰 공백 + 아주 새로운 파일 생성 시각), SRUM을 호스팅하는 `DPS`(진단 정책 서비스) 중지.

## 타임라인 / 상관분석 { #timeline-correlation }

| 질문 | 교차 확인 |
|---|---|
| 데이터를 보낸 도구는 무엇이었나? | [Amcache](amcache.md) SHA-1, [Prefetch](prefetch.md) 파일 참조 |
| 어디로 보냈나? | Sysmon 3 / `5156` WFP (켜져 있다면), 방화벽이나 프록시 로그, Zeek `conn.log` (`id.orig_h`별 `orig_bytes`), DNS 캐시 / Sysmon 22 |
| 먼저 무엇을 모았나? | [$MFT / USN](mft-usn.md) — 급증 직전 한 시간의 압축 파일 생성 |
| 어떤 세션 / 로그온? | 그 시간대 해당 SID의 `4624`, 원격이라면 RDP `21/25` |
| 다른 곳에도 같은 행동? | 전사 Velociraptor `Windows.Forensics.SRUM` 헌트, exe나 BytesSent 임계값으로 필터 |

## 참고 자료 { #references }

- [Yogesh Khatri — SRUM forensics (SANS DFIR Summit 2015)](https://www.sans.org/presentations/srum-forensics/)
- [Mark Baggett — srum-dump](https://github.com/MarkBaggett/srum-dump)
- [Eric Zimmerman — SrumECmd](https://ericzimmerman.github.io/#!index.md)
- [Velociraptor — Windows.Forensics.SRUM](https://docs.velociraptor.app/artifact_references/pages/windows.forensics.srum/)
