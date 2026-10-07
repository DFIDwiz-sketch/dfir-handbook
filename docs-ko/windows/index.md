---
title: Windows 포렌식
---

# Windows 포렌식 { #windows-forensics }

Windows의 호스트 기반 아티팩트 — 어디에 있고, 무엇을 증명하며, 어떻게 파싱하는지. 먼저 답해야 할 **질문**에서 출발한 뒤 아티팩트 페이지를 여세요.

## 아티팩트 지도 — 질문별 { #artifact-map-by-question }

| 질문 | 주요 아티팩트 | 함께 확인 |
|---|---|---|
| **이 프로그램이 실행됐나? 언제? 몇 번?** | [Prefetch](prefetch.md) · BAM/DAM ([레지스트리](registry-keys.md#program-execution-per-user-unless-noted)) · Security `4688` / Sysmon `1` ([이벤트 로그](event-logs.md)) | [Shimcache](shimcache.md) (존재 + 순서), [Amcache](amcache.md), UserAssist, [SRUM](srum.md) (시간 단위, 사용자 포함) |
| **그 바이너리는 *무엇*이었나?** (이름 변경 / 삭제됨) | [Amcache](amcache.md) — SHA-1 | [Prefetch](prefetch.md) 파일 참조, [$MFT](mft-usn.md) 상주 데이터, `MUICache` |
| **어떤 사용자가 실행했나?** | BAM/DAM, UserAssist, [SRUM](srum.md), `4688` `SubjectUserName` | 그 프로필 아래의 [LNK / Jump Lists](lnk-jumplists.md) |
| **사용자가 어떤 파일/폴더를 열었나?** | [LNK / Jump Lists](lnk-jumplists.md) · RecentDocs, OpenSavePidlMRU, Office MRU ([레지스트리](registry-keys.md#files-folders-opened-per-user)) | ShellBags (폴더), Office 신뢰할 수 있는 문서 (매크로 문서) |
| **파일에 무슨 일이 있었나 — 생성, 이름 변경, 삭제, 타임스톰핑?** | [$UsnJrnl + $MFT](mft-usn.md) | `$LogFile`, `$I30` 슬랙, Sysmon `11`, `4663` |
| **그 파일은 어디서 왔나?** | [$MFT](mft-usn.md)의 `Zone.Identifier` ADS (URL) | 브라우저 기록, [LNK](lnk-jumplists.md) 볼륨 시리얼 (USB), `5145` 공유 접근 |
| **USB 장치가 꽂혔나? 어떤 것? 누가 썼나?** | `USBSTOR`, `MountedDevices`, `MountPoints2` ([레지스트리](registry-keys.md#usb-removable-devices-system)) | `setupapi.dev.log`, `Partition/Diagnostic` `1006`, `E:\`를 가리키는 [LNK](lnk-jumplists.md) |
| **데이터가 밖으로 나갔나? 얼마나?** | [SRUM](srum.md) 네트워크 사용량 — 앱별·시간별 바이트 | [$UsnJrnl](mft-usn.md) 압축 파일 생성, Sysmon `3`, 프록시/방화벽/Zeek |
| **어떻게 들어왔고 / 어떻게 횡적 이동했나?** | `4624` type 3/10, `4648`, `4778`, RDP `21/25/1149`, `7045`, `5140/5145` ([이벤트 ID](../basics/windows-event-ids.md)) | WinRM / WMI-Activity 채널, `psexesvc`·`wsmprovhost`의 [Prefetch](prefetch.md) |
| **어떻게 지속성을 유지하나?** | Run 키, 서비스, 예약 작업, WMI, COM 하이재킹 ([레지스트리 ASEP](registry-keys.md#autostart-persistence-asep)) | `7045`, `4698`, WMI `5861`, 시작 프로그램 폴더, 오프라인 Autoruns |
| **로깅이 변조됐나?** | `1102`, `104`, `4719`, 레코드 ID 공백 ([이벤트 로그](event-logs.md#detecting-tampering)) | 채널별 가장 오래된 이벤트, `$UsnJrnl` 대비 비어 있는 로그, VSS 복사본 |
| **시스템, 시간대, 사용자, 네트워크는?** | `CurrentVersion`, `TimeZoneInformation`, `ProfileList`, `NetworkList`, SAM ([레지스트리](registry-keys.md#system-identity-timing)) | `setupapi`, `Tcpip\Parameters`의 DHCP 임대 |

## 아티팩트 페이지 { #artifact-pages }

<div class="grid cards" markdown>

-   **[Prefetch](prefetch.md)** — 실행 여부, 최근 8번 실행 시각, 접근한 파일
-   **[Amcache](amcache.md)** — 본 적 있는 모든 바이너리의 SHA-1
-   **[Shimcache](shimcache.md)** — 존재와 순서; 서버에서도 동작
-   **[레지스트리 키](registry-keys.md)** — 시스템 정보, 사용자 활동, USB, 지속성
-   **[LNK와 Jump Lists](lnk-jumplists.md)** — 연 파일/폴더, USB 시리얼
-   **[$MFT / $UsnJrnl / $LogFile](mft-usn.md)** — 파일시스템 이력, 타임스톰핑
-   **[SRUM](srum.md)** — 앱별·시간별 전송 바이트, 사용자 포함
-   **[이벤트 로그](event-logs.md)** — 채널, 보존, 파싱, 변조

</div>

## 수집 순서 (시간이 없을 때) { #collection-order-when-time-is-short }

1. **메모리** (라이브 시스템이고 가능하다면) — 그다음 나머지 전부.
2. `$MFT`, `$UsnJrnl:$J`, `$LogFile` — 수집 비용은 작고 얻는 건 큼.
3. 레지스트리 하이브 + 트랜잭션 로그 (`SYSTEM`, `SOFTWARE`, `SAM`, `SECURITY`, 모든 `NTUSER.DAT` + `UsrClass.dat`), `Amcache.hve`.
4. `C:\Windows\System32\winevt\Logs\*.evtx`.
5. `C:\Windows\Prefetch\`, `C:\Windows\System32\sru\`, 사용자 `Recent\` (LNK + Jump Lists), PowerShell `ConsoleHost_history.txt`.
6. 브라우저 데이터, `Tasks\`, `Startup` 폴더, `Temp` 폴더, `setupapi.dev.log`.

KAPE의 `!SANS_Triage` 복합 타깃이 위 항목을 몇 분 안에 모두 수집하고, Velociraptor의 `Windows.KapeFiles.Targets`는 같은 일을 원격으로 합니다.

!!! info "이 섹션에 페이지 추가하기"
    `python new.py windows/<name> -t artifact` — 또는 `docs/windows/`에 `.md` 파일을 그냥 넣으면 됩니다. 사이드바에 자동으로 나타납니다.
