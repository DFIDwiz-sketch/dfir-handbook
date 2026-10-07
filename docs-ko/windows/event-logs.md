---
title: Windows 이벤트 로그 (EVTX)
tags:
  - artifact
  - windows
  - logs
---

# Windows 이벤트 로그 (EVTX) { #windows-event-logs-evtx }

<div class="dfir-meta" markdown>
**분류:** 로그 · **OS:** Vista → 11 / Server 2008 → 2025 · **최종 수정:** 2026-09-16
</div>

!!! abstract "한 줄 요약"
    로그가 *어디에* 있는지, 어떤 채널이 중요한지, 덮어쓰기 전에 얼마나 커지는지, 대량으로 수집하고 파싱하는 방법, 누군가 지우거나 변조했는지 알아내는 방법을 모두 다룹니다 — **이벤트 ID**의 의미는 [Windows 이벤트 ID](../basics/windows-event-ids.md) 페이지에 있습니다.

## 위치와 포맷 { #location-format }

| 항목 | 내용 |
|---|---|
| 폴더 | `C:\Windows\System32\winevt\Logs\` |
| 파일 이름 | `Security.evtx`, `System.evtx`, `Application.evtx`, 그리고 `Microsoft-Windows-<Provider>%4<Channel>.evtx` (`%4`는 인코딩된 `/`) |
| 포맷 | 64 KB 청크 단위의 바이너리 XML, 청크마다 자체 CRC와 레코드 범위; 시그니처 `ElfFile` (파일 헤더), `ElfChnk` (청크) |
| 시간 | **UTC**로 저장 (`TimeCreated SystemTime`) — 이벤트 뷰어는 로컬 시간으로 표시 |
| 레코드 ID | `EventRecordID`는 채널마다 증가 — 순서에 **공백**이 있으면 레코드가 사라졌거나/지워졌거나/덮어써진 것 |
| 레지스트리 (채널 설정) | `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\<Log>` (클래식)와 `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\<Channel>` (`Enabled`, `MaxSize`, `File`) |
| 전달된 로그 | WEC 수집기의 `ForwardedEvents.evtx`; SIEM (Splunk UF / Winlogbeat / Sysmon → 에이전트) |

### 기본 크기 (Security 로그가 며칠 전까지만 남는 이유) { #default-sizes-why-the-security-log-only-goes-back-a-few-days }

| 로그 | 기본 최대 크기 | 바쁜 시스템에서의 일반적인 보존 기간 |
|---|---|---|
| Security | 20 MB (Win7/8); 최신 빌드는 GPO / Server 기본값으로 **최대 128 MB** 이상 | 몇 시간 ~ 며칠 — **가장 먼저 확인할 것** |
| System / Application | 20 MB | 몇 주 |
| PowerShell/Operational | 15 MB | 스크립트 블록 로깅이 켜져 있으면 며칠 |
| Sysmon/Operational | 64 MB (설정 기본값) | 몇 시간 ~ 며칠 |
| 대부분의 `*Operational` 채널 | 1 MB (!) | 아주 짧음 — 예: TaskScheduler, WMI-Activity |

보존 모드는 거의 항상 **"필요하면 이벤트 덮어쓰기"**라서 오래된 레코드는 조용히 사라집니다. **볼륨 섀도 복사본**에는 더 오래된 `Security.evtx`가 들어 있는 경우가 많으니 항상 `vssadmin list shadows` / KAPE `--vss`로 확인하세요.

## 수집할 만한 채널 (Security/System/Application 외) { #channels-worth-grabbing-beyond-securitysystemapplication }

| 채널 파일 | 이유 |
|---|---|
| `Microsoft-Windows-PowerShell%4Operational.evtx` | 스크립트 블록 로깅 `4104`, 모듈 `4103` |
| `Windows PowerShell.evtx` | 구식 PS 엔진 `400/403/600` — `HostApplication` 명령줄 포함 |
| `Microsoft-Windows-Sysmon%4Operational.evtx` | Sysmon (설치돼 있다면) — 프로세스, 네트워크, 파일, 레지스트리, DNS |
| `Microsoft-Windows-TaskScheduler%4Operational.evtx` | 작업 등록/실행 (꺼져 있는 경우가 많음 — `Enabled` 확인) |
| `Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` | RDP `21/22/24/25`, 출발지 IP 포함 |
| `Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx` | RDP `1149` |
| `Microsoft-Windows-RemoteDesktopServices-RdpCoreTS%4Operational.evtx` | RDP `131`, `98` |
| `Microsoft-Windows-WinRM%4Operational.evtx` | PowerShell remoting 클라이언트/서버 `6/91/168/169` |
| `Microsoft-Windows-WMI-Activity%4Operational.evtx` | WMI 지속성 `5857–5861`, 원격 WMI 실행 쿼리 |
| `Microsoft-Windows-Windows Defender%4Operational.evtx` | 탐지 `1116/1117`, 변조 `5001/5007`, 예외 |
| `Microsoft-Windows-Bits-Client%4Operational.evtx` | BITS 다운로드 (`59/60/61`) — LOLBin 다운로드/지속성 |
| `Microsoft-Windows-DNS-Client%4Operational.evtx` | 클라이언트 DNS (보통 꺼져 있음; 대신 Sysmon 22) |
| `Microsoft-Windows-SMBServer%4Security.evtx`, `SMBClient%4Connectivity/Security` | 공유 접근 오류, 횡적 이동의 부산물 |
| `Microsoft-Windows-NTLM%4Operational.evtx` | 감사가 켜져 있을 때 NTLM 인증 상세 |
| `Microsoft-Windows-Kernel-PnP%4Configuration.evtx`, `DriverFrameworks-UserMode%4Operational.evtx`, `Partition%4Diagnostic.evtx` | USB 장치 연결/분리 |
| `Microsoft-Windows-CodeIntegrity%4Operational.evtx` | 서명 없는/차단된 드라이버 (`3033/3077`) |
| `Microsoft-Windows-AppLocker%4EXE and DLL.evtx` 등 | AppLocker 차단/감사 `8002–8007` |
| `Microsoft-Windows-Shell-Core%4Operational.evtx` | Run 키 실행 `9707/9708` — Run 키의 명령이 보임 |
| `Microsoft-Windows-Storage-ClassPnP%4Operational.evtx`, `Ntfs%4Operational.evtx` | 볼륨/디스크 이벤트 |
| `Microsoft-Windows-Diagnosis-Scripted%4Operational.evtx`, `Windows-Kernel-Boot%4Operational.evtx` | 부팅 시각 — 가동 시간과 종료/삭제 시점 뒷받침 |
| `OpenSSH%4Operational.evtx` | Win32-OpenSSH 서버 로그인 |
| `Microsoft-Windows-Security-Mitigations%4KernelMode.evtx` | 익스플로잇 보호 |

## 수집 방법 { #how-to-collect }

=== "KAPE"

    ```powershell
    # All EVTX + parse to CSV with EvtxECmd (uses community maps to flatten fields)
    kape.exe --tsource C: --tdest C:\Case\out --target EventLogs --mdest C:\Case\mod --module EvtxECmd --vss
    ```

=== "Velociraptor"

    `Windows.EventLogs.Evtx` (채널 / ID로 필터), `Windows.EventLogs.EvtxHunter` (모든 로그에 정규식 헌트), 그리고 자주 묻는 질문용 `Windows.EventLogs.RDPAuth`, `Windows.EventLogs.PowershellScriptblock`.

=== "라이브 복사"

    ```powershell
    # Locked by the EventLog service but readable; wevtutil exports cleanly
    wevtutil epl Security C:\Case\Security.evtx
    wevtutil el | ForEach-Object { wevtutil epl $_ ("C:\Case\" + ($_ -replace '[\\/]','%4') + ".evtx") }

    # Or raw copy the directory (fine — files are consistent per chunk)
    robocopy C:\Windows\System32\winevt\Logs C:\Case\Logs *.evtx
    ```

## 파싱 방법 { #how-to-parse }

=== "EvtxECmd (Eric Zimmerman)"

    ```powershell
    # Everything → one CSV, with maps applied (PayloadData1..6 columns become meaningful)
    EvtxECmd.exe -d C:\Case\Logs --csv C:\Case\out --csvf evtx.csv

    # Only chosen IDs, time-bounded
    EvtxECmd.exe -d C:\Case\Logs --csv C:\Case\out --inc 4624,4625,4648,4672,4688,4698,4720,7045,1102 --sd "2026-09-01 00:00" --ed "2026-09-16 00:00"

    # Exclude the noisy ones
    EvtxECmd.exe -d C:\Case\Logs --csv C:\Case\out --exc 5156,5158,4658,4690

    # JSON for Splunk / jq
    EvtxECmd.exe -f C:\Case\Logs\Security.evtx --json C:\Case\out

    # Update the map files first (they define how each provider/ID is flattened)
    EvtxECmd.exe --sync
    ```

    CSV는 **Timeline Explorer**로 여세요. `MapDescription`, `UserName`, `RemoteHost`, `PayloadData*`, `ExecutableInfo` 열이 맵 덕분에 의미를 갖게 됩니다.

=== "Chainsaw + Sigma (빠른 트리아지)"

    ```bash
    # Hunt with Sigma rules across a folder of EVTX; outputs a table of detections
    chainsaw hunt C:\Case\Logs -s sigma/ --mapping mappings/sigma-event-logs-all.yml -o hits.csv --csv

    # Quick searches
    chainsaw search -t 'Event.System.EventID: =4624' -t 'Event.EventData.LogonType: =10' C:\Case\Logs
    chainsaw search "mimikatz" -i C:\Case\Logs
    ```

    **Hayabusa**가 대안입니다 (`hayabusa csv-timeline -d Logs -o out.csv`) — 매우 빠르고 Sigma 기반이며 심각도별 색상 표시, 타임라인 `logon-summary`와 `metrics` 모드가 있습니다.

=== "PowerShell"

    ```powershell
    # From saved evtx files
    Get-WinEvent -Path C:\Case\Logs\Security.evtx -FilterXPath "*[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='10']]" |
      Select TimeCreated, @{n='User';e={$_.Properties[5].Value}}, @{n='IP';e={$_.Properties[18].Value}}

    # Find the *oldest* record per log — tells you how far back you can see
    Get-ChildItem C:\Case\Logs\*.evtx | ForEach-Object {
      $e = Get-WinEvent -Path $_.FullName -Oldest -MaxEvents 1 -ErrorAction SilentlyContinue
      [pscustomobject]@{Log=$_.Name; Oldest=$e.TimeCreated; SizeMB=[math]::Round($_.Length/1MB,1)} }
    ```

=== "Plaso / Python"

    ```bash
    log2timeline.py --parsers winevtx out.plaso /evidence/Logs/
    # python-evtx (low level)
    evtx_dump.py Security.evtx > Security.xml
    ```

## 변조 탐지 { #detecting-tampering }

| 징후 | 의미 / 확인할 곳 |
|---|---|
| Security **`1102`** "감사 로그가 지워졌습니다" (계정 포함) | `wevtutil cl Security`, 이벤트 뷰어 "로그 지우기", Mimikatz `event::clear` |
| System **`104`** "<이름> 로그 파일이 지워졌습니다" | Security 이외의 채널 삭제 |
| 오래 켜져 있던 시스템인데 Security의 가장 오래된 레코드가 *몇 분* 전 | 삭제됨 (1102 자체가 유일하게 남은 레코드였거나, 곧바로 다시 지워짐) |
| 채널 안의 **`EventRecordID` 공백** | 레코드가 빠짐 (로그 덮어쓰기) 또는 선택적으로 삭제됨 (예: **DanderSpritz `eventlogedit`** 방식 — "참조되지 않은" 레코드를 남겨 청크 카빙으로 복구 가능) |
| Security `4719` 감사 정책 변경 / `4907` SACL 변경 / `4912` 사용자별 감사 정책 | 공격자가 다음 행동을 위해 로깅을 끔 |
| 있어야 할 `4688` / `4104`가 아예 없음 | 정책이 처음부터 꺼져 있었음 — `auditpol /get /category:*`와 PowerShell GPO 키 `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` 확인 |
| System `7036` EventLog 서비스 중지/시작; `7040` 시작 유형 변경 | 로그 파일을 직접 쓰거나 로깅을 멈추려고 서비스를 중지함 (**Phant0m** 방식의 스레드 종료는 중지 이벤트를 *남기지 않고* 서비스도 실행 중으로 보이지만 아무것도 기록되지 않음 — `$J`는 바쁜데 몇 시간 동안 이벤트가 0개인 평평한 구간을 찾을 것) |
| 시간 변경: Security `4616` (시스템 시간 변경), Kernel-General `1` | 타임라인을 헷갈리게 하려는 시간 조작 |
| 다른 파일은 오래됐는데 `.evtx` 파일의 `$SI` 생성 시각만 최근 | 파일이 삭제되고 서비스가 다시 만듦 |
| `WINEVT\Channels` 레지스트리에서 채널 `Enabled = 0` | 누군가 채널을 끔 (예: TaskScheduler) |

!!! tip "로그 이외의 증거로 뒷받침하세요"
    로그가 없을 때: [$UsnJrnl](mft-usn.md)은 여전히 파일 활동을, [Prefetch](prefetch.md)/[Amcache](amcache.md)는 실행을, [SRUM](srum.md)은 앱별·시간별 네트워크 바이트를 보여 줍니다. 그리고 `1102`는 *누가* *언제* 로그를 지웠는지 알려 주므로 — 그 직전 10분 동안 다른 모든 아티팩트에서 무슨 일이 있었는지 보세요.

**카빙**: 지워진 로그는 **EVTXtract**(`evtxtract image.dd > recovered.xml`)나 `ElfChnk` 청크 카빙(64 KB 청크 하나하나가 독립적으로 파싱 가능)으로 할당되지 않은 공간과 VSS에서 일부 복구할 수 있는 경우가 많습니다.

## 분석 팁 { #analysis-tips }

- **범위부터 확인**: 채널별 가장 오래된 이벤트, 최대 크기, `1102/104`, `4719`, `auditpol`. 보고서에 적으세요 — "Security 로그는 2026-09-14 03:12부터 2026-09-16 09:40까지만 존재했음".
- **시간대**: EVTX는 UTC입니다. Timeline Explorer / EvtxECmd 출력은 UTC이고 이벤트 뷰어는 로컬 시간입니다. 어느 쪽을 인용하는지 밝히세요.
- **Logon ID가 결합 키입니다**: `4624` → `4672` (관리자?) → `4634/4647` (세션 길이) → 같은 `SubjectLogonId`의 `4688` (그 세션에서 무엇이 실행됐나).
- **맵이 중요합니다**: EvtxECmd 맵(또는 SIEM의 필드 추출)이 없으면 `PayloadData3`만 쳐다보게 됩니다. 맵을 최신으로 유지하고, 사내 앱용 맵은 직접 만드세요.
- **Sysmon이 있으면 모든 게 달라집니다** — 있다면 거기서 시작하세요 (`1`, `3`, `7`, `8`, `10`, `11`, `12–14`, `22`).
- **서버 vs. 워크스테이션**: DC에는 `4768/4769/4776`(도메인 전체의 Kerberos/NTLM)이 있어서 Kerberoasting, 스프레이, 골든 티켓을 여기서 찾고, 워크스테이션에는 `4624 type 2/10`과 프로세스 이벤트가 있습니다.
- **`Computer` 필드를 무조건 믿지 마세요**: 전달/가져온 로그는 원래 호스트명을 유지합니다 — 좋은 점이지만 공격자가 호스트 이름을 바꾸면 헷갈릴 수 있습니다.

## 참고 자료 { #references }

- [Microsoft — Windows Event Log (EVTX) & wevtutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/wevtutil)
- [libevtx — Windows XML Event Log format](https://github.com/libyal/libevtx/blob/main/documentation/Windows%20XML%20Event%20Log%20(EVTX).asciidoc)
- [EvtxECmd + maps](https://github.com/EricZimmerman/evtx)
- [Chainsaw](https://github.com/WithSecureLabs/chainsaw) · [Hayabusa](https://github.com/Yamato-Security/hayabusa) · [EVTXtract](https://github.com/williballenthin/EVTXtract)
- [JPCERT — Tool Analysis Result Sheet (공격 도구별로 생성되는 이벤트)](https://jpcertcc.github.io/ToolAnalysisResultSheet/)
- [Windows 이벤트 ID 치트 페이지](../basics/windows-event-ids.md)
