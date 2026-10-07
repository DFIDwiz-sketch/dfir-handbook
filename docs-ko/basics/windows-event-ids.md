---
title: Windows 이벤트 ID
tags:
  - concept
  - basics
  - windows
---

# Windows 이벤트 ID { #windows-event-ids }

<div class="dfir-meta" markdown>
**분류:** 기초 · **최종 수정:** 2026-09-09
</div>

!!! abstract "한 줄 요약"
    침해사고 대응자가 가장 먼저 찾는 이벤트 ID를 질문별로 묶었습니다("누가 로그온했나?", "무엇이 실행됐나?", "무엇이 지속성을 남겼나?"). 구버전(Vista 이전) ID는 보통 최신 ID에서 4096을 뺀 값입니다 — `528` → `4624`.

!!! warning "기본으로 다 켜져 있지는 않습니다"
    `4688`(프로세스 생성), `4698`(예약 작업), `4104`(PowerShell 스크립트 블록)와 대부분의 객체 접근 이벤트는 감사 정책이나 GPO를 바꿔야 기록됩니다. "아무것도 실행되지 않았다"고 결론 내리기 전에 그 로그 소스가 켜져 있었는지 확인하세요 — `Security` 로그에서 `4719`(감사 정책 변경)를 찾고, 가장 오래된 이벤트 시각을 보고 로그 삭제나 덮어쓰기(rollover)를 확인합니다.

## 로그온과 인증 (Security 로그) { #logon-authentication-security-log }

| ID | 의미 | 메모 |
|---|---|---|
| 4624 | 로그온 성공 | 아래 **로그온 유형** 표 참고. `Logon ID`로 4634/4647, 4672와 연결 |
| 4625 | 로그온 실패 | `Status`/`SubStatus`가 이유를 알려 줌 (`0xC000006A` 비밀번호 틀림, `0xC0000064` 없는 사용자, `0xC0000234` 계정 잠김) |
| 4634 | 로그오프 | 세션 종료 |
| 4647 | 사용자가 직접 로그오프 | 대화형 로그오프 |
| 4648 | 명시적 자격증명으로 로그온 | `runas`, 저장된 자격증명을 쓰는 예약 작업, 다른 자격증명을 쓴 횡적 이동 |
| 4672 | 특수 권한 할당 | 관리자급 로그온. 같은 Logon ID의 4624와 짝지어 볼 것 |
| 4768 | Kerberos TGT 요청 (AS-REQ) | DC에 기록. `Result Code 0x6` = 없는 사용자; `0x18` = 비밀번호 틀림 |
| 4769 | Kerberos 서비스 티켓 요청 (TGS-REQ) | DC에 기록. **Kerberoasting**: 한 계정에서 `Ticket Encryption Type 0x17`(RC4) 4769가 다수 |
| 4771 | Kerberos 사전 인증 실패 | Kerberos 무차별 대입 |
| 4776 | NTLM 자격증명 검증 | DC(도메인 계정) 또는 로컬 머신에 기록. 몰려 나오면 스프레이 |
| 4778 / 4779 | RDP 세션 재연결 / 연결 끊김 | 출발지 호스트명과 IP 포함 |
| 4740 | 계정 잠김 | `Caller Computer Name`이 원인 호스트를 가리킴 |
| 4767 | 계정 잠금 해제 | |

### 4624 로그온 유형 { #4624-logon-types }

| 유형 | 이름 | 일반적인 의미 |
|---|---|---|
| 2 | Interactive | 키보드 앞에서 (또는 VNC 같은 도구로) |
| 3 | Network | SMB 공유 접근, WinRM(사전 인증), PsExec, WMI. 횡적 이동 대부분 |
| 4 | Batch | 예약 작업 |
| 5 | Service | 서비스 시작 |
| 7 | Unlock | 워크스테이션 잠금 해제 |
| 8 | NetworkCleartext | IIS Basic 인증, 일부 PowerShell remoting |
| 9 | NewCredentials | `runas /netonly`, Cobalt Strike `make_token`, pass-the-hash 도구 |
| 10 | RemoteInteractive | RDP / 터미널 서비스 |
| 11 | CachedInteractive | DC에 닿지 못할 때 도메인 자격증명 사용 (네트워크 밖 노트북) |

## 계정 관리 (Security 로그) { #account-management-security-log }

| ID | 의미 |
|---|---|
| 4720 | 사용자 계정 생성 |
| 4722 | 사용자 계정 활성화 |
| 4723 / 4724 | 비밀번호 변경 시도(사용자) / 재설정(관리자) |
| 4725 | 사용자 계정 비활성화 |
| 4726 | 사용자 계정 삭제 |
| 4728 / 4732 / 4756 | 전역 / 로컬 / 유니버설 **보안** 그룹에 멤버 추가 |
| 4729 / 4733 / 4757 | 같은 그룹에서 멤버 제거 |
| 4738 | 사용자 계정 변경 |
| 4741 / 4742 / 4743 | 컴퓨터 계정 생성 / 변경 / 삭제 |
| 4794 | DSRM 비밀번호 설정 (디렉터리 서비스 복원 모드 — DC 지속성) |

## 프로세스와 명령 실행 { #process-command-execution }

| 로그 | ID | 의미 | 메모 |
|---|---|---|---|
| Security | 4688 | 새 프로세스 생성 | GPO에서 *프로세스 생성 이벤트에 명령줄 포함*을 켜야 함. 안 켜면 이미지 경로만 남음 |
| Security | 4689 | 프로세스 종료 | |
| Sysmon | 1 | 프로세스 생성 | 명령줄, 해시, 부모 프로세스 — Sysmon이 있다면 최고의 기준 |
| Sysmon | 3 | 네트워크 연결 | 프로세스 ↔ 목적지 IP/포트 |
| Sysmon | 7 | 이미지 로드 | DLL 로드 — 사이드로딩, 서명 없는 DLL |
| Sysmon | 8 | CreateRemoteThread | 전형적인 인젝션 |
| Sysmon | 10 | ProcessAccess | LSASS 접근 (대상 `lsass.exe`, 접근 권한 `0x1010`/`0x1fffff`) = 자격증명 덤프 |
| Sysmon | 11 | 파일 생성 | 드로퍼, 스테이징된 도구 |
| Sysmon | 12 / 13 / 14 | 레지스트리 객체 생성·삭제 / 값 설정 / 키 이름 변경 | Run 키, 서비스 |
| Sysmon | 22 | DNS 조회 | 프로세스 → 도메인 |
| PowerShell/Operational | 4103 | 모듈 로깅 (파이프라인 실행) | |
| PowerShell/Operational | 4104 | 스크립트 블록 로깅 | 디코딩된 스크립트 내용 — `-enc` 페이로드도 보임. GPO로 활성화 |
| Windows PowerShell (클래식) | 400 / 403 | 엔진 시작 / 중지 | 4688이 없어도 `HostApplication` 필드에 명령줄이 남음 |
| Windows PowerShell (클래식) | 600 | 프로바이더 시작 | |
| Security | 4698 / 4699 | 예약 작업 생성 / 삭제 | 이벤트 안에 작업 XML이 들어 있음 |
| Security | 4700 / 4701 / 4702 | 예약 작업 활성화 / 비활성화 / 업데이트 | |
| TaskScheduler/Operational | 106 / 140 / 141 / 200 / 201 | 작업 등록 / 업데이트 / 삭제 / 동작 시작 / 동작 완료 | 최신 빌드에서는 기본으로 꺼져 있는 경우가 많음 |
| System | 7045 | 새 서비스 설치 | PsExec(`PSEXESVC`), Cobalt Strike `jump psexec`, Meterpreter 서비스 |
| Security | 4697 | 서비스 설치 (7045의 Security 로그 버전) | 감사 정책 필요 |
| System | 7034 / 7035 / 7036 / 7040 | 서비스 크래시 / 제어 명령 / 상태 변경 / 시작 유형 변경 | 7040 = 누군가 서비스를 비활성화함 (예: Defender, VSS) |
| Application | 1000 / 1001 | 애플리케이션 크래시 / WER 보고서 | 실패한 익스플로잇, 인젝션된 프로세스 크래시 |

## 지속성과 변조 { #persistence-tampering }

| 로그 | ID | 의미 |
|---|---|---|
| Security | 4657 | 레지스트리 값 수정 (SACL 필요) |
| Security | 4663 | 객체 접근 시도 (파일/레지스트리, SACL 필요) |
| Security | 4670 | 객체 권한 변경 |
| Security | 4719 | 시스템 감사 정책 변경 — 공격자가 로깅을 끔 |
| Security | 1102 | **Security 로그 삭제됨** |
| System | 104 | **이벤트 로그 삭제됨** (모든 로그) |
| Security | 4616 | 시스템 시간 변경 |
| Security | 4720 | (위 참고) 새 로컬 사용자 = 지속성 |
| Security | 5140 / 5145 | 네트워크 공유 접근 / 공유 객체 확인 (`\\*\ADMIN$`, `\\*\C$`, `IPC$`) |
| Security | 5156 / 5157 | Windows Filtering Platform이 연결 허용 / 차단 (매우 시끄러움) |
| Windows Defender/Operational | 1116 / 1117 | 악성코드 탐지 / 조치 |
| Windows Defender/Operational | 5001 / 5007 | 실시간 보호 비활성화 / 설정 변경 |
| Microsoft-Windows-WMI-Activity/Operational | 5857 – 5861 | WMI 프로바이더 / 컨슈머 활동. **5861** = 영구 이벤트 컨슈머 생성 (WMI 지속성) |
| Security | 4720 + 4732가 연달아 | 새 사용자를 바로 Administrators에 추가 |

## 원격 접근과 횡적 이동 { #remote-access-lateral-movement }

| 로그 | ID | 의미 |
|---|---|---|
| Security | 4624 type 3 + 5140 `ADMIN$` + System 7045 | PsExec 방식 실행 체인 |
| Security | 4624 type 10 / 4778 | RDP 로그온 |
| TerminalServices-RemoteConnectionManager/Operational | 1149 | RDP 네트워크 연결 성공 (로그온 전) — 출발지 IP 포함 |
| TerminalServices-LocalSessionManager/Operational | 21 / 22 / 24 / 25 | RDP 세션 로그온 / 셸 시작 / 연결 끊김 / 재연결 |
| RemoteDesktopServices-RdpCoreTS/Operational | 131 | 들어오는 RDP 연결 (출발지 IP) |
| Microsoft-Windows-WinRM/Operational | 6 / 91 / 168 | WinRM 클라이언트 연결 / 셸 생성 / 사용자 인증 |
| Security | 4688 `wsmprovhost.exe` | **대상** 호스트에서의 PowerShell Remoting |
| Security | 4688 부모가 `wmiprvse.exe` | **대상** 호스트에서의 WMI 실행 |
| Security | 4648 | 명시적 자격증명 — 흔히 횡적 이동의 **출발지** 쪽 |
| Security | 4624 type 9 | `runas /netonly` / pass-the-hash 형태의 토큰 |

## USB와 장치 { #usb-devices }

| 로그 | ID | 의미 |
|---|---|---|
| Security | 6416 | 새 외부 장치 인식 |
| Security | 6419 – 6424 | 장치 설치 / 비활성화 / 활성화 이벤트 |
| DriverFrameworks-UserMode/Operational | 2003 / 2100 / 2102 | USB 장치 연결 / 분리 (로그가 꺼져 있는 경우 많음) |
| Microsoft-Windows-Partition/Diagnostic | 1006 | 장치 연결/분리, 시리얼과 파티션 정보 포함 |
| Security | `\Device\HarddiskVolume`에 대한 4663 | 이동식 매체의 파일 접근 (SACL 필요) |

## 치트: 첫 트리아지 쿼리 세트 { #cheat-first-triage-query-set }

=== "Splunk"

    ```spl
    index=wineventlog sourcetype=WinEventLog:Security
    EventCode IN (1102, 4624, 4625, 4648, 4672, 4688, 4697, 4698, 4720, 4732, 4776)
    | eval LogonType=coalesce(Logon_Type, LogonType)
    | stats count min(_time) as first max(_time) as last by host, EventCode, user, LogonType
    | convert ctime(first) ctime(last)
    | sort host, EventCode
    ```

=== "PowerShell (라이브)"

    ```powershell
    Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625,4648,4672,4688,4698,4720,1102; StartTime=(Get-Date).AddDays(-7)} |
      Select-Object TimeCreated, Id, @{n='Msg';e={$_.Message.Split("`n")[0]}} |
      Format-Table -AutoSize
    ```

=== "EvtxECmd (오프라인)"

    ```powershell
    EvtxECmd.exe -d C:\Case\Logs --csv C:\Case\Out --inc 1102,4624,4625,4648,4672,4688,4697,4698,4720,4732,7045
    ```

## 참고 자료 { #references }

- [Microsoft — Security auditing event reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [Ultimate Windows Security — Event ID encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [SANS — Windows Event Log Analysis poster / Hunt Evil](https://www.sans.org/posters/)
- [Sysmon event ID reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
