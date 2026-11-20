---
title: 엔드포인트 공격
tags:
  - training
  - blue-team
  - endpoint
---

# 엔드포인트 공격 { #endpoint-attacks }

!!! abstract "한 줄 요약"
    전달이 성공하면 공격은 호스트 위로 옮겨 갑니다. 이 섹션은 엔드포인트 위의 침투를 한 단계씩 따라갑니다 — 최초 침투(서비스 측·클라이언트 측), 실행, 지속성, 정보 탐색, 권한 상승, 자격 증명 덤프, 옆으로 이동, 수집과 유출 — 그리고 각 단계가 남기는 프로세스·로그온·파일 증거와 대응하는 ATT&CK 기법을 함께 봅니다.

## 읽는 순서 { #reading-order }

| # | 페이지 | 핵심 |
| --- | --- | --- |
| 1 | [최초 침투 — 엔드포인트가 중요한 이유, 전달 단계, 서비스 측·클라이언트 측 익스플로잇](initial-exploitation.md) | 네트워크는 못 보고 엔드포인트는 보는 것(같은 연결의 Zeek `conn.log` vs Sysmon 3), 공격 단계 → ATT&CK 전술 → 가장 좋은 증거, 전달이 끝나는 지점, 세 개의 문(익스플로잇·사회공학·유효한 자격 증명), 공격자는 뚫린 프로세스가 된다 — "무엇이 어떤 권한으로 뚫렸나?"(`Get-Process -IncludeUserName`, `ps --forest`), 서비스 측: `Get-NetTCPConnection`/`ss -tlnp`로 듣는 포트 찾기, IIS 로그 한 줄과 `w3wp.exe` → `cmd.exe` 4688 칸별 해석, 클라이언트 측: `Zone.Identifier`(MotW)와 `WINWORD.EXE` → 숨긴 PowerShell Sysmon 1, 비교표와 분석 체크리스트, 경계 장비 익스플로잇·ClickFix(T1204.004)·기본 내장 Sysmon, 확인 문제 |
| 2 | [실행, 지속성, 정보 탐색 — 익스플로잇 직후 공격자가 하는 일](execution-persistence-discovery.md) | 익스플로잇 이후 활동과 정리 비용이 뛰는 이유, ATT&CK 전술 → 기법 → 하위 기법(Stealth TA0005 / Defense Impairment TA0112를 포함한 현재 전술 목록), 실행: 페이로드, 셸 vs C2 에이전트, `xp_cmdshell`로 SQL에서 빠져나오기(15457과 `sqlservr.exe` → `cmd.exe` 4688), 애플리케이션 제어와 AppLocker 8004, 지속성: 저울질, 여러 겹 지속성과 실패한 정리, Run 키(Sysmon 13)·예약 작업(4698 XML)·서비스(7045) 칸별 해석, 정보 탐색: 환경 속에 숨어 살기, `net group "Domain Admins" /domain`, 4688 PowerShell 사냥으로 몰아치기 탐지, 처음 5분 타임라인, 확인 문제 |
| 3 | [권한 상승 — 일반 사용자에서 관리자까지 올라가기](privilege-escalation.md) | 권한 사다리(사용자 → 로컬 관리자 → 여러 호스트 → 도메인 관리자)와 낮은 칸에서 시작해야 하는 이유, UAC 무결성 수준(`whoami /groups`), 권한 상승의 네 가지 방법(되기·속이기·특권 악용·익스플로잇), 허술한 권한: `icacls` ACL 칸별 해석, 덫 놓기(Sysmon 11) → 터짐(SYSTEM `0x3E7`의 4732) → `TokenElevationType`이 있는 4688, 서비스 실행 파일·레지스트리, 따옴표 없는 서비스 경로(`Get-CimInstance`로 점검), DLL 검색 순서 가로채기(Sysmon 7), 수정 가능한 작업, 리눅스 SUID/sudo(T1574.x, T1548), 메모리에서 도는 PowerUp과 4104, 커널 익스플로잇(T1068): 세 가지 재료, Dirty Pipe, `uname -r`, auditd `auid` ≠ `uid`, BYOVD, 관리자 보호, 확인 문제 |
| 4 | [자격 증명 덤프와 Mimikatz — 관리자 한 명에서 수많은 계정으로](credential-dumping-mimikatz.md) | 자격 증명 접근(TA0006)과 T1003 하위 기법(LSASS, SAM, LSA 비밀, 캐시, NTDS, DCSync, 리눅스), 덤프에 관리자가 필요한 이유(`SeDebugPrivilege`, `PROCESS_VM_READ`)와 그래도 이득인 이유, SSO와 인증 패키지별로 `lsass.exe`가 들고 있는 것(MSV1_0, Kerberos, WDigest, TsPkg, vault), 다시 쓸 비밀을 남기는 로그온 유형, NT 해시 = 자격 증명(T1550.002/.003), 방어자 수준의 Mimikatz(S0002), 가린 덤프 결과 한 줄씩, WDigest `UseLogonCredential` 수법, 파일 차단이 실패하는 이유, 증거: Sysmon 10 `GrantedAccess 0x1010`과 `UNKNOWN` 호출 추적, `comsvcs.dll MiniDump` 4688, 4104 `Invoke-Mimikatz`/`TVqQ`, Sysmon 13, 4624 유형 9 `seclogo`와 NTLM 유형 3, 7045 드라이버, 관리자 한 명에서 도메인까지의 사슬과 끊는 법(계층화, LAPS, Protected Users, Credential Guard, LSA 보호, ASR), Credential Guard·RunAsPPL 확인, 토큰 도용, NTLM 퇴장, 확인 문제 |

!!! info "이어서 추가될 내용"
    옆으로 이동·수집·유출 — 훔친 자격 증명으로 다른 호스트에 닿고, 데이터를 모으고, 밖으로 빼내는 방법(이 섹션의 마지막 페이지).

## 꼭 기억할 것 { #must-know }

1. 네트워크는 무언가 일어났다는 *사실*을, 엔드포인트는 *어떤 프로세스가, 어떤 사용자로, 무엇을*을 알려 준다.
2. 공격자는 뚫린 프로세스나 사용자가 된다 — 늘 그게 무엇이었고 어떤 권한이 있었는지 묻는다.
3. 서비스와 사용자의 최소 권한은 어떤 익스플로잇이든 피해를 줄이는 가장 싼 방법이다.
4. 서비스 측: 닿는 듣는 포트 필요, 사용자 불필요, 되풀이 가능 — 패치하거나 방화벽으로 막는다. 클라이언트 측: 사용자 필요, 들어오는 방향 방화벽 통과, 되풀이 어려움 — 지속성을 예상한다.
5. 서버 프로세스(`w3wp.exe`, `java.exe`)나 Office 프로그램이 셸·스크립트 실행기를 띄우는 건 가장 믿을 만한 익스플로잇 신호 중 하나다.

## 관련 레퍼런스 { #related }

- [피싱 전달](../../../adversary/phishing-delivery.md)
- [지속성](../../../adversary/persistence.md)
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md)
- [기타 네트워크 프로토콜](../other-protocols/index.md) — 옆으로 이동과 유출의 네트워크 쪽
