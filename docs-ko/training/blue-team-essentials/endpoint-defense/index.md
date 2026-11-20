---
title: 엔드포인트 방어
tags:
  - training
  - blue-team
  - endpoint
  - hardening
---

# 엔드포인트 방어 { #endpoint-defense }

!!! abstract "한 줄 요약"
    앞 섹션은 호스트 위를 지나가는 공격자를 따라갔고, 이 섹션은 같은 길을 방어자 쪽에서 다시 걷습니다. 공격 단계마다 방어선이 하나씩 있습니다 — 익스플로잇에는 인벤토리·취약점 스캔·패치·익스플로잇 보호, 설치에는 하드닝·백신·애플리케이션 제어·파일 무결성 모니터링·PAW, C2에는 호스트 방화벽, 최종 목표 행동에는 감사·행동 분석·DLP·로깅. 그리고 각 방어선은 막는 동시에 SOC가 쓸 증거를 남겨야 합니다.

## 읽는 순서 { #reading-order }

| # | 페이지 | 핵심 |
| --- | --- | --- |
| 1 | [자산 목록, 취약점 스캔, 패치, 익스플로잇 보호 — 공격이 자리 잡기 전에 막기](inventory-vulns-patching.md) | 킬 체인을 따라 겹겹이 막기(단계 → 공격자에게 필요한 것 → 엔드포인트 방어), 우리 소프트웨어 알기: Uninstall 레지스트리 인벤토리와 `dpkg-query`(백포트), `Win32_Product`를 쓰면 안 되는 이유, 능동 vs 수동 찾기, `nmap -sS -sV -O --script ftp-anon,smb-os-discovery` 스캔 한 줄씩(익명 FTP, 버전 숨긴 Tomcat, 지원 끝난 Server 2012 R2), T1046/T1595, 인증 없는 스캔 vs 인증 스캔 나란히, "reboot pending", 심각도·실제 악용(KEV/EPSS)·자산 등급으로 우선순위, OS·서버·클라이언트 패치, CIS Controls v7 → v8.1 번호, 긴급 패치 기준(Essential Eight 48시간), `Get-HotFix`·WindowsUpdateClient 19/20/43·`apt list --upgradable`·`reboot-required`로 확인, 익스플로잇 방지: DEP/ASLR/CFG/SEHOP의 원리, EMET → Exploit Guard → 지금, `Get-ProcessMitigation`, Security-Mitigations 로그, 제어된 폴더 액세스(1123/1124, T1486), 네트워크 보호(1125/1126), ASR 규칙, `Get-MpPreference` GUID와 동작, Office → PowerShell 차단 1121 칸별 해석, 라이선스와 수동 모드, 확인 문제 |
| 2 | [Credential Guard, Application Guard, 호스트 방화벽, 백신 — 비밀은 따로 가두고, 호스트에는 울타리 치기](vbs-firewall-antivirus.md) | LSASS 비밀이 왜 노림수인가(T1003.001 → T1550.002/.003), VBS와 두 신뢰 수준(VTL0/VTL1), 창구 구멍 뒤 금고로서의 `LsaIso.exe`, Credential Guard가 있을 때 덤프 모습, 필요 조건과 정말 도는지 확인(`Win32_DeviceGuard` Configured vs Running, `tasklist`, Wininit 13), 못 지키는 것(SAM, 키로거, 가짜 SSP T1547.005, 살아 있는 세션)과 부작용, LSA 보호(`RunAsPPL`) vs Credential Guard, Edge/Office용 Application Guard와 파일 차단, 그리고 은퇴, 킬 체인 전체에서 호스트 방화벽의 역할, 프로필, 기본 차단, `Get-NetFirewallProfile` 칸별 해석, `pfirewall.log` 칸별(SMB/RPC/WinRM 두드리기), WFP 5157 XML(들어올 때 Source = 로컬!), `auditpol` 실패만, 방화벽 변조(T1562.004, 4946~4950), 전술적 기록, 서브넷 안 호스트 vs 네트워크 방화벽과 PC↔PC 경보, 나가는 C2/유출(T1571, T1048), 백신: 시그니처 vs 머신러닝, 다형성, 파일 없는 공격과 AMSI, 변조(5001/5007/5013), 1116 칸별 해석(1117/1118), 희귀성 기반 분류, 확인 문제 |
| 3 | [애플리케이션 제어, 파일 무결성 모니터링, 지속성 잡기 — 아는 프로그램만 돌게, 바뀌면 바로 알게](appcontrol-fim-persistence.md) | 허용 목록 vs 차단 목록(초대 명단), 들어오는 게 아니라 실행을 막음, 스크립트/MSI/DLL까지 덮기, CIS 2.5~2.7과 Essential Eight, 규칙 종류(이름, 경로, 게시자, 해시)와 강도, `icacls`로 본 쓰기 가능한 허용 경로, 감사 → 다듬기 → 강제, 센서로서의 감사 이벤트, AppLocker vs App Control for Business(옛 WDAC), Gatekeeper, AppArmor/SELinux, fapolicyd, AppLocker 8004 XML 칸별(8002~8007), CodeIntegrity 3076/3077, AppArmor `DENIED exec` nginx → bash 한 줄, 우회와 흔적: 스크립트와 제한 언어 모드(T1059), LOLBin/`rundll32`(T1218), 인젝션(T1055), 이름·경로(T1036.005, T1574), 훔친 서명 키(T1553.002), SHA-1 충돌, FIM: 무엇을 기록하나, 어디에 거나, `aide --check`와 실시간 에이전트 경보로 잡은 웹 셸(T1505.003, 소유자 `www-data`), 다듬기, ASEP: Run 키/시작 프로그램, 서비스, 작업, 브라우저 확장(T1176.001), 정상 계정, Linux cron/systemd/SSH 키, 권한과 지속성 깊이(루트킷 T1014), Run 키 `Get-ItemProperty`, `autorunsc -a * -c -h -s -m`과 CSV 한 줄씩(`-enc SQBFAFgA` = `IEX`), 희귀성 비교, 계속 돌아가는 탐지(Sysmon 11/13, 7045/4697, 4698, 4720), 확인 문제 |
| 4 | [PAW, 권한과 특권, EDR, DLP, UEBA, 감사 로깅 — 관리자 열쇠는 지키고, 모든 건 기록하기](paw-edr-dlp-ueba.md) | 관리자 자격 증명이 평소 PC에 닿으면 안 되는 이유(LSASS, T1003.001 → T1550.002/.003), 계정 분리와 PAW(호스트 vs 게스트 VM), 깨끗한 출발점과 계층화(아래로는 로그온 금지), 인사팀 PC에 찍힌 `adm-` 유형 10 4624와 짝이 되는 4672 칸별 해석, PAW 위반 규칙, 권한 vs 특권(자물쇠 vs 직책), `utilman.exe`의 `icacls`(TrustedInstaller, T1546.008), `whoami /priv`(Disabled ≠ 없음), 위험한 특권 표(`SeDebug`, `SeBackup`, `SeRestore`, `SeLoadDriver`, `SeImpersonate`, `SeTakeOwnership`), Backup Operators의 `reg save HKLM\SAM`(T1003.002), VM 스냅숏, 4673/4674, 비행 기록 장치로서의 EDR, Word → 숨긴 `-enc` PowerShell → 203.0.113.45 기록 칸별 해석, 대응 기능과 RDP 접속보다 라이브 대응이 나은 이유, EDR 변조(T1562.001, BYOVD), XDR, DLP: 네트워크 vs 엔드포인트, 등급과 내용 검사, Luhn·개수 기준을 더한 카드 번호 정규식, USB 차단 경보(T1052.001), 세 가지 쓰임새와 한계, UEBA: 기준선, 동료 그룹, `svc-backup` → DC01 → `ntdsutil` 결과, 기저율 계산, 감사 정책: `auditpol` 구멍(프로세스 생성, 명령줄), 1102, `auditd` 규칙과 `auid`, rsyslog `@@` 전달, 수집 범위 지도, 심층 방어 정리 표, 확인 문제 |

!!! success "섹션 완료"
    엔드포인트 방어 섹션이 끝났습니다. 다음은 **Windows 로그** — 로그 수집이 왜 중요한지, Windows 이벤트 로깅이 어떻게 돌아가는지(공급자, 채널, 로그가 지나가는 길, 감사 설정), 이벤트의 System과 EventData 부분 읽기, 템플릿과 설명 문구, 그리고 SOC가 모아야 할 채널입니다.

## 꼭 기억할 것 { #must-know }

1. 방어는 한 겹으로 부족하다 — 공격 단계에 맞춰 방어 수단을 세우고, 모든 겹이 막는 동시에 기록하게 한다.
2. 모르는 건 지킬 수 없다 — 인벤토리(무엇이 설치됐나)와 네트워크 스캔(무엇이 드러났나)을 합친다.
3. 패치 결정은 인증 스캔으로 한다. 인증 없는 스캔의 "치명적 발견 없음"은 "안전"이 아니라 "알 수 없음"이다.
4. OS, 서버, *그리고* 클라이언트 소프트웨어를 패치하고, 긴급 패치 기준은 필요해지기 전에 합의한다. 재부팅 전까지는 "설치됨"이지 "패치됨"이 아니다.
5. 익스플로잇 방지는 특정 버그가 아니라 기법을 깨뜨린다. 그 차단 이벤트(Security-Mitigations, Defender 1121/1123/1126)는 SOC가 받는 가장 질 좋은 경보 중 하나다. 감사 모드는 아무것도 지켜 주지 않는다.
6. 관리자 자격 증명은 PAW에서만, 아래로는 절대 로그온하지 않는다. 디버그·백업·복원·드라이버 특권을 가진 계정은 모두 특권 계정이다.
7. EDR은 이벤트 사이의 관계를 기록하고 안전한 대응 통로를 준다. DLP와 UEBA는 데이터 탈취와 계정 오용을 늦추고 드러내지만, 서로를, 그리고 EDR을 대신하지 못한다. 감사 정책과 호스트 밖으로 보낸 로그가 없으면 이 중 아무것도 돌아가지 않는다.

## 관련 레퍼런스 { #related }

- [엔드포인트 공격](../endpoint-attacks/index.md) — 같은 단계를 공격자 쪽에서
- [Windows 버전별 하드닝](../../../adversary/hardening-by-version.md)
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md)
