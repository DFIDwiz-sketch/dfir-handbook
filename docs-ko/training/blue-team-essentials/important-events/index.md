---
title: 꼭 알아야 할 이벤트
tags:
  - training
  - blue-team
  - windows
  - linux
  - logging
---

# 꼭 알아야 할 이벤트 { #important-events }

!!! abstract "한 줄 요약"
    Windows 이벤트 ID 몇 개와 Linux 로그 줄 몇 가지가 조사 질문 대부분에 답합니다. 누가, 어떻게, 어디서 로그온했나; 무엇이 실행됐나; 무엇이 허용되거나 막혔나; 재부팅을 버티려고 무엇이 설치됐나; 어떤 계정이 바뀌었나; 백신과 PowerShell이 무엇을 봤나; Kerberos 티켓이 어떻게 발급됐나. 이 섹션은 그 하나하나를 칸 단위로 읽고, 무슨 뜻인지, 언제 생기는지, 공격자에게 왜 중요한지 설명합니다.

## 읽는 순서 { #reading-order }

| # | 페이지 | 핵심 |
| --- | --- | --- |
| 1 | [로그인 이벤트 — 4624/4625와 로그온 유형, 4648 명시적 자격 증명, Linux 로그인과 로그인 실패](logins.md) | 대상 컴퓨터에 남는 4624, EventData 칸별 해석(Subject vs Target, 로컬 계정이면 `TargetDomainName` = 컴퓨터 이름, `LogonProcessName`, `AuthenticationPackageName`, 믿으면 안 되는 `WorkstationName`, `IpAddress`, `ElevatedToken`/연결된 로그온); 로그온 유형 2–13 표와 정정(유형 11 = 캐시, 유형 2 ≠ 물리적 접근), RDP = 유형 3 + 10; 로그온 ID로 4672/4688/4634/4647 따라가기; 컴퓨터 계정·서비스 잡음과 `Get-WinEvent` 필터 한 줄씩; Status/SubStatus 표가 있는 4625, NLA RDP 실패는 유형 3, DC 쪽 4771/4776; 출발지에 남는 4648, subject/target/server/process, runas 사례, 유형 9 `seclogo`; PID로 묶인 여러 줄의 Linux SSH 로그인, 키 지문(T1098.004), `sshd-session`; Linux 실패 모양(`Invalid user`, `Failed password`, PAM `authentication failure`, sudo), 사용자 이름 칸의 비밀번호, IP별 실패 세기; Windows vs Linux 표; T1078, T1110, T1021, T1550.002, T1134.002; SOC 점검 목록; 확인 문제 |
| 2 | [프로세스 생성 이벤트 — 4688, Sysmon 이벤트 1, auditd와 audit.log, Snoopy](process-creation.md) | 프로세스 로그가 대부분의 공격을 잡는 이유(LOLBin, T1059/T1218), 이상적인 칸 표와 출처; Audit Process Creation과 별도 명령줄 정책이 필요한 4688, EventData 칸별 해석(`ProcessId` = 부모, `TokenElevationType` %%1936/7/8, `MandatoryLabel`), Word → cmd → certutil 사슬, `Get-WinEvent` 필터 한 줄씩; Sysmon 이벤트 1이 더 주는 것(`ProcessGuid`, `OriginalFileName`, `Hashes`/IMPHASH, `ParentCommandLine`, `ParentUser`)과 서명은 없다는 정정; 4688 vs Sysmon 표; auditd `execve` 규칙 단어별(b64 + b32, `execveat`, rules.d), 여섯 줄짜리 `audit.log` 기록 칸별 해석(일련번호, `syscall=59`, `auid` vs `uid`, `tty`, `ses`), 16진수 EXECVE/PROCTITLE, `ausearch -i`와 `aureport -x`; auditd 다듬기와 지키기(T1562.012, `-e 2`); `ld.so.preload`로 동작하는 Snoopy, 한 줄 칸별 해석, 정보 수집 스크립트 사례, 우회(T1574.006); 네 출처 비교; SOC 점검 목록; 확인 문제 |
| 3 | [방화벽과 개체 접근 이벤트 — Windows 방화벽 로그(pfirewall.log, 5156/5157/5152/5154), iptables/UFW 로그, 4663/4657/4660](firewall-object-access.md) | 동서 트래픽을 보고 프로세스까지 아는 센서로서의 호스트 방화벽; `pfirewall.log` 설정(프로필별 파일, 기본 4,096 KB, 최대 약 32 MB, `.old` 회전), 머리와 모든 칸 해석, 현지 시각, 이름 없이 PID만, 445/3389/ICMP를 찔러 보는 이웃; `auditpol`로 켜는 필터링 플랫폼 감사 하위 범주, 5156/5157/5152/5154/5158 표, 5156 칸별 해석(10진수 `ProcessID`, 장치 경로, `%%14593` 방향, `FilterRTID`, 계층); 방화벽 변경 이벤트 4946–4950과 2003–2006/2097(T1562.004); iptables `LOG` 규칙 단어별, UFW 접두어, 커널 줄 두 개를 syslog 머리와 `KEY=value` 칸으로 쪼개기, 깃발 단어와 두 번 나오는 `LEN`, 프로세스 없음, nftables; 비교 표; 정책 **그리고** SACL이 필요한 개체 접근, 접근 마스크 표와 PID 4로 보이는 SMB가 있는 4663 Subject/Object/Process/Access, Run 키의 옛 값/새 값을 보여 주는 4657(T1547.001), `HandleId`로 잇는 4660, 4656/4658/4670/5140/5145와 LSASS; SOC 점검 목록; 확인 문제 |
| 4 | [서비스, 예약 작업, USB 이벤트 — 7045/4697, 4698–4702와 작업 스케줄러 로그, 6416 플러그 앤 플레이](services-tasks-usb.md) | 지속성(T1543.003)과 원격 실행(T1569.002, PsExec 방식 임시 서비스)으로 쓰이는 서비스; 서비스 설정 표(`ImagePath`, 유형, 시작 유형, 계정); System 채널 7045 칸별 해석(유일한 "누가"인 `Security UserID`, `%COMSPEC%`와 `\\127.0.0.1\C$`가 든 명령줄 `ImagePath`, 수동 vs 자동 시작), 함께 나오는 7036/7009/7040과 부모 `services.exe`; `ImagePath` 변경은 설치 이벤트를 안 남김; *Security System Extension*과 Subject/로그온 ID가 있는 4697, 7045 vs 4697 표; 판단 점검 목록과 쌓아 보기; 지속성·원격 실행용 예약 작업(T1053.005), *Other Object Access Events*(SACL 불필요), 중첩 `TaskContent` XML이 든 4698 한 줄씩 해석(트리거, SYSTEM 주체, `Hidden`, rundll32 `Exec`), 중첩 XML 파싱; 4699–4702 표; 작업 스케줄러 Operational 106/129/140/141/200/201 타임라인; `SD` 값을 지운 숨은 작업; USB 위협(T1091, T1052.001, T1200), *Plug and Play Events*, 6416 칸별 해석(subject는 늘 SYSTEM, VID/PID/인스턴스 ID, `HIDClass`, `Class_03` 키보드), 장치 하나에 6416 여러 개, VID/PID 조회와 한계, 다른 장치 로그; SOC 점검 목록; 확인 문제 |

!!! info "이어서 추가될 내용"
    계정과 그룹 변경, Defender와 PowerShell 로그, Kerberos(4768, 4769, 4770).

## 꼭 기억할 것 { #must-know }

1. 4624/4625는 로그온을 받은 컴퓨터에, 4648은 자격 증명을 쓴 출발지 컴퓨터에 남는다. 워크스테이션, 서버, 도메인 컨트롤러 모두에서 수집한다.
2. 로그온 유형은 들어온 문이다. 2 콘솔, 3 네트워크, 4 배치, 5 서비스, 7 잠금 해제, 8 평문, 9 새 자격 증명, 10 RDP, 11 캐시. 유형 11은 "키보드 앞의 도메인 사용자"가 아니고, 유형 2는 물리적 접근의 증거가 아니다.
3. 로컬 계정의 도메인 칸은 컴퓨터 이름이다. 로컬 계정이 네트워크로 여러 호스트에 로그온하면 위험 신호다.
4. 로그온 ID는 로그온을 그 권한, 프로세스, 로그오프와 이어 준다. 호스트 이름과 같이 검색한다.
5. 컴퓨터 계정과 서비스 신원은 쿼리에서 거르고, 수집에서는 절대 빼지 않는다.
6. SubStatus가 실패 이유를 알려 준다. `0xc0000064` 없는 사용자, `0xc000006a` 틀린 비밀번호, `0xc0000234` 잠김.
7. Linux 로그인은 PID로 묶인 여러 줄의 자유 문장이다. 로그인 프로그램마다, 실패 이유마다 패턴이 따로 필요하다.
8. 로그인 로그에는 민감한 데이터(사용자 이름 칸에 친 비밀번호)가 있다. 접근을 제한한다.
9. 프로세스 생성에서 중요한 칸은 명령줄과 부모다. 4688은 명령줄 정책을 따로 켜야 하고, 4688의 `ProcessId`는 부모다.
10. Linux auditd의 `auid`는 `sudo`를 거쳐도 처음 로그인한 사용자를 간직한다. `auid`가 비어 있고 `tty=(none)`인데 셸이 돈다면 사람이 아니라 데몬이나 웹셸이다.
11. 호스트 방화벽 로그는 동서 트래픽을 본다. Windows에서는 5156/5157이 프로세스 이름까지 알려 준다. Filtering Platform Connection 성공을 켜기 전에 양부터 계획한다.
12. 개체 접근 이벤트(4663/4657/4660)에는 감사 하위 범주 **그리고** 개체의 SACL이 필요하다. SACL이 없으면 이벤트도 없다. 4660에는 이름이 없으니 `HandleId`를 따라간다.
13. 서비스 설치: **System**의 7045(늘 켜짐)와 Security의 4697(*Security System Extension* 필요). `ImagePath`부터 보세요. 명령줄이나 사용자가 쓸 수 있는 폴더면 위험 신호입니다.
14. 예약 작업: 4698–4702에는 *Other Object Access Events*가 필요하고, 명령은 `TaskContent` 안의 중첩 XML에 있습니다. 6416은 새 장치를 클래스와 VID/PID로 보여 줍니다. 저장 장치만이 아니라 키보드와 네트워크 어댑터도 지켜보세요.

## 관련 레퍼런스 { #related }

- [Windows 로그](../windows-logging/index.md) — Security 로그가 만들어지고 구성되는 방식
- [Linux 로그](../linux-logging/index.md) — syslog, 로그 파일, 저널
- [엔드포인트 공격](../endpoint-attacks/index.md) — 이 이벤트들이 기록하는 공격자 행동
- [Windows 이벤트 로그(EVTX)](../../../windows/event-logs.md)
