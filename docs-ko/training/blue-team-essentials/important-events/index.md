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

!!! info "이어서 추가될 내용"
    프로세스 생성(4688, auditd와 `audit.log`, Snoopy), 방화벽 로그와 개체 접근 감사, 서비스·예약 작업·USB 장치, 계정과 그룹 변경, Defender와 PowerShell 로그, Kerberos(4768, 4769, 4770).

## 꼭 기억할 것 { #must-know }

1. 4624/4625는 로그온을 받은 컴퓨터에, 4648은 자격 증명을 쓴 출발지 컴퓨터에 남는다. 워크스테이션, 서버, 도메인 컨트롤러 모두에서 수집한다.
2. 로그온 유형은 들어온 문이다. 2 콘솔, 3 네트워크, 4 배치, 5 서비스, 7 잠금 해제, 8 평문, 9 새 자격 증명, 10 RDP, 11 캐시. 유형 11은 "키보드 앞의 도메인 사용자"가 아니고, 유형 2는 물리적 접근의 증거가 아니다.
3. 로컬 계정의 도메인 칸은 컴퓨터 이름이다. 로컬 계정이 네트워크로 여러 호스트에 로그온하면 위험 신호다.
4. 로그온 ID는 로그온을 그 권한, 프로세스, 로그오프와 이어 준다. 호스트 이름과 같이 검색한다.
5. 컴퓨터 계정과 서비스 신원은 쿼리에서 거르고, 수집에서는 절대 빼지 않는다.
6. SubStatus가 실패 이유를 알려 준다. `0xc0000064` 없는 사용자, `0xc000006a` 틀린 비밀번호, `0xc0000234` 잠김.
7. Linux 로그인은 PID로 묶인 여러 줄의 자유 문장이다. 로그인 프로그램마다, 실패 이유마다 패턴이 따로 필요하다.
8. 로그인 로그에는 민감한 데이터(사용자 이름 칸에 친 비밀번호)가 있다. 접근을 제한한다.

## 관련 레퍼런스 { #related }

- [Windows 로그](../windows-logging/index.md) — Security 로그가 만들어지고 구성되는 방식
- [Linux 로그](../linux-logging/index.md) — syslog, 로그 파일, 저널
- [엔드포인트 공격](../endpoint-attacks/index.md) — 이 이벤트들이 기록하는 공격자 행동
- [Windows 이벤트 로그(EVTX)](../../../windows/event-logs.md)
