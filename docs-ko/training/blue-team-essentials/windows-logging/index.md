---
title: Windows 로그
tags:
  - training
  - blue-team
  - windows
  - logging
---

# Windows 로그 { #windows-logging }

!!! abstract "한 줄 요약"
    엔드포인트 조사는 거의 다 Windows 이벤트 로그로 끝납니다. 그래서 분석가는 로그가 어디서 오는지 알아야 합니다. 어느 프로그램(공급자)이 이벤트를 썼는지, Event Log 서비스가 그걸 어떻게 채널과 `.evtx` 파일로 나누는지, 애초에 이벤트가 기록될지를 무엇이 정했는지(감사 정책, Sysmon, 사용자 채널), 그리고 이벤트 하나의 XML이 어떻게 우리가 보는 읽기 좋은 메시지가 되는지. 이것이 무엇을 검색할 수 있고, 무엇이 빠질 수 있고, SIEM이 어떻게 파싱해야 하는지를 정합니다.

## 읽는 순서 { #reading-order }

| # | 페이지 | 핵심 |
| --- | --- | --- |
| 1 | [Windows 이벤트 로깅의 원리 — 공급자, 채널, 로그가 지나가는 길, 감사 설정, 한 이벤트의 세 가지 보기](how-event-logging-works.md) | 분석가가 수집을 알아야 하는 이유(0건 = 안 일어남 / 기록 안 됨 / 안 모임), 형식·내용·수집, Windows vs Linux, 이진 XML `.evtx`, Windows 로그 vs 응용 프로그램 및 서비스 로그, 채널 종류(Admin/Operational/Analytic/Debug), Security가 특별한 이유, 로그가 지나가는 길: 공급자 → EventLog 서비스 → 채널 → `winevt\Logs`(파일 이름의 `%4`) → 이벤트 뷰어/`Get-WinEvent`/`wevtutil`/에이전트, 변조 T1070.001/T1562.002, 1102/104, `Get-WinEvent -ListLog`와 `-FilterHashtable` 한 줄씩, 몰려 나오는 4625(T1110), `auditpol`로 본 감사 정책(4624/4625/4688/4663, SACL), 옛 방식 vs 고급, 4719, Sysmon과 `New-EventLog`/`Write-EventLog`로 만든 사용자 채널(5.1 전용), 자기 로그를 쓰는 앱과 Zeek/Suricata, 메타데이터: 수준 표, 키워드 감사 성공/실패, 공급자, 공급자별 이벤트 ID(System ID 1: Power-Troubleshooter vs Kernel-General), 작업 범주, `EventRecordID` 건너뜀, 4625 하나를 일반·쉬운 보기·XML로 칸별 해석(UTC, `%%2313`), 메시지 템플릿, 언어 번역과 SIEM에 EventData가 필요한 이유, 확인 문제 |

!!! info "이어서 추가될 내용"
    이벤트 구조 자세히 — System 부분 vs EventData/UserData 칸별 해석, 템플릿과 설명 문구, 하나로 묶어 보기, SOC가 모아야 할 채널 — 그리고 섹션 정리.

## 꼭 기억할 것 { #must-know }

1. 결과 0건은 그 이벤트가 설정되고, 기록되고, 남아 있고, 모였다는 걸 확인하기 전까지는 아무 의미가 없다.
2. 길: 공급자 → Windows Event Log 서비스 → 채널 → `C:\Windows\System32\winevt\Logs`의 `.evtx` → 읽는 도구나 에이전트. 모든 단계가 공격당할 수 있으니, 로그는 빨리 호스트 밖으로 보내고 1102, 104, 4719에 경보를 건다.
3. 어떤 Security 이벤트가 생길지는 감사 정책이 정한다. 적용된 정책은 `auditpol`로 확인하고, 고급 정책만 쓰고, 기본 정책이 못 보는 곳은 Sysmon으로 채운다.
4. 이벤트 ID는 공급자와 함께여야 의미가 있다. 탐지는 공급자(또는 채널) + ID로 짠다.
5. 일반 보기는 XML 값을 채운 문장 틀이다 — 언어마다 바뀌고 파싱하기 어렵다. SIEM에는 구조화된 EventData 필드를 보낸다.

## 관련 레퍼런스 { #related }

- [엔드포인트 방어](../endpoint-defense/index.md) — 방어선으로서의 감사 정책과 중앙 수집
- [Windows 이벤트 로그 (EVTX)](../../../windows/event-logs.md)
- [Windows 이벤트 ID](../../../basics/windows-event-ids.md)
