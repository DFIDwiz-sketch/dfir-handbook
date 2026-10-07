---
title: 침해된 워크스테이션
tags:
  - playbook
  - triage
---

# 침해된 워크스테이션 — 초기 트리아지 { #compromised-workstation-initial-triage }

<div class="dfir-meta" markdown>
**시나리오:** 엔드포인트 하나에서 EDR/AV 경보, 수상한 프로세스, 또는 사용자 신고 · **최종 수정:** 2026-09-17
</div>

!!! abstract "언제 쓰나"
    경보가 울렸거나, 사용자가 이상한 점(팝업, 느려짐, 클릭한 이상한 이메일)을 신고했거나, 호스트 하나에서 수상한 프로세스를 발견했을 때. 이것은 **초동 대응자**용 플레이북입니다: 진짜 사고인지 빨리 판단하고, 범위를 파악하고, 증거가 사라지기 전에 보존하세요 — 아직 지켜보고 있을지 모르는 공격자가 눈치채지 않게.

## 1. 트리아지 (첫 15분) { #1-triage-first-15-minutes }

- **경보가 진짜인지 확인하세요** — 실제 탐지 내용(프로세스, 명령줄, 파일 해시)을 읽으세요. 많은 EDR 경보는 무해한 관리 작업입니다. VirusTotal에서 해시를 확인하고 명령줄을 읽으세요.
- 호스트, 사용자, 시간 창을 **파악하세요**. 사용자 계정에 권한이 있나? 호스트가 서버인가, 점프 박스인가, 일반 워크스테이션인가?
- **결정: 지금 봉쇄할까, 지켜볼까?** 분명히 악성이고 퍼지고 있다면 격리하세요. 잠잠한 아티팩트 하나이고 범위부터 이해하고 싶다면, 전원을 끄지 말고 **EDR 격리**(네트워크는 막되 실행은 유지)하세요 — RAM을 유지하고 계속 수집할 수 있습니다.
- **공격자에게 알리지 마세요**: 살아 있는 행위자가 있을 수 있다면, 범위를 파악하기 전까지 눈에 띄는 조치(파일 삭제, 비밀번호 재설정)는 피하세요.

## 2. 수집 { #2-collect }

| 우선순위 | 출처 | 도구 |
|---|---|---|
| 1 | **RAM** (살아 있는 행위자 / 주입된 코드가 의심되면) | [WinPmem / FTK](../tools/imaging-collection.md) |
| 2 | 트리아지 아티팩트 세트 | [KAPE `!SANS_Triage`](../tools/kape.md) 또는 [Velociraptor](../tools/velociraptor.md) |
| 3 | EDR 프로세스 트리 + 타임라인 | EDR 콘솔에서 내보내기 |

Targets는 호스트에서 USB/네트워크 공유로 돌리고, 파싱은 다른 곳에서 하세요 ([수집은 대상 호스트에서, 파싱은 다른 곳에서](../tools/kape.md)).

## 3. 분석 — 트리아지 질문 순서 { #3-analyse-the-triage-question-order }

[Windows 아티팩트 지도](../windows/index.md)를 이 순서로 따라가세요:

1. **무엇이 실행됐고, 악성이었나?** [Prefetch](../windows/prefetch.md) (실행 + 접근한 파일), [Amcache](../windows/amcache.md) (SHA-1 → 인텔리전스), Sysmon 1 / [4688](../windows/event-logs.md) (명령줄, 부모 프로세스). 수상한 부모→자식을 찾으세요 ([피싱](../adversary/phishing-delivery.md), [PowerShell 크래들](../adversary/powershell-cradles.md)).
2. **어떻게 시스템에 들어왔나?** [`Zone.Identifier`](../windows/mft-usn.md) 다운로드 URL, [브라우저 기록], 이메일 ([피싱 전달](../adversary/phishing-delivery.md)), USB ([레지스트리 USB 키](../windows/registry-keys.md#usb-removable-devices-system)).
3. **누가 실행했나 / 누가 로그온해 있나?** [로그온 이벤트 4624](../windows/event-logs.md), [UserAssist/BAM](../windows/registry-keys.md#program-execution-per-user-unless-noted).
4. **지속성을 남겼나?** [Autoruns / ASEP](../adversary/persistence.md) — 서비스, 작업, Run 키.
5. **밖으로 통신했나?** [비코닝/C2](../network/beaconing-c2.md), Sysmon 3, [SRUM](../windows/srum.md) 앱별 바이트.
6. **자격증명을 훔치거나 이동했나?** [LSASS 접근](../adversary/lsass-dumping.md), 이 호스트에서의 [횡적 이동](../adversary/psexec-smb.md).

순서를 보려면 [호스트 타임라인](../splunk/security-searches.md#build-a-host-timeline-everything-about-one-machine)을 만드세요.

## 4. 봉쇄 / 제거 { #4-contain-eradicate }

- 호스트를 격리하세요 (EDR 네트워크 봉쇄).
- 계정이 다른 곳 인증에 쓰였거나 자격증명이 덤프됐을 수 있다면 **재설정**하고 어디로 갔는지 확인하세요 ([4648/4624 헌팅](../splunk/security-searches.md)).
- 지속성과 페이로드를 제거하고, 전사 헌팅을 위해 해시를 기록하세요.
- **범위 넓히기**: 같은 해시, C2, 부모/자식 패턴, 지속성 이름으로 전사를 헌팅하세요 — 침해된 워크스테이션이 혼자인 경우는 드뭅니다.

## 5. 복구와 교훈 { #5-recover-lessons }

- 차단된 파일 하나 이상의 침해였다면 정리하지 말고 재설치하세요 — 모든 것을 찾았다고 확신할 수 없습니다.
- 새 자격증명으로 사용자를 복귀시키세요.
- IOC(해시, 도메인, IP, JA3)를 탐지에 넣고, 그 기법에 대한 [탐지 규칙](../splunk/hunting-patterns.md#making-hunts-repeatable)을 작성하세요.
- 횡적 이동이나 자격증명 탈취로 번지면 [횡적 이동 / 도메인 플레이북](lateral-domain.md)으로 넘어가세요.

## 유용한 쿼리 { #useful-queries }

```spl
index=botsv3 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 host=<HOST>
| eval parent=lower(replace(ParentImage,".*\\\\","")), child=lower(replace(Image,".*\\\\",""))
| table _time, parent, child, User, CommandLine
| sort 0 _time
```

호스트 하나의 전체 프로세스 트리, 오래된 것부터 — 위에서 아래로 읽으며 무슨 일이 있었는지 재구성하세요. `replace(...,".*\\\\","")`가 경로를 떼고 파일명만 남겨서 부모→자식 체인을 따라가기 쉽게 합니다.

```spl
index=botsv3 host=<HOST> (sourcetype=WinEventLog EventCode IN (4624,4625,4648,4672,4688,7045,4698))
     OR (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID IN (1,3,11,22))
| eval what=coalesce(CommandLine, Process_Command_Line, TargetFilename, DestinationIp, Service_File_Name, Message)
| eval code=coalesce(EventCode, EventID)
| table _time, sourcetype, code, User, Account_Name, what
| sort 0 _time
```

Security와 Sysmon을 합친 단일 호스트 타임라인 — `coalesce`가 이벤트마다 있는 설명 필드를 골라서 읽기 쉬운 "무슨 일이 있었나" 열 하나를 만듭니다.

## 참고 자료 { #references }

- [Windows 포렌식 — 아티팩트 지도](../windows/index.md) · [보안 검색](../splunk/security-searches.md)
- [공격 기법](../adversary/index.md) · [KAPE](../tools/kape.md) · [Velociraptor](../tools/velociraptor.md)
