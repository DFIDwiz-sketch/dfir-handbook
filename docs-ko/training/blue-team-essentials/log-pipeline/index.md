---
title: 로그 파이프라인·SIEM
tags:
  - training
  - blue-team
  - logging
  - siem
---

# 로그 파이프라인·SIEM { #log-pipeline }

!!! abstract "한 줄 요약"
    호스트가 이벤트를 쓴 순간부터 우리가 그걸 검색하는 순간까지, 이벤트는 수집되고, 옮겨지고, 파싱되고, 때로는 형식이 바뀌고, 보강되고, 정규화되고, 인덱싱되어 저장됩니다. 그 단계 하나하나가 칸을 덧붙이고, 값을 바꾸고, 늦추고, 버릴 수 있습니다. 이 섹션은 그 여정을 따라가서 원본 데이터와 파이프라인이 덧붙인 것을, 그리고 "아무 일도 없었다"와 "파이프라인이 잃어버렸다"를 구별하게 해 줍니다. 수집 방법, 로그 형식과 구조가 중요한 이유, 보강, 필드 정규화와 공통 정보 모델, 저장과 로그 수명 주기를 다룹니다.

## 읽는 순서 { #reading-order }

| # | 페이지 | 핵심 |
| --- | --- | --- |
| 1 | [로그 수집 — 로그 파이프라인, 에이전트 vs 에이전트리스, Windows·Linux 수집 방법](collection-methods.md) | 분석가가 파이프라인을 알아야 하는 이유(설명 안 되는 칸, 지연, 빈 결과, `host=WEC01`), 소스 → 수집 → 집계기 → 파싱·보강 → 인덱싱·저장 → 검색·경보 블록과 각각이 덧붙이고·바꾸고·늦추고·버릴 수 있는 것, 예시 타임라인으로 보는 두 시계(`@timestamp` vs `event.created`/`event.ingested`, `_time` vs `_indextime`), 에이전트 vs 에이전트리스 밀어 보내기·끌어오기, Windows 선택지 표, Splunk UF `inputs.conf`/`outputs.conf`(`renderXml`, blacklist, `useACK`, TLS)와 NXLog XPath → JSON → TLS 한 줄씩, JSON vs syslog 문장으로 본 4624와 "Account Name:"이 정규식을 깨는 이유, `wecutil qc`·구독 관리자 GPO·XPath 구독·`wecutil gr` 하트비트로 보는 WEF/WEC, Network Service와 Security 채널, 전달된 이벤트의 `Computer`/`Channel`/`EventRecordID`와 `host=WEC01` 함정, 에이전트리스 `Get-WinEvent -ComputerName`, `wevtutil gl`(`channelAccess`, `maxSize`, 덮어쓰기 계산), 읽기 계정, 파이프라인 조작 1102/104/1100/7036/7040/4719(T1070.001, T1562.001/.002/.006), Linux 선택지, rsyslog TLS + 디스크 큐 + `imjournal` 한 줄씩, `logger`/`ss` 시험, 저널만 있는 배포판, cron + `journalctl --cursor-file` 밀어 보내기, SOC 점검표, 확인 문제 |
| 2 | [로그 형식과 구조 — 비정형 로그, CSV, 키-값, JSON, CEF/LEEF, 그리고 SIEM은 구글이 아니다](formats-structure.md) | 파싱이 탐지를 결정하는 이유(칸 없음 = 경보 없음 = 소리 없는 미탐), 비정형 syslog 줄(`dhclient`, `CRON`/`pam_unix`, `sudo`)을 부분별로 읽기, `sudo`용 이름 붙은 정규식과 깨지는 네 가지 경우(있다 없다 하는 부분, 공백, 다른 프로그램, 바뀐 문구), 파싱 실패 표시와 저널 칸, 같은 기록으로 본 CSV vs 키-값 vs JSON vs XML(38/78/96바이트)과 비교표, 칸이 끼어든 CSV 밀림, 따옴표 함정, 스스로를 설명하는 Zeek `#fields`/`#types`, 키-값 구분 문자 문제와 로그 인젝션(CWE-117), 중첩 JSON 프로세스 이벤트 한 줄씩, CEF 헤더와 확장 칸 사전(`rt`, `src`, `suser`, `act`, `cs1Label`)과 이스케이프, 사용자 지정 구분 문자가 있는 LEEF 1.0 vs 2.0, PRI vs 이벤트 심각도, Squid 한 줄로 칸별로 보는 인덱싱 vs 전문 검색, 쓸 때 스키마 vs 읽을 때 스키마, SPL 기초와 함께 `sara` → `index=proxy sara` → `index=proxy user=sara`로 좁히기, KQL/Elastic 대응, 앞 와일드카드와 인덱싱된 칸, SOC 점검표, 확인 문제 |

!!! info "이어서 추가될 내용"
    보강과 상관 분석, 필드 정규화와 공통 정보 모델(ECS, OCSF, ASIM, CIM), 분류, 저장, 로그 수명 주기, 그리고 SIEM 엔지니어에게 물어볼 질문. 이걸로 이 섹션이 끝나고, 그다음은 파일 분석입니다.

## 꼭 기억할 것 { #must-know }

1. SIEM 속 이벤트는 호스트가 쓴 그대로가 아니다. 어느 칸이 원본이고 어느 칸을 파이프라인이 붙였는지 안다.
2. 모든 파이프라인이 하는 일은 같다. 수집, 집계, 파싱·보강, 인덱싱·저장, 검색·경보. 제품마다 다른 건 어느 상자가 어떤 일을 하느냐뿐이다.
3. 경보는 예약된 검색이다. 지연 = 수집 지연 + 인덱싱 지연 + 주기. 주기 + 지연보다 더 길게 뒤를 돌아본다.
4. 시각을 근거로 결론 내리기 전에 이벤트 시각과 받은 시각을 비교한다.
5. 에이전트는 거르고, 쌓아 두고, 압축하고, 암호화한다. 에이전트리스 끌어오기는 포트를 열고, 어디서나 읽는 계정이 필요하며, 로그 덮어쓰기로 이벤트를 잃을 수 있다.
6. 수집 필터 하나하나가 탐지에 관한 결정이다. 가치 낮은 데이터는 버리지 말고 싼 저장소로 보낸다.
7. Windows 이벤트는 XML이나 JSON으로 유지한다. syslog 문장은 구조를 잃는다.
8. WEF: Network Service에 Security 읽기 권한이 필요하고, 진짜 호스트는 수집 서버 이름이 아니라 `Computer` 칸에 있다.
9. 조용한 호스트가 깨끗한 호스트는 아니다. 하트비트 끊김과 1102, 104, 1100, 4719, 에이전트 서비스 변경에 경보를 건다.

## 관련 레퍼런스 { #related }

- [Windows 로그](../windows-logging/index.md) — 이벤트가 만들어지고 구성되는 방식
- [Linux 로그](../linux-logging/index.md) — syslog, 로그 파일, 저널
- [꼭 알아야 할 이벤트](../important-events/index.md) — 가장 수집할 가치가 있는 것
- [로그 집계](../../network-forensics/part-2/log-aggregation.md)
