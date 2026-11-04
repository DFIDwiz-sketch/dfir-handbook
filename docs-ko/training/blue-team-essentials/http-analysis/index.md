---
title: HTTP(S) 분석과 공격
tags:
  - training
  - blue-team
  - http
---

# HTTP(S) 분석과 공격 { #http-analysis }

!!! abstract "한 줄 요약"
    HTTP는 공격의 거의 모든 단계(전달·공격·설치·C2·유출)에 쓰입니다. 이 섹션은 [HTTP 기초](../http/index.md) 위에서, 실제 악성 HTTP(S) 트래픽을 **빠르게 판정하고 깊게 파고드는 방법**을 다룹니다. 평판 조회 같은 자동 방법부터 헤더·내용 분석, 파일 추출, 이상 징후 찾기, 그리고 HTTPS(TLS) 분석까지 이어집니다.

## 읽는 순서 { #reading-order }

| # | 페이지 | 핵심 |
| --- | --- | --- |
| 1 | [HTTP 악용의 단계, 분석 방법, URL 평판](evil-http-and-reputation.md) | 킬 체인 단계별 HTTP 흔적, 자동·수동 분석 고르기, URL 평판 조회와 함정, OPSEC·디팽, 확인 문제 |
| 2 | [스크린샷, 샌드박스, 수동 분석으로 넘어갈 때](screenshots-sandboxes.md) | 스크린샷으로 피싱 확인과 결과 읽기, 도구별 공유 여부, 네트워크형·VM형 샌드박스와 도구 고르기, 샌드박스 회피, 약한 신호를 모으는 수동 분석, 확인 문제 |

!!! info "이어서 추가될 내용"
    User-Agent 분석, 쿠키, Base64, 파일 추출, 잦은 GET/POST, IP 직접 접속, 익스플로잇 킷 판별, HTTPS·TLS 분석.

## 꼭 기억할 것 { #must-know }

1. HTTP는 공격의 거의 모든 단계에 쓰인다. 단계마다 로그 모양이 다르다.
2. 빠른 자동 확인부터, 답이 안 나오면 수동 분석으로.
3. 평판 결과 없음 ≠ 안전. 좋은 도메인 ≠ 안전한 URL.
4. 공개 스캐너 제출은 정보를 흘릴 수 있다. URL은 디팽해서 기록한다.

## 관련 레퍼런스 { #related }

- [HTTP 기초 섹션](../http/index.md)
- [DNS 도메인 신호](../dns/domain-signals.md) — 도메인 나이·평판 판단
- [Beaconing & C2 탐지](../../../network/beaconing-c2.md)
- [Phishing 공격 기법](../../../adversary/phishing-delivery.md)
