---
title: "2부 — 핵심 프로토콜과 로그 집계·분석"
tags:
  - training
  - network-forensics
---

# 2부 — 핵심 프로토콜과 로그 집계·분석 { #part-2 }

!!! abstract "2부에서 다루는 것"
    거의 모든 사건에 등장하는 두 프로토콜, HTTP와 DNS를 조사자의 눈으로 읽는 법부터 시작합니다. 요청과 응답의 각 부분, 웹 서버 로그, DNS의 구조와 악용 방식(빠른 플럭스, 도메인 생성 알고리즘, 암호화 DNS)을 다룬 뒤, Zeek로 패킷을 로그로 바꾸고 jq로 다룹니다. 마지막으로 syslog와 Windows 이벤트 로그를 한곳에 모으는 로그 집계와 Elastic Stack 기반의 분석 환경을 익힙니다.

## 회차 { #lessons }

강의는 한 회차씩 차례대로 추가합니다. 아래 목록에서 아직 링크가 없는 회차는 준비 중입니다. 내용 분량에 따라 번호가 조금 바뀔 수 있어요.

| 회차 | 주제 | 상태 |
| --- | --- | --- |
| [2.1강](http-requests.md) | HTTP 요청 읽기: 메서드, URI, 요청 헤더 | 게시 |
| [2.2강](http-responses.md) | HTTP 응답 읽기: 상태 코드, 응답 헤더, 조사에서 쓰는 법 | 게시 |
| [2.3강](tracking-cookies-http2-http3.md) | 추적 쿠키로 과거 보기, 그리고 HTTP/2·HTTP/3 | 게시 |
| [2.4강](lab-http-profiling.md) | 실습 가이드: HTTP 프로파일링 | 게시 |
| [2.5강](web-server-logs.md) | 웹 서버 로그: 형식, 읽기, 공격의 흔적 | 게시 |
| [2.6강](dns-structure.md) | DNS의 구조: 레코드, 메시지, 압축, 위계 | 게시 |
| [2.7강](dns-investigation.md) | DNS 조사: 로그, 빠른 플럭스, DGA, 암호화 DNS, 퓨니코드 | 게시 |
| [2.8강](zeek.md) | Zeek로 패킷을 로그로: 로그 구조, jq, Community ID | 게시 |
| [2.9강](lab-dns-profiling.md) | 실습 가이드: DNS 프로파일링, 이상 징후, 범위 산정 | 게시 |
| [2.10강](syslog.md) | syslog: 데몬과 프로토콜, 시설과 심각도, 설정 읽기 | 게시 |
| [2.11강](windows-event-logs.md) | Windows 이벤트 로그와 이벤트 전달 | 게시 |
| [2.12강](log-aggregation.md) | 로그 집계: 왜 모으고, 어떻게 보내나 | 게시 |
| [2.13강](elastic-stack-sof-elk.md) | Elastic Stack과 SOF-ELK | 게시 |
| 2.14강 | 실습 가이드: 로그 집계와 분석 | 준비 중 |

## 시리즈 처음으로 { #back }

[Network Forensics 첫 페이지](../index.md)
