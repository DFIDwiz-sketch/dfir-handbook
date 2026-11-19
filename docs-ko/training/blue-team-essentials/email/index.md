---
title: SMTP·이메일 분석
tags:
  - training
  - blue-team
  - email
---

# SMTP·이메일 분석 { #email }

!!! abstract "한 줄 요약"
    이메일은 공격자가 회사 안으로 들어오는 가장 흔한 첫 관문입니다. 이 섹션은 메일이 어떤 서버들을 거쳐 전달되는지, 그 흔적이 헤더에 어떻게 남는지, 헤더를 읽어 사칭 메일을 가려내는 법(SPF·DKIM·DMARC)을 다룹니다.

## 읽는 순서 { #reading-order }

| # | 페이지 | 핵심 |
| --- | --- | --- |
| 1 | [이메일 전달 구조와 SMTP — MUA·MTA·MDA, 포트, SMTP 대화 읽기](delivery-smtp.md) | 제출·중계·받기 세 단계, MUA·MSA·MTA·MDA, 단계별 포트, MX 레코드, 속일 수 없는 경계 MTA IP, SMTP 대화 한 줄씩, 봉투 주소와 헤더 주소, 응답 코드, Zeek smtp.log, 네트워크 신호, 확인 문제 |
| 2 | [이메일 헤더 읽기 — 트레이스 헤더, 메시지 헤더, 본문, Received 줄 해석](email-headers.md) | 원문의 세 부분과 누가 쓰나, MIME·첨부·Base64, 헤더 보는 법과 안전한 수집(첨부로 전달), Received를 아래에서 위로 읽기, 신뢰의 경계(우리 경계 MTA가 쓴 줄), 위조 Received 줄, 한 줄 칸별 해석, Python으로 순서 뽑기, 확인 문제 |
| 3 | [이메일 위조와 SPF — SMTP가 아무나 믿는 이유, 위조 메일 주입, 세 가지 방어, SPF 동작 원리](spoofing-spf.md) | SMTP가 보낸 사람을 확인하지 않는 이유, 위조 SMTP 대화 한 줄씩, MX에 바로 연결해 SMTP AUTH 건너뛰기, SPF·DKIM·DMARC 비교, 연결 IP와 TCP 핸드셰이크, SPF는 From:이 아니라 MAIL FROM/HELO를 확인, dig로 SPF 레코드 읽기, 기호, 판정 따라가기, 조회 10회·빈 조회 제한, 확인 문제 |

!!! info "이어서 추가될 내용"
    SPF 결과와 트레이스 헤더에서 읽는 법, DKIM, 이어서 DMARC와 이메일 분석 정리.

## 꼭 기억할 것 { #must-know }

1. 서버끼리는 SMTP 25번으로 넘기고, 서버를 지날 때마다 Received 헤더가 쌓인다.
2. 우리 경계 MTA가 기록한 연결 IP는 속일 수 없다. 출처 판단의 기준점이다.
3. 봉투 주소와 헤더 주소는 다를 수 있다. 화면의 `From:`은 아무렇게나 적을 수 있다.
4. 서버 간 메일은 대부분 암호화되고 클라우드로 옮겨 갔다. 분석은 메일 플랫폼 로그가 중심이다.

## 관련 레퍼런스 { #related }

- [DNS 레코드(MX)](../dns/understanding-dns.md#records)
- [Phishing 공격 기법](../../../adversary/phishing-delivery.md)
- [Zeek files.log](../../../network/zeek/files-log.md) — 메일 첨부 파일 추출
