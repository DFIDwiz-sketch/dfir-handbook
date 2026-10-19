---
title: DNS
tags:
  - training
  - sec450
  - blue-team
  - dns
---

# DNS { #dns }

<div class="dfir-meta" markdown>
**교재:** SANS SEC450 (2022) Book 2 · **모듈:** Understanding DNS (p.31~50) → DNS Analysis and Attacks (p.51~85)
</div>

!!! abstract "한 줄 요약"
    DNS는 거의 모든 공격이 한 번은 지나가는 곳입니다. 도메인 이름 하나만 잘 걸러내고 덧붙여도 악을 꽤 많이 잡을 수 있습니다. 다만 2026년에는 암호화 DNS(DoH·DoT·DoQ)와 ECH 때문에 네트워크에서 보이는 것이 줄어, **회사 DNS 서버 기록 + PC 기록(Sysmon 22·EDR)**이 중심이 됐습니다.

## 읽는 순서 { #reading-order }

| # | 페이지 | 교재 | 핵심 |
| --- | --- | --- | --- |
| 1 | [Understanding DNS — 기본 구조와 레코드](understanding-dns.md) | p.31~50 | 서버 4종, 재귀 조회, TTL, A·AAAA·PTR·TXT·CNAME·MX·SRV·NS·HTTPS, 서브도메인 탈취, 도메인 하이재킹, 패킷 읽기 |
| 2 | [DNS 기록 수집과 안전한 조사](collection-and-investigation.md) | p.51~56 | 센서 위치, 방화벽 피벗, OPSEC 조사 순서, 탐지 4단계(쪼개기·덧붙이기·판단·활용) |
| 3 | [도메인 신호](domain-signals.md) | p.57~62, 85 | TLD, 평판, 나이, 무작위성(DGA), ASN, 위치, 순위 |
| 4 | [DNS 악용 공격](dns-abuse.md) | p.63~73 | 비인가 DNS와 흔적 6곳, 공유 호스팅, 레코드 변조, DNS 터널링 |
| 5 | [블록체인 DNS와 IDN](blockchain-dns-and-idn.md) | p.74~79 | EmerDNS·ENS·게이트웨이·EtherHiding, 퓨니코드, 호모글리프, 앱 속 IDN |
| 6 | [암호화 DNS](encrypted-dns.md) | p.80~85 | DoT·DoH·DoQ·DNSSEC, DoH 대응, Wireshark DoH, 2026년 수집 전략 |
| 7 | [수상한 DNS 기록 판별표](triage-sheet.md) | 종합 | 판별 원칙·칸별 신호·흐름·오탐, 교재 정정표, 헷갈리는 포인트 |

## 꼭 기억할 10가지 { #must-know }

1. DNS는 주소만 알려준다. 실제 접속은 따로 일어나므로 DNS 기록과 방화벽 기록을 함께 본다.
2. 포워딩 서버를 거치면 질문한 PC의 IP가 사라진다. 센서 위치가 가시성을 결정한다.
3. PTR은 IP 주인이 아무 이름이나 넣을 수 있다. 증거가 아니라 힌트다.
4. 도메인과 IP는 다대다이고 언제든 바뀐다. 공유 IP(CDN)는 막지 말고 도메인을 막는다.
5. 도메인은 **오른쪽부터, 등록 도메인 단위로** 주인을 판단한다.
6. 나쁜 평판은 증거지만, 좋은 평판은 증거가 아니다.
7. 조사 순서는 우리 기록 → Passive DNS → (비귀속 환경에서) 새 조회. 회사 PC에서 의심 도메인을 `nslookup` 하지 않는다.
8. 외부 53번 차단은 회사 DNS를 정상적으로 거치는 터널링을 못 막는다. 방화벽은 "길"을, DNS 서버는 "목적지"를 막는다.
9. `xn--`는 반드시 풀어서 본다. 문자 체계 섞임 + 브랜드 비교.
10. 신호 하나로 단정하지 않는다. **누가·무엇을·어디로·그다음**을 붙여서 판단한다.

## 관련 레퍼런스 { #related }

- [Zeek dns.log](../../../network/zeek/dns-log.md) — 필드별 설명
- [Beaconing & C2 탐지](../../../network/beaconing-c2.md) — 규칙적인 간격의 조회·연결
- [Windows 이벤트 로그](../../../windows/event-logs.md) — Sysmon·Security 이벤트
