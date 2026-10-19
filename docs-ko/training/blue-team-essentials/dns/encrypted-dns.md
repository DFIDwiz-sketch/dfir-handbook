---
title: "암호화 DNS — DoT·DoH·DoQ·DNSSEC와 수집 전략"
tags:
  - training
  - blue-team
  - dns
  - concept
  - doh
  - dnssec
---

# 암호화 DNS — DoT·DoH·DoQ·DNSSEC와 수집 전략

!!! abstract "이 페이지에서 다루는 것"
    DoT·DoH·DNSSEC이 각각 무엇을 지키는지, DoH가 블루팀 시야를 어떻게 가리는지와 네 가지 대응, Wireshark에서 본 DoH, 그리고 암호화가 기본이 된 2026년에 DNS 기록을 어디서 모아야 하는지.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 전체 흐름은 [DNS 개요](index.md)에서, 기록 한 줄을 판별하는 순서는 [판별표](triage-sheet.md)에서 볼 수 있습니다.

## DNS의 미래: DoT·DoH·DNSSEC { #dot-doh-dnssec }

세 기술은 지키는 대상이 다릅니다. DoT·DoH는 **기밀성**(엿보기 방지), DNSSEC은 **진위·무결성**(위조 방지)입니다. 사용자를 지키지만 블루팀 시야를 가립니다.

|  | DoT | DoH | DNSSEC |
| --- | --- | --- | --- |
| 방법 | TLS로 감싼 DNS | HTTPS 안에 넣은 DNS | 답에 전자 서명 |
| 포트 | TCP 853 | TCP 443(HTTP/3면 UDP 443) | 53(일반 DNS 그대로) |
| 지키는 것 | 기밀성 | 기밀성 | 진위·무결성 |
| 블루팀 시야 | 내용 안 보임, 포트로 식별·차단 쉬움 | 일반 웹과 구분 어려움(SNI·목적지 IP만 단서) | 그대로 보임 |
| 비유 | 봉투 | 택배 상자 속 편지 | 인감 도장 |

### 핵심

- DoT: 전용 포트라 "easy to block". Android "비공개 DNS"가 DoT → 회사 와이파이에서 853 트래픽이 흔함, MDM으로 통제
- DoH: 443을 막을 수 없어 "이기는" 표준. **[정정] "DoH는 JSON으로 인코딩된다"는 흔한 설명은 부정확** — 표준 DoH(RFC 8484)는 DNS 이진 형식 `application/dns-message`, JSON(`application/dns-json`)은 Google·Cloudflare 비표준 API
- DoH는 **PC ↔ 재귀 서버 구간만** 암호화. 재귀 서버 → 권한 서버는 대개 평문, DoH 업체는 전부 봄 → 외부 DoH 사용 = 회사는 못 보고 외부 업체는 봄
- DNSSEC 신뢰의 사슬: 루트 키(출발점) → 위층의 **DS**(아래층 도장 보증서) → 도메인의 **DNSKEY**(공개키) → 답의 **RRSIG**(서명). `dig +dnssec`의 플래그 **`ad`** = 검증 통과, 서명 불일치 시 SERVFAIL
- DNSSEC 한계: 대개 재귀 서버까지만 검증(PC는 `ad`를 믿음), **계정 탈취·레코드 바꿔치기는 못 막음**(진짜 열쇠로 서명됨), 서명 안 된 도메인 많음, 공격자 자기 도메인도 "진짜"로 검증(인증 ≠ 선의)

??? question "복습 Q&A"

    - "우리 도메인에 DNSSEC 켜서 직원 질문 엿보기·하이재킹을 막는다"의 오류: ① DNSSEC은 암호화를 안 하므로 엿보기를 못 막고, 우리 도메인의 서명은 **남들이 우리 도메인을 조회할 때의 위조**를 막을 뿐 직원이 다른 사이트를 조회하는 것과는 무관 ② 판매 업체 계정을 뚫으면 DS·NS를 바꾸거나 DNSSEC을 끄므로 하이재킹은 못 막음(MFA·Registry Lock·변경 감시가 답)
    - `→ 9.9.9.9:853` = Quad9 DoT, 포트로 바로 식별·차단 / `→ 104.16.248.249:443 SNI cloudflare-dns.com` = Cloudflare DoH, 웹과 섞여 더 어려움(알려진 업체라 SNI·IP로는 잡힘, 자체 DoH 서버·ECH면 못 잡음)
    - "외부 DoH면 아무도 모른다"는 틀림: DoH 업체는 전부 봄, 재귀→권한 구간은 평문(단 권한 서버는 재귀 서버 IP만 봄), PC 자체(EDR·브라우저 기록)는 봄, 조회 후 그 사이트에 접속할 때의 **SNI·목적지 IP**로 사이트가 드러남(ECH면 SNI도 가려짐)

!!! info "2026년 관점"

    - DoQ(RFC 9250, UDP 853), HTTP/3 기반 DoH(UDP 443) 추가
    - DDR(RFC 9462): PC가 지금 DNS 서버의 암호화 지원을 발견해 같은 서버로 암호화 연결 → 회사 DNS가 DoH를 지원하면 "암호화는 하되 기록은 회사가"(제품별 지원 수준은 확인 필요)
    - ODoH(RFC 9230): DoH 업체도 "누가" 물었는지 모르게
    - Windows 11 운영체제 수준 DoH("곧 온다"던 것이 현실화)
    - [주의] 탐지·프록시 정책에서 JSON 형식만 찾으면 표준 DoH를 놓침. "DNSSEC = DNS 보안 해결책"은 오해

## DoH 대응과 Wireshark에서 본 DoH { #doh-response }

DoH를 쓰면 DNS가 HTTP가 되어 ① 질문이 안 보이고 ② 사실상 허가되지 않은 외부 DNS가 됩니다. 큰 방향은 **외부 DoH는 막고, 내부 DoH를 제공하거나 끄는 것**입니다.

### 네 가지 대응

| 대응 | 무엇을 하나 | 잡는 범위 | 한계 |
| --- | --- | --- | --- |
| ① 복호화(전통적 최선책) | 회사 프록시가 TLS를 풀어 봄(회사 인증서를 PC에 설치) | 알려진·자체 DoH 모두 | 비용·성능, 인증서 고정 프로그램, 개인정보·법적 부담, 관리 PC만 |
| ② 신호 도메인 | 회사 DNS가 `use-application-dns.net`에 NXDOMAIN | Firefox **자동** DoH만 | 수동 설정·Chrome·Edge·OS DoH·악성코드엔 무력 |
| ③ 내부 DoH 서버 | 회사가 DoH 서버 운영 | 회사 서버로 오는 것(암호화 + 회사 기록·차단) | 외부 DoH는 따로 막아야 |
| ④ 클라이언트 기록 | Firefox `MOZ_LOG=nsHostResolver:5` + `MOZ_LOG_FILE`, `about:networking` | 그 PC·그 앱만 | 상시 운영 어려움, 조사용 |

### Wireshark

- 암호화 상태: `Application Data`뿐. 단서는 목적지 IP(`104.16.248.249` = Cloudflare)·SNI. 공격자 자체 DoH 서버면 DNS인지도, 무슨 이름인지도 모름
- 복호화 상태: **TLS → HTTP/2 → DNS**, `POST /dns-query`, `content-type: application/dns-message`, 질문 이름이 보임
- **Transaction ID 0x0000**: DoH 표준(RFC 8484)이 웹 캐시 효율을 위해 0을 권장 → 짝짓기는 **TCP 연결 + HTTP/2 Stream ID**. HTTP/2는 HEADERS와 DATA 프레임을 따로 보냄
- 홈 랩 실습: `SSLKEYLOGFILE` 환경 변수 → Wireshark TLS 설정에 열쇠 파일 지정 → 필터 `dns` 또는 `http2.header.value == "application/dns-message"`. 끝나면 파일 삭제·변수 해제. **업무 PC에 `SSLKEYLOGFILE`이 설정돼 있으면 조사 대상**
- 연습: 1.1.1.1·8.8.8.8·9.9.9.9로 가는 443 찾기. Zeek: `cat ssl.log | zeek-cut id.orig_h id.resp_h server_name`

??? question "복습 Q&A"

    - 신호 도메인으로 막히는 것: Firefox 기본(자동) DoH. 안 막히는 것: Firefox 수동 DoH, Chrome·Edge(신호를 안 봄), Windows 11·macOS·iOS 운영체제 DoH, 악성코드·기타 앱의 자체 DoH, DoT(853)
    - DoH Transaction ID가 0인 이유: HTTP 캐시가 같은 질문을 같은 요청으로 보게 하려고. 짝짓기는 TCP 연결 + HTTP/2 Stream ID
    - EDR에서 `firefox.exe → cloudflare-dns.com:443`과 `Temp\svchelper.exe → dns.google:443` 중 **후자 먼저**: 브라우저가 아닌 프로그램, Temp 폴더, 시스템 파일을 흉내 낸 이름 → 악성코드의 DoH C2 조회 의심(Sysmon 1·22, 부모 프로세스, 이후 연결 확인, 격리 검토). 전자는 정책 위반 점검

!!! info "2026년 관점"

    - 복호화보다 우선순위: ① 정책으로 DoH를 회사 서버로 고정·끄기(Chrome·Edge `DnsOverHttpsMode`/`DnsOverHttpsTemplates`, Firefox `DNSOverHTTPS`, Windows 그룹 정책) ② 내부 DoH·DDR ③ 공개 DoH·853 차단 ④ EDR로 브라우저 아닌 프로그램의 DoH 접속 탐지 ⑤ 선택적 복호화
    - [주의] 신호 도메인은 보조 장치일 뿐 "DoH 차단 완료"가 아님

## DNS Summary — 기록은 어디서 모을 것인가 { #summary }

결론: DNS 기록만 잘 걸러내고 덧붙이면 **도메인 이름만으로도 악을 잡을 수 있다.** 신호 8가지 총정리는 [도메인 신호](domain-signals.md#signals-summary) 페이지에 있습니다.

### 수집 고려사항

- DNS는 중간 서버를 거친다 → 어디서 모으느냐에 따라 "누가 물었나"가 사라짐(포워딩 서버 바깥 센서는 서버 IP만 봄)
- 네트워크 추출(Zeek 등)이 "지금은" 가장 쉬움
- 암호화 DNS가 퍼지면 → DNS 서버·PC 기록으로 옮겨가야 함

!!! info "2026년 관점"

    - [변경됨] 몇 년 전 "미래"라던 것이 현실이 됨: DoH·DoT·DoQ + ECH(SNI도 숨김) → 네트워크에서는 목적지 IP 정도만 남음
    - 수집 우선순위: ① 회사 DNS 서버 기록(Windows DNS Analytical 로그 256/257/258·260/261, BIND/Unbound query log) ② PC 기록(Sysmon 22 = 프로세스별 DNS, EDR) ③ Protective DNS(차단+기록을 같이) ④ 네트워크 추출은 보조
    - [변경됨] 순위 목록: Alexa Top 1M은 2022년 서비스 종료 → Tranco, Cisco Umbrella, Cloudflare Radar 등 사용
    - [주의] 신호 하나로 단정 금지. 여러 신호를 겹치고 맥락(누가·무엇을·어디로·그다음)을 붙여서 판단

??? question "복습 Q&A"

    - **인기 순위 상위 10만 개를 경보에서 빼기**: 장점은 경보 소음이 크게 줄어듦. 위험은 인기 플랫폼(Google Drive, GitHub, `*.workers.dev`, Discord CDN, 동적 DNS 등) 악용·해킹된 인기 도메인·순위 조작을 통째로 놓침. 조정: 기록은 계속 모으고 경보만 줄이기, 완전 제외 대신 점수 낮추기, 사용자 콘텐츠 플랫폼은 목록에서 빼고 하위 이름 단위로 보기, 브라우저가 아닌 프로그램의 조회는 순위와 상관없이 보기
    - **방화벽에는 C2 통신이 있는데 DNS 서버 256 이벤트에는 없다**: ① IP 하드코딩(DNS 안 씀) ② 악성코드 자체 DoH(정책은 브라우저만 막음) ③ 외부 53·853 직접 사용 ④ hosts 파일 ⑤ 다른 이름(CNAME·다른 도메인)으로 조회 ⑥ 기록 안 되는 다른 내부 DNS 서버 ⑦ 조회가 검색 시간 범위 밖(PC 캐시) ⑧ Analytical 로그 유실. 확인: Sysmon 22·3·11, EDR, 방화벽 53/853/DoH 서버, `ipconfig /displaydns`, 다른 DNS 서버 기록, 시간 범위 넓히기
    - **DNS 서버 256 + Sysmon 22 합치기**: 서버 기록 = 어느 PC IP가 무엇을 물었나(회사 전체 범위 확인용). Sysmon 22 = 어느 프로그램이 물었나. 합치면: `C:\ProgramData\Intel\igfxsvc.exe`(정상 위치가 아닌 Intel 흉내)가 처음 보는 `.top` 도메인을 조회 → 악성코드 의심. 다음: 해시·부모 프로세스·지속성 확인, 방화벽에서 응답 IP 연결, **DNS 서버 기록에서 같은 이름을 물은 다른 PC 찾기(범위 파악)**

### 2026년 수집 우선순위 자세히 [보충] { #collection-priority }

**① 회사 DNS 서버 기록** — Windows DNS 서버의 Analytical 로그(`Microsoft-Windows-DNSServer/Analytical`, 기본 꺼짐)

| 이벤트 ID | 뜻 | 언제 생기나 |
| --- | --- | --- |
| 256 | 질문을 받음(QUERY_RECEIVED) | PC가 DNS 서버에 물어볼 때마다 |
| 257 | 정상 응답(RESPONSE_SUCCESS) | 답을 돌려줬을 때 |
| 258 | 실패 응답(RESPONSE_FAILURE) | NXDOMAIN, SERVFAIL 등 |
| 260 | 외부로 재귀 질문(RECURSE_QUERY_OUT) | 캐시에 없어 밖에 물어볼 때 |
| 261 | 외부에서 재귀 답(RECURSE_RESPONSE_IN) | 밖에서 답이 왔을 때 |

```
Event ID: 256
QUERY_RECEIVED: TCP=0; InterfaceIP=10.20.0.10; Source=10.20.4.57; RD=1; QNAME=x7qpz9wm.top.; QTYPE=1; XID=41377; Port=52114; Flags=256; PacketData=...
```

`TCP=0` UDP로 옴 · `InterfaceIP` 질문을 받은 DNS 서버 IP · `Source` **질문한 PC의 IP** · `RD=1` 재귀 요청 · `QNAME` 물어본 이름(끝의 점 = 루트) · `QTYPE=1` A 레코드 · `XID` Transaction ID · `Port` PC 쪽 출발 포트. 회사 DNS를 거친 질문(터널링 포함)은 여기 다 남지만, 회사 DNS를 아예 안 거친 질문은 없습니다.

**② PC 기록** — Sysmon Event ID 22(DNSEvent): 어느 프로그램이 물었는지

```
Event ID: 22
UtcTime: 2026-10-19 02:14:07.311
ProcessId: 7412
QueryName: x7qpz9wm.top
QueryStatus: 0
QueryResults: ::ffff:185.199.xx.xx;
Image: C:\Users\jsmith\AppData\Local\Temp\svchelper.exe
```

`QueryStatus: 0` 성공(아니면 Windows 오류 코드, 예: 9003 = 이름 없음) · `QueryResults` 받은 주소(`::ffff:`는 IPv4를 IPv6 형식으로) · `Image` **물어본 프로그램 경로**. 한계: Windows DNS 클라이언트를 거치는 조회만 잡으므로 프로그램 자체 DoH는 안 남을 수 있음 → Sysmon 3(네트워크 연결)·EDR로 보완.

**③ Protective DNS** — 위협 정보를 가진 DNS로 차단 + 차단 기록. 미국 CISA·NSA 권고, 호주는 ASD가 정부 기관 대상 서비스를 운영하는 것으로 알려져 있음.

**④ 네트워크 추출(Zeek `dns.log`)** — 회사 DNS를 거치는 평문 DNS와 외부 53번 시도를 잡는 보조 수단. 자세한 필드는 [Zeek dns.log](../../../network/zeek/dns-log.md) 참고.
