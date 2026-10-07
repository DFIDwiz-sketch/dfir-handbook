---
title: dns.log
tags:
  - artifact
  - network
  - zeek
  - dns
---

# Zeek `dns.log` { #zeek-dnslog }

<div class="dfir-meta" markdown>
**분류:** 네트워크 · **출처:** Zeek · **최종 수정:** 2026-09-16
</div>

!!! abstract "한 줄 요약"
    DNS 쿼리마다 한 줄(보였다면 응답 포함)입니다 — 호스트가 *어디에 닿으려 했는지* 알아내고, DGA와 터널링 도메인을 잡고, `conn.log`의 IP를 악성코드가 요청한 이름으로 되짚어 가는 가장 저렴한 방법입니다.

## 필드 { #fields }

| 필드 | 의미 | 분석 메모 |
|---|---|---|
| `ts`, `uid`, `id.*` | `conn.log`와 같음 | 여러 쿼리가 UDP `uid` 하나를 공유할 수 있음 |
| `proto` | `udp` / `tcp` | 클라이언트의 **TCP DNS**는 드묾 — 큰 응답, 존 전송, 터널링 |
| `trans_id` | 16비트 트랜잭션 ID | 쿼리 ↔ 응답 연결 |
| `rtt` | 왕복 시간 | |
| `query` | 요청한 이름 | 세기 전에 소문자로 바꿀 것 |
| `qclass` / `qclass_name` | 보통 `1` / `C_INTERNET` | |
| `qtype` / `qtype_name` | 레코드 타입: `A`(1), `AAAA`(28), `CNAME`(5), `MX`(15), **`TXT`(16)**, `NS`(2), `PTR`(12), `SRV`(33), **`ANY`(255)**, `NULL`(10) | 한 호스트에서 `TXT`, `NULL`, `CNAME`이 많음 → 터널링; `ANY` → 증폭 / 정찰 |
| `rcode` / `rcode_name` | 응답 코드: `NOERROR`(0), **`NXDOMAIN`**(3), `SERVFAIL`(2), `REFUSED`(5) | NXDOMAIN이 몰려 나오면 = DGA, 타이포스쿼팅, 싱크홀된 C2 |
| `AA`, `TC`, `RD`, `RA` | 권한 있는 응답 / **잘림** / 재귀 요청 / 재귀 가능 | `TC=T` → 클라이언트가 TCP로 재시도 |
| `Z` | 예약 비트 | 0이 아니면 = 이상한 클라이언트/도구 |
| `answers` | 응답 벡터 (IP, CNAME 대상, TXT 문자열) | TSV에서는 쉼표로 구분 |
| `TTLs` | `answers`에 대응하는 TTL 벡터 | 수상한 도메인의 **아주 낮은 TTL**(≤ 60초) = fast-flux; 극단적인 값 = 이상 |
| `rejected` | 서버가 쿼리를 거부함 | |
| `saw_query` / `saw_reply` (선택) | Zeek이 각 방향을 봤는지 | |

## 빠른 쿼리 { #quick-queries }

=== "zeek-cut / 셸"

    ```bash
    # Most queried domains (strip to registered domain roughly: last two labels)
    zeek-cut query < dns.log | tr 'A-Z' 'a-z' | awk -F. 'NF>=2{print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head -30

    # Rare domains — queried by exactly one host, once or twice (long tail is where C2 hides)
    zeek-cut id.orig_h query < dns.log | sort -u | awk '{print $2}' | sort | uniq -c | awk '$1==1' | head -50

    # NXDOMAIN storm per host (DGA)
    zeek-cut id.orig_h rcode_name < dns.log | awk '$2=="NXDOMAIN"' | sort | uniq -c | sort -rn | head

    # Long / high-entropy subdomains (tunnelling: dnscat2, iodine, Cobalt Strike DNS beacon)
    zeek-cut -d ts id.orig_h query qtype_name < dns.log | awk 'length($3)>60'
    zeek-cut query < dns.log | awk -F. '{ if (length($1)>30) print }' | sort | uniq -c | sort -rn | head

    # TXT / NULL / unusual types by host
    zeek-cut id.orig_h qtype_name < dns.log | awk '$2=="TXT"||$2=="NULL"||$2=="ANY"' | sort | uniq -c | sort -rn

    # Which name resolved to a given IP? (pivot from conn.log)
    grep -F '203.0.113.7' dns.log | zeek-cut -d ts id.orig_h query answers

    # Hosts using a resolver other than the corporate one (10.0.0.53)
    zeek-cut id.orig_h id.resp_h < dns.log | awk '$2!="10.0.0.53"' | sort | uniq -c | sort -rn

    # Volume of DNS *bytes* per host — tunnels move data, not just names
    zeek-cut id.orig_h orig_bytes < conn.log | awk '{s[$1]+=$2} END{for(h in s) print s[h], h}' | sort -rn | head
    # (run that on conn.log filtered to id.resp_p==53)
    ```

=== "Splunk"

    ```spl
    index=zeek sourcetype=zeek:dns
    | eval qlen=len(query), labels=mvcount(split(query,"."))
    | eval sub=mvindex(split(query,"."),0), sublen=len(sub)
    | where sublen > 30 OR qtype_name IN ("TXT","NULL")
    | stats count dc(query) as uniq_names sum(qlen) as total_chars by id.orig_h, id.resp_h
    | sort - uniq_names
    ```

    `len()`은 문자열 길이, `split(query,".")`는 이름을 레이블의 다중값 목록으로 쪼개고, `mvcount()`는 그 개수를 세며, `mvindex(...,0)`은 첫 번째 레이블(가장 왼쪽 서브도메인)을 고릅니다. 같은 리졸버로 30자 이상의 고유한 첫 레이블을 수천 개 보내는 호스트는 DNS로 데이터를 밖으로 터널링하고 있는 것입니다.

    ```spl
    index=zeek sourcetype=zeek:dns rcode_name=NXDOMAIN
    | bin _time span=10m
    | stats count dc(query) as uniq by _time, id.orig_h
    | where uniq > 50
    ```

    `bin _time span=10m`은 각 이벤트 시각을 10분 단위 구간으로 내림해서 `stats`가 호스트별·10분별로 셀 수 있게 합니다. 10분 동안 존재하지 않는 고유 이름이 50개 넘게 나오면 C2를 찾고 있는 도메인 생성 알고리즘(DGA)입니다.

## 분석 팁 { #analysis-tips }

!!! tip "DNS는 범행 직전의 로그입니다"
    악성코드는 C2로 가는 `conn.log` 행이 나타나기 **전에** 이름을 조회합니다. 첫 수상한 `conn.log` 시각 주변으로 `dns.log`를 정렬하세요 — 50 ms 전의 쿼리가 C2 도메인이고, 그 `answers`가 차단할 IP 전체 목록입니다.

- **모든 DNS가 53번 포트에 있지는 않습니다.** DoH(`dns.google`, `cloudflare-dns.com`, `1.1.1.1`로 가는 `https`)와 DoT(853)는 `dns.log`를 우회합니다. 알려진 DoH 제공자를 `ssl.log` SNI에서, `conn.log`에서 `id.resp_p=853`을 찾으세요. 여전히 웹을 쓰는데 `dns.log`에서 갑자기 사라진 호스트는 DoH로 바꾼 것입니다.
- **리졸버 기준선을 잡으세요.** 클라이언트는 회사 리졸버와만 통신해야 합니다. 워크스테이션에서 인터넷으로 직접 53번을 쓰면 정책 위반이거나 리졸버가 하드코딩된 악성코드입니다(`8.8.8.8`은 Cobalt Strike DNS 프로필에 흔함).
- **터널 징후:** 한 도메인으로의 아주 높은 쿼리 빈도, 대부분 `TXT`/`NULL`/`CNAME`/`MX`, base32/base64처럼 보이는 긴 레이블, 아주 작은 TTL, 쓰레기처럼 보이는 `answers`가 달린 `NOERROR` 응답, 그리고 — 결정적으로 — 다른 호스트보다 훨씬 많은 전체 DNS **바이트**.
- **DGA 징후:** `NXDOMAIN` 다수, 길이가 일정한 무작위처럼 보이는 레이블, `.top .xyz .info .ru .cc` TLD가 많음, 그리고 마침내 살아 있는 C2를 찾았을 때 `NOERROR` 하나.
- **Fast-flux / CDN 혼동:** 낮은 TTL만으로는 CDN(Akamai, Cloudflare)에서 정상입니다. 표시하기 전에 도메인 나이 / 희소성과 함께 보세요.
- 한 호스트가 많은 내부 IP에 대해 **PTR 조회** = 정찰 (nmap `-sL`, BloodHound). `_ldap._tcp`, `_kerberos._tcp`에 대한 **SRV** = 정상 도메인 참가; 이상한 호스트의 `_msrcp`, `_vlmcs` 등 = 열거.
- **`answers`는 IOC를 공짜로 줍니다** — 수상한 도메인이 해석된 모든 IP를 뽑아서, 조회한 적 없는 *다른* 호스트가 그 IP로 직접 연결했는지 `conn.log`에서 찾아보세요(하드코딩된 IP 대체 경로).
- **싱크홀 / RPZ:** 리졸버가 나쁜 도메인을 `0.0.0.0`/싱크홀 IP로 바꿔 준다면, `dns.log`에는 감염된 호스트의 요청이, `conn.log`에는 실패한 연결이 보입니다. 둘 다 경보입니다.

## 상관분석 { #correlation }

| 질문 | 다음에 볼 곳 |
|---|---|
| 해석된 곳으로 실제로 연결했나? | `ts` 후 몇 초 안에 `id.resp_h ∈ answers`인 [`conn.log`](conn-log.md) |
| 무엇을 가져왔나? | 그 연결의 `uid` → [`http.log`](http-log.md) / [`ssl.log`](ssl-x509.md) (SNI가 `query`와 일치해야 함) |
| 어떤 프로세스가 물었나? | 호스트의 Sysmon **22** (`QueryName`, `QueryResults`, `Image`); Windows DNS 클라이언트 캐시 (`ipconfig /displaydns`, 메모리) |
| 도메인 인텔리전스 | 패시브 DNS, WHOIS/생성일, VirusTotal, 위협 피드; 도메인 간 `ssl.log` 인증서 재사용 |
| 서버 쪽 관점 | 센서가 못 보는 호스트는 DNS 서버 로그 (Windows DNS 디버그 로그 / 분석 ETW, BIND 쿼리 로그) |

## 참고 자료 { #references }

- [Zeek docs — dns.log](https://docs.zeek.org/en/master/scripts/base/protocols/dns/main.zeek.html)
- [IANA DNS parameters (qtypes, rcodes)](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)
- [SANS — Detecting DNS tunneling (Farnham)](https://www.sans.org/white-papers/34152/)
- [Active Countermeasures — RITA / AC-Hunter DNS analysis](https://www.activecountermeasures.com/free-tools/rita/)
