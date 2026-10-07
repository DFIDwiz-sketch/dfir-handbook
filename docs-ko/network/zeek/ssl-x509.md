---
title: ssl.log와 x509.log
tags:
  - artifact
  - network
  - zeek
  - tls
---

# Zeek `ssl.log`와 `x509.log` { #zeek-ssllog-x509log }

<div class="dfir-meta" markdown>
**분류:** 네트워크 · **출처:** Zeek · **최종 수정:** 2026-09-16
</div>

!!! abstract "한 줄 요약"
    암호화된 트래픽은 읽을 수 없지만 **핸드셰이크는 평문**입니다. `ssl.log`는 클라이언트가 요청한 서버 이름(SNI), TLS 버전과 암호 스위트, *클라이언트 소프트웨어*의 JA3/JA4 지문, 그리고 `x509.log`의 인증서 체인을 가리키는 포인터를 줍니다 — 자체 서명되거나 기본값인 인증서로 C2를 식별하고, 지문으로 도구를 찾고, 실제 웹 브라우징과 스크립트 트래픽을 구분하기에 충분합니다.

## `ssl.log` 필드 { #ssllog-fields }

| 필드 | 의미 | 분석 메모 |
|---|---|---|
| `ts`, `uid`, `id.*` | `conn.log`와 같음 | |
| `version` | `TLSv10`, `TLSv12`, **`TLSv13`**, `SSLv3`, `DTLSv12` | TLS 1.3은 서버 인증서를 암호화 → 해당 연결은 `x509.log`가 비어 있을 수 있음 |
| `cipher` | 협상된 암호 스위트 | 최신 호스트에서 아주 오래된/약한 스위트 = 오래된 도구 |
| `curve` | 키 교환 곡선 | |
| `server_name` | **SNI** — 클라이언트가 요청한 호스트명 | "어디에 연결했나" 필드. SNI가 비어 있으면 = IP로 직접 연결 또는 오래된 도구 |
| `resumed` | 세션 재개 사용 여부 | 비콘은 재개하는 경우가 많음; 한 호스트로 *전체* 핸드셰이크가 많은 것도 이상 |
| `last_alert` | TLS 경고 (있다면) | `handshake_failure`, `unknown_ca`… |
| `next_protocol` | ALPN (`h2`, `http/1.1`) | "브라우저"인데 ALPN이 없으면 = 브라우저가 아님 |
| `established` | 핸드셰이크 완료 여부 | 시도가 많은데 `F` = 탐색 / 실패하는 C2 |
| `ssl_history` (Zeek 5+) | 핸드셰이크의 글자 기록 | `conn.log history`의 TLS 버전 |
| `cert_chain_fuids` / `client_cert_chain_fuids` | 서버 / 클라이언트 인증서 체인의 파일 ID → `x509.log` | 첫 번째 요소 = 리프 인증서 |
| `subject` / `issuer` | 리프 인증서 주체 / 발급자 (보였다면) | 같으면 자체 서명 |
| `client_subject` / `client_issuer` | 클라이언트 인증서 (상호 TLS) | 드묾 — VPN, 일부 C2 |
| `validation_status` | `ok`, `self signed certificate`, `unable to get local issuer certificate`, `certificate has expired`… | `validate-certs` 정책 필요 |
| `ja3` / `ja3s` (정책) | 클라이언트 / 서버 TLS 지문 (MD5) | **클라이언트 소프트웨어 지문** |
| `ja4` / `ja4s` (정책, Zeek 6+) | 더 새롭고 정렬 가능한 지문 | 예: `t13d1516h2_8daaf6152771_02713d6af862` |
| `sni_matches_cert` (정책) | SNI가 인증서의 이름과 일치하나? | `F` = 도메인 프론팅, 설정 오류, 가짜 인증서 |

## `x509.log` 필드 { #x509log-fields }

| 필드 | 의미 | 분석 메모 |
|---|---|---|
| `ts`, `id` / `fingerprint` | 인증서의 파일 ID (`fuid`); SHA-1/256 지문 | `ssl.log cert_chain_fuids`와 결합 |
| `certificate.version` | 보통 3 | |
| `certificate.serial` | 일련번호 | 도구 기본 인증서는 알려진 일련번호를 가짐 |
| `certificate.subject` | `CN=…,O=…,C=…` | 비어 있음/쓰레기/`CN=localhost` → 수상 |
| `certificate.issuer` | 서명한 주체 | = subject → **자체 서명** |
| `certificate.not_valid_before` / `not_valid_after` | 유효 기간 | **처음 사용하기 몇 분 전에 만들어진** 인증서, 또는 1년이나 100년 유효 → 도구가 생성 |
| `certificate.key_alg`, `sig_alg`, `key_type`, `key_length`, `exponent`, `curve` | 키 상세 | 1024비트 RSA / `sha1WithRSA` = 오래됐거나 대충 만듦 |
| `san.dns`, `san.uri`, `san.email`, `san.ip` | 주체 대체 이름 (SAN) | 실제 사이트는 여러 개를 나열; C2 인증서는 없거나 하나 |
| `basic_constraints.ca`, `path_len` | CA 플래그 | `ca=T`인 리프 인증서는 이상 |
| `host_cert`, `client_cert` (Zeek 5+) | 인증서가 보인 위치 | |

## 빠른 쿼리 { #quick-queries }

=== "zeek-cut / 셸"

    ```bash
    # Top SNIs from internal hosts — long tail again
    zeek-cut server_name < ssl.log | sort | uniq -c | sort -n | head -40

    # TLS to raw IP (no SNI) — legit CDNs rarely, C2 often
    zeek-cut -d ts id.orig_h id.resp_h id.resp_p server_name version ja3 < ssl.log | awk '$5=="-"'

    # Self-signed / invalid certs
    zeek-cut -d ts id.orig_h id.resp_h server_name validation_status subject issuer < ssl.log | grep -v -P '\tok\t'

    # Rare JA3 hashes (few clients use them) and where they go
    zeek-cut id.orig_h ja3 < ssl.log | sort -u | awk '{print $2}' | sort | uniq -c | sort -n | head
    zeek-cut -d ts id.orig_h id.resp_h server_name < ssl.log | grep -F '<ja3 hash>'

    # Certificates valid for suspiciously short/long periods, or created just before use
    zeek-cut -d ts certificate.subject certificate.issuer certificate.not_valid_before certificate.not_valid_after < x509.log \
      | awk -F'\t' '{print}' | sort -u | head

    # Certs with no SAN (real sites almost always have one)
    zeek-cut fingerprint certificate.subject san.dns < x509.log | awk -F'\t' '$3=="-"' | sort -u

    # Pivot: one connection's cert chain
    grep -F 'CHhAvVGS1DHFjwGM9' ssl.log | zeek-cut cert_chain_fuids | tr ',' '\n' | while read f; do grep -F "$f" x509.log; done | zeek-cut certificate.subject certificate.issuer certificate.not_valid_before

    # Known-bad default certificates
    # Cobalt Strike default: CN=Major Cobalt Strike, serial 146473198 ; Metasploit: random CNs but 'O=…' patterns; Sliver: random 'O=' words
    grep -iE 'Major Cobalt Strike|146473198' x509.log
    ```

=== "Splunk"

    ```spl
    index=zeek sourcetype=zeek:ssl
    | stats dc(id.orig_h) as clients dc(id.resp_h) as servers values(server_name) as sni count by ja3
    | where clients <= 3
    | sort - count
    ```

    모든 TLS 핸드셰이크를 클라이언트 지문 `ja3`로 묶습니다. `values(server_name)`은 그 지문과 함께 본 모든 SNI를 (중복 없이) 나열합니다. 3대 이하의 머신이 쓰는 지문이 한두 서버와 수천 번 통신한다면 비콘입니다. 브라우저는 전사에서 공유하는 지문을 만듭니다.

    ```spl
    index=zeek sourcetype=zeek:ssl validation_status!="ok" validation_status!="-"
    | stats count min(_time) as first max(_time) as last by id.orig_h, id.resp_h, server_name, validation_status, subject
    | convert ctime(first) ctime(last)
    ```

    `min(_time)`/`max(_time)`은 각 내부 호스트가 신뢰할 수 없는 인증서에 처음과 마지막으로 접속한 시각을 주고, `convert ctime()`은 epoch 숫자를 읽을 수 있는 날짜로 바꿉니다. `count`로 정렬하면 어떤 자체 서명 인증서가 일정한 주기로 방문되는지 보입니다.

## 분석 팁 { #analysis-tips }

!!! tip "`ssl.log` 한 줄로 하는 저렴한 C2 체크리스트"
    SNI 없음 또는 SNI가 IP · `validation_status` ≠ `ok` · `subject` = `issuer` · *오늘*부터 유효한 인증서 · SAN 없음 · `next_protocol` 비어 있음 · 이 호스트만 쓰는 JA3 · 맨 VPS IP의 `id.resp_p` 443 · 일정한 간격으로 반복되는 연결. 세 개 이상 해당 → 반증될 때까지 C2로 취급하세요.

- **TLS 1.3은 서버 인증서를 숨깁니다.** 1.3에서도 SNI, JA3/JA4, ALPN, 타이밍은 남지만 `x509.log`에 서버 인증서는 없습니다(복호화 프록시가 아니라면). 암호화된 SNI/ECH는 이름까지 없애므로 — 그러면 JA4, 목적지 IP 평판, 행동만 남습니다.
- **JA3 충돌**: 많은 도구가 지문을 공유합니다(Go TLS 스택, .NET, Python `requests`). JA3는 그 자체로 시그니처가 아니라 **묶기**와 **희소 목록**에 쓰세요. JA4는 더 잘 구분합니다(`t13d…`가 버전, ALPN, 암호 개수를 보여 줌). **서버**도 지문을 찍으세요(`ja3s`/`ja4s`) — C2 프레임워크의 리스너는 모든 임플란트에 똑같이 응답합니다.
- **도메인 프론팅**: SNI는 `a.legit-cdn.com`이라고 하는데 안쪽 `Host`(보이지 않음)는 다른 곳입니다. 징후: `sni_matches_cert = F`, 유난히 **규칙적인** 트래픽이 있는 CDN SNI, 정해진 주기로 단 한 호스트만 접속하는 CDN 대역의 `resp_h`.
- **Let's Encrypt는 안전 신호가 아닙니다**: 최신 C2(Sliver, Mythic, Havoc, 리다이렉터)는 유효한 LE 인증서를 씁니다. 그럴 땐 **행동**으로 돌아가세요: 간격, 바이트 크기, 목적지 나이, JA3 희소성.
- **정상적인 자체 서명**: 프린터, IoT, 내부 관리 패널, 개발 장비. 먼저 `local_resp = T`를 걸러 내고 인터넷으로 나가는 나머지를 보세요.
- 워크스테이션 아웃바운드 트래픽의 **클라이언트 인증서**(`client_subject`) → VPN, 회사 프록시, 또는 상호 TLS를 쓰는 C2 (드물지만 Sliver mTLS 모드가 있음).
- **버전/암호 이상치**: 2026년에 `TLS_RSA_WITH_RC4_128_SHA`로 `TLSv10`을 협상하는 호스트 하나는 아주 오래된 무언가 — 또는 일부러 낮춘 도구를 돌리고 있습니다.
- **IP 간 인증서 재사용**: 같은 `x509` 지문이 시간에 따라 여러 `id.resp_h`에 나타나면 = 행위자가 인프라를 옮기면서 인증서는 유지한 것. 위협 인텔리전스와 과거 헌팅에 훌륭한 피벗입니다.

## 상관분석 { #correlation }

| 질문 | 다음에 볼 곳 |
|---|---|
| 얼마나 많이, 얼마나 자주 오갔나? | [`conn.log`](conn-log.md) `uid` → 바이트, 지속 시간; 간격 분석 ([비코닝과 C2](../beaconing-c2.md)) |
| 이름은 어디서 해석됐나? | 직전의 `query` = `server_name`인 [`dns.log`](dns-log.md) |
| 어떤 프로세스? | 호스트의 Sysmon `3` (`DestinationPort 443`); EDR 네트워크 텔레메트리 |
| 인증서가 다른 곳에서도 쓰였나? | 시간대별 `x509.log` `fingerprint`; 같은 지문이나 일련번호를 Censys / Shodan / crt.sh에서 |
| 경보? | Suricata `tls.sni`, JA3 규칙 (`ja3.hash`), `notice.log` `SSL::Invalid_Server_Cert` |
| 페이로드 | 복호화 없이는 볼 수 없음 — 호스트 아티팩트로 피벗 ([Prefetch](../../windows/prefetch.md), [SRUM](../../windows/srum.md), 메모리) |

## 참고 자료 { #references }

- [Zeek docs — ssl.log](https://docs.zeek.org/en/master/scripts/base/protocols/ssl/main.zeek.html) · [x509.log](https://docs.zeek.org/en/master/scripts/base/files/x509/main.zeek.html)
- [JA3 (Salesforce)](https://github.com/salesforce/ja3) · [JA4+ (FoxIO)](https://github.com/FoxIO-LLC/ja4)
- [Zeek JA4 package](https://github.com/FoxIO-LLC/ja4/tree/main/zeek)
- [SSLBL — abuse.ch SSL blacklist (JA3 + cert fingerprints)](https://sslbl.abuse.ch/)
