---
title: http.log
tags:
  - artifact
  - network
  - zeek
  - http
---

# Zeek `http.log` { #zeek-httplog }

<div class="dfir-meta" markdown>
**분류:** 네트워크 · **출처:** Zeek · **최종 수정:** 2026-09-16
</div>

!!! abstract "한 줄 요약"
    평문 HTTP의 요청/응답 쌍마다 한 줄입니다(복호화 프록시가 Zeek에 TLS를 풀어서 넘겨 준다면 그 트래픽도 포함). 메서드, 호스트, URI, User-Agent, 상태, 크기, 그리고 오간 파일의 `fuid`가 들어 있어서 페이로드 다운로드, 웹셸 트래픽, HTTP 기반 C2를 가장 빨리 찾을 수 있는 곳입니다.

## 필드 { #fields }

| 필드 | 의미 | 분석 메모 |
|---|---|---|
| `ts`, `uid`, `id.*` | `conn.log`와 같음 | TCP `uid` 하나가 여러 요청을 실을 수 있음 (keep-alive) |
| `trans_depth` | 연결 안에서의 요청 번호 (1, 2, 3…) | 파이프라이닝 / keep-alive 횟수 |
| `method` | `GET`, `POST`, `HEAD`, `PUT`, `OPTIONS`, `PROPFIND`, `CONNECT`… | `PUT`/`PROPFIND` = WebDAV (페이로드 스테이징), `CONNECT` = 프록시 터널링, 이상한 대소문자/메서드 = 도구 |
| `host` | `Host:` 헤더 | `id.resp_h`의 역방향/`dns.log`와 비교; **Host가 IP 그대로** = 수상; SNI 기대와 불일치 = 도메인 프론팅 |
| `uri` | 경로 + 쿼리 문자열 | 짧은 무작위 경로, `.php?cmd=`, base64 파라미터, 이상한 호스트의 `/api/v1/` |
| `referrer` | `Referer:` 헤더 | 악성코드의 직접 요청에는 없음; 드라이브 바이 체인에는 있음 |
| `version` | `1.0` / `1.1` / `2` | 최신 호스트에서 `1.0` = 스크립트 클라이언트 |
| `user_agent` | `User-Agent:` 헤더 | 황금 필드 — 아래 참고 |
| `origin` | `Origin:` 헤더 | |
| `request_body_len` / `response_body_len` | 바이트 | 모르는 호스트로 본문이 큰 POST = 유출; 작은 주기적 GET = 비콘 |
| `status_code` / `status_msg` | 응답 코드 | [HTTP 상태 코드](../../basics/http-status-codes.md) 참고 |
| `info_code` / `info_msg` | 1xx 중간 응답 | |
| `tags` | Zeek 자체 플래그 (예: `URI_SQLI`) | |
| `username` / `password` | `Authorization: Basic`에서 추출 | **평문 자격증명** |
| `proxied` | 프록시를 암시하는 헤더 (`X-Forwarded-For`, `Via`) | 프록시 뒤의 실제 클라이언트 IP |
| `orig_fuids` / `resp_fuids` | 업로드 / 다운로드한 파일 ID | → [`files.log`](files-log.md) |
| `orig_filenames` / `resp_filenames` | `Content-Disposition` / URI에서 | |
| `orig_mime_types` / `resp_mime_types` | 추정한 MIME 타입 (헤더가 아니라 내용 기준) | `image/png` 뒤의 `application/x-dosexec` = 위장한 EXE |
| `client_header_names` / `server_header_names` (선택 정책) | 헤더 이름 순서대로 | 헤더의 순서와 구성으로 도구를 식별 (예: `Accept-Language` 없음) |
| `cookie_vars`, `uri_vars` (선택) | 파싱된 변수 | |

## 빠른 쿼리 { #quick-queries }

=== "zeek-cut / 셸"

    ```bash
    # Rare user agents (count of distinct hosts using each UA — malware UAs are used by 1 host)
    zeek-cut id.orig_h user_agent < http.log | sort -u | awk -F'\t' '{print $2}' | sort | uniq -c | sort -n | head -30

    # Executables downloaded (by sniffed MIME type), with where from
    zeek-cut -d ts id.orig_h host uri resp_mime_types resp_fuids < http.log | grep -E 'x-dosexec|x-msdownload|x-executable|x-msdos' 

    # POSTs to raw-IP hosts or to hosts never seen before (exfil / C2 check-ins)
    zeek-cut -d ts id.orig_h host uri method request_body_len < http.log | awk '$5=="POST"' | grep -E '\t[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\t'

    # Beacon-like: same host+uri hit repeatedly by one client with small responses
    zeek-cut id.orig_h host uri response_body_len < http.log | sort | uniq -c | sort -rn | awk '$1>50' | head

    # Web shell hunting on your own web server (internal resp_h): POSTs to .php/.aspx/.jsp with 200
    zeek-cut -d ts id.orig_h uri method status_code < http.log | grep -E '\.(php|aspx?|jsp|jspx)\b' | awk '$4=="POST" && $5==200'

    # Directory brute force: one source, hundreds of 404s
    zeek-cut id.orig_h status_code < http.log | awk '$2==404' | sort | uniq -c | sort -rn | head

    # Cleartext credentials
    zeek-cut -d ts id.orig_h host username password < http.log | awk '$4!="-"'

    # Everything one connection said (pivot from conn.log uid)
    grep -F 'CHhAvVGS1DHFjwGM9' http.log | zeek-cut -d ts method host uri status_code user_agent
    ```

=== "Splunk"

    ```spl
    index=zeek sourcetype=zeek:http
    | stats dc(id.orig_h) as hosts count by user_agent
    | where hosts <= 2
    | sort count
    ```

    각 User-Agent를 *서로 다른* 클라이언트 몇 대가 쓰는지(`dc(id.orig_h)`) 셉니다. 회사 전체에서 한두 대만 쓰는 UA는 맞춤 도구이거나 악성코드입니다 — 정상 브라우저는 수백 대가 씁니다.

    ```spl
    index=zeek sourcetype=zeek:http resp_mime_types="application/x-dosexec"
    | table _time, id.orig_h, host, uri, response_body_len, resp_fuids
    | join type=left resp_fuids [ search index=zeek sourcetype=zeek:files | rename fuid as resp_fuids | fields resp_fuids, sha256, md5 ]
    ```

    `table`은 보여 줄 열을 고릅니다. `join type=left resp_fuids [ … ]`는 `files.log`에 두 번째 검색을 돌리고, 그 `fuid` 이름을 맞게 바꾼 뒤 각 다운로드 행에 해시를 붙입니다 — 그래서 "EXE가 다운로드됐다"에서 "이게 그 SHA-256이다"까지 쿼리 하나로 갑니다. (`join`은 큰 데이터에서 느립니다; 넓은 범위에는 `OR` 검색 후 `stats … by fuid`를 쓰세요.)

## 분석 팁 { #analysis-tips }

!!! tip "User-Agent 트리아지: 세 바구니"
    1. **실제 브라우저** — UA가 길고, 많은 호스트가 쓰며, 보유 OS와 일치.
    2. **정상 도구/업데이터** — `Microsoft-CryptoAPI/10.0`, `Windows-Update-Agent`, `Microsoft BITS/7.8`, `Microsoft-Delivery-Optimization`, `Google Update`, **Office**/WinHTTP가 쓰는 `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; …)`. 이것들을 익혀 두면 더 이상 놀라지 않게 됩니다.
    3. **그 밖의 모든 것** — `python-requests/2.x`, `curl/…`, `Go-http-client/1.1`, `PowerShell`/`WindowsPowerShell/5.1`, `Wget`, `Java/1.8`, 빈 UA, 오타가 있는 UA(`Mozila`), 그럴듯한 IE 문자열이지만 Win11 호스트에서 `MSIE 9.0; Windows NT 6.1`로 고정된 Cobalt Strike식 *기본* UA. **드묾 + 워크스테이션에서 + 모르는 호스트로** = 실마리를 당겨 보세요.

- **Host ≠ IP**: Zeek은 `host`를 헤더에서 기록합니다. `host`는 `cdn.example.com`인데 `id.resp_h`는 무작위 VPS이거나, `host`가 비어 있거나 IP 그대로라면 볼 가치가 있습니다. 악성코드는 IP를 하드코딩하고 `Host`를 빼거나 꾸미는 경우가 많습니다.
- **추정 MIME이 선언된 것을 이깁니다**: `resp_mime_types`는 바이트가 실제로 *무엇인지*입니다. `uri`는 `.jpg`로 끝나는데 `resp_mime_types`가 `application/x-dosexec` → 이미지로 위장한 2단계 페이로드. 실제로는 PowerShell인 `text/plain` 본문도 주의하세요.
- **비콘 패턴**: 고정되거나 돌아가는 짧은 `uri`에 N초/분마다 `GET`, 대기 중에는 `response_body_len`이 아주 작고(0–200) 작업이 있을 때만 가끔 커짐; 결과를 돌려보낼 때는 `request_body_len`이 커지는 `POST`. Cobalt Strike 기본값: `GET /ca`, `/dpixel`, `/__utm.gif`, `/pixel.gif`, `/activity`, `/submit.php?id=…` — malleable 프로필로 바꿀 수 있지만 랩/저가 작전에서는 기본값을 그대로 두는 경우가 많습니다.
- **내 서버의 웹셸 트래픽**: 스크립트 하나로의 `POST`, `200`, `referrer -`, 이상한 UA, 길이가 제각각인 요청 본문, 명령 출력 크기의 응답 본문. 셸을 만든 업로드(`orig_fuids`가 있는 `PUT`/`POST`)를 `files.log`에서 확인하세요.
- **80이 아닌 포트의 HTTP**도 여기 기록됩니다 (DPD로 `service=http`). `id.resp_p!=80`으로 필터하면 프록시, 8080/8443 평문 C2, 내부 도구를 찾을 수 있습니다.
- **HTTP/2와 HTTPS**는 여기 *없습니다* — 핸드셰이크는 `ssl.log`이고, 내용은 프록시 복호화나 EDR 수준의 가시성이 필요합니다.
- **청크 / 압축 본문**: `response_body_len`은 Zeek이 본 압축 해제 후 길이이고, `conn.log`의 `resp_bytes`는 실제 전송량입니다.

## 상관분석 { #correlation }

| 질문 | 다음에 볼 곳 |
|---|---|
| 다운로드한 파일은 무엇이었나? | `resp_fuids` → [`files.log`](files-log.md) (`sha256`, `mime_type`, `total_bytes`) → `pe.log`, `extract_files/<fuid>` |
| 실행됐나? | 호스트: [Prefetch](../../windows/prefetch.md), [Amcache](../../windows/amcache.md), [$MFT](../../windows/mft-usn.md)의 `Zone.Identifier` `HostUrl`에 이 URL이 있을 것 |
| 어떤 프로세스가 요청했나? | `uid` 5-튜플/시각과 맞는 Sysmon `3`; 사용자명이 있는 프록시 로그 |
| 이름은 어디서 해석됐나? | `ts` 직전 `query`=`host`인 [`dns.log`](dns-log.md) |
| 경보? | Suricata HTTP 규칙 (`eve.json` `http.hostname`, `http.url`), `notice.log` |
| 요청/응답 본문 전체 | pcap: [`tshark -Y "http.request && ip.addr==…" -T fields -e http.file_data`](../wireshark-tshark.md); Arkime 세션 보기 |

## 참고 자료 { #references }

- [Zeek docs — http.log](https://docs.zeek.org/en/master/scripts/base/protocols/http/main.zeek.html)
- [Cobalt Strike default HTTP indicators — Malleable C2 profiles reference](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/malleable-c2_main.htm)
- [HTTP 상태 코드](../../basics/http-status-codes.md) · [잘 알려진 포트](../../basics/well-known-ports.md)
