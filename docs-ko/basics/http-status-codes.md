---
title: HTTP 상태 코드
tags:
  - concept
  - basics
  - network
---

# HTTP 상태 코드 { #http-status-codes }

<div class="dfir-meta" markdown>
**분류:** 기초 · **최종 수정:** 2026-09-09
</div>

!!! abstract "한 줄 요약"
    첫 자리가 분류를 알려 줍니다. 로그 분석에서는 코드 하나보다 **패턴**(401/403/404가 몰려 나옴, 404 수백 개 뒤에 홀로 나온 200)이 더 중요한 경우가 많습니다.

## 분류 { #classes }

| 분류 | 의미 | 분석가 관점 |
|---|---|---|
| 1xx | 정보 | 로그에서는 드묾. `101` = WebSocket 업그레이드 (WebSocket 위의 C2도 있음) |
| 2xx | 성공 | 요청이 성공함. 이상한 경로에 `200` = 그게 실제로 있다는 뜻 |
| 3xx | 리다이렉션 | `Location` 헤더를 따라가 볼 것. 리다이렉트 체인은 피싱·악성광고의 전형 |
| 4xx | 클라이언트 오류 | 스캐닝, 무차별 대입, 고장 난 봇 |
| 5xx | 서버 오류 | 크래시, 설정 오류, 또는 익스플로잇이 성공해서 앱이 터짐 |

## 실제로 자주 보는 코드 { #the-ones-you-will-actually-see }

| 코드 | 이름 | DFIR 메모 |
|---|---|---|
| 200 | OK | 정상. **응답 크기**를 볼 것 — 0바이트이거나 크기가 늘 같은 200은 C2 하트비트일 수 있음 |
| 201 | Created | 업로드 성공 (WebDAV PUT, API) |
| 204 | No Content | 비콘·텔레메트리 체크인에서 흔함 |
| 206 | Partial Content | Range 요청 — 미디어 스트리밍이지만 쪼개서 하는 유출/다운로드일 수도 |
| 301 | Moved Permanently | |
| 302 | Found (임시 리다이렉트) | 로그인 흐름, 피싱 리다이렉터, 광고 네트워크 |
| 304 | Not Modified | 캐시됨; 클라이언트가 이미 갖고 있음 |
| 307 / 308 | 임시 / 영구 리다이렉트 (메서드 유지) | |
| 400 | Bad Request | 잘못된 요청 — 퍼징, 익스플로잇 시도, 고장 난 도구 |
| 401 | Unauthorized | 인증 필요/실패. 몰려 나오면 자격증명 무차별 대입 (Basic/NTLM) |
| 403 | Forbidden | 인증은 됐지만 허용 안 됨, 또는 WAF 차단. 디렉터리 무차별 대입은 403/404가 많이 보임 |
| 404 | Not Found | 한 IP에서 수백 개 연속 = 디렉터리 무차별 대입 (gobuster, dirb, feroxbuster) |
| 405 | Method Not Allowed | 예: 허용하지 않는 서버에 `PUT` — 업로드 가능 여부 탐색 |
| 407 | Proxy Authentication Required | 회사 프록시. 프록시 인증을 못 하는 악성코드는 여기서 막힘 |
| 408 | Request Timeout | |
| 413 | Payload Too Large | 허용치보다 큰 업로드 시도 |
| 418 | I'm a teapot | RFC 2324. 이게 보이면 누군가 장난치는 중 |
| 429 | Too Many Requests | 속도 제한 발동 — 누군가 마구 두드렸음 |
| 500 | Internal Server Error | 앱 크래시. 수상한 요청 직후라면 → 익스플로잇 가능성 |
| 501 | Not Implemented | |
| 502 | Bad Gateway | 리버스 프록시가 백엔드에 닿지 못함 |
| 503 | Service Unavailable | 과부하 / 점검 / DoS |
| 504 | Gateway Timeout | |

## 경보를 걸 만한 패턴 { #patterns-worth-alerting-on }

| 패턴 | 가능성 높은 의미 |
|---|---|
| 한 출발지에서 몇 초 안에 다양한 경로로 `404` 다수 | 디렉터리/파일 무차별 대입 |
| 한 출발지에서 같은 경로로 `401` 다수 | 패스워드 스프레이 / 무차별 대입 |
| `/wp-login.php`, `/admin`, `/.git/`, `/.env`에 `200` | 민감한 리소스 노출 — 무엇이 반환됐는지 확인 |
| `PUT`/`POST` → `201` 다음 같은 경로 `GET` → `200` | 웹셸 업로드와 첫 사용 |
| 일정 간격의 `GET`, 응답이 작고 똑같은 `200` | 비코닝 (지터, User-Agent, URI 엔트로피 확인) |
| `'`, `../`, `${jndi:`, `<script`가 들어간 요청 직후 `500` | 무언가를 건드린 익스플로잇 시도 |

## 빠르게 찾아보기 { #looking-these-up-quickly }

=== "Zeek http.log"

    ```bash
    # status code distribution per source
    zeek-cut id.orig_h status_code < http.log | sort | uniq -c | sort -rn | head
    ```

=== "Splunk"

    ```spl
    index=web sourcetype=access_combined
    | stats count by clientip, status
    | where status>=400
    | sort - count
    ```

=== "Apache / Nginx access log"

    ```bash
    awk '{print $9}' access.log | sort | uniq -c | sort -rn
    ```

## 참고 자료 { #references }

- [MDN — HTTP response status codes](https://developer.mozilla.org/en-US/docs/Web/HTTP/Status)
- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110)
