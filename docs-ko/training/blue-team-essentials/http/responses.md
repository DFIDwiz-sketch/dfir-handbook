---
title: "응답 헤더와 응답 코드"
tags:
  - training
  - blue-team
  - http
  - concept
---

# 응답 헤더와 응답 코드 { #responses }

!!! abstract "이 페이지에서 다루는 것"
    서버가 돌려보내는 응답의 헤더(Server, Date, Content-Type, Content-Length, Last-Modified, Set-Cookie, 그리고 실무 필수인 Location·Content-Disposition), 서버의 거짓말을 잡는 매직 바이트, 응답 코드(1xx~5xx)를 SOC 관점에서 읽는 법, "407 다음에 아무것도 없으면?"이라는 행간 읽기, 그리고 8바이트짜리 응답 해부. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 요청 쪽은 [POST, 그 밖의 메서드, 요청 헤더](post-methods-headers.md)와 [요청 판정 연습](reading-requests.md)에 있습니다.

## 한눈에 보는 핵심 10가지 { #key-points }

1. 요청은 "무엇을 달라고 했나", 응답은 "실제로 무엇을 받았나"를 알려 준다. 둘 다 봐야 한다.
2. Content-Type은 서버의 **주장**이다. 실제 내용물은 매직 바이트(예: 실행 파일의 `MZ`)와 Zeek `resp_mime_types`로 확인한다.
3. Content-Type과 `resp_mime_types`가 다르면 강한 의심 신호다.
4. 크기는 헤더(Content-Length)보다 장비가 실제로 센 값(Zeek `response_body_len`)을 믿는다.
5. `Location`은 다음 행선지, `Content-Disposition`은 사용자 PC에 저장된 실제 파일 이름이다.
6. 응답 코드 첫 자리: 1 = 잠깐만, 2 = 성공, 3 = 저쪽으로, 4 = 손님 잘못, 5 = 주방 잘못.
7. 악성 요청에 200(또는 201·206)이 났는가가 가장 중요한 질문이다.
8. 404 폭풍 속 200, 401 폭풍(비밀번호 대입), 이상한 입력 뒤 500(취약점 신호)을 찾는다.
9. 407을 받고도 인증하지 않고 같은 간격으로 반복하는 프로그램 = 프록시를 모르는 프로그램, 흔히 악성코드.
10. 응답 코드도 서버가 고르는 값이다. "404니까 아무 일 없음"은 위험한 판단이다.

## 응답 헤더 { #response-headers }

**왜 필요한가.** 요청 헤더가 손님이 쓴 주문서 메모라면, 응답 헤더는 **주방이 음식 상자에 붙여 보낸 배송 전표**입니다. 누가 만들었고, 언제 보냈고, 내용물이 뭐고, 얼마나 큰지가 적혀 있습니다. 요청만 보면 "무엇을 달라고 했는지"만 알 수 있고, 응답을 봐야 "실제로 무엇을 받았는지"를 압니다.

헤더는 응답 자체를 설명하는 것(`Server` 등)과 상자 안 내용물을 설명하는 것(`Content-Type`, `Content-Length`, `Content-Encoding` 등)으로 나뉩니다. 예전엔 후자를 "엔티티 헤더"라고 불렀지만 RFC 9110(2022년 6월) 이후 공식 용어는 "Representation"/"Content" 헤더입니다.

```
HTTP/1.1 200 OK
Server: Apache/2.4.62 (Ubuntu)
Date: Sun, 01 Nov 2026 08:55:12 GMT
Content-Type: application/pdf
Content-Length: 482113
Last-Modified: Fri, 30 Oct 2026 23:10:04 GMT
Set-Cookie: sessionid=a91f3c7e2b; Path=/; Secure; HttpOnly; SameSite=Lax

%PDF-1.7 ... (file bytes) ...
```

첫 줄은 **상태 줄**(Status Line)입니다. 버전(`HTTP/1.1`), 응답 코드(`200`), 사람이 읽는 설명(`OK`). 그 아래가 헤더, 빈 줄 아래가 실제 내용물입니다.

### Server — 만든 주방 이름 { #server }

응답을 만든 웹 서버 프로그램과 버전입니다(위 예: 우분투의 Apache 2.4.62).

- **우리 서버 점검:** 버전이 너무 자세히 보이면 공격자가 "이 버전엔 이 취약점" 하고 바로 표적을 고릅니다. 그래서 운영자는 보통 `Server: nginx`처럼 버전을 숨깁니다.
- **외부 서버 추정:** User-Agent처럼 자기소개일 뿐이라 아무 값이나 쓸 수 있습니다. 공격자 서버도 대부분 nginx나 Apache라고 말합니다.

**[보충] 말하는 이름보다 말하는 버릇.** 같은 프로그램은 헤더 순서, 기본 오류 페이지, TLS 연결 때의 반응이 늘 같습니다. 이를 이용한 서버 지문 기법(JARM, JA4S, JA4X 등)으로 인터넷에 숨은 C2 서버를 찾기도 합니다. 요청 쪽 [헤더 순서 지문](post-methods-headers.md#header-order)과 같은 원리를 서버 쪽에 쓰는 것입니다.

### Date — 보낸 시각 { #date }

서버가 응답을 보낸 시각이며 <strong>항상 GMT(=UTC)</strong>입니다. 위 `08:55:12 GMT`는 시드니 서머타임(+11시간)으로 19:55:12입니다. 우리 장비 로그 시각과 맞춰 타임라인을 만들 때 쓰지만, 공격자 서버라면 아무 값이나 쓸 수 있으니 참고값입니다.

### Content-Type — 내용물 종류(가장 중요) { #content-type }

서버가 "이 상자엔 이런 파일이 들었다"고 밝히는 칸입니다. 형식은 **MIME 타입**(원래 이메일 첨부 파일 종류 표시 규칙)으로, `종류/세부종류` 모양입니다.

```
text/html                         ← web page
image/png                         ← PNG image
application/pdf                   ← PDF document
application/zip                   ← ZIP archive
application/x-dosexec             ← Windows executable (EXE/DLL)
application/x-msdownload          ← Windows executable (another common label)
application/octet-stream          ← "just bytes" — unknown/generic binary
application/vnd.openxmlformats-officedocument.wordprocessingml.document  ← .docx
```

**SIEM에서 한꺼번에 검색하기 좋다**는 게 이 칸의 큰 장점입니다. 프록시 로그에 Content-Type이 있으면 "지난 일주일 회사 PC가 외부에서 받은 실행 파일 전부"를 한 번에 뽑을 수 있습니다.

단, Content-Type은 **서버가 주장하는 값**입니다. 공격자 서버는 실행 파일을 보내며 `image/png`라고 거짓말할 수 있습니다.

**[보충] 거짓말 잡기: 매직 바이트(Magic Bytes).** 파일은 대부분 맨 앞 몇 바이트에 고유 표시를 갖고 있습니다. 이름표(Content-Type, 확장자)는 바꿔 달 수 있어도, 몸에 새겨진 이 표시를 바꾸면 파일이 망가집니다.

```
4D 5A           "MZ"      ← Windows executable (EXE, DLL)
25 50 44 46     "%PDF"    ← PDF
50 4B 03 04     "PK.."    ← ZIP (also .docx, .xlsx, .jar, .apk — they are ZIP inside)
89 50 4E 47     ".PNG"    ← PNG image
FF D8 FF                  ← JPEG image
D0 CF 11 E0               ← old Office file (.doc, .xls) and .msi
```

`MZ`는 MS-DOS 실행 파일 형식을 만든 개발자 Mark Zbikowski의 이니셜입니다. `.docx`, `.xlsx`, `.jar`는 속이 ZIP이라 똑같이 `PK`로 시작합니다.

Zeek `http.log`의 `resp_mime_types`는 서버 헤더가 아니라 **내용물의 매직 바이트를 보고** 판단한 값입니다. 그래서 **서버의 Content-Type과 Zeek의 `resp_mime_types`가 다르면 강한 의심 신호**입니다.

**콘텐츠 스니핑(Content Sniffing).** Content-Type이 없으면 일부 브라우저는 내용물을 보고 종류를 추측합니다. 그림인 척하는 파일 속 스크립트를 실행시키는 데 악용될 수 있어, 요즘 서버는 `X-Content-Type-Options: nosniff`로 "추측하지 말고 내가 말한 대로만 처리해"라고 지시합니다.

### Content-Length — 내용물 크기 { #content-length }

응답 본문이 몇 바이트인지입니다. 응답의 Content-Length로 **가장 큰 다운로드**를, 요청의 Content-Length로 **가장 큰 업로드**(데이터 유출 단서)를 찾습니다.

**[보충] Content-Length가 없는 경우가 많습니다.** 서버가 크기를 미리 모르면 `Transfer-Encoding: chunked`로 토막 내 보내고, HTTP/2·3에서도 생략이 흔합니다. 크기는 **실제로 오간 바이트를 센 값**(Zeek `response_body_len`, `request_body_len`)이 더 믿을 만합니다.

### Last-Modified — 마지막으로 바뀐 시각 { #last-modified }

서버 쪽 파일의 마지막 수정 시각입니다. 원래 용도는 캐시입니다.

**[정정] 주된 방식은 HEAD가 아니라 조건부 GET입니다.** 브라우저가 GET에 `If-Modified-Since: (지난번 Last-Modified)`를 붙이면, 서버는 안 바뀐 경우 내용물 없이 **`304 Not Modified`**로 답합니다. 요즘은 날짜 대신 파일 지문 같은 `ETag`로 비교(`If-None-Match`)하는 방식도 많습니다.

**[보충]** 악성 파일 응답의 Last-Modified는 **공격자가 그 파일을 올리거나 바꾼 시각**의 힌트가 됩니다. 조작 가능하니 참고값입니다.

### Set-Cookie — 손목밴드 채워 주기 { #set-cookie }

서버가 "이 쿠키를 저장하고 다음부터 요청마다 보여 줘"라고 지시하는 헤더입니다. 이후 요청의 `Cookie:`로 돌아옵니다([Cookie](post-methods-headers.md#cookie)).

| 속성 | 뜻 |
| --- | --- |
| `Secure` | https 연결에서만 보냄 |
| `HttpOnly` | 웹 페이지 스크립트가 못 읽음 → XSS로 쿠키 훔치기가 어려워짐 |
| `SameSite=Lax` | 다른 사이트에서 시작된 요청엔 함부로 붙이지 않음 |
| `Path=/` | 사이트 전체에서 사용 |

분석가에게는 **로그인 성공 직후 서버가 세션 쿠키를 새로 주는 순간**이 중요합니다. AiTM 피싱이 가로채는 게 바로 이 Set-Cookie입니다.

### [보충] Location과 Content-Disposition { #location-disposition }

```
HTTP/1.1 302 Found
Location: https://cdn.example.net/files/update.zip

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="Invoice_2026-10.pdf.exe"
```

- **`Location`** — "그건 여기 없으니 이 주소로 가세요". 3xx에 붙으며 **다음 행선지**를 알려 줍니다. 피싱·악성 광고는 리디렉션을 여러 번 거치므로 Location을 이어 보면 경로 전체가 나옵니다.
- **`Content-Disposition: attachment; filename="..."`** — "화면에 띄우지 말고 **이 이름으로 저장**하세요". URL이 `/dl?id=8812`처럼 이름을 알려 주지 않아도 실제 저장 이름은 여기 있습니다. 위 예는 확장자를 두 번 붙인 `.pdf.exe`. "다운로드 폴더의 이 파일은 어디서 왔나"를 찾을 때 결정적입니다.

## 응답 코드 { #status-codes }

**왜 필요한가.** 응답 코드는 주방이 주문에 내리는 **한 줄 결론**입니다. 분석가는 이걸로 "실제로 받아 갔나?", "문제가 생겼다면 손님 탓인가 주방 탓인가, 무슨 문제인가?"를 판단합니다.

```
1xx  Informational   ← "hold on, keep going"
2xx  Success         ← "here you go"
3xx  Redirection     ← "not here, go over there"
4xx  Client error    ← "customer's fault"
5xx  Server error    ← "kitchen's fault"
```

| 코드 | 뜻 | SOC에서 읽는 법 |
| --- | --- | --- |
| 100 Continue | "본문 계속 보내세요" | 큰 POST 전에 `Expect: 100-continue`의 답. 보안상 의미 적음 |
| 101 Switching Protocols | "말하는 방식을 바꿉시다" | 주로 **웹소켓** 시작. 이후 대화는 일반 HTTP 로그에 거의 안 남아 C2 은신처가 될 수 있음 |
| 200 OK | 성공 | 악성 요청에 200이면 실행·다운로드가 일어났을 가능성 |
| 201 Created | 새로 만들었음 | 외부 PUT + 201 = 웹셸 업로드 의심 |
| 204 No Content | 성공, 돌려줄 내용 없음 | 비콘의 "명령 없음" 응답으로도 쓰임 |
| 206 Partial Content | 일부분만 보냄 | 이어받기. 윈도우 BITS가 자주 만들고 공격자도 BITS로 몰래 다운로드 → 206 여러 개가 실행 파일 하나가 되는 패턴 |
| 301 / 308 | 영구 이사 | 흔히 http → https |
| 302 / 307 | 임시로 저쪽 | **이동 경로.** 피싱·악성 광고·TDS가 이어 붙임. Location을 따라감 |
| 304 Not Modified | 바뀐 거 없음, 사본 쓰세요 | 캐시. 보통 정상 |
| 400 Bad Request | 문법이 틀린 요청 | 정상 브라우저는 안 틀림 → 손으로 만든 요청·공격 도구 |
| 401 Unauthorized | 로그인부터 하세요(아직 인증 안 됨) | 같은 출발지의 401 폭풍 = 비밀번호 대입·스프레이 |
| 403 Forbidden | 누군지 알지만 권한 없음 | 관리자 페이지 등 금지 구역 두드리기 |
| 404 Not Found | 없음 | 404 폭풍 = 스캐너. 그 사이의 **200을 찾음** |
| 405 Method Not Allowed | 그 방식은 안 받음 | PUT·DELETE 시도 흔적 |
| 407 Proxy Auth Required | **프록시**에 먼저 인증하세요 | 아래 "행간 읽기" |
| 421 Misdirected Request | 이 연결로는 그 사이트 처리 불가 | SNI·Host 불일치(도메인 프론팅 시도) 흔적 |
| 429 Too Many Requests | 너무 많이 보냄 | 속도 제한에 걸린 자동화 공격 |
| 500 Internal Server Error | 서버 내부 오류 | 이상한 입력(예: SQL 인젝션) 직후 500 = 그 입력이 서버 코드를 깨뜨림 = **취약점 신호** |
| 502 / 504 | 뒤쪽 서버가 응답 못 함 | 프록시·로드밸런서 뒤 장애 |
| 503 Service Unavailable | 감당 못 함 | 과부하·점검, DoS 의심 |

401과 403이 헷갈리면: 401은 회사 출입문에서 사원증을 **안 보여 준** 것, 403은 사원증은 보여 줬는데 **권한 없는 층**에 가려 한 것입니다.

### 행간 읽기: 407 다음에 아무것도 없으면? { #proxy-407 }

회사 프록시가 윈도우 로그인 정보로 자동 인증하게 설정돼 있다면, 정상 브라우저나 윈도우 정식 통신 기능(WinINet, WinHTTP)을 쓰는 프로그램은 407을 받자마자 **사용자 몰래** Kerberos·NTLM으로 인증해 다시 요청합니다.

```
20:15:02.101  10.1.5.23  -        CONNECT login.microsoftonline.com:443  407
20:15:02.188  10.1.5.23  jsmith   CONNECT login.microsoftonline.com:443  200
```

사용자 이름 없는 첫 요청에 407 → 0.1초도 안 돼 `jsmith` 이름을 달고 다시 와서 200. 사람은 아무것도 느끼지 못합니다.

```
20:15:00  10.1.5.40  -  CONNECT update-svc.example:443  407
20:16:00  10.1.5.40  -  CONNECT update-svc.example:443  407
20:17:00  10.1.5.40  -  CONNECT update-svc.example:443  407
20:18:00  10.1.5.40  -  CONNECT update-svc.example:443  407
```

407을 받고도 **인증을 시도하지 않고** 정확히 1분 뒤 같은 요청을 반복합니다. 회사 프록시 인증을 할 줄 모르는 프로그램, 대개 **자기만의 HTTP 통신 코드를 들고 온 악성코드**입니다. 1분 간격이면 비콘입니다.

**실패한 통신이 오히려 단서가 됩니다.** 악성코드는 C2에 닿지도 못했지만 프록시 로그에 자기 존재를 계속 알리고 있습니다. 그리고 이게 이상하다는 걸 알려면 **우리 회사의 정상 흐름(407 → 0.1초 뒤 인증 → 200)을 먼저 알아야** 합니다. 기준선이 탐지의 출발점입니다.

!!! warning "[주의] 407 무응답이 전부 악성은 아니다"
    프록시 설정을 모르는 정상 소프트웨어(일부 업데이트 도구, 개발 도구, 오래된 프로그램)도 같은 모양을 만듭니다. **어떤 프로그램이 연결을 만들었는지** 호스트에서 확인해야 결론이 납니다(Sysmon Event ID 3).

## 응답 읽기 연습: 8바이트짜리 웹 페이지 { #reading-response }

```
HTTP/1.1 200 OK
Server: nginx
Date: Mon, 08 Feb 2021 14:21:07 GMT
Content-Type: text/html
Content-Length: 8
Connection: keep-alive

........
```

| 칸 | 해설 |
| --- | --- |
| `200 OK` | 성공, 서버가 무언가를 돌려줌 |
| `Date` | 2021년 2월 8일(월) 응답. 우리 프록시 로그 시각과 맞춰 같은 사건인지 확인 |
| `Content-Type: text/html` | 웹 페이지라고 **주장**. 악성코드와 악성 서버의 대화라면 일부러 속인 값일 수 있음 |
| `Server: nginx` | 버전 없음. nginx는 기본값이 버전 표시(`nginx/1.24.0` 등)라 운영자가 일부러 숨긴 것(`server_tokens off`). 정상 보안 설정으로도 흔함 |
| `Content-Length: 8` | 내용물 **8바이트** |

**[보충] 8바이트짜리 웹 페이지라는 단서.** 가장 짧은 HTML 뼈대(`<html></html>`)도 13바이트라, 8바이트로는 사람이 볼 페이지를 만들 수 없습니다. 프로그램이 읽는 짧은 신호(`OK`, `0`, `noop`, 짧은 토큰)일 가능성이 있습니다. 상태 확인 주소(Health Check)나 광고 추적 응답처럼 정상일 수도 있지만, **같은 PC에 일정한 간격으로 매번 같은 크기**로 돌아온다면 C2 비콘의 "명령 없음" 응답의 전형입니다. 그러다 **크기가 갑자기 커진 응답**이 하나 섞이면 그게 실제 명령이나 추가 악성코드가 내려온 순간입니다. 비콘 분석에서는 간격만큼 **응답 크기 패턴**이 중요합니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 그대로 유효한 것"
    응답 헤더 읽는 법(특히 Content-Type, Content-Length, Set-Cookie), 응답 코드의 뜻, "407 뒤 무응답은 프록시를 모르는 프로그램"이라는 행간 읽기는 지금도 유효합니다. 인증 프록시 환경이라면 지금도 쓸 만한 탐지 아이디어입니다.

!!! info "[변경됨] 바뀐 것"
    - **HTTP/2·3에는 "OK" 글자가 없습니다.** 설명 글자(Reason Phrase)는 사라지고 `:status: 200`처럼 숫자만 갑니다. 도구에 "200 OK"로 보이는 건 도구가 덧붙인 것입니다.
    - **`421 Misdirected Request`가 실무에서 보입니다.** SNI와 Host가 안 맞는 연결(도메인 프론팅 시도 등)에 CDN이 돌려주는 코드입니다([도메인 프론팅](post-methods-headers.md#domain-fronting)).
    - **Content-Length를 믿기 어려워졌습니다.** chunked 전송, HTTP/2·3, 압축 때문에 없거나 실제와 다른 경우가 흔합니다.
    - **보안 응답 헤더가 표준처럼 쓰입니다.** `X-Content-Type-Options: nosniff`, `Strict-Transport-Security`, `Content-Security-Policy`가 대부분의 정상 서비스에 붙습니다. 유명 브랜드를 흉내 낸 페이지에 이런 헤더가 하나도 없으면 급조한 피싱 페이지일 수 있다는 약한 단서가 됩니다.
    - **인증 프록시 환경 자체가 줄었습니다.** 클라우드 보안 웹 게이트웨이(SWG)나 엔드포인트 에이전트 방식으로 옮겨 가면 407 탐지는 못 쓰고, 대신 **에이전트를 거치지 않고 직접 나가는 연결**을 찾습니다.

!!! warning "[주의] 지금 그대로 하면 틀리거나 위험한 것"
    - **Content-Type은 주장일 뿐입니다.** 확장자도 Content-Type도 거짓일 수 있습니다. 매직 바이트, `resp_mime_types`, 파일 해시로 판단합니다.
    - **"404니까 아무 일 없었다"는 위험합니다.** 일부 C2 프레임워크는 스캐너·연구자에게 죽은 사이트처럼 보이도록 **가짜 404**를 돌려주고, 진짜 명령은 그 404 본문이나 특정 조건에서만 내려보냅니다. 404인데 크기가 크거나, 매번 다르거나, 주기적으로 반복되면 의심합니다.
    - **Date, Last-Modified, Server도 서버가 쓰는 값입니다.** 우리 장비가 기록한 시각과 크기가 1차 증거입니다.

## 확인 문제 { #quiz }

먼저 직접 답해 본 뒤 해설을 펼쳐 보세요.

### 문제 1

회사 프록시는 윈도우 로그인 정보로 자동 인증합니다. 다른 PC들은 대부분 "407 → 0.1초 안에 사용자 이름이 붙은 200" 모양인데, 한 PC에서 이런 기록이 밤새 이어집니다.

```
01:00:03  10.1.5.77  -  CONNECT cdn-sync-api.example:443  407
01:05:03  10.1.5.77  -  CONNECT cdn-sync-api.example:443  407
01:10:03  10.1.5.77  -  CONNECT cdn-sync-api.example:443  407
01:15:03  10.1.5.77  -  CONNECT cdn-sync-api.example:443  407
```

(a) 이 패턴에서 읽을 수 있는 것은? (b) 악성코드라고 바로 단정하면 안 되는 이유와, 결론을 내리려면 확인할 것은? (c) C2 연결에 실패했는데도 왜 위험 신호입니까?

??? success "정답과 해설"
    **(a)** 이 PC의 어떤 프로그램이 **정확히 5분마다, 사람이 없는 밤새** `cdn-sync-api.example`에 연결하려 하고, 407을 받고도 **인증을 한 번도 시도하지 않습니다.** 회사 프록시 인증을 모르는 프로그램, 즉 윈도우 정식 통신 기능이 아닌 자기만의 HTTP 코드를 쓰는 프로그램입니다. 기계적인 주기까지 합치면 비콘 모양입니다.

    **(b)** 프록시를 모르는 **정상 소프트웨어**(동기화 도구, 업데이트 도구, 개발 도구, 오래된 프로그램)도 똑같은 모양을 만듭니다. 이름 `cdn-sync-api`도 정상 동기화 서비스처럼 보일 수 있습니다. 결론을 내리려면:

    1. **어떤 프로그램인지** — EDR 또는 **Sysmon Event ID 3**(네트워크 연결: 어떤 실행 파일이 어느 IP·포트로 연결했는지)에서 프록시 주소로 연결한 프로세스의 실행 파일 경로 확인
    2. 그 파일의 위치(`AppData`, `Temp` 같은 이상한 곳인지), 디지털 서명, 해시 평판
    3. 그 프로그램이 어떻게 자동 실행되는지(예약 작업, 서비스, Run 키 같은 지속성 장치)
    4. 도메인의 처음 등장 시점, 등록일, 평판
    5. 같은 PC가 프록시를 거치지 않고 **방화벽으로 직접** 나간 연결이 있는지

    **(c)** 실패했어도 위험한 이유:

    - PC에 **정체 모를 프로그램이 지속적으로 실행 중**이라는 증거입니다. 감염과 지속성 장치는 이미 성공한 것입니다.
    - 공격자는 연결이 안 되는 걸 알아채면 프록시를 아는 버전으로 업데이트하거나, DNS 터널링이나 직접 연결 같은 다른 통로를 시도할 수 있습니다.
    - 같은 악성코드의 다른 변종이 다른 PC에서는 성공하고 있을 수 있습니다. 같은 도메인·같은 패턴을 회사 전체에서 찾아야 합니다.
    - 실패는 우리에게 주어진 **시간**입니다. 성공하기 전에 찾아서 제거할 기회입니다.

### 문제 2

Zeek `http.log`와 같은 요청의 응답 헤더입니다.

```
http.log:  method=GET  host=static-img-cdn.example  uri=/img/banner.png
           status_code=200  resp_mime_types=["application/x-dosexec"]
           response_body_len=1245184

Response header:  Content-Type: image/png
```

(a) 서버가 말한 내용물과 Zeek가 본 내용물은? 어느 쪽을 믿어야 하고 왜? (b) 내용물의 첫 두 바이트는 16진수로 무엇일 가능성이 높습니까? (c) 다음으로 할 일은?

??? success "정답과 해설"
    **(a)** 서버는 `image/png`(PNG 그림)라고 **주장**하고, Zeek는 내용물을 보고 `application/x-dosexec`(윈도우 실행 파일)라고 판단했습니다. **Zeek를 믿습니다.** Content-Type은 서버가 마음대로 쓰는 이름표이고, `resp_mime_types`는 실제 내용물의 매직 바이트로 판단한 값이기 때문입니다. 크기도 약 1.2MB로, 배너 그림치고는 크고 실행 파일로는 자연스럽습니다. 확장자(`.png`), 경로(`/img/`), Content-Type까지 셋 다 그림처럼 위장한 실행 파일입니다.

    **(b)** **`4D 5A`("MZ")** — 윈도우 실행 파일의 시작 표시.

    **(c)** 

    1. **파일 확보** — Zeek `files.log`의 해당 파일 기록(파일 추출 기능을 켰다면 추출본) 또는 패킷 캡처에서 내보내기
    2. **해시(SHA-256) 계산과 평판 조회**, 필요하면 격리된 샌드박스에서 분석
    3. **누가 받았나** — 요청한 PC와 User-Agent 확인. 정상 브라우저는 그림 주소로 받은 실행 파일을 실행하지 않으므로, 위장 파일을 일부러 받아 가는 **다운로더 프로그램**이 PC에 이미 있을 가능성이 큼 → Sysmon Event ID 3으로 연결한 프로세스 확인
    4. **실행됐나** — Sysmon Event ID 11(파일 생성)로 디스크에 써졌는지, Sysmon 1 / 4688(프로세스 생성)로 같은 해시가 실행됐는지
    5. 도메인 차단, 같은 URL·해시를 받은 다른 PC 찾기, 필요 시 PC 격리

### 문제 3

한 PC가 같은 외부 주소로 정확히 5분마다 요청합니다.

```
02:00  GET /status  →  404 Not Found   Content-Length: 0
02:05  GET /status  →  404 Not Found   Content-Length: 0
02:10  GET /status  →  404 Not Found   Content-Length: 0
02:15  GET /status  →  404 Not Found   Content-Length: 18736
02:20  GET /status  →  404 Not Found   Content-Length: 0
```

동료가 "계속 404니까 그 주소엔 아무것도 없어. 무시해도 돼"라고 합니다. 이 판단의 문제점과, 02:15 응답이 무엇을 의미할 수 있는지 설명해 보세요.

??? success "정답과 해설"
    **동료 판단의 문제점:**

    1. **응답 코드는 서버가 고르는 값**입니다. C2 서버는 스캐너·연구자에게 죽은 주소처럼 보이려고 일부러 404를 돌려줄 수 있습니다.
    2. "아무것도 없는 주소"에 PC가 **정확히 5분마다, 새벽에** 요청할 이유가 없습니다. 이 주기 자체가 비콘 신호입니다.
    3. 정상 웹 서버의 404는 보통 HTML 오류 페이지가 붙어 **일정한 크기의 본문**이 있습니다. 본문이 매번 **0바이트**인 404는 그 자체로 흔하지 않습니다.

    **02:15 응답의 의미:** 평소엔 0바이트("명령 없음")이다가 한 번만 **18,736바이트**가 내려왔습니다. 404로 위장한 채 **실제 명령이나 추가 악성코드가 전달된 순간**일 가능성이 높습니다. 크기가 다시 0으로 돌아간 것도 "명령 전달 → 평소 대기"의 전형입니다.

    **다음 행동:**

    1. 02:15 응답의 **실제 내용물** 확보(프록시 저장본, 패킷 캡처)
    2. 02:15 직후 그 PC의 호스트 활동 확인 — 새 프로세스(Sysmon 1 / 4688), 새 파일(Sysmon 11), 새 연결(Sysmon 3)
    3. 같은 주소에 연결하는 다른 PC 찾기, PC 격리 검토
    4. 교훈: **응답 코드보다 주기와 크기 패턴을 본다**
