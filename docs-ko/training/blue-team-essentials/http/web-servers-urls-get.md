---
title: "웹 서버, URL, GET 요청"
tags:
  - training
  - blue-team
  - http
  - concept
---

# 웹 서버, URL, GET 요청 { #web-servers-urls-get }

!!! abstract "이 페이지에서 다루는 것"
    HTTP가 무엇인지(주문과 배달), 웹 서버가 실제로 하는 일(파일 나눠 주기)과 그 구조 때문에 생기는 웹셸, 웹셸을 윈도우 로그(4688, Sysmon 1)로 잡는 법, URL을 조각별로 읽는 법과 피싱용 URL 속임수(`@`, `#`, `%`, `file://`), Zeek `http.log` 읽기, 그리고 GET 요청의 모양·로그 기록·공격 패턴(SQL 인젝션, 경로 조작, C2 비콘). 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 전체 흐름은 [HTTP 개요](index.md)에서 볼 수 있습니다.

## 한눈에 보는 핵심 10가지 { #key-points }

1. HTTP는 브라우저(손님)와 웹 서버(주방)가 글자로 주고받는 주문서다. 그래서 로그만 보고도 무슨 일이 있었는지 읽을 수 있다.
2. 웹 서버는 결국 파일 공유다. URL 경로가 서버 디스크 경로(문서 루트)에 그대로 붙는다.
3. `.php`, `.aspx`, `.jsp`는 서버가 "실행"하는 파일이다. 여기에 악성 파일 하나를 넣으면 웹셸이 된다.
4. 웹셸의 고전 신호: 웹 서버 프로세스(`w3wp.exe`, `java.exe` 등)가 `cmd.exe`·`powershell.exe`를 자식으로 띄운다 → 이벤트 4688 / Sysmon 1.
5. URL은 프로토콜 → 호스트 → 포트 → 폴더 → 파일 → 파라미터로 쪼개 읽는다. 도메인은 **오른쪽부터** 읽어 진짜 주인을 찾는다.
6. URL에 `@`가 있으면 `@` 뒤가 실제 접속 대상이다. `#` 뒤는 서버로 전송되지 않아 로그에 없다.
7. `%27`, `%2F` 같은 URL 인코딩은 풀어서 본다. 공격자는 인코딩으로 위험한 글자를 숨긴다.
8. GET은 보낼 정보를 전부 주소(URL)에 넣는다. 그래서 웹 서버·프록시·SIEM 로그와 브라우저 기록에 그대로 남는다. 비밀번호를 GET으로 보내면 안 된다.
9. GET 파라미터에서 공격이 보인다: 따옴표·`OR`(SQL 인젝션), `../`(경로 조작), Base64 덩어리 + 일정한 주기(C2 비콘).
10. IP 하나 뒤에 사이트 수천 개가 있을 수 있다(CDN). IP보다 도메인·URL로 판단하고 막는다.

## 준비 운동: HTTP는 "주문과 배달" { #basics }

식당을 떠올려 보면 쉽습니다. 손님이 "김치찌개 주세요"라고 주문하면 주방이 음식을 내줍니다. 웹도 같습니다.

| 식당 | 웹 | 정식 용어 |
| --- | --- | --- |
| 손님 | 브라우저(크롬, 엣지 등) | 클라이언트(Client) |
| 주방 | 웹 서버 | 서버(Server) |
| 주문 | "이 파일 주세요" | 요청(Request) |
| 음식 | 파일, 웹 페이지 | 응답(Response) |
| 주문 규칙 | 서로 알아듣게 정한 형식 | HTTP(HyperText Transfer Protocol) |

실제 요청은 정말로 이렇게 생긴 짧은 글입니다.

```
GET /menu.html HTTP/1.1
Host: www.restaurant.com
```

첫 줄은 "`/menu.html` 파일을 주세요(GET), HTTP 1.1 규칙으로 말할게요"라는 뜻이고, 둘째 줄은 "주문하는 가게는 `www.restaurant.com`입니다"라는 뜻입니다.

서버의 응답은 이렇게 옵니다.

```
HTTP/1.1 200 OK
Content-Type: text/html

<html> ... menu page ... </html>
```

`200 OK`는 "주문 잘 받았어요, 여기 있습니다", `Content-Type: text/html`은 "보내는 건 웹 페이지예요"라는 표시입니다. 빈 줄 아래가 실제 내용물입니다.

**SOC에서 왜 중요한가.** HTTP는 사람이 읽을 수 있는 글자로 된 대화라서 로그만으로 사건을 재구성할 수 있습니다. 회사 PC가 인터넷에서 하는 일은 대부분 이 주문과 배달이고, 악성코드의 파일 다운로드와 C2 통신도 같은 주문서 형식을 씁니다. 정상 주문서를 알아야 이상한 주문서가 보입니다.

## 웹 서버 = 파일을 나눠 주는 프로그램 { #web-servers }

한 문장으로 말하면 웹 서버는 <strong>"HTTP를 쓰는, 좀 멋진 파일 공유"</strong>입니다. 대표적인 웹 서버 프로그램은 Apache, NGINX, IIS(마이크로소프트)입니다.

### 문서 루트: URL 경로가 곧 디스크 경로

웹 서버에는 "이 폴더 안은 인터넷에 보여 줘도 된다"고 정한 폴더가 있습니다. 이를 **문서 루트**(Document Root)라고 합니다. 가게 진열대라고 생각하면 됩니다.

```
Browser asks for:   /main/index.htm
Linux server:       /var/www/html/main/index.htm
Windows IIS:        C:\inetpub\wwwroot\main\index.htm
```

- 1줄: 브라우저가 요청한 경로
- 2줄: 리눅스 웹 서버(Apache, NGINX)의 기본 문서 루트 `/var/www/html` 뒤에 그 경로를 붙인 실제 파일 위치
- 3줄: 윈도우 IIS의 기본 문서 루트 `C:\inetpub\wwwroot` 뒤에 붙인 위치

URL 경로가 서버 하드디스크 경로에 그대로 이어집니다. 이 원리는 아래 [경로 조작 공격](#get-attacks)에서 다시 씁니다.

### 그냥 주는 파일 vs 실행해서 주는 파일

| 종류 | 예 | 서버가 하는 일 | 비유 |
| --- | --- | --- | --- |
| 정적(Static) | `.html`, `.jpg`, `.css` | 있는 그대로 보내 줌 | 미리 만든 반찬 |
| 동적(Dynamic) | `.php`, `.aspx`, `.jsp` | **먼저 실행**한 뒤 결과만 보내 줌 | 레시피(즉석 요리) |

검색 결과 페이지처럼 미리 만들어 둘 수 없는 페이지는 사용자 입력을 받아 스크립트가 즉석에서 만듭니다.

### 웹셸: 해커가 몰래 넣은 레시피

서버는 "레시피 폴더 안의 파일은 무조건 실행한다"는 규칙으로 움직입니다. 해커가 업로드 기능의 허점 같은 걸 이용해 그 폴더에 **자기가 쓴 레시피 한 장**을 넣으면, 그 파일을 부를 때마다 서버가 해커의 지시를 실행합니다. 이 악성 파일이 **웹셸**(Web Shell)입니다.

```
GET /uploads/img.aspx?c=whoami HTTP/1.1
Host: intranet.corp.local
```

- "`/uploads/img.aspx`를 실행해 주세요. `c`라는 값으로 `whoami`를 넘길게요"라는 요청
- 서버가 `img.aspx`를 실행 → 악성 코드가 `c` 값 `whoami`(지금 어떤 계정인지 묻는 윈도우 명령)를 실행 → 결과가 웹 페이지로 해커에게 돌아감
- 해커는 브라우저 하나로 서버를 원격 조종하는 셈

### 웹셸을 윈도우 로그로 잡기: 프로세스의 부모와 자식

실행 중인 프로그램 하나하나를 **프로세스**(Process)라고 합니다. 프로그램이 다른 프로그램을 실행하면, 실행한 쪽이 **부모**(Parent), 실행된 쪽이 **자식**(Child)입니다. 바탕화면에서 메모장을 열면 부모는 `explorer.exe`, 자식은 `notepad.exe`입니다.

IIS에서 웹 요청을 처리하는 프로세스는 `w3wp.exe`입니다. 주방장이라고 생각하면 됩니다. 정상 주방장은 요리만 하지 금고(`cmd.exe`, `powershell.exe`)를 열 일이 거의 없습니다. 웹셸이 명령을 실행하면 `w3wp.exe`가 `cmd.exe`를 자식으로 낳습니다. **"주방장이 금고를 열었다"는 장면이 웹셸 탐지의 가장 고전적인 신호**입니다.

**이벤트 4688 — "새 프로세스가 생성됨(A new process has been created)".** 어떤 프로그램이든 실행될 때마다 보안 로그(Security Log)에 남고, 실행 계정·새 프로세스·부모 프로세스가 적힙니다.

- **기본값으로 꺼져 있습니다.** 감사 정책 "Audit Process Creation"을 켜야 기록되고, 명령 내용까지 남기려면 그룹 정책 "Include command line in process creation events"도 켜야 합니다.
- 공격자 관점에서 4688이 무서운 이유: 서버에서 무엇을 하든 결국 프로그램을 실행해야 하고, 그때마다 이 기록이 남습니다.

```
EventCode=4688
Account Name:          DefaultAppPool
New Process Name:      C:\Windows\System32\cmd.exe
Process Command Line:  cmd.exe /c whoami
Creator Process Name:  C:\Windows\System32\inetsrv\w3wp.exe
```

| 필드 | 의미 |
| --- | --- |
| `EventCode=4688` | 새 프로세스가 생겼다 |
| `Account Name: DefaultAppPool` | 실행 계정. IIS 웹사이트 전용 계정(사람 계정이 아님) |
| `New Process Name` | 새로 실행된 프로그램 = 명령 프롬프트 |
| `Process Command Line` | 실제 명령 `whoami` — URL의 `c=whoami`와 같음 |
| `Creator Process Name` | 부모 = IIS 주방장 `w3wp.exe` |

웹 서버 로그의 GET 한 줄과 이 4688 한 건이 같은 시각에 짝을 이루면 웹셸이 거의 확실합니다.

**[보충] Sysmon Event ID 1(Process Create).** 마이크로소프트의 무료 감시 도구 Sysmon을 설치하면 같은 정보가 더 자세히(파일 해시, 부모의 명령줄까지) 남습니다. 4688과 Sysmon 1을 함께 쓰는 SOC가 많습니다.

### 모듈(플러그인) 백도어: 직원으로 위장한 스파이

웹 서버에는 기능을 추가하는 부품을 끼울 수 있습니다(Apache의 `mod_*` 모듈, IIS 모듈). 식당으로 치면 주방 직원을 새로 채용하는 것과 같습니다.

**[보충]** 해커는 **악성 모듈을 서버 부품으로 등록**하기도 합니다. 손님인 척 레시피를 끼워 넣는 게 아니라 직원으로 위장해 취직하는 것입니다. IIS 모듈형 백도어는 실제 사례가 여러 번 보고됐습니다. 이 경우 웹 폴더에 수상한 `.aspx` 파일이 없어서 "웹 폴더에서 이상한 파일 찾기"만으로는 놓칩니다. IIS에서는 등록된 모듈 목록이 `applicationHost.config`에 있으니, 이를 평소 상태(기준선, Baseline)와 비교해 "처음 보는 직원"을 찾습니다.

## URL을 쪼개서 읽기 { #url }

분석가는 하루에도 수백 개의 URL을 봅니다. 우편 주소를 "나라 → 도시 → 거리 → 건물 → 호수"로 읽듯이 정해진 순서로 쪼개 읽으면 됩니다.

```
http://this.is.a.site.com:8000/mysite/index.html?key1=val&key2=val
```

```
http://              ← 1. Protocol (how to talk)
this.is.a.site.com   ← 2. Hostname (which computer)
:8000                ← 3. Port (which door)
/mysite/             ← 4. Folder
index.html           ← 5. File
?key1=val&key2=val   ← 6. Parameters (extra info)
```

### 1. 프로토콜 { #protocol }

"어떤 규칙으로 대화할지"입니다. `http`는 엽서(누구나 내용을 읽음), `https`는 봉투에 넣은 편지(암호화)입니다. ftp, ssh, file 같은 다른 프로토콜도 있습니다.

**[보충] `file://`의 위험.** 피싱 문서 안에 `file://203.0.113.5/share/doc.docx` 같은 링크가 있으면 윈도우는 그 컴퓨터의 공유 폴더(SMB)에 접속하려 합니다. 이때 윈도우는 자격을 증명하려고 **사용자의 로그인 증명 정보(NTLM 인증 정보)를 자동으로** 보낼 수 있습니다. 경비원이 묻지도 않았는데 사원증을 먼저 내미는 셈인데, 그 건물이 해커 건물인 것입니다. 해커는 받은 정보로 비밀번호를 풀어 보거나, 그 정보를 다른 서버에 그대로 내밀어 사용자인 척할 수 있습니다(환경과 보안 설정에 따라 막혀 있기도 합니다). `file://`이나 `\\IP주소\` 형태의 링크가 외부 IP를 가리키면 의심합니다.

### 2. 호스트 이름 — 오른쪽부터 읽기 { #hostname }

"어느 컴퓨터로 갈지"이며, DNS가 IP로 바꿔 줍니다.

- `site.com` = **부모 도메인**(Parent Domain, 등록 도메인). 돈 내고 등록한 **진짜 주인**
- `this.is.a` = **서브도메인**(Subdomain). 주인이 마음대로 붙이는 앞부분

```
microsoft.com.login-check.site.com
```

앞에 `microsoft.com`이 있어 마이크로소프트처럼 보이지만, 오른쪽 끝의 진짜 주인은 `site.com`입니다. 앞부분은 `site.com` 주인이 붙인 이름표일 뿐입니다. 피싱에서 정말 자주 쓰는 속임수입니다.

**[정정] "서브도메인은 IP 하나당 하나"가 아닙니다.** 아파트 한 동(IP 하나)에 수백 가구(사이트 수백 개)가 살 수 있습니다. 서버는 요청의 `Host:` 줄을 보고 어느 사이트 손님인지 구분합니다(가상 호스팅, [요청 헤더](post-methods-headers.md#host) 참고). 반대로 도메인 하나가 IP 여러 개를 가질 수도 있습니다.

### 3. 포트 { #port }

"그 컴퓨터의 몇 번 문으로 들어갈지"입니다. 생략하면 `http`는 80번, `https`는 443번입니다. 8000, 8080, 800 같은 번호도 정상 사이트에서 쓰이므로 포트만으로 나쁘다고 단정하지 않습니다. "평소 안 보이던 포트 + 처음 보는 도메인"처럼 다른 신호와 겹칠 때 의미가 커집니다.

### 4~5. 폴더와 파일 { #path }

`/mysite/index.html`은 [문서 루트](#web-servers) 안의 위치, 즉 서버 디스크의 폴더와 파일입니다.

### 6. 파라미터(쿼리 스트링) { #parameters }

서버에 덧붙여 보내는 정보입니다. `?`부터 시작하고, `이름=값`으로 쓰며, 여러 개면 `&`로 잇습니다.

```
https://www.google.com/search?q=weather+sydney&hl=en
```

- `q=weather+sydney` → 검색어 "weather sydney"(`+`는 띄어쓰기)
- `hl=en` → 화면 언어 영어

분석가는 파라미터를 보고 사용자가 무엇을 하고 있었는지 알아낼 수 있습니다.

### URL의 숨은 칸 두 개: `@`와 `#` { #userinfo-fragment }

**[보충]** URL의 완전한 모양(RFC 3986)은 이렇습니다.

```
scheme://userinfo@host:port/path?query#fragment
```

**`userinfo@`(사용자 정보) — 피싱 속임수.**

```
http://login.microsoftonline.com@198.51.100.7/common/login
```

규칙상 **`@` 앞은 전부 "사용자 이름"이고, 실제 접속 대상은 `@` 뒤의 `198.51.100.7`**입니다. 봉투에 "마이크로소프트 님께"라고 크게 써 놓고 받는 주소는 해커 집으로 적어 둔 것과 같습니다. 브라우저에 따라 경고를 띄우기도 하지만 메일·문서 속 링크에서는 여전히 쓰입니다. **URL에 `@`가 보이면 무조건 `@` 뒤를 봅니다.**

**`#fragment`(조각) — 서버로 전송되지 않음.** `#` 뒤는 브라우저 안에서만 쓰입니다. 책을 주문하며 "37쪽에 책갈피 꽂을 거예요"라는 메모는 서점에 보내지 않는 것과 같습니다. 사용자가 `https://site.com/page#token=abc`를 열어도 프록시·웹 서버 로그에는 `/page`까지만 남습니다. <strong>"로그에 없다" ≠ "요청에 없었다"</strong>입니다.

### `%`로 변장한 글자: URL 인코딩 { #url-encoding }

URL에 넣을 수 없는 글자는 `%` + 16진수 두 자리로 바꿔 씁니다(URL Encoding, Percent-encoding).

```
%20  →  (space)
%21  →  !
%27  →  '
%2F  →  /
%3D  →  =
```

공격자는 이를 **변장 도구**로 씁니다. `'`나 `/` 같은 위험한 글자를 찾는 단순 검사를 피하려고 일부러 `%27`, `%2F`로 바꿔 보냅니다. `%`가 잔뜩 붙은 URL은 풀어서 봅니다.

### 실제 로그: Zeek http.log { #zeek-http-log }

네트워크 감시 도구 Zeek는 HTTP 요청마다 `http.log`에 한 줄씩 기록합니다(JSON, 주요 필드만).

```json
{
  "ts": "2026-10-24T07:15:02.113Z",
  "uid": "CHhAvVGS1DHFjwGM9",
  "id.orig_h": "10.1.5.23",
  "id.resp_h": "203.0.113.80",
  "id.resp_p": 8000,
  "method": "GET",
  "host": "this.is.a.site.com:8000",
  "uri": "/mysite/index.html?key1=val&key2=val",
  "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...",
  "status_code": 200,
  "resp_mime_types": ["text/html"]
}
```

| 필드 | 의미 |
| --- | --- |
| `ts` | 요청 시각. 끝의 `Z` = UTC. 시드니 서머타임이면 +11시간 |
| `uid` | 연결의 사건 번호표. `conn.log`·`files.log`와 같은 번호로 엮임 |
| `id.orig_h` | 요청을 보낸 쪽(우리 PC) |
| `id.resp_h` / `id.resp_p` | 응답한 서버의 IP / 포트(문 번호) |
| `method` | 요청 방식(GET) |
| `host` | Host 헤더 값. 기본 포트가 아니라서 `:8000`까지 붙음 |
| `uri` | 폴더·파일·파라미터 |
| `user_agent` | 요청한 프로그램의 자기소개 |
| `status_code` | 응답 코드(200 = 성공) |
| `resp_mime_types` | Zeek가 응답 내용을 직접 보고 판단한 파일 종류 |

Zeek는 URL을 **`host`와 `uri`로 나눠** 저장합니다. 전체 주소는 `http://` + `host` + `uri`로 직접 이어 붙여야 합니다. 필드 전체 설명은 [Zeek http.log](../../../network/zeek/http-log.md)에 있습니다.

## GET 요청 = "이거 주세요" { #get }

요청 방식(Method)을 밴드로 치면 GET이 메인 보컬입니다. 웹 페이지 하나를 열면 HTML, 사진, CSS, JavaScript를 각각 따로 GET으로 받아 오므로 사이트 하나에 GET 수십~수백 개가 정상입니다.

### 실제 모양 { #get-request }

```
GET /search?q=weather+sydney&hl=en HTTP/1.1
Host: www.google.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/141.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

```

1. `GET /search?q=weather+sydney&hl=en HTTP/1.1` — **요청 줄**(Request Line). 방식(`GET`) / 대상(검색 페이지 + 파라미터) / 규칙 버전(`HTTP/1.1`)
2. `Host` — 어느 사이트(아파트의 어느 가구)에 요청하는지
3. `User-Agent` — "윈도우 10의 크롬이에요"라는 자기소개
4. `Accept` — "웹 페이지 형식으로 주세요"
5. `Accept-Encoding` — "gzip, deflate, br로 압축해도 풀 수 있어요"
6. `Connection: keep-alive` — "이 연결을 끊지 말고 다음 파일도 이걸로 받을게요"
7. 빈 줄 — "주문 끝"

2~6번처럼 `이름: 값`으로 된 줄이 **헤더**(Header)입니다([요청 헤더](post-methods-headers.md#headers)에서 자세히). 핵심은 **GET은 보낼 정보를 전부 첫 줄의 주소에 넣고, 본문(Body)은 보통 비어 있다**는 점입니다.

```
HTTP/1.1 200 OK
Server: nginx
Content-Type: text/html; charset=UTF-8
Content-Length: 18342

<!DOCTYPE html><html> ... (search results page) ...
```

`200 OK` = 성공, `Server: nginx` = 서버 프로그램의 자기소개, `Content-Type` = 내용물 종류, `Content-Length: 18342` = 내용물 크기(바이트). 응답 코드는 [HTTP 상태 코드](../../../basics/http-status-codes.md)에 정리돼 있습니다.

### 비밀번호를 GET으로 보내면 안 되는 이유 { #get-logging }

주소에 들어간 정보는 **로그에 그대로 적힙니다.** 웹 서버와 프록시는 보통 방문한 전체 URL을 기록합니다. 회사 앱이 실수로 로그인을 GET으로 만들었다면 Apache 접근 로그(Combined 형식)에 이런 줄이 남습니다.

```
10.1.5.23 - - [24/Oct/2026:18:15:02 +1100] "GET /login.php?user=jsmith&pass=Winter2026! HTTP/1.1" 302 215 "https://app.corp.local/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..."
```

| 칸 | 값 | 의미 |
| --- | --- | --- |
| 1 | `10.1.5.23` | 접속한 PC의 IP |
| 2 | `-` | ident(옛 기능 자리, 요즘 늘 빈칸) |
| 3 | `-` | HTTP 자체 로그인 사용자 이름(없음) |
| 4 | `[24/Oct/2026:18:15:02 +1100]` | 접속 시각(`+1100` = 시드니 서머타임) |
| 5 | `"GET /login.php?user=jsmith&pass=Winter2026! HTTP/1.1"` | 요청 줄 전체 — **비밀번호가 평문으로 보임** |
| 6 | `302` | 응답 코드("다른 페이지로 가세요") |
| 7 | `215` | 응답 크기(바이트) |
| 8 | `"https://app.corp.local/"` | Referer(직전 페이지) |
| 9 | `"Mozilla/5.0 ..."` | User-Agent |

이 한 줄은 웹 서버, 프록시, SIEM에 모두 복사됩니다.

**[보충] 유출 경로가 두 개 더 있습니다.**

- **브라우저 방문 기록** — 주소가 그대로 저장됨
- **Referer** — 새 요청에 붙는 "방금 이 페이지에서 왔어요" 소개장. 비밀번호가 든 페이지에서 외부 이미지나 링크를 불러오면 그 주소가 외부로 갈 수 있음. 요즘 브라우저는 기본적으로 외부 사이트에는 도메인까지만 잘라 보내지만, 사이트 설정에 따라 전체 주소가 갈 수도 있음

그래서 로그인, 파일 업로드, 큰 데이터는 정보를 본문에 담는 [POST](post-methods-headers.md#post)로 보냅니다.

### GET에서 공격 찾기 { #get-attacks }

공격자가 GET으로 보낸 것도 로그에 다 남습니다.

**공격 1: SQL 인젝션(SQL Injection).** 서버는 파라미터 값을 데이터베이스 질문 안에 끼워 넣습니다(`id=1` → "1번 상품을 보여 줘"). 공격자는 빈칸에 **질문 자체를 바꾸는 글자**를 넣습니다.

```
GET /product.php?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1
```

풀면 `id=1' OR '1'='1` → "1번 상품, **또는 1이 1과 같은 것**을 보여 줘". 1=1은 항상 참이라 모든 데이터가 나옵니다. **숫자 자리에 따옴표, `OR`, `UNION`, `--`가 보이면 의심**합니다.

**공격 2: 경로 조작(Path Traversal).**

```
GET /download?file=..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1
```

풀면 `../../../etc/passwd`. `../`는 "한 칸 위 폴더로"입니다. [URL 경로 = 디스크 경로](#web-servers) 원리를 거꾸로 이용해 진열대 밖으로 세 칸 올라가 리눅스 계정 목록 파일을 꺼내려는 시도입니다. 윈도우 서버라면 `..\..\windows\win.ini` 같은 모양입니다.

**공격 3: GET으로 위장한 C2 비콘(Beacon).** C2(Command and Control)는 감염 PC를 원격 조종하는 해커의 지휘 서버, 비콘은 감염 PC가 정기적으로 보내는 "나 살아 있어요, 시킬 일 있어요?" 연락입니다.

```
GET /images/logo.gif?id=YWRtaW4tUEMx HTTP/1.1
Host: cdn-static-assets.example.net
```

겉보기엔 이미지 요청이지만 `id` 값은 **Base64**로 포장된 글자입니다. Base64는 아무 데이터나 영문자·숫자·`+`·`/`·`=`로 바꿔 쓰는 방법으로, 선물 포장지일 뿐 **암호가 아닙니다.** 풀면 `admin-PC1`, 즉 감염 PC의 이름입니다. 결정적 단서는 **반복 패턴**입니다. 같은 PC가 같은 주소로 정확히 60초마다 밤낮없이 보낸다면 사람이 아니라 프로그램입니다. 자세한 분석법은 [Beaconing & C2 탐지](../../../network/beaconing-c2.md)를 봅니다.

### "GET은 작은 데이터만"의 진짜 의미 { #get-size }

웹 서버는 주소 길이를 제한합니다(Apache·NGINX 기본 설정 기준 요청 줄 약 8KB 안팎). 하지만 **"GET으로는 많이 못 빼낸다"가 아닙니다.** 공격자는 데이터를 잘게 쪼개 수천 번의 GET에 나눠 보내거나 쿠키 헤더에 숨깁니다. 쌀 한 가마니를 숟가락으로 만 번 옮기는 식입니다. 요청 하나의 크기보다 **같은 목적지로 가는 요청의 개수와 주기**를 봅니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 그대로 유효한 것"
    웹 서버 구조, URL 해부, GET의 모양, "주소에 넣은 정보는 로그에 남는다"는 원칙은 지금도 그대로입니다. HTTP/2·HTTP/3에서도 GET과 경로의 의미는 같고 전송 형식만 이진(바이너리)으로 바뀌었습니다. 웹셸은 여전히 웹 서버 침해 후 가장 흔한 흔적이고, "웹 서버 프로세스 → 셸" 부모-자식 탐지도 여전히 기본기입니다.

!!! info "[변경됨] 바뀐 것"
    - **거의 모든 웹이 https.** 네트워크 중간에서는 경로·파라미터·헤더가 암호화되어 안 보이고, 대체로 **SNI**(암호화 대화를 시작할 때 밝히는 사이트 이름, 봉투 겉면의 받는 사람 이름) 정도만 보입니다. 경로와 파라미터는 TLS 검사 프록시, 웹 서버 자체 로그, WAF, EDR에서 얻습니다. ECH(Encrypted Client Hello)가 퍼지면서 SNI까지 가려지기 시작했습니다.
    - **웹 서버 순위.** 2026년 10월 W3Techs 기준 Cloudflare 32.5%, NGINX 30.3%, Apache 21.4%, LiteSpeed 14.0%, IIS 2.9%. 1위 Cloudflare는 **CDN**(전국 배달 대행 체인)이라, 응답의 `Server: cloudflare`는 대행 지점의 대답이고 진짜 서버(오리진)는 보이지 않습니다.
    - **IIS는 회사 내부에서 여전히 핵심 표적.** Exchange, SharePoint가 IIS 위에서 돌아갑니다. 2025년 7월 "ToolShell"(CVE-2025-53770) 공격에서 공격자들은 온프레미스 SharePoint에 `spinstall0.aspx` 웹셸을 심어 **MachineKey**(서버가 "내가 만든 진짜 데이터"를 확인할 때 쓰는 인감도장)를 훔쳤습니다. 도장을 훔치면 패치 후에도 위조 데이터로 다시 들어올 수 있어, 패치와 함께 MachineKey 교체가 필요했습니다.
    - **"웹 서버 = 파일 공유" 비유의 한계.** 요즘은 API·SPA 구조라 `/api/v2/users/1234/orders` 같은 경로는 실제 파일이 아니라 프로그램이 정한 **길 안내 규칙**(Route)입니다. 정상 경로도 길고 복잡해서 기준선 없이 눈으로 판단하기 어려워졌습니다.
    - **"GET에 민감 정보 금지"가 표준이 됨.** OAuth(“구글로 로그인” 같은 기능)의 옛 암묵적 승인(Implicit Grant) 방식은 출입증(토큰)을 URL `#` 뒤에 실었습니다. 2025년 1월 RFC 9700(OAuth 2.0 보안 모범 사례)은 이 방식을 쓰지 말라고 권고합니다.

!!! warning "[주의] 지금 그대로 하면 틀리거나 위험한 것"
    - **IP 하나 = 사이트 하나로 생각하면 사고가 납니다.** CDN IP 하나 뒤에 사이트 수천 개가 있습니다. "이 IP가 악성"이라고 IP를 막으면 정상 사이트도 같이 막힙니다. 도메인·URL 기준으로 판단하고 차단합니다.
    - **"GET은 작아서 유출에 못 쓴다"고 생각하면 안 됩니다.** 쪼개서 반복 전송합니다. 개수와 주기를 봅니다.
    - **SIEM이 비밀번호 창고가 될 수 있습니다.** 앱 하나라도 GET으로 비밀번호·토큰을 보내면 SIEM에 쌓입니다. SIEM 접근 권한 점검, 수집 단계 마스킹(Masking), 앱 개발팀 통보가 필요합니다.

## 확인 문제 { #quiz }

먼저 직접 답해 본 뒤 해설을 펼쳐 보세요.

### 문제 1

피싱 메일에서 이 링크가 발견되었습니다.

```
http://portal.office.com@198.51.100.7:8080/login?next=%2Fmail%2Finbox#step2
```

(a) 실제로 어느 컴퓨터의 몇 번 포트로 접속합니까? (b) 서버로 전송되지 않아 프록시 로그에 안 남는 부분은 어디입니까? (c) `next` 값을 풀면 무엇입니까?

??? success "정답과 해설"
    **(a)** `198.51.100.7`의 **8080번 포트**. `@` 앞의 `portal.office.com`은 "사용자 이름" 칸에 들어간 글자일 뿐입니다.

    **(b)** `#step2`. `#` 뒤 조각은 브라우저 안에서만 쓰입니다.

    **(c)** `%2F` = `/` 이므로 `/mail/inbox`.

    이 링크는 피싱 수법 세 가지를 함께 씁니다. ① `@` 앞에 유명 도메인을 둬서 눈을 속임 ② `next=/mail/inbox`로 "로그인하면 받은편지함으로 보내 드릴게요"라는 진짜 같은 분위기 연출 ③ `https`가 아닌 `http` — 진짜 마이크로소프트 로그인은 암호화 없는 `http`나 IP + 8080 포트를 절대 쓰지 않으며, `http`라서 입력한 비밀번호가 네트워크에 엽서처럼 실려 갑니다.

### 문제 2

회사 IIS 웹 서버 로그에 이 줄이 있습니다. 무슨 일일 가능성이 크고, 같은 시각 윈도우 보안 로그에서 **몇 번 이벤트**의 **어떤 부모-자식 관계**를 확인해야 할까요?

```
2026-10-24 07:42:11 10.20.1.15 GET /uploads/avatar.aspx c=ipconfig+/all 443 - 185.220.101.4 Mozilla/5.0 200 0 0 312
```

(힌트: IIS 로그 순서 = 날짜, 시각, 서버 IP, 방식, 경로, 파라미터, 포트, 사용자 이름, 접속자 IP, User-Agent, 응답 코드, 세부 코드 두 개, 처리 시간)

??? success "정답과 해설"
    **웹셸일 가능성이 큽니다.** 근거 네 가지:

    1. `uploads`(그림이 있어야 할 폴더)에 실행 파일 `.aspx`가 있음
    2. 파라미터가 `ipconfig /all`(`+` = 띄어쓰기) — 서버 네트워크 설정을 모두 보여 주는 명령으로, 침입 직후 정찰에 자주 씀
    3. 응답 `200` — 서버가 정상 처리, 명령이 실제로 실행됐을 가능성
    4. 요청이 회사 밖 IP에서 옴 — 평판 조회 필요

    **확인할 것: 이벤트 4688**. 부모(`Creator Process Name`) = **`w3wp.exe`**, 자식(`New Process Name`) = **`cmd.exe`** 또는 **`ipconfig.exe`**, 명령줄 = `ipconfig /all`.

    **시간 함정:** IIS 로그는 기본값이 **UTC**이고, 이벤트 뷰어는 **서버 현지 시각**으로 보여 줍니다. 시드니 서버라면 IIS의 `07:42:11`은 이벤트 뷰어에서 **18:42:11** 근처입니다. 07:42를 찾으면 "흔적이 없네"라고 잘못 결론 내리기 쉽습니다.

    **다음 행동:** `avatar.aspx` 생성 시각 확인 → 그 앞뒤로 같은 IP가 이 파일을 업로드한 요청(보통 POST) 찾기 → 같은 IP의 다른 명령 전부 추출 → 서버 격리 여부 결정. 대응 흐름은 [Web shell / server 플레이북](../../../playbooks/webshell-server.md)을 봅니다.

### 문제 3

위협 정보로 "IP `104.21.48.10`이 피싱 사이트를 호스팅 중"이라는 알림이 왔고, 조회해 보니 Cloudflare IP입니다. 방화벽에서 바로 차단하는 것이 좋은 대응일까요?

??? success "정답과 해설"
    **좋은 대응이 아닙니다.** Cloudflare IP 하나 뒤에 사이트 수천 개가 있을 수 있어, 아파트 한 동 전체의 출입을 막는 셈입니다. 멀쩡한 업무 사이트가 끊길 수 있고, 피싱 사이트 주인은 다른 IP로 쉽게 옮겨 가서 효과도 오래가지 않습니다.

    **더 나은 대응:**

    1. 위협 정보에서 **피싱 도메인·URL**을 확인해 그것을 기준으로 차단(프록시 URL/도메인 차단, DNS 차단·RPZ)
    2. 프록시·DNS 로그에서 **이미 접속한 직원**을 찾아 피해 범위 확인
    3. 필요하면 Cloudflare 신고(Abuse) 창구에 신고
