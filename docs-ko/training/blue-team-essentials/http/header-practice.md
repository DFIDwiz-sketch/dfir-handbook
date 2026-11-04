---
title: "헤더 판독 실전 연습 — 요청 하나, 응답 하나"
tags:
  - training
  - blue-team
  - http
  - practice
---

# 헤더 판독 실전 연습 — 요청 하나, 응답 하나 { #header-practice }

!!! abstract "이 페이지에서 다루는 것"
    지금까지 배운 요청 헤더와 응답 헤더 지식으로 실제 모양의 요청 하나와 응답 하나를 처음부터 끝까지 판독합니다. 요청에서는 사이트·포트·파일, 어디서 왔는지, 무엇을 보고 있었는지, 브라우저와 OS, 사용자의 언어를 읽고, 응답에서는 성공 여부, 파일 종류, 서버 소프트웨어, 크기, 시각, 그리고 "HTML이라는데 왜 깨진 글자로 보이나?"를 풉니다. gzip 압축을 직접 푸는 법도 다룹니다. 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 헤더 각각의 뜻은 [POST, 그 밖의 메서드, 요청 헤더](post-methods-headers.md#headers)와 [응답 헤더와 응답 코드](responses.md)에 있습니다. 예시의 도메인은 모두 만들어 낸 것입니다.

## 한눈에 보는 핵심 8가지 { #key-points }

1. 판독은 질문 목록으로 한다: 어디로(Host·포트·경로) → 어디서(Referer) → 무엇을(Referer·경로의 내용) → 무엇으로(User-Agent) → 누가(Accept-Language).
2. 기본 포트가 아니면 Host에 포트가 붙는다(`:85`). 비표준 포트 + 무작위 경로 + 낯선 도메인은 겹친 신호다.
3. Referer가 평범한 사이트(포럼 등)인데 다음 목적지가 수상하다면, **그 평범한 사이트가 해킹당해 리디렉션을 심었을** 가능성을 먼저 본다.
4. `Trident/4.0`은 IE8, `Trident/7.0`은 IE11(그리고 Edge의 IE 모드)이다.
5. Accept-Language는 사용자가 쓰는 언어의 힌트일 뿐 국적·위치의 증거가 아니다.
6. 응답에 `Content-Encoding: gzip`이 있으면 본문은 압축된 상태다. 깨진 글자처럼 보이는 게 정상이고, 풀어야 원래 파일이 나온다.
7. gzip 데이터는 `1F 8B`로 시작한다. 이 매직 바이트가 보이면 압축부터 푼다.
8. 아주 오래된 서버 버전(예: 10년도 더 된 nginx)은 관리가 안 되는 서버라는 신호다. 해킹당했거나 공격자 인프라일 가능성을 염두에 둔다.

## 연습 1: 요청 헤더 판독 { #request-practice }

다음은 한 직원 PC가 보낸 요청입니다.

```
GET /Kq3vZ8pLwX1mR7tNc0YbA5eHs2Uj9DfGq HTTP/1.1
Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, */*
Referer: http://www.fitness-forum-training.example/showthread.php?95-Lumbar-Flexion-when-squatting
Accept-Language: en-US
User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)
Accept-Encoding: gzip, deflate
Host: quietmeadow-ledger.example:85
Connection: Keep-Alive
```

다음 다섯 가지에 답해 보세요.

1. 사용자가 접속하는 사이트, 포트, 파일은?
2. 어떤 사이트가 사용자를 이 새 사이트로 보냈나?
3. 사용자는 어떤 내용을 보고 있었나?
4. 클라이언트의 브라우저와 OS는?
5. 사용자는 어떤 언어를 쓸 가능성이 높은가?

??? success "정답과 해설"
    **1. 사이트·포트·파일.** Host를 보면 `quietmeadow-ledger.example`의 **85번 포트**입니다. HTTP 기본 포트(80)가 아니라서 Host 값에 `:85`가 붙어 있습니다. 파일은 요청 줄 `GET` 뒤의 긴 무작위 문자열 `/Kq3vZ8pLwX1mR7tNc0YbA5eHs2Uj9DfGq`입니다. 전체 URL은 Host와 경로를 이어 붙여 `http://quietmeadow-ledger.example:85/Kq3vZ8pLwX1mR7tNc0YbA5eHs2Uj9DfGq`가 됩니다. 비표준 포트, 무작위 경로, 낯선 도메인 세 가지가 겹쳤습니다.

    **2. 보낸 사이트.** Referer에 따르면 사용자는 직전에 `www.fitness-forum-training.example`에 있었습니다.

    **3. 보고 있던 내용.** Referer 경로 `showthread.php?95-Lumbar-Flexion-when-squatting`은 "스쿼트할 때 허리가 굽는 문제"에 관한 **운동 포럼 글**입니다. 평범한 운동 포럼 글에서 무작위 이름의 사이트, 그것도 비표준 포트로 넘어갔다는 게 어색합니다. 해석은 두 가지입니다.

    - **포럼이 해킹당해** 자동 리디렉션(숨은 iframe, 삽입된 스크립트)이 심어졌다 → 사용자는 아무것도 누르지 않았는데 끌려감. 익스플로잇 킷 시절의 전형적인 첫 단계
    - 사용자가 포럼 글 속 **링크를 직접 눌렀다** → 누군가 악성 링크를 글이나 댓글에 올려 둠

    어느 쪽이든 포럼 자체를 의심해야 합니다.

    **4. 브라우저와 OS.** `MSIE 8.0`과 `Trident/4.0`은 **인터넷 익스플로러 8**, `Windows NT 6.1`은 **윈도우 7**입니다. 이 시절 브라우저는 플러그인 취약점이 많아 드라이브 바이 다운로드의 주된 표적이었습니다. 덧붙여 `Accept`의 `application/x-ms-application`, `application/xaml+xml`도 당시 IE가 흔히 보내던 값이라 User-Agent와 맞아떨어집니다. 이 요청은 위장이 아니라 **피해자의 진짜 브라우저**가 보낸 것으로 보입니다.

    **5. 언어.** `Accept-Language: en-US` → 영어(미국) 사용자일 가능성이 높습니다. 다만 이건 브라우저 언어 설정일 뿐, 국적이나 위치의 증거는 아닙니다.

    **종합 판단:** "평범한 포럼 → 무작위 도메인·비표준 포트·무작위 경로"는 해킹된 사이트를 통한 악성 리디렉션의 모양입니다. 다음으로 이 요청의 **응답**(무엇을 받았나), 그다음 요청들(추가 다운로드가 있었나), 같은 포럼을 방문한 다른 직원을 확인합니다.

### [보충] 2026년에 IE 계열 User-Agent를 보면 { #ie-mode }

IE8·윈도우 7 조합은 2026년 회사 PC에서는 나올 수 없습니다. 그런데 `Trident`라는 글자 자체는 지금도 볼 수 있습니다. 마이크로소프트 엣지에는 옛 사내 시스템을 위한 **IE 모드**(Internet Explorer mode)가 있어서, 그 모드로 열린 페이지는 IE11 모양의 User-Agent를 보냅니다.

```
Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; rv:11.0) like Gecko
```

`Trident/7.0`과 `rv:11.0`이 IE11 표시입니다. 그래서 `Trident`를 보면 무조건 수상한 게 아니라, **목적지가 IE 모드로 열도록 등록된 사내 옛 시스템인가, 아니면 외부 사이트인가**를 먼저 확인합니다. 외부의 낯선 사이트로 IE 모드 User-Agent가 나간다면 흉내 낸 값이거나 정책 밖의 사용입니다.

## 연습 2: 응답 헤더 판독 { #response-practice }

다음은 어느 서버가 돌려준 응답입니다.

```
HTTP/1.1 200 OK
Server: nginx/0.7.67
Date: Tue, 29 Oct 2013 04:05:56 GMT
Content-Type: text/html
Content-Length: 2182
Connection: keep-alive
Content-Encoding: gzip

<binary-looking bytes: 1f 8b 08 00 00 00 00 00 00 03 ...>
```

다음 여섯 가지에 답해 보세요.

1. 페이지가 성공적으로 돌아왔나?
2. 어떤 종류의 파일이 돌아왔나?
3. 서버는 어떤 소프트웨어를 쓰나?
4. 파일 크기는?
5. 이 응답은 언제 보내졌나?
6. HTML이라는데 왜 내용이 HTML처럼 안 보이나?

??? success "정답과 해설"
    **1. 성공.** 첫 줄 `200 OK`.

    **2. 파일 종류.** `Content-Type: text/html` → 서버는 HTML 웹 페이지라고 **주장**합니다.

    **3. 서버 소프트웨어.** `Server: nginx/0.7.67` → nginx **0.7.67** 버전. 2010년 무렵의 아주 오래된 버전으로, 두 가지를 시사합니다.

    - 버전을 숨기지 않았고, 10년 넘게 업데이트하지 않은 **관리되지 않는 서버**일 가능성 → 이미 해킹당해 악성 콘텐츠를 내보내고 있을 수 있음
    - 공격자가 오래된 이미지나 도구로 급하게 띄운 인프라일 수도 있음

    **4. 크기.** `Content-Length: 2182` → 2,182바이트. 단, 이건 **압축된 상태의 크기**입니다. 풀면 더 커집니다.

    **5. 보낸 시각.** `Date: Tue, 29 Oct 2013 04:05:56 GMT` → 2013년 10월 29일(화) 04:05:56 UTC(시드니 서머타임으로 15:05:56). 오래된 패킷 캡처에서 나온 응답이라면 그럴 만한 날짜입니다. 지금 수집한 트래픽인데 서버 날짜가 몇 년씩 틀리다면, 서버 시계가 망가진 방치된 서버이거나 일부러 꾸민 값일 수 있습니다.

    **6. 왜 HTML처럼 안 보이나 — `Content-Encoding: gzip`.** 서버가 HTML을 **gzip으로 압축해서** 보냈기 때문입니다. Content-Type은 "압축을 풀면 나오는 원래 내용"을 말하고, Content-Encoding은 "지금 어떻게 포장돼 있는지"를 말합니다. 그래서 패킷 그대로 보면 깨진 바이너리처럼 보이는 게 정상입니다. 본문 첫 바이트 `1f 8b`가 바로 **gzip의 매직 바이트**입니다. 파일을 꺼내 분석하려면 반드시 압축을 먼저 풀어야 합니다(아래 [gzip 풀기](#gunzip)).

### [보충] Content-Type과 Content-Encoding의 차이 { #type-vs-encoding }

택배로 비유하면 이렇습니다.

| 헤더 | 비유 | 예 |
| --- | --- | --- |
| `Content-Type` | 상자 안 **물건**이 무엇인가 | `text/html` = 웹 페이지 |
| `Content-Encoding` | 물건을 어떻게 **포장**했나 | `gzip` = 진공 압축 포장 |

요청의 `Accept-Encoding: gzip, deflate`는 "압축 포장해도 풀 줄 알아요"라는 손님의 말이고, 응답의 `Content-Encoding: gzip`은 "그래서 압축 포장해서 보냈어요"라는 주방의 답입니다. 최근에는 gzip보다 압축률이 좋은 `br`(Brotli)과 `zstd`(Zstandard)도 흔합니다.

### [보충] gzip 직접 풀기 { #gunzip }

대부분의 분석 도구(Wireshark의 "Export Objects → HTTP", Zeek 등)는 gzip을 자동으로 풀어 줍니다. 하지만 패킷에서 바이트를 직접 잘라 냈다면 손으로 풀어야 합니다.

먼저 첫 바이트로 gzip인지 확인합니다.

```
$ od -An -tx1 -N16 body.bin
 1f 8b 08 00 00 00 00 00 00 03 b3 c9 28 c9 cd b1
```

- `od` — 파일을 바이트 단위로 보여 주는 리눅스 명령
- `-An` — 왼쪽의 위치 번호를 빼고 출력
- `-tx1` — 1바이트씩 16진수로 출력
- `-N16` — 앞 16바이트만 출력
- 결과의 `1f 8b`가 gzip 매직 바이트, 이어지는 `08`은 압축 방식(deflate)

그다음 풉니다.

```
$ python3 -c "import gzip; print(gzip.decompress(open('body.bin','rb').read()).decode())"
<html><body>hello analyst</body></html>
```

- `python3 -c "..."` — 따옴표 안의 파이썬 코드를 한 줄로 실행
- `open('body.bin','rb').read()` — 파일을 바이너리 그대로 읽음
- `gzip.decompress(...)` — gzip 압축을 풂
- `.decode()` — 바이트를 글자로 바꿔 화면에 출력
- 결과: 원래의 HTML이 나옴

리눅스라면 `gunzip -c body.bin`, 웹 도구로는 CyberChef의 "Gunzip"으로도 됩니다. **의심 파일은 격리된 분석 환경에서만** 다룹니다.

## 2026년 관점 { #trends }

!!! success "[2026 현재] 그대로 유효한 것"
    질문 목록으로 요청과 응답을 차례로 판독하는 방법, Referer로 "어디서 왔나"를 되짚는 방법, Content-Encoding을 먼저 확인하고 압축을 풀어야 한다는 원칙은 그대로입니다.

!!! info "[변경됨] 바뀐 것"
    - **압축 방식이 늘었습니다.** gzip·deflate 외에 Brotli(`br`)가 웹에서 아주 흔하고, Zstandard(`zstd`)도 주요 브라우저와 CDN에서 쓰이기 시작했습니다. 도구가 이 방식을 못 풀면 내용이 깨져 보이니, Content-Encoding 값을 먼저 확인합니다.
    - **HTTP/2·3에서는 헤더 자체도 압축됩니다**(HPACK·QPACK). 이건 본문 압축(Content-Encoding)과는 별개라, 헤더를 읽으려면 해당 버전을 해석할 줄 아는 도구가 필요합니다.
    - **IE 계열 User-Agent는 거의 사라졌지만** 엣지 IE 모드의 `Trident/7.0`은 사내 옛 시스템 접속에서 아직 보입니다.

!!! warning "[주의] 지금 그대로 하면 틀리거나 위험한 것"
    - **Content-Length는 압축된 크기입니다.** 풀었을 때 크기나 파일 해시는 압축 상태와 다릅니다. 위협 정보의 해시와 비교할 때는 **푼 뒤의 파일**로 해시를 계산합니다.
    - **Accept-Language로 공격자 국적을 단정하지 않습니다.** 브라우저 설정일 뿐이며 공격 도구는 아무 값이나 쓸 수 있습니다.
    - **포럼처럼 평범한 Referer를 안전하다고 넘기지 않습니다.** 해킹된 정상 사이트가 악성 리디렉션의 출발점인 경우가 많습니다.

## 확인 문제 { #quiz }

### 문제 1

회사 PC에서 이 User-Agent가 보입니다. 무조건 악성으로 봐야 할까요? 무엇을 확인해야 할까요?

```
Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; .NET4.0C; .NET4.0E; rv:11.0) like Gecko
```

??? success "정답과 해설"
    **무조건 악성은 아닙니다.** `Trident/7.0`과 `rv:11.0`은 IE11 모양인데, 2026년에는 주로 **엣지의 IE 모드**가 보내는 값입니다. 많은 조직이 옛 사내 시스템(오래된 인사·결재 시스템 등)을 IE 모드로 열도록 정책에 등록해 둡니다.

    확인할 것:

    1. **목적지** — IE 모드로 열도록 등록된 **사내 시스템**인가, 외부 사이트인가
    2. 외부의 낯선 사이트라면 → 정책 밖 사용이거나 **흉내 낸 User-Agent**(악성코드나 도구)일 가능성
    3. 연결을 만든 프로세스(Sysmon Event ID 3) — `msedge.exe`인지, 다른 프로그램인지

### 문제 2

응답 헤더에는 `Content-Type: text/html`만 있고 **`Content-Encoding` 헤더가 없습니다.** 그런데 본문 첫 바이트가 `1F 8B`입니다. 무엇이 이상하고, 어떻게 해야 할까요?

??? success "정답과 해설"
    `1F 8B`는 **gzip의 매직 바이트**입니다. 정상이라면 서버가 `Content-Encoding: gzip`을 붙여 "압축했다"고 알려야 브라우저가 풀어서 HTML로 보여 줍니다. 그 표시가 없으니 브라우저 입장에서는 "깨진 HTML"이 됩니다. 즉 이 응답은 **사람이 브라우저로 볼 페이지가 아닐** 가능성이 큽니다.

    가능성은 두 가지입니다.

    - 서버 설정 실수(드물지만 있음)
    - **악성 프로그램이 스스로 풀어 쓰도록 압축 데이터를 HTML로 위장**해 보낸 것 → 다운로더가 받아 가는 추가 악성코드나 설정 파일

    할 일: 본문을 꺼내 **압축을 풀고**, 푼 결과의 매직 바이트(예: `MZ`)를 다시 확인 → 해시 계산과 평판 조회 → 이 요청을 보낸 PC의 프로세스(Sysmon Event ID 3)와 User-Agent 확인. "선언된 종류와 실제 내용이 다르다"는 [응답 헤더의 원칙](responses.md#content-type)과 같은 신호입니다.

### 문제 3

연습 1처럼 평범한 운동 포럼(Referer)에서 무작위 도메인으로 넘어간 요청이 여러 직원 PC에서 보입니다. 포럼 쪽에 대해 무엇을 해야 할까요?

??? success "정답과 해설"
    여러 직원이 같은 포럼에서 같은 패턴으로 넘어갔다면 **포럼이 해킹당해 리디렉션이 심어졌을** 가능성이 큽니다(사용자가 각자 같은 링크를 눌렀을 가능성보다 높음).

    1. **피해 범위:** 프록시·DNS 로그에서 그 포럼을 방문한 직원 전원과, 이어서 수상한 도메인으로 넘어간 PC를 찾음
    2. **다음 단계 확인:** 넘어간 PC들이 무엇을 받았는지(응답의 Content-Type, `resp_mime_types`, 크기), 이후 새 프로세스·파일이 생겼는지
    3. **포럼 페이지 분석:** **격리된 분석 환경**에서만 페이지 소스를 가져와 삽입된 스크립트나 숨은 iframe 찾기(회사 PC에서 열지 않음)
    4. **차단:** 리디렉션 목적지 도메인 차단. 포럼 자체는 업무 영향과 위험을 보고 일시 차단 여부 결정
    5. **알림:** 포럼 운영자에게 해킹 사실 통보
