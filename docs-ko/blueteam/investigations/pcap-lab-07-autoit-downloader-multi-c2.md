---
title: PCAP 실습 07 — 웹메일 이후 AutoIt 다운로더와 여러 C2
tags:
  - blue-team
  - pcap
  - zeek
  - tshark
  - autoit
  - lokibot
  - c2
  - capture-loss
---

# PCAP 실습 07 — 웹메일 이후 AutoIt 다운로더와 여러 C2 { #lab-07 }

!!! abstract "사례 요약"
    도메인에 속하지 않은 윈도우 7 PC가 Internet Explorer로 Yahoo 메일을 열었습니다. 약 45초 뒤 브라우저가 아닌 프로그램이 `jjjj.exe`를 받았습니다. 14분 뒤에는 AutoIt 기반 프로그램이 두 번째 EXE `zugu.exe`를 받았습니다. 그다음 공인 IP를 확인하고 여러 C2와 통신하기 시작했습니다.

    - LokiBot 유형 User-Agent(`Charon; Inferno`)로 HTTP POST
    - `config.jpg` / `gate.php` 패널
    - 인증서가 만료된 HTTPS 서버
    - TCP 5552 포트로 232번 접속 시도(모두 거부됨)

    또 암호화된 SMTP로 AOL에 약 4KB를 보냈습니다. 캡처에서 패킷이 빠져서 **두 EXE 모두 해시를 구할 수 없습니다**.

| | |
|---|---|
| **증거** | `Phase1_PCAP_7.pcap`, 2017-11-20 23:58:00 – 2017-11-21 00:16:33 UTC (18.5분) |
| **환경** | 인터넷이 막힌 리눅스 분석 VM, Zeek 4.x, tshark |
| **주 도구** | Zeek 로그 + `zeek-cut`, `awk`, `grep`. TTL과 DHCP 옵션은 tshark |
| **실습 안내** | [트레이닝 → PCAP 침해사고 분석 실습 → 실습 7](../../training/pcap-ir-labs/lab-guide.md#lab-7) |

## 질문 { #questions }

감염 PC가 윈도우라고 **가정하지 않습니다**.

1. 감염 호스트의 IP 주소
2. MAC 주소
3. 호스트 이름
4. 운영체제
5. 무엇을, 몇 개 받았나
6. 각 파일을 어디서 받았나
7. 파일을 내부에서 받았나, 외부에서 받았나
8. 추가 조사에 도움이 될 정보
9. 다운로드 이후에 다른 일이 있었나
10. 무엇이 다운로드를 시작했나
11. 침해 설명

## 답 한눈에 보기 { #answers }

| # | 답 | 상태 |
|---|---|---|
| 1 | **10.192.1.157** | 확인됨 |
| 2 | **50:46:5d:d5:24:3b** | 확인됨 |
| 3 | **WIN-D5243B** | 확인됨 |
| 4 | **Windows 7** (User-Agent `Windows NT 6.1`, DHCP `MSFT 5.0`, TTL 128) | 확인됨 |
| 5 | **32비트 윈도우 EXE 2개**: `jjjj.exe` (3,061,200 바이트), `zugu.exe` (5,895,226 바이트) | 확인됨 |
| 6 | `http://lucrecianos.com.ar/imagen/1/2/jjjj.exe` (170.231.127.136), `http://virtualsmsonline.site/zugu.exe` (104.31.92.140) | 확인됨 |
| 7 | **외부**: 인터넷의 공인 IP에서 HTTP로 받음 | 확인됨 |
| 8 | URL, IP, 크기, 컴파일 시각, C2 호스트, User-Agent, SMTP. **해시는 없음**(캡처 손실) | [IOC](#iocs) 참고 |
| 9 | 두 번째 다운로드, 공인 IP 확인, C2 4곳, SMTPS로 약 4KB | 통신은 확인됨, 계열과 유출은 추정 |
| 10 | 브라우저가 아님: 첫 요청은 **User-Agent 없음**, 두 번째는 **AutoIt** | 일부 확인됨 |
| 11 | [보고서](#report) 참고 | — |

---

## 0단계 — 준비와 Zeek 로그 만들기 { #step-0 }

```bash
cd ~/Investigation_7
sha256sum Phase1_PCAP_7.pcap | tee pcap.sha256
mkdir zeek_full && cd zeek_full
zeek -C -r ../Phase1_PCAP_7.pcap local \
     frameworks/files/extract-all-files \
     policy/protocols/conn/mac-logging 2>/dev/null
ll
```

옵션 설명은 [실습 06의 0단계](pcap-lab-06-invoice-macro-c2.md#step-0)와 같습니다. 이번에는 **생긴 로그 목록 자체가 증거**입니다.

```text
capture_loss.log  conn.log  dhcp.log  dns.log  extract_files/  files.log  http.log
loaded_scripts.log  notice.log  packet_filter.log  pe.log  reporter.log  ssl.log
stats.log  x509.log
```

| 보이는 것 | 의미 |
|---|---|
| `kerberos.log`, `smb_*.log` 없음 | 도메인 로그인이 없습니다. Active Directory에 속하지 않은 **단독 PC**입니다(추정). 이번 실습에 계정 질문이 없는 것과도 맞습니다 |
| `pe.log` | 트래픽에서 **윈도우 실행 파일**을 하나 이상 분석했다는 뜻입니다 |
| `notice.log` | Zeek이 살펴볼 만한 것을 표시했습니다 |
| `capture_loss.log` | 패킷 손실 통계입니다. [5단계](#capture-loss)에서 중요해집니다 |
| `software.log` 없음 | 이 환경의 `local` 설정이 소프트웨어 버전을 기록하지 않거나, 찾은 것이 없습니다. User-Agent는 `http.log`에서 직접 봅니다 |

---

## 1단계 — 전체 그림 { #step-1 }

```bash
zeek-cut -u ts < conn.log | sort | sed -n '1p;$p'
zeek-cut id.orig_h < conn.log | grep -E "^10\.|^172\.|^192\.168\." | sort | uniq -c | sort -rn
zeek-cut service < conn.log | sort | uniq -c | sort -rn
```

```text
2017-11-20T23:58:00+0000
2017-11-21T00:16:33+0000

    575 10.192.1.157

    254 -
    163 dns
    119 ssl
     31 http
     10 dhcp
```

- 18.5분 분량이고 **내부 호스트는 하나**뿐입니다. 감염 후보는 이 PC입니다.
- `service`는 Zeek이 연결 내용을 보고 알아낸 프로토콜입니다. DNS, TLS, HTTP, DHCP뿐이므로 다운로드는 FTP, SMB, TFTP가 아닙니다.
- **service가 `-`인 연결 254개**: Zeek이 프로토콜을 알아보지 못한 연결입니다. 보통 연결이 내용을 주고받을 만큼 진행되지 못했다는 뜻입니다. [7단계](#unknown-service)에서 봅니다.

=== "tshark 대안"

    ```bash
    tshark -r ../Phase1_PCAP_7.pcap -q -z io,phs
    ```

    `-z io,phs`는 **프로토콜 계층 통계**(Wireshark *Statistics → Protocol Hierarchy*)입니다. ARP, LLMNR, NBNS, mDNS, TFTP처럼 Zeek이 로그를 따로 만들지 않는 프로토콜도 보여 줍니다. 다운로드 프로토콜을 모를 때 먼저 보면 좋습니다.

---

## 2단계 — IP, MAC, 호스트 이름 (1~3번) { #identity }

```bash
zeek-cut -u ts client_addr mac host_name < dhcp.log
```

```text
2017-11-20T23:58:00+0000   10.192.1.157   50:46:5d:d5:24:3b   -
2017-11-20T23:58:04+0000   10.192.1.157   50:46:5d:d5:24:3b   WIN-D5243B
2017-11-21T00:08:27+0000   10.192.1.157   50:46:5d:d5:24:3b   WIN-D5243B
2017-11-21T00:13:01+0000   10.192.1.157   50:46:5d:d5:24:3b   WIN-D5243B
2017-11-21T00:13:28+0000   10.192.1.157   50:46:5d:d5:24:3b   WIN-D5243B
2017-11-21T00:14:46+0000   10.192.1.157   50:46:5d:d5:24:3b   WIN-D5243B
2017-11-21T00:15:48+0000   10.192.1.157   50:46:5d:d5:24:3b   WIN-D5243B
```

- **10.192.1.157 · 50:46:5d:d5:24:3b · WIN-D5243B** (1~3번, 확인됨)
- 첫 줄에 이름이 없는 것은 맨 처음 DHCP 메시지에 옵션 12(호스트 이름)가 없었기 때문입니다. 정상입니다.
- `WIN-` + 6글자는 윈도우가 설치될 때 스스로 붙이는 임의 이름의 모양입니다. OS의 힌트일 뿐 증거는 아닙니다.

=== "tshark 대안 (DHCP에 이름이 없을 때)"

    ```bash
    tshark -r ../Phase1_PCAP_7.pcap -Y "nbns || llmnr || mdns" \
           -T fields -e ip.src -e eth.src -e nbns.name -e dns.qry.name | sort | uniq -c
    ```

    윈도우가 아닌 PC는 DHCP에 이름을 안 보내기도 합니다. 대신 NBNS, LLMNR, mDNS(`이름.local`)로 자기 이름을 알립니다. Zeek은 NBNS 로그를 만들지 않으므로 이때는 tshark가 쉽습니다. 이번 캡처는 DHCP에 이름이 있었습니다.

---

## 3단계 — 운영체제 (4번) { #os }

### User-Agent { #user-agents }

```bash
zeek-cut user_agent < http.log | sort | uniq -c | sort -rn
```

```text
     15 Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko
      8 Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0; .NET4.0C; .NET4.0E)
      7 Mozilla/4.08 (Charon; Inferno)
      3 Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko/20100101 Firefox/12.0
      2 AutoIt
      1 Microsoft NCSI
      1 -
```

| 횟수 | User-Agent | 판단 |
|---|---|---|
| 15 | IE 11, `Windows NT 6.1` | **윈도우 7**의 진짜 브라우저 |
| 1 | `Microsoft NCSI` | 윈도우의 "인터넷 연결됐나?" 확인. 윈도우만 보냄 |
| 8 | `MSIE 7.0 … .NET CLR …` | 2017년 윈도우 7에서 IE 7은 말이 안 됨 → 프로그램에 박혀 있는 문자열 |
| 7 | `Mozilla/4.08 (Charon; Inferno)` | 브라우저가 아님. **LokiBot**과 연관된 것으로 널리 알려진 고정 문자열 |
| 3 | `NT 6.3 … like Gecko/20100101 Firefox/12.0` | IE와 Firefox가 섞인 이상한 문자열. 하지만 광고 네트워크로만 갔으므로([4단계](#http-timeline)) 악성이 아니라 광고 스크립트일 가능성이 높음 |
| 2 | `AutoIt` | 윈도우 자동화 언어 **AutoIt**의 기본 User-Agent. 악성코드를 만드는 데 자주 쓰임 |
| 1 | `-` | User-Agent가 **없는** 요청 → 브라우저가 아님 |

!!! warning "User-Agent는 맥락과 함께 봅니다"
    이상한 Firefox 문자열만 보면 악성처럼 보였습니다. 하지만 목적지를 보니 광고 통신이었습니다. User-Agent는 항상 **어디로, 언제** 갔는지와 같이 판단합니다.

### TTL과 DHCP 벤더 클래스 (tshark) { #ttl-vendor }

Zeek은 IP TTL과 DHCP 벤더 클래스를 기록하지 않습니다. tshark는 둘 다 바로 읽습니다.

```bash
tshark -r ../Phase1_PCAP_7.pcap -Y "ip.src==10.192.1.157" -T fields -e ip.ttl | sort | uniq -c
tshark -r ../Phase1_PCAP_7.pcap -Y "dhcp.option.vendor_class_id" \
       -T fields -e eth.src -e dhcp.option.vendor_class_id | sort -u
```

```text
     10 1
   6809 128

50:46:5d:d5:24:3b    MSFT 5.0
```

| 증거 | 의미 |
|---|---|
| 6,809개 패킷의 TTL **128** | 윈도우의 기본 TTL(리눅스·맥·안드로이드는 64, 네트워크 장비는 255). LAN 안에서 캡처했으므로 값이 그대로입니다 |
| 10개 패킷의 TTL **1** | LLMNR(224.0.0.252)이나 IGMP 같은 근거리 멀티캐스트. TTL 1은 LAN 밖으로 못 나가게 하려는 것이고 OS와는 상관없음 |
| `MSFT 5.0` | 윈도우 2000 이후 모든 윈도우가 보내는 DHCP 벤더 클래스 |

??? note "TTL 1인 패킷은 무엇인가?"
    ```bash
    tshark -r ../Phase1_PCAP_7.pcap -Y "ip.src==10.192.1.157 && ip.ttl==1" \
           -T fields -e ip.dst -e _ws.col.Protocol | sort | uniq -c
    ```
    `_ws.col.Protocol`은 Wireshark 화면의 *Protocol* 열입니다.

**4번 답: Windows 7.** 브라우저 User-Agent(`NT 6.1`), DHCP 벤더 클래스(`MSFT 5.0`), TTL 128이 모두 같은 결론입니다. NCSI 요청과 `WIN-` 호스트 이름도 맞습니다. IE 문자열에 `WOW64`나 `Win64`가 없어서 32비트 윈도우 7로 보입니다(추정).

---

## 4단계 — HTTP 타임라인 (5, 6, 10번) { #http-timeline }

```bash
zeek-cut -u ts id.resp_h host method uri status_code resp_mime_types user_agent < http.log
```

간추린 결과(날짜 생략, UTC):

```text
23:58:11  63.146.14.19     www.msftncsi.com       GET  /ncsi.txt                                    200  text/plain    Microsoft NCSI
23:58:41  131.253.33.200   www.bing.com           GET  /favicon.ico                                 200  image/png     IE 11
23:58:49  13.107.13.80     api.bing.com           GET  /qsml.aspx?query=m&...                       -    -             IE 11
23:58:49  13.107.13.80     api.bing.com           GET  /qsml.aspx?query=ma&...                      -    -             IE 11
   ...    (query=mai, mail, mail., mail.y, mail.ya ... 글자를 칠 때마다 한 번씩)
23:58:51  13.107.13.80     api.bing.com           GET  /qsml.aspx?query=mail.yahoo.com&...          200  application/xml  IE 11
23:58:56  162.208.20.184   geo-um.btrll.com       GET  /v1/map/68e4318f0f7098c3/...             302  -             NT 6.3 ... Firefox/12.0
23:58:56  52.84.14.115     cache.btrll.com        GET  /default/Pix-1x1.gif                         200  image/gif     NT 6.3 ... Firefox/12.0
23:59:35  170.231.127.136  lucrecianos.com.ar     GET  /imagen/1/2/jjjj.exe                         200  application/x-dosexec  -
00:13:28  104.31.92.140    virtualsmsonline.site  GET  /zugu.exe                                    200  application/x-dosexec  AutoIt
00:13:38  104.20.17.242    icanhazip.com          GET  /                                            200  text/plain    AutoIt
00:13:59  185.118.166.155  tcoolonline.mobi       POST /wp-admin/css/colors/blue/Panel/five/fre.php 404  text/plain    Mozilla/4.08 (Charon; Inferno)
00:14:04  37.48.82.212     www.harddomainname.biz GET  /wordpress/wp-admin/css/colors/blue/panel/config.jpg 200 image/jpeg MSIE 7.0 ...
00:14:06  5.255.255.55     yandex.ru              GET  /                                            302  -             MSIE 7.0 ...
00:14:07  37.48.82.212     www.harddomainname.biz POST /wordpress/wp-admin/css/colors/blue/panel/gate.php 200 -     MSIE 7.0 ...
00:15:01  ... tcoolonline.mobi POST .../fre.php (404, Charon; Inferno)
00:15:07  ... harddomainname.biz GET .../config.jpg (304), 00:15:08 POST .../gate.php (200)
00:16:08  ... harddomainname.biz GET .../config.jpg (304), POST .../gate.php (200)
00:16:29–31  ... tcoolonline.mobi POST .../fre.php x3 (404)
```

| 시각 | 일어난 일 | 의미 |
|---|---|---|
| 23:58:49~51 | `api.bing.com/qsml.aspx?query=m`, `ma`, `mai`, … `mail.yahoo.com` | IE 주소창은 **글자를 칠 때마다** Bing 자동완성을 요청합니다. 사용자가 **mail.yahoo.com을 입력**했습니다. Yahoo 메일 자체는 HTTPS라서 메일 내용은 안 보입니다 |
| 23:58:56 | `btrll.com` 302 + 1×1 GIF | Yahoo 페이지의 광고 픽셀(BrightRoll, Yahoo 계열 광고 네트워크) |
| **23:59:35** | `lucrecianos.com.ar`에서 **`jjjj.exe`**, **User-Agent 없음** | 첫 번째 실행 파일. **브라우저가 아닌** 것이 요청함 |
| *14분 공백* | 정상 HTTPS만 있음([6단계](#ssl)) | 1단계 악성코드가 기다리거나 조용히 동작한 시간(추정) |
| **00:13:28** | `virtualsmsonline.site`에서 **`zugu.exe`**, User-Agent **AutoIt** | 두 번째 실행 파일. **AutoIt 기반 프로그램**이 받음 |
| 00:13:38 | `icanhazip.com` (AutoIt) | 공인 IP 확인 |
| 00:13:59 → | `…/Panel/five/fre.php`로 POST, `Charon; Inferno`, 약 1분마다 | C2 #1. `fre.php` + 이 User-Agent는 전형적인 **LokiBot** 패턴. LokiBot 패널은 일부러 404로 답하는 경우가 많음 |
| 00:14:04 → | `…/panel/config.jpg` GET, `…/panel/gate.php` POST, MSIE 7 UA, 약 60초마다 | C2 #2. 별도의 봇/정보 탈취 패널(계열은 정하지 못함) |
| 00:14:06 | `yandex.ru` (MSIE 7 UA) | 같은 프로그램의 인터넷 연결 확인 |

=== "tshark 대안"

    ```bash
    tshark -r ../Phase1_PCAP_7.pcap -Y "http.request" -T fields \
           -e frame.time_utc -e ip.dst -e http.host -e http.request.method -e http.request.uri -e http.user_agent
    ```

    요청만 나오고 응답 종류는 없습니다. 요청과 응답을 한 줄로 보여 주는 Zeek이 여기서는 더 편합니다. Zeek 줄이 길어 읽기 어려울 때 보조로 씁니다.

---

## 5단계 — 받은 파일 (5~8번)과 해시가 없는 이유 { #files }

```bash
zeek-cut -u ts tx_hosts rx_hosts source mime_type filename seen_bytes fuid < files.log \
  | grep -v -i -E "x509|pkix"
```

`grep -v`는 맞는 줄을 **빼고** 보여 줍니다. HTTPS 연결마다 서버 인증서가 `files.log`에 기록되는데, 그것은 다운로드가 아니므로 뺍니다. 실행 파일은 두 줄입니다.

```text
2017-11-20T23:59:36+0000  170.231.127.136  10.192.1.157  HTTP  application/x-dosexec  -  2870222  FwavXQ2AM4W84BhH44
2017-11-21T00:13:29+0000  104.31.92.140    10.192.1.157  HTTP  application/x-dosexec  -  5812128  FuT2N64AuTHxEdqVil
```

나머지는 작은 웹 파일과 C2 통신입니다. `tx_hosts`가 감염 PC인 줄은 PC가 **보낸** POST 본문입니다. 185.118.166.155로 204·177바이트, 37.48.82.212로 345바이트를 보냈습니다. 눈에 띄는 것은 `config.jpg`입니다. C2 패널 경로에서 받은 **81,393바이트**짜리 `image/jpeg`입니다. 그림 안에 설정이나 데이터를 숨겼을 수 있습니다(추정).

### PE 헤더 정보 { #pe }

```bash
zeek-cut -u ts id machine os compile_ts is_exe is_64bit < pe.log
```

```text
2017-11-20T23:59:36+0000  FwavXQ2AM4W84BhH44  I386  Windows 95 or NT 4.0          2017-11-20T15:10:13+0000  T  F
2017-11-21T00:13:29+0000  FuT2N64AuTHxEdqVil  I386  Windows Vista or Server 2008  2017-07-31T15:19:47+0000  T  F
```

- 둘 다 **32비트(`I386`) EXE**입니다(`is_exe T`, `is_64bit F`).
- `os`는 그 파일이 요구하는 *최소* 윈도우 버전입니다. 감염 PC의 OS가 아닙니다.
- `jjjj.exe`는 **다운로드되기 약 9시간 전에 컴파일**됐습니다. 갓 만든 샘플입니다. 컴파일 시각은 조작할 수 있으므로 보조 정보로만 씁니다.

### MD5와 SHA1이 비어 있는 이유: 캡처 손실 { #capture-loss }

```bash
zeek-cut fuid mime_type md5 sha1 < files.log | grep dosexec
zeek-cut < files.log | grep dosexec        # 모든 칸
```

```text
FwavXQ2AM4W84BhH44   application/x-dosexec   -   -
FuT2N64AuTHxEdqVil   application/x-dosexec   -   -
```

`jjjj.exe`의 전체 줄을 Zeek 4 `files.log` 칸 순서에 맞춰 읽으면 이렇습니다.

| 칸 | 값 | 의미 |
|---|---|---|
| `conn_uids` | `CJ9NTy1RmcRnZRVcma` | 파일이 지나간 연결 |
| `analyzers` | `EXTRACT,MD5,SHA1,PE` | 해시 계산을 **시도함** |
| `seen_bytes` | 2,870,222 | 캡처에 실제로 있는 바이트 |
| `total_bytes` | **3,061,200** | 서버가 알려 준 진짜 크기(`Content-Length`) |
| `missing_bytes` | **190,978** | 캡처에 없는 바이트 |
| `md5` / `sha1` | `-` | 계산 안 됨 |

`zugu.exe`: 전체 **5,895,226**, 본 것 5,812,128, 빠진 것 **83,098**.

해시는 모든 바이트로 계산하고, 한 바이트만 빠져도 완전히 다른 값이 됩니다. 그래서 Zeek은 **틀린 해시를 만들지 않습니다**. 같은 이유로 추출된 파일이나 tshark로 꺼낸 파일에 `sha256sum`을 돌린 값은 진짜 파일의 해시가 **아니므로** 보고하면 안 됩니다.

!!! danger "크기는 `seen_bytes`가 아니라 `total_bytes`로"
    파일 크기는 서버가 **알려 준** 크기인 3,061,200바이트와 5,895,226바이트입니다. `seen_bytes`는 캡처에 들어 있던 양일 뿐입니다. 이 풀이도 처음에는 5번을 `seen_bytes`로 답했다가, `missing_bytes`를 확인한 뒤 고쳤습니다.

손실 확인:

```bash
zeek-cut -u ts peer gaps acks percent_lost < capture_loss.log
zeek-cut uid id.resp_h missed_bytes history < conn.log | grep -E "CJ9NTy1RmcRnZRVcma|CtsW3u4avJGUQUma66"
zeek-cut fuid seen_bytes total_bytes missing_bytes < files.log | grep -E "FwavXQ2AM4W84BhH44|FuT2N64AuTHxEdqVil"
```

- `percent_lost`가 0보다 크면 센서가 패킷을 놓쳤다는 뜻입니다.
- `conn.log`의 `missed_bytes`는 `missing_bytes`와 비슷해야 합니다.
- `history`에 `g`나 `G`가 있으면 내용 중간에 빈틈이 있었다는 표시입니다.

=== "tshark 대안"

    ```bash
    tshark -r ../Phase1_PCAP_7.pcap -Y "tcp.analysis.lost_segment || tcp.analysis.ack_lost_segment" | wc -l
    mkdir objs && tshark -r ../Phase1_PCAP_7.pcap -q --export-objects http,objs && ls -l objs/*.exe
    ```

    첫 줄은 Wireshark가 "이전 TCP 조각을 못 봤다"고 표시한 패킷 수입니다. 두 번째 줄은 파일을 **URL 이름 그대로**(`jjjj.exe`, `zugu.exe`) 꺼내서 찾기 편합니다. 하지만 캡처 손실이 있으면 파일이 불완전하므로 보고용 해시를 구하면 안 됩니다.

### 7번 — 내부인가 외부인가 { #direction }

```bash
zeek-cut -u ts tx_hosts rx_hosts mime_type seen_bytes < files.log | grep dosexec
zeek-cut -u ts query answers < dns.log | grep -E "lucrecianos|virtualsmsonline"
```

`tx_hosts`(보낸 쪽)는 170.231.127.136과 104.31.92.140입니다. 둘 다 10/8, 172.16/12, 192.168/16 밖의 공인 주소이고, 인터넷 도메인 이름으로 접속했습니다. `rx_hosts`가 피해 PC이므로 방향은 **외부 → 내부**입니다. 단독 PC라서 내부 서버도 없고, 연결을 시작한 내부 호스트도 이 PC 하나뿐입니다.

---

## 6단계 — Zeek 경고와 HTTPS 목적지 { #ssl }

```bash
zeek-cut -u ts note msg src dst < notice.log
zeek-cut -u ts id.resp_h server_name < ssl.log | awk -F'\t' '$1 >= "2017-11-20T23:59:30+0000"'
```

**notice.log**: `SSL::Invalid_Server_Cert … unable to get local issuer certificate` 경고가 11개 있습니다. 대부분 Google(172.217.x), Amazon(52.x, 34.x) 같은 큰 클라우드·CDN입니다. 오래된 캡처라 Zeek이 인증서 체인을 끝까지 확인하지 못한 것이고, **잡음**입니다. **마지막 한 줄만 다릅니다.**

```text
2017-11-21T00:13:39+0000  SSL::Invalid_Server_Cert  SSL certificate validation failed with (certificate has expired)  10.192.1.157  5.189.170.24
```

**ssl.log** (`server_name`은 SNI입니다. 내용은 암호화돼도 접속할 도메인 이름은 평문으로 보냅니다):

| 시각 | 서버 | 판단 |
|---|---|---|
| 23:59:41 | `ieonline.microsoft.com` | IE의 정상 통신 |
| 00:08:34 | `update.googleapis.com` | 구글 업데이트, 정상 |
| **00:13:39 – 00:16:08** | **`idea.bsit.pk`** (5.189.170.24), 30~50초 간격으로 몰아서 접속 | **인증서 만료**, `zugu.exe` 직후 시작 → **HTTPS C2 #3**(추정) |
| **00:14:14** | **`smtp.aol.com`** (152.163.0.69) | 웹메일 사용자의 PC에서 나간 **메일 보내기** 연결 |

14분 공백에는 정상 HTTPS만 있습니다. 1단계 악성코드가 00:13까지 기다렸거나 네트워크 없이 동작했을 가능성이 있습니다(추정).

### SMTP: 얼마나 보냈나 { #smtp }

```bash
zeek-cut -u ts id.resp_h id.resp_p service duration orig_bytes resp_bytes < conn.log | grep 152.163.0.69
```

```text
2017-11-21T00:14:14+0000  152.163.0.69  465  ssl  2.435390  4380  5804
2017-11-21T00:14:16+0000  152.163.0.69  465  -    3.016734  0     0
2017-11-21T00:14:25+0000  152.163.0.69  465  -    -         -     -
```

- **465번 포트는 SMTPS**(처음부터 TLS로 감싼 SMTP)입니다. 내용은 볼 수 없습니다.
- `orig_bytes` 4,380은 PC가 **보낸** 양입니다. TLS 연결 설정에 1~2KB가 쓰이므로, 몇 KB의 메일을 보낼 양이 남습니다. 훔친 계정 목록을 보내기에 충분합니다.
- 사용자는 브라우저로 메일을 봤습니다. 그런데 메일 프로그램처럼 SMTP에 직접 접속한 것은 어울리지 않습니다. **훔친 데이터 유출일 가능성**이 큽니다(추정).

---

## 7단계 — Zeek이 알아보지 못한 연결 (9번) { #unknown-service }

```bash
zeek-cut id.resp_h id.resp_p proto service conn_state < conn.log \
  | awk -F'\t' '$4=="-" {print $1, $2, $3, $5}' | sort | uniq -c | sort -rn | head -20
```

```text
    231 213.183.58.34 5552 tcp REJ
      6 64.94.116.170 443 tcp S0
      3 64.94.116.170 443 tcp RSTRH
      3 181.215.247.234 1031 tcp REJ
      2 64.12.88.133 465 tcp S0
      2 172.217.0.227 443 tcp OTH
      2 152.163.0.69 465 tcp S0
      1 213.183.58.34 5552 tcp S0
      1 131.253.33.200 80 tcp RSTR
      1 13.107.13.80 80 tcp RSTR
      1 10.192.1.157 49322 tcp OTH
      1 10.192.1.157 49304 tcp OTH
```

| `conn_state` | 의미 |
|---|---|
| `SF` | 정상적으로 열리고 닫힘 |
| `S0` | SYN을 보냈지만 응답 없음 |
| `REJ` | 거부됨(서버가 RST로 응답) |
| `RSTR` / `RSTRH` | 응답 쪽이 연결을 끊음 |
| `OTH` | Zeek이 연결의 시작을 못 봄(중간부터) |

- **213.183.58.34:5552, 232번 시도, 모두 거부.** 같은 서버와 포트에 계속 다시 연결하는 것은 C2에 붙으려는 악성코드의 모습입니다. REJ는 포트가 닫혀 있었다는 뜻이므로, 서버가 이미 꺼졌을 가능성이 있습니다(추정). **TCP 5552는 njRAT의 기본 포트**입니다(포트만 보고 한 약한 추정).
- **181.215.247.234:1031**(REJ ×3)과 **64.94.116.170:443**(S0/RST): 모르는 호스트로 나간 다른 실패 시도들입니다. 지표로 적어 둡니다.
- **64.12.88.133:465**: SMTPS 실패 시도 2번(AOL 대역 주소로 보임, 추정).
- 10.192.1.157을 향한 `OTH` 줄은 시작 부분이 캡처되지 않은 연결 조각입니다. 들어오는 공격이 아닙니다.
- Zeek이 `service -`로 둔 것은 이 연결들이 알아볼 만한 데이터를 한 번도 주고받지 못했기 때문입니다.

5552 접속은 언제 시작됐나:

```bash
zeek-cut -u ts id.resp_h id.resp_p conn_state < conn.log | awk -F'\t' '$3==5552' | sed -n '1p;$p'
```

`awk -F'\t' '$3==5552'`는 세 번째 칸(목적지 포트)이 5552인 줄만 남기고, `sed -n '1p;$p'`는 첫 줄과 마지막 줄만 보여 줍니다.

---

## 8단계 — 무엇이 다운로드를 시작했나 (10번) { #download-tool }

| 증거 | 상태 |
|---|---|
| `jjjj.exe` 요청에 **User-Agent가 없음**. 브라우저는 항상 보내므로 스크립트나 프로그램이 받은 것. 예를 들어 PowerShell의 `Net.WebClient`는 기본으로 User-Agent를 보내지 않음 | UA 없음은 확인됨, 도구는 추정 |
| `zugu.exe`와 `icanhazip.com` 요청의 User-Agent가 **`AutoIt`** | 확인됨 |
| 첫 다운로드 약 45초 전에 사용자가 **Yahoo 메일**을 염 | 확인됨 |
| `jjjj.exe`에 `strings`를 돌렸지만 `AutoIt` / `AU3!` 표시가 **없음** | 확인 안 됨: 파일이 압축·암호화됐거나, 캡처 손실로 일부가 없거나, AutoIt 부분을 다른 파일로 만들어 냈을 수 있음 |

```bash
strings -n 6 extract_files/*FwavXQ2AM4W84BhH44 | grep -i -E "autoit|AU3!" | sort | uniq -c | head
```

결론: **실행 파일을 받은 것은 브라우저가 아닙니다.** 첫 번째는 브라우저가 아닌 프로그램이, 두 번째는 **AutoIt 기반 프로그램**이 받았습니다. Yahoo 메일에서 연 악성 메일이 시작점일 가능성이 높습니다. 하지만 메일은 HTTPS로 암호화돼 있어서 이 캡처로는 확정할 수 없습니다.

---

## 타임라인 { #timeline }

| UTC | 이벤트 | 출처 |
|---|---|---|
| 2017-11-20 23:58:00 | 캡처 시작. WIN-D5243B(10.192.1.157) DHCP | dhcp.log |
| 23:58:11 | 윈도우 NCSI 확인 | http.log |
| 23:58:49~51 | 사용자가 IE에 `mail.yahoo.com` 입력(Bing 자동완성) | http.log |
| 23:58:56 | Yahoo 페이지 광고 픽셀(btrll.com) | http.log |
| **23:59:35** | lucrecianos.com.ar에서 `jjjj.exe` 다운로드, User-Agent 없음 | http.log, files.log, pe.log |
| 23:59:41 – 00:08:34 | 정상 HTTPS만(Microsoft, Google) | ssl.log |
| **00:13:28** | virtualsmsonline.site에서 `zugu.exe` 다운로드, User-Agent AutoIt | http.log, files.log, pe.log |
| 00:13:38 | 공인 IP 확인, icanhazip.com | http.log |
| 00:13:39 → | idea.bsit.pk로 HTTPS(인증서 만료), 몰아서 접속 | ssl.log, notice.log |
| 00:13:59 → | tcoolonline.mobi로 `fre.php` POST(`Charon; Inferno`), 약 1분마다 | http.log |
| 00:14:04 → | harddomainname.biz의 `config.jpg` / `gate.php`(MSIE 7 UA), 약 60초마다 | http.log |
| 00:14:14 | smtp.aol.com으로 SMTPS, 약 4.4KB 보냄 | conn.log, ssl.log |
| 캡처 동안 | 213.183.58.34:5552로 232번 접속, 모두 거부 | conn.log |
| 00:16:33 | 캡처 끝 | conn.log |

## 침해 지표 (IOC) { #iocs }

| 종류 | 지표 | 역할 |
|---|---|---|
| URL | `hxxp://lucrecianos[.]com[.]ar/imagen/1/2/jjjj.exe` | 첫 번째 EXE(3,061,200 바이트, 2017-11-20 15:10:13 UTC 컴파일) |
| IP | `170.231.127[.]136` | lucrecianos.com.ar |
| URL | `hxxp://virtualsmsonline[.]site/zugu.exe` | 두 번째 EXE(5,895,226 바이트) |
| IP | `104.31.92[.]140` | virtualsmsonline.site |
| URL | `hxxp://tcoolonline[.]mobi/wp-admin/css/colors/blue/Panel/five/fre.php` | C2 #1(LokiBot 유형) |
| IP | `185.118.166[.]155` | tcoolonline.mobi |
| URL | `hxxp://www.harddomainname[.]biz/wordpress/wp-admin/css/colors/blue/panel/gate.php`, `…/config.jpg` | C2 #2 |
| IP | `37.48.82[.]212` | harddomainname.biz |
| 도메인 / IP | `idea.bsit[.]pk` / `5.189.170[.]24` | HTTPS C2 #3, 인증서 만료 |
| IP:포트 | `213.183.58[.]34:5552` | 실패한 C2(njRAT 가능성) |
| IP:포트 | `181.215.247[.]234:1031`, `64.94.116[.]170:443` | 실패한 외부 접속 시도 |
| 호스트 | `smtp.aol[.]com` (`152.163.0[.]69:465`), `64.12.88[.]133:465` | SMTPS, 유출 가능성 |
| User-Agent | `AutoIt` · `Mozilla/4.08 (Charon; Inferno)` · `Mozilla/4.0 (compatible; MSIE 7.0; …)` | 악성 프로그램 |
| 해시 | 없음 | 캡처 손실(`missing_bytes` > 0) |

## ATT&CK 매핑 { #attack }

| 기법 | 근거 |
|---|---|
| T1566 Phishing | Yahoo 메일을 연 직후 다운로드 시작(추정) |
| T1105 Ingress Tool Transfer | `jjjj.exe`, `zugu.exe` |
| T1059.010 Command and Scripting Interpreter: AutoHotKey & AutoIT | `AutoIt` User-Agent |
| T1016.001 Internet Connection Discovery | `icanhazip.com`, `yandex.ru` 확인 |
| T1071.001 Application Layer Protocol: Web Protocols | `fre.php`, `gate.php`, HTTPS C2 |
| T1571 Non-Standard Port | TCP 5552, 1031 |
| T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol | AOL로 SMTPS(추정) |

## 보고서 (11번) { #report }

> On 2017-11-20 at 23:59 UTC, the Windows 7 host WIN-D5243B (10.192.1.157) downloaded jjjj.exe from lucrecianos.com.ar, shortly after the user opened Yahoo Mail. At 00:13, an AutoIt-based program downloaded a second EXE, zugu.exe. The host then checked its public IP and contacted several C2 servers. One pattern matches LokiBot (not confirmed). It sent about 4 KB over encrypted SMTP to AOL, likely stolen data. It also kept trying a possible njRAT server on port 5552. The host should be isolated and rebuilt, and all saved passwords changed.

## 탐지 아이디어 { #detection }

=== "Zeek"

    ```bash
    # 실행 파일을 받은 요청과 그 User-Agent
    zeek-cut -u ts id.orig_h host uri user_agent resp_mime_types < http.log | grep dosexec
    # 알려진 악성 / 말이 안 되는 User-Agent
    zeek-cut id.orig_h host user_agent < http.log | grep -E "AutoIt|Charon; Inferno|MSIE 7\.0" | sort | uniq -c
    # 닫힌 포트 하나에 계속 접속하는 호스트 (같은 목적지에 REJ가 많음)
    zeek-cut id.orig_h id.resp_h id.resp_p conn_state < conn.log | awk -F'\t' '$4=="REJ"' | sort | uniq -c | sort -rn | head
    # SMTP(S)에 직접 접속하는 PC
    zeek-cut -u ts id.orig_h id.resp_h id.resp_p orig_bytes < conn.log | awk -F'\t' '$4==25 || $4==465 || $4==587'
    ```

=== "Snort 2"

    ```text
    alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL LokiBot-style User-Agent Charon Inferno"; flow:established,to_server; content:"Charon|3B| Inferno"; http_header; classtype:trojan-activity; sid:1000701; rev:1;)
    alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"LOCAL AutoIt User-Agent"; flow:established,to_server; content:"User-Agent|3A| AutoIt|0D 0A|"; http_header; classtype:policy-violation; sid:1000702; rev:1;)
    alert tcp $HOME_NET any -> $EXTERNAL_NET 5552 (msg:"LOCAL Outbound TCP 5552 (njRAT default port)"; flags:S; threshold:type both, track by_src, count 10, seconds 60; classtype:trojan-activity; sid:1000703; rev:1;)
    ```

=== "Splunk"

    ```spl
    index=zeek sourcetype=zeek:http (user_agent="AutoIt" OR user_agent="*Charon; Inferno*" OR resp_mime_types="*dosexec*")
    | table _time id.orig_h host uri user_agent resp_mime_types
    | sort _time
    ```

    인덱스와 소스타입은 환경에 맞게 바꿉니다. Snort 룰의 `|3B|`와 `|3A|`는 `;`와 `:`의 16진수 표기입니다.

## 교훈 { #lessons }

- **로그 목록도 증거입니다.** `kerberos.log`가 없으면 도메인이 아니고, `pe.log`가 있으면 실행 파일이 오갔습니다.
- **해시 전에 `missing_bytes`를 확인합니다.** 캡처 손실이 있으면 Zeek은 `md5`/`sha1`을 비워 두고, 꺼낸 파일의 해시는 틀린 값입니다. 크기는 `total_bytes`로 쓰고, 해시가 없는 이유를 적습니다.
- **User-Agent는 목적지와 같이 읽습니다.** 이상한 Firefox 문자열은 광고였고, `AutoIt`과 `Charon; Inferno`는 악성코드였습니다.
- **`service -` 안에 가장 큰 신호가 숨어 있었습니다.** 한 포트로 거부된 232번의 접속은 알 수 없는 연결을 요약했을 때만 보였습니다.
- **웹메일 사용자의 PC에서 나간 암호화 SMTP는 어울리지 않습니다.** 유출 가능성으로 보고하되, 내용은 볼 수 없다고 함께 적습니다.
- **tshark는 Zeek의 빈틈을 채웁니다:** TTL, DHCP 벤더 클래스, 프로토콜 계층, NBNS 이름, 손실된 세그먼트 수.
